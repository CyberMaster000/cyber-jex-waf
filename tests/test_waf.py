"""
Unit and integration tests for Sentinel Transformer WAF.
Runs with the standard Python unittest module.
"""
import unittest
from pathlib import Path

from fastapi.testclient import TestClient

from src.api.detection_api import app

MODEL_WEIGHTS = Path("models/securebert_clf/model.safetensors")


@unittest.skipUnless(
    MODEL_WEIGHTS.exists() and MODEL_WEIGHTS.stat().st_size > 1_000_000,
    "SecureBERT weights are not present",
)
class TestSentinelWAF(unittest.TestCase):
    def setUp(self):
        self.client = TestClient(app)
        self.headers = {"X-API-Key": "waf-key-dev-001"}
        self.admin_headers = {"X-API-Key": "waf-admin-key-001"}
        self.auth = ("sentinel", "change-me")

    def test_health_endpoint(self):
        response = self.client.get("/health")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["status"], "healthy")

    def test_history_page_requires_auth(self):
        self.assertEqual(self.client.get("/history").status_code, 401)
        response = self.client.get("/history", auth=self.auth)
        self.assertEqual(response.status_code, 200)
        self.assertIn("Sentinel WAF", response.text)
        self.assertIn('<canvas id="timelineChart"></canvas>', response.text)

    def test_history_page_rejects_bad_password(self):
        response = self.client.get("/history", auth=("sentinel", "wrong"))
        self.assertEqual(response.status_code, 401)

    def test_stats_endpoint(self):
        response = self.client.get("/stats", headers=self.headers)
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertIn("total_requests", data)
        self.assertIn("anomalies", data)
        self.assertIn("benign", data)

    def test_detect_benign_request(self):
        payload = {
            "method": "GET",
            "path": "/api/v1/products?cat=books&sort=asc",
            "headers": {"User-Agent": "Mozilla/5.0"},
            "body": "",
        }
        response = self.client.post("/detect", json=payload, headers=self.headers)
        self.assertEqual(response.status_code, 200)
        data = response.json()
        for key in ("anomaly_score", "is_anomaly", "request_id", "decision", "reason"):
            self.assertIn(key, data)
        self.assertEqual(data["decision"], "ALLOWED")

    def test_detect_benign_json_login_is_not_blocked(self):
        payload = {
            "method": "POST",
            "path": "/api/login",
            "headers": {"Content-Type": "application/json", "User-Agent": "Mozilla/5.0"},
            "body": '{"username":"nikhil","password":"Passw0rd!"}',
        }
        response = self.client.post("/detect", json=payload, headers=self.headers)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["decision"], "ALLOWED")

    def test_detect_sqli_hard_rule_blocks(self):
        payload = {
            "method": "GET",
            "path": "/items?id=1%20UNION%20SELECT%20null,password%20FROM%20users--",
            "headers": {"User-Agent": "Mozilla/5.0"},
            "body": "",
        }
        response = self.client.post("/detect", json=payload, headers=self.headers)
        data = response.json()
        self.assertEqual(data["decision"], "BLOCKED")
        self.assertIn("sqli_union", data["matched_rules"])

    def test_detect_xss_hard_rule_blocks(self):
        payload = {
            "method": "GET",
            "path": "/?q=<script>alert(1)</script>",
            "headers": {},
            "body": "",
        }
        data = self.client.post("/detect", json=payload, headers=self.headers).json()
        self.assertEqual(data["decision"], "BLOCKED")
        self.assertIn("xss_script_tag", data["matched_rules"])

    def test_check_endpoint_status_codes(self):
        benign = {
            "method": "GET",
            "path": "/api/v1/products?cat=books",
            "headers": {"User-Agent": "Mozilla/5.0"},
            "body": "",
        }
        self.assertEqual(
            self.client.post("/check", json=benign, headers=self.headers).status_code,
            204,
        )
        attack = {
            "method": "GET",
            "path": "/?file=../../../../etc/passwd",
            "headers": {},
            "body": "",
        }
        self.assertEqual(
            self.client.post("/check", json=attack, headers=self.headers).status_code,
            403,
        )

    def test_api_key_required(self):
        payload = {"method": "GET", "path": "/", "headers": {}, "body": ""}
        self.assertEqual(self.client.post("/detect", json=payload).status_code, 401)

    def test_clear_history_requires_admin_key(self):
        self.assertEqual(self.client.post("/clear", headers=self.headers).status_code, 401)
        response = self.client.post("/clear", headers=self.admin_headers)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["status"], "cleared")

    def test_metrics_and_request_id(self):
        payload = {"method": "GET", "path": "/", "headers": {}, "body": ""}
        response = self.client.post(
            "/detect", json=payload, headers={**self.headers, "X-Request-ID": "test-trace-123"}
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.headers["X-Request-ID"], "test-trace-123")
        metrics = self.client.get("/metrics")
        self.assertEqual(metrics.status_code, 200)
        self.assertIn("waf_requests_total", metrics.text)

    def test_sensitive_data_is_redacted_in_logs(self):
        payload = {
            "method": "POST",
            "path": "/api/redaction-test",
            "headers": {
                "Content-Type": "application/json",
                "Authorization": "Bearer supersecrettoken123456",
                "User-Agent": "Mozilla/5.0",
            },
            "body": '{"username":"nikhil","password":"SuperSecret123!","email":"user@example.com"}',
        }
        response = self.client.post("/detect", json=payload, headers=self.headers)
        self.assertEqual(response.status_code, 200)
        request_id = response.json()["request_id"]
        stored = self.client.get(
            f"/logs?path_contains=redaction-test", headers=self.headers
        ).json()["events"]
        event = next(e for e in stored if e["request_id"] == request_id)
        self.assertNotIn("SuperSecret123!", event["body"])
        self.assertNotIn("supersecrettoken", event["headers"].get("Authorization", ""))
        self.assertIn("[REDACTED]", event["body"])

    def test_request_limits(self):
        headers = {f"X-Test-{i}": "x" for i in range(120)}
        payload = {"method": "GET", "path": "/", "headers": headers, "body": ""}
        self.assertEqual(
            self.client.post("/detect", json=payload, headers=self.headers).status_code,
            431,
        )


if __name__ == "__main__":
    unittest.main()
