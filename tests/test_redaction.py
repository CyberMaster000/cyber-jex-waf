import json
import unittest

from src.utils.audit import fingerprint_secret
from src.utils.redaction import MASK, redact_body, redact_headers, redact_query


class TestRedaction(unittest.TestCase):
    def test_headers(self):
        headers = redact_headers(
            {
                "Authorization": "Bearer abcdefghijklmnop",
                "Cookie": "sid=secret",
                "User-Agent": "Mozilla/5.0",
            }
        )
        self.assertEqual(headers["Authorization"], MASK)
        self.assertEqual(headers["Cookie"], MASK)
        self.assertEqual(headers["User-Agent"], "Mozilla/5.0")

    def test_json_body(self):
        body = json.dumps(
            {
                "username": "nikhil",
                "password": "hunter2",
                "nested": {"access_token": "abc", "email": "a@b.com"},
            }
        )
        redacted = json.loads(redact_body(body, "application/json"))
        self.assertEqual(redacted["password"], MASK)
        self.assertEqual(redacted["nested"]["access_token"], MASK)
        self.assertNotIn("a@b.com", redacted["nested"]["email"])

    def test_form_and_xml(self):
        form = redact_body("user=a&password=secret&x=1", "application/x-www-form-urlencoded")
        self.assertIn("password=%5BREDACTED%5D", form)
        xml = redact_body("<login><password>secret</password></login>", "text/xml")
        self.assertIn(MASK, xml)
        self.assertNotIn("secret", xml)

    def test_query(self):
        self.assertEqual(redact_query({"token": "abc", "q": "shoes"})["token"], MASK)

    def test_key_fingerprint_is_not_reversible(self):
        fp = fingerprint_secret("waf-admin-key-001")
        self.assertEqual(len(fp), 12)
        self.assertNotIn("waf", fp)


if __name__ == "__main__":
    unittest.main()
