import os
import unittest

from src.utils import ipfilter


class TestIPFilter(unittest.TestCase):
    def tearDown(self):
        os.environ.pop("WAF_IP_ALLOWLIST", None)
        os.environ.pop("WAF_IP_BLOCKLIST", None)
        ipfilter._configured.cache_clear()

    def test_blocklist_and_allowlist(self):
        os.environ["WAF_IP_BLOCKLIST"] = "203.0.113.0/24"
        ipfilter._configured.cache_clear()
        self.assertEqual(ipfilter.ip_decision("203.0.113.9"), "blocklisted")
        self.assertIsNone(ipfilter.ip_decision("10.0.0.1"))

        os.environ["WAF_IP_ALLOWLIST"] = "10.0.0.0/8, 192.168.0.0/16"
        ipfilter._configured.cache_clear()
        self.assertEqual(ipfilter.ip_decision("10.1.2.3"), "allowlisted")
        self.assertEqual(ipfilter.ip_decision("8.8.8.8"), "not_allowlisted")
        self.assertIsNone(ipfilter.ip_decision("not-an-ip"))


if __name__ == "__main__":
    unittest.main()
