import unittest

from converter.exporters.mihomo import normalize_no_active_resolve


class MihomoExporterTest(unittest.TestCase):
    def test_ip_provider_reference_gets_no_resolve(self):
        config = {"rule-providers": {"A-ip": {"behavior": "ipcidr"}}, "rules": ["RULE-SET,A-ip,Proxy"]}
        output = normalize_no_active_resolve(config, {"A-ip": ["192.0.2.0/24"]})
        self.assertEqual(output["rules"], ["RULE-SET,A-ip,Proxy,no-resolve"])


if __name__ == "__main__":
    unittest.main()
