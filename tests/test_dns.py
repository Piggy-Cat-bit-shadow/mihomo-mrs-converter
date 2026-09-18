import unittest

from converter.exporters.dns import collect_dns_domain_payloads


class DnsExporterTest(unittest.TestCase):
    def test_groups_are_fixed_and_payload_driven(self):
        config = {"rule-providers": {"Direct-domain": {"behavior": "domain"}, "China-domain": {"behavior": "domain"}, "AI-domain": {"behavior": "domain"}, "Global-domain": {"behavior": "domain"}}}
        result = collect_dns_domain_payloads(config, {"Direct-domain": ["direct.example"], "China-domain": ["cn.example"], "AI-domain": ["ai.example"], "Global-domain": ["global.example"]})
        self.assertEqual(result["China"][0], ["direct.example", "cn.example"])
        self.assertEqual(result["Global"][0], ["ai.example", "global.example"])


if __name__ == "__main__":
    unittest.main()
