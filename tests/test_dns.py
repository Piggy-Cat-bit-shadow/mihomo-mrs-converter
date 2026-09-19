import unittest

from converter.exporters.dns import collect_dns_domain_payloads


class DnsExporterTest(unittest.TestCase):
    def test_groups_are_fixed_and_payload_driven(self):
        config = {"rule-providers": {"Direct-domain": {"behavior": "domain"}, "China-domain": {"behavior": "domain"}, "AI-domain": {"behavior": "domain"}, "Global-domain": {"behavior": "domain"}}}
        result = collect_dns_domain_payloads(config, {"Direct-domain": ["direct.example"], "China-domain": ["cn.example"], "AI-domain": ["ai.example"], "Global-domain": ["global.example"]}, segment_roles={"Direct": "direct", "China": "china", "AI": "ai", "Global": "global"})
        self.assertEqual(result["China"][0], ["direct.example", "cn.example"])
        self.assertEqual(result["Global"][0], ["ai.example", "global.example"])

    def test_reject_role_is_valid_but_excluded_from_dns_groups(self):
        config = {"rule-providers": {
            "HTTPDNS-domain": {"behavior": "domain"},
            "Direct-domain": {"behavior": "domain"},
            "China-domain": {"behavior": "domain"},
            "AI-domain": {"behavior": "domain"},
            "Global-domain": {"behavior": "domain"},
        }}
        result = collect_dns_domain_payloads(config, {
            "HTTPDNS-domain": ["dns-bypass.example"], "Direct-domain": ["direct.example"],
            "China-domain": ["cn.example"], "AI-domain": ["ai.example"], "Global-domain": ["global.example"],
        }, segment_roles={"HTTPDNS": "reject", "Direct": "direct", "China": "china", "AI": "ai", "Global": "global"})
        self.assertNotIn("dns-bypass.example", result["China"][0] + result["Global"][0])


if __name__ == "__main__":
    unittest.main()
