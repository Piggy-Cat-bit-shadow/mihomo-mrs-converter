import tempfile
import unittest
from pathlib import Path

import yaml

from converter.exporters.egern import export_egern


class EgernExporterTest(unittest.TestCase):
    def test_large_payload_deduplicates_in_first_seen_order(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            payload = [f"domain-{index}.example" for index in range(10000)]
            payload.extend([payload[0], payload[5000], payload[-1]])
            export_egern(
                {"rule-providers": {"China-domain": {"behavior": "domain"}}, "rules": []},
                {"China-domain": payload}, root, "https://example.invalid",
            )
            fields = yaml.safe_load((root / "egern/China.yaml").read_text())
            self.assertEqual(fields["domain_set"], payload[:10000])
            self.assertEqual(fields["domain_set"], sorted(fields["domain_set"], key=payload[:10000].index))

    def test_export_consumes_payload_mapping(self):
        with tempfile.TemporaryDirectory() as tmp:
            stats = export_egern({"rule-providers": {"AI-domain": {"behavior": "domain"}}, "rules": ["RULE-SET,AI-domain,AI"]}, {"AI-domain": ["example.com"]}, Path(tmp), "https://example.invalid")
            self.assertEqual(stats["segments"], 1)

    def test_top_level_destination_ip_rules_are_preserved_without_resolve(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            export_egern(
                {"rule-providers": {}, "rules": [
                    "IP-CIDR,0.0.0.0/32,REJECT-DROP,no-resolve",
                    "IP-CIDR6,::/128,REJECT-DROP,no-resolve",
                    "MATCH,🌍 国外流量",
                ]},
                {}, root, "https://example.invalid",
            )
            rules = yaml.safe_load((root / "generated/egern-rules.yaml").read_text())["rules"]
            self.assertEqual(rules[0]["ip_cidr"], {"match": "0.0.0.0/32", "policy": "REJECT-DROP", "no_resolve": True})
            self.assertEqual(rules[1]["ip_cidr6"], {"match": "::/128", "policy": "REJECT-DROP", "no_resolve": True})

    def test_domestic_policy_is_translated_at_all_egern_rule_entries(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            export_egern(
                {"rule-providers": {"Direct-domain": {"behavior": "domain"}, "China-domain": {"behavior": "domain"}},
                 "rules": ["RULE-SET,Direct-domain,🏠 国内流量", "RULE-SET,China-domain,🏠 国内流量", "MATCH,🏠 国内流量"]},
                {"Direct-domain": ["direct.example"], "China-domain": ["china.example"]}, root, "https://example.invalid",
                {"🏠 国内流量": "DIRECT"},
            )
            rules = yaml.safe_load((root / "generated/egern-rules.yaml").read_text())["rules"]
            self.assertEqual([item["rule_set"]["policy"] for item in rules[:2]], ["DIRECT", "DIRECT"])
            self.assertEqual(rules[-1]["default"]["policy"], "DIRECT")

    def test_other_policies_are_not_translated(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            export_egern({"rule-providers": {}, "rules": ["IP-CIDR,192.0.2.0/24,REJECT,no-resolve", "MATCH,🤖 AI"]}, {}, root, "https://example.invalid")
            rules = yaml.safe_load((root / "generated/egern-rules.yaml").read_text())["rules"]
            self.assertEqual(rules[0]["ip_cidr"]["policy"], "REJECT")
            self.assertEqual(rules[1]["default"]["policy"], "🤖 AI")


if __name__ == "__main__":
    unittest.main()
