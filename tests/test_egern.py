import tempfile
import unittest
from pathlib import Path

import yaml

from converter.exporters.egern import export_egern
from tests.support import optimized_config, provider, segment_views


class EgernExporterTest(unittest.TestCase):
    def test_large_payload_deduplicates_in_first_seen_order(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            payload = [f"domain-{index}.example" for index in range(10000)]
            payload.extend([payload[0], payload[5000], payload[-1]])
            config = optimized_config(providers=[provider("China-domain", "domain", payload, segment="China")])
            export_egern(config, segment_views(config), root, "https://example.invalid")
            fields = yaml.safe_load((root / "egern/China.yaml").read_text(encoding="utf-8"))
            self.assertEqual(fields["domain_set"], payload[:10000])
            self.assertEqual(fields["domain_set"], sorted(fields["domain_set"], key=payload[:10000].index))

    def test_export_consumes_segment_views(self):
        with tempfile.TemporaryDirectory() as tmp:
            config = optimized_config(
                providers=[provider("AI-domain", "domain", ["example.com"], segment="AI")],
                rules=["RULE-SET,AI-domain,AI"],
            )
            stats = export_egern(config, segment_views(config), Path(tmp), "https://example.invalid")
            self.assertEqual(stats["segments"], 1)

    def test_top_level_destination_ip_rules_are_preserved_without_resolve(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            config = optimized_config(rules=[
                "IP-CIDR,192.0.2.0/32,REJECT-DROP,no-resolve",
                "IP-CIDR6,2001:db8::1/128,REJECT-DROP,no-resolve",
                "MATCH,🌍 国外流量",
            ])
            export_egern(config, segment_views(config), root, "https://example.invalid")
            rules = yaml.safe_load((root / "generated/egern-rules.yaml").read_text(encoding="utf-8"))["rules"]
            self.assertEqual(rules[0]["ip_cidr"], {"match": "192.0.2.0/32", "policy": "REJECT-DROP", "no_resolve": True})
            self.assertEqual(rules[1]["ip_cidr6"], {"match": "2001:db8::1/128", "policy": "REJECT-DROP", "no_resolve": True})

    def test_domestic_policy_is_translated_at_all_egern_rule_entries(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            config = optimized_config(
                providers=[
                    provider("Direct-domain", "domain", ["direct.example"], segment="Direct"),
                    provider("China-domain", "domain", ["china.example"], segment="China"),
                ],
                rules=["RULE-SET,Direct-domain,🏠 国内流量", "RULE-SET,China-domain,🏠 国内流量", "MATCH,🏠 国内流量"],
            )
            export_egern(config, segment_views(config), root, "https://example.invalid", {"🏠 国内流量": "DIRECT"})
            rules = yaml.safe_load((root / "generated/egern-rules.yaml").read_text(encoding="utf-8"))["rules"]
            self.assertEqual([item["rule_set"]["policy"] for item in rules[:2]], ["DIRECT", "DIRECT"])
            self.assertEqual(rules[-1]["default"]["policy"], "DIRECT")

    def test_other_policies_are_not_translated(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            config = optimized_config(rules=["IP-CIDR,192.0.2.0/24,REJECT,no-resolve", "MATCH,🤖 AI"])
            export_egern(config, segment_views(config), root, "https://example.invalid")
            rules = yaml.safe_load((root / "generated/egern-rules.yaml").read_text(encoding="utf-8"))["rules"]
            self.assertEqual(rules[0]["ip_cidr"]["policy"], "REJECT")
            self.assertEqual(rules[1]["default"]["policy"], "🤖 AI")


    def test_undefined_sub_rule_is_rejected_instead_of_becoming_a_policy(self):
        with tempfile.TemporaryDirectory() as tmp:
            config = optimized_config(
                providers=[provider("AI-domain", "domain", ["ai.example"], segment="AI")],
                rules=["SUB-RULE,(RULE-SET,AI-domain),DoesNotExist", "MATCH,DIRECT"],
            )
            with self.assertRaisesRegex(ValueError, "SUB-RULE 'DoesNotExist' is not defined"):
                export_egern(config, segment_views(config), Path(tmp), "https://example.invalid")

    def test_non_terminal_match_in_sub_rule_is_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            config = optimized_config(
                providers=[provider("AI-domain", "domain", ["ai.example"], segment="AI")],
                rules=["SUB-RULE,(RULE-SET,AI-domain),R", "MATCH,DIRECT"],
                sub_rules={"R": ["MATCH,Proxy", "NETWORK,UDP,REJECT"]},
            )
            with self.assertRaisesRegex(ValueError, "unsupported SUB-RULE member"):
                export_egern(config, segment_views(config), Path(tmp), "https://example.invalid")


    def test_non_terminal_match_is_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            config = optimized_config(
                providers=[provider("AI-domain", "domain", ["ai.example"], segment="AI")],
                rules=["MATCH,DIRECT", "RULE-SET,AI-domain,AI"],
            )
            with self.assertRaisesRegex(ValueError, "Egern MATCH must be the final rule"):
                export_egern(config, segment_views(config), Path(tmp), "https://example.invalid")


if __name__ == "__main__":
    unittest.main()
