import json
import shutil
import tempfile
import unittest
from pathlib import Path

from scripts.singbox_export import SingBoxExportError, _groups, export_singbox


SING_BOX = shutil.which("sing-box") or "sing-box"


class SingBoxExportTest(unittest.TestCase):
    def test_canonical_names_do_not_use_policy_occurrence(self):
        config = {
            "rule-providers": {
                "Direct-domain": {"behavior": "domain"},
                "China-domain": {"behavior": "domain"},
            },
            "rules": ["RULE-SET,Direct-domain,DIRECT", "NETWORK,TCP,DIRECT", "RULE-SET,China-domain,DIRECT", "MATCH,DIRECT"],
        }
        groups = _groups(config)
        self.assertEqual([group["tag"] for group in groups], ["Direct", "China"])

    def test_canonical_no_resolve_variant_uses_semantic_suffix(self):
        config = {
            "rule-providers": {
                "China-domain": {"behavior": "domain"},
                "China-ip": {"behavior": "ipcidr"},
            },
            "rules": ["RULE-SET,China-domain,DIRECT", "RULE-SET,China-ip,DIRECT,no-resolve", "MATCH,DIRECT"],
        }
        groups = _groups(config)
        self.assertEqual([group["tag"] for group in groups], ["China", "China-no-resolve"])

    def test_committed_example_artifacts_use_canonical_tags(self):
        route = json.loads(Path("dist/generated/singbox-rules.json").read_text(encoding="utf-8"))["route"]
        tags = [item["tag"] for item in route["rule_set"]]
        self.assertEqual(tags, ["Direct", "AI", "Global", "China", "China-no-resolve"])
        self.assertFalse(any(tag.startswith("segment-") or tag == "China-2" for tag in tags))

    def test_provider_serialization_and_policy_preservation(self):
        config = {
            "rule-providers": {"A": {"behavior": "classical"}},
            "rules": ["RULE-SET,A,🤖 AI", "MATCH,DIRECT"],
        }
        with tempfile.TemporaryDirectory() as tmp:
            result = export_singbox(
                config,
                {"A": [
                    "DOMAIN,exact.example",
                    "DOMAIN-SUFFIX,suffix.example",
                    "DOMAIN-KEYWORD,needle",
                    "DOMAIN-WILDCARD,*.wild.example",
                    "IP-CIDR,192.0.2.0/24",
                    "IP-CIDR6,2001:db8::/32",
                    "SRC-IP-CIDR,198.51.100.0/24",
                    "DST-PORT,443",
                    "NETWORK,TCP",
                    "PROCESS-NAME,example",
                ]},
                Path(tmp), "https://example.test/repo", SING_BOX,
            )
            route = json.loads((Path(tmp) / "generated/singbox-rules.json").read_text())
            self.assertEqual(route["route"]["final"], "direct")
            self.assertEqual(route["route"]["rules"][0]["outbound"], "🤖 AI")
            self.assertEqual(result["segments"], 1)
            self.assertTrue((Path(tmp) / "singbox/segment-01-01.srs").exists())

    def test_sub_rule_udp_precedes_fallback_and_noncontiguous_policy_is_not_merged(self):
        config = {
            "sub-rules": {"AI-Routing": ["NETWORK,UDP,REJECT", "MATCH,🤖 AI"]},
            "rule-providers": {"A": {"behavior": "domain"}, "B": {"behavior": "domain"}, "C": {"behavior": "domain"}},
            "rules": ["RULE-SET,A,DIRECT", "RULE-SET,B,🤖 AI", "NETWORK,TCP,DIRECT", "RULE-SET,C,🤖 AI", "MATCH,DIRECT"],
        }
        with tempfile.TemporaryDirectory() as tmp:
            result = export_singbox(config, {"A": ["a.example"], "B": ["b.example"], "C": ["c.example"]}, Path(tmp), "https://x", SING_BOX)
            tags = [item["tag"] for item in result["route"]["route"]["rule_set"]]
            self.assertEqual(len(tags), 3)
            self.assertEqual([item["outbound"] for item in result["route"]["route"]["rules"] if "outbound" in item], ["direct", "🤖 AI", "direct", "🤖 AI"])

    def test_unsupported_rule_fails_closed(self):
        config = {"rule-providers": {"A": {"behavior": "classical"}}, "rules": ["RULE-SET,A,DIRECT"]}
        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaises(SingBoxExportError):
                export_singbox(config, {"A": ["GEOIP,CN"]}, Path(tmp), "https://x", SING_BOX)

    def test_asn_expansion_is_injected_and_source_is_not_mutated(self):
        config = {"rule-providers": {"A": {"behavior": "classical"}}, "rules": ["RULE-SET,A,DIRECT"]}
        payload = {"A": ["IP-ASN,64512", "SRC-IP-ASN,64512"]}
        with tempfile.TemporaryDirectory() as tmp:
            export_singbox(config, payload, Path(tmp), "https://x", SING_BOX, lambda _: {"64512": ["192.0.2.0/24", "2001:db8::/32"]})
            self.assertEqual(payload["A"], ["IP-ASN,64512", "SRC-IP-ASN,64512"])


if __name__ == "__main__":
    unittest.main()
