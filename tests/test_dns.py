import tempfile
import unittest
from pathlib import Path

from converter.export_config import DEFAULT_DNS_GROUPS
from converter.exporters.dns import export_dns
from converter.views import build_dns_views
from tests.support import provider


class DnsExporterTest(unittest.TestCase):
    def test_groups_are_fixed_and_payload_driven(self):
        providers = [
            provider("Direct-domain", "domain", ["direct.example"], segment="Direct"),
            provider("China-domain", "domain", ["cn.example"], segment="China"),
            provider("AI-domain", "domain", ["ai.example"], segment="AI"),
            provider("Global-domain", "domain", ["global.example"], segment="Global"),
        ]
        roles = {"Direct": "direct", "China": "china", "AI": "ai", "Global": "global"}
        result = build_dns_views(providers, roles, DEFAULT_DNS_GROUPS)
        self.assertEqual([entry.as_rule() for entry in result["China"].domains], ["direct.example", "cn.example"])
        self.assertEqual([entry.as_rule() for entry in result["Global"].domains], ["ai.example", "global.example"])

    def test_reject_role_is_valid_but_excluded_from_dns_groups(self):
        providers = [
            provider("HTTPDNS-domain", "domain", ["dns-bypass.example"], segment="HTTPDNS"),
            provider("Direct-domain", "domain", ["direct.example"], segment="Direct"),
            provider("China-domain", "domain", ["cn.example"], segment="China"),
            provider("AI-domain", "domain", ["ai.example"], segment="AI"),
            provider("Global-domain", "domain", ["global.example"], segment="Global"),
        ]
        roles = {"HTTPDNS": "reject", "Direct": "direct", "China": "china", "AI": "ai", "Global": "global"}
        result = build_dns_views(providers, roles, DEFAULT_DNS_GROUPS)
        self.assertNotIn(
            "dns-bypass.example",
            [entry.as_rule() for group in result.values() for entry in group.domains],
        )

    def test_dns_domains_are_deduplicated_after_merging_roles(self):
        providers = [
            provider("Direct-domain", "domain", ["shared.example", "direct.example"], segment="Direct"),
            provider("China-domain", "domain", ["shared.example", "cn.example"], segment="China"),
        ]
        roles = {"Direct": "direct", "China": "china", "AI": "ai", "Global": "global"}
        result = build_dns_views(providers, roles, DEFAULT_DNS_GROUPS)
        self.assertEqual(
            [entry.as_rule() for entry in result["China"].domains],
            ["shared.example", "direct.example", "cn.example"],
        )


    def test_dns_export_fails_closed_when_required_roles_are_missing(self):
        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaisesRegex(SystemExit, "requires missing segment"):
                export_dns({}, Path(tmp), "mihomo", required_roles={"direct"}, present_roles=set())


if __name__ == "__main__":
    unittest.main()
