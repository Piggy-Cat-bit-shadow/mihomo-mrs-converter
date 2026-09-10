import tempfile
import sys
import unittest
import contextlib
import io
from collections import Counter
from pathlib import Path
from unittest.mock import patch

import yaml

import scripts.convert as convert


BASE_URL = "https://raw.githubusercontent.com/owner/repo/main"


def http_provider(behavior: str = "classical", fmt: str = "yaml") -> dict[str, object]:
    return {
        "type": "http",
        "behavior": behavior,
        "format": fmt,
        "url": "https://example.com/rules.yaml",
        "path": f"./ruleset/source.{fmt}",
    }


class ConvertTestCase(unittest.TestCase):
    def build_options(
        self,
        dist: Path,
        providers: set[str] | None = None,
        mihomo: str | None = None,
    ) -> convert.BuildOptions:
        return convert.BuildOptions(
            dist=dist,
            base_url=BASE_URL,
            mihomo=mihomo,
            used_names=set(providers or set()),
            used_paths=set(),
            memory_cache={},
        )

    def process_with_text(
        self,
        name: str,
        provider: dict[str, object],
        remote_text: str,
        dist: Path,
        providers: set[str] | None = None,
        mihomo: str | None = None,
    ) -> convert.ProviderResult:
        with patch.object(convert, "fetch_text", return_value=remote_text):
            return convert.process_provider(
                name,
                provider,
                self.build_options(dist, providers or {name}, mihomo=mihomo),
            )


class SourceDomainValueTest(unittest.TestCase):
    def test_domain_keeps_exact_value(self) -> None:
        self.assertEqual(convert.source_domain_value(convert.parse_rule("DOMAIN,chatgpt.com")), "chatgpt.com")

    def test_domain_suffix_uses_mihomo_wildcard_root_form(self) -> None:
        self.assertEqual(
            convert.source_domain_value(convert.parse_rule("DOMAIN-SUFFIX,chatgpt.com")),
            "+.chatgpt.com",
        )

    def test_domain_suffix_strips_existing_leading_dot(self) -> None:
        self.assertEqual(
            convert.source_domain_value(convert.parse_rule("DOMAIN-SUFFIX,.chatgpt.com")),
            "+.chatgpt.com",
        )

    def test_domain_with_extra_field_is_not_convertible(self) -> None:
        self.assertIsNone(convert.source_domain_value(convert.parse_rule("DOMAIN,example.com,foo")))

    def test_domain_suffix_with_extra_field_is_not_convertible(self) -> None:
        self.assertIsNone(convert.source_domain_value(convert.parse_rule("DOMAIN-SUFFIX,example.com,foo")))

    def test_domain_no_resolve_is_not_convertible(self) -> None:
        self.assertIsNone(convert.source_domain_value(convert.parse_rule("DOMAIN,example.com,no-resolve")))

    def test_domain_suffix_no_resolve_is_not_convertible(self) -> None:
        self.assertIsNone(convert.source_domain_value(convert.parse_rule("DOMAIN-SUFFIX,example.com,no-resolve")))

    def test_domain_suffix_with_multiple_extra_fields_is_not_convertible(self) -> None:
            self.assertIsNone(convert.source_domain_value(convert.parse_rule("DOMAIN-SUFFIX,example.com,foo,bar")))


class NestedRulesetCompatibilityTest(unittest.TestCase):
    def setUp(self) -> None:
        self.replacements = {"A": ["A-domain", "A-ip", "A-classical"], "B": ["B-domain"]}
        self.behaviors = {"A-domain": "domain", "A-ip": "ipcidr", "A-classical": "classical", "B-domain": "domain"}

    def test_parenthesis_safe_tokenizer(self) -> None:
        self.assertEqual(convert.split_top_level_commas("SUB-RULE,(RULE-SET,A),Foo"), ["SUB-RULE", "(RULE-SET,A)", "Foo"])
        self.assertEqual(convert.split_top_level_commas("AND,((RULE-SET,A),(NETWORK,tcp)),DIRECT"), ["AND", "((RULE-SET,A),(NETWORK,tcp))", "DIRECT"])

    def test_finds_nested_references(self) -> None:
        self.assertEqual(convert.find_ruleset_refs("OR,((RULE-SET,A),(RULE-SET,B)),PROXY"), ["A", "B"])
        self.assertEqual(convert.find_ruleset_refs("SUB-RULE,(AND,((RULE-SET,A),(NETWORK,tcp))),Foo"), ["A"])

    def test_sub_rule_expands_and_keeps_modifier_behavior(self) -> None:
        self.assertEqual(
            convert.rewrite_rules(["SUB-RULE,(RULE-SET,A,no-resolve),Foo"], self.replacements, self.behaviors),
            ["SUB-RULE,(RULE-SET,A-domain),Foo", "SUB-RULE,(RULE-SET,A-ip,no-resolve),Foo", "SUB-RULE,(RULE-SET,A-classical),Foo"],
        )

    def test_complex_expression_uses_or_instead_of_copying_boolean_rule(self) -> None:
        rewritten = convert.rewrite_rules(["NOT,((RULE-SET,A)),DIRECT"], self.replacements, self.behaviors)[0]
        self.assertIn("OR,(", rewritten)
        self.assertNotIn("RULE-SET,A)", rewritten)
        self.assertEqual(convert.find_ruleset_refs(rewritten), ["A-domain", "A-ip", "A-classical"])

    def test_nested_references_count_as_used_and_validate(self) -> None:
        config = {"rule-providers": {"A": {}}, "rules": ["AND,((RULE-SET,A),(NETWORK,tcp)),DIRECT"]}
        convert.validate_no_orphan_providers(config)
        with self.assertRaises(SystemExit):
            convert.validate_generated_rulesets(["SUB-RULE,(RULE-SET,missing),Foo"], {"A"})

    def test_extra_top_level_fields_are_preserved_in_suite_materialization(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            config = {
                "sub-rules": {"Foo": ["NETWORK,udp,REJECT"]},
                "some-future-key": {"a": 1},
                "rule-providers": {},
                "rules": [],
            }
            output = convert.materialize_suite_config(config, "unmerged", Path(tmp), BASE_URL)
            self.assertEqual(output["sub-rules"], config["sub-rules"])
            self.assertEqual(output["some-future-key"], config["some-future-key"])


class ProviderConversionTest(ConvertTestCase):
    def test_ipcidr_metadata_backed_asn_becomes_classical_companion(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            dist = Path(tmp)
            result = self.process_with_text(
                "ChinaMax-ip",
                http_provider("ipcidr"),
                "# IP-ASN: 1\npayload:\n- 1.1.1.0/24\n- 132203\n",
                dist,
            )
            self.assertEqual(result.generated_names, ["ChinaMax-ip", "ChinaMax-classical"])
            self.assertEqual(
                yaml.safe_load((dist / "source/ipcidr/ChinaMax-ip.yaml").read_text()),
                {"payload": ["1.1.1.0/24"]},
            )
            self.assertEqual(
                yaml.safe_load((dist / "classical/ChinaMax-classical.yaml").read_text()),
                {"payload": ["IP-ASN,132203"]},
            )
            self.assertEqual(sum(result.original_rules.values()), 2)
            self.assertEqual(result.original_rules, result.rebuilt_rules)

    def test_ipcidr_does_not_guess_bare_number_as_asn(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaises(SystemExit):
                self.process_with_text("sample", http_provider("ipcidr"), "payload:\n- 132203\n", Path(tmp))

    def test_ipcidr_asn_metadata_count_must_match(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaises(SystemExit):
                self.process_with_text(
                    "sample", http_provider("ipcidr"), "# IP-ASN: 1\npayload:\n- 132203\n- 12345\n", Path(tmp)
                )

    def test_ipcidr_unknown_invalid_entry_fails(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaises(SystemExit):
                self.process_with_text("sample", http_provider("ipcidr"), "# IP-ASN: 1\npayload:\n- foo\n", Path(tmp))

    def test_ip_cidr_enters_ipcidr(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            dist = Path(tmp)
            result = self.process_with_text(
                "sample",
                http_provider(),
                "payload:\n- IP-CIDR,1.2.3.0/24\n",
                dist,
            )

            self.assertEqual(result.generated_names, ["sample-ip"])
            self.assertEqual(
                yaml.safe_load((dist / "source/ipcidr/sample.yaml").read_text()),
                {"payload": ["1.2.3.0/24"]},
            )

    def test_ip_cidr_no_resolve_stays_classical(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            dist = Path(tmp)
            result = self.process_with_text(
                "sample",
                http_provider(),
                "payload:\n- IP-CIDR,1.2.3.0/24,no-resolve\n",
                dist,
            )

            self.assertEqual(result.generated_names, ["sample-classical"])
            self.assertEqual(
                yaml.safe_load((dist / "classical/sample.yaml").read_text()),
                {"payload": ["IP-CIDR,1.2.3.0/24,no-resolve"]},
            )

    def test_ipv6_no_resolve_stays_classical(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            dist = Path(tmp)
            self.process_with_text(
                "sample",
                http_provider(),
                "payload:\n- IP-CIDR6,2001:db8::/32,no-resolve\n",
                dist,
            )

            self.assertEqual(
                yaml.safe_load((dist / "classical/sample.yaml").read_text()),
                {"payload": ["IP-CIDR6,2001:db8::/32,no-resolve"]},
            )

    def test_text_format_does_not_use_yaml_parser(self) -> None:
        self.assertEqual(
            convert.payload_from_remote("sample", "- DOMAIN,example.com\n# comment\n", "text"),
            ["- DOMAIN,example.com"],
        )

    def test_yaml_format_parses_payload(self) -> None:
        self.assertEqual(
            convert.payload_from_remote("sample", "payload:\n- DOMAIN,example.com\n", "yaml"),
            ["DOMAIN,example.com"],
        )

    def test_yaml_non_string_payload_fails(self) -> None:
        with self.assertRaises(SystemExit):
            convert.payload_from_remote("sample", "payload:\n- 123\n", "yaml")

    def test_empty_provider_fails(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaises(SystemExit):
                self.process_with_text("sample", http_provider(), "payload: []\n", Path(tmp))

    def test_mrs_domain_passthrough(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            provider = http_provider("domain", "mrs")
            provider["url"] = "https://example.com/rules.mrs"
            provider["path"] = "./ruleset/sample.mrs"
            result = convert.process_provider(
                "sample",
                provider,
                self.build_options(Path(tmp), {"sample"}),
            )

            self.assertEqual(result.generated_names, ["sample"])
            self.assertEqual(result.providers["sample"]["format"], "mrs")
            self.assertEqual(result.providers["sample"]["url"], "https://example.com/rules.mrs")

    def test_mrs_ipcidr_passthrough(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            provider = http_provider("ipcidr", "mrs")
            provider["url"] = "https://example.com/ip.mrs"
            provider["path"] = "./ruleset/ip.mrs"
            result = convert.process_provider(
                "sample",
                provider,
                self.build_options(Path(tmp), {"sample"}),
            )

            self.assertEqual(result.providers["sample"]["behavior"], "ipcidr")

    def test_mrs_classical_fails(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            provider = http_provider("classical", "mrs")
            provider["url"] = "https://example.com/rules.mrs"
            provider["path"] = "./ruleset/sample.mrs"
            with self.assertRaises(SystemExit):
                convert.process_provider("sample", provider, self.build_options(Path(tmp), {"sample"}))

    def test_provider_name_collision_does_not_overwrite(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            result = self.process_with_text(
                "sample",
                http_provider(),
                "payload:\n- DOMAIN,example.com\n",
                Path(tmp),
                {"sample", "sample-domain"},
            )

            self.assertEqual(result.generated_names, ["sample-mrs-domain"])

    def test_path_traversal_provider_name_fails(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaises(SystemExit):
                self.process_with_text("../evil", http_provider(), "payload:\n- DOMAIN,example.com\n", Path(tmp))

    def test_file_url_fails(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            provider = http_provider()
            provider["url"] = "file:///tmp/rules.yaml"
            with self.assertRaises(SystemExit):
                self.process_with_text("sample", provider, "payload:\n- DOMAIN,example.com\n", Path(tmp))

    def test_missing_ruleset_provider_fails(self) -> None:
        with self.assertRaises(SystemExit):
            convert.validate_top_level_rulesets(["RULE-SET,missing,DIRECT"], {"known"})

    def test_counter_detects_duplicate_count_changes(self) -> None:
        with self.assertRaises(SystemExit):
            convert.validate_rule_counts("sample", Counter({"A": 2}), Counter({"A": 1}))

    def test_fallback_uses_original_raw(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            dist = Path(tmp)
            raw = "PROCESS-NAME,  Example App  ,Proxy"
            self.process_with_text("sample", http_provider(), f"payload:\n- {raw}\n", dist)

            self.assertEqual(
                yaml.safe_load((dist / "classical/sample.yaml").read_text()),
                {"payload": [raw]},
            )

    def test_domain_rules_with_extra_fields_stay_in_classical_fallback(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            dist = Path(tmp)
            self.process_with_text(
                "sample",
                http_provider(),
                "\n".join(
                    [
                        "payload:",
                        "- DOMAIN,exact.example.com",
                        "- DOMAIN-SUFFIX,suffix.example.com",
                        "- DOMAIN,keep.example.com,some-option",
                        "- DOMAIN-SUFFIX,keep-suffix.example.com,some-option",
                    ]
                ),
                dist,
            )

            domain_payload = yaml.safe_load((dist / "source/domain/sample.yaml").read_text())["payload"]
            classical_payload = yaml.safe_load((dist / "classical/sample.yaml").read_text())["payload"]
            self.assertEqual(domain_payload, ["exact.example.com", "+.suffix.example.com"])
            self.assertNotIn("keep.example.com", domain_payload)
            self.assertNotIn("+.keep-suffix.example.com", domain_payload)
            self.assertEqual(
                classical_payload,
                [
                    "DOMAIN,keep.example.com,some-option",
                    "DOMAIN-SUFFIX,keep-suffix.example.com,some-option",
                ],
            )

    def test_allow_no_mihomo_uses_yaml_source_urls(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            dist = Path(tmp)
            result = self.process_with_text(
                "sample",
                http_provider("domain"),
                "payload:\n- example.com\n",
                dist,
            )

            provider = result.providers["sample"]
            self.assertEqual(provider["format"], "yaml")
            self.assertIn("/dist/source/domain/sample.yaml", provider["url"])
            self.assertNotIn(".mrs", provider["url"])

    def test_unmerged_rewrite_does_not_add_extra_ruleset_duplicates(self) -> None:
        rules = ["RULE-SET,A,Proxy", "RULE-SET,B,Proxy", "RULE-SET,B,Proxy"]
        replacements = {"A": ["A-domain"], "B": ["B-domain", "B-classical"]}
        behaviors = {"A-domain": "domain", "B-domain": "domain", "B-classical": "classical"}

        self.assertEqual(
            convert.rewrite_rules(rules, replacements, behaviors),
            [
                "RULE-SET,A-domain,Proxy",
                "RULE-SET,B-domain,Proxy",
                "RULE-SET,B-classical,Proxy",
                "RULE-SET,B-domain,Proxy",
                "RULE-SET,B-classical,Proxy",
            ],
        )

    def test_merged_rules_do_not_cross_non_ruleset_barriers(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            dist = Path(tmp)
            options = self.build_options(dist)
            rules = [
                "RULE-SET,A,Proxy",
                "RULE-SET,B,Proxy",
                "DOMAIN,barrier.example,Proxy",
                "RULE-SET,C,Proxy",
                "RULE-SET,D,Proxy",
            ]
            replacements = {name: [f"{name}-domain"] for name in "ABCD"}
            providers = {
                f"{name}-domain": {
                    "type": "http",
                    "behavior": "domain",
                    "format": "mrs",
                    "url": f"{BASE_URL}/dist/domain/{name}.mrs",
                    "path": f"./ruleset/{name}-domain.mrs",
                }
                for name in "ABCD"
            }
            behaviors = {name: "domain" for name in providers}
            source_payloads = {f"{name}-domain": [f"{name.lower()}.example"] for name in "ABCD"}

            merged = convert.build_merged_config(
                rules,
                replacements,
                providers,
                behaviors,
                source_payloads,
                options,
            )

            merged_rules = merged["rules"]
            self.assertEqual(
                merged_rules,
                [
                    "RULE-SET,merged-segment-01-domain,Proxy",
                    "DOMAIN,barrier.example,Proxy",
                    "RULE-SET,merged-segment-02-domain,Proxy",
                ],
            )
            first_payload = yaml.safe_load(
                (dist / "merged/source/domain/merged-segment-01-domain.yaml").read_text()
            )["payload"]
            second_payload = yaml.safe_load(
                (dist / "merged/source/domain/merged-segment-02-domain.yaml").read_text()
            )["payload"]
            self.assertEqual(first_payload, ["a.example", "b.example"])
            self.assertEqual(second_payload, ["c.example", "d.example"])
            convert.validate_no_orphan_providers(merged)

    def test_merged_rules_keep_domain_ipcidr_and_classical_separate(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            dist = Path(tmp)
            options = self.build_options(dist)
            rules = ["RULE-SET,A,Proxy,no-resolve", "RULE-SET,B,Proxy,no-resolve"]
            replacements = {
                "A": ["A-domain", "A-ip", "A-classical"],
                "B": ["B-domain", "B-ip", "B-classical"],
            }
            providers = {
                "A-domain": {"type": "http", "behavior": "domain", "format": "mrs", "url": f"{BASE_URL}/dist/domain/A.mrs", "path": "./ruleset/A-domain.mrs"},
                "A-ip": {"type": "http", "behavior": "ipcidr", "format": "mrs", "url": f"{BASE_URL}/dist/ipcidr/A.mrs", "path": "./ruleset/A-ip.mrs"},
                "A-classical": {"type": "http", "behavior": "classical", "format": "yaml", "url": f"{BASE_URL}/dist/classical/A.yaml", "path": "./ruleset/A-classical.yaml"},
                "B-domain": {"type": "http", "behavior": "domain", "format": "mrs", "url": f"{BASE_URL}/dist/domain/B.mrs", "path": "./ruleset/B-domain.mrs"},
                "B-ip": {"type": "http", "behavior": "ipcidr", "format": "mrs", "url": f"{BASE_URL}/dist/ipcidr/B.mrs", "path": "./ruleset/B-ip.mrs"},
                "B-classical": {"type": "http", "behavior": "classical", "format": "yaml", "url": f"{BASE_URL}/dist/classical/B.yaml", "path": "./ruleset/B-classical.yaml"},
            }
            behaviors = {name: provider["behavior"] for name, provider in providers.items()}
            source_payloads = {
                "A-domain": ["a.example"],
                "A-ip": ["10.0.0.0/8"],
                "B-domain": ["b.example"],
                "B-ip": ["192.168.0.0/16"],
            }

            merged = convert.build_merged_config(
                rules,
                replacements,
                providers,
                behaviors,
                source_payloads,
                options,
            )

            self.assertEqual(
                merged["rules"],
                [
                    "RULE-SET,merged-segment-01-domain,Proxy",
                    "RULE-SET,merged-segment-01-ip,Proxy,no-resolve",
                    "RULE-SET,A-classical,Proxy",
                    "RULE-SET,B-classical,Proxy",
                ],
            )
            self.assertEqual(merged["rule-providers"]["merged-segment-01-domain"]["behavior"], "domain")
            self.assertEqual(merged["rule-providers"]["merged-segment-01-ip"]["behavior"], "ipcidr")
            classical_providers = [
                name
                for name, provider in merged["rule-providers"].items()
                if provider["behavior"] == "classical"
            ]
            self.assertEqual(classical_providers, ["A-classical", "B-classical"])
            convert.validate_no_orphan_providers(merged)


class SafeDedupTest(ConvertTestCase):
    def test_domain_dedup_removes_exact_duplicates(self) -> None:
        output, stats = convert.dedup_domain_payload(["example.com", "example.com", "+.example.com"])

        self.assertEqual(output, ["+.example.com"])
        self.assertEqual(stats.exact_duplicates_removed, 1)
        self.assertEqual(stats.domain_covered_by_suffix, 1)

    def test_domain_dedup_removes_domains_covered_by_suffix(self) -> None:
        output, stats = convert.dedup_domain_payload(
            ["+.example.com", "example.com", "api.example.com", "a.b.example.com"]
        )

        self.assertEqual(output, ["+.example.com"])
        self.assertEqual(stats.domain_covered_by_suffix, 3)

    def test_domain_dedup_removes_child_suffixes_covered_by_parent(self) -> None:
        output, stats = convert.dedup_domain_payload(
            ["+.example.com", "+.api.example.com", "+.a.b.example.com"]
        )

        self.assertEqual(output, ["+.example.com"])
        self.assertEqual(stats.suffix_covered_by_parent_suffix, 2)

    def test_domain_dedup_keeps_uncovered_and_similar_domains(self) -> None:
        output, stats = convert.dedup_domain_payload(
            ["+.example.com", "notexample.com", "example.org", "+.other.example.org"]
        )

        self.assertEqual(output, ["+.example.com", "notexample.com", "example.org", "+.other.example.org"])
        self.assertEqual(stats.removed, 0)

    def test_ipcidr_dedup_removes_exact_duplicates(self) -> None:
        output, stats = convert.dedup_ipcidr_payload(["1.1.1.0/24", "1.1.1.0/24"])

        self.assertEqual(output, ["1.1.1.0/24"])
        self.assertEqual(stats.ipcidr_duplicates_removed, 1)

    def test_ipcidr_dedup_removes_ipv4_subnets_covered_by_parent(self) -> None:
        output, stats = convert.dedup_ipcidr_payload(
            ["1.1.0.0/16", "1.1.1.0/24", "1.1.1.1/32"]
        )

        self.assertEqual(output, ["1.1.0.0/16"])
        self.assertEqual(stats.ipcidr_covered_by_parent, 2)

    def test_ipcidr_dedup_removes_ipv6_subnets_covered_by_parent(self) -> None:
        output, stats = convert.dedup_ipcidr_payload(
            ["2001:db8::/32", "2001:db8:1::/48", "2001:db8:1::1/128"]
        )

        self.assertEqual(output, ["2001:db8::/32"])
        self.assertEqual(stats.ipcidr_covered_by_parent, 2)

    def test_ipcidr_dedup_keeps_uncovered_networks(self) -> None:
        output, stats = convert.dedup_ipcidr_payload(["1.1.1.0/24", "1.1.2.0/24", "2001:db9::/32"])

        self.assertEqual(output, ["1.1.1.0/24", "1.1.2.0/24", "2001:db9::/32"])
        self.assertEqual(stats.removed, 0)

    def test_dedup_config_keeps_classical_provider_payload_unchanged(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            dist = Path(tmp)
            classical_path = dist / "merged/classical/sample.yaml"
            convert.write_yaml_payload(classical_path, ["DOMAIN-SUFFIX,example.com", "PROCESS-NAME,App"])
            config = {
                "rule-providers": {
                    "sample-classical": {
                        "type": "http",
                        "behavior": "classical",
                        "format": "yaml",
                        "url": f"{BASE_URL}/dist/merged/classical/sample.yaml",
                        "path": "./ruleset/merged/sample-classical.yaml",
                    }
                },
                "rules": ["RULE-SET,sample-classical,Proxy"],
            }

            dedup, stats = convert.build_dedup_config(config, self.build_options(dist))

            self.assertEqual(stats, {})
            self.assertEqual(
                dedup["rule-providers"]["merged-segment-01-classical"]["path"],
                "./ruleset/merged-dedup/merged-segment-01-classical.yaml",
            )
            self.assertNotIn("sample-classical", dedup["rule-providers"])
            self.assertEqual(
                yaml.safe_load((dist / "merged-dedup/classical/merged-segment-01-classical.yaml").read_text()),
                {"payload": ["DOMAIN-SUFFIX,example.com", "PROCESS-NAME,App"]},
            )


class SuiteStatsTest(unittest.TestCase):
    def test_referenced_rule_counts_reads_final_sources(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            dist = Path(tmp)
            convert.write_yaml_payload(dist / "source/domain/domain.yaml", ["a", "b"])
            convert.write_yaml_payload(dist / "source/ipcidr/ip.yaml", ["1.1.1.0/24"])
            convert.write_yaml_payload(dist / "classical/classical.yaml", ["DOMAIN,example.com", "GEOIP,CN"])
            config = {"rule-providers": {
                "domain": {"behavior": "domain", "url": f"{BASE_URL}/dist/source/domain/domain.yaml"},
                "ip": {"behavior": "ipcidr", "url": f"{BASE_URL}/dist/source/ipcidr/ip.yaml"},
                "classical": {"behavior": "classical", "url": f"{BASE_URL}/dist/classical/classical.yaml"},
            }}
            counts = convert.referenced_rule_counts(config, dist)
            total = counts["domain"] + counts["ipcidr"] + counts["classical"]
            self.assertEqual(counts, Counter({"domain": 2, "ipcidr": 1, "classical": 2}))
            self.assertEqual(total, counts["domain"] + counts["ipcidr"] + counts["classical"])


class AdjacentClassicalConsolidationTest(ConvertTestCase):
    def make_config(
        self,
        dist: Path,
        rules: list[str],
        payloads: dict[str, list[str]],
        metadata: dict[str, dict[str, object]] | None = None,
    ) -> dict[str, object]:
        providers: dict[str, dict[str, object]] = {}
        for name, payload in payloads.items():
            convert.write_yaml_payload(dist / "merged-dedup/classical" / f"{name}.yaml", payload)
            behavior = "domain" if name.endswith("-domain") else "ipcidr" if name.endswith("-ip") else "classical"
            provider = {
                "type": "http",
                "behavior": behavior,
                "format": "yaml",
                "url": f"{BASE_URL}/dist/merged-dedup/classical/{name}.yaml",
                "path": f"./ruleset/merged-dedup/{name}.yaml",
            }
            provider.update((metadata or {}).get(name, {}))
            providers[name] = provider
        return {"rule-providers": providers, "rules": rules}

    def consolidate(
        self,
        rules: list[str],
        payloads: dict[str, list[str]],
        metadata: dict[str, dict[str, object]] | None = None,
    ) -> tuple[dict[str, object], Path]:
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        dist = Path(tmp.name)
        config = self.make_config(dist, rules, payloads, metadata)
        result = convert.merge_adjacent_classical_providers(config, self.build_options(dist))
        return result, dist

    def test_adjacent_classical_providers_merge_in_order(self) -> None:
        result, dist = self.consolidate(
            ["RULE-SET,A-classical,Proxy", "RULE-SET,B-classical,Proxy"],
            {"A-classical": ["A1", "A2"], "B-classical": ["B1", "B2"]},
        )

        self.assertEqual(result["rules"], ["RULE-SET,merged-classical-01,Proxy"])
        self.assertEqual(
            yaml.safe_load((dist / "merged-dedup/classical/merged-classical-01.yaml").read_text()),
            {"payload": ["A1", "A2", "B1", "B2"]},
        )
        self.assertNotIn("A-classical", result["rule-providers"])
        self.assertNotIn("B-classical", result["rule-providers"])
        self.assertEqual(result["rule-providers"]["merged-classical-01"]["behavior"], "classical")
        self.assertEqual(result["rule-providers"]["merged-classical-01"]["format"], "yaml")

    def test_classical_merge_preserves_duplicates(self) -> None:
        result, dist = self.consolidate(
            ["RULE-SET,A-classical,Proxy", "RULE-SET,B-classical,Proxy"],
            {"A-classical": ["DOMAIN,a.com", "DOMAIN,a.com"], "B-classical": ["DOMAIN,a.com"]},
        )

        provider = result["rule-providers"]["merged-classical-01"]
        payload = yaml.safe_load(
            (dist / "merged-dedup/classical/merged-classical-01.yaml").read_text()
        )["payload"]
        self.assertEqual(payload, ["DOMAIN,a.com", "DOMAIN,a.com", "DOMAIN,a.com"])
        self.assertEqual(provider["url"], f"{BASE_URL}/dist/merged-dedup/classical/merged-classical-01.yaml")

    def test_barriers_and_different_contexts_prevent_merge(self) -> None:
        for rules in (
            ["RULE-SET,A-classical,Proxy", "DOMAIN,barrier.example,Proxy", "RULE-SET,B-classical,Proxy"],
            ["RULE-SET,A-classical,Proxy", "RULE-SET,X-domain,Proxy", "RULE-SET,B-classical,Proxy"],
            ["RULE-SET,A-classical,DIRECT", "RULE-SET,B-classical,Proxy"],
        ):
            with self.subTest(rules=rules):
                classical = {"A-classical": ["A1"], "B-classical": ["B1"]}
                if "X-domain" in rules:
                    classical["X-domain"] = ["X1"]
                result, _ = self.consolidate(rules, classical)
                self.assertNotIn("merged-classical-01", result["rule-providers"])
                self.assertEqual(result["rules"], rules)

    def test_sub_rule_classical_providers_merge(self) -> None:
        result, _ = self.consolidate(
            [
                "SUB-RULE,(RULE-SET,A-classical),AI-Routing",
                "SUB-RULE,(RULE-SET,B-classical),AI-Routing",
            ],
            {"A-classical": ["A1"], "B-classical": ["B1"]},
        )

        self.assertEqual(result["rules"], ["SUB-RULE,(RULE-SET,merged-classical-01),AI-Routing"])

    def test_sub_rule_classical_can_cross_ipcidr(self) -> None:
        result, dist = self.consolidate(
            [
                "SUB-RULE,(RULE-SET,A-classical),AI-Routing",
                "SUB-RULE,(RULE-SET,X-ip),AI-Routing",
                "SUB-RULE,(RULE-SET,B-classical),AI-Routing",
            ],
            {"A-classical": ["A1"], "X-ip": ["X1"], "B-classical": ["B1"]},
        )

        self.assertEqual(
            result["rules"],
            [
                "SUB-RULE,(RULE-SET,merged-classical-01),AI-Routing",
                "SUB-RULE,(RULE-SET,X-ip),AI-Routing",
            ],
        )
        self.assertEqual(
            yaml.safe_load((dist / "merged-dedup/classical/merged-classical-01.yaml").read_text())["payload"],
            ["A1", "B1"],
        )

    def test_sub_rule_block_keeps_nonclassical_order_and_multiple_gaps(self) -> None:
        result, _ = self.consolidate(
            [
                "SUB-RULE,(RULE-SET,D-domain),AI-Routing",
                "SUB-RULE,(RULE-SET,A-classical),AI-Routing",
                "SUB-RULE,(RULE-SET,X-ip),AI-Routing",
                "SUB-RULE,(RULE-SET,B-classical),AI-Routing",
                "SUB-RULE,(RULE-SET,Y-domain),AI-Routing",
                "SUB-RULE,(RULE-SET,C-classical),AI-Routing",
            ],
            {
                "D-domain": ["D1"],
                "A-classical": ["A1"],
                "X-ip": ["X1"],
                "B-classical": ["B1"],
                "Y-domain": ["Y1"],
                "C-classical": ["C1"],
            },
        )

        self.assertEqual(
            result["rules"],
            [
                "SUB-RULE,(RULE-SET,D-domain),AI-Routing",
                "SUB-RULE,(RULE-SET,merged-classical-01),AI-Routing",
                "SUB-RULE,(RULE-SET,X-ip),AI-Routing",
                "SUB-RULE,(RULE-SET,Y-domain),AI-Routing",
            ],
        )

    def test_sub_rule_different_target_and_wrapper_are_barriers(self) -> None:
        cases = [
            [
                "SUB-RULE,(RULE-SET,A-classical),AI-Routing",
                "SUB-RULE,(RULE-SET,X-ip),Other-Routing",
                "SUB-RULE,(RULE-SET,B-classical),AI-Routing",
            ],
            [
                "SUB-RULE,(RULE-SET,A-classical),AI-Routing",
                "RULE-SET,X-ip,AI-Routing",
                "SUB-RULE,(RULE-SET,B-classical),AI-Routing",
            ],
        ]
        for rules in cases:
            with self.subTest(rules=rules):
                result, _ = self.consolidate(
                    rules,
                    {"A-classical": ["A1"], "X-ip": ["X1"], "B-classical": ["B1"]},
                )
                self.assertEqual(result["rules"], rules)

    def test_incompatible_metadata_does_not_merge(self) -> None:
        result, _ = self.consolidate(
            ["RULE-SET,A-classical,Proxy", "RULE-SET,B-classical,Proxy"],
            {"A-classical": ["A1"], "B-classical": ["B1"]},
            {
                "A-classical": {"proxy": "proxy-a"},
                "B-classical": {"proxy": "proxy-b"},
            },
        )

        self.assertEqual(result["rules"], ["RULE-SET,A-classical,Proxy", "RULE-SET,B-classical,Proxy"])

    def canonical_config(self, dist: Path, rules: list[str], behaviors: dict[str, str]) -> dict[str, object]:
        providers: dict[str, dict[str, object]] = {}
        for name, behavior in behaviors.items():
            folder = "classical" if behavior == "classical" else "source/" + ("ipcidr" if behavior == "ipcidr" else "domain")
            suffix = ".yaml"
            artifact = dist / "merged-dedup" / folder / f"{name}{suffix}"
            convert.write_yaml_payload(artifact, [f"{name}-payload"])
            providers[name] = {
                "type": "http",
                "behavior": behavior,
                "format": "yaml",
                "url": f"{BASE_URL}/dist/merged-dedup/{folder}/{name}.yaml",
                "path": f"./ruleset/merged-dedup/{name}.yaml",
            }
        return {"rule-providers": providers, "rules": rules}

    def test_logical_blocks_share_segment_ids_and_advance_globally(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            dist = Path(tmp)
            config = self.canonical_config(
                dist,
                [
                    "RULE-SET,D-domain,DIRECT",
                    "RULE-SET,Lan-classical,DIRECT",
                    "SUB-RULE,(RULE-SET,X-ip),AI-Routing",
                    "SUB-RULE,(RULE-SET,A-domain),AI-Routing",
                    "SUB-RULE,(RULE-SET,A-classical),AI-Routing",
                    "RULE-SET,B-domain,DIRECT",
                    "RULE-SET,B-classical,DIRECT",
                ],
                {
                    "D-domain": "domain",
                    "Lan-classical": "classical",
                    "A-domain": "domain",
                    "A-classical": "classical",
                    "X-ip": "ipcidr",
                    "B-domain": "domain",
                    "B-classical": "classical",
                },
            )
            result, _ = convert.canonicalize_dedup_provider_names(config, self.build_options(dist))

            self.assertEqual(
                result["rules"],
                [
                    "RULE-SET,merged-segment-01-domain,DIRECT",
                    "RULE-SET,merged-segment-01-classical,DIRECT",
                    "SUB-RULE,(RULE-SET,merged-segment-02-domain),AI-Routing",
                    "SUB-RULE,(RULE-SET,merged-segment-02-classical),AI-Routing",
                    "SUB-RULE,(RULE-SET,merged-segment-02-ip),AI-Routing",
                    "RULE-SET,merged-segment-03-domain,DIRECT",
                    "RULE-SET,merged-segment-03-classical,DIRECT",
                ],
            )
            self.assertNotIn("merged-classical-01", result["rule-providers"])
            for name in (
                "merged-segment-01-domain",
                "merged-segment-01-classical",
                "merged-segment-02-domain",
                "merged-segment-02-classical",
                "merged-segment-02-ip",
                "merged-segment-03-domain",
                "merged-segment-03-classical",
            ):
                provider = result["rule-providers"][name]
                self.assertTrue((dist / provider["url"].split("/dist/", 1)[1]).exists())
                self.assertTrue(provider["path"].endswith(f"/{name}.yaml"))


class SegmentNameMappingTest(ConvertTestCase):
    def test_mapping_renames_provider_artifact_and_nested_rules(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            dist = Path(tmp)
            artifact = dist / "merged-dedup" / "domain" / "merged-segment-02-domain.mrs"
            artifact.parent.mkdir(parents=True)
            artifact.write_bytes(b"mrs")
            config = {
                "rule-providers": {
                    "merged-segment-02-domain": {
                        "behavior": "domain", "format": "mrs",
                        "url": f"{BASE_URL}/dist/merged-dedup/domain/merged-segment-02-domain.mrs",
                        "path": "./ruleset/merged-dedup/merged-segment-02-domain.mrs",
                    }
                },
                "rules": ["SUB-RULE,(RULE-SET,merged-segment-02-domain),Proxy"],
            }
            result = convert.apply_segment_name_mapping(
                config, self.build_options(dist), {"merged-segment-02": "AI"}
            )
            self.assertIn("AI-domain", result["rule-providers"])
            self.assertNotIn("merged-segment-02-domain", result["rule-providers"])
            self.assertIn("RULE-SET,AI-domain", result["rules"][0])
            self.assertTrue((dist / "merged-dedup/domain/AI-domain.mrs").exists())

    def test_mapping_rejects_duplicate_and_invalid_names(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "segment-names.yaml").write_text(
                "segments:\n  merged-segment-01: China\n  merged-segment-02: China\n",
                encoding="utf-8",
            )
            with self.assertRaises(SystemExit):
                convert.load_segment_name_mapping(root)
            (root / "segment-names.yaml").write_text(
                "segments:\n  merged-segment-01: ../bad\n", encoding="utf-8"
            )
            with self.assertRaises(SystemExit):
                convert.load_segment_name_mapping(root)


class EgernExporterTest(unittest.TestCase):
    def test_top_level_network_exports_protocol_and_normalizes_case(self) -> None:
        self.assertEqual(convert.parse_egern_network_rule("NETWORK,UDP,TUIC"), ("udp", "TUIC"))
        self.assertEqual(convert.parse_egern_network_rule("network,udp,A"), ("udp", "A"))
        self.assertEqual(convert.parse_egern_network_rule("Network,TcP,B"), ("tcp", "B"))
        self.assertIsNone(convert.parse_egern_network_rule("NETWORK,UDP"))
        self.assertIsNone(convert.parse_egern_network_rule("NETWORK,UDP,A,extra"))
        self.assertIsNone(convert.parse_egern_network_rule("NETWORK,QUIC,A"))

        with tempfile.TemporaryDirectory() as tmp:
            output = Path(tmp) / "output"
            config = {"rule-providers": {}, "rules": ["NETWORK,UDP,TUIC", "network,tcp,Proxy", "MATCH,Foreign"]}
            convert.export_egern(config, Path(tmp) / "staging", output, BASE_URL)
            rules = yaml.safe_load((output / "generated/egern-rules.yaml").read_text())["rules"]
            self.assertEqual(rules, [
                {"protocol": {"match": "udp", "policy": "TUIC"}},
                {"protocol": {"match": "tcp", "policy": "Proxy"}},
                {"default": {"policy": "Foreign"}},
            ])

    def test_top_level_network_keeps_order_and_is_not_deduped_with_and_or_subrule(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            staging = Path(tmp) / "staging"
            output = Path(tmp) / "output"
            convert.write_yaml_payload(staging / "source/domain/Global-domain.yaml", ["example.com"])
            config = {
                "rule-providers": {"Global-domain": {"behavior": "domain", "format": "mrs", "url": f"{BASE_URL}/dist/domain/Global-domain.mrs"}},
                "sub-rules": {"Global-Routing": ["NETWORK,UDP,TUIC", "MATCH,Foreign"]},
                "rules": [
                    "RULE-SET,Global-domain,DIRECT",
                    "AND,((RULE-SET,Global-domain),(NETWORK,UDP)),TUIC",
                    "SUB-RULE,(RULE-SET,Global-domain),Global-Routing",
                    "NETWORK,UDP,TUIC",
                    "MATCH,Foreign",
                ],
            }
            convert.export_egern(config, staging, output, BASE_URL)
            rules = yaml.safe_load((output / "generated/egern-rules.yaml").read_text())["rules"]
            self.assertEqual([next(iter(rule)) for rule in rules], ["rule_set", "and", "rule_set", "protocol", "default"])
            self.assertEqual(rules[1]["and"]["policy"], "TUIC")
            self.assertEqual(rules[2]["rule_set"]["policy"], "Foreign")
            self.assertEqual(rules[3], {"protocol": {"match": "udp", "policy": "TUIC"}})

    def test_udp_and_ruleset_is_exported_strictly(self) -> None:
        self.assertEqual(
            convert.egern_udp_and_ruleset(
                "AND,((RULE-SET,Global-domain),(NETWORK,UDP)),TUIC"
            ),
            ("Global-domain", "TUIC"),
        )
        self.assertIsNone(
            convert.egern_udp_and_ruleset(
                "AND,((RULE-SET,Global-domain),(DST-PORT,443)),TUIC"
            )
        )
        with tempfile.TemporaryDirectory() as tmp:
            staging = Path(tmp) / "staging"
            output = Path(tmp) / "output"
            convert.write_yaml_payload(staging / "source/domain/Global-domain.yaml", ["example.com"])
            config = {
                "rule-providers": {"Global-domain": {"behavior": "domain", "format": "mrs", "url": f"{BASE_URL}/dist/domain/Global-domain.mrs"}},
                "rules": ["AND,((RULE-SET,Global-domain),(NETWORK,UDP)),TUIC"],
            }
            convert.export_egern(config, staging, output, BASE_URL)
            rules = yaml.safe_load((output / "generated/egern-rules.yaml").read_text())["rules"]
            self.assertEqual(rules[0]["and"]["policy"], "TUIC")

    def test_udp_and_uses_final_egern_segment_name(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            staging = Path(tmp) / "staging"
            output = Path(tmp) / "output"
            convert.write_yaml_payload(staging / "source/domain/Renamed-domain.yaml", ["example.com"])
            config = {
                "rule-providers": {
                    "Renamed-domain": {
                        "behavior": "domain",
                        "format": "mrs",
                        "url": f"{BASE_URL}/dist/domain/Renamed-domain.mrs",
                    }
                },
                "rules": ["AND,((RULE-SET,Renamed-domain),(NETWORK,udp)),Proxy"],
            }
            convert.export_egern(config, staging, output, BASE_URL)
            rules = yaml.safe_load((output / "generated/egern-rules.yaml").read_text())["rules"]
            self.assertEqual(
                rules[0]["and"]["match"][0]["rule_set"]["match"],
                f"{BASE_URL}/dist/egern/Renamed.yaml",
            )

    def test_production_global_rules_collapse_and_preserve_order(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            staging = Path(tmp) / "staging"
            output = Path(tmp) / "output"
            providers = {}
            for name, behavior, folder in (
                ("Global-domain", "domain", "domain"),
                ("Global-classical", "classical", "classical"),
                ("Global-ip", "ipcidr", "ipcidr"),
            ):
                source = staging / (f"source/{folder}/{name}.yaml" if behavior != "classical" else f"classical/{name}.yaml")
                convert.write_yaml_payload(source, ["example.com"] if behavior == "domain" else ["1.2.3.0/24"] if behavior == "ipcidr" else ["DOMAIN,example.com"])
                providers[name] = {"behavior": behavior, "format": "yaml", "url": f"{BASE_URL}/dist/{folder}/{name}.yaml"}
            sub_rules = {"Global-Routing": ["NETWORK,UDP,TUIC", "MATCH,Foreign"]}
            rules = [
                "SUB-RULE,(RULE-SET,Global-domain),Global-Routing",
                "SUB-RULE,(RULE-SET,Global-classical),Global-Routing",
                "SUB-RULE,(RULE-SET,Global-ip),Global-Routing",
                "MATCH,Foreign",
            ]
            convert.export_egern({"rule-providers": providers, "sub-rules": sub_rules, "rules": rules}, staging, output, BASE_URL)
            exported = yaml.safe_load((output / "generated/egern-rules.yaml").read_text())["rules"]
            self.assertEqual(len(exported), 3)
            self.assertEqual(exported[0]["and"]["policy"], "TUIC")
            self.assertEqual(exported[0]["and"]["match"][0]["rule_set"]["match"], f"{BASE_URL}/dist/egern/Global.yaml")
            self.assertEqual(exported[0]["and"]["match"][1], {"protocol": {"match": "udp"}})
            self.assertEqual(exported[1], {"rule_set": {"match": f"{BASE_URL}/dist/egern/Global.yaml", "policy": "Foreign", "update_interval": 172800}})
            self.assertEqual(exported[2], {"default": {"policy": "Foreign"}})

    def test_defined_sub_rule_expands_network_and_match_in_order(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            staging = Path(tmp) / "staging"
            output = Path(tmp) / "output"
            convert.write_yaml_payload(staging / "source/domain/AI-domain.yaml", ["example.com"])
            config = {
                "rule-providers": {
                    "AI-domain": {"behavior": "domain", "format": "mrs", "url": f"{BASE_URL}/dist/domain/AI-domain.mrs"},
                },
                "sub-rules": {"AI-Routing": ["NETWORK,UDP,REJECT", "MATCH,AI"]},
                "rules": ["SUB-RULE,(RULE-SET,AI-domain),AI-Routing"],
            }
            convert.export_egern(config, staging, output, BASE_URL)
            rules = yaml.safe_load((output / "generated/egern-rules.yaml").read_text())["rules"]
            self.assertEqual(rules[0]["and"]["policy"], "REJECT")
            self.assertEqual(rules[0]["and"]["match"][1], {"protocol": {"match": "udp"}})
            self.assertEqual(rules[1], {"rule_set": {"match": f"{BASE_URL}/dist/egern/AI.yaml", "policy": "AI", "update_interval": 172800}})

    def test_sub_rule_supports_tcp_udp_case_insensitively(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            staging = Path(tmp) / "staging"
            output = Path(tmp) / "output"
            convert.write_yaml_payload(staging / "source/domain/Foo-domain.yaml", ["example.com"])
            config = {
                "rule-providers": {"Foo-domain": {"behavior": "domain", "format": "mrs", "url": f"{BASE_URL}/dist/domain/Foo-domain.mrs"}},
                "sub-rules": {"Example": ["network,udp,A", "Network,Tcp,B", "MATCH,C"]},
                "rules": ["SUB-RULE,(RULE-SET,Foo-domain),Example"],
            }
            convert.export_egern(config, staging, output, BASE_URL)
            rules = yaml.safe_load((output / "generated/egern-rules.yaml").read_text())["rules"]
            self.assertEqual([rule["and"]["match"][1]["protocol"]["match"] for rule in rules[:2]], ["udp", "tcp"])
            self.assertEqual(rules[2]["rule_set"]["policy"], "C")

    def test_undefined_sub_rule_keeps_legacy_policy_fallback(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            staging = Path(tmp) / "staging"
            output = Path(tmp) / "output"
            convert.write_yaml_payload(staging / "source/domain/X-domain.yaml", ["example.com"])
            config = {
                "rule-providers": {"X-domain": {"behavior": "domain", "format": "mrs", "url": f"{BASE_URL}/dist/domain/X-domain.mrs"}},
                "rules": ["SUB-RULE,(RULE-SET,X-domain),LegacyPolicy"],
            }
            convert.export_egern(config, staging, output, BASE_URL)
            rules = yaml.safe_load((output / "generated/egern-rules.yaml").read_text())["rules"]
            self.assertEqual(rules[0]["rule_set"]["policy"], "LegacyPolicy")

    def test_unsupported_defined_sub_rule_skips_whole_expansion(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            staging = Path(tmp) / "staging"
            output = Path(tmp) / "output"
            convert.write_yaml_payload(staging / "source/domain/X-domain.yaml", ["example.com"])
            config = {
                "rule-providers": {"X-domain": {"behavior": "domain", "format": "mrs", "url": f"{BASE_URL}/dist/domain/X-domain.mrs"}},
                "sub-rules": {"Foo": ["DST-PORT,443,Proxy", "MATCH,DIRECT"]},
                "rules": ["SUB-RULE,(RULE-SET,X-domain),Foo"],
            }
            with contextlib.redirect_stdout(io.StringIO()) as captured:
                convert.export_egern(config, staging, output, BASE_URL)
            self.assertIn("SUB-RULE expansion skipped: Foo", captured.getvalue())
            self.assertEqual(yaml.safe_load((output / "generated/egern-rules.yaml").read_text())["rules"], [])

    def test_defined_sub_rule_covers_no_resolve_segment(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            staging = Path(tmp) / "staging"
            output = Path(tmp) / "output"
            convert.write_yaml_payload(staging / "source/domain/X-domain.yaml", ["example.com"])
            convert.write_yaml_payload(staging / "classical/X-classical.yaml", ["IP-CIDR,10.0.0.0/8,no-resolve"])
            config = {
                "rule-providers": {
                    "X-domain": {"behavior": "domain", "format": "mrs", "url": f"{BASE_URL}/dist/domain/X-domain.mrs"},
                    "X-classical": {"behavior": "classical", "format": "yaml", "url": f"{BASE_URL}/dist/classical/X-classical.yaml"},
                },
                "sub-rules": {"Foo": ["NETWORK,UDP,Proxy", "MATCH,DIRECT"]},
                "rules": ["SUB-RULE,(RULE-SET,X-domain),Foo"],
            }
            convert.export_egern(config, staging, output, BASE_URL)
            rules = yaml.safe_load((output / "generated/egern-rules.yaml").read_text())["rules"]
            self.assertEqual(len(rules), 4)
            self.assertEqual({rule["and"]["match"][0]["rule_set"]["match"] for rule in rules[:2]}, {f"{BASE_URL}/dist/egern/X.yaml", f"{BASE_URL}/dist/egern/X-no-resolve.yaml"})
            self.assertEqual({rule["rule_set"]["match"] for rule in rules[2:]}, {f"{BASE_URL}/dist/egern/X.yaml", f"{BASE_URL}/dist/egern/X-no-resolve.yaml"})

    def test_sub_rules_are_preserved_as_a_top_level_field(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            config = {"rule-providers": {}, "sub-rules": {"Foo": ["NETWORK,UDP,Proxy"]}, "rules": []}
            output = convert.materialize_suite_config(config, "unmerged", Path(tmp), BASE_URL)
            self.assertEqual(output["sub-rules"], config["sub-rules"])
            self.assertEqual(yaml.safe_load((Path(tmp) / "unmerged/generated/mihomo-rules.yaml").read_text())["sub-rules"], config["sub-rules"])


class EgernRuleSetOptimizationTest(unittest.TestCase):
    def test_domain_coverage_is_stable_and_label_bounded(self) -> None:
        optimized, removed = convert.optimize_egern_rule_set({
            "domain_set": ["www.example.com", "fakeexample.com"],
            "domain_suffix_set": ["a.example.com", "example.org", "example.com"],
        })
        self.assertEqual(optimized, {
            "domain_set": ["fakeexample.com"],
            "domain_suffix_set": ["example.org", "example.com"],
        })
        self.assertEqual(removed["exact_domains_covered_by_suffix"], 1)
        self.assertEqual(removed["child_suffixes_covered_by_parent"], 1)

    def test_domain_does_not_synthesize_parent_suffix(self) -> None:
        optimized, removed = convert.optimize_egern_rule_set({
            "domain_suffix_set": ["a.example.com", "b.example.com"],
        })
        self.assertEqual(optimized["domain_suffix_set"], ["a.example.com", "b.example.com"])
        self.assertEqual(removed["safe_semantic_duplicates"], 0)

    def test_cidr_coverage_is_separated_by_family_and_keeps_order(self) -> None:
        optimized, removed = convert.optimize_egern_rule_set({
            "ip_cidr_set": ["10.1.2.0/24", "10.0.0.0/8", "192.168.1.0/24", "10.128.0.0/9", "10.0.0.0/9"],
            "ip_cidr6_set": ["2001:db8:1::/48", "2001:db8::/32"],
        })
        self.assertEqual(optimized["ip_cidr_set"], ["10.0.0.0/8", "192.168.1.0/24"])
        self.assertEqual(optimized["ip_cidr6_set"], ["2001:db8::/32"])
        self.assertEqual(removed["ipv4_cidrs_covered_by_parent"], 3)
        self.assertEqual(removed["ipv6_cidrs_covered_by_parent"], 1)

    def test_cidr_does_not_merge_adjacent_networks(self) -> None:
        optimized, removed = convert.optimize_egern_rule_set({
            "ip_cidr_set": ["10.0.0.0/9", "10.128.0.0/9"],
        })
        self.assertEqual(optimized["ip_cidr_set"], ["10.0.0.0/9", "10.128.0.0/9"])
        self.assertEqual(removed["safe_semantic_duplicates"], 0)

    def test_no_resolve_and_unsupported_fields_are_isolated(self) -> None:
        optimized, removed = convert.optimize_egern_rule_set({
            "no_resolve": True,
            "ip_cidr_set": ["1.2.3.0/24", "1.2.3.0/25"],
            "domain_set": ["www.example.com"],
            "domain_keyword_set": ["example"],
            "domain_regex_set": [".*example.*"],
            "domain_wildcard_set": ["*.example.com"],
        })
        self.assertTrue(optimized["no_resolve"])
        self.assertEqual(optimized["ip_cidr_set"], ["1.2.3.0/24"])
        self.assertEqual(optimized["domain_set"], ["www.example.com"])
        self.assertEqual(removed["safe_semantic_duplicates"], 1)

    def test_payload_mapping_and_rule_flattening(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            staging = Path(tmp) / "staging"
            output = Path(tmp) / "output"
            convert.write_yaml_payload(staging / "merged-dedup/source/domain/AI-domain.yaml", ["example.com", "+.google.com"])
            convert.write_yaml_payload(staging / "merged-dedup/source/ipcidr/AI-ip.yaml", ["1.2.3.0/24", "2001:db8::/32"])
            convert.write_yaml_payload(staging / "merged-dedup/classical/AI-classical.yaml", ["DOMAIN-KEYWORD,chat", "DOMAIN-REGEX,^foo.*$", "DOMAIN-WILDCARD,clients*.google.com", "IP-ASN,132203", "NETWORK,udp", "DST-PORT,443", "IP-CIDR,10.0.0.0/8,no-resolve"])
            config = {"rule-providers": {
                "AI-domain": {"behavior": "domain", "format": "mrs", "url": f"{BASE_URL}/dist/merged-dedup/domain/AI-domain.mrs"},
                "AI-ip": {"behavior": "ipcidr", "format": "mrs", "url": f"{BASE_URL}/dist/merged-dedup/ipcidr/AI-ip.mrs"},
                "AI-classical": {"behavior": "classical", "format": "yaml", "url": f"{BASE_URL}/dist/merged-dedup/classical/AI-classical.yaml"},
            }, "rules": ["RULE-SET,AI-domain,Proxy", "SUB-RULE,(RULE-SET,AI-ip),Proxy", "RULE-SET,AI-classical,Proxy", "MATCH,DIRECT"]}
            convert.export_egern(config, staging, output, BASE_URL)
            data = yaml.safe_load((output / "egern/AI.yaml").read_text())
            self.assertEqual(data["domain_set"], ["example.com"])
            self.assertEqual(data["domain_suffix_set"], ["google.com"])
            self.assertEqual(data["ip_cidr_set"], ["1.2.3.0/24"])
            self.assertEqual(data["ip_cidr6_set"], ["2001:db8::/32"])
            self.assertEqual(data["domain_regex_set"], ["^foo.*$"])
            self.assertEqual(data["domain_wildcard_set"], ["clients*.google.com"])
            self.assertEqual(data["asn_set"], ["132203"])
            no_resolve = yaml.safe_load((output / "egern/AI-no-resolve.yaml").read_text())
            self.assertEqual(no_resolve["ip_cidr_set"], ["10.0.0.0/8"])
            self.assertIs(no_resolve["no_resolve"], True)
            rules = yaml.safe_load((output / "generated/egern-rules.yaml").read_text())["rules"]
            self.assertEqual(len([x for x in rules if "rule_set" in x]), 2)
            self.assertEqual(rules[-1], {"default": {"policy": "DIRECT"}})


class ManagedStatePathTest(unittest.TestCase):
    def test_managed_state_uses_state_directory(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            dist = Path(tmp) / "dist"
            manifest = convert.write_managed_manifest(dist, convert.FINAL_SUITE, BASE_URL, {})
            self.assertEqual(convert.read_managed_manifest(dist, convert.FINAL_SUITE), manifest)
            self.assertTrue((Path(tmp) / ".state/managed-state.yaml").exists())
            self.assertFalse((dist / "generated/managed-state.yaml").exists())


class CompleteConfigRefreshTest(unittest.TestCase):
    def provider(self, name: str, behavior: str = "domain") -> dict[str, object]:
        return {
            "type": "http",
            "behavior": behavior,
            "format": "yaml",
            "url": f"https://example.com/{name}.yaml",
            "path": f"./rule-providers/{name}.yaml",
        }

    def run_convert_cli(
        self,
        input_path: Path,
        dist: Path,
        remotes: dict[str, str],
        complete_config: Path | None = None,
    ) -> None:
        argv = [
            "convert.py",
            str(input_path),
            "--dist",
            str(dist),
            "--base-url",
            BASE_URL,
            "--allow-no-mihomo",
        ]
        if complete_config is not None:
            argv.extend(
                [
                    "--complete-config",
                    str(complete_config),
                    "--complete-output",
                    str(complete_config),
                    "--complete-suite",
                    "merged-dedup",
                ]
            )

        def fetch(url: str, headers: dict[str, object] | None, memory_cache: dict[str, str]) -> str:
            return remotes[url]

        with (
            patch.object(sys, "argv", argv),
            patch.object(convert, "fetch_text", side_effect=fetch),
            contextlib.redirect_stdout(io.StringIO()),
        ):
            convert.main()

    def write_input(self, path: Path, provider_names: list[str], rules: list[str]) -> None:
        data = {
            "rule-providers": {
                name: self.provider(name, "classical" if name in {"xxx", "s7a", "s7b"} else "domain")
                for name in provider_names
            },
            "rules": rules,
        }
        path.write_text(yaml.safe_dump(data, sort_keys=False), encoding="utf-8")

    def snapshot_files(self, root: Path) -> dict[str, bytes]:
        return {
            str(path.relative_to(root)): path.read_bytes()
            for path in sorted(root.rglob("*"))
            if path.is_file()
        }

    def test_refresh_removes_stale_managed_providers_and_rules(self) -> None:
        complete = {
            "proxies": [{"name": "keep-proxy", "type": "direct"}],
            "rule-providers": {
                "custom-provider": {
                    "type": "http",
                    "behavior": "domain",
                    "format": "yaml",
                    "url": "https://example.com/custom.yaml",
                    "path": "./rule-providers/custom.yaml",
                },
                "xxx-classical": {
                    "type": "http",
                    "behavior": "classical",
                    "format": "yaml",
                    "url": f"{BASE_URL}/dist/merged-dedup/classical/xxx.yaml",
                    "path": "./ruleset/merged-dedup/xxx-classical.yaml",
                },
                "merged-segment-06-domain": {
                    "type": "http",
                    "behavior": "domain",
                    "format": "mrs",
                    "url": f"{BASE_URL}/dist/merged-dedup/domain/merged-segment-06-domain.mrs",
                    "path": "./ruleset/merged-dedup/merged-segment-06-domain.mrs",
                },
                "merged-segment-07-domain": {
                    "type": "http",
                    "behavior": "domain",
                    "format": "mrs",
                    "url": f"{BASE_URL}/dist/merged-dedup/domain/merged-segment-07-domain.mrs",
                    "path": "./ruleset/merged-dedup/merged-segment-07-domain.mrs",
                },
                "merged-segment-07-ip": {
                    "type": "http",
                    "behavior": "ipcidr",
                    "format": "mrs",
                    "url": f"{BASE_URL}/dist/merged-dedup/ipcidr/merged-segment-07-ip.mrs",
                    "path": "./ruleset/merged-dedup/merged-segment-07-ip.mrs",
                },
            },
            "rules": [
                "DOMAIN,manual-before.example,DIRECT",
                "RULE-SET,merged-segment-06-domain,DIRECT",
                "RULE-SET,xxx-classical,DIRECT",
                "RULE-SET,merged-segment-07-domain,DIRECT",
                "RULE-SET,merged-segment-07-ip,DIRECT,no-resolve",
                "RULE-SET,custom-provider,Proxy",
                "MATCH,Proxy",
            ],
        }
        generated = {
            "rule-providers": {
                "merged-segment-06-domain": {
                    "type": "http",
                    "behavior": "domain",
                    "format": "mrs",
                    "url": f"{BASE_URL}/dist/merged-dedup/domain/merged-segment-06-domain.mrs",
                    "path": "./ruleset/merged-dedup/merged-segment-06-domain.mrs",
                }
            },
            "rules": ["RULE-SET,merged-segment-06-domain,DIRECT"],
        }

        old_managed = {
            name: provider
            for name, provider in complete["rule-providers"].items()
            if name != "custom-provider"
        }
        manifest = convert.build_managed_manifest("merged-dedup", BASE_URL, old_managed)

        refreshed = convert.refresh_complete_config(
            complete,
            generated,
            manifest,
            BASE_URL,
            "merged-dedup",
        )

        self.assertEqual(refreshed["proxies"], complete["proxies"])
        self.assertIn("custom-provider", refreshed["rule-providers"])
        self.assertIn("merged-segment-06-domain", refreshed["rule-providers"])
        self.assertNotIn("xxx-classical", refreshed["rule-providers"])
        self.assertNotIn("merged-segment-07-domain", refreshed["rule-providers"])
        self.assertNotIn("merged-segment-07-ip", refreshed["rule-providers"])
        self.assertEqual(
            refreshed["rules"],
            [
                "DOMAIN,manual-before.example,DIRECT",
                "RULE-SET,merged-segment-06-domain,DIRECT",
                "RULE-SET,custom-provider,Proxy",
                "MATCH,Proxy",
            ],
        )

    def test_refresh_does_not_inject_generated_plain_rules(self) -> None:
        complete = {
            "rule-providers": {
                "old-managed": {
                    "type": "http",
                    "behavior": "domain",
                    "format": "mrs",
                    "url": f"{BASE_URL}/dist/merged-dedup/domain/old-managed.mrs",
                    "path": "./ruleset/merged-dedup/old-managed.mrs",
                }
            },
            "rules": [
                "RULE-SET,old-managed,Proxy",
                "IP-CIDR,1.1.1.1/32,DIRECT,no-resolve",
                "GEOIP,CN,DIRECT",
                "MATCH,Proxy",
            ],
        }
        generated = {
            "rule-providers": {
                "new-managed": {
                    "type": "http",
                    "behavior": "domain",
                    "format": "mrs",
                    "url": f"{BASE_URL}/dist/merged-dedup/domain/new-managed.mrs",
                    "path": "./ruleset/merged-dedup/new-managed.mrs",
                }
            },
            "rules": [
                "RULE-SET,new-managed,Proxy",
                "IP-CIDR,1.1.1.1/32,DIRECT,no-resolve",
                "GEOIP,CN,DIRECT",
                "MATCH,Proxy",
            ],
        }
        manifest = convert.build_managed_manifest(
            "merged-dedup",
            BASE_URL,
            {"old-managed": complete["rule-providers"]["old-managed"]},
        )

        refreshed = convert.refresh_complete_config(
            complete,
            generated,
            manifest,
            BASE_URL,
            "merged-dedup",
        )

        self.assertEqual(refreshed["rules"].count("IP-CIDR,1.1.1.1/32,DIRECT,no-resolve"), 1)
        self.assertEqual(refreshed["rules"].count("GEOIP,CN,DIRECT"), 1)
        self.assertEqual(refreshed["rules"].count("MATCH,Proxy"), 1)

    def test_refresh_preserves_custom_provider_with_dist_url_or_ruleset_path(self) -> None:
        complete = {
            "rule-providers": {
                "custom-url": {
                    "type": "http",
                    "behavior": "domain",
                    "format": "mrs",
                    "url": "https://raw.githubusercontent.com/other/repo/main/dist/domain/custom.mrs",
                    "path": "./rule-providers/custom-url.mrs",
                },
                "custom-path": {
                    "type": "http",
                    "behavior": "domain",
                    "format": "mrs",
                    "url": "https://example.com/custom-path.mrs",
                    "path": "./ruleset/merged-dedup/custom-path.mrs",
                },
                "old-managed": {
                    "type": "http",
                    "behavior": "domain",
                    "format": "mrs",
                    "url": f"{BASE_URL}/dist/merged-dedup/domain/old-managed.mrs",
                    "path": "./ruleset/merged-dedup/old-managed.mrs",
                },
            },
            "rules": [
                "RULE-SET,custom-url,Proxy",
                "RULE-SET,old-managed,Proxy",
                "RULE-SET,custom-path,Proxy",
            ],
        }
        generated = {
            "rule-providers": {
                "new-managed": {
                    "type": "http",
                    "behavior": "domain",
                    "format": "mrs",
                    "url": f"{BASE_URL}/dist/merged-dedup/domain/new-managed.mrs",
                    "path": "./ruleset/merged-dedup/new-managed.mrs",
                }
            },
            "rules": ["RULE-SET,new-managed,Proxy"],
        }
        manifest = convert.build_managed_manifest(
            "merged-dedup",
            BASE_URL,
            {"old-managed": complete["rule-providers"]["old-managed"]},
        )

        refreshed = convert.refresh_complete_config(
            complete,
            generated,
            manifest,
            BASE_URL,
            "merged-dedup",
        )

        self.assertIn("custom-url", refreshed["rule-providers"])
        self.assertIn("custom-path", refreshed["rule-providers"])
        self.assertIn("RULE-SET,custom-url,Proxy", refreshed["rules"])
        self.assertIn("RULE-SET,custom-path,Proxy", refreshed["rules"])

    def test_first_migration_uses_base_url_suite_url_not_path_guess(self) -> None:
        complete = {
            "rule-providers": {
                "custom-path": {
                    "type": "http",
                    "behavior": "domain",
                    "format": "mrs",
                    "url": "https://example.com/custom-path.mrs",
                    "path": "./ruleset/merged-dedup/custom-path.mrs",
                },
                "old-managed": {
                    "type": "http",
                    "behavior": "domain",
                    "format": "mrs",
                    "url": f"{BASE_URL}/dist/merged-dedup/domain/old-managed.mrs",
                    "path": "./ruleset/merged-dedup/old-managed.mrs",
                },
            },
            "rules": ["RULE-SET,old-managed,Proxy", "RULE-SET,custom-path,Proxy"],
        }
        generated = {
            "rule-providers": {
                "new-managed": {
                    "type": "http",
                    "behavior": "domain",
                    "format": "mrs",
                    "url": f"{BASE_URL}/dist/merged-dedup/domain/new-managed.mrs",
                    "path": "./ruleset/merged-dedup/new-managed.mrs",
                }
            },
            "rules": ["RULE-SET,new-managed,Proxy"],
        }

        refreshed = convert.refresh_complete_config(
            complete,
            generated,
            None,
            BASE_URL,
            "merged-dedup",
        )

        self.assertNotIn("old-managed", refreshed["rule-providers"])
        self.assertIn("custom-path", refreshed["rule-providers"])
        self.assertIn("RULE-SET,custom-path,Proxy", refreshed["rules"])

    def test_refresh_fails_when_generated_provider_collides_with_custom_provider(self) -> None:
        complete = {
            "rule-providers": {
                "new-managed": {
                    "type": "http",
                    "behavior": "domain",
                    "format": "mrs",
                    "url": "https://example.com/custom.mrs",
                    "path": "./rule-providers/custom.mrs",
                },
                "old-managed": {
                    "type": "http",
                    "behavior": "domain",
                    "format": "mrs",
                    "url": f"{BASE_URL}/dist/merged-dedup/domain/old-managed.mrs",
                    "path": "./ruleset/merged-dedup/old-managed.mrs",
                },
            },
            "rules": ["RULE-SET,old-managed,Proxy", "RULE-SET,new-managed,Proxy"],
        }
        generated = {
            "rule-providers": {
                "new-managed": {
                    "type": "http",
                    "behavior": "domain",
                    "format": "mrs",
                    "url": f"{BASE_URL}/dist/merged-dedup/domain/new-managed.mrs",
                    "path": "./ruleset/merged-dedup/new-managed.mrs",
                }
            },
            "rules": ["RULE-SET,new-managed,Proxy"],
        }
        manifest = convert.build_managed_manifest(
            "merged-dedup",
            BASE_URL,
            {"old-managed": complete["rule-providers"]["old-managed"]},
        )

        with self.assertRaises(SystemExit):
            convert.refresh_complete_config(
                complete,
                generated,
                manifest,
                BASE_URL,
                "merged-dedup",
            )

    def test_two_cli_runs_remove_stale_state_and_are_idempotent(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            dist = root / "dist"
            first_input = root / "first.yaml"
            second_input = root / "second.yaml"
            complete = root / "complete.yaml"

            first_names = [
                *[f"s{index}{suffix}" for index in range(1, 7) for suffix in ("a", "b")],
                "xxx",
                "s7a",
                "s7b",
            ]
            first_rules = [
                rule
                for index in range(1, 7)
                for rule in (
                    f"RULE-SET,s{index}a,P{index}",
                    f"RULE-SET,s{index}b,P{index}",
                    *(("RULE-SET,xxx,P6",) if index == 6 else ()),
                )
            ]
            first_rules.extend(["RULE-SET,s7a,P7,no-resolve", "RULE-SET,s7b,P7,no-resolve"])
            self.write_input(first_input, first_names, first_rules)
            first_remotes = {
                f"https://example.com/{name}.yaml": f"payload:\n- DOMAIN,{name}.example\n"
                for name in first_names
                if name not in {"xxx", "s7a", "s7b"}
            }
            first_remotes["https://example.com/xxx.yaml"] = "payload:\n- PROCESS-NAME,OldApp\n"
            first_remotes["https://example.com/s7a.yaml"] = "payload:\n- DOMAIN,s7a.example\n- IP-CIDR,10.7.1.0/24\n"
            first_remotes["https://example.com/s7b.yaml"] = "payload:\n- DOMAIN,s7b.example\n- IP-CIDR,10.7.2.0/24\n"

            self.run_convert_cli(first_input, dist, first_remotes)

            first_generated = yaml.safe_load((dist / "generated/mihomo-rules.yaml").read_text())
            old_complete = {
                "proxies": [{"name": "Custom", "type": "direct"}],
                "rule-providers": {
                    **first_generated["rule-providers"],
                    "custom-provider": {
                        "type": "http",
                        "behavior": "domain",
                        "format": "mrs",
                        "url": "https://raw.githubusercontent.com/other/repo/main/dist/domain/custom.mrs",
                        "path": "./ruleset/merged-dedup/custom.mrs",
                    },
                },
                "rules": [
                    *first_generated["rules"],
                    "RULE-SET,custom-provider,Custom",
                    "IP-CIDR,1.1.1.1/32,DIRECT,no-resolve",
                    "GEOIP,CN,DIRECT",
                    "MATCH,Custom",
                ],
            }
            complete.write_text(yaml.safe_dump(old_complete, sort_keys=False), encoding="utf-8")

            second_names = [
                *[f"s{index}{suffix}" for index in range(1, 7) for suffix in ("a", "b")],
                "xxx",
            ]
            second_rules = [
                rule
                for index in range(1, 7)
                for rule in (
                    f"RULE-SET,s{index}a,P{index}",
                    f"RULE-SET,s{index}b,P{index}",
                    *(("RULE-SET,xxx,P6",) if index == 6 else ()),
                )
            ]
            self.write_input(second_input, second_names, second_rules)
            second_remotes = {
                f"https://example.com/{name}.yaml": f"payload:\n- DOMAIN,{name}.example\n"
                for name in second_names
            }

            self.run_convert_cli(second_input, dist, second_remotes, complete)

            refreshed = yaml.safe_load(complete.read_text(encoding="utf-8"))
            providers = refreshed["rule-providers"]
            rules = refreshed["rules"]
            self.assertNotIn("xxx-classical", providers)
            self.assertNotIn("merged-segment-07-domain", providers)
            self.assertNotIn("merged-segment-07-ip", providers)
            self.assertFalse(any("xxx-classical" in rule for rule in rules if isinstance(rule, str)))
            self.assertFalse(any("merged-segment-07" in rule for rule in rules if isinstance(rule, str)))
            self.assertFalse((dist / "classical/xxx.yaml").exists())
            self.assertFalse((dist / "source/domain/merged-segment-07-domain.yaml").exists())
            self.assertFalse((dist / "source/ipcidr/merged-segment-07-ip.yaml").exists())
            self.assertIn("custom-provider", providers)
            self.assertIn("RULE-SET,custom-provider,Custom", rules)
            self.assertEqual(rules.count("IP-CIDR,1.1.1.1/32,DIRECT,no-resolve"), 1)
            self.assertEqual(rules.count("GEOIP,CN,DIRECT"), 1)
            self.assertEqual(rules.count("MATCH,Custom"), 1)
            self.assertLess(
                rules.index("RULE-SET,custom-provider,Custom"),
                rules.index("IP-CIDR,1.1.1.1/32,DIRECT,no-resolve"),
            )
            self.assertLess(
                rules.index("GEOIP,CN,DIRECT"),
                rules.index("MATCH,Custom"),
            )

            managed_rules = {
                convert.ruleset_provider_name(rule)
                for rule in rules
                if convert.ruleset_provider_name(rule) in providers
                and str(providers[convert.ruleset_provider_name(rule)]["url"]).startswith(f"{BASE_URL}/dist/")
            }
            managed_providers = {
                name
                for name, provider in providers.items()
                if str(provider["url"]).startswith(f"{BASE_URL}/dist/")
            }
            self.assertEqual(managed_providers, managed_rules)

            paths = [provider["path"] for provider in providers.values()]
            self.assertEqual(len(paths), len(set(paths)))
            for provider in managed_providers:
                artifact = dist / providers[provider]["url"].split("/dist/", 1)[1]
                self.assertTrue(artifact.exists(), artifact)

            complete_snapshot = complete.read_bytes()
            dist_snapshot = self.snapshot_files(dist)
            self.run_convert_cli(second_input, dist, second_remotes, complete)
            self.assertEqual(complete.read_bytes(), complete_snapshot)
            self.assertEqual(self.snapshot_files(dist), dist_snapshot)

    def test_refresh_fails_when_managed_provider_was_modified(self) -> None:
        old_managed = {
            "old-managed": {
                "type": "http",
                "behavior": "domain",
                "format": "mrs",
                "url": f"{BASE_URL}/dist/merged-dedup/domain/old-managed.mrs",
                "path": "./ruleset/merged-dedup/old-managed.mrs",
            }
        }
        manifest = convert.build_managed_manifest("merged-dedup", BASE_URL, old_managed)
        complete = {
            "rule-providers": {
                "old-managed": {
                    **old_managed["old-managed"],
                    "url": f"{BASE_URL}/dist/merged-dedup/domain/hand-edited.mrs",
                }
            },
            "rules": ["RULE-SET,old-managed,Proxy"],
        }
        generated = {"rule-providers": {}, "rules": []}

        with self.assertRaises(SystemExit):
            convert.refresh_complete_config(
                complete,
                generated,
                manifest,
                BASE_URL,
                "merged-dedup",
            )


if __name__ == "__main__":
    unittest.main()
