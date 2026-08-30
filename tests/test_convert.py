import tempfile
import unittest
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


class ProviderConversionTest(ConvertTestCase):
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
            self.assertEqual(dedup["rule-providers"]["sample-classical"]["path"], "./ruleset/merged-dedup/sample-classical.yaml")
            self.assertEqual(
                yaml.safe_load((dist / "merged-dedup/classical/sample.yaml").read_text()),
                {"payload": ["DOMAIN-SUFFIX,example.com", "PROCESS-NAME,App"]},
            )


class CompleteConfigRefreshTest(unittest.TestCase):
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

        refreshed = convert.refresh_complete_config(complete, generated)

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


if __name__ == "__main__":
    unittest.main()
