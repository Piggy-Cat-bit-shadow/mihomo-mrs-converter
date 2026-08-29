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


if __name__ == "__main__":
    unittest.main()
