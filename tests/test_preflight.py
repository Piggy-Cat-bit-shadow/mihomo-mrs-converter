import tempfile
import unittest
from pathlib import Path

import yaml

from converter.preflight import PreflightError, run_preflight


class PreflightTest(unittest.TestCase):
    def make_config(
        self,
        root: Path,
        rules: list[str] | None = None,
        sub_rules: dict | None = None,
        providers: dict | None = None,
        segments: dict | None = None,
        export_config: dict | None = None,
    ) -> tuple[Path, Path, Path]:
        input_path = root / "rules.yaml"
        segment_path = root / "segment-names.yaml"
        export_path = root / "export.yaml"

        default_providers = {
            "BlockHttpDNS": {"type": "http", "behavior": "classical", "format": "yaml", "url": "https://example.test/dns.yaml"},
            "Lan": {"type": "http", "behavior": "classical", "format": "yaml", "url": "https://example.test/lan.yaml"},
            "me-pure": {"type": "http", "behavior": "classical", "format": "yaml", "url": "https://example.test/ai.yaml"},
            "Scholar-Foreign": {"type": "http", "behavior": "classical", "format": "yaml", "url": "https://example.test/global.yaml"},
            "apple": {"type": "http", "behavior": "classical", "format": "yaml", "url": "https://example.test/china.yaml"},
        }
        default_sub_rules = {
            "AI-Routing": ["NETWORK,UDP,REJECT", "MATCH,🤖 AI"]
        }
        default_rules = [
            "RULE-SET,BlockHttpDNS,REJECT",
            "RULE-SET,Lan,DIRECT",
            "SUB-RULE,(RULE-SET,me-pure),AI-Routing",
            "RULE-SET,Scholar-Foreign,🌍 国外流量",
            "RULE-SET,apple,DIRECT",
            "MATCH,🌍 国外流量",
        ]
        default_segments = {
            "segments": {
                "BlockHttpDNS": {"name": "HTTPDNS", "role": "reject", "reject-mode": "reject"},
                "Lan": {"name": "Direct", "role": "direct"},
                "me-pure": {"name": "AI", "role": "ai"},
                "Scholar-Foreign": {"name": "Global", "role": "global"},
                "apple": {"name": "China", "role": "china"},
            }
        }
        default_export = {
            "egern": {"policy-map": {"🏠 国内流量": "DIRECT"}},
            "singbox": {"policy-map": {"🏠 国内流量": "direct"}},
            "dns": {
                "groups": {
                    "China": {"roles": ["direct", "china"]},
                    "Global": {"roles": ["ai", "global"]},
                }
            }
        }

        input_path.write_text(yaml.safe_dump({
            "rule-providers": providers if providers is not None else default_providers,
            "sub-rules": sub_rules if sub_rules is not None else default_sub_rules,
            "rules": rules if rules is not None else default_rules,
        }, allow_unicode=True), encoding="utf-8")

        segment_path.write_text(yaml.safe_dump(
            segments if segments is not None else default_segments,
            allow_unicode=True
        ), encoding="utf-8")

        export_path.write_text(yaml.safe_dump(
            export_config if export_config is not None else default_export,
            allow_unicode=True
        ), encoding="utf-8")

        return input_path, segment_path, export_path

    def test_valid_config_passes_preflight(self):
        with tempfile.TemporaryDirectory() as tmp:
            input_path, segment_path, export_path = self.make_config(Path(tmp))
            run_preflight(input_path, segment_path, export_path)

    def test_missing_provider_fails_fast(self):
        with tempfile.TemporaryDirectory() as tmp:
            rules = ["RULE-SET,NonExistentProvider,DIRECT", "MATCH,DIRECT"]
            input_path, segment_path, export_path = self.make_config(Path(tmp), rules=rules)
            with self.assertRaisesRegex(PreflightError, "missing provider"):
                run_preflight(input_path, segment_path, export_path)

    def test_ruleset_without_policy_fails_fast(self):
        with tempfile.TemporaryDirectory() as tmp:
            # Rule with no policy
            rules = ["RULE-SET,Lan", "MATCH,DIRECT"]
            input_path, segment_path, export_path = self.make_config(Path(tmp), rules=rules)
            with self.assertRaisesRegex(PreflightError, "no policy"):
                run_preflight(input_path, segment_path, export_path)

    def test_reject_mode_mismatch_fails_fast(self):
        with tempfile.TemporaryDirectory() as tmp:
            # metadata specifies reject-mode: drop, but rule uses REJECT
            segments = {
                "segments": {
                    "BlockHttpDNS": {"name": "HTTPDNS", "role": "reject", "reject-mode": "drop"},
                    "Lan": {"name": "Direct", "role": "direct"},
                    "me-pure": {"name": "AI", "role": "ai"},
                    "Scholar-Foreign": {"name": "Global", "role": "global"},
                    "apple": {"name": "China", "role": "china"},
                }
            }
            input_path, segment_path, export_path = self.make_config(Path(tmp), segments=segments)
            with self.assertRaisesRegex(PreflightError, "production reject policy mismatch"):
                run_preflight(input_path, segment_path, export_path)

    def test_subrule_non_terminal_match_fails_fast(self):
        with tempfile.TemporaryDirectory() as tmp:
            sub_rules = {
                "AI-Routing": ["MATCH,🤖 AI", "NETWORK,UDP,REJECT"]
            }
            input_path, segment_path, export_path = self.make_config(Path(tmp), sub_rules=sub_rules)
            with self.assertRaisesRegex(PreflightError, "MATCH must be terminal"):
                run_preflight(input_path, segment_path, export_path)

    def test_export_config_invalid_singbox_policy_map_fails_fast(self):
        with tempfile.TemporaryDirectory() as tmp:
            export_config = {
                "singbox": {"policy-map": {"CUSTOM_ROUTE": "REJECT-DROP"}},
                "dns": {
                    "groups": {
                        "China": {"roles": ["direct", "china"]},
                    }
                },
            }
            input_path, segment_path, export_path = self.make_config(Path(tmp), export_config=export_config)
            with self.assertRaisesRegex(PreflightError, "cannot introduce intrinsic rejection policy"):
                run_preflight(input_path, segment_path, export_path)

    def test_export_config_dns_group_unknown_role_fails_fast(self):
        with tempfile.TemporaryDirectory() as tmp:
            export_config = {
                "dns": {
                    "groups": {
                        "China": {"roles": ["direct", "unknown_role"]},
                    }
                }
            }
            input_path, segment_path, export_path = self.make_config(Path(tmp), export_config=export_config)
            with self.assertRaisesRegex(PreflightError, "not assigned to any configured segment"):
                run_preflight(input_path, segment_path, export_path)

    def test_missing_terminal_match_fails_fast(self):
        with tempfile.TemporaryDirectory() as tmp:
            rules = ["RULE-SET,Lan,DIRECT"]
            input_path, segment_path, export_path = self.make_config(Path(tmp), rules=rules)
            with self.assertRaisesRegex(PreflightError, "no terminal MATCH"):
                run_preflight(input_path, segment_path, export_path)

    def test_decoupled_preflight_rules_only(self):
        with tempfile.TemporaryDirectory() as tmp:
            input_path, _, _ = self.make_config(Path(tmp))
            # Rules-only validation passes when rules are structurally valid
            run_preflight(input_path, None, None)

    def test_decoupled_preflight_segments_only(self):
        with tempfile.TemporaryDirectory() as tmp:
            _, segment_path, _ = self.make_config(Path(tmp))
            # Segment-only validation passes when segments are valid
            run_preflight(None, segment_path, None)

            # Invalid segment role fails fast in segment-only mode
            bad_seg = Path(tmp) / "bad-seg.yaml"
            bad_seg.write_text(yaml.safe_dump({"segments": {"Lan": {"name": "Direct", "role": "invalid_role"}}}))
            with self.assertRaisesRegex(PreflightError, "unknown role"):
                run_preflight(None, bad_seg, None)

    def test_decoupled_preflight_export_only(self):
        with tempfile.TemporaryDirectory() as tmp:
            _, _, export_path = self.make_config(Path(tmp))
            # Export-only validation passes when export configuration is valid
            run_preflight(None, None, export_path)

            # Invalid policy map fails fast in export-only mode
            bad_exp = Path(tmp) / "bad-exp.yaml"
            bad_exp.write_text(yaml.safe_dump({
                "singbox": {"policy-map": {"FOO": "REJECT-DROP"}},
                "dns": {"groups": {"China": {"roles": ["direct"]}}},
            }))
            with self.assertRaisesRegex(PreflightError, "cannot introduce intrinsic rejection policy"):
                run_preflight(None, None, bad_exp)

