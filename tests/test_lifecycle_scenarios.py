import os
import shutil
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import yaml

from converter.model import BuildConfig
from converter.pipeline import build
from converter.state import read_managed_manifest


class LifecycleScenariosTest(unittest.TestCase):
    def test_scenario_a_managed_lifecycle_refresh_rename_delete(self):
        """Scenario A: Verify full lifecycle from bootstrap/initial build through incremental refreshes."""
        mihomo = shutil.which("mihomo")
        if not mihomo:
            self.skipTest("real mihomo binary is required for lifecycle scenario")

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            input_path = root / "input.yaml"
            segment_path = root / "segment-names.yaml"
            complete_path = root / "complete.yaml"
            dist = root / "dist"

            # 1. Initial configuration with 2 providers: Direct and Global
            input_path.write_text(yaml.safe_dump({
                "rule-providers": {
                    "Lan": {"type": "http", "behavior": "domain", "format": "yaml", "url": "https://example.invalid/lan"},
                    "Scholar": {"type": "http", "behavior": "domain", "format": "yaml", "url": "https://example.invalid/scholar"},
                },
                "rules": ["RULE-SET,Lan,DIRECT", "RULE-SET,Scholar,Proxy", "MATCH,DIRECT"],
            }))
            segment_path.write_text(yaml.safe_dump({
                "segments": {
                    "Lan": {"name": "Direct", "role": "direct"},
                    "Scholar": {"name": "Global", "role": "global"},
                }
            }))

            def mock_fetch(url, headers, cache):
                name = url.rsplit("/", 1)[-1]
                return f"payload:\n- {name}.example\n"

            no_op = {"route": {}}
            with patch("converter.net.fetch_text", side_effect=mock_fetch), \
                 patch("converter.pipeline.export_egern", return_value=no_op), \
                 patch("converter.pipeline.export_loon", return_value=no_op), \
                 patch("converter.pipeline.export_singbox", return_value=no_op), \
                 patch("converter.pipeline.export_singbox_dns", return_value=no_op), \
                 patch("converter.pipeline.export_dns", return_value=no_op):
                build(BuildConfig(input_path, dist, "https://example.invalid/repo/main", mihomo, None, segment_names=segment_path))

            # Verify initial dist and state exist
            self.assertTrue((dist / ".generation").exists())
            manifest = read_managed_manifest(dist)
            self.assertIsNotNone(manifest)
            self.assertIn("Direct-domain", manifest["providers"])
            self.assertIn("Global-domain", manifest["providers"])

            # 2. Complete config with user customizations outside managed block
            first_generated = yaml.safe_load((dist / "generated" / "mihomo-rules.yaml").read_text(encoding="utf-8"))
            complete_path.write_text(yaml.safe_dump({
                "rule-providers": {
                    "Direct-domain": first_generated["rule-providers"]["Direct-domain"],
                    "Global-domain": first_generated["rule-providers"]["Global-domain"],
                    "UserCustom": {"type": "file", "behavior": "classical", "path": "./custom.yaml"},
                },
                "rules": [
                    "DOMAIN,user-first.com,DIRECT",
                    "RULE-SET,Direct-domain,DIRECT",
                    "RULE-SET,Global-domain,Proxy",
                    "DOMAIN,user-last.com,Proxy",
                    "MATCH,Proxy",
                ],
            }))

            # 3. Second build: update rule-providers (rename/modify: add AI provider, remove Global)
            input_path.write_text(yaml.safe_dump({
                "rule-providers": {
                    "Lan": {"type": "http", "behavior": "domain", "format": "yaml", "url": "https://example.invalid/lan"},
                    "me-pure": {"type": "http", "behavior": "domain", "format": "yaml", "url": "https://example.invalid/ai"},
                },
                "rules": ["RULE-SET,Lan,DIRECT", "RULE-SET,me-pure,Proxy", "MATCH,DIRECT"],
            }))
            segment_path.write_text(yaml.safe_dump({
                "segments": {
                    "Lan": {"name": "Direct", "role": "direct"},
                    "me-pure": {"name": "AI", "role": "ai"},
                }
            }))

            with patch("converter.net.fetch_text", side_effect=mock_fetch), \
                 patch("converter.pipeline.export_egern", return_value=no_op), \
                 patch("converter.pipeline.export_loon", return_value=no_op), \
                 patch("converter.pipeline.export_singbox", return_value=no_op), \
                 patch("converter.pipeline.export_singbox_dns", return_value=no_op), \
                 patch("converter.pipeline.export_dns", return_value=no_op):
                build(BuildConfig(input_path, dist, "https://example.invalid/repo/main", mihomo, None, segment_names=segment_path, complete_config=complete_path))

            # 4. Verify refreshed complete config preserves user rules and updates managed block
            refreshed_complete = yaml.safe_load(complete_path.read_text(encoding="utf-8"))
            self.assertIn("UserCustom", refreshed_complete["rule-providers"])
            self.assertIn("Direct-domain", refreshed_complete["rule-providers"])
            self.assertIn("AI-domain", refreshed_complete["rule-providers"])
            self.assertNotIn("Global-domain", refreshed_complete["rule-providers"])

            self.assertEqual(refreshed_complete["rules"], [
                "DOMAIN,user-first.com,DIRECT",
                "RULE-SET,Direct-domain,DIRECT",
                "RULE-SET,AI-domain,Proxy",
                "DOMAIN,user-last.com,Proxy",
                "MATCH,Proxy",
            ])

    def test_scenario_b_atomic_publish_rollback_on_export_failure(self):
        """Scenario B: If an exporter fails, dist and .state must not be corrupted."""
        mihomo = shutil.which("mihomo")
        if not mihomo:
            self.skipTest("real mihomo binary is required for rollback scenario")

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            input_path = root / "input.yaml"
            dist = root / "dist"

            input_path.write_text(yaml.safe_dump({
                "rule-providers": {
                    "Lan": {"type": "http", "behavior": "domain", "format": "yaml", "url": "https://example.invalid/lan"},
                },
                "rules": ["RULE-SET,Lan,DIRECT", "MATCH,DIRECT"],
            }))

            def mock_fetch(url, headers, cache):
                return "payload:\n- lan.example\n"

            no_op = {"route": {}}
            # Successful initial build
            with patch("converter.net.fetch_text", side_effect=mock_fetch), \
                 patch("converter.pipeline.export_egern", return_value=no_op), \
                 patch("converter.pipeline.export_loon", return_value=no_op), \
                 patch("converter.pipeline.export_singbox", return_value=no_op), \
                 patch("converter.pipeline.export_singbox_dns", return_value=no_op), \
                 patch("converter.pipeline.export_dns", return_value=no_op):
                build(BuildConfig(input_path, dist, "https://example.invalid/repo/main", mihomo, None))

            orig_generation = (dist / ".generation").read_text(encoding="utf-8")
            state_file = dist.parent / ".state" / "managed-state.yaml"
            orig_state = state_file.read_text(encoding="utf-8")

            # Second build where exporter raises an exception
            def failing_export(*args):
                raise RuntimeError("simulated exporter crash")

            with patch("converter.net.fetch_text", side_effect=mock_fetch), \
                 patch("converter.pipeline.export_egern", side_effect=failing_export), \
                 patch("converter.pipeline.export_loon", return_value=no_op), \
                 patch("converter.pipeline.export_singbox", return_value=no_op), \
                 patch("converter.pipeline.export_singbox_dns", return_value=no_op), \
                 patch("converter.pipeline.export_dns", return_value=no_op):
                with self.assertRaisesRegex(RuntimeError, "simulated exporter crash"):
                    build(BuildConfig(input_path, dist, "https://example.invalid/repo/main", mihomo, None))

            # Dist and state should remain 100% intact
            self.assertEqual((dist / ".generation").read_text(encoding="utf-8"), orig_generation)
            self.assertEqual(state_file.read_text(encoding="utf-8"), orig_state)

    def test_scenario_c_first_build_rollback_on_manifest_write_failure(self):
        """Scenario C: On first build, if write_managed_manifest fails, dist and .state must be cleaned up."""
        mihomo = shutil.which("mihomo")
        if not mihomo:
            self.skipTest("real mihomo binary is required for rollback scenario")

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            input_path = root / "input.yaml"
            dist = root / "dist"

            input_path.write_text(yaml.safe_dump({
                "rule-providers": {
                    "Lan": {"type": "http", "behavior": "domain", "format": "yaml", "url": "https://example.invalid/lan"},
                },
                "rules": ["RULE-SET,Lan,DIRECT", "MATCH,DIRECT"],
            }))

            def mock_fetch(url, headers, cache):
                return "payload:\n- lan.example\n"

            no_op = {"route": {}}

            def failing_manifest_write(*args, **kwargs):
                raise RuntimeError("simulated manifest write failure")

            with patch("converter.net.fetch_text", side_effect=mock_fetch), \
                 patch("converter.pipeline.export_egern", return_value=no_op), \
                 patch("converter.pipeline.export_loon", return_value=no_op), \
                 patch("converter.pipeline.export_singbox", return_value=no_op), \
                 patch("converter.pipeline.export_singbox_dns", return_value=no_op), \
                 patch("converter.pipeline.export_dns", return_value=no_op), \
                 patch("converter.pipeline.write_managed_manifest", side_effect=failing_manifest_write):
                with self.assertRaisesRegex(RuntimeError, "simulated manifest write failure"):
                    build(BuildConfig(input_path, dist, "https://example.invalid/repo/main", mihomo, None))

            # dist must NOT exist because it was a first build that failed
            self.assertFalse(dist.exists())
            state_file = dist.parent / ".state" / "managed-state.yaml"
            self.assertFalse(state_file.exists())
            self.assertFalse(dist.with_name(f".{dist.name}.previous").exists())

    def test_scenario_d_first_build_rollback_on_complete_config_write_failure(self):
        """Scenario D: On first build with complete config, failure writing complete config must clean up dist and state."""
        mihomo = shutil.which("mihomo")
        if not mihomo:
            self.skipTest("real mihomo binary is required for rollback scenario")

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            input_path = root / "input.yaml"
            segment_path = root / "segment-names.yaml"
            dist = root / "dist"
            complete_input = root / "complete_in.yaml"
            complete_output = root / "complete_out.yaml"

            input_path.write_text(yaml.safe_dump({
                "rule-providers": {
                    "Lan": {"type": "http", "behavior": "domain", "format": "yaml", "url": "https://example.invalid/lan"},
                },
                "rules": ["RULE-SET,Lan,DIRECT", "MATCH,DIRECT"],
            }))
            segment_path.write_text(yaml.safe_dump({
                "segments": {
                    "Lan": {"name": "Direct", "role": "direct"},
                }
            }))
            complete_input.write_text(yaml.safe_dump({
                "rule-providers": {
                    "Direct-domain": {"type": "http", "behavior": "domain", "format": "mrs", "url": "https://example.invalid/repo/main/dist/domain/Direct-domain.mrs", "path": "./ruleset/Direct-domain.mrs"},
                },
                "rules": ["RULE-SET,Direct-domain,DIRECT", "MATCH,DIRECT"],
            }))

            def mock_fetch(url, headers, cache):
                return "payload:\n- lan.example\n"

            no_op = {"route": {}}

            from converter.artifacts import write_yaml_atomic
            real_write_yaml = write_yaml_atomic

            def selective_fail_write(path, data):
                if Path(path) == complete_output:
                    raise RuntimeError("simulated complete output write crash")
                return real_write_yaml(path, data)

            with patch("converter.net.fetch_text", side_effect=mock_fetch), \
                 patch("converter.pipeline.export_egern", return_value=no_op), \
                 patch("converter.pipeline.export_loon", return_value=no_op), \
                 patch("converter.pipeline.export_singbox", return_value=no_op), \
                 patch("converter.pipeline.export_singbox_dns", return_value=no_op), \
                 patch("converter.pipeline.export_dns", return_value=no_op), \
                 patch("converter.pipeline.write_yaml_atomic", side_effect=selective_fail_write):
                with self.assertRaisesRegex(RuntimeError, "simulated complete output write crash"):
                    build(BuildConfig(
                        input_path,
                        dist,
                        "https://example.invalid/repo/main",
                        mihomo,
                        None,
                        segment_names=segment_path,
                        complete_config=complete_input,
                        complete_output=complete_output,
                        bootstrap_managed=True,
                    ))

            self.assertFalse(dist.exists())
            self.assertFalse((dist.parent / ".state" / "managed-state.yaml").exists())
            self.assertFalse(complete_output.exists())

    def test_scenario_e_subsequent_build_rollback_on_complete_config_write_failure(self):
        """Scenario E: On subsequent build, if complete config write fails, old dist, state, and complete output are restored."""
        mihomo = shutil.which("mihomo")
        if not mihomo:
            self.skipTest("real mihomo binary is required for rollback scenario")

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            input_path = root / "input.yaml"
            dist = root / "dist"
            complete_file = root / "complete.yaml"

            input_path.write_text(yaml.safe_dump({
                "rule-providers": {
                    "Lan": {"type": "http", "behavior": "domain", "format": "yaml", "url": "https://example.invalid/lan"},
                },
                "rules": ["RULE-SET,Lan,DIRECT", "MATCH,DIRECT"],
            }))

            def mock_fetch(url, headers, cache):
                return "payload:\n- lan.example\n"

            no_op = {"route": {}}

            # Build 1: successful initial build
            with patch("converter.net.fetch_text", side_effect=mock_fetch), \
                 patch("converter.pipeline.export_egern", return_value=no_op), \
                 patch("converter.pipeline.export_loon", return_value=no_op), \
                 patch("converter.pipeline.export_singbox", return_value=no_op), \
                 patch("converter.pipeline.export_singbox_dns", return_value=no_op), \
                 patch("converter.pipeline.export_dns", return_value=no_op):
                build(BuildConfig(input_path, dist, "https://example.invalid/repo/main", mihomo, None))

            generated_rules = (dist / "generated" / "mihomo-rules.yaml").read_text(encoding="utf-8")
            complete_file.write_text(generated_rules)

            orig_gen = (dist / ".generation").read_text(encoding="utf-8")
            state_file = dist.parent / ".state" / "managed-state.yaml"
            orig_state = state_file.read_bytes()
            orig_complete = complete_file.read_bytes()

            # Build 2: new provider added, but complete config write fails
            input_path.write_text(yaml.safe_dump({
                "rule-providers": {
                    "Lan": {"type": "http", "behavior": "domain", "format": "yaml", "url": "https://example.invalid/lan"},
                    "Wan": {"type": "http", "behavior": "domain", "format": "yaml", "url": "https://example.invalid/wan"},
                },
                "rules": ["RULE-SET,Lan,DIRECT", "RULE-SET,Wan,Proxy", "MATCH,DIRECT"],
            }))

            from converter.artifacts import write_yaml_atomic
            real_write_yaml = write_yaml_atomic

            def selective_fail_write(path, data):
                if Path(path) == complete_file:
                    raise RuntimeError("simulated complete write failure in build 2")
                return real_write_yaml(path, data)

            with patch("converter.net.fetch_text", side_effect=mock_fetch), \
                 patch("converter.pipeline.export_egern", return_value=no_op), \
                 patch("converter.pipeline.export_loon", return_value=no_op), \
                 patch("converter.pipeline.export_singbox", return_value=no_op), \
                 patch("converter.pipeline.export_singbox_dns", return_value=no_op), \
                 patch("converter.pipeline.export_dns", return_value=no_op), \
                 patch("converter.pipeline.write_yaml_atomic", side_effect=selective_fail_write):
                with self.assertRaisesRegex(RuntimeError, "simulated complete write failure in build 2"):
                    build(BuildConfig(
                        input_path,
                        dist,
                        "https://example.invalid/repo/main",
                        mihomo,
                        None,
                        complete_config=complete_file,
                    ))

            # Must restore original generation, state, and complete config byte-for-byte
            self.assertTrue(dist.exists())
            self.assertEqual((dist / ".generation").read_text(encoding="utf-8"), orig_gen)
            self.assertEqual(state_file.read_bytes(), orig_state)
            self.assertEqual(complete_file.read_bytes(), orig_complete)
            self.assertFalse(dist.with_name(f".{dist.name}.previous").exists())


if __name__ == "__main__":
    unittest.main()
