import tempfile
import unittest
import shutil
from pathlib import Path
from unittest.mock import patch

import yaml

from converter.model import BuildConfig
from converter.pipeline import build


class PipelineTest(unittest.TestCase):
    def test_prefetch_worker_count_keeps_final_outputs_identical(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            input_path = root / "input.yaml"
            input_path.write_text(yaml.safe_dump({
                "rule-providers": {
                    "Lan": {"type": "http", "behavior": "domain", "format": "yaml", "url": "https://example.invalid/a"},
                    "me-pure": {"type": "http", "behavior": "domain", "format": "yaml", "url": "https://example.invalid/b"},
                },
                "rules": ["RULE-SET,Lan,DIRECT", "RULE-SET,me-pure,DIRECT", "MATCH,DIRECT"],
            }))
            mihomo = shutil.which("mihomo")
            if not mihomo:
                self.skipTest("real mihomo binary is required")
            def fetch(url, headers, cache):
                return f"payload:\n- {url.rsplit('/', 1)[-1]}.example\n"
            no_op = {"route": {}}
            snapshots = []
            for workers, name in (("1", "dist-one"), ("8", "dist-eight")):
                dist = root / name
                with patch.dict("os.environ", {"PROVIDER_PREFETCH_WORKERS": workers}), patch("converter.net.fetch_text", side_effect=fetch), patch("converter.pipeline.export_egern", return_value=no_op), patch("converter.pipeline.export_loon", return_value=no_op), patch("converter.pipeline.export_singbox", return_value=no_op), patch("converter.pipeline.export_singbox_dns", return_value=no_op), patch("converter.pipeline.export_dns", return_value=no_op):
                    build(BuildConfig(input_path, dist, "https://example.invalid/repo/main", mihomo, None))
                snapshots.append({path.relative_to(dist): path.read_bytes() for path in dist.rglob("*") if path.is_file()})
            self.assertEqual(snapshots[0], snapshots[1])

    def test_sub_rule_provider_is_fetched_materialized_and_unused_is_skipped(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            input_path = root / "input.yaml"
            dist = root / "dist"
            input_path.write_text(yaml.safe_dump({
                "rule-providers": {
                    "OnlyInSubRule": {"type": "http", "behavior": "domain", "format": "yaml", "url": "https://example.invalid/used"},
                    "Unused": {"type": "http", "behavior": "domain", "format": "yaml", "url": "https://example.invalid/unused"},
                },
                "sub-rules": {"Example": ["RULE-SET,OnlyInSubRule,DIRECT"]},
                "rules": ["MATCH,DIRECT"],
            }))
            mihomo = shutil.which("mihomo")
            if not mihomo:
                self.skipTest("real mihomo binary is required")
            fetched = []
            def fetch(url, headers, cache):
                fetched.append(url)
                return "payload:\n- example.com\n"
            no_op = {"route": {}}
            with patch("converter.net.fetch_text", side_effect=fetch), patch("converter.pipeline.export_egern", return_value=no_op), patch("converter.pipeline.export_loon", return_value=no_op), patch("converter.pipeline.export_singbox", return_value=no_op), patch("converter.pipeline.export_singbox_dns", return_value=no_op), patch("converter.pipeline.export_dns", return_value=no_op):
                result = build(BuildConfig(input_path, dist, "https://example.invalid/repo/main", mihomo, None))
            self.assertEqual(fetched, ["https://example.invalid/used"])
            self.assertIn("OnlyInSubRule", result.final_config["rule-providers"])
            self.assertTrue((dist / "domain/OnlyInSubRule.mrs").exists())

    def test_build_is_atomic_and_has_no_semantic_stage_directories(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            input_path = root / "input.yaml"
            dist = root / "dist"
            input_path.write_text(yaml.safe_dump({
                "rule-providers": {
                    "Lan": {"type": "http", "behavior": "classical", "format": "yaml", "url": "https://example.invalid/direct"},
                    "me-pure": {"type": "http", "behavior": "domain", "format": "yaml", "url": "https://example.invalid/ai"},
                    "apple": {"type": "http", "behavior": "domain", "format": "yaml", "url": "https://example.invalid/china"},
                    "Scholar-Foreign": {"type": "http", "behavior": "domain", "format": "yaml", "url": "https://example.invalid/global"},
                },
                "sub-rules": {"AI-Routing": ["NETWORK,UDP,REJECT", "MATCH,🤖 AI"]},
                "rules": ["RULE-SET,Lan,DIRECT", "SUB-RULE,(RULE-SET,me-pure),AI-Routing", "RULE-SET,Scholar-Foreign,AI", "RULE-SET,apple,DIRECT", "MATCH,DIRECT"],
            }))
            responses = {
                "https://example.invalid/direct": "payload:\n- DOMAIN,direct.example\n",
                "https://example.invalid/ai": "payload:\n- +.ai.example\n",
                "https://example.invalid/china": "payload:\n- +.cn.example\n",
                "https://example.invalid/global": "payload:\n- +.global.example\n",
            }
            mihomo = shutil.which("mihomo")
            sing_box = shutil.which("sing-box")
            if not mihomo or not sing_box:
                self.skipTest("real exporter binaries are required")
            with patch("converter.net.fetch_text", side_effect=lambda url, headers, cache: responses[url]):
                result = build(BuildConfig(input_path, dist, "https://example.invalid/repo/main", mihomo, sing_box))
            self.assertEqual(len(result.final_config["rule-providers"]), 4)
            self.assertFalse(any(path.name.startswith("stage-") for path in dist.rglob("*")))
            self.assertTrue((dist / "loon/AI-udp.lsr").exists())

    def test_failed_export_rolls_back_dist_state_and_complete_config(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            input_path = root / "input.yaml"
            dist = root / "dist"
            dist.mkdir()
            (dist / "sentinel.txt").write_text("old-production", encoding="utf-8")
            state = root / ".state"
            state.mkdir()
            (state / "managed-state.yaml").write_text("version: 2\nbase_url: https://example.invalid/repo/main\nproviders: {}\n", encoding="utf-8")
            complete = root / "complete.yaml"
            complete.write_text("rule-providers: {Custom: {behavior: domain}}\nrules: [MATCH, DIRECT]\n", encoding="utf-8")
            complete_before = complete.read_bytes()
            state_before = (state / "managed-state.yaml").read_bytes()
            input_path.write_text(yaml.safe_dump({
                "rule-providers": {
                    "Lan": {"type": "http", "behavior": "classical", "format": "yaml", "url": "https://example.invalid/direct"},
                    "me-pure": {"type": "http", "behavior": "domain", "format": "yaml", "url": "https://example.invalid/ai"},
                },
                "rules": ["RULE-SET,Lan,DIRECT", "RULE-SET,me-pure,AI", "MATCH,DIRECT"],
            }))
            responses = {
                "https://example.invalid/direct": "payload:\n- DOMAIN,direct.example\n",
                "https://example.invalid/ai": "payload:\n- +.ai.example\n",
            }
            mihomo = shutil.which("mihomo")
            sing_box = shutil.which("sing-box")
            if not mihomo or not sing_box:
                self.skipTest("real exporter binaries are required")
            with patch("converter.net.fetch_text", side_effect=lambda url, headers, cache: responses[url]), patch(
                "converter.pipeline.export_loon", side_effect=RuntimeError("simulated exporter failure")
            ):
                with self.assertRaisesRegex(RuntimeError, "simulated exporter failure"):
                    build(BuildConfig(input_path, dist, "https://example.invalid/repo/main", mihomo, sing_box, complete))
            self.assertEqual((dist / "sentinel.txt").read_text(encoding="utf-8"), "old-production")
            self.assertEqual((state / "managed-state.yaml").read_bytes(), state_before)
            self.assertEqual(complete.read_bytes(), complete_before)
            self.assertFalse(any(path.name.startswith("mihomo-mrs-publish-") for path in root.iterdir()))


if __name__ == "__main__":
    unittest.main()
