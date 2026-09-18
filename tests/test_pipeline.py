import tempfile
import unittest
import shutil
from pathlib import Path
from unittest.mock import patch

import yaml

from converter.model import BuildConfig
from converter.pipeline import build


class PipelineTest(unittest.TestCase):
    def test_build_is_atomic_and_has_no_semantic_stage_directories(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            input_path = root / "input.yaml"
            dist = root / "dist"
            input_path.write_text(yaml.safe_dump({
                "rule-providers": {
                    "Direct": {"type": "http", "behavior": "classical", "format": "yaml", "url": "https://example.invalid/direct"},
                    "AI": {"type": "http", "behavior": "domain", "format": "yaml", "url": "https://example.invalid/ai"},
                    "China": {"type": "http", "behavior": "domain", "format": "yaml", "url": "https://example.invalid/china"},
                    "Global": {"type": "http", "behavior": "domain", "format": "yaml", "url": "https://example.invalid/global"},
                },
                "sub-rules": {"AI-Routing": ["NETWORK,UDP,REJECT", "MATCH,🤖 AI"]},
                "rules": ["RULE-SET,Direct,DIRECT", "SUB-RULE,(RULE-SET,AI),AI-Routing", "RULE-SET,China,DIRECT", "RULE-SET,Global,AI", "MATCH,DIRECT"],
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
            (state / "managed-state.yaml").write_text("version: 2\nproviders: {}\n", encoding="utf-8")
            complete = root / "complete.yaml"
            complete.write_text("rule-providers: {Custom: {behavior: domain}}\nrules: [MATCH, DIRECT]\n", encoding="utf-8")
            complete_before = complete.read_bytes()
            state_before = (state / "managed-state.yaml").read_bytes()
            input_path.write_text(yaml.safe_dump({
                "rule-providers": {
                    "Direct": {"type": "http", "behavior": "classical", "format": "yaml", "url": "https://example.invalid/direct"},
                    "AI": {"type": "http", "behavior": "domain", "format": "yaml", "url": "https://example.invalid/ai"},
                },
                "rules": ["RULE-SET,Direct,DIRECT", "RULE-SET,AI,AI", "MATCH,DIRECT"],
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
