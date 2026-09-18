import tempfile
import unittest
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
            with patch("converter.net.fetch_text", side_effect=lambda url, headers, cache: responses[url]):
                result = build(BuildConfig(input_path, dist, "https://example.invalid/repo/main", "/Users/jie/.local/bin/mihomo", "/Users/jie/.local/bin/sing-box"))
            self.assertEqual(len(result.final_config["rule-providers"]), 4)
            self.assertFalse(any(path.name.startswith("stage-") for path in dist.rglob("*")))
            self.assertTrue((dist / "loon/AI-udp.lsr").exists())


if __name__ == "__main__":
    unittest.main()
