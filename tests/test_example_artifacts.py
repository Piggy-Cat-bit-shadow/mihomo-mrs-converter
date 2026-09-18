import json
import unittest
from pathlib import Path

import yaml


ROOT = Path(__file__).resolve().parents[1]
DIST = ROOT / "dist"


class ExampleArtifactTest(unittest.TestCase):
    def test_committed_example_shape(self) -> None:
        config = yaml.safe_load((DIST / "generated/mihomo-rules.yaml").read_text(encoding="utf-8"))
        self.assertEqual(list(config["rule-providers"]), [
            "Direct-domain", "Direct-classical",
            "AI-domain", "AI-classical", "AI-ip",
            "Global-domain", "Global-classical", "Global-ip",
            "China-domain", "China-classical", "China-ip",
        ])
        self.assertFalse(any("-part-" in name for name in config["rule-providers"]))
        self.assertEqual(sorted(path.name for path in (DIST / "egern").glob("*.yaml")), ["AI.yaml", "China.yaml", "Direct.yaml", "Global.yaml"])
        self.assertEqual(sorted(path.name for path in (DIST / "singbox").glob("*.srs")), ["AI.srs", "China.srs", "Direct.srs", "Global.srs"])
        loon_names = sorted(path.name for path in (DIST / "loon").glob("*.lsr"))
        self.assertEqual(loon_names, ["AI-udp.lsr", "AI.lsr", "China.lsr", "Direct.lsr", "Global.lsr"])
        remote = (DIST / "generated/loon-rules.conf").read_text(encoding="utf-8")
        self.assertLess(remote.index("AI-udp.lsr"), remote.index("tag=AI,enabled=true"))
        singbox = json.loads((DIST / "generated/singbox-rules.json").read_text(encoding="utf-8"))
        self.assertEqual(len(singbox["route"]["rule_set"]), 4)


if __name__ == "__main__":
    unittest.main()
