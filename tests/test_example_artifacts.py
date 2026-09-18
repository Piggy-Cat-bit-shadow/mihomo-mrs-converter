import json
import unittest
from pathlib import Path

import yaml

from converter.artifacts import generated_artifact_path


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
        self.assertEqual(sorted(path.name for path in (DIST / "singbox").glob("*.srs")), [
            "AI-ip.srs", "AI.srs", "China-ip.srs", "China-no-resolve.srs", "China.srs",
            "Direct-no-resolve.srs", "Direct.srs", "Global-ip.srs", "Global-no-resolve.srs", "Global.srs",
        ])
        loon_names = sorted(path.name for path in (DIST / "loon").glob("*.lsr"))
        self.assertEqual(loon_names, ["AI-udp.lsr", "AI.lsr", "China.lsr", "Direct.lsr", "Global.lsr"])
        remote = (DIST / "generated/loon-rules.conf").read_text(encoding="utf-8")
        self.assertLess(remote.index("AI-udp.lsr"), remote.index("tag=AI,enabled=true"))
        singbox = json.loads((DIST / "generated/singbox-rules.json").read_text(encoding="utf-8"))
        self.assertEqual(len(singbox["route"]["rule_set"]), 4)
        self.assertEqual({item["tag"] for item in singbox["route"]["rule_set"]}, {"Direct", "AI", "Global", "China"})
        for item in singbox["route"]["rule_set"]:
            self.assertTrue((DIST / "singbox" / f"{item['tag']}.srs").exists())
        for name, provider in config["rule-providers"].items():
            artifact = generated_artifact_path(DIST, provider)
            self.assertIsNotNone(artifact, name)
            self.assertTrue(artifact.exists(), name)


if __name__ == "__main__":
    unittest.main()
