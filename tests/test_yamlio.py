import tempfile
import unittest
from pathlib import Path

from converter.yamlio import load_yaml_unique


class UniqueYamlTest(unittest.TestCase):
    def assert_duplicate(self, text: str, key: str) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "duplicate.yaml"
            path.write_text(text, encoding="utf-8")
            with self.assertRaisesRegex(SystemExit, rf"duplicate YAML key: '{key}'"):
                load_yaml_unique(path)

    def test_nested_duplicate_provider_key(self):
        self.assert_duplicate("rule-providers:\n  A: {}\n  A: {}\n", "A")

    def test_nested_duplicate_segment_anchor(self):
        self.assert_duplicate("segments:\n  Lan: {name: Direct, role: direct}\n  Lan: {name: Other, role: china}\n", "Lan")

    def test_nested_duplicate_policy_map_key(self):
        self.assert_duplicate("egern:\n  policy-map:\n    A: DIRECT\n    A: REJECT\n", "A")

    def test_deep_duplicate_key_is_rejected(self):
        self.assert_duplicate("outer:\n  inner:\n    value: 1\n    value: 2\n", "value")


if __name__ == "__main__":
    unittest.main()
