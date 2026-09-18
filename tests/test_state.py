import tempfile
import unittest
from pathlib import Path

from converter.state import build_managed_manifest, read_managed_manifest, write_managed_manifest


class StateTest(unittest.TestCase):
    def test_manifest_is_v2_without_suite(self):
        manifest = build_managed_manifest("https://example.invalid/repo/main", {"A": {"behavior": "domain", "url": "https://example.invalid/A.mrs", "path": "./ruleset/A.mrs"}})
        self.assertEqual(manifest["version"], 2)
        self.assertNotIn("suite", manifest)

    def test_v1_suite_is_ignored_on_read(self):
        with tempfile.TemporaryDirectory() as tmp:
            dist = Path(tmp) / "dist"
            state = Path(tmp) / ".state"
            state.mkdir()
            (state / "managed-state.yaml").write_text("version: 1\nsuite: stage-final\nproviders: {}\n")
            self.assertEqual(read_managed_manifest(dist)["version"], 1)


if __name__ == "__main__":
    unittest.main()
