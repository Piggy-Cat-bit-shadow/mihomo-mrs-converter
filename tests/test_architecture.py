import ast
import unittest
from pathlib import Path


class ArchitectureTest(unittest.TestCase):
    def test_core_and_stage_pipeline_are_gone(self):
        root = Path(__file__).parents[1]
        self.assertFalse((root / "converter/core.py").exists())
        source = "\n".join(path.read_text(encoding="utf-8") for path in (root / "converter").rglob("*.py"))
        self.assertNotIn("materialize_suite_config", source)
        self.assertNotIn('"stage-input"', source)
        self.assertNotIn('"stage-merge"', source)
        self.assertNotIn('"stage-final"', source)

    def test_production_modules_do_not_import_core(self):
        root = Path(__file__).parents[1] / "converter"
        for path in root.rglob("*.py"):
            self.assertNotIn("core", path.read_text(encoding="utf-8"), path.as_posix())

    def test_ci_separates_read_verify_from_write_publish_and_pins_actions(self):
        root = Path(__file__).parents[1]
        workflow = (root / ".github/workflows/build.yml").read_text(encoding="utf-8")
        self.assertIn("contents: read", workflow)
        self.assertIn("contents: write", workflow)
        self.assertIn("jobs:\n  verify:", workflow)
        self.assertIn("\n  publish:\n", workflow)
        for line in workflow.splitlines():
            if "uses:" in line:
                self.assertRegex(line, r"uses:\s+[0-9a-f]{40}\s+#")

    def test_ci_locks_dependencies_and_binary_digests(self):
        root = Path(__file__).parents[1]
        requirements = (root / "requirements-ci.txt").read_text(encoding="utf-8")
        workflow = (root / ".github/workflows/build.yml").read_text(encoding="utf-8")
        self.assertIn("PyYAML==", requirements)
        self.assertIn("certifi==", requirements)
        self.assertRegex(workflow, r"MIHOMO_SHA256: \"[0-9a-f]{64}\"")
        self.assertRegex(workflow, r"SING_BOX_SHA256: \"[0-9a-f]{64}\"")


if __name__ == "__main__":
    unittest.main()
