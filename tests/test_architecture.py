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


if __name__ == "__main__":
    unittest.main()
