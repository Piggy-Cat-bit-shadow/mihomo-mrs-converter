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
        self.assertIn("outputs:\n      changed:", workflow)
        self.assertIn("actions/cache@55cc8345863c7cc4c66a329aec7e433d2d1c52a9 # v6.1.0", workflow)
        self.assertIn('paths-ignore:', workflow)
        self.assertIn("needs.verify.outputs.changed == 'true'", workflow)
        self.assertNotIn("Validate Sing-box rule sets", workflow)
        for line in workflow.splitlines():
            if "uses:" in line:
                self.assertRegex(line, r"uses:\s+[^@\s]+@[0-9a-f]{40}\s+#")
        verify = workflow.split("\n  publish:\n", 1)[0]
        publish = workflow.split("\n  publish:\n", 1)[1]
        self.assertIn("persist-credentials: false", verify)
        self.assertNotIn("persist-credentials: false", publish)

    def test_workflow_keeps_provider_refresh_uncached(self):
        root = Path(__file__).parents[1]
        workflow = (root / ".github/workflows/build.yml").read_text(encoding="utf-8")
        self.assertIn("python scripts/convert.py", workflow)
        self.assertIn("path: .cache/geolite2", workflow)
        self.assertNotIn("cache hit", workflow.lower())

    def test_ci_locks_dependencies_and_binary_digests(self):
        root = Path(__file__).parents[1]
        requirements = (root / "requirements-ci.txt").read_text(encoding="utf-8")
        workflow = (root / ".github/workflows/build.yml").read_text(encoding="utf-8")
        self.assertIn("PyYAML==", requirements)
        self.assertIn("certifi==", requirements)
        self.assertRegex(workflow, r"MIHOMO_SHA256: \"[0-9a-f]{64}\"")
        self.assertRegex(workflow, r"SING_BOX_SHA256: \"[0-9a-f]{64}\"")

    def test_geolite_source_is_pinned(self):
        root = Path(__file__).parents[1]
        source = (root / "converter/exporters/singbox.py").read_text(encoding="utf-8")
        data_sources = (root / "converter/data_sources.py").read_text(encoding="utf-8")
        self.assertNotIn("releases/latest", source)
        self.assertIn('GEOLITE2_RELEASE = "1789596753"', data_sources)
        self.assertEqual(data_sources.count('"sha256":'), 2)


if __name__ == "__main__":
    unittest.main()
