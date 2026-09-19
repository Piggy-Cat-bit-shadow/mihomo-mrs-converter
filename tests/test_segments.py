import tempfile
import unittest
from pathlib import Path

from converter.segments import load_segment_specs, segment_mapping, segment_roles


class SegmentMetadataTest(unittest.TestCase):
    def write(self, root: Path, value: str) -> Path:
        path = root / "segments.yaml"
        path.write_text(value, encoding="utf-8")
        return path

    def test_loader_exposes_one_validated_identity_model(self):
        with tempfile.TemporaryDirectory() as tmp:
            specs = load_segment_specs(self.write(Path(tmp), """segments:
  ExampleReject:
    name: ExampleReject
    role: reject
"""))
        self.assertEqual(segment_mapping(specs), {"ExampleReject": "ExampleReject"})
        self.assertEqual(segment_roles(specs), {"ExampleReject": "reject"})

    def test_missing_role_is_fail_fast(self):
        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaisesRegex(SystemExit, "requires a non-empty string role"):
                load_segment_specs(self.write(Path(tmp), """segments:
  Example:
    name: Example
"""))

    def test_duplicate_names_are_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaisesRegex(SystemExit, "duplicate segment name"):
                load_segment_specs(self.write(Path(tmp), """segments:
  one: {name: Same, role: direct}
  two: {name: Same, role: reject}
"""))


if __name__ == "__main__":
    unittest.main()
