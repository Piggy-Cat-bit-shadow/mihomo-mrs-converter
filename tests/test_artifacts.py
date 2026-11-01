import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from converter.artifacts import write_text_atomic, write_yaml_atomic, write_yaml_payload


class ArtifactsTest(unittest.TestCase):
    def test_atomic_and_payload_writes(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write_text_atomic(root / "nested/file.txt", "ok")
            write_yaml_payload(root / "payload.yaml", ["example.com"])
            self.assertEqual((root / "nested/file.txt").read_text(), "ok")
            self.assertTrue((root / "payload.yaml").exists())

    def test_failed_serialization_leaves_no_temporary_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            with self.assertRaises(Exception):
                write_yaml_atomic(root / "bad.yaml", {"value": object()})
            self.assertEqual(list(root.iterdir()), [])

    def test_failed_replace_keeps_previous_file_and_no_scratch_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            target = root / "state.yaml"
            write_yaml_atomic(target, {"value": 1})
            with patch("converter.artifacts.os.replace", side_effect=OSError("disk full")):
                with self.assertRaises(OSError):
                    write_yaml_atomic(target, {"value": 2})
            self.assertEqual(target.read_text(encoding="utf-8"), "value: 1\n")
            self.assertEqual(sorted(path.name for path in root.iterdir()), ["state.yaml"])


if __name__ == "__main__":
    unittest.main()
