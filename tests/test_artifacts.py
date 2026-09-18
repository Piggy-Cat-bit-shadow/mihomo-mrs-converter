import tempfile
import unittest
from pathlib import Path

from converter.artifacts import write_text_atomic, write_yaml_payload


class ArtifactsTest(unittest.TestCase):
    def test_atomic_and_payload_writes(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write_text_atomic(root / "nested/file.txt", "ok")
            write_yaml_payload(root / "payload.yaml", ["example.com"])
            self.assertEqual((root / "nested/file.txt").read_text(), "ok")
            self.assertTrue((root / "payload.yaml").exists())


if __name__ == "__main__":
    unittest.main()
