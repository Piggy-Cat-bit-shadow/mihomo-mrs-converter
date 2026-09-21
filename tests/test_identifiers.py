import os
import tempfile
import unittest
from pathlib import Path

from converter.identifiers import ensure_path_within, is_valid_artifact_id, validate_artifact_id


class IdentifiersTest(unittest.TestCase):
    def test_valid_artifact_identifiers(self):
        valid_cases = [
            "valid-name",
            "China-domain",
            "merged-segment-01-ip",
            "provider.123",
            "A_B_C",
            "v1.0.0",
        ]
        for name in valid_cases:
            self.assertTrue(is_valid_artifact_id(name), f"expected valid: {name}")
            self.assertEqual(validate_artifact_id(name), name)

    def test_invalid_artifact_identifiers(self):
        invalid_cases = [
            "",
            ".",
            "..",
            "../escape",
            "foo/bar",
            "foo\\bar",
            "name with spaces",
            "name\x00null",
            "name\nnewline",
            "name\ttab",
            "/absolute",
            "colon:test",
            "semi;test",
            "wild*card",
            "question?mark",
        ]
        for name in invalid_cases:
            self.assertFalse(is_valid_artifact_id(name), f"expected invalid: {name}")
            with self.assertRaises(SystemExit):
                validate_artifact_id(name)

    def test_ensure_path_within(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp).resolve()
            inside = base / "domain" / "valid.mrs"
            resolved = ensure_path_within(inside, base)
            self.assertEqual(resolved, inside.resolve())

            outside = base.parent / "escape.txt"
            with self.assertRaises(SystemExit):
                ensure_path_within(outside, base)

            traversal = base / "domain" / ".." / ".." / "escape.txt"
            with self.assertRaises(SystemExit):
                ensure_path_within(traversal, base)

    def test_ensure_path_within_symlink_escape(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp).resolve()
            outside = Path(tempfile.mkdtemp()).resolve()
            secret_file = outside / "secret.txt"
            secret_file.write_text("secret")

            symlink_dir = base / "linked"
            os.symlink(outside, symlink_dir)

            target = symlink_dir / "secret.txt"
            with self.assertRaises(SystemExit):
                ensure_path_within(target, base)


if __name__ == "__main__":
    unittest.main()
