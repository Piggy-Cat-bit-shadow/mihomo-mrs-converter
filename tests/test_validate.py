import tempfile
import unittest
from pathlib import Path

from converter.validate import validate_final_config


class ValidateTest(unittest.TestCase):
    def test_validate_final_config_passes_valid(self):
        with tempfile.TemporaryDirectory() as tmp:
            dist = Path(tmp)
            art_dir = dist / "domain"
            art_dir.mkdir(parents=True)
            art_file = art_dir / "Direct.mrs"
            art_file.write_bytes(b"data")

            config = {
                "rule-providers": {
                    "Direct": {
                        "type": "http",
                        "behavior": "domain",
                        "format": "mrs",
                        "url": "https://example.invalid/dist/domain/Direct.mrs",
                        "path": "./ruleset/Direct.mrs",
                    }
                },
                "rules": ["RULE-SET,Direct,DIRECT"],
            }
            validate_final_config(dist, config)

    def test_validate_final_config_rejects_missing_artifact(self):
        with tempfile.TemporaryDirectory() as tmp:
            dist = Path(tmp)
            config = {
                "rule-providers": {
                    "Direct": {
                        "type": "http",
                        "behavior": "domain",
                        "format": "mrs",
                        "url": "https://example.invalid/dist/domain/Direct.mrs",
                        "path": "./ruleset/Direct.mrs",
                    }
                },
                "rules": ["RULE-SET,Direct,DIRECT"],
            }
            with self.assertRaisesRegex(ValueError, "missing artifact"):
                validate_final_config(dist, config)

    def test_validate_final_config_rejects_orphan_provider(self):
        with tempfile.TemporaryDirectory() as tmp:
            dist = Path(tmp)
            art_dir = dist / "domain"
            art_dir.mkdir(parents=True)
            (art_dir / "Direct.mrs").write_bytes(b"data")
            (art_dir / "Orphan.mrs").write_bytes(b"data")

            config = {
                "rule-providers": {
                    "Direct": {
                        "type": "http",
                        "behavior": "domain",
                        "format": "mrs",
                        "url": "https://example.invalid/dist/domain/Direct.mrs",
                        "path": "./ruleset/Direct.mrs",
                    },
                    "Orphan": {
                        "type": "http",
                        "behavior": "domain",
                        "format": "mrs",
                        "url": "https://example.invalid/dist/domain/Orphan.mrs",
                        "path": "./ruleset/Orphan.mrs",
                    },
                },
                "rules": ["RULE-SET,Direct,DIRECT"],
            }
            with self.assertRaisesRegex(ValueError, "orphan provider"):
                validate_final_config(dist, config)

    def test_validate_final_config_rejects_duplicate_path(self):
        with tempfile.TemporaryDirectory() as tmp:
            dist = Path(tmp)
            config = {
                "rule-providers": {
                    "A": {"type": "http", "behavior": "domain", "format": "mrs", "url": "https://x/a.mrs", "path": "./ruleset/same.mrs"},
                    "B": {"type": "http", "behavior": "domain", "format": "mrs", "url": "https://x/b.mrs", "path": "./ruleset/same.mrs"},
                },
                "rules": ["RULE-SET,A,DIRECT", "RULE-SET,B,DIRECT"],
            }
            with self.assertRaisesRegex(ValueError, "duplicate provider path"):
                validate_final_config(dist, config)


if __name__ == "__main__":
    unittest.main()
