import unittest
import tempfile
from pathlib import Path
from unittest.mock import patch

import yaml

import scripts.extract_rules_input as extract_rules_input


class ExtractRulesInputTest(unittest.TestCase):
    def test_sub_rules_are_preserved_without_reordering(self) -> None:
        source = {"rule-providers": {}, "rules": ["MATCH,DIRECT"], "sub-rules": {"AI-Routing": ["NETWORK,UDP,REJECT", "MATCH,🤖 AI"]}}
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source_path, output_path = root / "source.yaml", root / "rules.yaml"
            source_path.write_text(yaml.safe_dump(source, allow_unicode=True, sort_keys=False), encoding="utf-8")
            with patch("sys.argv", ["extract", str(source_path), str(output_path)]):
                extract_rules_input.main()
            self.assertEqual(yaml.safe_load(output_path.read_text(encoding="utf-8"))["sub-rules"], source["sub-rules"])

    def test_sub_rules_are_optional(self) -> None:
        source = {"rule-providers": {}, "rules": ["MATCH,DIRECT"]}
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source_path, output_path = root / "source.yaml", root / "rules.yaml"
            source_path.write_text(yaml.safe_dump(source, sort_keys=False), encoding="utf-8")
            with patch("sys.argv", ["extract", str(source_path), str(output_path)]):
                extract_rules_input.main()
            self.assertNotIn("sub-rules", yaml.safe_load(output_path.read_text(encoding="utf-8")))
    def test_sensitive_header_is_rejected_by_default(self) -> None:
        data = {
            "rule-providers": {
                "secret-provider": {
                    "type": "http",
                    "url": "https://example.com/rules.yaml",
                    "header": {"Authorization": "Bearer secret"},
                }
            }
        }

        with self.assertRaises(SystemExit) as context:
            extract_rules_input.check_sensitive_config(data)

        message = str(context.exception)
        self.assertIn("secret-provider", message)
        self.assertIn("Authorization", message)
        self.assertNotIn("Bearer secret", message)


if __name__ == "__main__":
    unittest.main()
