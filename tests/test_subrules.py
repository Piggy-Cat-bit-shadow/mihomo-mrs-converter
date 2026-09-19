import tempfile
import unittest
from pathlib import Path

from converter.validate import validate_final_config


class SubRulesValidationTest(unittest.TestCase):
    def test_provider_used_only_in_sub_rule_is_not_orphaned(self):
        with tempfile.TemporaryDirectory() as tmp:
            config = {
                "rule-providers": {"OnlyInSubRule": {"behavior": "domain"}},
                "rules": ["MATCH,DIRECT"],
                "sub-rules": {"Example": ["RULE-SET,OnlyInSubRule,DIRECT"]},
            }
            validate_final_config(Path(tmp), config)

    def test_missing_provider_only_in_sub_rule_fails_closed(self):
        with tempfile.TemporaryDirectory() as tmp:
            config = {
                "rule-providers": {},
                "rules": ["MATCH,DIRECT"],
                "sub-rules": {"Example": ["RULE-SET,Missing,DIRECT"]},
            }
            with self.assertRaisesRegex(ValueError, "missing referenced provider"):
                validate_final_config(Path(tmp), config)


if __name__ == "__main__":
    unittest.main()
