import unittest

import scripts.extract_rules_input as extract_rules_input


class ExtractRulesInputTest(unittest.TestCase):
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
