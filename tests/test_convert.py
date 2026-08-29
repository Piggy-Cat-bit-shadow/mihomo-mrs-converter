import unittest

from scripts.convert import parse_rule, source_domain_value


class SourceDomainValueTest(unittest.TestCase):
    def test_domain_keeps_exact_value(self) -> None:
        self.assertEqual(source_domain_value(parse_rule("DOMAIN,chatgpt.com")), "chatgpt.com")

    def test_domain_suffix_uses_mihomo_wildcard_root_form(self) -> None:
        self.assertEqual(
            source_domain_value(parse_rule("DOMAIN-SUFFIX,chatgpt.com")),
            "+.chatgpt.com",
        )

    def test_domain_suffix_strips_existing_leading_dot(self) -> None:
        self.assertEqual(
            source_domain_value(parse_rule("DOMAIN-SUFFIX,.chatgpt.com")),
            "+.chatgpt.com",
        )


if __name__ == "__main__":
    unittest.main()
