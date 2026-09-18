import unittest

from converter.rules import find_ruleset_refs, iter_all_rules, parse_ruleset_reference, rule_policy, split_top_level_commas


class RulesTest(unittest.TestCase):
    def test_nested_references_are_found(self):
        self.assertEqual(find_ruleset_refs("AND,((RULE-SET,A,Proxy),(NETWORK,tcp)),DIRECT"), ["A"])

    def test_expression_split_respects_parentheses(self):
        self.assertEqual(split_top_level_commas("AND,((RULE-SET,A,Proxy),(NETWORK,tcp)),DIRECT"), ["AND", "((RULE-SET,A,Proxy),(NETWORK,tcp))", "DIRECT"])

    def test_reference_preserves_policy_and_modifier(self):
        ref = parse_ruleset_reference("(RULE-SET,A,Proxy,no-resolve)")
        self.assertEqual((ref.provider, ref.policy, ref.modifiers), ("A", "Proxy", ("no-resolve",)))

    def test_all_rules_includes_sub_rules(self):
        config = {"rules": ["RULE-SET,Top,DIRECT"], "sub-rules": {"Example": ["RULE-SET,Nested,Proxy"]}}
        self.assertEqual(list(iter_all_rules(config)), ["RULE-SET,Top,DIRECT", "RULE-SET,Nested,Proxy"])

    def test_policy_parser_does_not_treat_modifiers_as_policies(self):
        cases = {
            "RULE-SET,A,OnlyPolicy": "OnlyPolicy",
            "RULE-SET,A,OnlyPolicy,no-resolve": "OnlyPolicy",
            "SUB-RULE,(RULE-SET,A),Proxy": "Proxy",
            "IP-CIDR,1.1.1.0/24,Proxy,no-resolve": "Proxy",
            "DOMAIN,example.com,Proxy": "Proxy",
            "NETWORK,UDP,REJECT": "REJECT",
            "MATCH,Proxy": "Proxy",
        }
        for raw, expected in cases.items():
            with self.subTest(raw=raw):
                self.assertEqual(rule_policy(raw), expected)


if __name__ == "__main__":
    unittest.main()
