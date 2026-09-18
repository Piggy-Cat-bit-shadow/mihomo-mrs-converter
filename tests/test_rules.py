import unittest

from converter.rules import find_ruleset_refs, parse_ruleset_reference, split_top_level_commas


class RulesTest(unittest.TestCase):
    def test_nested_references_are_found(self):
        self.assertEqual(find_ruleset_refs("AND,((RULE-SET,A,Proxy),(NETWORK,tcp)),DIRECT"), ["A"])

    def test_expression_split_respects_parentheses(self):
        self.assertEqual(split_top_level_commas("AND,((RULE-SET,A,Proxy),(NETWORK,tcp)),DIRECT"), ["AND", "((RULE-SET,A,Proxy),(NETWORK,tcp))", "DIRECT"])

    def test_reference_preserves_policy_and_modifier(self):
        ref = parse_ruleset_reference("(RULE-SET,A,Proxy,no-resolve)")
        self.assertEqual((ref.provider, ref.policy, ref.modifiers), ("A", "Proxy", ("no-resolve",)))


if __name__ == "__main__":
    unittest.main()
