import unittest

from converter.optimize import dedup_domain_payload, dedup_ipcidr_payload, iter_ruleset_blocks, optimize_config


class OptimizeTest(unittest.TestCase):
    def test_domain_and_ip_dedup_are_stable(self):
        self.assertEqual(dedup_domain_payload(["a.example", "+.example"])[0], ["+.example"])
        self.assertEqual(dedup_ipcidr_payload(["192.0.2.0/24", "192.0.2.0/25"])[0], ["192.0.2.0/24"])

    def test_block_iterator_stops_at_policy_barrier(self):
        rules = ["RULE-SET,A,Proxy", "RULE-SET,B,Proxy", "RULE-SET,C,DIRECT"]
        providers = {name: {"behavior": "domain"} for name in ("A", "B", "C")}
        blocks = list(iter_ruleset_blocks(rules, providers))
        self.assertEqual([block[4] for block in blocks], [["A", "B"], ["C"]])

    def test_optimizer_is_filesystem_free_and_emits_final_identity(self):
        config = {"rule-providers": {"A": {"behavior": "domain"}, "B": {"behavior": "domain"}}, "rules": ["RULE-SET,A,Proxy", "RULE-SET,B,Proxy"]}
        final, payloads, _ = optimize_config(config, {"A": ["a.example"], "B": ["b.example"]}, {"merged-segment-01": "AI"})
        self.assertIn("AI-domain", final["rule-providers"])
        self.assertEqual(payloads["AI-domain"], ["a.example", "b.example"])
        self.assertEqual(final["rules"], ["RULE-SET,AI-domain,Proxy"])


if __name__ == "__main__":
    unittest.main()
