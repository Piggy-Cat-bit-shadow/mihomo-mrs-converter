import unittest

from converter.optimize import dedup_domain_payload, dedup_ipcidr_payload, iter_ruleset_blocks, optimize_config, rewrite_rules


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

    def test_ordinary_rule_is_a_block_barrier_in_real_optimizer(self):
        config = {"rule-providers": {"A": {"behavior": "domain"}, "B": {"behavior": "domain"}}, "rules": [
            "RULE-SET,A,Proxy", "DOMAIN,barrier.example,DIRECT", "RULE-SET,B,Proxy"
        ]}
        final, _, _ = optimize_config(config, {"A": ["a.example"], "B": ["b.example"]})
        self.assertEqual(final["rules"], ["RULE-SET,merged-segment-01-domain,Proxy", "DOMAIN,barrier.example,DIRECT", "RULE-SET,merged-segment-02-domain,Proxy"])

    def test_metadata_conflict_falls_back_to_original_providers(self):
        config = {"rule-providers": {"A": {"behavior": "domain", "proxy": "one"}, "B": {"behavior": "domain", "proxy": "two"}}, "rules": [
            "RULE-SET,A,Proxy", "RULE-SET,B,Proxy"
        ]}
        final, payloads, _ = optimize_config(config, {"A": ["a.example"], "B": ["b.example"]})
        self.assertEqual(set(final["rule-providers"]), {"A", "B"})
        self.assertEqual(payloads, {"A": ["a.example"], "B": ["b.example"]})

    def test_part_fallback_is_produced_for_colliding_segment_names(self):
        config = {"rule-providers": {"A": {"behavior": "ipcidr"}, "B": {"behavior": "ipcidr"}}, "rules": [
            "RULE-SET,A,Proxy", "DOMAIN,barrier.example,DIRECT", "RULE-SET,B,Proxy"
        ]}
        final, _, _ = optimize_config(config, {"A": ["192.0.2.0/24"], "B": ["198.51.100.0/24"]}, {
            "merged-segment-01": "Something", "merged-segment-02": "Something"
        })
        self.assertIn("Something-ip", final["rule-providers"])
        self.assertIn("Something-ip-part-02", final["rule-providers"])

    def test_classical_concat_is_stable_and_not_semantically_deduped(self):
        config = {"rule-providers": {"A": {"behavior": "classical"}, "B": {"behavior": "classical"}}, "rules": [
            "RULE-SET,A,Proxy", "RULE-SET,B,Proxy"
        ]}
        final, payloads, _ = optimize_config(config, {"A": ["DOMAIN,a.example,DIRECT", "DOMAIN,shared.example,DIRECT"], "B": ["DOMAIN,shared.example,DIRECT", "DOMAIN,b.example,DIRECT"]})
        self.assertEqual(payloads["merged-segment-01-classical"], ["DOMAIN,a.example,DIRECT", "DOMAIN,shared.example,DIRECT", "DOMAIN,shared.example,DIRECT", "DOMAIN,b.example,DIRECT"])
        self.assertEqual(final["rules"], ["RULE-SET,merged-segment-01-classical,Proxy"])

    def test_modifier_and_nested_ruleset_references_are_preserved(self):
        rules = ["RULE-SET,A,Proxy,no-resolve", "AND,((RULE-SET,A,Proxy),(NETWORK,tcp)),DIRECT"]
        rewritten = rewrite_rules(rules, {"A": ["A-ip"]}, {"A-ip": "ipcidr"})
        self.assertEqual(rewritten[0], "RULE-SET,A-ip,Proxy,no-resolve")
        self.assertIn("RULE-SET,A-ip,Proxy", rewritten[1])

    def test_nested_reference_rename_does_not_add_no_resolve_to_domain(self):
        rewritten = rewrite_rules(["AND,((RULE-SET,A,Proxy),(NETWORK,tcp)),DIRECT"], {"A": ["A-domain"]}, {"A-domain": "domain"})
        self.assertEqual(rewritten, ["AND,((RULE-SET,A-domain,Proxy),(NETWORK,tcp)),DIRECT"])


if __name__ == "__main__":
    unittest.main()
