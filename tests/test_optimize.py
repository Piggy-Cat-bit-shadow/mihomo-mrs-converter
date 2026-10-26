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
        final, payloads, _ = optimize_config(config, {"A": ["a.example"], "B": ["b.example"]}, {"A": "AI"})
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
            "A": "Something", "B": "Something"
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

    def test_ruleset_modifier_follows_domain_and_ip_behavior(self):
        rules = ["RULE-SET,A,Proxy,no-resolve"]
        self.assertEqual(rewrite_rules(rules, {"A": ["A-domain"]}, {"A-domain": "domain"}), ["RULE-SET,A-domain,Proxy"])
        self.assertEqual(rewrite_rules(rules, {"A": ["A-ip"]}, {"A-ip": "ipcidr"}), ["RULE-SET,A-ip,Proxy,no-resolve"])

    def test_classical_modifier_is_deferred_to_payload_semantics(self):
        rules = ["RULE-SET,A,Proxy,no-resolve"]
        self.assertEqual(rewrite_rules(rules, {"A": ["A-classical"]}, {"A-classical": "classical"}), ["RULE-SET,A-classical,Proxy"])

    def test_split_provider_assigns_no_resolve_only_to_ip_variant(self):
        rewritten = rewrite_rules(
            ["RULE-SET,A,REJECT-DROP,no-resolve"],
            {"A": ["A-domain", "A-ip"]},
            {"A-domain": "domain", "A-ip": "ipcidr"},
        )
        self.assertEqual(rewritten, [
            "RULE-SET,A-domain,REJECT-DROP",
            "RULE-SET,A-ip,REJECT-DROP,no-resolve",
        ])

    def test_sub_rule_split_provider_normalizes_each_variant(self):
        rules = ["SUB-RULE,(RULE-SET,A,no-resolve),AI-Routing"]
        replacements = {"A": ["A-domain", "A-ip"]}
        behaviors = {"A-domain": "domain", "A-ip": "ipcidr"}
        self.assertEqual(rewrite_rules(rules, replacements, behaviors), [
            "SUB-RULE,(RULE-SET,A-domain),AI-Routing",
            "SUB-RULE,(RULE-SET,A-ip,no-resolve),AI-Routing",
        ])

    def test_nested_reference_rename_does_not_add_no_resolve_to_domain(self):
        rewritten = rewrite_rules(["AND,((RULE-SET,A,Proxy),(NETWORK,tcp)),DIRECT"], {"A": ["A-domain"]}, {"A-domain": "domain"})
        self.assertEqual(rewritten, ["AND,((RULE-SET,A-domain,Proxy),(NETWORK,tcp)),DIRECT"])

    def test_sub_rule_reference_is_rewritten_with_the_same_parser(self):
        config = {
            "rule-providers": {"A": {"behavior": "domain"}},
            "rules": ["MATCH,DIRECT"],
            "sub-rules": {"Example": ["RULE-SET,A,Proxy,no-resolve"]},
        }
        final, payloads, _ = optimize_config(config, {"A": ["a.example"]})
        self.assertEqual(final["sub-rules"]["Example"], ["RULE-SET,A,Proxy"])
        self.assertIn("A", final["rule-providers"])
        self.assertEqual(payloads["A"], ["a.example"])

    def test_sub_rule_domain_modifier_is_normalized(self):
        config = {
            "rule-providers": {"A": {"behavior": "domain"}},
            "rules": ["MATCH,DIRECT"],
            "sub-rules": {"Example": ["SUB-RULE,(RULE-SET,A,no-resolve),Proxy"]},
        }
        final, _, _ = optimize_config(config, {"A": ["a.example"]})
        self.assertEqual(final["sub-rules"]["Example"], ["SUB-RULE,(RULE-SET,A),Proxy"])

    def test_sub_rule_reference_keeps_original_match_set(self):
        config = {
            "rule-providers": {"A": {"behavior": "domain"}, "B": {"behavior": "domain"}},
            "rules": ["RULE-SET,A,Proxy", "RULE-SET,B,Proxy"],
            "sub-rules": {"Example": ["RULE-SET,A,Proxy"]},
        }
        final, payloads, _ = optimize_config(config, {"A": ["a.example"], "B": ["b.example"]})
        self.assertEqual(final["sub-rules"]["Example"], ["RULE-SET,A,Proxy"])
        self.assertEqual(payloads["A"], ["a.example"])

    def test_segment_anchor_rejects_ordinal_shift(self):
        config = {"rule-providers": {"Inserted": {"behavior": "domain"}, "AI": {"behavior": "domain"}}, "rules": [
            "RULE-SET,Inserted,Proxy", "DOMAIN,barrier.example,DIRECT", "RULE-SET,AI,Proxy"
        ]}
        mapping = {"Direct": "Direct"}
        with self.assertRaisesRegex(ValueError, "anchor"):
            optimize_config(config, {"Inserted": ["inserted.example"], "AI": ["ai.example"]}, mapping)

    def test_segment_anchor_maps_expected_provider(self):
        config = {"rule-providers": {"AI": {"behavior": "domain"}}, "rules": ["RULE-SET,AI,Proxy"]}
        final, _, _ = optimize_config(config, {"AI": ["ai.example"]}, {
            "AI": "AI"
        })
        self.assertIn("AI-domain", final["rule-providers"])


if __name__ == "__main__":
    unittest.main()


class AnchorBoundaryTest(unittest.TestCase):
    def test_consecutive_anchors_preserve_order_across_policies_and_behaviors(self):
        import itertools
        for order in itertools.permutations(('A', 'B', 'C')):
            for policies in [('Proxy',) * 3, ('Proxy', 'DIRECT', 'Proxy')]:
                for behaviors in [('domain',) * 3, ('domain', 'classical', 'ipcidr')]:
                    with self.subTest(order=order, policies=policies, behaviors=behaviors):
                        mapping = {name: f'Named{name}' for name in order}
                        providers = {name: {'behavior': behavior} for name, behavior in zip(order, behaviors)}
                        rules = [f'RULE-SET,{name},{policy}' for name, policy in zip(order, policies)]
                        payloads = {name: {'domain': ['shared.example'], 'classical': ['DOMAIN,shared.example'],
                                           'ipcidr': ['192.0.2.0/24']}[providers[name]['behavior']] for name in order}
                        blocks = list(iter_ruleset_blocks(rules, providers, mapping))
                        self.assertEqual([b[4] for b in blocks], [[name] for name in order])
                        final, output, _ = optimize_config({'rule-providers': providers, 'rules': rules}, payloads, mapping)
                        for index, (name, policy, behavior) in enumerate(zip(order, policies, behaviors)):
                            suffix = 'ip' if behavior == 'ipcidr' else behavior
                            self.assertEqual(final['rules'][index], f'RULE-SET,Named{name}-{suffix},{policy}')
                            self.assertEqual(output[f'Named{name}-{suffix}'], payloads[name])

    def test_normalized_variants_keep_same_anchor_and_unnamed_members(self):
        names = ['A-domain', 'A-ip', 'extra', 'B-domain', 'B-ip']
        providers = {name: {'behavior': 'domain'} for name in names}
        rules = [f'RULE-SET,{name},Proxy' for name in names]
        blocks = list(iter_ruleset_blocks(rules, providers, {'A': 'First', 'B': 'Second'}))
        self.assertEqual([b[4] for b in blocks], [names[:3], names[3:]])

    def test_wrappers_and_ordinary_rules_remain_barriers(self):
        providers = {name: {'behavior': 'domain'} for name in 'ABC'}
        rules = ['SUB-RULE,(RULE-SET,A),Routing', 'SUB-RULE,(RULE-SET,B),Routing',
                 'DOMAIN,shared.example,DIRECT', 'RULE-SET,C,Proxy']
        final, _, _ = optimize_config({'rule-providers': providers, 'rules': rules},
                                     {n: ['shared.example'] for n in providers}, {n: n for n in providers})
        self.assertEqual(final['rules'], ['SUB-RULE,(RULE-SET,A-domain),Routing',
                                        'SUB-RULE,(RULE-SET,B-domain),Routing', rules[2],
                                        'RULE-SET,C-domain,Proxy'])

    def test_overlapping_anchor_patterns_still_fail_explicitly(self):
        with self.assertRaisesRegex(ValueError, 'multiple configured anchors'):
            optimize_config({'rule-providers': {'A-B': {'behavior': 'domain'}},
                             'rules': ['RULE-SET,A-B,Proxy']}, {'A-B': ['example']},
                            {'A': 'One', 'A-B': 'Two'})

    def test_first_match_for_overlapping_sets_and_reordered_rules(self):
        from converter.rules import parse_ruleset_reference
        def route(config, payloads, domain):
            for raw in config['rules']:
                ref = parse_ruleset_reference(raw)
                if ref and any(domain == p or (p.startswith('+.') and
                              (domain == p[2:] or domain.endswith('.' + p[2:])))
                              for p in payloads[ref.provider]):
                    return ref.policy
                if raw.startswith('DOMAIN,'):
                    _, value, policy = raw.split(',')
                    if domain == value:
                        return policy
            return 'Fallback'
        providers = {n: {'behavior': 'domain'} for n in 'ABC'}
        payloads = {'A': ['shared.example', 'a.example'], 'B': ['+.example'], 'C': ['shared.example']}
        for rules in [
            ['RULE-SET,A,Proxy', 'RULE-SET,B,Proxy', 'DOMAIN,shared.example,REJECT', 'RULE-SET,C,DIRECT'],
            ['RULE-SET,C,DIRECT', 'RULE-SET,A,Proxy', 'RULE-SET,B,Proxy'],
            ['RULE-SET,A,Proxy', 'RULE-SET,C,DIRECT', 'RULE-SET,B,Proxy'],
        ]:
            config = {'rule-providers': providers, 'rules': rules}
            final, output, _ = optimize_config(config, payloads, {n: n for n in providers})
            for domain in ['shared.example', 'a.example', 'child.example', 'outside.test']:
                self.assertEqual(route(config, payloads, domain), route(final, output, domain))
