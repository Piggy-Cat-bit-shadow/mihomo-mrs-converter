import contextlib
import io
import itertools
import unittest

from converter.model import ProviderMetadata
from converter.optimize import optimize_config
from converter.payload import dedup_domains, dedup_networks, parse_domain_payload, parse_ipcidr_payload
from converter.rules import parse_ruleset_reference, rewrite_rules
from converter.segments import plan_blocks
from tests.support import normalized, semantic_config


def rendered(payload) -> list[str]:
    return [entry.as_rule() if hasattr(entry, "as_rule") else entry.raw for entry in payload]


class OptimizeTest(unittest.TestCase):
    def test_domain_and_ip_dedup_are_stable(self):
        self.assertEqual(rendered(dedup_domains(parse_domain_payload(["a.example", "+.example"]))[0]), ["+.example"])
        self.assertEqual(
            rendered(dedup_networks(parse_ipcidr_payload(["192.0.2.0/24", "192.0.2.0/25"]))[0]),
            ["192.0.2.0/24"],
        )

    def test_block_iterator_stops_at_policy_barrier(self):
        rules = ["RULE-SET,A,Proxy", "RULE-SET,B,Proxy", "RULE-SET,C,DIRECT"]
        providers = {name: {"behavior": "domain"} for name in ("A", "B", "C")}
        blocks = plan_blocks(rules, {name: name for name in providers})
        self.assertEqual([block.providers for block in blocks], [("A", "B"), ("C",)])

    def test_optimizer_is_filesystem_free_and_emits_final_identity(self):
        semantic = semantic_config(
            providers=[normalized("A", "A", "domain", ["a.example"]), normalized("B", "B", "domain", ["b.example"])],
            rules=["RULE-SET,A,Proxy", "RULE-SET,B,Proxy"],
        )
        final = optimize_config(semantic, {"A": "AI"})
        providers = final.provider_map()
        self.assertIn("AI-domain", providers)
        self.assertEqual(rendered(providers["AI-domain"].payload), ["a.example", "b.example"])
        self.assertEqual(final.rules, ("RULE-SET,AI-domain,Proxy",))

    def test_ordinary_rule_is_a_block_barrier_in_real_optimizer(self):
        semantic = semantic_config(
            providers=[normalized("A", "A", "domain", ["a.example"]), normalized("B", "B", "domain", ["b.example"])],
            rules=["RULE-SET,A,Proxy", "DOMAIN,barrier.example,DIRECT", "RULE-SET,B,Proxy"],
        )
        final = optimize_config(semantic)
        self.assertEqual(
            final.rules,
            ("RULE-SET,merged-segment-01-domain,Proxy", "DOMAIN,barrier.example,DIRECT", "RULE-SET,merged-segment-02-domain,Proxy"),
        )

    def test_metadata_conflict_falls_back_to_original_providers(self):
        semantic = semantic_config(
            providers=[
                normalized("A", "A", "domain", ["a.example"], metadata=ProviderMetadata(proxy="one")),
                normalized("B", "B", "domain", ["b.example"], metadata=ProviderMetadata(proxy="two")),
            ],
            rules=["RULE-SET,A,Proxy", "RULE-SET,B,Proxy"],
        )
        final = optimize_config(semantic)
        self.assertEqual({provider.name for provider in final.providers}, {"A", "B"})
        self.assertEqual(rendered(final.provider_map()["A"].payload), ["a.example"])

    def test_part_fallback_is_produced_for_colliding_segment_names(self):
        semantic = semantic_config(
            providers=[normalized("A", "A", "ipcidr", ["192.0.2.0/24"]), normalized("B", "B", "ipcidr", ["198.51.100.0/24"])],
            rules=["RULE-SET,A,Proxy", "DOMAIN,barrier.example,DIRECT", "RULE-SET,B,Proxy"],
        )
        final = optimize_config(semantic, {"A": "Something", "B": "Something"})
        names = {provider.name for provider in final.providers}
        self.assertIn("Something-ip", names)
        self.assertIn("Something-ip-part-02", names)
        self.assertEqual([provider.segment for provider in final.providers], ["Something", "Something"])

    def test_classical_concat_is_stable_and_not_semantically_deduped(self):
        semantic = semantic_config(
            providers=[
                normalized("A", "A", "classical", ["DOMAIN,a.example,DIRECT", "DOMAIN,shared.example,DIRECT"]),
                normalized("B", "B", "classical", ["DOMAIN,shared.example,DIRECT", "DOMAIN,b.example,DIRECT"]),
            ],
            rules=["RULE-SET,A,Proxy", "RULE-SET,B,Proxy"],
        )
        final = optimize_config(semantic)
        self.assertEqual(
            rendered(final.provider_map()["merged-segment-01-classical"].payload),
            ["DOMAIN,a.example,DIRECT", "DOMAIN,shared.example,DIRECT", "DOMAIN,shared.example,DIRECT", "DOMAIN,b.example,DIRECT"],
        )
        self.assertEqual(final.rules, ("RULE-SET,merged-segment-01-classical,Proxy",))

    def test_empty_extras_are_preserved(self):
        semantic = semantic_config(
            providers=[normalized("A", "A", "domain", ["a.example"])],
            rules=["RULE-SET,A,Proxy"],
            extras={"mixed-port": 7890, "proxies": [{"name": "p"}]},
        )
        final = optimize_config(semantic)
        config = final.as_config()
        self.assertEqual(config["mixed-port"], 7890)
        self.assertEqual(config["proxies"], [{"name": "p"}])
        self.assertEqual(list(config)[0], "mixed-port")


class RewriteRulesTest(unittest.TestCase):
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


class SubRuleReferenceTest(unittest.TestCase):
    def test_sub_rule_reference_is_rewritten_with_the_same_parser(self):
        semantic = semantic_config(
            providers=[normalized("A", "A", "domain", ["a.example"])],
            rules=["MATCH,DIRECT"],
            sub_rules={"Example": ["RULE-SET,A,Proxy,no-resolve"]},
        )
        final = optimize_config(semantic)
        self.assertEqual(final.sub_rules["Example"], ("RULE-SET,A,Proxy",))
        self.assertIn("A", final.provider_map())

    def test_sub_rule_domain_modifier_is_normalized(self):
        semantic = semantic_config(
            providers=[normalized("A", "A", "domain", ["a.example"])],
            rules=["MATCH,DIRECT"],
            sub_rules={"Example": ["SUB-RULE,(RULE-SET,A,no-resolve),Proxy"]},
        )
        final = optimize_config(semantic)
        self.assertEqual(final.sub_rules["Example"], ("SUB-RULE,(RULE-SET,A),Proxy",))

    def test_sub_rule_reference_keeps_original_match_set(self):
        semantic = semantic_config(
            providers=[normalized("A", "A", "domain", ["a.example"]), normalized("B", "B", "domain", ["b.example"])],
            rules=["RULE-SET,A,Proxy", "RULE-SET,B,Proxy"],
            sub_rules={"Example": ["RULE-SET,A,Proxy"]},
        )
        final = optimize_config(semantic)
        self.assertEqual(final.sub_rules["Example"], ("RULE-SET,A,Proxy",))
        self.assertEqual(rendered(final.provider_map()["A"].payload), ["a.example"])

    def test_external_reference_name_cannot_overwrite_merged_union(self):
        semantic = semantic_config(
            providers=[normalized("A", "A-domain", "domain", ["a.example"]), normalized("B", "B", "domain", ["b.example"])],
            rules=["RULE-SET,A-domain,Proxy", "RULE-SET,B,Proxy"],
            sub_rules={"Routing": ["RULE-SET,A-domain,DIRECT"]},
        )
        final = optimize_config(semantic, {"A": "A"})
        providers = final.provider_map()
        merged = parse_ruleset_reference(final.rules[0]).provider
        self.assertNotEqual(merged, "A-domain")
        self.assertEqual(rendered(providers[merged].payload), ["a.example", "b.example"])
        self.assertEqual(rendered(providers["A-domain"].payload), ["a.example"])
        self.assertEqual(final.sub_rules["Routing"], ("RULE-SET,A-domain,DIRECT",))

    def test_nested_reference_does_not_expand_to_a_merged_union(self):
        nested = "AND,((RULE-SET,A,Proxy),(NETWORK,tcp)),DIRECT"
        semantic = semantic_config(
            providers=[normalized("A", "A", "domain", ["a.example"]), normalized("B", "B", "domain", ["b.example"])],
            rules=["RULE-SET,A,Proxy", "RULE-SET,B,Proxy", nested],
        )
        final = optimize_config(semantic)
        self.assertEqual(final.rules[-1], nested)
        self.assertEqual(rendered(final.provider_map()["A"].payload), ["a.example"])

    def test_unmatched_anchor_falls_back_to_a_generated_identity(self):
        semantic = semantic_config(
            providers=[normalized("Inserted", "Inserted", "domain", ["inserted.example"]), normalized("AI", "AI", "domain", ["ai.example"])],
            rules=["RULE-SET,Inserted,Proxy", "DOMAIN,barrier.example,DIRECT", "RULE-SET,AI,Proxy"],
        )
        stderr = io.StringIO()
        with contextlib.redirect_stderr(stderr):
            final = optimize_config(semantic, {"Direct": "Direct"})
        self.assertEqual(
            [provider.name for provider in final.providers],
            ["merged-segment-01-domain", "merged-segment-02-domain"],
        )
        self.assertIn("did not match any provider: ['Direct']", stderr.getvalue())

    def test_segment_anchor_maps_expected_provider(self):
        semantic = semantic_config(
            providers=[normalized("AI", "AI", "domain", ["ai.example"])],
            rules=["RULE-SET,AI,Proxy"],
        )
        final = optimize_config(semantic, {"AI": "AI"})
        self.assertIn("AI-domain", final.provider_map())


class AnchorBoundaryTest(unittest.TestCase):
    def test_consecutive_anchors_preserve_order_across_policies_and_behaviors(self):
        for order in itertools.permutations(("A", "B", "C")):
            for policies in [("Proxy",) * 3, ("Proxy", "DIRECT", "Proxy")]:
                for behaviors in [("domain",) * 3, ("domain", "classical", "ipcidr")]:
                    with self.subTest(order=order, policies=policies, behaviors=behaviors):
                        mapping = {name: f"Named{name}" for name in order}
                        providers = {name: behavior for name, behavior in zip(order, behaviors)}
                        rules = [f"RULE-SET,{name},{policy}" for name, policy in zip(order, policies)]
                        payloads = {
                            "domain": ["shared.example"],
                            "classical": ["DOMAIN,shared.example"],
                            "ipcidr": ["192.0.2.0/24"],
                        }
                        blocks = plan_blocks(rules, {name: name for name in providers}, mapping)
                        self.assertEqual([block.providers for block in blocks], [(name,) for name in order])
                        semantic = semantic_config(
                            providers=[normalized(name, name, providers[name], payloads[providers[name]]) for name in order],
                            rules=rules,
                        )
                        final = optimize_config(semantic, mapping)
                        for index, (name, policy, behavior) in enumerate(zip(order, policies, behaviors)):
                            suffix = "ip" if behavior == "ipcidr" else behavior
                            self.assertEqual(final.rules[index], f"RULE-SET,Named{name}-{suffix},{policy}")
                            self.assertEqual(
                                rendered(final.provider_map()[f"Named{name}-{suffix}"].payload),
                                payloads[behavior],
                            )

    def test_normalized_variants_keep_same_anchor_and_unnamed_members(self):
        names = ["A-domain", "A-ip", "extra", "B-domain", "B-ip"]
        sources = {"A-domain": "A", "A-ip": "A", "extra": "extra", "B-domain": "B", "B-ip": "B"}
        rules = [f"RULE-SET,{name},Proxy" for name in names]
        blocks = plan_blocks(rules, sources, {"A": "First", "B": "Second"})
        self.assertEqual([block.providers for block in blocks], [tuple(names[:3]), tuple(names[3:])])
        self.assertEqual([block.name for block in blocks], ["First", "Second"])

    def test_wrappers_and_ordinary_rules_remain_barriers(self):
        providers = {name: "domain" for name in "ABC"}
        rules = [
            "SUB-RULE,(RULE-SET,A),Routing", "SUB-RULE,(RULE-SET,B),Routing",
            "DOMAIN,shared.example,DIRECT", "RULE-SET,C,Proxy",
        ]
        semantic = semantic_config(
            providers=[normalized(name, name, providers[name], ["shared.example"]) for name in providers],
            rules=rules,
        )
        final = optimize_config(semantic, {name: name for name in providers})
        self.assertEqual(final.rules, (
            "SUB-RULE,(RULE-SET,A-domain),Routing",
            "SUB-RULE,(RULE-SET,B-domain),Routing",
            rules[2],
            "RULE-SET,C-domain,Proxy",
        ))

    def test_configured_anchor_wins_over_a_longer_anchor_of_the_same_prefix(self):
        semantic = semantic_config(
            providers=[normalized("A", "A", "domain", ["one.example"]), normalized("A-B", "A-B", "domain", ["two.example"])],
            rules=["RULE-SET,A,Proxy", "RULE-SET,A-B,Proxy"],
        )
        final = optimize_config(semantic, {"A": "One", "A-B": "Two"})
        self.assertEqual([provider.name for provider in final.providers], ["One-domain", "Two-domain"])
        self.assertEqual([provider.segment for provider in final.providers], ["One", "Two"])

    def test_first_match_for_overlapping_sets_and_reordered_rules(self):
        providers = {name: "domain" for name in "ABC"}
        payloads = {"A": ["shared.example", "a.example"], "B": ["+.example"], "C": ["shared.example"]}

        def route(config, output, domain):
            for raw in config:
                reference = parse_ruleset_reference(raw)
                if reference and any(
                    domain == value or (value.startswith("+.") and (domain == value[2:] or domain.endswith("." + value[2:])))
                    for value in output[reference.provider]
                ):
                    return reference.policy
                if raw.startswith("DOMAIN,"):
                    _, value, policy = raw.split(",")
                    if domain == value:
                        return policy
            return "Fallback"

        for rules in [
            ["RULE-SET,A,Proxy", "RULE-SET,B,Proxy", "DOMAIN,shared.example,REJECT", "RULE-SET,C,DIRECT"],
            ["RULE-SET,C,DIRECT", "RULE-SET,A,Proxy", "RULE-SET,B,Proxy"],
            ["RULE-SET,A,Proxy", "RULE-SET,C,DIRECT", "RULE-SET,B,Proxy"],
        ]:
            semantic = semantic_config(
                providers=[normalized(name, name, providers[name], payloads[name]) for name in providers],
                rules=rules,
            )
            final = optimize_config(semantic, {name: name for name in providers})
            output = {provider.name: rendered(provider.payload) for provider in final.providers}
            for domain in ["shared.example", "a.example", "child.example", "outside.test"]:
                self.assertEqual(route(rules, payloads, domain), route(final.rules, output, domain))


class ExternalIdentityCollisionTest(unittest.TestCase):
    def test_single_provider_segment_can_share_its_own_name_with_a_sub_rule_reference(self):
        semantic = semantic_config(
            providers=[normalized("China", "China", "domain", ["cn.example"])],
            rules=["RULE-SET,China,Proxy"],
            sub_rules={"R": ["RULE-SET,China,DIRECT"]},
        )
        final = optimize_config(semantic, {"China": "China"})
        names = [provider.name for provider in final.providers]
        self.assertEqual(names, ["China-domain", "China"])
        self.assertEqual(final.providers[0].payload, final.providers[1].payload)

    def test_wider_segment_cannot_share_its_name_with_an_external_reference(self):
        semantic = semantic_config(
            providers=[
                normalized("China", "China", "domain", ["cn.example"]),
                normalized("Other", "Other", "domain", ["other.example"]),
            ],
            rules=["RULE-SET,China,Proxy", "RULE-SET,Other,Proxy"],
            sub_rules={"R": ["RULE-SET,China,DIRECT"]},
        )
        with self.assertRaisesRegex(ValueError, "per-segment exports cannot represent both"):
            optimize_config(semantic, {"China": "China"})


if __name__ == "__main__":
    unittest.main()
