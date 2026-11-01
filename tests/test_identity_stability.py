"""Metamorphic identity tests: unrelated input edits must not rename artifacts.

Segment identity comes from configured anchors (input provider keys), so these
tests assert the properties the refactor is supposed to guarantee rather than
the shape of the implementation.
"""
import unittest

from converter.optimize import optimize_config
from tests.support import normalized, semantic_config


class IdentityStabilityTest(unittest.TestCase):
    def final(self, providers, rules, mapping):
        return optimize_config(semantic_config(providers=providers, rules=rules), mapping)

    @staticmethod
    def names(config) -> list[str]:
        return [provider.name for provider in config.providers]

    def test_inserting_an_unrelated_segment_does_not_rename_existing_artifacts(self):
        baseline = self.final(
            [normalized("Lan", "Lan-domain", "domain", ["lan.example"]),
             normalized("me-pure", "me-pure-domain", "domain", ["ai.example"])],
            ["RULE-SET,Lan-domain,DIRECT", "RULE-SET,me-pure-domain,DIRECT"],
            {"Lan": "Direct", "me-pure": "AI"},
        )
        self.assertEqual(self.names(baseline), ["Direct-domain", "AI-domain"])

        inserted = self.final(
            [normalized("Extra", "Extra-domain", "domain", ["extra.example"]),
             normalized("Lan", "Lan-domain", "domain", ["lan.example"]),
             normalized("me-pure", "me-pure-domain", "domain", ["ai.example"])],
            ["RULE-SET,Extra-domain,REJECT", "RULE-SET,Lan-domain,DIRECT", "RULE-SET,me-pure-domain,DIRECT"],
            {"Extra": "Extra", "Lan": "Direct", "me-pure": "AI"},
        )
        self.assertEqual(self.names(inserted), ["Extra-domain", "Direct-domain", "AI-domain"])

    def test_changing_one_display_name_only_renames_that_artifact(self):
        providers = [normalized("Lan", "Lan-domain", "domain", ["lan.example"]),
                     normalized("me-pure", "me-pure-domain", "domain", ["ai.example"])]
        rules = ["RULE-SET,Lan-domain,DIRECT", "RULE-SET,me-pure-domain,DIRECT"]
        before = self.final(providers, rules, {"Lan": "Direct", "me-pure": "AI"})
        after = self.final(providers, rules, {"Lan": "Direct", "me-pure": "ChatAI"})
        self.assertEqual(self.names(before), ["Direct-domain", "AI-domain"])
        self.assertEqual(self.names(after), ["Direct-domain", "ChatAI-domain"])
        self.assertEqual(before.providers[0].payload, after.providers[0].payload)

    def test_reordering_same_policy_segments_keeps_artifact_names(self):
        providers = [normalized("me-foreign", "me-foreign-domain", "domain", ["foreign.example"]),
                     normalized("global", "global-domain", "domain", ["global.example"])]
        mapping = {"me-foreign": "Global-First", "global": "Global"}
        forward = self.final(providers, ["RULE-SET,me-foreign-domain,Proxy", "RULE-SET,global-domain,Proxy"], mapping)
        backward = self.final(providers, ["RULE-SET,global-domain,Proxy", "RULE-SET,me-foreign-domain,Proxy"], mapping)
        self.assertEqual(self.names(forward), ["Global-First-domain", "Global-domain"])
        self.assertEqual(self.names(backward), ["Global-domain", "Global-First-domain"])
        self.assertEqual(forward.rules, ("RULE-SET,Global-First-domain,Proxy", "RULE-SET,Global-domain,Proxy"))
        self.assertEqual(backward.rules, ("RULE-SET,Global-domain,Proxy", "RULE-SET,Global-First-domain,Proxy"))

    def test_the_same_provider_under_two_policies_is_not_shared(self):
        provider = normalized("A", "A-domain", "domain", ["shared.example", "a.example"])
        final = self.final(
            [provider],
            ["RULE-SET,A-domain,Proxy", "DOMAIN,barrier.example,DIRECT", "RULE-SET,A-domain,DIRECT"],
            None,
        )
        self.assertEqual(len(final.providers), 2)
        self.assertNotEqual(final.providers[0].name, final.providers[1].name)
        self.assertEqual(final.providers[0].payload, final.providers[1].payload)
        self.assertEqual([rule.split(",")[1] for rule in final.rules if rule.startswith("RULE-SET")], ["merged-segment-01-domain", "merged-segment-02-domain"])

    def test_unnamed_blocks_keep_ordinal_identity_as_documented(self):
        # Without a configured anchor there is no stable external identity; the
        # generated name follows route order.  Inserting a block before it
        # therefore renames it, which is the one documented limitation.
        providers = [normalized("Extra", "Extra-domain", "domain", ["extra.example"]),
                     normalized("Lan", "Lan-domain", "domain", ["lan.example"])]
        mapping = {"Lan": "Direct"}
        final = self.final(
            providers,
            ["RULE-SET,Extra-domain,DIRECT", "DOMAIN,barrier.example,DIRECT", "RULE-SET,Lan-domain,DIRECT"],
            mapping,
        )
        self.assertEqual(self.names(final), ["merged-segment-01-domain", "Direct-domain"])


if __name__ == "__main__":
    unittest.main()
