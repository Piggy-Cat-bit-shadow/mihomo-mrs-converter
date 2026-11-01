import contextlib
import io
import tempfile
import unittest
from pathlib import Path

from converter.segments import (
    load_segment_specs,
    plan_blocks,
    resolve_segment_roles,
    segment_mapping,
    segment_roles,
)


class SegmentMetadataTest(unittest.TestCase):
    def write(self, root: Path, value: str) -> Path:
        path = root / "segments.yaml"
        path.write_text(value, encoding="utf-8")
        return path

    def load(self, text: str):
        with tempfile.TemporaryDirectory() as tmp:
            path = self.write(Path(tmp), text)
            stderr = io.StringIO()
            with contextlib.redirect_stderr(stderr):
                specs = load_segment_specs(path)
        return specs, stderr.getvalue()

    def test_loader_exposes_one_validated_identity_model(self):
        specs, warnings = self.load("""segments:
  ExampleReject:
    name: ExampleReject
    role: reject
    reject-mode: reject
""")
        self.assertEqual(segment_mapping(specs), {"ExampleReject": "ExampleReject"})
        self.assertEqual(segment_roles(specs), {"ExampleReject": "reject"})
        self.assertEqual(warnings, "")

    def test_missing_role_is_tolerated_and_excluded_from_dns_grouping(self):
        specs, warnings = self.load("""segments:
  Example:
    name: Example
""")
        self.assertIsNone(specs[0].role)
        self.assertEqual(segment_roles(specs), {})
        self.assertIn("no role configured", warnings)

    def test_duplicate_names_fall_back_to_a_stable_anchor_name(self):
        specs, warnings = self.load("""segments:
  one: {name: Same, role: direct}
  two: {name: Same, role: global}
""")
        self.assertEqual([spec.name for spec in specs], ["Same", "two"])
        self.assertIn("already used by segment 'one'", warnings)
        # Deterministic: repeating the load yields the same fallback.
        again, _ = self.load("""segments:
  one: {name: Same, role: direct}
  two: {name: Same, role: global}
""")
        self.assertEqual([spec.name for spec in again], ["Same", "two"])

    def test_invalid_and_blank_names_fall_back_without_failing(self):
        specs, warnings = self.load("""segments:
  one: {name: "bad/name", role: direct}
  two: {name: "   ", role: global}
""")
        self.assertEqual([spec.name for spec in specs], ["one", "two"])
        self.assertIn("not a safe artifact name", warnings)
        self.assertIn("non-empty string name is required", warnings)

    def test_unknown_role_is_tolerated_but_kept_semantic_for_dns(self):
        specs, warnings = self.load("""segments:
  one: {name: One, role: rejct}
""")
        self.assertIsNone(specs[0].role)
        self.assertIn("unknown role 'rejct'", warnings)

    def test_reserved_namespace_is_reported_and_ignored(self):
        specs, warnings = self.load("""segments:
  "merged-segment-01": {name: Example, role: direct}
  two: {name: "merged-segment-02", role: direct}
""")
        self.assertEqual([spec.anchor for spec in specs], ["two"])
        self.assertEqual([spec.name for spec in specs], ["two"])
        self.assertIn("reserved", warnings)

    def test_fallback_never_displaces_a_configured_name(self):
        specs, warnings = self.load("""segments:
  A: {name: "bad/name", role: direct}
  B: {name: A, role: global}
""")
        # "A" is configured for anchor B, so anchor A's fallback must avoid it.
        self.assertEqual([spec.name for spec in specs], ["A-2", "A"])
        self.assertIn("using 'A-2'", warnings)

    def test_case_insensitive_duplicate_names_fall_back(self):
        specs, warnings = self.load("""segments:
  A: {name: Same, role: direct}
  B: {name: same, role: global}
""")
        self.assertEqual([spec.name for spec in specs], ["Same", "B"])
        self.assertIn("already used by segment 'A'", warnings)

    def test_unusable_anchor_is_ignored_with_a_warning(self):
        specs, warnings = self.load("""segments:
  1: {name: One, role: direct}
  "bad anchor": {name: Two, role: direct}
  Good: {name: Good, role: direct}
""")
        self.assertEqual([spec.anchor for spec in specs], ["Good"])
        self.assertIn("not a usable identifier", warnings)

    def test_reject_mode_is_required_and_validated(self):
        for body in ("role: reject\n", "role: reject\n    reject-mode: invalid\n"):
            with self.subTest(body=body), tempfile.TemporaryDirectory() as tmp:
                with self.assertRaisesRegex(SystemExit, "requires reject-mode"):
                    load_segment_specs(self.write(Path(tmp), f"segments:\n  Example:\n    name: Example\n    {body}"))

    def test_reject_mode_on_a_non_reject_segment_is_ignored_with_a_warning(self):
        specs, warnings = self.load("""segments:
  Example:
    name: Example
    role: direct
    reject-mode: reject
""")
        self.assertIsNone(specs[0].reject_mode)
        self.assertIn("only used by reject segments", warnings)


class InheritedRoleTest(unittest.TestCase):
    def resolve(self, entries, mapping=None, roles=None, sources=None):
        mapping = mapping or {"A": "First", "B": "Second"}
        blocks = plan_blocks(entries, sources or {name: name for name in ("A", "B", "Unnamed")}, mapping)
        return resolve_segment_roles(blocks, roles or {"First": "global", "Second": "global"})

    def test_unnamed_block_inherits_only_metadata_from_unanimous_peers(self):
        rules = ['RULE-SET,Unnamed,Proxy', 'DOMAIN,barrier.example,DIRECT',
                 'RULE-SET,A,Proxy', 'RULE-SET,B,Proxy']
        before = list(rules)
        roles = self.resolve(rules)
        self.assertEqual(roles['merged-segment-01'], 'global')
        self.assertEqual(rules, before)

    def test_inheritance_is_independent_of_named_peer_order(self):
        for named in [('A', 'B'), ('B', 'A')]:
            roles = self.resolve([f'RULE-SET,{name},Proxy' for name in named] +
                                 ['DOMAIN,barrier.example,DIRECT', 'RULE-SET,Unnamed,Proxy'])
            self.assertEqual(roles['merged-segment-03'], 'global')

    def test_conflicting_roles_fail_even_if_they_share_a_dns_group(self):
        with self.assertRaisesRegex(ValueError, 'unambiguous role'):
            self.resolve(['RULE-SET,Unnamed,Proxy', 'DOMAIN,barrier.example,DIRECT',
                          'RULE-SET,A,Proxy', 'RULE-SET,B,Proxy'],
                         roles={'First': 'global', 'Second': 'ai'})

    def test_different_policy_or_wrapper_cannot_supply_a_role(self):
        for named in ['RULE-SET,A,DIRECT', 'SUB-RULE,(RULE-SET,A),Proxy']:
            with self.subTest(named=named), self.assertRaisesRegex(ValueError, 'unambiguous role'):
                self.resolve(['RULE-SET,Unnamed,Proxy', named], mapping={"A": "First"}, roles={"First": "global"})

    def test_normalized_rule_types_share_same_routing_role(self):
        rules = ['RULE-SET,Unnamed-ip,Proxy,no-resolve', 'DOMAIN,barrier.example,DIRECT',
                 'RULE-SET,A-domain,Proxy', 'RULE-SET,B-classical,Proxy']
        sources = {'Unnamed-ip': 'Unnamed', 'A-domain': 'A', 'B-classical': 'B'}
        roles = self.resolve(rules, sources=sources)
        self.assertEqual(roles['merged-segment-01'], 'global')

    def test_unnamed_foreign_block_inherits_global_from_named_peers(self):
        # Freeze the regression input: user edits to production rule order must
        # not invalidate the historical unnamed-block inheritance scenario.
        rules = ['RULE-SET,Lan,DIRECT', 'RULE-SET,Telegram,Proxy',
                 'RULE-SET,github,Proxy', 'RULE-SET,AppleProxy,Proxy',
                 'DOMAIN,barrier.example,DIRECT', 'RULE-SET,me-foreign,Proxy',
                 'RULE-SET,global,Proxy', 'MATCH,DIRECT']
        providers = ['Lan', 'Telegram', 'github', 'AppleProxy', 'me-foreign', 'global']
        mapping = {'Lan': 'Direct', 'me-foreign': 'Global-First', 'global': 'Global'}
        explicit = {'Direct': 'direct', 'Global-First': 'global', 'Global': 'global'}
        blocks = plan_blocks(rules, {name: name for name in providers}, mapping)
        roles = resolve_segment_roles(blocks, explicit)
        self.assertEqual(roles['merged-segment-02'], 'global')
        self.assertEqual({name: roles[name] for name in explicit}, explicit)

    def test_all_named_blocks_do_not_require_an_unnamed_role(self):
        for order in [('A', 'B'), ('B', 'A')]:
            with self.subTest(order=order):
                roles = self.resolve([f'RULE-SET,{name},Proxy' for name in order])
                self.assertEqual(roles, {'First': 'global', 'Second': 'global'})

    def test_unmatched_anchor_is_reported_and_ignored(self):
        stderr = io.StringIO()
        with contextlib.redirect_stderr(stderr):
            blocks = plan_blocks(['RULE-SET,A,Proxy'], {'A': 'A'}, {'A': 'First', 'B': 'Second'})
        self.assertEqual([block.name for block in blocks], ['First'])
        self.assertIn("did not match any provider: ['B']", stderr.getvalue())

    def test_named_segment_without_role_is_excluded_without_failing(self):
        roles = resolve_segment_roles(
            plan_blocks(['RULE-SET,A,Proxy'], {'A': 'A'}, {'A': 'First'}),
            {'First': None},
        )
        self.assertEqual(roles, {})


if __name__ == "__main__":
    unittest.main()
