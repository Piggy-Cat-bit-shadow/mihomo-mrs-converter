import tempfile
import unittest
from pathlib import Path

from converter.segments import load_segment_specs, segment_mapping, segment_roles


class SegmentMetadataTest(unittest.TestCase):
    def write(self, root: Path, value: str) -> Path:
        path = root / "segments.yaml"
        path.write_text(value, encoding="utf-8")
        return path

    def test_loader_exposes_one_validated_identity_model(self):
        with tempfile.TemporaryDirectory() as tmp:
            specs = load_segment_specs(self.write(Path(tmp), """segments:
  ExampleReject:
    name: ExampleReject
    role: reject
    reject-mode: reject
"""))
        self.assertEqual(segment_mapping(specs), {"ExampleReject": "ExampleReject"})
        self.assertEqual(segment_roles(specs), {"ExampleReject": "reject"})

    def test_missing_role_is_fail_fast(self):
        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaisesRegex(SystemExit, "requires a non-empty string role"):
                load_segment_specs(self.write(Path(tmp), """segments:
  Example:
    name: Example
"""))

    def test_duplicate_names_are_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaisesRegex(SystemExit, "duplicate segment name"):
                load_segment_specs(self.write(Path(tmp), """segments:
  one: {name: Same, role: direct}
  two: {name: Same, role: reject, reject-mode: reject}
"""))

    def test_reject_mode_is_required_and_validated(self):
        cases = (
            ("role: reject\n", "requires reject-mode"),
            ("role: reject\n    reject-mode: invalid\n", "requires reject-mode"),
            ("role: direct\n    reject-mode: reject\n", "only valid for role=reject"),
        )
        for body, message in cases:
            with self.subTest(body=body), tempfile.TemporaryDirectory() as tmp:
                with self.assertRaisesRegex(SystemExit, message):
                    load_segment_specs(self.write(Path(tmp), f"segments:\n  Example:\n    name: Example\n    {body}"))


if __name__ == "__main__":
    unittest.main()


class InheritedRoleTest(unittest.TestCase):
    def resolve(self, entries, mapping=None, roles=None):
        from converter.segments import resolve_segment_roles
        config = {'rules': entries, 'rule-providers': {
            name: {'behavior': 'domain'} for name in ['A', 'B', 'Unnamed']}}
        return resolve_segment_roles(config, mapping or {'A': 'First', 'B': 'Second'},
                                     roles or {'First': 'global', 'Second': 'global'})

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
                self.resolve(['RULE-SET,Unnamed,Proxy', named])

    def test_normalized_rule_types_share_same_routing_role(self):
        from converter.segments import resolve_segment_roles
        config = {'rules': ['RULE-SET,Unnamed-ip,Proxy,no-resolve', 'DOMAIN,barrier.example,DIRECT',
                            'RULE-SET,A-domain,Proxy', 'RULE-SET,B-classical,Proxy'],
                  'rule-providers': {'Unnamed-ip': {'behavior': 'ipcidr'},
                                     'A-domain': {'behavior': 'domain'},
                                     'B-classical': {'behavior': 'classical'}}}
        roles = resolve_segment_roles(config, {'A': 'First', 'B': 'Second'},
                                      {'First': 'global', 'Second': 'global'})
        self.assertEqual(roles['merged-segment-01'], 'global')

    def test_repository_unnamed_block_is_global(self):
        from converter.segments import resolve_segment_roles
        from converter.yamlio import load_yaml_unique
        root = Path(__file__).resolve().parents[1]
        specs = load_segment_specs(root / 'segment-names.yaml')
        roles = resolve_segment_roles(load_yaml_unique(root / 'config/rules.yaml'),
                                      segment_mapping(specs), segment_roles(specs))
        self.assertEqual(roles['merged-segment-02'], 'global')
