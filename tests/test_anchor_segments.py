"""End-to-end anchor boundaries without remote provider dependencies."""
import json
import shutil
import tempfile
import unittest
from pathlib import Path

import yaml

from converter.exporters.egern import export_egern
from converter.exporters.loon import export_loon
from converter.exporters.singbox import export_singbox
from converter.optimize import optimize_config
from converter.preflight import run_preflight


class AnchorExportTest(unittest.TestCase):
    def test_repository_config_preflight(self):
        root = Path(__file__).resolve().parents[1]
        run_preflight(root / 'config/rules.yaml', root / 'segment-names.yaml', root / 'config/export.yaml')

    @unittest.skipUnless(shutil.which('sing-box'), 'requires sing-box')
    def test_adjacent_same_policy_anchors_survive_all_exporters_and_reordering(self):
        for order in [('me-foreign', 'global'), ('global', 'me-foreign')]:
            with self.subTest(order=order), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                mapping = {'me-foreign': 'Global-First', 'global': 'Global'}
                source = {'rule-providers': {name: {'behavior': 'domain'} for name in order},
                          'rules': [f'RULE-SET,{name},Proxy' for name in order] + ['MATCH,DIRECT']}
                input_path = root / 'rules.yaml'
                input_path.write_text(yaml.safe_dump(source))
                segments = root / 'segments.yaml'
                segments.write_text(yaml.safe_dump({'segments': {
                    anchor: {'name': name, 'role': 'global'} for anchor, name in mapping.items()}}))
                run_preflight(input_path, segments)
                final, payloads, _ = optimize_config(source, {
                    'me-foreign': ['shared.example', 'first.example'],
                    'global': ['shared.example', 'global.example'],
                }, mapping)
                expected = [mapping[name] for name in order]
                export_egern(final, payloads, root, 'https://example.test')
                export_loon(final, payloads, root, 'https://example.test')
                export_singbox(final, payloads, root, 'https://example.test', shutil.which('sing-box'))
                route = json.loads((root / 'generated/singbox-rules.json').read_text())['route']
                self.assertEqual([item['tag'] for item in route['rule_set']], expected)
                self.assertEqual([item['rule_set'][0] for item in route['rules']], expected)
                self.assertEqual({p.name for p in (root / 'singbox').glob('*.srs')},
                                 {'Global-First.srs', 'Global.srs'})
                egern = yaml.safe_load((root / 'generated/egern-rules.yaml').read_text())
                self.assertEqual([Path(item['rule_set']['match']).stem for item in egern['rules']
                                  if 'rule_set' in item], expected)
                loon = (root / 'generated/loon-rules.conf').read_text()
                self.assertLess(loon.index(f'tag={expected[0]},'), loon.index(f'tag={expected[1]},'))
                # Overlap remains in both artifacts; no cross-anchor deduplication.
                for name in expected:
                    self.assertIn('shared.example', payloads[f'{name}-domain'])
