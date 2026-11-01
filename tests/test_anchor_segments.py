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
from converter.views import build_segment_views
from tests.support import normalized, semantic_config


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
                input_path.write_text(yaml.safe_dump(source), encoding='utf-8')
                segments = root / 'segments.yaml'
                segments.write_text(yaml.safe_dump({'segments': {
                    anchor: {'name': name, 'role': 'global'} for anchor, name in mapping.items()}}), encoding='utf-8')
                run_preflight(input_path, segments)
                semantic = semantic_config(
                    providers=[
                        normalized('me-foreign', 'me-foreign', 'domain', ['shared.example', 'first.example']),
                        normalized('global', 'global', 'domain', ['shared.example', 'global.example']),
                    ],
                    rules=source['rules'],
                )
                final = optimize_config(semantic, mapping)
                payloads = {provider.name: [entry.as_rule() for entry in provider.payload] for provider in final.providers}
                views = build_segment_views(final.providers)
                expected = [mapping[name] for name in order]
                export_egern(final, views, root, 'https://example.test')
                export_loon(final, views, root, 'https://example.test')
                export_singbox(final, root, 'https://example.test', shutil.which('sing-box'))
                route = json.loads((root / 'generated/singbox-rules.json').read_text(encoding='utf-8'))['route']
                self.assertEqual([item['tag'] for item in route['rule_set']], expected)
                self.assertEqual([item['rule_set'][0] for item in route['rules']], expected)
                self.assertEqual({p.name for p in (root / 'singbox').glob('*.srs')},
                                 {'Global-First.srs', 'Global.srs'})
                egern = yaml.safe_load((root / 'generated/egern-rules.yaml').read_text(encoding='utf-8'))
                self.assertEqual([Path(item['rule_set']['match']).stem for item in egern['rules']
                                  if 'rule_set' in item], expected)
                loon = (root / 'generated/loon-rules.conf').read_text(encoding='utf-8')
                self.assertLess(loon.index(f'tag={expected[0]},'), loon.index(f'tag={expected[1]},'))
                # Overlap remains in both artifacts; no cross-anchor deduplication.
                for name in expected:
                    self.assertIn('shared.example', payloads[f'{name}-domain'])


if __name__ == "__main__":
    unittest.main()
