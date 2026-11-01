import contextlib
import io
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import yaml

from converter.cli import main as cli_main
from converter.exporters.loon import export_loon
from converter.optimize import optimize_config
from converter.production_audit import artifact_segment
from converter.views import build_segment_views
from tests.support import normalized, optimized_config, provider, semantic_config


class RefactorRegressionTest(unittest.TestCase):
    def test_identity_comes_from_explicit_sources_not_artifact_names(self):
        # A split provider keeps its input key as its source, so an anchor with
        # the same name still matches even though the artifact has a suffix.
        semantic = semantic_config(
            providers=[normalized("Lan", "Lan-domain", "domain", ["lan.example"])],
            rules=["RULE-SET,Lan-domain,DIRECT"],
        )
        final = optimize_config(semantic, {"Lan": "Direct"})
        self.assertEqual(final.providers[0].name, "Direct-domain")
        self.assertEqual(final.providers[0].segment, "Direct")

    def test_artifact_segment_parses_only_the_published_name_contract(self):
        self.assertEqual(artifact_segment("China-domain"), "China")
        self.assertEqual(artifact_segment("China-ip-part-02"), "China")
        self.assertEqual(artifact_segment("Global-First-classical"), "Global-First")
        self.assertEqual(artifact_segment("Custom"), "Custom")

    def test_complete_suite_is_removed_from_cli(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "input.yaml"
            path.write_text(yaml.safe_dump({"rule-providers": {}, "rules": []}), encoding="utf-8")
            with patch.object(sys, "argv", ["convert.py", str(path), "--base-url", "https://example.invalid", "--complete-suite", "stage-final"]):
                with self.assertRaises(SystemExit) as error:
                    cli_main()
            self.assertEqual(error.exception.code, 2)

    def test_external_mrs_fails_closed_for_multi_client_build(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "input.yaml"
            path.write_text(yaml.safe_dump({
                "rule-providers": {"external": {"type": "http", "behavior": "domain", "format": "mrs", "url": "https://example.invalid/rules.mrs", "path": "./ruleset/external.mrs"}},
                "rules": ["RULE-SET,external,DIRECT"],
            }), encoding="utf-8")
            metadata = Path(tmp) / "segment-names.yaml"
            metadata.write_text("segments: {}\n", encoding="utf-8")
            argv = ["convert.py", str(path), "--base-url", "https://example.invalid", "--mihomo", "/bin/true", "--sing-box", "/bin/true", "--dist", str(Path(tmp) / "dist"), "--segment-names", str(metadata)]
            with patch.object(sys, "argv", argv), contextlib.redirect_stdout(io.StringIO()):
                with self.assertRaises(SystemExit) as error:
                    cli_main()
            self.assertIn("external MRS input is unsupported", str(error.exception))

    def test_unsupported_loon_subrule_fails_closed(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            config = optimized_config(
                providers=[provider("AI-domain", "domain", ["ai.example"], segment="AI")],
                rules=["SUB-RULE,(RULE-SET,AI-domain),AI-Routing"],
                sub_rules={"AI-Routing": ["DOMAIN,other.example,DIRECT", "MATCH,🤖 AI"]},
            )
            with self.assertRaises(SystemExit):
                export_loon(config, build_segment_views(config.providers), root / "out", "https://example.invalid")


if __name__ == "__main__":
    unittest.main()
