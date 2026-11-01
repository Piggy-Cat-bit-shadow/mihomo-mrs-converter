"""Naming tolerance end-to-end: warnings and fallbacks must not abort a build."""

import contextlib
import io
import shutil
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import yaml

from converter.model import BuildConfig
from converter.pipeline import build
from converter.preflight import PreflightError, run_preflight
from converter.state import read_managed_manifest


class NamingToleranceBuildTest(unittest.TestCase):
    def setUp(self):
        if not shutil.which("mihomo"):
            self.skipTest("real mihomo binary is required")
        self._tmp = tempfile.TemporaryDirectory()
        self.root = Path(self._tmp.name)
        self.dist = self.root / "dist"
        self.input = self.root / "rules.yaml"
        self.segments = self.root / "segment-names.yaml"
        self.export = self.root / "export.yaml"
        self.input.write_text(yaml.safe_dump({
            "rule-providers": {
                "A": {"type": "http", "behavior": "domain", "format": "yaml", "url": "https://example.invalid/a"},
                "B": {"type": "http", "behavior": "domain", "format": "yaml", "url": "https://example.invalid/b"},
            },
            "rules": ["RULE-SET,A,DIRECT", "RULE-SET,B,Proxy", "MATCH,DIRECT"],
        }), encoding="utf-8")
        self.write_export({"China": ["direct"], "Global": ["global"]})

    def tearDown(self):
        self._tmp.cleanup()

    def write_export(self, groups: dict[str, list[str]]) -> None:
        self.export.write_text(yaml.safe_dump({
            "dns": {"groups": {name: {"roles": roles} for name, roles in groups.items()}},
        }), encoding="utf-8")

    def write_segments(self, value: dict) -> None:
        self.segments.write_text(yaml.safe_dump({"segments": value}), encoding="utf-8")

    def build(self) -> tuple[object, str]:
        no_op = {"route": {}}
        stderr = io.StringIO()
        def fetch(url, headers, cache):
            return "payload:\n- example.com\n"
        with contextlib.redirect_stderr(stderr), \
             patch("converter.net.fetch_text", side_effect=fetch), \
             patch("converter.pipeline.export_egern", return_value=no_op), \
             patch("converter.pipeline.export_loon", return_value=no_op), \
             patch("converter.pipeline.export_singbox", return_value=no_op), \
             patch("converter.pipeline.export_singbox_dns", return_value=no_op):
            result = build(BuildConfig(
                self.input, self.dist, "https://example.invalid/repo/main", shutil.which("mihomo"), None,
                segment_names=self.segments, export_config=self.export,
            ))
        return result, stderr.getvalue()

    def test_duplicate_display_names_build_with_distinct_artifacts(self):
        self.write_segments({
            "A": {"name": "Same", "role": "direct"},
            "B": {"name": "Same", "role": "global"},
        })
        run_preflight(self.input, self.segments, self.export)
        _, warnings = self.build()
        self.assertIn("already used by segment 'A'", warnings)
        manifest = read_managed_manifest(self.dist)
        self.assertEqual(sorted(manifest["providers"]), ["B-domain", "Same-domain"])
        self.assertTrue((self.dist / "domain" / "Same-domain.mrs").exists())
        self.assertTrue((self.dist / "domain" / "B-domain.mrs").exists())

    def test_invalid_metadata_name_falls_back_to_the_anchor(self):
        self.write_segments({
            "A": {"name": "bad/name", "role": "direct"},
            "B": {"name": "Good", "role": "global"},
        })
        run_preflight(self.input, self.segments, self.export)
        _, warnings = self.build()
        self.assertIn("not a safe artifact name", warnings)
        self.assertEqual(sorted(read_managed_manifest(self.dist)["providers"]), ["A-domain", "Good-domain"])

    def test_unmatched_anchor_is_ignored_and_the_build_proceeds(self):
        self.write_segments({
            "Nope": {"name": "Nope", "role": "direct"},
            "A": {"name": "SegA", "role": "direct"},
            "B": {"name": "SegB", "role": "global"},
        })
        run_preflight(self.input, self.segments, self.export)
        _, warnings = self.build()
        self.assertIn("did not match any provider: ['Nope']", warnings)
        self.assertEqual(sorted(read_managed_manifest(self.dist)["providers"]), ["SegA-domain", "SegB-domain"])

    def test_unnamed_block_inherits_a_peer_role_and_warns_about_positional_identity(self):
        self.write_export({"Global": ["global"]})
        self.input.write_text(yaml.safe_dump({
            "rule-providers": {
                "A": {"type": "http", "behavior": "domain", "format": "yaml", "url": "https://example.invalid/a"},
                "B": {"type": "http", "behavior": "domain", "format": "yaml", "url": "https://example.invalid/b"},
            },
            "rules": ["RULE-SET,A,Proxy", "NETWORK,TCP,DIRECT", "RULE-SET,B,Proxy", "MATCH,DIRECT"],
        }), encoding="utf-8")
        self.write_segments({"A": {"name": "SegA", "role": "global"}})
        run_preflight(self.input, self.segments, self.export)
        _, warnings = self.build()
        self.assertIn("positional identities", warnings)
        manifest = read_managed_manifest(self.dist)
        self.assertEqual(sorted(manifest["providers"]), ["SegA-domain", "merged-segment-02-domain"])

    def test_invalid_role_fails_closed_when_dns_groups_need_it(self):
        self.write_segments({
            "A": {"name": "SegA", "role": "nonsense"},
            "B": {"name": "SegB", "role": "global"},
        })
        with self.assertRaisesRegex(PreflightError, "not assigned to any configured segment"):
            run_preflight(self.input, self.segments, self.export)
        no_op = {"route": {}}
        with patch("converter.net.fetch_text", side_effect=lambda url, headers, cache: "payload:\n- example.com\n"), \
             patch("converter.pipeline.export_egern", return_value=no_op), \
             patch("converter.pipeline.export_loon", return_value=no_op), \
             patch("converter.pipeline.export_singbox", return_value=no_op), \
             patch("converter.pipeline.export_singbox_dns", return_value=no_op):
            with self.assertRaisesRegex(SystemExit, "DNS export requires missing segment"):
                build(BuildConfig(
                    self.input, self.dist, "https://example.invalid/repo/main", shutil.which("mihomo"), None,
                    segment_names=self.segments, export_config=self.export,
                ))
        self.assertFalse(self.dist.exists())


if __name__ == "__main__":
    unittest.main()
