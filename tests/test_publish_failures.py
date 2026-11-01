"""Publish/rollback fault injection around the atomic dist and state commit."""

import shutil
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import yaml

from converter.model import BuildConfig
from converter.pipeline import build


def snapshot(root: Path) -> dict[str, bytes]:
    return {
        path.relative_to(root).as_posix(): path.read_bytes()
        for path in sorted(root.rglob("*"))
        if path.is_file()
    }


class PublishFailureTest(unittest.TestCase):
    def setUp(self):
        if not shutil.which("mihomo"):
            self.skipTest("real mihomo binary is required")
        self._tmp = tempfile.TemporaryDirectory()
        self.root = Path(self._tmp.name)
        self.dist = self.root / "dist"
        self.input = self.root / "input.yaml"
        self.state = self.root / ".state" / "managed-state.yaml"

    def tearDown(self):
        self._tmp.cleanup()

    def write_input(self, extra: bool = False) -> None:
        providers = {
            "Lan": {"type": "http", "behavior": "domain", "format": "yaml", "url": "https://example.invalid/lan"},
        }
        rules = ["RULE-SET,Lan,DIRECT", "MATCH,DIRECT"]
        if extra:
            providers["Wan"] = {"type": "http", "behavior": "domain", "format": "yaml", "url": "https://example.invalid/wan"}
            rules = ["RULE-SET,Lan,DIRECT", "RULE-SET,Wan,Proxy", "MATCH,DIRECT"]
        self.input.write_text(yaml.safe_dump({"rule-providers": providers, "rules": rules}), encoding="utf-8")

    def build(self):
        def fetch(url, headers, cache):
            return "payload:\n- lan.example\n"

        no_op = {"route": {}}
        with patch("converter.net.fetch_text", side_effect=fetch), \
             patch("converter.pipeline.export_egern", return_value=no_op), \
             patch("converter.pipeline.export_loon", return_value=no_op), \
             patch("converter.pipeline.export_singbox", return_value=no_op), \
             patch("converter.pipeline.export_singbox_dns", return_value=no_op), \
             patch("converter.pipeline.export_dns", return_value=no_op):
            return build(BuildConfig(self.input, self.dist, "https://example.invalid/repo/main", shutil.which("mihomo"), None))

    def assert_rolled_back(self, dist_before: dict[str, bytes], state_before: bytes) -> None:
        self.assertTrue(self.dist.exists())
        self.assertEqual(snapshot(self.dist), dist_before)
        self.assertEqual(self.state.read_bytes(), state_before)
        self.assertFalse(self.dist.with_name(f".{self.dist.name}.previous").exists())
        self.assertEqual(list(self.root.glob("mihomo-mrs-publish-*")), [])

    def test_state_write_failure_after_swap_restores_published_generation(self):
        self.write_input()
        self.build()
        dist_before = snapshot(self.dist)
        state_before = self.state.read_bytes()

        self.write_input(extra=True)
        with patch("converter.pipeline.write_managed_manifest", side_effect=RuntimeError("state write failed")):
            with self.assertRaisesRegex(RuntimeError, "state write failed"):
                self.build()
        self.assert_rolled_back(dist_before, state_before)

    def test_generation_marker_failure_before_swap_leaves_publication_untouched(self):
        self.write_input()
        self.build()
        dist_before = snapshot(self.dist)
        state_before = self.state.read_bytes()

        self.write_input(extra=True)
        with patch("converter.pipeline.build_managed_manifest", side_effect=RuntimeError("generation failed")):
            with self.assertRaisesRegex(RuntimeError, "generation failed"):
                self.build()
        self.assert_rolled_back(dist_before, state_before)

    def test_keyboard_interrupt_in_exporter_rolls_back_the_whole_build(self):
        self.write_input()
        self.build()
        dist_before = snapshot(self.dist)
        state_before = self.state.read_bytes()

        self.write_input(extra=True)
        no_op = {"route": {}}
        with patch("converter.net.fetch_text", side_effect=lambda url, headers, cache: "payload:\n- lan.example\n"), \
             patch("converter.pipeline.export_egern", side_effect=KeyboardInterrupt), \
             patch("converter.pipeline.export_loon", return_value=no_op), \
             patch("converter.pipeline.export_singbox", return_value=no_op), \
             patch("converter.pipeline.export_singbox_dns", return_value=no_op), \
             patch("converter.pipeline.export_dns", return_value=no_op):
            with self.assertRaises(KeyboardInterrupt):
                build(BuildConfig(self.input, self.dist, "https://example.invalid/repo/main", shutil.which("mihomo"), None))
        self.assert_rolled_back(dist_before, state_before)

    def test_leftover_previous_directory_is_cleaned_by_the_next_build(self):
        self.write_input()
        self.build()
        stale = self.dist.with_name(f".{self.dist.name}.previous")
        stale.mkdir()
        (stale / "stale-file").write_text("stale", encoding="utf-8")

        self.build()
        self.assertTrue(self.dist.exists())
        self.assertFalse(stale.exists())

    def test_first_build_generation_failure_leaves_no_dist_state_or_temp(self):
        self.write_input()
        with patch("converter.pipeline.build_managed_manifest", side_effect=RuntimeError("generation failed")):
            with self.assertRaisesRegex(RuntimeError, "generation failed"):
                self.build()
        self.assertFalse(self.dist.exists())
        self.assertFalse(self.state.exists())
        self.assertEqual(list(self.root.glob("mihomo-mrs-publish-*")), [])


if __name__ == "__main__":
    unittest.main()
