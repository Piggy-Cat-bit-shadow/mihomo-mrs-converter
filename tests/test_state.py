import tempfile
import unittest
from pathlib import Path

from converter.state import build_managed_manifest, provider_fingerprint, read_managed_manifest, refresh_complete_config


class StateTest(unittest.TestCase):
    BASE_URL = "https://example.invalid/repo/main"

    def test_manifest_is_v2_without_suite(self):
        manifest = build_managed_manifest("https://example.invalid/repo/main", {"A": {"behavior": "domain", "url": "https://example.invalid/A.mrs", "path": "./ruleset/A.mrs"}})
        self.assertEqual(manifest["version"], 2)
        self.assertNotIn("suite", manifest)

    def test_invalid_v1_state_fails_closed(self):
        with tempfile.TemporaryDirectory() as tmp:
            dist = Path(tmp) / "dist"
            state = Path(tmp) / ".state"
            state.mkdir()
            (state / "managed-state.yaml").write_text("version: 1\nsuite: stage-final\nproviders: {}\n")
            with self.assertRaises(SystemExit):
                read_managed_manifest(dist)

    def _provider(self, name, marker=None):
        marker = marker or name.lower()
        return {"type": "http", "behavior": "domain", "format": "mrs", "url": f"https://example.invalid/{marker}.mrs", "path": f"./ruleset/{marker}.mrs"}

    def _manifest(self, providers):
        return {"version": 2, "base_url": self.BASE_URL, "providers": {
            name: {"fingerprint": provider_fingerprint(provider)} for name, provider in providers.items()
        }}

    def test_refresh_replaces_removes_adds_and_preserves_unmanaged_providers(self):
        old_a = self._provider("A", "old-a")
        old_b = self._provider("B")
        custom = {"type": "file", "behavior": "domain", "path": "./custom.yaml"}
        new_a = self._provider("A", "new-a")
        new_c = self._provider("C")
        complete = {"rule-providers": {"A": old_a, "B": old_b, "Custom": custom}, "rules": [
            "RULE-SET,A,DIRECT", "RULE-SET,B,Proxy", "MATCH,DIRECT"
        ]}
        final = {"rule-providers": {"A": new_a, "C": new_c}, "rules": [
            "RULE-SET,A,DIRECT", "RULE-SET,C,Proxy"
        ]}
        refreshed = refresh_complete_config(complete, final, self._manifest({"A": old_a, "B": old_b}), self.BASE_URL)
        self.assertEqual(refreshed["rule-providers"], {"Custom": custom, "A": new_a, "C": new_c})
        self.assertEqual(refreshed["rules"], ["RULE-SET,A,DIRECT", "RULE-SET,C,Proxy", "MATCH,DIRECT"])

    def test_refresh_detects_unmanaged_collision(self):
        custom = self._provider("Global-domain", "custom")
        with self.assertRaisesRegex(SystemExit, "collide with unmanaged"):
            refresh_complete_config(
                {"rule-providers": {"Global-domain": custom}, "rules": ["MATCH,DIRECT"]},
                {"rule-providers": {"Global-domain": self._provider("Global-domain")}, "rules": ["RULE-SET,Global-domain,DIRECT"]},
                {"version": 2, "providers": {}}, self.BASE_URL,
            )

    def test_refresh_rejects_modified_managed_provider(self):
        original = self._provider("A")
        modified = {**original, "interval": 3600}
        with self.assertRaisesRegex(SystemExit, "modified outside converter"):
            refresh_complete_config(
                {"rule-providers": {"A": modified}, "rules": ["RULE-SET,A,DIRECT"]},
                {"rule-providers": {"A": self._provider("A", "new")}, "rules": ["RULE-SET,A,DIRECT"]},
                self._manifest({"A": original}), self.BASE_URL,
            )

    def test_refresh_replaces_block_at_original_position(self):
        a, b = self._provider("A"), self._provider("B")
        complete = {"rule-providers": {"A": a, "B": b}, "rules": [
            "DOMAIN,foo.com,DIRECT", "RULE-SET,A,DIRECT", "RULE-SET,B,Proxy", "IP-CIDR,1.2.3.0/24,DIRECT", "MATCH,Proxy"
        ]}
        final = {"rule-providers": {"C": self._provider("C"), "D": self._provider("D")}, "rules": [
            "RULE-SET,C,DIRECT", "RULE-SET,D,Proxy", "MATCH,DIRECT"
        ]}
        refreshed = refresh_complete_config(complete, final, self._manifest({"A": a, "B": b}), self.BASE_URL)
        self.assertEqual(refreshed["rules"], [
            "DOMAIN,foo.com,DIRECT", "RULE-SET,C,DIRECT", "RULE-SET,D,Proxy", "IP-CIDR,1.2.3.0/24,DIRECT", "MATCH,Proxy"
        ])

    def test_refresh_allows_missing_old_provider_and_cleans_its_rules(self):
        old = self._provider("A")
        final = {"rule-providers": {"B": self._provider("B")}, "rules": ["RULE-SET,B,DIRECT"]}
        refreshed = refresh_complete_config(
            {"rule-providers": {}, "rules": ["RULE-SET,A,DIRECT", "MATCH,Proxy"]},
            final, self._manifest({"A": old}), self.BASE_URL,
        )
        self.assertEqual(refreshed["rules"], ["RULE-SET,B,DIRECT", "MATCH,Proxy"])

    def test_refresh_rejects_mixed_and_noncontiguous_managed_rules(self):
        a, b = self._provider("A"), self._provider("B")
        custom = self._provider("Custom")
        mixed = {"rule-providers": {"A": a, "B": b, "Custom": custom}, "rules": [
            "AND,((RULE-SET,A,DIRECT),(RULE-SET,Custom,DIRECT)),DIRECT"
        ]}
        final = {"rule-providers": {"A": a}, "rules": ["RULE-SET,A,DIRECT"]}
        with self.assertRaisesRegex(SystemExit, "mixed managed and unmanaged providers"):
            refresh_complete_config(mixed, final, self._manifest({"A": a, "B": b}), self.BASE_URL)
        noncontiguous = {"rule-providers": {"A": a, "B": b}, "rules": [
            "RULE-SET,A,DIRECT", "DOMAIN,barrier.example,DIRECT", "RULE-SET,B,Proxy"
        ]}
        with self.assertRaisesRegex(SystemExit, "not contiguous"):
            refresh_complete_config(noncontiguous, final, self._manifest({"A": a, "B": b}), self.BASE_URL)

    def test_bootstrap_managed_manifest_success_and_type_error_fix(self):
        from converter.state import bootstrap_managed_manifest
        p_a = self._provider("A")
        p_b = self._provider("B")
        complete = {
            "rule-providers": {"A": p_a, "B": p_b},
            "rules": ["DOMAIN,custom.com,DIRECT", "RULE-SET,A,DIRECT", "RULE-SET,B,Proxy", "MATCH,DIRECT"],
        }
        final = {
            "rule-providers": {"A": p_a, "B": p_b},
            "rules": ["RULE-SET,A,DIRECT", "RULE-SET,B,Proxy"],
        }
        manifest = bootstrap_managed_manifest(complete, final, self.BASE_URL)
        self.assertEqual(manifest["version"], 2)
        self.assertIn("A", manifest["providers"])
        self.assertIn("B", manifest["providers"])

    def test_bootstrap_managed_manifest_rejects_candidate_length_mismatch(self):
        from converter.state import bootstrap_managed_manifest
        p_a = self._provider("A")
        p_b = self._provider("B")
        complete = {
            "rule-providers": {"A": p_a, "B": p_b},
            "rules": ["RULE-SET,A,DIRECT", "MATCH,DIRECT"],
        }
        final = {
            "rule-providers": {"A": p_a, "B": p_b},
            "rules": ["RULE-SET,A,DIRECT", "RULE-SET,B,Proxy"],
        }
        with self.assertRaisesRegex(SystemExit, "does not match generated rules"):
            bootstrap_managed_manifest(complete, final, self.BASE_URL)

    def test_bootstrap_managed_manifest_rejects_semantic_mismatch(self):
        from converter.state import bootstrap_managed_manifest
        p_a = self._provider("A")
        p_b = self._provider("B")
        complete = {
            "rule-providers": {"A": p_a, "B": p_b},
            "rules": ["RULE-SET,A,DIRECT", "RULE-SET,B,REJECT"],
        }
        final = {
            "rule-providers": {"A": p_a, "B": p_b},
            "rules": ["RULE-SET,A,DIRECT", "RULE-SET,B,Proxy"],
        }
        with self.assertRaisesRegex(SystemExit, "policy or modifier mismatch"):
            bootstrap_managed_manifest(complete, final, self.BASE_URL)

    def test_bootstrap_managed_manifest_rejects_non_contiguous_rules(self):
        from converter.state import bootstrap_managed_manifest
        p_a = self._provider("A")
        p_b = self._provider("B")
        complete = {
            "rule-providers": {"A": p_a, "B": p_b},
            "rules": ["RULE-SET,A,DIRECT", "DOMAIN,barrier.com,DIRECT", "RULE-SET,B,Proxy"],
        }
        final = {
            "rule-providers": {"A": p_a, "B": p_b},
            "rules": ["RULE-SET,A,DIRECT", "RULE-SET,B,Proxy"],
        }
        with self.assertRaisesRegex(SystemExit, "contiguous"):
            bootstrap_managed_manifest(complete, final, self.BASE_URL)

    def test_bootstrap_managed_manifest_rejects_managed_provider_in_sub_rules(self):
        from converter.state import bootstrap_managed_manifest
        p_a = self._provider("A")
        complete = {
            "rule-providers": {"A": p_a},
            "sub-rules": {"Sub1": ["RULE-SET,A,DIRECT"]},
            "rules": ["RULE-SET,A,DIRECT"],
        }
        final = {
            "rule-providers": {"A": p_a},
            "rules": ["RULE-SET,A,DIRECT"],
        }
        with self.assertRaisesRegex(SystemExit, "managed provider appears in sub-rules"):
            bootstrap_managed_manifest(complete, final, self.BASE_URL)

    def test_generation_marker_validation_in_read_manifest(self):
        from converter.state import write_managed_manifest
        with tempfile.TemporaryDirectory() as tmp:
            dist = Path(tmp) / "dist"
            dist.mkdir()
            p_a = self._provider("A")
            manifest = write_managed_manifest(dist, self.BASE_URL, {"A": p_a})
            self.assertIn("generation", manifest)
            self.assertTrue((dist / ".generation").exists())
            self.assertEqual((dist / ".generation").read_text(encoding="utf-8").strip(), manifest["generation"])

            # Valid read
            read_back = read_managed_manifest(dist)
            self.assertIsNotNone(read_back)

            # Missing .generation marker fails closed
            (dist / ".generation").unlink()
            with self.assertRaisesRegex(SystemExit, "dist/.generation marker missing"):
                read_managed_manifest(dist)

            # Mismatched .generation fails closed
            (dist / ".generation").write_text("corrupt_generation_hash\n")
            with self.assertRaisesRegex(SystemExit, "dist/state generation mismatch"):
                read_managed_manifest(dist)

    def test_read_manifest_requires_generation_field(self):
        import yaml
        with tempfile.TemporaryDirectory() as tmp:
            dist = Path(tmp) / "dist"
            dist.mkdir()
            (dist / ".generation").write_text("any_gen\n")
            state_dir = Path(tmp) / ".state"
            state_dir.mkdir()
            state_file = state_dir / "managed-state.yaml"

            # Missing generation field
            state_file.write_text(yaml.safe_dump({
                "version": 2,
                "base_url": self.BASE_URL,
                "providers": {},
            }))
            with self.assertRaisesRegex(SystemExit, "requires non-empty generation field"):
                read_managed_manifest(dist)

            # Empty or whitespace generation field
            state_file.write_text(yaml.safe_dump({
                "version": 2,
                "base_url": self.BASE_URL,
                "providers": {},
                "generation": "   ",
            }))
            with self.assertRaisesRegex(SystemExit, "requires non-empty generation field"):
                read_managed_manifest(dist)

            # Non-string generation field
            state_file.write_text(yaml.safe_dump({
                "version": 2,
                "base_url": self.BASE_URL,
                "providers": {},
                "generation": 12345,
            }))
            with self.assertRaisesRegex(SystemExit, "requires non-empty generation field"):
                read_managed_manifest(dist)


if __name__ == "__main__":
    unittest.main()
