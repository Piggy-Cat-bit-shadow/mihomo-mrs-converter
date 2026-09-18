import json
import shutil
import tempfile
import unittest
from unittest.mock import patch
from pathlib import Path
import yaml

from converter.audit import audit_dist, validate_mihomo
from converter.rules import parse_rule
from converter.semantics import ensure_single_no_resolve, is_target_ip_kind


ROOT = Path(__file__).resolve().parents[1]
DIST = ROOT / "dist"


class NoActiveResolveTest(unittest.TestCase):
    def test_target_ip_normalization_is_single_and_source_ip_is_excluded(self) -> None:
        self.assertTrue(is_target_ip_kind("IP-CIDR"))
        self.assertFalse(is_target_ip_kind("SRC-IP-CIDR"))
        normalized = ensure_single_no_resolve(parse_rule("IP-CIDR,1.2.3.0/24,no-resolve,no-resolve").parts)
        self.assertEqual(normalized, ["IP-CIDR", "1.2.3.0/24", "no-resolve"])

    def test_audit_rejects_missing_loon_no_resolve(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "dist"
            shutil.copytree(DIST, root)
            path = root / "loon/AI.lsr"
            lines = path.read_text(encoding="utf-8").splitlines()
            path.write_text("\n".join(line.replace(",no-resolve", "", 1) if line.startswith("IP-") else line for line in lines) + "\n", encoding="utf-8")
            with self.assertRaisesRegex(ValueError, r"Loon: .*AI\.lsr.*missing no-resolve"):
                audit_dist(root)

    def test_audit_rejects_missing_artifact(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "dist"
            shutil.copytree(DIST, root)
            (root / "loon/AI.lsr").unlink()
            with self.assertRaisesRegex(ValueError, r"Loon: remote resources"):
                audit_dist(root)

    def test_audit_rejects_singbox_resolve(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "dist"
            shutil.copytree(DIST, root)
            path = root / "generated/singbox-rules.json"
            data = json.loads(path.read_text(encoding="utf-8"))
            data["route"]["rules"].append({"action": "resolve"})
            path.write_text(json.dumps(data), encoding="utf-8")
            with self.assertRaisesRegex(ValueError, r"Sing-box: route contains action: resolve"):
                audit_dist(root)

    def test_audit_decompiles_canonical_and_dns_srs(self) -> None:
        sing_box = shutil.which("sing-box")
        if not sing_box:
            self.skipTest("sing-box binary is required")
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "dist"
            shutil.copytree(DIST, root)
            audit_dist(root, sing_box=sing_box)

    def test_audit_rejects_corrupt_legacy_alias(self) -> None:
        sing_box = shutil.which("sing-box")
        if not sing_box:
            self.skipTest("sing-box binary is required")
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "dist"
            shutil.copytree(DIST, root)
            path = root / "singbox/AI-ip.srs"
            path.write_bytes(path.read_bytes() + b"corrupt")
            with self.assertRaisesRegex(ValueError, "legacy alias AI-ip"):
                audit_dist(root, sing_box=sing_box)

    def test_mihomo_audit_policy_parser_ignores_no_resolve(self) -> None:
        config = {
            "rule-providers": {"Test": {"behavior": "domain"}},
            "rules": ["RULE-SET,Test,OnlyPolicy,no-resolve"],
        }
        captured = {}
        def capture_run(args, **kwargs):
            captured.update(yaml.safe_load(Path(args[-1]).read_text(encoding="utf-8")))
        with patch("converter.audit.subprocess.run", side_effect=capture_run):
            validate_mihomo("mihomo", config)
        policies = {group["name"] for group in captured["proxy-groups"]}
        self.assertIn("OnlyPolicy", policies)
        self.assertNotIn("no-resolve", policies)


if __name__ == "__main__":
    unittest.main()
