"""Audit gates for published provider and DNS artifacts."""

import tempfile
import unittest
from pathlib import Path

from converter.audit import _check_dns_artifacts, _check_provider_artifacts


def write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


class ProviderArtifactAuditTest(unittest.TestCase):
    def config(self, url: str, fmt: str = "yaml") -> dict:
        return {
            "rule-providers": {
                "A": {"behavior": "classical", "format": fmt, "url": url, "path": "./ruleset/A"},
            },
            "rules": ["RULE-SET,A,DIRECT"],
        }

    def test_missing_artifact_is_reported(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            config = self.config("https://example.invalid/dist/classical/A.yaml")
            with self.assertRaisesRegex(ValueError, "missing artifact"):
                _check_provider_artifacts(root, config)

    def test_empty_artifact_is_reported(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            config = self.config("https://example.invalid/dist/classical/A.yaml")
            write(root / "classical" / "A.yaml", "")
            with self.assertRaisesRegex(ValueError, "empty artifact"):
                _check_provider_artifacts(root, config)

    def test_yaml_artifact_without_payload_is_reported(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            config = self.config("https://example.invalid/dist/classical/A.yaml")
            write(root / "classical" / "A.yaml", "payload: []\n")
            with self.assertRaisesRegex(ValueError, "has no payload"):
                _check_provider_artifacts(root, config)

    def test_provider_without_dist_url_is_reported(self):
        with tempfile.TemporaryDirectory() as tmp:
            config = self.config("https://example.invalid/elsewhere/A.yaml")
            with self.assertRaisesRegex(ValueError, "no resolvable artifact URL"):
                _check_provider_artifacts(Path(tmp), config)

    def test_valid_yaml_and_binary_artifacts_pass(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write(root / "classical" / "A.yaml", "payload:\n- DOMAIN,example.com\n")
            _check_provider_artifacts(root, self.config("https://example.invalid/dist/classical/A.yaml"))
            (root / "domain").mkdir()
            (root / "domain" / "A.mrs").write_bytes(b"\x00\x01")
            _check_provider_artifacts(root, self.config("https://example.invalid/dist/domain/A.mrs", "mrs"))


class DnsArtifactAuditTest(unittest.TestCase):
    def make_group(self, root: Path, group: str, *, egern: bool = True, empty_mrs: bool = False) -> None:
        (root / "dns" / "singbox").mkdir(parents=True, exist_ok=True)
        (root / "dns" / "mihomo").mkdir(parents=True, exist_ok=True)
        (root / "dns" / "egern").mkdir(parents=True, exist_ok=True)
        (root / "dns" / "singbox" / f"{group}-domain.srs").write_bytes(b"binary")
        (root / "dns" / "mihomo" / f"{group}-domain.mrs").write_bytes(b"" if empty_mrs else b"binary")
        write(root / "dns" / "mihomo" / f"{group}-classical.yaml", "payload:\n- DOMAIN-KEYWORD,k\n")
        if egern:
            write(root / "dns" / "egern" / f"{group}.yaml", "domain_set:\n- example.com\n")

    def test_all_families_must_exist_for_every_group(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self.make_group(root, "China")
            self.make_group(root, "Global")
            _check_dns_artifacts(root)

    def test_missing_egern_dns_file_is_reported(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self.make_group(root, "China")
            self.make_group(root, "Global", egern=False)
            with self.assertRaisesRegex(ValueError, "missing or empty Egern YAML"):
                _check_dns_artifacts(root)

    def test_empty_mihomo_dns_binary_is_reported(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self.make_group(root, "China", empty_mrs=True)
            with self.assertRaisesRegex(ValueError, "missing or empty mihomo domain MRS"):
                _check_dns_artifacts(root)

    def test_missing_dns_directory_is_reported(self):
        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaisesRegex(ValueError, "contains no SRS artifacts"):
                _check_dns_artifacts(Path(tmp))


if __name__ == "__main__":
    unittest.main()
