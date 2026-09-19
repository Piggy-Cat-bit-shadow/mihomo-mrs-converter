import contextlib
import io
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import yaml

from converter import Behavior, ProviderIdentity
from converter.cli import main as cli_main
from converter.model import format_provider_name, parse_provider_identity
from converter.exporters.loon import export_loon


class RefactorRegressionTest(unittest.TestCase):
    def test_identity_serialization(self) -> None:
        identity = ProviderIdentity("Global", Behavior.IPCIDR)
        self.assertEqual(format_provider_name(identity), "Global-ip")
        self.assertEqual(format_provider_name(ProviderIdentity("Global", Behavior.IPCIDR, 2)), "Global-ip-part-02")
        self.assertEqual(parse_provider_identity("Global-ip-part-02"), ProviderIdentity("Global", Behavior.IPCIDR, 2))

    def test_complete_suite_is_removed_from_cli(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "input.yaml"
            path.write_text(yaml.safe_dump({"rule-providers": {}, "rules": []}))
            with patch.object(sys, "argv", ["convert.py", str(path), "--base-url", "https://example.invalid", "--complete-suite", "stage-final"]):
                with self.assertRaises(SystemExit) as error:
                    cli_main()
            self.assertEqual(error.exception.code, 2)

    def test_external_mrs_fails_closed_for_multi_client_build(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "input.yaml"
            path.write_text(yaml.safe_dump({
                "rule-providers": {"external": {"type": "http", "behavior": "domain", "format": "mrs", "url": "https://example.invalid/rules.mrs", "path": "./ruleset/external.mrs"}},
                "rules": ["RULE-SET,external,DIRECT"],
            }))
            argv = ["convert.py", str(path), "--base-url", "https://example.invalid", "--mihomo", "/bin/true", "--sing-box", "/bin/true", "--dist", str(Path(tmp) / "dist")]
            with patch.object(sys, "argv", argv), contextlib.redirect_stdout(io.StringIO()):
                with self.assertRaises(SystemExit) as error:
                    cli_main()
            self.assertIn("external MRS input is unsupported", str(error.exception))

    def test_unsupported_loon_subrule_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            config = {
                "sub-rules": {"AI-Routing": ["DOMAIN,other.example,DIRECT", "MATCH,🤖 AI"]},
                "rule-providers": {"AI-domain": {"behavior": "domain"}},
                "rules": ["SUB-RULE,(RULE-SET,AI-domain),AI-Routing"],
            }
            with self.assertRaises(SystemExit):
                export_loon(config, {}, root / "out", "https://example.invalid")


if __name__ == "__main__":
    unittest.main()
