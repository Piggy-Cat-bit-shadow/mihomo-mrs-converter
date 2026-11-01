import tempfile
import unittest
from pathlib import Path

from converter.exporters.loon import export_loon
from tests.support import optimized_config, provider, segment_views


class LoonExporterTest(unittest.TestCase):
    def test_export_consumes_segment_views(self):
        with tempfile.TemporaryDirectory() as tmp:
            config = optimized_config(
                providers=[provider("AI-domain", "domain", ["example.com"], segment="AI")],
                rules=["RULE-SET,AI-domain,AI"],
            )
            stats = export_loon(config, segment_views(config), Path(tmp), "https://example.invalid")
            self.assertEqual(stats["segments"], 1)

    def test_same_segment_dedup_keeps_first_seen_order(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            config = optimized_config(
                providers=[
                    provider("China-domain", "domain", ["first.example", "duplicate.example"], segment="China"),
                    provider("China-classical", "classical", ["DOMAIN,duplicate.example", "DOMAIN,last.example"], segment="China"),
                ],
                rules=["RULE-SET,China-domain,DIRECT", "RULE-SET,China-classical,DIRECT"],
            )
            export_loon(config, segment_views(config), root, "https://example.invalid")
            lines = (root / "loon/China.lsr").read_text(encoding="utf-8").splitlines()
            self.assertEqual(lines, [
                "DOMAIN,first.example",
                "DOMAIN,duplicate.example",
                "DOMAIN,last.example",
            ])


    def test_non_terminal_match_is_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            config = optimized_config(
                providers=[provider("AI-domain", "domain", ["ai.example"], segment="AI")],
                rules=["MATCH,DIRECT", "RULE-SET,AI-domain,AI"],
            )
            with self.assertRaisesRegex(SystemExit, "Loon MATCH must be the final rule"):
                export_loon(config, segment_views(config), Path(tmp), "https://example.invalid")


if __name__ == "__main__":
    unittest.main()
