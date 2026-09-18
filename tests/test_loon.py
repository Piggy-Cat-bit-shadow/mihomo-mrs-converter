import tempfile
import unittest
from pathlib import Path
import yaml

from converter.exporters.loon import export_loon


class LoonExporterTest(unittest.TestCase):
    def test_export_consumes_payload_mapping(self):
        with tempfile.TemporaryDirectory() as tmp:
            stats = export_loon({"rule-providers": {"AI-domain": {"behavior": "domain"}}, "rules": ["RULE-SET,AI-domain,AI"]}, {"AI-domain": ["example.com"]}, Path(tmp), "https://example.invalid")
            self.assertEqual(stats["segments"], 1)

    def test_same_segment_dedup_keeps_first_seen_order(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            export_loon(
                {"rule-providers": {
                    "China-domain": {"behavior": "domain"},
                    "China-classical": {"behavior": "classical"},
                }, "rules": [
                    "RULE-SET,China-domain,DIRECT",
                    "RULE-SET,China-classical,DIRECT",
                ]},
                {
                    "China-domain": ["first.example", "duplicate.example"],
                    "China-classical": ["DOMAIN,duplicate.example", "DOMAIN,last.example"],
                }, root, "https://example.invalid",
            )
            lines = (root / "loon/China.lsr").read_text(encoding="utf-8").splitlines()
            self.assertEqual(lines, [
                "DOMAIN,first.example",
                "DOMAIN,duplicate.example",
                "DOMAIN,last.example",
            ])


if __name__ == "__main__":
    unittest.main()
