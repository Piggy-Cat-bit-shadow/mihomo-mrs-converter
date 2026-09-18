import tempfile
import unittest
from pathlib import Path

from converter.exporters.egern import export_egern


class EgernExporterTest(unittest.TestCase):
    def test_export_consumes_payload_mapping(self):
        with tempfile.TemporaryDirectory() as tmp:
            stats = export_egern({"rule-providers": {"AI-domain": {"behavior": "domain"}}, "rules": ["RULE-SET,AI-domain,AI"]}, {"AI-domain": ["example.com"]}, Path(tmp), "https://example.invalid")
            self.assertEqual(stats["segments"], 1)


if __name__ == "__main__":
    unittest.main()
