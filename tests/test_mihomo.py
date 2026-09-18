import unittest
import tempfile
from pathlib import Path

from converter.exporters.mihomo import materialize_final_config, normalize_no_active_resolve


class MihomoExporterTest(unittest.TestCase):
    def test_ip_provider_reference_gets_no_resolve(self):
        config = {"rule-providers": {"A-ip": {"behavior": "ipcidr"}}, "rules": ["RULE-SET,A-ip,Proxy"]}
        output = normalize_no_active_resolve(config, {"A-ip": ["192.0.2.0/24"]})
        self.assertEqual(output["rules"], ["RULE-SET,A-ip,Proxy,no-resolve"])

    def test_nested_ip_provider_reference_gets_no_resolve(self):
        config = {"rule-providers": {"A-ip": {"behavior": "ipcidr"}}, "rules": [
            "AND,((RULE-SET,A-ip,Proxy),(NETWORK,tcp)),DIRECT"
        ]}
        output = normalize_no_active_resolve(config, {"A-ip": ["192.0.2.0/24"]})
        self.assertEqual(output["rules"], ["AND,((RULE-SET,A-ip,Proxy,no-resolve),(NETWORK,tcp)),DIRECT"])

    def test_size_limit_is_enforced_in_bytes_after_materialization(self):
        config = {"rule-providers": {"A": {"behavior": "domain", "size-limit": 1}}, "rules": ["RULE-SET,A,DIRECT"]}
        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaisesRegex(ValueError, "exceeds size-limit 1 bytes"):
                materialize_final_config(config, {"A": ["example.com"]}, Path(tmp), "https://x", None)

    def test_zero_size_limit_means_unlimited(self):
        config = {"rule-providers": {"A": {"behavior": "domain", "size-limit": 0}}, "rules": ["RULE-SET,A,DIRECT"]}
        with tempfile.TemporaryDirectory() as tmp:
            result = materialize_final_config(config, {"A": ["example.com"]}, Path(tmp), "https://x", None)
            self.assertIn("A", result["rule-providers"])


if __name__ == "__main__":
    unittest.main()
