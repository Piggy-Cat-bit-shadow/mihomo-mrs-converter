import unittest
import tempfile
from pathlib import Path

from converter.exporters.mihomo import materialize_final_config, normalize_no_active_resolve


class MihomoExporterTest(unittest.TestCase):
    def test_domain_provider_drops_redundant_no_resolve(self):
        config = {"rule-providers": {"A-domain": {"behavior": "domain"}}, "rules": ["RULE-SET,A-domain,Proxy,no-resolve"]}
        output = normalize_no_active_resolve(config, {"A-domain": ["example.com"]})
        self.assertEqual(output["rules"], ["RULE-SET,A-domain,Proxy"])

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

    def test_ip_provider_modifier_is_single_and_idempotent(self):
        config = {"rule-providers": {"A-ip": {"behavior": "ipcidr"}}, "rules": ["RULE-SET,A-ip,Proxy,NO-RESOLVE,no-resolve"]}
        once = normalize_no_active_resolve(config, {"A-ip": ["192.0.2.0/24"]})
        twice = normalize_no_active_resolve(once, {"A-ip": ["192.0.2.0/24"]})
        expected = ["RULE-SET,A-ip,Proxy,no-resolve"]
        self.assertEqual(once["rules"], expected)
        self.assertEqual(twice["rules"], expected)

    def test_classical_payload_controls_no_resolve(self):
        domain = {"rule-providers": {"A": {"behavior": "classical"}}, "rules": ["RULE-SET,A,Proxy,no-resolve"]}
        ip = {"rule-providers": {"A": {"behavior": "classical"}}, "rules": ["RULE-SET,A,Proxy,no-resolve"]}
        self.assertEqual(normalize_no_active_resolve(domain, {"A": ["DOMAIN,example.com"]})["rules"], ["RULE-SET,A,Proxy"])
        self.assertEqual(normalize_no_active_resolve(ip, {"A": ["IP-CIDR,203.0.113.0/24"]})["rules"], ["RULE-SET,A,Proxy,no-resolve"])

    def test_split_classical_provider_gets_domain_and_ip_modifiers(self):
        config = {
            "rule-providers": {"A-domain": {"behavior": "domain"}, "A-ip": {"behavior": "ipcidr"}},
            "rules": ["RULE-SET,A-domain,REJECT-DROP,no-resolve", "RULE-SET,A-ip,REJECT-DROP,no-resolve"],
        }
        output = normalize_no_active_resolve(config, {"A-domain": ["httpdns.example"], "A-ip": ["203.107.1.0/24"]})
        self.assertEqual(output["rules"], ["RULE-SET,A-domain,REJECT-DROP", "RULE-SET,A-ip,REJECT-DROP,no-resolve"])

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
