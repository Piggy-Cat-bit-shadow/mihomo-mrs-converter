import unittest
import tempfile
from pathlib import Path

from converter.exporters.mihomo import materialize_final_config, normalize_no_active_resolve
from converter.model import ProviderMetadata
from tests.support import optimized_config, provider


class MihomoExporterTest(unittest.TestCase):
    def test_domain_provider_drops_redundant_no_resolve(self):
        config = optimized_config(
            providers=[provider("A-domain", "domain", ["example.com"], segment="A")],
            rules=["RULE-SET,A-domain,Proxy,no-resolve"],
        )
        self.assertEqual(normalize_no_active_resolve(config).rules, ("RULE-SET,A-domain,Proxy",))

    def test_ip_provider_reference_gets_no_resolve(self):
        config = optimized_config(
            providers=[provider("A-ip", "ipcidr", ["192.0.2.0/24"], segment="A")],
            rules=["RULE-SET,A-ip,Proxy"],
        )
        self.assertEqual(normalize_no_active_resolve(config).rules, ("RULE-SET,A-ip,Proxy,no-resolve",))

    def test_nested_ip_provider_reference_gets_no_resolve(self):
        config = optimized_config(
            providers=[provider("A-ip", "ipcidr", ["192.0.2.0/24"], segment="A")],
            rules=["AND,((RULE-SET,A-ip,Proxy),(NETWORK,tcp)),DIRECT"],
        )
        self.assertEqual(
            normalize_no_active_resolve(config).rules,
            ("AND,((RULE-SET,A-ip,Proxy,no-resolve),(NETWORK,tcp)),DIRECT",),
        )

    def test_ip_provider_modifier_is_single_and_idempotent(self):
        config = optimized_config(
            providers=[provider("A-ip", "ipcidr", ["192.0.2.0/24"], segment="A")],
            rules=["RULE-SET,A-ip,Proxy,NO-RESOLVE,no-resolve"],
        )
        once = normalize_no_active_resolve(config)
        twice = normalize_no_active_resolve(once)
        expected = ("RULE-SET,A-ip,Proxy,no-resolve",)
        self.assertEqual(once.rules, expected)
        self.assertEqual(twice.rules, expected)

    def test_classical_payload_controls_no_resolve(self):
        domain = optimized_config(
            providers=[provider("A", "classical", ["DOMAIN,example.com"], segment="A")],
            rules=["RULE-SET,A,Proxy,no-resolve"],
        )
        ip = optimized_config(
            providers=[provider("A", "classical", ["IP-CIDR,203.0.113.0/24"], segment="A")],
            rules=["RULE-SET,A,Proxy,no-resolve"],
        )
        self.assertEqual(normalize_no_active_resolve(domain).rules, ("RULE-SET,A,Proxy",))
        self.assertEqual(normalize_no_active_resolve(ip).rules, ("RULE-SET,A,Proxy,no-resolve",))

    def test_split_classical_provider_gets_domain_and_ip_modifiers(self):
        config = optimized_config(
            providers=[
                provider("A-domain", "domain", ["httpdns.example"], segment="A"),
                provider("A-ip", "ipcidr", ["203.107.1.0/24"], segment="A"),
            ],
            rules=["RULE-SET,A-domain,REJECT-DROP,no-resolve", "RULE-SET,A-ip,REJECT-DROP,no-resolve"],
        )
        self.assertEqual(
            normalize_no_active_resolve(config).rules,
            ("RULE-SET,A-domain,REJECT-DROP", "RULE-SET,A-ip,REJECT-DROP,no-resolve"),
        )

    def test_size_limit_validation_requires_non_negative_int(self):
        for bad_limit in (-1, True, "100"):
            with self.subTest(limit=bad_limit), tempfile.TemporaryDirectory() as tmp:
                with self.assertRaisesRegex(ValueError, "size-limit must be a non-negative byte count"):
                    materialize_final_config(
                        optimized_config(
                            providers=[
                                provider(
                                    "A", "domain", ["example.com"], segment="A",
                                    metadata=ProviderMetadata(size_limit=bad_limit),
                                )
                            ],
                            rules=["RULE-SET,A,DIRECT"],
                        ),
                        Path(tmp),
                        "https://x",
                        None,
                    )

    def test_zero_size_limit_means_unlimited(self):
        config = optimized_config(
            providers=[provider("A", "domain", ["example.com"], segment="A", metadata=ProviderMetadata(size_limit=0))],
            rules=["RULE-SET,A,DIRECT"],
        )
        with tempfile.TemporaryDirectory() as tmp:
            result = materialize_final_config(config, Path(tmp), "https://x", None)
            self.assertIn("A", result["rule-providers"])


if __name__ == "__main__":
    unittest.main()
