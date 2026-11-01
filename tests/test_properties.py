"""Property tests with independent reference implementations.

These do not reuse the production algorithms: the dedup reference is written
from the documented matching contract, and the routing reference is a small
first-match evaluator over the input rules.  They are deliberately seeded so a
failure is reproducible.
"""

import ipaddress
import random
import unittest

from converter.optimize import optimize_config
from converter.payload import dedup_domains, dedup_networks, parse_domain_payload, parse_ipcidr_payload
from converter.rules import find_ruleset_refs, parse_rule
from tests.support import normalized, semantic_config


def rendered(payload) -> list[str]:
    return [entry.as_rule() if hasattr(entry, "as_rule") else entry.raw for entry in payload]


class DomainDedupReference:
    """Reference: exact duplicates first, then suffix coverage, first-seen order."""

    @staticmethod
    def dedup(rules: list[str]) -> list[str]:
        unique: list[str] = []
        for rule in rules:
            if rule not in unique:
                unique.append(rule)

        def suffix_of(rule: str) -> str | None:
            value = rule.strip().lower()
            return value[2:].rstrip(".") if value.startswith("+.") and len(value) > 2 else None

        suffixes = {suffix_of(rule) for rule in unique if suffix_of(rule) is not None}
        output: list[str] = []
        for rule in unique:
            suffix = suffix_of(rule)
            if suffix is not None:
                labels = suffix.split(".")
                if any(".".join(labels[index:]) in suffixes for index in range(1, len(labels))):
                    continue
            else:
                labels = rule.strip().lower().rstrip(".").split(".")
                if any(".".join(labels[index:]) in suffixes for index in range(len(labels))):
                    continue
            output.append(rule)
        return output


class NetworkDedupReference:
    @staticmethod
    def dedup(rules: list[str]) -> list[str]:
        unique: list[str] = []
        for rule in rules:
            if rule not in unique:
                unique.append(rule)
        parsed = {}
        for rule in unique:
            parsed[rule] = ipaddress.ip_network(rule.strip(), strict=False)
        networks = set(parsed.values())
        output: list[str] = []
        for rule in unique:
            network = parsed[rule]
            if any(network.supernet(new_prefix=prefix) in networks for prefix in range(network.prefixlen - 1, -1, -1)):
                continue
            output.append(rule)
        return output


def random_domain(rng: random.Random) -> str:
    labels = rng.choice([
        ["example", "com"], ["a", "example", "com"], ["b", "a", "example", "com"],
        ["Example", "COM"], ["example", "com", ""], ["", "example"], ["x"], ["com"],
    ])
    value = ".".join(labels)
    prefix = "+." if rng.random() < 0.45 else ""
    if rng.random() < 0.1:
        value = value.upper()
    return prefix + value


def random_cidr(rng: random.Random) -> str:
    if rng.random() < 0.5:
        base = rng.choice(["192.0.2.0", "10.0.0.1", "10.0.0.0", "0.0.0.0", "255.255.255.255"])
        prefix = rng.choice([0, 1, 7, 8, 9, 24, 25, 31, 32])
        return f"{base}/{prefix}"
    base = rng.choice(["2001:db8::", "2001:db8::1", "::", "::1", "fe80::"])
    prefix = rng.choice([0, 1, 32, 64, 65, 127, 128])
    return f"{base}/{prefix}"


class PayloadDedupPropertyTest(unittest.TestCase):
    def test_domain_dedup_matches_reference(self):
        rng = random.Random(20241102)
        for _ in range(600):
            rules = [random_domain(rng) for _ in range(rng.randint(0, 8))]
            self.assertEqual(
                DomainDedupReference.dedup(rules),
                rendered(dedup_domains(parse_domain_payload(rules))[0]),
                rules,
            )

    def test_network_dedup_matches_reference(self):
        rng = random.Random(20241103)
        for _ in range(600):
            rules = [random_cidr(rng) for _ in range(rng.randint(0, 8))]
            self.assertEqual(
                NetworkDedupReference.dedup(rules),
                rendered(dedup_networks(parse_ipcidr_payload(rules))[0]),
                rules,
            )


DOMAINS = [
    "example.com", "a.example.com", "b.a.example.com", "badexample.com",
    "example.com.evil", "other.test", "x.test", "shared.test",
]
IPS = ["192.0.2.1", "192.0.2.200", "10.0.0.5", "198.51.100.9", "2001:db8::1", "::1"]


def domain_matches(entry, domain: str) -> bool:
    if entry.suffix:
        base = entry.value.lower().lstrip(".").rstrip(".")
        return domain == base or domain.endswith("." + base)
    return domain == entry.value.lower().rstrip(".")


def probe_matches(behavior: str, payload, probe) -> bool:
    if behavior == "domain":
        return probe[0] == "domain" and any(domain_matches(entry, probe[1]) for entry in payload)
    if behavior == "ipcidr":
        if probe[0] != "ip":
            return False
        for entry in payload:
            try:
                if probe[1] in entry.network:
                    return True
            except TypeError:
                continue
        return False
    for rule in payload:
        if len(rule.parts) < 2:
            continue
        value = rule.parts[1]
        if rule.kind == "DOMAIN" and probe[0] == "domain":
            if probe[1] == value.lower().rstrip("."):
                return True
        elif rule.kind == "DOMAIN-SUFFIX" and probe[0] == "domain":
            base = value.lower().lstrip(".").rstrip(".")
            if probe[1] == base or probe[1].endswith("." + base):
                return True
        elif rule.kind in {"IP-CIDR", "IP-CIDR6"} and probe[0] == "ip":
            if probe[1] in ipaddress.ip_network(value, strict=False):
                return True
    return False


def decide(rules, providers, probe):
    by_name = {provider.name: provider for provider in providers}
    for raw in rules:
        parsed = parse_rule(raw)
        if parsed.kind == "MATCH" and len(parsed.parts) == 2:
            return parsed.parts[1]
        if not raw.startswith("RULE-SET,"):
            if parsed.kind == "DOMAIN" and len(parsed.parts) >= 3:
                if probe[0] == "domain" and probe[1] == parsed.parts[1].lower().rstrip("."):
                    return parsed.parts[2]
                continue
            if parsed.kind in {"IP-CIDR", "IP-CIDR6"} and len(parsed.parts) >= 3:
                if probe[0] == "ip" and probe[1] in ipaddress.ip_network(parsed.parts[1], strict=False):
                    return parsed.parts[2]
                continue
            continue
        refs = find_ruleset_refs(raw)
        if len(refs) != 1:
            raise AssertionError(f"unexpected expression: {raw!r}")
        provider = by_name[refs[0]]
        if probe_matches(provider.behavior.value, provider.payload, probe):
            return parsed.parts[2]
    return None


def random_payload(rng: random.Random, behavior: str) -> list[str]:
    if behavior == "domain":
        values = []
        for _ in range(rng.randint(1, 4)):
            domain = rng.choice(DOMAINS)
            values.append(("+." + domain) if rng.random() < 0.4 else domain)
        return values
    if behavior == "ipcidr":
        pool = ["192.0.2.0/24", "192.0.2.0/25", "10.0.0.0/8", "198.51.100.0/24", "2001:db8::/32", "::1/128", "0.0.0.0/0"]
        return [rng.choice(pool) for _ in range(rng.randint(1, 3))]
    pool = [
        "DOMAIN,example.com", "DOMAIN-SUFFIX,example.com", "DOMAIN,a.example.com",
        "IP-CIDR,192.0.2.0/24,no-resolve", "IP-CIDR6,2001:db8::/32,no-resolve",
        "DOMAIN-KEYWORD,example",
    ]
    return [rng.choice(pool) for _ in range(rng.randint(1, 3))]


class RoutingPreservationPropertyTest(unittest.TestCase):
    def test_optimizer_preserves_first_match_routing(self):
        rng = random.Random(424242)
        probes = [("domain", domain) for domain in DOMAINS]
        probes += [("ip", ipaddress.ip_address(value)) for value in IPS]
        for _case in range(150):
            providers = []
            for index in range(rng.randint(1, 4)):
                behavior = rng.choice(["domain", "classical", "ipcidr"])
                source = f"S{index}"
                providers.append(normalized(source, source, behavior, random_payload(rng, behavior)))
            rules = []
            for provider in providers:
                policy = rng.choice(["DIRECT", "Proxy", "REJECT"])
                modifier = ",no-resolve" if (provider.behavior.value == "ipcidr" and rng.random() < 0.4) else ""
                rules.append(f"RULE-SET,{provider.name},{policy}{modifier}")
                if rng.random() < 0.3:
                    rules.append(f"DOMAIN,{rng.choice(DOMAINS)},{rng.choice(['DIRECT', 'Proxy'])}")
                if rng.random() < 0.2:
                    rules.append(rng.choice(["NETWORK,UDP,REJECT", "IP-CIDR,198.51.100.0/24,DIRECT,no-resolve"]))
            rules.append("MATCH,Proxy")
            mapping = {(p.source): f"Seg{p.source}" for p in providers if rng.random() < 0.6}
            config = semantic_config(providers=providers, rules=rules)
            final = optimize_config(config, mapping)
            for probe in probes:
                self.assertEqual(
                    decide(rules, providers, probe),
                    decide(final.rules, final.providers, probe),
                    f"routing changed for {probe} with rules {rules}",
                )
            referenced = {name for rule in final.rules for name in find_ruleset_refs(rule)}
            referenced |= {
                name for members in final.sub_rules.values() for rule in members for name in find_ruleset_refs(rule)
            }
            defined = {provider.name for provider in final.providers}
            self.assertEqual(referenced - defined, set(), "dangling provider references")
            self.assertEqual(defined - referenced, set(), "orphan providers")


class IdentityInsertionPropertyTest(unittest.TestCase):
    def test_inserting_an_unrelated_segment_never_renames_anchored_artifacts(self):
        rng = random.Random(777)
        for _case in range(150):
            anchors = [f"A{index}" for index in range(rng.randint(1, 4))]
            order = anchors[:]
            rng.shuffle(order)
            providers = [normalized(anchor, f"{anchor}-domain", "domain", [f"{anchor.lower()}.example"]) for anchor in order]
            base_rules = [f"RULE-SET,{provider.name},Proxy" for provider in providers] + ["MATCH,Proxy"]
            mapping = {anchor: f"Seg{anchor}" for anchor in anchors}
            baseline = [p.name for p in optimize_config(semantic_config(providers=providers, rules=base_rules), mapping).providers]

            inserted = [normalized("Inserted", "Inserted-domain", "domain", ["extra.example"])] + providers
            inserted_rules = ["RULE-SET,Inserted-domain,REJECT"] + base_rules
            inserted_mapping = {**mapping, "Inserted": "SegInserted"}
            actual = [
                p.name
                for p in optimize_config(
                    semantic_config(providers=inserted, rules=inserted_rules), inserted_mapping
                ).providers
            ]
            self.assertEqual(set(actual) - {"SegInserted-domain"}, set(baseline))
            self.assertEqual([name for name in actual if name in baseline], baseline)


if __name__ == "__main__":
    unittest.main()
