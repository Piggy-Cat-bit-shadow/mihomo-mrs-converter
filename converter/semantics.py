"""Single source of truth for matcher semantics shared by all exporters."""

DOMAIN_KINDS = frozenset({"DOMAIN", "DOMAIN-SUFFIX", "DOMAIN-KEYWORD", "DOMAIN-REGEX", "DOMAIN-WILDCARD"})
TARGET_IP_KINDS = frozenset({"IP-CIDR", "IP-CIDR6", "IP-ASN", "GEOIP"})
SOURCE_IP_KINDS = frozenset({"SRC-IP-CIDR", "SRC-IP-ASN"})

import ipaddress


def parse_ip_network(rule: str) -> ipaddress._BaseNetwork | None:
    try:
        return ipaddress.ip_network(rule.strip(), strict=False)
    except ValueError:
        return None


def is_domain_kind(kind: str) -> bool:
    return kind.upper() in DOMAIN_KINDS


def is_target_ip_kind(kind: str) -> bool:
    return kind.upper() in TARGET_IP_KINDS


def is_source_ip_kind(kind: str) -> bool:
    return kind.upper() in SOURCE_IP_KINDS


def ensure_single_no_resolve(parts: list[str]) -> list[str]:
    return [*parts[:2], *(part for part in parts[2:] if part.lower() != "no-resolve"), "no-resolve"]
