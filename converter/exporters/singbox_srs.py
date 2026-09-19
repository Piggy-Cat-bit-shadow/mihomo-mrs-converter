"""SRS validation helpers shared by the Sing-box route and DNS exporters."""
from __future__ import annotations

import ipaddress
from typing import Any

from ..timing import current_timing


def representatives(source_rules: list[dict[str, Any]]) -> list[str]:
    probes: list[str] = []
    for rule in source_rules:
        if "domain" in rule:
            probes.append(rule["domain"][0])
        elif "domain_suffix" in rule:
            probes.append("audit." + rule["domain_suffix"][0])
        elif "domain_keyword" in rule:
            probes.append("audit-" + rule["domain_keyword"][0] + ".invalid")
        elif "ip_cidr" in rule:
            probes.append(str(ipaddress.ip_network(rule["ip_cidr"][0], strict=False).network_address))
    return list(dict.fromkeys(probes))


def canonicalize_decompiled_rules(rules: list[dict[str, Any]]) -> list[dict[str, Any]]:
    matcher_fields = {
        "domain", "domain_suffix", "domain_keyword", "domain_regex", "ip_cidr", "source_ip_cidr",
        "network", "process_name", "process_path", "process_path_regex", "port", "source_port",
        "port_range", "source_port_range",
    }
    return [
        {field: value if isinstance(value, list) else [value] if field in matcher_fields else value for field, value in rule.items()}
        for rule in rules
    ]


def _collect_canonical_fields(rules: list[dict[str, Any]]) -> dict[str, set[Any]]:
    matcher_fields = {
        "domain", "domain_suffix", "domain_keyword", "domain_regex", "ip_cidr", "source_ip_cidr",
        "network", "process_name", "process_path", "process_path_regex", "port", "source_port",
        "port_range", "source_port_range",
    }
    fields: dict[str, set[Any]] = {}
    for rule in rules:
        for field, value in rule.items():
            normalized = value if isinstance(value, list) else [value] if field in matcher_fields else value
            bucket = fields.setdefault(field, set())
            bucket.update(normalized if isinstance(normalized, list) else normalized)
    return fields


def semantic_matcher_equivalent(source: list[dict[str, Any]], decoded: list[dict[str, Any]]) -> bool:
    """Compare matcher families without depending on rule order or scalar style."""
    timing = current_timing()
    context = timing.phase("Sing-box semantic equivalence") if timing is not None else _NullContext()
    with context:
        source_fields = _collect_canonical_fields(source)
        decoded_fields = _collect_canonical_fields(decoded)
        cidr_fields = {"ip_cidr", "source_ip_cidr"}
        network_cache: dict[str, ipaddress._BaseNetwork] = {}

        def parse_networks(values: set[Any]) -> list[ipaddress._BaseNetwork]:
            networks: list[ipaddress._BaseNetwork] = []
            for value in values:
                if value not in network_cache:
                    network_cache[value] = ipaddress.ip_network(value, strict=False)
                networks.append(network_cache[value])
            return networks

        def collapsed(networks: list[ipaddress._BaseNetwork]) -> list[str]:
            return sorted(
                str(network)
                for version in (4, 6)
                for network in ipaddress.collapse_addresses([item for item in networks if item.version == version])
            )

        try:
            for field in source_fields.keys() | decoded_fields.keys():
                source_values = source_fields.get(field, set())
                decoded_values = decoded_fields.get(field, set())
                if field not in cidr_fields:
                    if source_values != decoded_values:
                        return False
                elif collapsed(parse_networks(source_values)) != collapsed(parse_networks(decoded_values)):
                    return False
        except (TypeError, ValueError):
            return False
        return True


class _NullContext:
    def __enter__(self) -> None:
        return None

    def __exit__(self, *_: object) -> None:
        return None
