"""Independent egern exporter implementation."""

from collections import Counter
from pathlib import Path
from contextlib import nullcontext
from time import perf_counter
from typing import Any
import ipaddress
import re

from ..artifacts import public_url, write_yaml_atomic
from ..model import provider_segment
from ..rules import (
    egern_udp_and_ruleset, find_ruleset_refs, parse_egern_network_rule,
    parse_egern_sub_rule_members, parse_rule, parse_ruleset_reference,
    simple_ruleset_wrapper,
)
from ..semantics import is_target_ip_kind, parse_ip_network
from ..optimize import domain_covered_by_suffix, suffix_covered_by_parent_suffix
from ..timing import current_timing


def _timed(name: str):
    timing = current_timing()
    return timing.phase(name) if timing is not None else nullcontext()


def network_covered_by_parent(network: ipaddress._BaseNetwork, networks: set[ipaddress._BaseNetwork]) -> bool:
    return any(network.supernet(new_prefix=prefix) in networks for prefix in range(network.prefixlen - 1, -1, -1))

EGERN_FIELD_BY_KIND = {
    "DOMAIN": "domain_set",
    "DOMAIN-SUFFIX": "domain_suffix_set",
    "DOMAIN-KEYWORD": "domain_keyword_set",
    "DOMAIN-REGEX": "domain_regex_set",
    "DOMAIN-WILDCARD": "domain_wildcard_set",
    "IP-CIDR": "ip_cidr_set",
    "IP-CIDR6": "ip_cidr6_set",
    "GEOIP": "geoip_set",
    "NETWORK": "protocol_set",
    "DST-PORT": "dest_port_set",
    "IP-ASN": "asn_set",
}


def validate_provider_name(name: str) -> None:
    if not re.fullmatch(r"[A-Za-z0-9._-]+", name):
        raise ValueError(f"invalid provider name: {name!r}")


def egern_policy(policy: str, policy_map: dict[str, str] | None = None) -> str:
    return (policy_map or {}).get(policy, policy)


def egern_segment_name(provider_name: str) -> str:
    return provider_segment(provider_name)


def classify_egern_classical(rule: str) -> tuple[str, str, bool] | None:
    parsed = parse_rule(rule)
    field = EGERN_FIELD_BY_KIND.get(parsed.kind)
    if field is None or len(parsed.parts) not in {2, 3}:
        return None
    no_resolve = len(parsed.parts) == 3
    if no_resolve and (parsed.parts[2].lower() != "no-resolve" or not is_target_ip_kind(parsed.kind)):
        return None
    value = parsed.parts[1]
    if parsed.kind == "IP-CIDR":
        try:
            if ipaddress.ip_network(value, strict=False).version != 4:
                return None
        except ValueError:
            return None
    elif parsed.kind == "IP-CIDR6":
        try:
            if ipaddress.ip_network(value, strict=False).version != 6:
                return None
        except ValueError:
            return None
    return field, value, no_resolve


def optimize_egern_rule_set(fields: dict[str, Any]) -> tuple[dict[str, Any], Counter[str]]:
    """Safely remove only coverage-redundant values within one Egern set."""
    optimized = {field: list(values) if isinstance(values, list) else values for field, values in fields.items()}
    removed: Counter[str] = Counter()

    suffix_values = optimized.get("domain_suffix_set", [])
    suffixes = {
        value.strip().lower().rstrip(".")
        for value in suffix_values
        if isinstance(value, str) and value.strip().rstrip(".")
    }
    if isinstance(optimized.get("domain_set"), list):
        retained_domains: list[str] = []
        for value in optimized["domain_set"]:
            if isinstance(value, str) and domain_covered_by_suffix(value, suffixes):
                removed["exact_domains_covered_by_suffix"] += 1
            else:
                retained_domains.append(value)
        optimized["domain_set"] = retained_domains
    if isinstance(suffix_values, list):
        retained_suffixes: list[str] = []
        for value in suffix_values:
            normalized = value.strip().lower().rstrip(".") if isinstance(value, str) else ""
            if normalized and suffix_covered_by_parent_suffix(normalized, suffixes):
                removed["child_suffixes_covered_by_parent"] += 1
            else:
                retained_suffixes.append(value)
        optimized["domain_suffix_set"] = retained_suffixes

    for field, stat_name in (("ip_cidr_set", "ipv4_cidrs_covered_by_parent"), ("ip_cidr6_set", "ipv6_cidrs_covered_by_parent")):
        values = optimized.get(field)
        if not isinstance(values, list):
            continue
        networks = {
            network
            for value in values
            if isinstance(value, str) and (network := parse_ip_network(value)) is not None
        }
        retained: list[Any] = []
        for value in values:
            network = parse_ip_network(value) if isinstance(value, str) else None
            if network is not None and network_covered_by_parent(network, networks):
                removed[stat_name] += 1
            else:
                retained.append(value)
        optimized[field] = retained

    removed["safe_semantic_duplicates"] = sum(removed.values())
    return optimized, removed


def export_egern(
    config: dict[str, Any], final_payloads: dict[str, list[str]], output_dist: Path, base_url: str,
    policy_map: dict[str, str] | None = None, allowed_unsupported: frozenset[str] | set[str] | None = None,
) -> dict[str, int]:
    """Serialize the already-final Mihomo config into compact Egern rule sets."""
    egern_started = perf_counter()
    sets: dict[str, dict[str, Any]] = {}
    seen_values: dict[str, dict[str, set[str]]] = {}
    counts = Counter()
    unsupported = Counter()
    unsupported_classical_examples: dict[str, list[str]] = {}

    def add(segment: str, field: str, value: str) -> bool:
        values = sets.setdefault(segment, {}).setdefault(field, [])
        seen = seen_values.setdefault(segment, {}).setdefault(field, set())
        if value in seen:
            return False
        seen.add(value)
        values.append(value)
        return True

    with _timed("Egern collect"):
        for name, provider in config["rule-providers"].items():
            segment = egern_segment_name(name)
            behavior = provider.get("behavior")
            payload = final_payloads.get(name, [])
            for rule in payload:
                if behavior == "domain":
                    value = rule[2:] if rule.startswith("+.") else rule
                    add(segment, "domain_suffix_set" if rule.startswith("+.") else "domain_set", value)
                    counts["domain"] += 1
                elif behavior == "ipcidr":
                    try:
                        version = ipaddress.ip_network(rule, strict=False).version
                    except ValueError:
                        unsupported["invalid-ip"] += 1
                        continue
                    sets.setdefault(segment, {})["no_resolve"] = True
                    add(segment, "ip_cidr6_set" if version == 6 else "ip_cidr_set", rule)
                    counts["ipv6" if version == 6 else "ipv4"] += 1
                elif behavior == "classical":
                    classified = classify_egern_classical(rule)
                    if classified is None:
                        kind = parse_rule(rule).kind or "unknown"
                        unsupported[kind] += 1
                        unsupported_classical_examples.setdefault(kind, [])
                        if len(unsupported_classical_examples[kind]) < 5:
                            unsupported_classical_examples[kind].append(rule)
                        continue
                    field, value, _no_resolve = classified
                    target = segment
                    if is_target_ip_kind(parse_rule(rule).kind):
                        sets.setdefault(target, {})["no_resolve"] = True
                        counts["no_resolve"] += 1
                    add(target, field, value)
                    counts["classical"] += 1

    egern_dir = output_dist / "egern"
    semantic_removed: Counter[str] = Counter()
    expected_egern_files = {f"{segment}.yaml" for segment in sets}
    with _timed("Egern optimize"):
        for stale in egern_dir.glob("*.yaml"):
            if stale.name not in expected_egern_files:
                stale.unlink()
        for segment, fields in sets.items():
            if any(field in {"ip_cidr_set", "ip_cidr6_set", "asn_set", "geoip_set"} for field in fields):
                fields["no_resolve"] = True
            validate_provider_name(segment)
            optimized, removed = optimize_egern_rule_set(fields)
            sets[segment] = optimized
            semantic_removed.update(removed)

    egern_rules: list[dict[str, Any]] = []
    emitted_keys: set[tuple[str, ...]] = set()

    def segment_targets(segment: str) -> list[str]:
        return [segment] if segment in sets else []

    def referenced_segment_targets(segment: str, modifiers: tuple[str, ...]) -> list[str]:
        return segment_targets(segment)

    def emit_ruleset(target: str, policy: str) -> None:
        key = ("rule_set", target, policy)
        if key in emitted_keys:
            return
        emitted_keys.add(key)
        egern_rules.append({"rule_set": {
            "match": public_url(base_url, "dist", "egern", f"{target}.yaml"),
            "policy": egern_policy(policy, policy_map),
            "update_interval": 172800,
        }})

    def emit_network(segment: str, protocol: str, policy: str, include_no_resolve: bool = False) -> None:
        targets = segment_targets(segment)
        for target in targets:
            key = ("and-network", target, protocol, policy)
            if key in emitted_keys:
                continue
            emitted_keys.add(key)
            egern_rules.append({"and": {
                "match": [
                    {"rule_set": {
                        "match": public_url(base_url, "dist", "egern", f"{target}.yaml"),
                        "update_interval": 172800,
                    }},
                    {"protocol": {"match": protocol}},
                ],
                "policy": egern_policy(policy, policy_map),
            }})

    def emit_protocol(protocol: str, policy: str) -> None:
        key = ("protocol", protocol, policy)
        if key in emitted_keys:
            return
        emitted_keys.add(key)
        egern_rules.append({"protocol": {"match": protocol, "policy": egern_policy(policy, policy_map)}})

    def emit_native_ip(kind: str, match: str, policy: str) -> None:
        native_kind = {"IP-CIDR": "ip_cidr", "IP-CIDR6": "ip_cidr6", "IP-ASN": "asn", "GEOIP": "geoip"}[kind]
        egern_rules.append({native_kind: {
            "match": match,
            "policy": egern_policy(policy, policy_map),
            "no_resolve": True,
        }})

    with _timed("Egern top-level"):
        for rule in config.get("rules", []):
            if not isinstance(rule, str):
                continue
            parsed = parse_rule(rule)
            if parsed.kind == "MATCH" and len(parsed.parts) >= 2:
                egern_rules.append({"default": {"policy": egern_policy(parsed.parts[1], policy_map)}})
                continue
            if parsed.kind in {"IP-CIDR", "IP-CIDR6", "IP-ASN", "GEOIP"}:
                if len(parsed.parts) < 3 or any(item.lower() != "no-resolve" for item in parsed.parts[3:]):
                    raise ValueError(f"Egern structural unsupported {parsed.kind} rule: {rule}")
                emit_native_ip(parsed.kind, parsed.parts[1], parsed.parts[2])
                continue
            if parsed.kind == "NETWORK":
                network = parse_egern_network_rule(rule)
                if network is None:
                    raise ValueError(f"Egern structural unsupported NETWORK rule: {rule}")
                emit_protocol(*network)
                continue
            udp_and = egern_udp_and_ruleset(rule)
            if parsed.kind == "AND":
                if udp_and is None:
                    raise ValueError(f"Egern structural unsupported AND rule: {rule}")
                provider_name, policy = udp_and
                segment = egern_segment_name(provider_name)
                if segment not in sets:
                    raise ValueError(f"Egern rule references an empty or unsupported segment: {rule}")
                emit_network(segment, "udp", policy)
                continue
            wrapper = simple_ruleset_wrapper(rule)
            if wrapper is None:
                continue
            reference = parse_ruleset_reference(rule)
            assert reference is not None
            parts, prefix, suffix = wrapper
            refs = find_ruleset_refs(rule)
            if len(refs) != 1:
                raise ValueError(f"Egern structural unsupported rule: {rule}")
            segment = egern_segment_name(refs[0])
            targets = referenced_segment_targets(segment, reference.modifiers)
            if not targets:
                raise ValueError(f"Egern rule references an empty or unsupported segment: {rule}")

            sub_rules = config.get("sub-rules", {})
            sub_rule_name = reference.policy
            if prefix.upper() == "SUB-RULE" and isinstance(sub_rules, dict) and sub_rule_name in sub_rules:
                members = parse_egern_sub_rule_members(sub_rules[sub_rule_name])
                if members is None:
                    raise ValueError(f"Egern unsupported SUB-RULE member: {sub_rule_name}: {sub_rules[sub_rule_name]}")
                for protocol, member_policy in members:
                    if protocol == "match":
                        for target in targets:
                            emit_ruleset(target, member_policy)
                    else:
                        emit_network(segment, protocol, member_policy, include_no_resolve=True)
                continue

            for target in targets:
                emit_ruleset(target, reference.policy)
    unexpected_unsupported = set(unsupported) - set(allowed_unsupported or ())
    if unexpected_unsupported:
        examples = {kind: unsupported_classical_examples.get(kind, [])[:1] for kind in sorted(unexpected_unsupported)}
        raise ValueError(f"Egern unsupported matcher(s) not allowlisted: {examples}")
    with _timed("Egern write YAML"):
        for segment, fields in sets.items():
            write_yaml_atomic(egern_dir / f"{segment}.yaml", fields)
        write_yaml_atomic(output_dist / "generated" / "egern-rules.yaml", {"rules": egern_rules})
    timing = current_timing()
    if timing is not None:
        timing.phases["Egern total"] = perf_counter() - egern_started
    counts["segments"] = len(sets)
    counts["unsupported"] = sum(unsupported.values())
    print("\n========== Egern Export Summary ==========")
    print(f"segments: {counts['segments']}")
    field_counts = Counter(
        field
        for fields in sets.values()
        for field, values in fields.items()
        if field != "no_resolve"
        for _ in values
)
    print(f"rule set files: {sum(1 for _ in egern_dir.glob('*.yaml'))}")
    print(f"exact domains: {field_counts['domain_set']}")
    print(f"domain suffixes: {field_counts['domain_suffix_set']}")
    print(f"domain keywords: {field_counts['domain_keyword_set']}")
    print(f"domain regexes: {field_counts['domain_regex_set']}")
    print(f"domain wildcards: {field_counts['domain_wildcard_set']}")
    print(f"IPv4 CIDRs: {field_counts['ip_cidr_set']}")
    print(f"IPv6 CIDRs: {field_counts['ip_cidr6_set']}")
    print(f"ASNs: {field_counts['asn_set']}")
    print(f"other converted classical rules: {field_counts['geoip_set'] + field_counts['protocol_set'] + field_counts['dest_port_set']}")
    print(f"no-resolve rules: {counts['no_resolve']}")
    print(f"unsupported classical rules: {counts['unsupported']}")
    print(f"safe semantic duplicates removed: {semantic_removed['safe_semantic_duplicates']}")
    print(f"exact domains covered by suffix: {semantic_removed['exact_domains_covered_by_suffix']}")
    print(f"child suffixes covered by parent: {semantic_removed['child_suffixes_covered_by_parent']}")
    print(f"IPv4 CIDRs covered by parent: {semantic_removed['ipv4_cidrs_covered_by_parent']}")
    print(f"IPv6 CIDRs covered by parent: {semantic_removed['ipv6_cidrs_covered_by_parent']}")
    if unsupported:
        print("unsupported classical types: " + ", ".join(f"{k}={v}" for k, v in sorted(unsupported.items())))
    for kind, examples in sorted(unsupported_classical_examples.items()):
        print(f"[Egern] unsupported classical rules skipped: {kind}: {unsupported[kind]}")
        print(f"  examples: {', '.join(examples)}")
    print("==========================================")
    return dict(counts)
