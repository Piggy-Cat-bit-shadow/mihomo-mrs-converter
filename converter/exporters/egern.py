"""Egern rule-set and route exporter."""

from collections import Counter
from pathlib import Path
from time import perf_counter
from typing import Any, Iterable

from ..artifacts import public_url, write_yaml_atomic
from ..model import OptimizedConfig
from ..rules import RuleLine
from ..rules import (
    COMMA_TEXT_KINDS,
    DOMAIN_KINDS,
    egern_udp_and_ruleset,
    find_ruleset_refs,
    is_target_ip_kind,
    parse_egern_network_rule,
    parse_egern_sub_rule_members,
    parse_ip_network,
    parse_rule,
    parse_ruleset_reference,
    rule_text_value,
    simple_ruleset_wrapper,
)
from ..timing import current_timing, timed
from ..views import SegmentView

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


def egern_policy(policy: str, policy_map: dict[str, str] | None = None) -> str:
    return (policy_map or {}).get(policy, policy)


def egern_rule_field(rule: RuleLine) -> tuple[str, str, bool] | None:
    """Map one classical rule to an Egern rule-set field, or None if unsupported."""
    field = EGERN_FIELD_BY_KIND.get(rule.kind)
    if field is None or len(rule.parts) < 2:
        return None
    value = rule_text_value(rule)
    if rule.kind in COMMA_TEXT_KINDS:
        # Free-text values may contain commas; these kinds take no modifier.
        return field, value, False
    if len(rule.parts) not in {2, 3}:
        return None
    no_resolve = len(rule.parts) == 3
    if no_resolve and (rule.parts[2].lower() != "no-resolve" or not is_target_ip_kind(rule.kind)):
        return None
    if rule.kind in {"IP-CIDR", "IP-CIDR6"}:
        network = parse_ip_network(value)
        expected = 4 if rule.kind == "IP-CIDR" else 6
        if network is None or network.version != expected:
            return None
    return field, value, no_resolve






def egern_dns_fields(domains: Iterable[Any], classical: Iterable[RuleLine]) -> dict[str, Any]:
    """Build an Egern rule-set body from authoritative DNS domain rules."""
    fields: dict[str, Any] = {}
    for entry in domains:
        field = "domain_suffix_set" if entry.suffix else "domain_set"
        fields.setdefault(field, []).append(entry.value)
    for rule in classical:
        if rule.kind not in DOMAIN_KINDS:
            continue
        classified = egern_rule_field(rule)
        if classified is None:
            continue
        field, value, no_resolve = classified
        if not no_resolve:
            fields.setdefault(field, []).append(value)
    if any(field in {"ip_cidr_set", "ip_cidr6_set", "asn_set", "geoip_set"} for field in fields):
        fields["no_resolve"] = True
    return fields


def _collect_rule_sets(views: dict[str, SegmentView]) -> tuple[dict[str, dict[str, Any]], Counter, Counter, dict[str, list[str]], int]:
    sets: dict[str, dict[str, Any]] = {}
    seen_values: dict[str, dict[str, set[str]]] = {}
    counts: Counter = Counter()
    unsupported: Counter = Counter()
    examples: dict[str, list[str]] = {}
    no_resolve_rules = 0

    def add(segment: str, field: str, value: str) -> None:
        values = sets.setdefault(segment, {}).setdefault(field, [])
        seen = seen_values.setdefault(segment, {}).setdefault(field, set())
        if value in seen:
            return
        seen.add(value)
        values.append(value)

    for segment, view in views.items():
        for entry in view.domains:
            add(segment, "domain_suffix_set" if entry.suffix else "domain_set", entry.value)
            counts["domain"] += 1
        for rule in view.classical:
            classified = egern_rule_field(rule)
            if classified is None:
                kind = rule.kind or "unknown"
                unsupported[kind] += 1
                examples.setdefault(kind, [])
                if len(examples[kind]) < 5:
                    examples[kind].append(rule.raw)
                continue
            field, value, _ = classified
            if is_target_ip_kind(rule.kind):
                sets.setdefault(segment, {})["no_resolve"] = True
                no_resolve_rules += 1
            add(segment, field, value)
            counts["classical"] += 1
        for network in view.networks:
            sets.setdefault(segment, {})["no_resolve"] = True
            add(segment, "ip_cidr6_set" if network.version == 6 else "ip_cidr_set", network.raw)
            counts["ipv6" if network.version == 6 else "ipv4"] += 1
    return sets, counts, unsupported, examples, no_resolve_rules


def export_egern(
    optimized: OptimizedConfig,
    views: dict[str, SegmentView],
    output_dist: Path,
    base_url: str,
    policy_map: dict[str, str] | None = None,
    allowed_unsupported: frozenset[str] | set[str] | None = None,
) -> dict[str, int]:
    """Serialize the final config into compact Egern rule sets and a route."""
    started = perf_counter()
    with timed("Egern collect"):
        sets, counts, unsupported, unsupported_examples, no_resolve_rules = _collect_rule_sets(views)
    counts["no_resolve"] = no_resolve_rules
    semantic_removed = Counter(
        {
            "exact_domains_covered_by_suffix": sum(view.stats.domain_covered_by_suffix for view in views.values()),
            "child_suffixes_covered_by_parent": sum(view.stats.suffix_covered_by_parent_suffix for view in views.values()),
            "ipv4_cidrs_covered_by_parent": sum(view.stats.ipcidr_covered_by_parent for view in views.values()),
        }
    )
    semantic_removed["safe_semantic_duplicates"] = sum(semantic_removed.values())

    egern_dir = output_dist / "egern"
    expected_egern_files = {f"{segment}.yaml" for segment in sets}
    for stale in egern_dir.glob("*.yaml"):
        if stale.name not in expected_egern_files:
            stale.unlink()
    with timed("Egern write rule sets"):
        for segment, fields in sets.items():
            if any(field in {"ip_cidr_set", "ip_cidr6_set", "asn_set", "geoip_set"} for field in fields):
                fields["no_resolve"] = True
            write_yaml_atomic(egern_dir / f"{segment}.yaml", fields)

    segments_by_provider = optimized.provider_segments()
    egern_rules: list[dict[str, Any]] = []
    emitted_keys: set[tuple[str, ...]] = set()

    def segment_targets(segment: str) -> list[str]:
        return [segment] if segment in sets else []

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

    def emit_network(segment: str, protocol: str, policy: str) -> None:
        for target in segment_targets(segment):
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

    def segment_of(provider: str) -> str:
        try:
            return segments_by_provider[provider]
        except KeyError:
            raise ValueError(f"Egern rule references unknown provider: {provider!r}") from None

    sub_rules = optimized.sub_rules
    with timed("Egern top-level"):
        for index, rule in enumerate(optimized.rules):
            if not isinstance(rule, str):
                continue
            parsed = parse_rule(rule)
            if parsed.kind == "MATCH":
                if len(parsed.parts) != 2:
                    raise ValueError(f"Egern structural unsupported MATCH rule: {rule}")
                if index != len(optimized.rules) - 1:
                    raise ValueError(f"Egern MATCH must be the final rule: {rule}")
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
                segment = segment_of(provider_name)
                if segment not in sets:
                    raise ValueError(f"Egern rule references an empty or unsupported segment: {rule}")
                emit_network(segment, "udp", policy)
                continue
            wrapper = simple_ruleset_wrapper(rule)
            if wrapper is None:
                continue
            reference = parse_ruleset_reference(rule)
            if reference is None:
                raise ValueError(f"Egern structural unsupported rule: {rule}")
            prefix = wrapper[1]
            refs = find_ruleset_refs(rule)
            if len(refs) != 1:
                raise ValueError(f"Egern structural unsupported rule: {rule}")
            segment = segment_of(refs[0])
            targets = segment_targets(segment)
            if not targets:
                raise ValueError(f"Egern rule references an empty or unsupported segment: {rule}")

            sub_rule_name = reference.policy
            if prefix.upper() == "SUB-RULE":
                members = sub_rules.get(sub_rule_name)
                if members is None:
                    raise ValueError(f"Egern SUB-RULE {sub_rule_name!r} is not defined (rule: {rule!r})")
                parsed_members = parse_egern_sub_rule_members(list(members))
                if parsed_members is None:
                    raise ValueError(f"Egern unsupported SUB-RULE member: {sub_rule_name}: {list(members)}")
                for protocol, member_policy in parsed_members:
                    if protocol == "match":
                        for target in targets:
                            emit_ruleset(target, member_policy)
                    else:
                        emit_network(segment, protocol, member_policy)
                continue

            for target in targets:
                emit_ruleset(target, reference.policy)

    unexpected_unsupported = set(unsupported) - set(allowed_unsupported or ())
    if unexpected_unsupported:
        examples = {kind: unsupported_examples.get(kind, [])[:1] for kind in sorted(unexpected_unsupported)}
        raise ValueError(f"Egern unsupported matcher(s) not allowlisted: {examples}")
    with timed("Egern write YAML"):
        write_yaml_atomic(output_dist / "generated" / "egern-rules.yaml", {"rules": egern_rules})
    timing = current_timing()
    if timing is not None:
        timing.phases["Egern total"] = perf_counter() - started
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
    if unsupported:
        print("unsupported classical types: " + ", ".join(f"{k}={v}" for k, v in sorted(unsupported.items())))
    for kind, kind_examples in sorted(unsupported_examples.items()):
        print(f"[Egern] unsupported classical rules skipped: {kind}: {unsupported[kind]}")
        print(f"  examples: {', '.join(kind_examples)}")
    print("==========================================")
    return dict(counts)
