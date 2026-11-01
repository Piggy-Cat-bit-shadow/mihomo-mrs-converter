"""Loon rule-resource and route exporter."""

from collections import Counter
from pathlib import Path
from typing import Any

from ..artifacts import public_url, write_text_atomic
from ..model import OptimizedConfig
from ..rules import RuleLine
from ..payload import DomainEntry, IpEntry
from ..rules import (
    find_ruleset_refs,
    is_target_ip_kind,
    parse_egern_sub_rule_members,
    parse_ip_network,
    parse_rule,
    parse_ruleset_reference,
    simple_ruleset_wrapper,
    split_top_level_commas,
)
from ..views import SegmentView

LOON_RULE_PRIORITY = {
    "DOMAIN": 0,
    "DOMAIN-SUFFIX": 1,
    "DOMAIN-KEYWORD": 2,
    "IP-CIDR": 3,
    "IP-CIDR6": 4,
    "GEOIP": 5,
    "IP-ASN": 6,
    "SRC-PORT": 7,
    "DEST-PORT": 8,
    "PROTOCOL": 9,
    "USER-AGENT": 10,
}
LOON_CLASSICAL_KINDS = {
    "DOMAIN",
    "DOMAIN-SUFFIX",
    "DOMAIN-KEYWORD",
    "IP-CIDR",
    "IP-CIDR6",
    "GEOIP",
    "IP-ASN",
    "DST-PORT",
    "DEST-PORT",
    "SRC-PORT",
    "PROTOCOL",
    "USER-AGENT",
    "NETWORK",
}


def loon_domain_rule(entry: DomainEntry) -> tuple[str, str]:
    if entry.suffix:
        return "DOMAIN-SUFFIX", f"DOMAIN-SUFFIX,{entry.value}"
    return "DOMAIN", f"DOMAIN,{entry.value}"


def loon_network_rule(entry: IpEntry) -> tuple[str, str]:
    kind = "IP-CIDR" if entry.version == 4 else "IP-CIDR6"
    return kind, ",".join([kind, entry.raw, "no-resolve"])


def loon_classical_rule(rule: RuleLine) -> tuple[str, str]:
    """Convert one normalized classical entry to a native Loon rule."""
    kind = rule.kind
    if kind == "DST-PORT":
        kind = "DEST-PORT"
    elif kind == "NETWORK":
        kind = "PROTOCOL"
    if kind not in LOON_CLASSICAL_KINDS and kind not in {"DST-PORT"}:
        raise ValueError(f"unsupported Loon rule type {rule.kind or '<empty>'}")
    if len(rule.parts) not in {2, 3}:
        raise ValueError("rule has unsupported fields or an embedded policy")
    if len(rule.parts) == 3 and (
        rule.parts[2].lower() != "no-resolve"
        or not is_target_ip_kind(kind)
    ):
        raise ValueError("only IP-CIDR/IP-CIDR6/IP-ASN may use no-resolve")
    if kind == "IP-CIDR":
        network = parse_ip_network(rule.parts[1])
        if network is None or network.version != 4:
            raise ValueError("IP-CIDR contains an invalid or IPv6 network")
    if kind == "IP-CIDR6":
        network = parse_ip_network(rule.parts[1])
        if network is None or network.version != 6:
            raise ValueError("IP-CIDR6 contains an invalid or IPv4 network")
    values = list(rule.parts[1:])
    if is_target_ip_kind(kind) and "no-resolve" not in {item.lower() for item in values[1:]}:
        values.append("no-resolve")
    return kind, ",".join([kind, *values])


def export_loon(
    optimized: OptimizedConfig,
    views: dict[str, SegmentView],
    output_dist: Path,
    base_url: str,
    allowed_unsupported: frozenset[str] | set[str] | None = None,
) -> dict[str, int]:
    """Export final normalized providers directly as independent Loon rule lists."""
    rules_by_segment: dict[str, list[tuple[str, str]]] = {}
    unsupported: Counter[str] = Counter()
    top_level_unsupported: Counter[str] = Counter()
    unsupported_examples: dict[str, list[str]] = {}
    policies: dict[str, str] = {}
    remote_order: list[str] = []
    conditional_by_provider: dict[str, list[tuple[str, str]]] = {}
    subrule_fallback_policy: dict[str, str] = {}
    subrule_conditional_policy: dict[tuple[str, str], str] = {}

    for segment, view in views.items():
        converted: list[tuple[str, str]] = []
        seen: set[str] = set()
        for domain in view.domains:
            line = loon_domain_rule(domain)
            if line[1] not in seen:
                seen.add(line[1])
                converted.append(line)
        for rule in view.classical:
            try:
                line = loon_classical_rule(rule)
            except ValueError:
                kind = rule.kind or "<empty>"
                unsupported[kind] += 1
                unsupported_examples.setdefault(kind, [])
                if len(unsupported_examples[kind]) < 5:
                    unsupported_examples[kind].append(rule.raw)
                continue
            if line[1] not in seen:
                seen.add(line[1])
                converted.append(line)
        for network in view.networks:
            line = loon_network_rule(network)
            if line[1] not in seen:
                seen.add(line[1])
                converted.append(line)
        rules_by_segment[segment] = converted

    segments_by_provider = optimized.provider_segments()
    sub_rules = optimized.sub_rules

    def segment_of(provider_name: str) -> str:
        try:
            return segments_by_provider[provider_name]
        except KeyError:
            raise SystemExit(f"Loon rule references unknown provider: {provider_name!r}") from None

    def parse_loon_subrule(name: str) -> list[tuple[str, str, str]]:
        members = sub_rules.get(name)
        parsed = parse_egern_sub_rule_members(list(members) if members is not None else None)
        if parsed is None:
            raise SystemExit(f"Loon exporter unsupported SUB-RULE member: {name}")
        fallback = [policy for kind, policy in parsed if kind == "match"]
        if len(fallback) != 1:
            raise SystemExit(f"Loon exporter requires exactly one SUB-RULE MATCH fallback: {name}")
        result: list[tuple[str, str, str]] = []
        for kind, policy in parsed:
            if kind in {"udp", "tcp"}:
                result.append((kind, policy, fallback[0]))
        if not result:
            raise SystemExit(f"Loon exporter SUB-RULE has no UDP/TCP conditional member: {name}")
        return result

    def record_policy(segment: str, policy: str, raw_rule: str) -> None:
        if segment not in policies:
            remote_order.append(segment)
        elif policies[segment] != policy:
            raise SystemExit(
                f"Loon policy conflict for segment {segment}: {policies[segment]!r} vs {policy!r} in {raw_rule!r}"
            )
        policies[segment] = policy

    loon_rules: list[str] = []

    def record_top_level_unsupported(kind: str, raw_rule: Any) -> None:
        top_level_unsupported[kind] += 1
        unsupported_examples.setdefault(kind, [])
        if isinstance(raw_rule, str) and len(unsupported_examples[kind]) < 5:
            unsupported_examples[kind].append(raw_rule)

    for rule_index, raw_rule in enumerate(optimized.rules):
        if not isinstance(raw_rule, str):
            record_top_level_unsupported("<non-string>", raw_rule)
            continue
        parsed = parse_rule(raw_rule)
        wrapper = simple_ruleset_wrapper(raw_rule)
        if wrapper is not None:
            reference = parse_ruleset_reference(raw_rule)
            if reference is None:
                record_top_level_unsupported(parsed.kind or "<empty>", raw_rule)
                continue
            refs = find_ruleset_refs(raw_rule)
            if len(refs) != 1:
                record_top_level_unsupported(parsed.kind or "<empty>", raw_rule)
                continue
            segment = segment_of(refs[0])
            if reference.wrapper_kind == "SUB-RULE":
                for protocol, conditional_policy, fallback_policy in parse_loon_subrule(reference.policy):
                    conditional_by_provider.setdefault(refs[0], []).append((protocol, conditional_policy))
                    subrule_fallback_policy[segment] = fallback_policy
                    subrule_conditional_policy[(segment, protocol)] = conditional_policy
                record_policy(segment, subrule_fallback_policy[segment], raw_rule)
            else:
                record_policy(segment, reference.policy, raw_rule)
            continue
        if parsed.kind == "NETWORK" and len(parsed.parts) == 3 and parsed.parts[1].upper() in {"TCP", "UDP"}:
            loon_rules.append(f"PROTOCOL,{parsed.parts[1].upper()},{parsed.parts[2]}")
        elif parsed.kind == "MATCH":
            if len(parsed.parts) != 2:
                raise SystemExit(f"Loon structural unsupported MATCH rule: {raw_rule}")
            if rule_index != len(optimized.rules) - 1:
                raise SystemExit(f"Loon MATCH must be the final rule: {raw_rule}")
            loon_rules.append(f"FINAL,{parsed.parts[1]}")
        else:
            parts = split_top_level_commas(raw_rule)
            modifiers: list[str] = []
            while len(parts) > 2 and parts[-1].lower() in {"no-resolve", "src"}:
                modifiers.insert(0, parts.pop())
            policy = parts.pop() if len(parts) >= 3 else ""
            matcher_parts = parts
            if (
                policy
                and len(matcher_parts) >= 2
                and parsed.kind in LOON_CLASSICAL_KINDS
                and all(item.lower() in {"no-resolve", "src"} for item in modifiers)
            ):
                try:
                    native = loon_classical_rule(parse_rule(",".join([*matcher_parts, *modifiers])))
                except ValueError:
                    native = None
                if native is not None:
                    converted_parts = native[1].split(",")
                    modifier_index = next(
                        (index for index, item in enumerate(converted_parts[2:], start=2)
                         if item.lower() in {"no-resolve", "src"}),
                        len(converted_parts),
                    )
                    converted_parts.insert(modifier_index, policy)
                    loon_rules.append(",".join(converted_parts))
                    continue
            record_top_level_unsupported(parsed.kind or "<empty>", raw_rule)

    loon_dir = output_dist / "loon"
    emitted_segments: list[str] = []
    conditional_lines: dict[tuple[str, str], list[str]] = {}
    conditional_seen: dict[tuple[str, str], set[str]] = {}
    for provider_name, conditions in conditional_by_provider.items():
        segment = segment_of(provider_name)
        entries = rules_by_segment.get(segment, [])
        for protocol, _policy in conditions:
            lines = conditional_lines.setdefault((segment, protocol), [])
            seen = conditional_seen.setdefault((segment, protocol), set())
            for _kind, matcher in entries:
                conditional_line = f"AND,(({matcher}),(PROTOCOL,{protocol.upper()}))"
                if conditional_line not in seen:
                    seen.add(conditional_line)
                    lines.append(conditional_line)

    expected_loon_files = {f"{segment}.lsr" for segment in remote_order if segment in policies}
    expected_loon_files.update(f"{segment}-{protocol}.lsr" for segment, protocol in conditional_lines)
    for stale in loon_dir.glob("*.lsr"):
        if stale.name not in expected_loon_files:
            stale.unlink()
    for segment in remote_order:
        entries = rules_by_segment.get(segment, [])
        if not entries:
            print(f"[Loon] segment has no convertible rules: segment={segment}; remote rule omitted")
            continue
        ordered = sorted(entries, key=lambda item: LOON_RULE_PRIORITY.get(item[0], 100))
        write_text_atomic(loon_dir / f"{segment}.lsr", "".join(f"{line}\n" for _, line in ordered))
        emitted_segments.append(segment)

    remote_lines = ["[Remote Rule]"]
    for segment in emitted_segments:
        for protocol in ("udp", "tcp"):
            lines = conditional_lines.get((segment, protocol), [])
            if not lines:
                continue
            resource = f"{segment}-{protocol}.lsr"
            write_text_atomic(loon_dir / resource, "".join(f"{line}\n" for line in lines))
            remote_lines.append(
                f"{public_url(base_url, 'dist', 'loon', resource)},policy={subrule_conditional_policy[(segment, protocol)]},tag={segment}-{protocol},enabled=true"
            )
        remote_lines.append(
            f"{public_url(base_url, 'dist', 'loon', f'{segment}.lsr')},policy={policies[segment]},tag={segment},enabled=true"
        )
    remote_lines.extend(["", "[Rule]"])
    remote_lines.extend(loon_rules)
    write_text_atomic(output_dist / "generated" / "loon-rules.conf", "\n".join(remote_lines) + "\n")
    print("Loon outputs:")
    for segment in emitted_segments:
        rule_count = len(rules_by_segment.get(segment, []))
        print(f"  {segment}.lsr: {rule_count} rules, policy={policies[segment]}")
    total_skipped = sum(unsupported.values()) + sum(top_level_unsupported.values())
    unexpected_unsupported = set(unsupported) - set(allowed_unsupported or ())
    if unexpected_unsupported:
        examples = {kind: unsupported_examples.get(kind, [])[:1] for kind in sorted(unexpected_unsupported)}
        raise ValueError(f"Loon unsupported matcher(s) not allowlisted: {examples}")
    if top_level_unsupported:
        raise ValueError(f"Loon structural unsupported rule(s): {dict(top_level_unsupported)}")
    print("========== Loon Unsupported Summary ==========")
    type_counts = unsupported + top_level_unsupported
    for kind, count in sorted(type_counts.items()):
        print(f"{kind}: {count}")
        kind_examples = unsupported_examples.get(kind, [])
        if kind_examples:
            print("  examples:")
            for example in kind_examples:
                print(f"    {example}")
    print(f"top-level unsupported: {sum(top_level_unsupported.values())}")
    print(f"total skipped: {total_skipped}")
    print("==============================================")
    return {"segments": len(emitted_segments), "unsupported": total_skipped, "top_level_unsupported": sum(top_level_unsupported.values())}
