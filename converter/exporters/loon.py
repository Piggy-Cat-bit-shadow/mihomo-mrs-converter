"""Independent loon exporter implementation."""

from collections import Counter
from pathlib import Path
from typing import Any
import ipaddress

from ..artifacts import public_url, write_text_atomic, write_yaml_atomic
from ..model import parse_legacy_provider_name
from ..rules import find_ruleset_refs, parse_egern_sub_rule_members, parse_rule, parse_ruleset_reference, simple_ruleset_wrapper, split_top_level_commas
from ..semantics import is_target_ip_kind, parse_ip_network

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


def loon_segment_name(provider_name: str) -> str:
    """Return the logical segment through the shared legacy identity parser."""
    identity = parse_legacy_provider_name(provider_name)
    return identity.segment if identity else provider_name


def loon_rule_from_provider(
    behavior: str, rule: str, segment: str, modifiers: tuple[str, ...] = ()
) -> tuple[str, str] | None:
    """Convert one normalized provider entry to a native Loon rule."""
    if behavior == "domain":
        if rule.startswith("+."):
            return "DOMAIN-SUFFIX", f"DOMAIN-SUFFIX,{rule[2:]}"
        return "DOMAIN", f"DOMAIN,{rule}"
    if behavior == "ipcidr":
        network = parse_ip_network(rule)
        if network is None:
            raise ValueError("normalized ipcidr provider entry is not a CIDR")
        kind = "IP-CIDR" if network.version == 4 else "IP-CIDR6"
        return kind, ",".join([kind, rule, "no-resolve"])

    parsed = parse_rule(rule)
    kind = parsed.kind
    if kind == "DST-PORT":
        kind = "DEST-PORT"
    elif kind == "NETWORK":
        kind = "PROTOCOL"
    if kind not in LOON_CLASSICAL_KINDS and kind not in {"DST-PORT"}:
        raise ValueError(f"unsupported Loon rule type {parsed.kind or '<empty>'}")
    if len(parsed.parts) not in {2, 3}:
        raise ValueError("rule has unsupported fields or an embedded policy")
    if len(parsed.parts) == 3 and (
        parsed.parts[2].lower() != "no-resolve"
        or not is_target_ip_kind(kind)
    ):
        raise ValueError("only IP-CIDR/IP-CIDR6/IP-ASN may use no-resolve")
    if kind == "IP-CIDR":
        try:
            if ipaddress.ip_network(parsed.parts[1], strict=False).version != 4:
                raise ValueError("IP-CIDR contains an IPv6 network")
        except ValueError as exc:
            raise ValueError(f"invalid IPv4 CIDR: {exc}") from exc
    if kind == "IP-CIDR6":
        try:
            if ipaddress.ip_network(parsed.parts[1], strict=False).version != 6:
                raise ValueError("IP-CIDR6 contains an IPv4 network")
        except ValueError as exc:
            raise ValueError(f"invalid IPv6 CIDR: {exc}") from exc
    values = list(parsed.parts[1:])
    if is_target_ip_kind(kind) and "no-resolve" not in {item.lower() for item in values[1:]}:
        values.append("no-resolve")
    return kind, ",".join([kind, *values])


def export_loon(
    config: dict[str, Any], final_payloads: dict[str, list[str]], output_dist: Path, base_url: str
) -> dict[str, int]:
    """Export final normalized providers directly as independent Loon rule lists."""
    rules_by_segment: dict[str, list[tuple[str, str]]] = {}
    unsupported: Counter[str] = Counter()
    top_level_unsupported: Counter[str] = Counter()
    unsupported_examples: dict[str, list[str]] = {}
    first_segment_index: dict[str, int] = {}
    provider_modifiers: dict[str, set[str]] = {}
    conditional_by_provider: dict[str, list[tuple[str, str]]] = {}
    subrule_fallback_policy: dict[str, str] = {}
    subrule_conditional_policy: dict[tuple[str, str], str] = {}
    seen_by_segment: dict[str, set[str]] = {}

    for raw_rule in config.get("rules", []):
        reference = parse_ruleset_reference(raw_rule)
        if reference is not None:
            provider_modifiers.setdefault(reference.provider, set()).update(
                modifier.lower() for modifier in reference.modifiers
)

    for name, provider in config["rule-providers"].items():
        segment = loon_segment_name(name)
        payload = final_payloads.get(name, [])
        entries = rules_by_segment.setdefault(segment, [])
        seen = seen_by_segment.setdefault(segment, set())
        for raw_rule in payload:
            try:
                converted = loon_rule_from_provider(
                    provider.get("behavior", ""),
                    raw_rule,
                    segment,
                    tuple(provider_modifiers.get(name, set())),
                )
            except ValueError as exc:
                kind = parse_rule(raw_rule).kind or "<empty>"
                unsupported[kind] += 1
                unsupported_examples.setdefault(kind, [])
                if len(unsupported_examples[kind]) < 5:
                    unsupported_examples[kind].append(raw_rule)
                continue
            if converted[1] not in seen:
                entries.append(converted)
                seen.add(converted[1])

    policies: dict[str, str] = {}
    remote_order: list[str] = []

    sub_rules = config.get("sub-rules") or {}

    def parse_loon_subrule(name: str) -> list[tuple[str, str, str]]:
        members = sub_rules.get(name)
        parsed = parse_egern_sub_rule_members(members)
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

    def record_policy(provider_name: str, policy: str, raw_rule: str) -> None:
        segment = loon_segment_name(provider_name)
        if segment not in first_segment_index:
            first_segment_index[segment] = len(first_segment_index)
            remote_order.append(segment)
        if segment in policies and policies[segment] != policy:
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

    for raw_rule in config.get("rules", []):
        if not isinstance(raw_rule, str):
            record_top_level_unsupported("<non-string>", raw_rule)
            continue
        parsed = parse_rule(raw_rule)
        wrapper = simple_ruleset_wrapper(raw_rule)
        if wrapper is not None:
            reference = parse_ruleset_reference(raw_rule)
            assert reference is not None
            refs = find_ruleset_refs(raw_rule)
            if len(refs) != 1:
                record_top_level_unsupported(parsed.kind or "<empty>", raw_rule)
                continue
            if reference.wrapper_kind == "SUB-RULE":
                for protocol, conditional_policy, fallback_policy in parse_loon_subrule(reference.policy):
                    segment = loon_segment_name(refs[0])
                    conditional_by_provider.setdefault(refs[0], []).append((protocol, conditional_policy))
                    subrule_fallback_policy[segment] = fallback_policy
                    subrule_conditional_policy[(segment, protocol)] = conditional_policy
                record_policy(refs[0], subrule_fallback_policy[loon_segment_name(refs[0])], raw_rule)
            else:
                record_policy(refs[0], reference.policy, raw_rule)
            continue
        if parsed.kind == "NETWORK" and len(parsed.parts) == 3 and parsed.parts[1].upper() in {"TCP", "UDP"}:
            loon_rules.append(f"PROTOCOL,{parsed.parts[1].upper()},{parsed.parts[2]}")
        elif parsed.kind == "MATCH" and len(parsed.parts) == 2:
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
                    converted = loon_rule_from_provider(
                        "classical", ",".join([*matcher_parts, *modifiers]), "<top-level>", tuple(modifiers)
                    )
                except ValueError:
                    converted = None
                if converted is not None:
                    converted_parts = converted[1].split(",")
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
        segment = loon_segment_name(provider_name)
        entries = rules_by_segment.get(segment, [])
        for protocol, _policy in conditions:
            lines = conditional_lines.setdefault((segment, protocol), [])
            seen = conditional_seen.setdefault((segment, protocol), set())
            for _kind, matcher in entries:
                line = f"AND,(({matcher}),(PROTOCOL,{protocol.upper()}))"
                if line not in seen:
                    seen.add(line)
                    lines.append(line)

    expected_loon_files = {f"{segment}.lsr" for segment in remote_order if segment in policies}
    expected_loon_files.update(f"{segment}-{protocol}.lsr" for segment, protocol in conditional_lines)
    for stale in loon_dir.glob("*.lsr"):
        if stale.name not in expected_loon_files:
            stale.unlink()
    for segment in remote_order:
        if segment not in policies:
            continue
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
        with (loon_dir / f"{segment}.lsr").open(encoding="utf-8") as handle:
            rule_count = sum(1 for _ in handle)
        print(f"  {segment}.lsr: {rule_count} rules, policy={policies[segment]}")
    total_skipped = sum(unsupported.values()) + sum(top_level_unsupported.values())
    print("========== Loon Unsupported Summary ==========")
    type_counts = unsupported + top_level_unsupported
    for kind, count in sorted(type_counts.items()):
        print(f"{kind}: {count}")
        examples = unsupported_examples.get(kind, [])
        if examples:
            print("  examples:")
            for example in examples:
                print(f"    {example}")
    print(f"top-level unsupported: {sum(top_level_unsupported.values())}")
    print(f"total skipped: {total_skipped}")
    print("==============================================")
    return {"segments": len(emitted_segments), "unsupported": total_skipped, "top_level_unsupported": sum(top_level_unsupported.values())}
