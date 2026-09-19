"""Independent dns exporter implementation."""

from collections import Counter
from pathlib import Path
import tempfile
from typing import Any

from ..artifacts import convert_source_to_mrs, write_yaml_atomic, write_yaml_payload
from ..rules import parse_rule
from ..model import provider_segment
from ..optimize import dedup_domain_payload, dedup_exact_rules
from .egern_ruleset import classify_egern_classical, optimize_egern_rule_set

DNS_CLASSICAL_KINDS = {"DOMAIN-KEYWORD", "DOMAIN-WILDCARD", "DOMAIN-REGEX"}
from ..rules import DNS_DOMAIN_KINDS
DNS_ROLE_GROUPS = {
    "China": {"direct", "china"},
    "Global": {"ai", "global"},
}


def collect_dns_domain_payloads(
    config: dict[str, Any], payloads: dict[str, list[str]] | None = None,
    classical_kinds: set[str] | None = None, segment_roles: dict[str, str] | None = None,
) -> dict[str, tuple[list[str], list[str]]]:
    """Return the shared normalized domain/classical DNS view for each group."""
    domain_rules: dict[str, list[str]] = {group: [] for group in DNS_ROLE_GROUPS}
    classical_rules: dict[str, list[str]] = {group: [] for group in DNS_ROLE_GROUPS}
    classical_kinds = classical_kinds or DNS_CLASSICAL_KINDS
    for name, provider in config["rule-providers"].items():
        segment = provider_segment(name)
        role = (segment_roles or {}).get(segment)
        if role is None:
            raise SystemExit(f"DNS provider segment {segment!r} has no explicit role")
        group = next((group for group, roles in DNS_ROLE_GROUPS.items() if role in roles), None)
        if group is None:
            continue
        if payloads is None or name not in payloads:
            continue
        provider_payload = payloads[name]
        if provider.get("behavior") == "domain":
            domain_rules[group].extend(provider_payload)
        elif provider.get("behavior") == "classical":
            classical_rules[group].extend(
                rule for rule in provider_payload if parse_rule(rule).kind in classical_kinds
)
    return {
        group: (dedup_domain_payload(domain_rules[group])[0], dedup_exact_rules(classical_rules[group])[0])
        for group in DNS_ROLE_GROUPS
    }


def export_dns(
    config: dict[str, Any], final_payloads: dict[str, list[str]], output_dist: Path, base_url: str, mihomo: str | None,
    segment_roles: dict[str, str] | None = None,
) -> dict[str, int]:
    """Export DNS-only views from the already-final, deduplicated providers."""
    if not mihomo:
        raise SystemExit("DNS domain MRS output requires a mihomo binary")

    dns_payloads = collect_dns_domain_payloads(config, final_payloads, segment_roles=segment_roles)

    present_segments = {
        (segment_roles or {}).get(provider_segment(name))
        for name in config["rule-providers"]
        if (segment_roles or {}).get(provider_segment(name), provider_segment(name).lower()) in {"direct", "china", "ai", "global"}
    }
    missing = sorted({"direct", "china", "ai", "global"} - present_segments)
    if missing:
        raise SystemExit("DNS export requires missing segment(s): " + ", ".join(missing))

    dns_root = output_dist / "dns"
    counts: Counter[str] = Counter()
    with tempfile.TemporaryDirectory(prefix="mihomo-mrs-dns-") as scratch:
        scratch_root = Path(scratch)
        for group in DNS_ROLE_GROUPS:
            optimized_domains, optimized_classical = dns_payloads[group]
            source_path = scratch_root / f"{group}-domain.yaml"
            write_yaml_payload(source_path, optimized_domains)
            convert_source_to_mrs(
                mihomo, "domain", source_path, dns_root / "mihomo" / f"{group}-domain.mrs"
            )

            write_yaml_payload(dns_root / "mihomo" / f"{group}-classical.yaml", optimized_classical)

            egern_fields: dict[str, list[str]] = {}
            for rule in optimized_domains:
                field = "domain_suffix_set" if rule.startswith("+.") else "domain_set"
                egern_fields.setdefault(field, []).append(rule[2:] if rule.startswith("+.") else rule)
            for rule in optimized_classical:
                classified = classify_egern_classical(rule)
                if classified is not None:
                    field, value, no_resolve = classified
                    if not no_resolve:
                        egern_fields.setdefault(field, []).append(value)
            egern_fields, _ = optimize_egern_rule_set(egern_fields)
            write_yaml_atomic(dns_root / "egern" / f"{group}.yaml", egern_fields)
            counts[f"{group}-domain"] = len(optimized_domains)
            counts[f"{group}-classical"] = len(optimized_classical)
            counts[f"{group}-egern"] = sum(
                len(values) for field, values in egern_fields.items() if field != "no_resolve"
            )

    print("DNS outputs:")
    for group in DNS_ROLE_GROUPS:
        print(f"  Mihomo {group}: domain={counts[f'{group}-domain']}, classical-domain={counts[f'{group}-classical']}")
        print(f"  Egern {group}: domain entries={counts[f'{group}-egern']}")
    return dict(counts)
