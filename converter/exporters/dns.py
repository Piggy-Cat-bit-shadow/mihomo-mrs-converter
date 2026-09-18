"""Independent dns exporter implementation."""

from ..pipeline import *  # shared parser, artifacts and semantic primitives

DNS_CLASSICAL_KINDS = {"DOMAIN-KEYWORD", "DOMAIN-WILDCARD", "DOMAIN-REGEX"}
DNS_DOMAIN_KINDS = {"DOMAIN", "DOMAIN-SUFFIX", "DOMAIN-KEYWORD", "DOMAIN-REGEX", "DOMAIN-WILDCARD"}
DNS_SEGMENT_GROUPS = {
    "China": {"Direct", "China"},
    "Global": {"AI", "Global"},
}


def collect_dns_domain_payloads(
    config: dict[str, Any], payloads: dict[str, list[str]] | None = None,
    classical_kinds: set[str] | None = None,
) -> dict[str, tuple[list[str], list[str]]]:
    """Return the shared normalized domain/classical DNS view for each group."""
    domain_rules: dict[str, list[str]] = {group: [] for group in DNS_SEGMENT_GROUPS}
    classical_rules: dict[str, list[str]] = {group: [] for group in DNS_SEGMENT_GROUPS}
    classical_kinds = classical_kinds or DNS_CLASSICAL_KINDS
    for name, provider in config["rule-providers"].items():
        segment = egern_segment_name(name)
        group = next((group for group, members in DNS_SEGMENT_GROUPS.items() if segment in members), None)
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
        for group in DNS_SEGMENT_GROUPS
    }


def export_dns(
    config: dict[str, Any], staging: Path, output_dist: Path, base_url: str, mihomo: str | None,
    payloads: dict[str, list[str]] | None = None,
) -> dict[str, int]:
    """Export DNS-only views from the already-final, deduplicated providers."""
    if not mihomo:
        raise SystemExit("DNS domain MRS output requires a mihomo binary")

    if payloads is None:
        payloads = {}
        for name, provider in config["rule-providers"].items():
            payload_path = source_path_for_provider(staging, provider) or generated_artifact_path(staging, provider)
            if payload_path is not None and payload_path.exists():
                payloads[name] = read_yaml_payload(payload_path)
    dns_payloads = collect_dns_domain_payloads(config, payloads)

    present_segments = {
        egern_segment_name(name)
        for name in config["rule-providers"]
        if egern_segment_name(name) in {"Direct", "China", "AI", "Global"}
    }
    missing = sorted({"Direct", "China", "AI", "Global"} - present_segments)
    if missing:
        raise SystemExit("DNS export requires missing segment(s): " + ", ".join(missing))

    dns_root = output_dist / "dns"
    counts: Counter[str] = Counter()
    for group in DNS_SEGMENT_GROUPS:
        optimized_domains, optimized_classical = dns_payloads[group]
        source_path = staging / "dns" / "source" / f"{group}-domain.yaml"
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
    for group in DNS_SEGMENT_GROUPS:
        print(f"  Mihomo {group}: domain={counts[f'{group}-domain']}, classical-domain={counts[f'{group}-classical']}")
        print(f"  Egern {group}: domain entries={counts[f'{group}-egern']}")
    return dict(counts)


