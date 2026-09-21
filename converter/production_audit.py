"""Production-profile assertions for this repository's published rules."""
from __future__ import annotations

import json
from pathlib import Path

import yaml

from .export_config import ExportProfile, load_export_profile
from .rules import find_ruleset_refs, iter_all_rules
from .model import provider_segment
from .segments import load_segment_specs
from .yamlio import load_yaml_unique


def _canonical_route_order(config: dict, expected_names: set[str]) -> list[str]:
    order: list[str] = []
    for raw in iter_all_rules(config):
        for provider in find_ruleset_refs(raw):
            name = provider_segment(provider)
            if name in expected_names and name not in order:
                order.append(name)
    return order


def _assert_no_legacy_top_level_rules(root: Path) -> None:
    legacy = {"0.0.0.0/32", "::/128"}
    mihomo = load_yaml_unique(root / "generated/mihomo-rules.yaml") or {}
    for raw in mihomo.get("rules", []):
        if isinstance(raw, str):
            parts = [part.strip() for part in raw.split(",")]
            if len(parts) >= 3 and parts[0].upper() in {"IP-CIDR", "IP-CIDR6"} and parts[1] in legacy and parts[2] in {"REJECT", "REJECT-DROP"}:
                raise ValueError(f"production Mihomo route contains removed zero-address rule: {raw}")
    egern = load_yaml_unique(root / "generated/egern-rules.yaml") or {}
    for item in egern.get("rules", []):
        for key in ("ip_cidr", "ip_cidr6"):
            if isinstance(item, dict) and isinstance(item.get(key), dict) and item[key].get("match") in legacy:
                raise ValueError(f"production Egern route contains removed zero-address rule: {item}")
    loon = (root / "generated/loon-rules.conf").read_text(encoding="utf-8")
    rule_section = loon.split("[Rule]", 1)[1] if "[Rule]" in loon else ""
    if any(address in rule_section for address in legacy):
        raise ValueError("production Loon route contains removed zero-address rule")
    route = json.loads((root / "generated/singbox-rules.json").read_text(encoding="utf-8")).get("route", {})
    for item in route.get("rules", []):
        if not isinstance(item, dict):
            continue
        if any(item.get(key) in (["0.0.0.0/32"], ["::/128"], "0.0.0.0/32", "::/128") for key in ("ip_cidr", "ip_cidr6")) and item.get("action") == "reject":
            raise ValueError(f"production Sing-box route contains removed zero-address rule: {item}")


def _expected_reject_policy(spec) -> str:
    if spec.reject_mode == "reject":
        return "REJECT"
    if spec.reject_mode == "drop":
        return "REJECT-DROP"
    raise ValueError(f"production reject segment has no valid reject-mode: {spec.name}")


def audit_production(root: Path, segment_names: Path | None = None, export_config: Path | None = None) -> None:
    metadata_path = segment_names or root.parent / "segment-names.yaml"
    specs = load_segment_specs(metadata_path)
    if not specs:
        raise ValueError(f"production segment metadata is empty: {metadata_path}")
    profile_path = export_config or root.parent / "config/export.yaml"
    profile = load_export_profile(profile_path if profile_path.exists() else None)
    expected_names = [spec.name for spec in specs]
    mihomo = load_yaml_unique(root / "generated/mihomo-rules.yaml") or {}
    providers = mihomo.get("rule-providers") or {}
    if any("-part-" in name for name in providers):
        raise ValueError("unexpected fallback provider in generated production artifacts")
    canonical_order = _canonical_route_order(mihomo, set(expected_names))
    if set(canonical_order) != set(expected_names):
        raise ValueError(f"production canonical route segments mismatch: {canonical_order}")
    egern = load_yaml_unique(root / "generated/egern-rules.yaml") or {}
    policies = {
        Path(str(item["rule_set"]["match"])).name: item["rule_set"].get("policy")
        for item in egern.get("rules", [])
        if isinstance(item, dict) and isinstance(item.get("rule_set"), dict)
    }
    egern_order = [
        Path(str(item["rule_set"]["match"])).name.removesuffix(".yaml")
        for item in egern.get("rules", [])
        if isinstance(item, dict) and isinstance(item.get("rule_set"), dict)
    ]
    expected_order = canonical_order
    expected_reject_policies = {
        spec.name: _expected_reject_policy(spec)
        for spec in specs
        if spec.role == "reject"
    }
    for raw in mihomo.get("rules", []):
        if not isinstance(raw, str):
            continue
        refs = find_ruleset_refs(raw)
        if len(refs) != 1:
            continue
        provider = provider_segment(refs[0])
        if provider not in expected_reject_policies:
            continue
        parts = [part.strip() for part in raw.split(",")]
        if parts[0].upper() == "RULE-SET" and len(parts) >= 3:
            actual = parts[2]
            if actual != expected_reject_policies[provider]:
                raise ValueError(
                    f"production Mihomo reject policy mismatch for {provider}: "
                    f"expected {expected_reject_policies[provider]}, got {actual}"
                )
    for spec in specs:
        resource = f"{spec.name}.yaml"
        if resource not in policies:
            raise ValueError(f"production Egern missing segment: {spec.name}")
        if spec.role == "reject" and policies[resource] != expected_reject_policies[spec.name]:
            raise ValueError(
                f"production Egern reject policy mismatch for {spec.name}: "
                f"expected {expected_reject_policies[spec.name]}, got {policies[resource]}"
            )
    actual_egern_order = [name for name in egern_order if name in set(expected_order)]
    if actual_egern_order != expected_order:
        raise ValueError("production Egern segment order does not match segment metadata")
    _assert_no_legacy_top_level_rules(root)
    defaults = [item["default"] for item in egern.get("rules", []) if isinstance(item, dict) and isinstance(item.get("default"), dict)]
    default_rules = [raw for raw in mihomo.get("rules", []) if isinstance(raw, str) and raw.upper().startswith("MATCH,")]
    expected_default = profile.egern_policy_map.get(default_rules[-1].split(",", 1)[1], default_rules[-1].split(",", 1)[1]) if default_rules else None
    if not defaults or expected_default is None or defaults[-1].get("policy") != expected_default:
        raise ValueError("production Egern default policy mismatch")
    loon = (root / "generated/loon-rules.conf").read_text(encoding="utf-8")
    loon_order = [
        line.split("tag=", 1)[1].split(",", 1)[0]
        for line in loon.splitlines()
        if line.startswith("http") and "tag=" in line
        and line.split("tag=", 1)[1].split(",", 1)[0] in expected_order
    ]
    if loon_order != expected_order:
        raise ValueError(f"production Loon segment order mismatch: {loon_order}")
    for spec in specs:
        if spec.role == "reject" and f"tag={spec.name}," in loon:
            line = next(line for line in loon.splitlines() if f"tag={spec.name}," in line)
            expected = expected_reject_policies[spec.name]
            if f"policy={expected}," not in line:
                raise ValueError(f"production Loon reject policy mismatch for {spec.name}: expected {expected}")
    route = json.loads((root / "generated/singbox-rules.json").read_text(encoding="utf-8")).get("route", {})
    route_sets = route.get("rule_set", [])
    tags = [item.get("tag") for item in route_sets if isinstance(item, dict)]
    if len(tags) != len(set(tags)):
        raise ValueError("production Sing-box route contains duplicate SRS tags")
    if tags != expected_order:
        missing = sorted(set(expected_order) - set(tags))
        unknown = sorted(set(tags) - set(expected_order))
        raise ValueError(f"production Sing-box route segments mismatch: missing={missing}, unknown={unknown}, order={tags}")
    actual_srs = {path.name for path in (root / "singbox").glob("*.srs")}
    expected_srs = {f"{tag}.srs" for tag in tags}
    if actual_srs != expected_srs:
        raise ValueError(f"production Sing-box SRS files mismatch: missing={sorted(expected_srs - actual_srs)}, unknown={sorted(actual_srs - expected_srs)}")
    route_rules = route.get("rules", [])
    rule_positions = {
        tag: index
        for index, item in enumerate(route_rules)
        if isinstance(item, dict)
        for tag in (item.get("rule_set", []) if isinstance(item.get("rule_set"), list) else [])
    }
    if set(rule_positions) != set(expected_order):
        raise ValueError("production Sing-box route rules do not reference every configured segment")
    if any(rule_positions[expected_order[i]] > rule_positions[expected_order[i + 1]] for i in range(len(expected_order) - 1)):
        raise ValueError("production Sing-box route segment order does not match segment metadata")
    for spec in specs:
        if spec.role == "reject":
            rule = next((item for item in route_rules if isinstance(item, dict) and spec.name in item.get("rule_set", [])), None)
            expected = expected_reject_policies[spec.name]
            if not rule or rule.get("action") != "reject":
                raise ValueError(f"production Sing-box reject action mismatch for {spec.name}")
            if expected == "REJECT-DROP" and rule.get("method") != "drop":
                raise ValueError(f"production Sing-box reject mode mismatch for {spec.name}: expected drop")
            if expected == "REJECT" and "method" in rule:
                raise ValueError(f"production Sing-box reject mode mismatch for {spec.name}: method must be absent")
    expected_dns = {f"{group}-domain.srs" for group in profile.dns_groups}
    if {path.name for path in (root / "dns/singbox").glob("*.srs")} != expected_dns:
        raise ValueError("production DNS files do not match export profile groups")
    print("converter production audit: ok")


def main() -> None:
    import argparse
    parser = argparse.ArgumentParser(description="Audit the repository production profile.")
    parser.add_argument("root", nargs="?", type=Path, default=Path("dist"))
    parser.add_argument("--segment-names", type=Path)
    parser.add_argument("--export-config", type=Path)
    args = parser.parse_args()
    audit_production(args.root, args.segment_names, args.export_config)


if __name__ == "__main__":
    main()
