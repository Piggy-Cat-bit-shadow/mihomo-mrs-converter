"""Production-profile assertions for this repository's published rules."""
from __future__ import annotations

import json
from pathlib import Path

import yaml

from .segments import load_segment_specs


def audit_production(root: Path, mihomo: str | None = None, sing_box: str | None = None, segment_names: Path | None = None) -> None:
    metadata_path = segment_names or root.parent / "segment-names.yaml"
    specs = load_segment_specs(metadata_path)
    if not specs:
        raise ValueError(f"production segment metadata is empty: {metadata_path}")
    expected_names = [spec.name for spec in specs]
    egern = yaml.safe_load((root / "generated/egern-rules.yaml").read_text(encoding="utf-8")) or {}
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
    egern_positions = {name: egern_order.index(name) for name in expected_names if name in egern_order}
    for spec in specs:
        resource = f"{spec.name}.yaml"
        if resource not in policies:
            raise ValueError(f"production Egern missing segment: {spec.name}")
        if spec.role == "reject" and policies[resource] != "REJECT-DROP":
            raise ValueError(f"production Egern reject segment must use REJECT-DROP: {spec.name}")
    if list(egern_positions) != expected_names:
        raise ValueError("production Egern segment order does not match segment metadata")
    udp = [item for item in egern.get("rules", []) if isinstance(item, dict) and isinstance(item.get("and"), dict)]
    if not any(item["and"].get("policy") == "REJECT" and any(isinstance(m, dict) and m.get("protocol", {}).get("match") == "udp" for m in item["and"].get("match", [])) for item in udp):
        raise ValueError("production Egern AI UDP rule must use REJECT")
    native_ip = {
        key: value for item in egern.get("rules", []) if isinstance(item, dict)
        for key, value in item.items() if key in {"ip_cidr", "ip_cidr6"} and isinstance(value, dict)
    }
    for key, match in (("ip_cidr6", "::/128"), ("ip_cidr", "0.0.0.0/32")):
        rule = native_ip.get(key)
        if not rule or rule.get("match") != match or rule.get("policy") != "REJECT-DROP" or rule.get("no_resolve") is not True:
            raise ValueError(f"production Egern missing {key} rule for {match}")
    defaults = [item["default"] for item in egern.get("rules", []) if isinstance(item, dict) and isinstance(item.get("default"), dict)]
    if not defaults or defaults[-1].get("policy") != "🌍 国外流量":
        raise ValueError("production Egern default policy mismatch")
    loon = (root / "generated/loon-rules.conf").read_text(encoding="utf-8")
    loon_order = [
        line.split("tag=", 1)[1].split(",", 1)[0]
        for line in loon.splitlines()
        if line.startswith("http") and "tag=" in line
        and line.split("tag=", 1)[1].split(",", 1)[0] in expected_names
    ]
    if loon_order != expected_names:
        raise ValueError(f"production Loon segment order mismatch: {loon_order}")
    for spec in specs:
        if spec.role == "reject" and f"tag={spec.name}," in loon and "policy=REJECT-DROP" not in next(line for line in loon.splitlines() if f"tag={spec.name}," in line):
            raise ValueError(f"production Loon reject segment must use REJECT-DROP: {spec.name}")
    if "AI-udp.lsr" in loon and "AI.lsr" in loon:
        if loon.index("AI-udp.lsr") > loon.index("AI.lsr") or "policy=REJECT" not in loon or "policy=🤖 AI" not in loon:
            raise ValueError("production Loon AI UDP/fallback policy mismatch")
    route = json.loads((root / "generated/singbox-rules.json").read_text(encoding="utf-8")).get("route", {})
    route_sets = route.get("rule_set", [])
    tags = [item.get("tag") for item in route_sets if isinstance(item, dict)]
    if len(tags) != len(set(tags)):
        raise ValueError("production Sing-box route contains duplicate SRS tags")
    if tags != expected_names:
        missing = sorted(set(expected_names) - set(tags))
        unknown = sorted(set(tags) - set(expected_names))
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
    if set(rule_positions) != set(expected_names):
        raise ValueError("production Sing-box route rules do not reference every configured segment")
    if any(rule_positions[expected_names[i]] > rule_positions[expected_names[i + 1]] for i in range(len(expected_names) - 1)):
        raise ValueError("production Sing-box route segment order does not match segment metadata")
    for spec in specs:
        if spec.role == "reject":
            rule = next((item for item in route_rules if isinstance(item, dict) and spec.name in item.get("rule_set", [])), None)
            if not rule or rule.get("action") != "reject" or rule.get("method") != "drop":
                raise ValueError(f"production Sing-box reject segment must use drop: {spec.name}")
    if {path.name for path in (root / "dns/singbox").glob("*.srs")} != {"China-domain.srs", "Global-domain.srs"}:
        raise ValueError("production DNS must contain China and Global SRS")
    print("converter production audit: ok")


def main() -> None:
    import argparse
    parser = argparse.ArgumentParser(description="Audit the repository production profile.")
    parser.add_argument("root", nargs="?", type=Path, default=Path("dist"))
    parser.add_argument("--mihomo")
    parser.add_argument("--sing-box")
    parser.add_argument("--segment-names", type=Path)
    args = parser.parse_args()
    audit_production(args.root, args.mihomo, args.sing_box, args.segment_names)


if __name__ == "__main__":
    main()
