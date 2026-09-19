"""Production-profile assertions for this repository's published rules."""
from __future__ import annotations

import json
from pathlib import Path

import yaml

from .audit import audit_dist


def audit_production(root: Path, mihomo: str | None = None, sing_box: str | None = None) -> None:
    audit_dist(root, mihomo, sing_box)
    egern = yaml.safe_load((root / "generated/egern-rules.yaml").read_text(encoding="utf-8")) or {}
    policies = {
        Path(str(item["rule_set"]["match"])).name: item["rule_set"].get("policy")
        for item in egern.get("rules", [])
        if isinstance(item, dict) and isinstance(item.get("rule_set"), dict)
    }
    expected = {"Direct.yaml": "DIRECT", "AI.yaml": "🤖 AI", "Global.yaml": "🌍 国外流量", "China.yaml": "DIRECT"}
    for resource, policy in expected.items():
        if policies.get(resource) != policy:
            raise ValueError(f"production Egern policy mismatch: {resource} != {policy!r}")
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
    if "AI-udp.lsr" in loon and "AI.lsr" in loon:
        if loon.index("AI-udp.lsr") > loon.index("AI.lsr") or "policy=REJECT" not in loon or "policy=🤖 AI" not in loon:
            raise ValueError("production Loon AI UDP/fallback policy mismatch")
    route = json.loads((root / "generated/singbox-rules.json").read_text(encoding="utf-8")).get("route", {})
    if len(route.get("rule_set", [])) != 4:
        raise ValueError("production Sing-box route must contain four SRS")
    if {path.name for path in (root / "dns/singbox").glob("*.srs")} != {"China-domain.srs", "Global-domain.srs"}:
        raise ValueError("production DNS must contain China and Global SRS")
    print("converter production audit: ok")


def main() -> None:
    import argparse
    parser = argparse.ArgumentParser(description="Audit the repository production profile.")
    parser.add_argument("root", nargs="?", type=Path, default=Path("dist"))
    parser.add_argument("--mihomo")
    parser.add_argument("--sing-box")
    args = parser.parse_args()
    audit_production(args.root, args.mihomo, args.sing_box)


if __name__ == "__main__":
    main()
