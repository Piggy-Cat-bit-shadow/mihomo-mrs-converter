"""One command for final artifact audits used locally and by CI."""

import json
import subprocess
import sys
import tempfile
from pathlib import Path

import yaml

from .pipeline import is_target_ip_kind, parse_rule
from .validate import validate_config


def validate_mihomo(binary: str, config: dict) -> None:
    policies = set(config.get("sub-rules", {}))
    for value in [*config.get("rules", []), *sum(config.get("sub-rules", {}).values(), [])]:
        if isinstance(value, str):
            parts = value.split(",")
            if len(parts) >= 2:
                policies.add(parts[-1].strip("()"))
    reserved = {"DIRECT", "REJECT", "REJECT-DROP", "PASS", "COMPATIBLE"}
    base = "__audit_base__"
    candidate = dict(config)
    candidate["proxies"] = [{"name": base, "type": "ss", "server": "127.0.0.1", "port": 1, "cipher": "aes-128-gcm", "password": "audit"}]
    candidate["proxy-groups"] = [{"name": policy, "type": "select", "proxies": [base]} for policy in sorted(policies - reserved) if policy]
    with tempfile.TemporaryDirectory(prefix="converter-audit-") as tmp:
        path = Path(tmp) / "config.yaml"
        path.write_text(yaml.safe_dump(candidate, allow_unicode=True, sort_keys=False), encoding="utf-8")
        subprocess.run([binary, "-t", "-f", str(path)], check=True)


def audit_dist(root: Path, mihomo: str | None = None) -> None:
    mihomo_path = root / "generated/mihomo-rules.yaml"
    config = yaml.safe_load(mihomo_path.read_text(encoding="utf-8"))
    validate_config(root, config, require_no_orphans=True)
    providers = config["rule-providers"]
    if any("-part-" in name for name in providers):
        raise ValueError("unexpected fallback provider in committed example")
    for raw in config.get("rules", []):
        if not isinstance(raw, str): continue
        parsed = parse_rule(raw)
        if is_target_ip_kind(parsed.kind) and "no-resolve" not in {part.lower() for part in parsed.parts[2:]}:
            raise ValueError(f"destination IP rule lacks no-resolve: {raw}")
    for path in sorted((root / "egern").glob("*.yaml")):
        data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
        if any(field in data for field in ("ip_cidr_set", "ip_cidr6_set", "asn_set", "geoip_set")) and data.get("no_resolve") is not True:
            raise ValueError(f"Egern target-IP set lacks no_resolve: {path}")
    for path in sorted((root / "loon").glob("*.lsr")):
        for line in path.read_text(encoding="utf-8").splitlines():
            kind = line.split(",", 1)[0].upper()
            if kind in {"IP-CIDR", "IP-CIDR6", "IP-ASN", "GEOIP"} and "no-resolve" not in line.lower():
                raise ValueError(f"Loon target-IP rule lacks no-resolve: {path}: {line}")
    singbox = json.loads((root / "generated/singbox-rules.json").read_text(encoding="utf-8"))
    if any(rule.get("action") == "resolve" for rule in singbox.get("route", {}).get("rules", [])):
        raise ValueError("Sing-box contains action: resolve")
    if mihomo:
        validate_mihomo(mihomo, config)
    print("converter audit: ok")


def main(argv: list[str] | None = None) -> None:
    args = argv if argv is not None else sys.argv[1:]
    root = Path(args[0] if args and not args[0].startswith("--") else "dist")
    mihomo = args[args.index("--mihomo") + 1] if "--mihomo" in args else None
    audit_dist(root, mihomo)


if __name__ == "__main__":
    main()
