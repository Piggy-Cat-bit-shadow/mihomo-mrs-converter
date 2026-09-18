"""One command for final artifact audits used locally and by CI."""

import json
import subprocess
import sys
import tempfile
from pathlib import Path

import yaml

from .rules import parse_rule
from .semantics import is_target_ip_kind
from .validate import validate_config
from .exporters.singbox import LEGACY_ROUTE_ALIASES


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
    egern_files = sorted((root / "egern").glob("*.yaml"))
    if not egern_files:
        raise ValueError(f"Egern: {root / 'egern'} contains no rule-set artifacts")
    for path in egern_files:
        data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
        if any(field in data for field in ("ip_cidr_set", "ip_cidr6_set", "asn_set", "geoip_set")) and data.get("no_resolve") is not True:
            raise ValueError(f"Egern: {path}: target-IP set lacks no_resolve:true")
    egern_config = yaml.safe_load((root / "generated/egern-rules.yaml").read_text(encoding="utf-8")) or {}
    egern_refs = {
        Path(str(item["rule_set"]["match"])).name
        for item in egern_config.get("rules", [])
        if isinstance(item, dict) and isinstance(item.get("rule_set"), dict)
    }
    actual_egern = {path.name for path in egern_files}
    if egern_refs != actual_egern:
        raise ValueError(f"Egern: rule-set references {sorted(egern_refs)} != artifacts {sorted(actual_egern)}")

    loon_files = sorted((root / "loon").glob("*.lsr"))
    if not loon_files:
        raise ValueError(f"Loon: {root / 'loon'} contains no rule resources")
    for path in loon_files:
        lines = path.read_text(encoding="utf-8").splitlines()
        if len(lines) != len(set(lines)):
            raise ValueError(f"Loon: {path}: duplicate rule")
        for line in lines:
            kind = line.split(",", 1)[0].upper()
            if kind in {"IP-CIDR", "IP-CIDR6", "IP-ASN", "GEOIP"} and "no-resolve" not in line.lower():
                raise ValueError(f"Loon: {path}: target-IP rule missing no-resolve: {line}")
    remote_text = (root / "generated/loon-rules.conf").read_text(encoding="utf-8")
    remote_section = remote_text.split("[Remote Rule]\n", 1)[1].split("[Rule]", 1)[0]
    remote_lines = [line for line in remote_section.splitlines() if line.strip()]
    remote_names = [Path(line.split(",", 1)[0]).name for line in remote_lines]
    if len(remote_names) != len(set(remote_names)):
        raise ValueError("Loon: generated/loon-rules.conf contains duplicate remote resources")
    if set(remote_names) != {path.name for path in loon_files}:
        raise ValueError(f"Loon: remote resources {sorted(remote_names)} != artifacts {sorted(path.name for path in loon_files)}")
    if "AI-udp.lsr" in remote_names and "AI.lsr" in remote_names:
        if remote_names.index("AI-udp.lsr") > remote_names.index("AI.lsr"):
            raise ValueError("Loon: AI-udp.lsr must precede AI.lsr")
        udp = next(line for line in remote_lines if line.startswith("http") and "/AI-udp.lsr," in line)
        fallback = next(line for line in remote_lines if line.startswith("http") and "/AI.lsr," in line)
        if "policy=REJECT" not in udp or "policy=🤖 AI" not in fallback:
            raise ValueError("Loon: AI UDP/fallback policies are incorrect")

    singbox = json.loads((root / "generated/singbox-rules.json").read_text(encoding="utf-8"))
    route = singbox.get("route", {})
    route_sets = route.get("rule_set", [])
    tags = [item.get("tag") for item in route_sets if isinstance(item, dict)]
    if len(tags) != len(set(tags)):
        raise ValueError("Sing-box: generated route contains duplicate rule-set tags")
    if len(tags) != 4:
        raise ValueError(f"Sing-box: expected 4 route SRS, found {len(tags)}")
    if any(rule.get("action") == "resolve" for rule in route.get("rules", []) if isinstance(rule, dict)):
        raise ValueError("Sing-box: route contains action: resolve")
    srs_dir = root / "singbox"
    canonical_tags = set(tags)
    expected_aliases = {
        alias for canonical, aliases in LEGACY_ROUTE_ALIASES.items() if canonical in canonical_tags for alias in aliases
    }
    actual_srs = {path.stem for path in srs_dir.glob("*.srs")}
    if actual_srs != canonical_tags | expected_aliases:
        raise ValueError(f"Sing-box: canonical/compatibility artifacts mismatch: expected {sorted(canonical_tags | expected_aliases)}, found {sorted(actual_srs)}")
    for item in route_sets:
        if not isinstance(item, dict) or item.get("format") != "binary":
            raise ValueError(f"Sing-box: invalid rule-set declaration: {item!r}")
        artifact = srs_dir / f"{item.get('tag')}.srs"
        if not artifact.exists():
            raise ValueError(f"Sing-box: missing artifact for tag {item.get('tag')}: {artifact}")
    dns_dir = root / "dns/singbox"
    dns_files = sorted(dns_dir.glob("*.srs"))
    if {path.name for path in dns_files} != {"China-domain.srs", "Global-domain.srs"}:
        raise ValueError(f"DNS: expected China-domain.srs and Global-domain.srs, found {[path.name for path in dns_files]}")
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
