"""One command for final artifact audits used locally and by CI."""

import json
import subprocess
import argparse
import tempfile
from pathlib import Path

import yaml

from .rules import iter_all_rules, parse_rule, rule_policy
from .semantics import is_target_ip_kind
from .validate import validate_final_config


def validate_mihomo(binary: str, config: dict) -> None:
    policies = set(config.get("sub-rules", {}))
    for value in iter_all_rules(config):
        policy = rule_policy(value)
        if policy and policy.lower() != "no-resolve":
            policies.add(policy.strip("()"))
    reserved = {"DIRECT", "REJECT", "REJECT-DROP", "PASS", "COMPATIBLE"}
    base = "__audit_base__"
    candidate = dict(config)
    candidate["proxies"] = [{"name": base, "type": "ss", "server": "127.0.0.1", "port": 1, "cipher": "aes-128-gcm", "password": "audit"}]
    candidate["proxy-groups"] = [{"name": policy, "type": "select", "proxies": [base]} for policy in sorted(policies - reserved) if policy]
    with tempfile.TemporaryDirectory(prefix="converter-audit-") as tmp:
        path = Path(tmp) / "config.yaml"
        path.write_text(yaml.safe_dump(candidate, allow_unicode=True, sort_keys=False), encoding="utf-8")
        subprocess.run([binary, "-t", "-f", str(path)], check=True)


def _validate_srs(binary: str, path: Path, temporary: Path) -> None:
    output = temporary / f"{path.name}.json"
    subprocess.run([binary, "rule-set", "decompile", str(path), "-o", str(output)], check=True)
    json.loads(output.read_text(encoding="utf-8"))


def audit_dist(root: Path, mihomo: str | None = None, sing_box: str | None = None) -> None:
    mihomo_path = root / "generated/mihomo-rules.yaml"
    config = yaml.safe_load(mihomo_path.read_text(encoding="utf-8"))
    validate_final_config(root, config)
    providers = config["rule-providers"]
    if any("-part-" in name for name in providers):
        raise ValueError("unexpected fallback provider in generated artifacts")
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
    egern_rules = egern_config.get("rules", [])
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
    singbox = json.loads((root / "generated/singbox-rules.json").read_text(encoding="utf-8"))
    route = singbox.get("route", {})
    route_sets = route.get("rule_set", [])
    tags = [item.get("tag") for item in route_sets if isinstance(item, dict)]
    if len(tags) != len(set(tags)):
        raise ValueError("Sing-box: generated route contains duplicate rule-set tags")
    if any(rule.get("action") == "resolve" for rule in route.get("rules", []) if isinstance(rule, dict)):
        raise ValueError("Sing-box: route contains action: resolve")
    srs_dir = root / "singbox"
    canonical_tags = set(tags)
    actual_srs = {path.stem for path in srs_dir.glob("*.srs")}
    if actual_srs != canonical_tags:
        raise ValueError(f"Sing-box: canonical artifacts mismatch: expected {sorted(canonical_tags)}, found {sorted(actual_srs)}")
    for item in route_sets:
        if not isinstance(item, dict) or item.get("format") != "binary":
            raise ValueError(f"Sing-box: invalid rule-set declaration: {item!r}")
        artifact = srs_dir / f"{item.get('tag')}.srs"
        if not artifact.exists():
            raise ValueError(f"Sing-box: missing artifact for tag {item.get('tag')}: {artifact}")
    dns_dir = root / "dns/singbox"
    dns_files = sorted(dns_dir.glob("*.srs"))
    if not dns_files:
        raise ValueError(f"DNS: {dns_dir} contains no SRS artifacts")
    if sing_box:
        with tempfile.TemporaryDirectory(prefix="converter-srs-audit-") as tmp:
            temporary = Path(tmp)
            for tag in sorted(canonical_tags):
                _validate_srs(sing_box, srs_dir / f"{tag}.srs", temporary)
            for path in dns_files:
                _validate_srs(sing_box, path, temporary)
    if mihomo:
        validate_mihomo(mihomo, config)
    print("converter audit: ok")


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(description="Audit generated artifacts without production-specific policy assumptions.")
    parser.add_argument("root", nargs="?", type=Path, default=Path("dist"))
    parser.add_argument("--mihomo")
    parser.add_argument("--sing-box")
    args = parser.parse_args(argv)
    audit_dist(args.root, args.mihomo, args.sing_box)


if __name__ == "__main__":
    main()
