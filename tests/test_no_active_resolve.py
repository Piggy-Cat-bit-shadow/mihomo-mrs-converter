import json
import unittest
from pathlib import Path

import yaml

from scripts.convert import is_target_ip_kind, parse_rule, provider_has_target_ip


ROOT = Path(__file__).resolve().parents[1]
DIST = ROOT / "dist"


class NoActiveResolveAuditTest(unittest.TestCase):
    def test_committed_artifacts_follow_no_active_resolve_policy(self) -> None:
        mihomo = yaml.safe_load((DIST / "generated/mihomo-rules.yaml").read_text(encoding="utf-8"))
        providers = mihomo["rule-providers"]
        target_providers = set()
        for name, provider in providers.items():
            relative = str(provider["url"]).split("/dist/", 1)[-1]
            artifact = DIST / relative
            payload = []
            if artifact.suffix in {".yaml", ".yml"} and artifact.exists():
                payload = yaml.safe_load(artifact.read_text(encoding="utf-8")).get("payload", [])
            if provider_has_target_ip(provider.get("behavior", ""), payload):
                target_providers.add(name)

        for raw in mihomo["rules"]:
            if not isinstance(raw, str):
                continue
            parsed = parse_rule(raw)
            if is_target_ip_kind(parsed.kind):
                self.assertIn("no-resolve", {part.lower() for part in parsed.parts[2:]}, raw)
            for name in target_providers:
                if f"RULE-SET,{name}" in raw:
                    self.assertIn("no-resolve", raw.lower(), raw)

        egern_files = sorted((DIST / "egern").glob("*.yaml"))
        self.assertFalse([path for path in egern_files if path.stem.endswith("-no-resolve")])
        for path in egern_files:
            data = yaml.safe_load(path.read_text(encoding="utf-8"))
            has_target_ip = any(field in data for field in ("ip_cidr_set", "ip_cidr6_set", "asn_set", "geoip_set"))
            if has_target_ip:
                self.assertIs(data.get("no_resolve"), True, str(path))

        target_kinds = {"IP-CIDR", "IP-CIDR6", "IP-ASN", "GEOIP"}
        for path in sorted((DIST / "loon").glob("*.lsr")):
            for line in path.read_text(encoding="utf-8").splitlines():
                parts = line.split(",")
                if parts and parts[0].upper() in target_kinds:
                    self.assertIn("no-resolve", {part.lower() for part in parts[2:]}, line)
        loon_rules = (DIST / "generated/loon-rules.conf").read_text(encoding="utf-8").split("[Rule]\n", 1)[1]
        for line in loon_rules.splitlines():
            parts = line.split(",")
            if parts and parts[0].upper() in target_kinds:
                self.assertIn("no-resolve", {part.lower() for part in parts[2:]}, line)

        singbox = json.loads((DIST / "generated/singbox-rules.json").read_text(encoding="utf-8"))
        self.assertFalse(any(rule.get("action") == "resolve" for rule in singbox["route"]["rules"]))


if __name__ == "__main__":
    unittest.main()
