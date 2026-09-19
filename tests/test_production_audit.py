import json
import tempfile
import unittest
from pathlib import Path

import yaml

from converter.production_audit import audit_production


class ProductionAuditTest(unittest.TestCase):
    def make_fixture(self, root: Path, include_legacy_zero: bool = False) -> Path:
        metadata = root / "segment-names.yaml"
        metadata.write_text(yaml.safe_dump({"segments": {
            "BlockHttpDNS": {"name": "HTTPDNS", "role": "reject"},
            "Lan": {"name": "Direct", "role": "direct"},
            "me-pure": {"name": "AI", "role": "ai"},
            "Scholar-Foreign": {"name": "Global", "role": "global"},
            "apple": {"name": "China", "role": "china"},
        }}, sort_keys=False), encoding="utf-8")
        generated = root / "dist/generated"
        generated.mkdir(parents=True)
        egern_rules = [{"rule_set": {"match": f"https://example.test/{name}.yaml", "policy": policy}}
            for name, policy in (("HTTPDNS", "REJECT-DROP"), ("Direct", "DIRECT"), ("AI", "🤖 AI"), ("Global", "🌍 国外流量"), ("China", "DIRECT"))]
        egern_rules.extend([
            {"and": {"match": [{"rule_set": {"match": "https://example.test/AI.yaml"}}, {"protocol": {"match": "udp"}}], "policy": "REJECT"}},
            {"default": {"policy": "🌍 国外流量"}},
        ])
        if include_legacy_zero:
            egern_rules.insert(0, {"ip_cidr": {"match": "0.0.0.0/32", "policy": "REJECT-DROP"}})
        (generated / "egern-rules.yaml").write_text(yaml.safe_dump({"rules": egern_rules}, allow_unicode=True), encoding="utf-8")
        (generated / "mihomo-rules.yaml").write_text("rules: []\n", encoding="utf-8")
        (generated / "loon-rules.conf").write_text("[Remote Rule]\n", encoding="utf-8")
        route = {"route": {"rule_set": [{"tag": name} for name in ("HTTPDNS", "Direct", "AI", "Global", "China")], "rules": [{"rule_set": [name], "action": "reject", "method": "drop"} for name in ("HTTPDNS", "Direct", "AI", "Global", "China")]}}
        (generated / "singbox-rules.json").write_text(json.dumps(route), encoding="utf-8")
        for name in ("HTTPDNS", "Direct", "AI", "Global", "China"):
            (root / "dist/egern").mkdir(exist_ok=True)
            (root / "dist/egern" / f"{name}.yaml").write_text("{}\n", encoding="utf-8")
            (root / "dist/singbox").mkdir(exist_ok=True)
            (root / "dist/singbox" / f"{name}.srs").write_bytes(b"")
        (root / "dist/generated/loon-rules.conf").write_text("\n".join(
            f"https://example.test/{name}.lsr,policy={policy},tag={name},enabled=true"
            for name, policy in (("HTTPDNS", "REJECT-DROP"), ("Direct", "DIRECT"), ("AI", "🤖 AI"), ("Global", "🌍 国外流量"), ("China", "DIRECT"))
        ) + "\n", encoding="utf-8")
        (root / "dist/dns/singbox").mkdir(parents=True)
        for name in ("China", "Global"):
            (root / "dist/dns/singbox" / f"{name}-domain.srs").write_bytes(b"")
        return metadata

    def test_removed_zero_address_rules_are_not_required(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            metadata = self.make_fixture(root)
            audit_production(root / "dist", segment_names=metadata)

    def test_removed_zero_address_rules_cannot_return_to_generated_output(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            metadata = self.make_fixture(root, include_legacy_zero=True)
            with self.assertRaisesRegex(ValueError, "removed zero-address rule"):
                audit_production(root / "dist", segment_names=metadata)
