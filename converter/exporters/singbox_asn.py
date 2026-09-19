"""ASN identity and index contracts used by the Sing-box exporter."""
from __future__ import annotations

from typing import Any

from ..rules import parse_rule

ASN_INDEX_VERSION = 2
ASN_INDEX_FILENAME = "asn-index-v2.json"


def collect_required_asns(groups: list[dict[str, Any]], payloads: dict[str, list[str]]) -> set[str]:
    required: set[str] = set()
    for group in groups:
        for provider in group["providers"]:
            for raw in payloads.get(provider, []):
                parsed = parse_rule(raw)
                if parsed.kind in {"IP-ASN", "SRC-IP-ASN"} and len(parsed.parts) > 1:
                    required.add(parsed.parts[1])
    return required
