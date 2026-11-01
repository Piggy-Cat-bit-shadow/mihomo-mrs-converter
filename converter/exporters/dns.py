"""DNS-only Mihomo and Egern artifacts; Sing-box DNS lives in its exporter."""

from collections import Counter
from pathlib import Path
import tempfile
from typing import Mapping

from ..artifacts import convert_sources_to_mrs, write_yaml_atomic, write_yaml_payload
from ..payload import serialize_payload
from ..views import DnsView
from .egern import egern_dns_fields

DNS_CLASSICAL_KINDS = frozenset({"DOMAIN-KEYWORD", "DOMAIN-WILDCARD", "DOMAIN-REGEX"})


def export_dns(
    views: Mapping[str, DnsView],
    output_dist: Path,
    mihomo: str | None,
    required_roles: frozenset[str] | set[str] | None = None,
    present_roles: set[str] | None = None,
) -> dict[str, int]:
    """Export DNS-only views from the already-final, deduplicated providers."""
    if not mihomo:
        raise SystemExit("DNS domain MRS output requires a mihomo binary")
    missing = sorted(set(required_roles or ()) - set(present_roles or ()))
    if missing:
        raise SystemExit("DNS export requires missing segment(s): " + ", ".join(missing))

    dns_root = output_dist / "dns"
    counts: Counter[str] = Counter()
    with tempfile.TemporaryDirectory(prefix="mihomo-mrs-dns-") as scratch:
        jobs: list[tuple[str, Path, Path]] = []
        for group, view in views.items():
            classical = [rule for rule in view.classical if rule.kind in DNS_CLASSICAL_KINDS]
            source_path = Path(scratch) / f"{group}-domain.yaml"
            write_yaml_payload(source_path, serialize_payload(view.domains))
            jobs.append(("domain", source_path, dns_root / "mihomo" / f"{group}-domain.mrs"))
            write_yaml_payload(dns_root / "mihomo" / f"{group}-classical.yaml", [rule.raw for rule in classical])
            egern_fields = egern_dns_fields(view.domains, classical)
            write_yaml_atomic(dns_root / "egern" / f"{group}.yaml", egern_fields)
            counts[f"{group}-domain"] = len(view.domains)
            counts[f"{group}-classical"] = len(classical)
            counts[f"{group}-egern"] = sum(
                len(values) for field, values in egern_fields.items() if field != "no_resolve"
            )
        convert_sources_to_mrs(mihomo, jobs)

    print("DNS outputs:")
    for group in views:
        print(f"  Mihomo {group}: domain={counts[f'{group}-domain']}, classical-domain={counts[f'{group}-classical']}")
        print(f"  Egern {group}: domain entries={counts[f'{group}-egern']}")
    return dict(counts)
