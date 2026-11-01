"""Typed rule payloads: parse each provider value once, consume it everywhere.

Before this module existed every exporter re-split the same provider strings and
re-classified them.  A payload now records what a value *is* (domain entry,
network entry or classical rule) so exporters only project it into their own
serialization.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Sequence

from .rules import RuleLine, is_target_ip_kind, parse_ip_network, parse_rule


@dataclass(frozen=True, slots=True)
class DomainEntry:
    """A domain provider value: ``suffix=True`` means a ``+.`` suffix rule."""

    suffix: bool
    value: str

    def as_rule(self) -> str:
        return f"+.{self.value}" if self.suffix else self.value

    @property
    def suffix_value(self) -> str | None:
        """Lower-cased suffix label used for coverage checks."""
        if not self.suffix or not self.value:
            return None
        return self.value.lower().rstrip(".")

    @property
    def exact_value(self) -> str:
        """Lower-cased exact domain used for coverage checks."""
        return self.value.lower().rstrip(".")


@dataclass(frozen=True, slots=True)
class IpEntry:
    """An IP-CIDR provider value, kept verbatim plus its parsed network."""

    raw: str
    network: Any

    def as_rule(self) -> str:
        return self.raw

    @property
    def version(self) -> int:
        return int(self.network.version)


# The concrete entry type is implied by the provider behavior: domain payloads
# hold DomainEntry, ipcidr payloads hold IpEntry, classical payloads RuleLine.
Payload = tuple[Any, ...]


@dataclass
class DedupStats:
    input_count: int = 0
    exact_duplicates_removed: int = 0
    domain_covered_by_suffix: int = 0
    suffix_covered_by_parent_suffix: int = 0
    ipcidr_duplicates_removed: int = 0
    ipcidr_covered_by_parent: int = 0
    output_count: int = 0


    def merge(self, other: "DedupStats") -> None:
        for name in ("input_count", "exact_duplicates_removed", "domain_covered_by_suffix",
                     "suffix_covered_by_parent_suffix", "ipcidr_duplicates_removed",
                     "ipcidr_covered_by_parent", "output_count"):
            setattr(self, name, getattr(self, name) + getattr(other, name))


def parse_domain_payload(values: Sequence[str]) -> tuple[DomainEntry, ...]:
    return tuple(_domain_entry(value) for value in values)


def _domain_entry(value: str) -> DomainEntry:
    return DomainEntry(value.startswith("+."), value[2:] if value.startswith("+.") else value)


def parse_ipcidr_payload(values: Sequence[str]) -> tuple[IpEntry, ...]:
    entries: list[IpEntry] = []
    for value in values:
        network = parse_ip_network(value)
        if network is None:
            raise SystemExit(f"invalid ipcidr provider entry: {value!r}")
        entries.append(IpEntry(value, network))
    return tuple(entries)


def parse_classical_payload(values: Sequence[str]) -> tuple[RuleLine, ...]:
    return tuple(parse_rule(value) for value in values)


def serialize_payload(payload: Payload) -> list[str]:
    return [entry.as_rule() for entry in payload]


def dedup_domains(entries: Sequence[DomainEntry]) -> tuple[tuple[DomainEntry, ...], DedupStats]:
    stats = DedupStats(input_count=len(entries))
    unique: list[DomainEntry] = []
    seen: set[str] = set()
    for entry in entries:
        raw = entry.as_rule()
        if raw in seen:
            stats.exact_duplicates_removed += 1
            continue
        seen.add(raw)
        unique.append(entry)
    suffixes = {suffix for entry in unique if (suffix := entry.suffix_value) is not None}
    output: list[DomainEntry] = []
    for entry in unique:
        suffix = entry.suffix_value
        if suffix is not None:
            if _parent_suffix_covered(suffix, suffixes):
                stats.suffix_covered_by_parent_suffix += 1
                continue
        elif _domain_covered(entry.exact_value, suffixes):
            stats.domain_covered_by_suffix += 1
            continue
        output.append(entry)
    stats.output_count = len(output)
    return tuple(output), stats


def _domain_covered(domain: str, suffixes: set[str]) -> bool:
    labels = domain.split(".")
    return any(".".join(labels[index:]) in suffixes for index in range(len(labels)))


def _parent_suffix_covered(suffix: str, suffixes: set[str]) -> bool:
    labels = suffix.split(".")
    return any(".".join(labels[index:]) in suffixes for index in range(1, len(labels)))


def dedup_networks(entries: Sequence[IpEntry]) -> tuple[tuple[IpEntry, ...], DedupStats]:
    stats = DedupStats(input_count=len(entries))
    unique: list[IpEntry] = []
    seen: set[str] = set()
    for entry in entries:
        if entry.raw in seen:
            stats.ipcidr_duplicates_removed += 1
            continue
        seen.add(entry.raw)
        unique.append(entry)
    networks = {entry.network for entry in unique}
    output: list[IpEntry] = []
    for entry in unique:
        if any(entry.network.supernet(new_prefix=prefix) in networks for prefix in range(entry.network.prefixlen - 1, -1, -1)):
            stats.ipcidr_covered_by_parent += 1
            continue
        output.append(entry)
    stats.output_count = len(output)
    return tuple(output), stats


def dedup_rules(entries: Sequence[RuleLine]) -> tuple[tuple[RuleLine, ...], DedupStats]:
    stats = DedupStats(input_count=len(entries))
    output: list[RuleLine] = []
    seen: set[str] = set()
    for entry in entries:
        if entry.raw in seen:
            stats.exact_duplicates_removed += 1
            continue
        seen.add(entry.raw)
        output.append(entry)
    stats.output_count = len(output)
    return tuple(output), stats


def dedup_payload(behavior: str, payload: Payload) -> tuple[Payload, DedupStats]:
    if behavior == "domain":
        return dedup_domains(payload)
    if behavior == "ipcidr":
        return dedup_networks(payload)
    return dedup_rules(payload)


def payload_has_target_ip(behavior: str, payload: Payload) -> bool:
    if behavior == "ipcidr":
        return True
    if behavior != "classical":
        return False
    return any(isinstance(entry, RuleLine) and is_target_ip_kind(entry.kind) for entry in payload)


__all__ = [
    "DedupStats", "DomainEntry", "IpEntry", "Payload", "dedup_domains", "dedup_networks",
    "dedup_payload", "dedup_rules", "parse_classical_payload", "parse_domain_payload",
    "parse_ipcidr_payload", "payload_has_target_ip", "serialize_payload",
]
