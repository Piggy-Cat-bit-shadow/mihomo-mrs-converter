"""Shared per-segment and per-DNS-group views consumed by the exporters.

Every exporter needs the same content: the domain entries, networks and
classical rules of a logical segment, already deduplicated.  Building that view
once keeps the deduplication rules in one place and stops each exporter from
re-classifying the same payload.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Mapping, Sequence

from .model import Behavior, Provider
from .payload import DedupStats, DomainEntry, IpEntry, dedup_domains, dedup_networks, dedup_rules
from .rules import DOMAIN_KINDS, RuleLine


@dataclass(frozen=True)
class SegmentView:
    domains: tuple[DomainEntry, ...]
    networks: tuple[IpEntry, ...]
    classical: tuple[RuleLine, ...]
    stats: DedupStats


@dataclass(frozen=True)
class DnsView:
    domains: tuple[DomainEntry, ...]
    classical: tuple[RuleLine, ...]


def build_segment_views(providers: Sequence[Provider]) -> dict[str, SegmentView]:
    grouped: dict[str, dict[str, list]] = {}
    for provider in providers:
        slot = grouped.setdefault(provider.segment, {"domain": [], "classical": [], "ipcidr": []})
        slot[provider.behavior.value].extend(provider.payload)
    views: dict[str, SegmentView] = {}
    for name, slot in grouped.items():
        domains, domain_stats = dedup_domains(slot["domain"])
        networks, network_stats = dedup_networks(slot["ipcidr"])
        classical, classical_stats = dedup_rules(slot["classical"])
        stats = DedupStats()
        for part in (domain_stats, network_stats, classical_stats):
            stats.merge(part)
        views[name] = SegmentView(domains, networks, classical, stats)
    return views


def build_dns_views(
    providers: Sequence[Provider],
    roles: Mapping[str, str],
    groups: Mapping[str, frozenset[str]],
) -> dict[str, DnsView]:
    domain_payload: dict[str, list[DomainEntry]] = {group: [] for group in groups}
    classical_payload: dict[str, list[RuleLine]] = {group: [] for group in groups}
    for provider in providers:
        role = roles.get(provider.segment)
        if role is None:
            # Providers outside a planned segment are not routed as a DNS
            # group; exporters still fail closed when a required role is
            # missing from the build.
            continue
        group = next((name for name, group_roles in groups.items() if role in group_roles), None)
        if group is None:
            continue
        if provider.behavior is Behavior.DOMAIN:
            domain_payload[group].extend(provider.payload)
        elif provider.behavior is Behavior.CLASSICAL:
            classical_payload[group].extend(entry for entry in provider.payload if entry.kind in DOMAIN_KINDS)
    views: dict[str, DnsView] = {}
    for group in groups:
        domains, _ = dedup_domains(domain_payload[group])
        classical, _ = dedup_rules(classical_payload[group])
        views[group] = DnsView(domains, classical)
    return views
