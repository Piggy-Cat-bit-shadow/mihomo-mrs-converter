"""Shared helpers for building typed build inputs in tests."""

from __future__ import annotations

from typing import Any, Iterable, Mapping, Sequence

from converter.model import (
    Behavior,
    NormalizedProvider,
    OptimizedConfig,
    Provider,
    ProviderMetadata,
    SemanticConfig,
)
from converter.payload import parse_payload
from converter.views import DnsView, SegmentView, build_dns_views, build_segment_views


def provider(
    name: str,
    behavior: str,
    rules: Iterable[str],
    *,
    segment: str | None = None,
    metadata: ProviderMetadata | None = None,
) -> Provider:
    return Provider(
        name=name,
        segment=segment or name,
        behavior=Behavior(behavior),
        payload=parse_payload(behavior, list(rules)),
        metadata=metadata or ProviderMetadata(),
    )


def normalized(
    source: str,
    name: str,
    behavior: str,
    rules: Iterable[str],
    *,
    metadata: ProviderMetadata | None = None,
) -> NormalizedProvider:
    return NormalizedProvider(
        name=name,
        source=source,
        behavior=Behavior(behavior),
        payload=parse_payload(behavior, list(rules)),
        metadata=metadata or ProviderMetadata(),
    )


def semantic_config(
    providers: Iterable[NormalizedProvider] = (),
    rules: Iterable[str] = (),
    sub_rules: Mapping[str, Sequence[str]] | None = None,
    extras: Mapping[str, Any] | None = None,
) -> SemanticConfig:
    return SemanticConfig(
        providers=tuple(providers),
        rules=tuple(rules),
        sub_rules={name: tuple(members) for name, members in (sub_rules or {}).items()},
        extras=dict(extras or {}),
    )


def optimized_config(
    providers: Iterable[Provider] = (),
    rules: Iterable[str] = (),
    sub_rules: Mapping[str, Sequence[str]] | None = None,
    extras: Mapping[str, Any] | None = None,
) -> OptimizedConfig:
    return OptimizedConfig(
        providers=tuple(providers),
        rules=tuple(rules),
        sub_rules={name: tuple(members) for name, members in (sub_rules or {}).items()},
        extras=dict(extras or {}),
    )


def segment_views(config: OptimizedConfig) -> dict[str, SegmentView]:
    return build_segment_views(config.providers)


def dns_views(
    config: OptimizedConfig,
    roles: Mapping[str, str],
    groups: Mapping[str, frozenset[str]],
) -> dict[str, DnsView]:
    return build_dns_views(config.providers, roles, groups)
