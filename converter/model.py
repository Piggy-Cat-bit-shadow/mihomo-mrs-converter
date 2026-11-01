"""Immutable core models shared by normalization, optimization and exporters."""

from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any

from .payload import Payload


class Behavior(str, Enum):
    DOMAIN = "domain"
    CLASSICAL = "classical"
    IPCIDR = "ipcidr"

    def __str__(self) -> str:  # pragma: no cover - convenience only
        return self.value


@dataclass(frozen=True)
class ProviderMetadata:
    """Only provider attributes that affect semantic output."""

    interval: Any = None
    proxy: Any = None
    size_limit: Any = None

    @classmethod
    def from_mapping(cls, provider: dict[str, Any]) -> "ProviderMetadata":
        return cls(provider.get("interval"), provider.get("proxy"), provider.get("size-limit"))

    def as_mapping(self) -> dict[str, Any]:
        return {
            key: value
            for key, value in {
                "interval": self.interval,
                "proxy": self.proxy,
                "size-limit": self.size_limit,
            }.items()
            if value is not None
        }

    def merged_with(self, others: list["ProviderMetadata"]) -> "ProviderMetadata | None":
        """Combine metadata of providers that are about to become one artifact.

        Returns ``None`` when the providers disagree on attributes clients would
        see, in which case the caller must keep them as separate providers.
        """
        every = [self, *others]
        for attribute in ("proxy", "size_limit"):
            values = [getattr(item, attribute) for item in every]
            if any(value is None for value in values) and any(value is not None for value in values):
                return None
            if len({repr(value) for value in values}) > 1:
                return None
        intervals = [item.interval for item in every if isinstance(item.interval, int)]
        return ProviderMetadata(min(intervals) if intervals else None, self.proxy, self.size_limit)


@dataclass(frozen=True)
class NormalizedProvider:
    """A provider generated from one input source, before segment identity exists."""

    name: str
    source: str
    behavior: Behavior
    payload: Payload
    metadata: ProviderMetadata = ProviderMetadata()

    def as_config(self) -> dict[str, Any]:
        return {"behavior": self.behavior.value, **self.metadata.as_mapping()}


@dataclass(frozen=True)
class Provider:
    """A published provider artifact with explicit segment identity."""

    name: str
    segment: str
    behavior: Behavior
    payload: Payload
    metadata: ProviderMetadata = ProviderMetadata()

    def as_config(self) -> dict[str, Any]:
        return {"behavior": self.behavior.value, **self.metadata.as_mapping()}


@dataclass(frozen=True)
class PlannedBlock:
    """A contiguous block of compatible RULE-SET rules before provider merging."""

    start: int
    end: int
    ordinal: int
    routing: tuple[str, str]
    wrapper: tuple[str, str]
    providers: tuple[str, ...]
    sources: tuple[str, ...]
    segment: str | None
    name: str


@dataclass(frozen=True)
class SemanticConfig:
    """Normalized build input: providers plus rewritten rule text."""

    providers: tuple[NormalizedProvider, ...]
    rules: tuple[str, ...]
    sub_rules: dict[str, tuple[str, ...]] = field(default_factory=dict)
    extras: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class OptimizedConfig:
    """Final in-memory build state after merging, deduplication and renaming."""

    providers: tuple[Provider, ...]
    rules: tuple[str, ...]
    sub_rules: dict[str, tuple[str, ...]] = field(default_factory=dict)
    extras: dict[str, Any] = field(default_factory=dict)
    blocks: tuple[PlannedBlock, ...] = ()

    def provider_map(self) -> dict[str, Provider]:
        return {provider.name: provider for provider in self.providers}

    def provider_segments(self) -> dict[str, str]:
        return {provider.name: provider.segment for provider in self.providers}

    def as_config(self) -> dict[str, Any]:
        return {
            **self.extras,
            "rule-providers": {provider.name: provider.as_config() for provider in self.providers},
            "rules": list(self.rules),
            "sub-rules": {name: list(members) for name, members in self.sub_rules.items()},
        }


@dataclass(frozen=True)
class BuildConfig:
    input: Path
    dist: Path
    base_url: str
    mihomo_bin: str | None
    sing_box_bin: str | None
    complete_config: Path | None = None
    complete_output: Path | None = None
    segment_names: Path | None = None
    export_config: Path | None = None
    bootstrap_managed: bool = False
    provider_cache: Path | None = None


@dataclass
class BuildResult:
    final_config: dict[str, Any]


@dataclass
class BuildContext:
    """Mutable per-build input context; it never stores artifact paths or payload output."""

    memory_cache: dict[object, str]
    used_names: set[str]
