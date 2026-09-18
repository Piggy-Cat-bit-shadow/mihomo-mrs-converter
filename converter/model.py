"""Small immutable models shared by normalization, optimization and exporters."""

from dataclasses import dataclass
from enum import Enum
from collections import Counter
from pathlib import Path
from typing import Any


class Behavior(str, Enum):
    DOMAIN = "domain"
    CLASSICAL = "classical"
    IPCIDR = "ipcidr"


@dataclass(frozen=True)
class RuleLine:
    raw: str
    kind: str
    parts: tuple[str, ...]


@dataclass(frozen=True)
class RulesetReference:
    provider: str
    policy: str
    modifiers: tuple[str, ...]
    wrapper_kind: str


@dataclass(frozen=True)
class ProviderIdentity:
    segment: str
    behavior: Behavior
    part: int = 1


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


@dataclass(frozen=True)
class NormalizedProvider:
    """Provider state before final serialization; it contains no artifact identity."""

    name: str
    behavior: Behavior
    payload: tuple[str, ...]
    metadata: ProviderMetadata = ProviderMetadata()

    def as_config(self) -> dict[str, Any]:
        return {"behavior": self.behavior.value, **self.metadata.as_mapping()}


@dataclass
class ProviderResult:
    name: str
    providers: list[NormalizedProvider]
    generated_names: list[str]
    original_rules: Counter[str]
    rebuilt_rules: Counter[str]


@dataclass(frozen=True)
class BuildConfig:
    input: Path
    dist: Path
    base_url: str
    mihomo_bin: str
    sing_box_bin: str
    complete_config: Path | None = None
    complete_output: Path | None = None


@dataclass
class BuildResult:
    final_config: dict[str, Any]
    final_payloads: dict[str, list[str]]
    dedup_stats: dict[str, Any]
    exporter_stats: dict[str, Any]


@dataclass
class BuildContext:
    """Mutable per-build input context; it never stores artifact paths or payload output."""

    memory_cache: dict[str, str]
    used_names: set[str]


@dataclass
class DedupStats:
    input_count: int = 0
    exact_duplicates_removed: int = 0
    domain_covered_by_suffix: int = 0
    suffix_covered_by_parent_suffix: int = 0
    ipcidr_duplicates_removed: int = 0
    ipcidr_covered_by_parent: int = 0
    output_count: int = 0

    @property
    def removed(self) -> int:
        return self.input_count - self.output_count


def format_provider_name(identity: ProviderIdentity) -> str:
    suffix = {Behavior.DOMAIN: "domain", Behavior.CLASSICAL: "classical", Behavior.IPCIDR: "ip"}[identity.behavior]
    base = f"{identity.segment}-{suffix}"
    return base if identity.part == 1 else f"{base}-part-{identity.part:02d}"


def parse_legacy_provider_name(name: str) -> ProviderIdentity | None:
    import re
    match = re.fullmatch(r"(.+?)-(domain|classical|ip)(?:-part-(\d+))?", name)
    if not match:
        return None
    behavior = {"domain": Behavior.DOMAIN, "classical": Behavior.CLASSICAL, "ip": Behavior.IPCIDR}[match.group(2)]
    return ProviderIdentity(match.group(1), behavior, int(match.group(3) or 1))
