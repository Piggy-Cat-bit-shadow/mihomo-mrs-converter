"""Small immutable models shared by normalization, optimization and exporters."""

from dataclasses import dataclass
from enum import Enum
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
