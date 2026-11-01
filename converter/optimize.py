"""Merge contiguous RULE-SET blocks, deduplicate payloads and rename providers."""

from typing import Any, Mapping, Sequence

from .model import NormalizedProvider, OptimizedConfig, Provider, SemanticConfig
from .payload import dedup_payload
from .rules import (
    find_ruleset_refs,
    parse_ruleset_reference,
    rewrite_rules,
    ruleset_suffix_for_behavior,
    simple_ruleset_wrapper,
    wrap_ruleset_rule,
)
from .segments import PlannedBlock, plan_blocks

BEHAVIOR_ORDER = {"domain": 0, "classical": 1, "ipcidr": 2}
BEHAVIOR_LABEL = {"ipcidr": "ip"}


def _block_groups(
    block: PlannedBlock, rules: Sequence[Any], providers: Mapping[str, NormalizedProvider]
) -> tuple[dict[str, list[NormalizedProvider]], dict[str, set[str]]]:
    """Group a block's providers by behavior, collecting their RULE-SET modifiers."""
    grouped: dict[str, list[NormalizedProvider]] = {}
    modifiers: dict[str, set[str]] = {}
    for offset, name in enumerate(block.providers):
        provider = providers[name]
        reference = parse_ruleset_reference(rules[block.start + offset])
        if reference is None:
            raise ValueError(f"invalid ruleset reference: {rules[block.start + offset]}")
        behavior = provider.behavior.value
        grouped.setdefault(behavior, []).append(provider)
        modifiers.setdefault(behavior, set()).update(ruleset_suffix_for_behavior(reference.modifiers, behavior))
    return grouped, modifiers


def _external_references(semantic: SemanticConfig) -> set[str]:
    """Providers referenced outside a mergeable block must keep their own payload."""
    external = {
        name
        for members in semantic.sub_rules.values()
        for item in members
        for name in find_ruleset_refs(item)
    }
    external.update(
        name
        for item in semantic.rules
        if simple_ruleset_wrapper(item) is None
        for name in find_ruleset_refs(item)
    )
    return external


def optimize_config(
    semantic: SemanticConfig, mapping: dict[str, str] | None = None
) -> OptimizedConfig:
    """Perform all provider transformations without touching the filesystem."""
    rules = list(semantic.rules)
    providers = {provider.name: provider for provider in semantic.providers}
    blocks = plan_blocks(rules, {name: provider.source for name, provider in providers.items()}, mapping)
    external_refs = _external_references(semantic) & set(providers)

    final: list[Provider] = []
    assigned: set[str] = set(external_refs)
    rename_map: dict[str, list[str]] = {}
    rewritten_rules: list[Any] = []

    def reserve(base: str) -> str:
        if base in assigned:
            part = 2
            while f"{base}-part-{part:02d}" in assigned:
                part += 1
            base = f"{base}-part-{part:02d}"
        assigned.add(base)
        return base

    def emit(provider: Provider, sources: Sequence[str], base: str, policy: str, modifiers: Sequence[str], wrapper: tuple[str, str]) -> None:
        name = reserve(base)
        published = Provider(name, provider.segment, provider.behavior, provider.payload, provider.metadata)
        final.append(published)
        for source in sources:
            rename_map.setdefault(source, []).append(name)
        parts = ["RULE-SET", name]
        if wrapper[0].upper() != "SUB-RULE":
            parts.append(policy)
        parts.extend(modifiers)
        rewritten_rules.append(wrap_ruleset_rule(",".join(parts), wrapper))

    block_by_start = {block.start: block for block in blocks}
    index = 0
    while index < len(rules):
        block = block_by_start.get(index)
        if block is None:
            item = rules[index]
            rewritten_rules.append(rewrite_rules([item], {}, {})[0] if isinstance(item, str) else item)
            index += 1
            continue
        grouped, modifiers = _block_groups(block, rules, providers)
        policy = block.routing[1]
        segment_providers: list[Provider] = []
        for behavior in sorted(grouped, key=BEHAVIOR_ORDER.__getitem__):
            group = grouped[behavior]
            payload: tuple[Any, ...] = tuple(entry for provider in group for entry in provider.payload)
            if behavior in {"domain", "ipcidr"}:
                payload, _stats = dedup_payload(behavior, payload)
            metadata = group[0].metadata.merged_with([provider.metadata for provider in group[1:]])
            behavior_modifiers = tuple(sorted(modifiers[behavior]))
            if metadata is None:
                for provider in group:
                    emit(
                        Provider(provider.name, block.name, provider.behavior, provider.payload, provider.metadata),
                        [provider.name], provider.name, policy, behavior_modifiers, block.wrapper,
                    )
                    segment_providers.append(final[-1])
                continue
            base = f"{block.name}-{BEHAVIOR_LABEL.get(behavior, behavior)}"
            emit(
                Provider(base, block.name, group[0].behavior, payload, metadata),
                [provider.name for provider in group], base, policy, behavior_modifiers, block.wrapper,
            )
            segment_providers.append(final[-1])
        index = block.end

    # Providers that no block consumed keep their own identity: externally
    # referenced payloads must stay intact, and unreferenced providers are
    # retained so validation can report them instead of silently dropping them.
    consumed = {name for block in blocks for name in block.providers}
    for name, provider in providers.items():
        if name in consumed and name not in external_refs:
            continue
        final.append(Provider(name, name, provider.behavior, provider.payload, provider.metadata))
        assigned.add(name)
        rename_map[name] = [name]

    final_behaviors = {provider.name: provider.behavior.value for provider in final}
    rewritten_sub_rules = {
        name: tuple(rewrite_rules(list(members), rename_map, final_behaviors))
        for name, members in semantic.sub_rules.items()
    }
    return OptimizedConfig(
        providers=tuple(final),
        rules=tuple(rewritten_rules),
        sub_rules=rewritten_sub_rules,
        extras=dict(semantic.extras),
        blocks=blocks,
    )
