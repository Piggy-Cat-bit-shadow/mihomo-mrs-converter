"""Unified provider consolidation, canonical naming and final optimization."""

from .pipeline import *  # shared typed rules, artifacts and validation primitives
from .pipeline import _rewrite_expression, _ruleset_parts_in_expression

def canonicalize_dedup_provider_names(
    config: dict[str, Any],
    options: BuildOptions,
) -> tuple[dict[str, Any], dict[str, str]]:
    """Give all providers in each merged-dedup logical rule block one segment ID."""
    suite = "merged-dedup"
    suite_root = options.dist / suite
    providers = config["rule-providers"]
    provider_segments: dict[str, tuple[int, str, int]] = {}
    segment_id = 0
    rule_index = 0

    while rule_index < len(config["rules"]):
        wrapper = simple_ruleset_wrapper(config["rules"][rule_index])
        if wrapper is None or wrapper[0][1] not in providers:
            rule_index += 1
            continue
        reference = parse_ruleset_reference(config["rules"][rule_index])
        assert reference is not None
        signature = ruleset_routing_signature(reference)
        block: list[tuple[str, tuple[str, ...], tuple[str, str], dict[str, Any]]] = []
        next_index = rule_index
        while next_index < len(config["rules"]):
            next_wrapper = simple_ruleset_wrapper(config["rules"][next_index])
            if next_wrapper is None or next_wrapper[0][1] not in providers:
                break
            provider = providers[next_wrapper[0][1]]
            next_reference = parse_ruleset_reference(config["rules"][next_index])
            assert next_reference is not None
            if ruleset_routing_signature(next_reference) != signature:
                break
            if provider.get("behavior") not in {"domain", "ipcidr", "classical"}:
                break
            block.append((next_wrapper[0][1], tuple(next_wrapper[0][2:]), signature, provider))
            next_index += 1

        if not block:
            rule_index += 1
            continue
        segment_id += 1
        behavior_counts: dict[str, int] = {}
        for name, _, _, provider in block:
            behavior = provider["behavior"]
            if name in provider_segments:
                continue
            part = behavior_counts.get(behavior, 0) + 1
            behavior_counts[behavior] = part
            provider_segments[name] = (segment_id, behavior, part)
        rule_index = next_index

    if not provider_segments:
        return config, {}

    used_names: set[str] = set()
    renamed: dict[str, str] = {}
    for old_name, (current_segment, behavior, part) in provider_segments.items():
        label = "ip" if behavior == "ipcidr" else behavior
        base = f"merged-segment-{current_segment:02d}-{label}"
        candidate = base if part == 1 else f"{base}-part-{part:02d}"
        if candidate in used_names or (candidate in providers and candidate != old_name):
            collision_part = part
            while candidate in used_names or (candidate in providers and candidate != old_name):
                collision_part += 1
                candidate = f"{base}-part-{collision_part:02d}"
        used_names.add(candidate)
        renamed[old_name] = candidate

    new_providers: dict[str, dict[str, Any]] = {}
    for old_name, provider in providers.items():
        new_name = renamed.get(old_name, old_name)
        if new_name == old_name:
            new_providers[new_name] = provider
            continue
        new_provider = dict(provider)
        old_artifact = generated_artifact_path(options.dist, provider)
        old_source = source_path_for_provider(options.dist, provider)
        new_artifact: Path | None = None
        if old_artifact is not None and old_artifact.exists() and old_artifact.parent.is_relative_to(suite_root):
            new_artifact = old_artifact.with_name(f"{new_name}{old_artifact.suffix}")
            if new_artifact != old_artifact:
                copy_file(old_artifact, new_artifact)
                old_artifact.unlink(missing_ok=True)
            relative = new_artifact.relative_to(options.dist)
            new_provider["url"] = public_url(options.base_url, "dist", *relative.parts)
        if old_source is not None and old_source.exists() and old_source.parent.is_relative_to(suite_root / "source"):
            new_source = old_source.with_name(f"{new_name}.yaml")
            if new_source != old_source:
                copy_file(old_source, new_source)
                old_source.unlink(missing_ok=True)
        new_provider["path"] = provider_path_for_suite(new_name, new_provider, suite)
        new_providers[new_name] = new_provider

    def canonical_rule(item: Any) -> Any:
        if not isinstance(item, str):
            return item
        wrapper = simple_ruleset_wrapper(item)
        if wrapper is None or wrapper[0][1] not in renamed:
            return item
        parts, prefix, suffix = wrapper
        rewritten = ",".join(["RULE-SET", renamed[parts[1]], *parts[2:]])
        return wrap_ruleset_rule(rewritten, (prefix, suffix))

    rewritten_rules: list[Any] = []
    rule_index = 0
    while rule_index < len(config["rules"]):
        item = config["rules"][rule_index]
        wrapper = simple_ruleset_wrapper(item)
        if wrapper is None or wrapper[0][1] not in renamed:
            rewritten_rules.append(canonical_rule(item))
            rule_index += 1
            continue
        reference = parse_ruleset_reference(item)
        assert reference is not None
        signature = ruleset_routing_signature(reference)
        block: list[Any] = []
        next_index = rule_index
        while next_index < len(config["rules"]):
            next_wrapper = simple_ruleset_wrapper(config["rules"][next_index])
            if (
                next_wrapper is None
                or next_wrapper[0][1] not in renamed
                or ruleset_routing_signature(parse_ruleset_reference(config["rules"][next_index])) != signature
            ):
                break
            block.append(config["rules"][next_index])
            next_index += 1
        block.sort(
            key=lambda rule: BEHAVIOR_ORDER[providers[simple_ruleset_wrapper(rule)[0][1]]["behavior"]]
        )
        rewritten_rules.extend(canonical_rule(rule) for rule in block)
        rule_index = next_index

    ordered_names: list[str] = []
    for rule in rewritten_rules:
        for name in find_ruleset_refs(rule):
            if name in new_providers and name not in ordered_names:
                ordered_names.append(name)
    ordered_names.extend(name for name in new_providers if name not in ordered_names)
    ordered_providers = {name: new_providers[name] for name in ordered_names}
    return {**config, "rule-providers": ordered_providers, "rules": rewritten_rules}, renamed


def apply_segment_name_mapping(
    config: dict[str, Any], options: BuildOptions, mapping: dict[str, str]
) -> dict[str, Any]:
    """Rename canonical segments only after merge/dedup has completed."""
    if not mapping:
        return config
    suite = "merged-dedup"
    suite_root = options.dist / suite
    renames: dict[str, str] = {}
    for old_name in config["rule-providers"]:
        match = re.match(r"^(merged-segment-\d+)(-.+)$", old_name)
        if match and match.group(1) in mapping:
            renames[old_name] = mapping[match.group(1)] + match.group(2)
    new_names = set(config["rule-providers"]) - set(renames) | set(renames.values())
    if len(new_names) != len(config["rule-providers"]):
        raise SystemExit("segment-names.yaml creates a provider name collision")
    for old, new in renames.items():
        if new in config["rule-providers"] and new not in renames:
            raise SystemExit(f"segment-names.yaml creates a provider name collision: {new}")

    def rewrite_rule(rule: Any) -> Any:
        if not isinstance(rule, str):
            return rule
        direct = _ruleset_parts_in_expression(rule)
        if direct is not None:
            renamed = renames.get(direct[1], direct[1])
            rewritten = ",".join(["RULE-SET", renamed, *direct[2:]])
            return f"({rewritten})" if strip_balanced_outer_parentheses(rule)[1] else rewritten
        inner, wrapped = strip_balanced_outer_parentheses(rule)
        parts = split_top_level_commas(inner if wrapped else rule)
        rewritten = []
        for part in parts:
            rewritten.append(rewrite_rule(part) if strip_balanced_outer_parentheses(part)[1] else part)
        result = ",".join(rewritten)
        return f"({result})" if wrapped else result

    providers: dict[str, dict[str, Any]] = {}
    for old, provider in config["rule-providers"].items():
        new = renames.get(old, old)
        updated = dict(provider)
        artifact = generated_artifact_path(options.dist, provider)
        source = source_path_for_provider(options.dist, provider)
        if new != old and artifact is not None and artifact.exists():
            destination = artifact.with_name(new + artifact.suffix)
            copy_file(artifact, destination)
            artifact.unlink()
            updated["url"] = public_url(options.base_url, "dist", *destination.relative_to(options.dist).parts)
        if new != old and source is not None and source.exists():
            destination = source.with_name(new + source.suffix)
            copy_file(source, destination)
            source.unlink()
        updated["path"] = provider_path_for_suite(new, updated, suite)
        providers[new] = updated
    return {**config, "rule-providers": providers, "rules": [rewrite_rule(rule) for rule in config["rules"]]}


def build_dedup_config(
    config: dict[str, Any],
    options: BuildOptions,
    require_no_orphans: bool = True,
) -> tuple[dict[str, Any], dict[str, DedupStats]]:
    suite = "merged-dedup"
    suite_root = options.dist / suite
    dedup_providers: dict[str, dict[str, Any]] = {}
    stats_by_provider: dict[str, DedupStats] = {}

    for name, provider in config["rule-providers"].items():
        behavior = provider.get("behavior")
        if behavior not in {"domain", "ipcidr"}:
            copy_provider_artifacts_to_suite(name, provider, suite, options.dist)
            dedup_providers[name] = rewrite_provider_for_suite(
                name,
                provider,
                suite,
                options.base_url,
            )
            continue

        source = source_path_for_provider(options.dist, provider)
        if source is None:
            copy_provider_artifacts_to_suite(name, provider, suite, options.dist)
            dedup_providers[name] = rewrite_provider_for_suite(
                name,
                provider,
                suite,
                options.base_url,
            )
            continue

        payload = read_yaml_payload(source)
        if behavior == "domain":
            optimized, stats = dedup_domain_payload(payload)
        else:
            optimized, stats = dedup_ipcidr_payload(payload)
        stats_by_provider[name] = stats

        source_dir = provider_source_dir(behavior)
        source_path = suite_root / "source" / source_dir / f"{name}.yaml"
        write_yaml_payload(source_path, optimized)

        if options.mihomo:
            artifact_path = suite_root / source_dir / f"{name}.mrs"
            convert_source_to_mrs(options.mihomo, behavior, source_path, artifact_path)
            fmt = "mrs"
            url = public_url(options.base_url, "dist", suite, source_dir, f"{name}.mrs")
            path = f"./ruleset/{suite}/{name}.mrs"
        else:
            fmt = "yaml"
            url = public_url(options.base_url, "dist", suite, "source", source_dir, f"{name}.yaml")
            path = f"./ruleset/{suite}/{name}.yaml"

        dedup_providers[name] = make_provider(
            behavior,
            fmt,
            url,
            path,
            provider,
        )

    dedup_config = {
        **{key: value for key, value in config.items() if key not in {"rule-providers", "rules"}},
        "rule-providers": dedup_providers,
        "rules": config["rules"],
    }
    dedup_config = consolidate_segment_behavior_providers(dedup_config, options)
    dedup_config, renamed_providers = canonicalize_dedup_provider_names(dedup_config, options)
    stats_by_provider = {
        renamed_providers.get(name, name): stats
        for name, stats in stats_by_provider.items()
    }
    output = suite_root / "generated" / "mihomo-rules.yaml"
    validate_generated_config(options.dist, dedup_config, require_no_orphans=require_no_orphans)
    write_yaml_atomic(output, dedup_config)
    options.final_payloads = {}
    for name, provider in dedup_config["rule-providers"].items():
        payload_path = source_path_for_provider(options.dist, provider)
        if payload_path is None:
            payload_path = generated_artifact_path(options.dist, provider)
        if payload_path is not None and payload_path.exists():
            options.final_payloads[name] = read_yaml_payload(payload_path)
    return dedup_config, stats_by_provider


def rewrite_rules(
    rules: list[Any],
    replacements: dict[str, list[str]],
    provider_behaviors: dict[str, str],
) -> list[Any]:
    rewritten: list[Any] = []
    for item in rules:
        if not isinstance(item, str):
            rewritten.append(item)
            continue
        wrapper = simple_ruleset_wrapper(item)
        if wrapper is not None and wrapper[0][1] in replacements:
            parts, prefix, suffix = wrapper
            for replacement in replacements[parts[1]]:
                nested = ",".join(["RULE-SET", replacement, *ruleset_suffix_for_behavior(tuple(parts[2:]), provider_behaviors[replacement])])
                if prefix or suffix:
                    fields = [field for field in (prefix, f"({nested})", suffix) if field]
                    rewritten.append(",".join(fields))
                else:
                    rewritten.append(nested)
            continue
        rewritten.append(_rewrite_expression(item, replacements, provider_behaviors))
    return rewritten


def write_merged_ruleset(
    segment_index: int,
    behavior: str,
    suffix: tuple[str, ...],
    generated_names: list[str],
    generated_providers: dict[str, dict[str, Any]],
    source_payloads: dict[str, list[str]],
    options: BuildOptions,
    used_names: set[str],
    used_paths: set[str],
) -> tuple[str | None, dict[str, Any] | None]:
    mergeable = [
        name
        for name in generated_names
        if name in source_payloads and generated_providers[name]["behavior"] == behavior
    ]
    if len(mergeable) < 2:
        return None, None
    source_providers = [generated_providers[name] for name in mergeable]
    if not merge_metadata_compatible(source_providers):
        return None, None

    suffix_name = "ip" if behavior == "ipcidr" else behavior
    merged_name = reserve_provider_name(f"merged-segment-{segment_index:02d}", suffix_name, used_names)
    payload: list[str] = []
    expected = Counter()
    for name in mergeable:
        payload.extend(source_payloads[name])
        expected.update(source_payloads[name])
    validate_rule_counts(merged_name, expected, Counter(payload))

    source_dir = "ipcidr" if behavior == "ipcidr" else "domain"
    source_path = options.dist / "merged" / "source" / source_dir / f"{merged_name}.yaml"
    write_yaml_payload(source_path, payload)
    if options.mihomo:
        mrs_path = options.dist / "merged" / source_dir / f"{merged_name}.mrs"
        convert_source_to_mrs(options.mihomo, behavior, source_path, mrs_path)
        fmt = "mrs"
        url = public_url(options.base_url, "dist/merged", source_dir, f"{merged_name}.mrs")
        path = f"./ruleset/{merged_name}.mrs"
    else:
        fmt = "yaml"
        url = public_url(options.base_url, "dist/merged/source", source_dir, f"{merged_name}.yaml")
        path = f"./ruleset/{merged_name}.yaml"
    reserve_path(path, used_paths)
    provider = make_merged_provider(behavior, fmt, url, path, source_providers)
    return merged_name, provider


def build_merged_segment_rules(
    segment_index: int,
    parts_list: list[list[str]],
    replacements: dict[str, list[str]],
    generated_providers: dict[str, dict[str, Any]],
    provider_behaviors: dict[str, str],
    source_payloads: dict[str, list[str]],
    options: BuildOptions,
    used_names: set[str],
    used_paths: set[str],
) -> tuple[list[str], dict[str, dict[str, Any]], set[str]]:
    expanded_names = [
        generated_name
        for parts in parts_list
        for generated_name in replacements[parts[1]]
    ]
    merged_providers: dict[str, dict[str, Any]] = {}
    replaced: set[str] = set()
    merged_rules: list[str] = []

    groups: dict[tuple[str, tuple[str, ...]], list[str]] = {}
    for parts in parts_list:
        modifiers = tuple(parts[2:])
        for generated_name in replacements[parts[1]]:
            behavior = provider_behaviors[generated_name]
            key = (behavior, tuple(ruleset_suffix_for_behavior(modifiers, behavior)))
            groups.setdefault(key, []).append(generated_name)

    merged_by_group: dict[tuple[str, tuple[str, ...]], str] = {}
    for (behavior, modifiers), names in groups.items():
        merged_name, provider = write_merged_ruleset(
            segment_index,
            behavior,
            modifiers,
            names,
            generated_providers,
            source_payloads,
            options,
            used_names,
            used_paths,
        )
        if merged_name and provider:
            merged_providers[merged_name] = provider
            merged_by_group[(behavior, modifiers)] = merged_name
            replaced.update(
                name
                for name in names
                if name in source_payloads and generated_providers[name]["behavior"] == behavior
            )

    emitted_merged: set[tuple[str, tuple[str, ...]]] = set()
    for parts in parts_list:
        original_modifiers = tuple(parts[2:])
        for generated_name in replacements[parts[1]]:
            behavior = provider_behaviors[generated_name]
            modifiers = tuple(ruleset_suffix_for_behavior(original_modifiers, behavior))
            group = (behavior, modifiers)
            merged_name = merged_by_group.get(group)
            if merged_name:
                if group in emitted_merged:
                    continue
                emitted_merged.add(group)
                merged_rules.append(",".join(["RULE-SET", merged_name, *modifiers]))
                continue
            merged_rules.append(",".join(["RULE-SET", generated_name, *modifiers]))

    return merged_rules, merged_providers, replaced


def build_merged_config(
    rules: list[Any],
    replacements: dict[str, list[str]],
    generated_providers: dict[str, dict[str, Any]],
    provider_behaviors: dict[str, str],
    source_payloads: dict[str, list[str]],
    options: BuildOptions,
) -> dict[str, Any]:
    used_names = set(generated_providers)
    used_paths: set[str] = set()
    merged_providers: dict[str, dict[str, Any]] = {}
    merged_rules: list[Any] = []
    used_provider_names: list[str] = []
    seen_provider_names: set[str] = set()
    index = 0
    segment_index = 1

    def mark_used(name: str) -> None:
        if name not in seen_provider_names:
            seen_provider_names.add(name)
            used_provider_names.append(name)

    while index < len(rules):
        wrapper = simple_ruleset_wrapper(rules[index])
        if wrapper is None or wrapper[0][1] not in replacements:
            rewritten = _rewrite_expression(rules[index], replacements, provider_behaviors) if isinstance(rules[index], str) else rules[index]
            merged_rules.append(rewritten)
            for name in find_ruleset_refs(rewritten):
                if name in generated_providers:
                    mark_used(name)
            index += 1
            continue

        parts = wrapper[0]
        reference = parse_ruleset_reference(rules[index])
        assert reference is not None
        routing_signature = ruleset_routing_signature(reference)
        wrapper_signature = (wrapper[1], wrapper[2])
        segment = [parts]
        index += 1
        while index < len(rules):
            next_wrapper = simple_ruleset_wrapper(rules[index])
            if (
                next_wrapper is None
                or next_wrapper[0][1] not in replacements
                or ruleset_routing_signature(parse_ruleset_reference(rules[index])) != routing_signature
            ):
                break
            segment.append(next_wrapper[0])
            index += 1

        segment_rules, segment_providers, replaced = build_merged_segment_rules(
            segment_index,
            segment,
            replacements,
            generated_providers,
            provider_behaviors,
            source_payloads,
            options,
            used_names,
            used_paths,
        )
        segment_index += 1
        merged_rules.extend(wrap_ruleset_rule(rule, wrapper_signature) for rule in segment_rules)
        merged_providers.update(segment_providers)
        for rule in segment_rules:
            rule_parts = ruleset_parts(rule)
            if rule_parts is not None:
                mark_used(rule_parts[1])
        for parts_item in segment:
            for generated_name in replacements[parts_item[1]]:
                if generated_name not in replaced:
                    mark_used(generated_name)

    for name in used_provider_names:
        if name not in merged_providers:
            provider = generated_providers[name]
            reserve_path(provider["path"], used_paths)
            merged_providers[name] = provider

    return {
        "rule-providers": merged_providers,
        "rules": merged_rules,
    }


def consolidate_segment_behavior_providers(
    config: dict[str, Any], options: BuildOptions
) -> dict[str, Any]:
    """Merge compatible same-behavior providers inside one routing block.

    A block is bounded by any non-RULE-SET rule or by a different routing
    signature, so this cannot cross a real priority barrier.  The first
    provider remains the stable identity and receives the union payload.
    """
    suite = "merged-dedup"
    providers = dict(config["rule-providers"])
    rules = list(config["rules"])
    replacements: dict[str, str] = {}

    def payload_for(provider: dict[str, Any]) -> tuple[Path | None, list[str]]:
        source = source_path_for_provider(options.dist, provider)
        if source is None:
            source = generated_artifact_path(options.dist, provider)
        if source is None or not source.exists():
            return None, []
        return source, read_yaml_payload(source)

    def merge_group(names: list[str], behavior: str) -> None:
        if len(names) < 2:
            return
        source_providers = [providers[name] for name in names]
        if not merge_metadata_compatible(source_providers):
            return
        first = names[0]
        first_provider = source_providers[0]
        paths_and_payloads = [payload_for(provider) for provider in source_providers]
        if any(path is None for path, _payload in paths_and_payloads):
            return
        payload = [item for _path, values in paths_and_payloads for item in values]
        if behavior == "domain":
            payload = dedup_domain_payload(payload)[0]
        elif behavior == "ipcidr":
            payload = dedup_ipcidr_payload(payload)[0]

        first_source, _first_payload = paths_and_payloads[0]
        first_artifact = generated_artifact_path(options.dist, first_provider)
        if first_source is None or first_artifact is None:
            return
        if behavior in {"domain", "ipcidr"}:
            write_yaml_payload(first_source, payload)
            if first_provider.get("format") == "mrs":
                if not options.mihomo:
                    return
                convert_source_to_mrs(options.mihomo, behavior, first_source, first_artifact)
            else:
                if first_source != first_artifact:
                    copy_file(first_source, first_artifact)
        else:
            write_yaml_payload(first_artifact, payload)

        providers[first] = make_merged_provider(
            behavior,
            first_provider.get("format", "yaml"),
            first_provider["url"],
            first_provider["path"],
            source_providers,
        )
        for name, provider in zip(names[1:], source_providers[1:]):
            replacements[name] = first
            old_source = source_path_for_provider(options.dist, provider)
            old_artifact = generated_artifact_path(options.dist, provider)
            if old_source is not None and old_source != first_source:
                old_source.unlink(missing_ok=True)
            if old_artifact is not None and old_artifact != first_artifact:
                old_artifact.unlink(missing_ok=True)
            providers.pop(name, None)

    index = 0
    while index < len(rules):
        wrapper = simple_ruleset_wrapper(rules[index])
        if wrapper is None or wrapper[0][1] not in providers:
            index += 1
            continue
        reference = parse_ruleset_reference(rules[index])
        assert reference is not None
        signature = ruleset_routing_signature(reference)
        block: list[str] = []
        next_index = index
        while next_index < len(rules):
            candidate = simple_ruleset_wrapper(rules[next_index])
            if candidate is None or candidate[0][1] not in providers:
                break
            candidate_reference = parse_ruleset_reference(rules[next_index])
            assert candidate_reference is not None
            if ruleset_routing_signature(candidate_reference) != signature:
                break
            block.append(candidate[0][1])
            next_index += 1
        for behavior in ("domain", "classical", "ipcidr"):
            names: list[str] = []
            for name in block:
                if name in providers and providers[name].get("behavior") == behavior and name not in names:
                    names.append(name)
            merge_group(names, behavior)
        index = next_index

    def rewrite(item: Any) -> Any:
        if not isinstance(item, str):
            return item
        direct = _ruleset_parts_in_expression(item)
        if direct is not None:
            name = replacements.get(direct[1], direct[1])
            rewritten = ",".join(["RULE-SET", name, *direct[2:]])
            return f"({rewritten})" if strip_balanced_outer_parentheses(item)[1] else rewritten
        inner, wrapped = strip_balanced_outer_parentheses(item)
        parts = split_top_level_commas(inner if wrapped else item)
        rewritten = ",".join(rewrite(part) if strip_balanced_outer_parentheses(part)[1] else part for part in parts)
        return f"({rewritten})" if wrapped else rewritten

    rewritten_rules: list[Any] = []
    index = 0
    while index < len(rules):
        wrapper = simple_ruleset_wrapper(rules[index])
        if wrapper is None or (wrapper[0][1] not in providers and wrapper[0][1] not in replacements):
            rewritten_rules.append(rewrite(rules[index]))
            index += 1
            continue
        reference = parse_ruleset_reference(rules[index])
        assert reference is not None
        signature = ruleset_routing_signature(reference)
        block: list[str] = []
        next_index = index
        while next_index < len(rules):
            candidate = simple_ruleset_wrapper(rules[next_index])
            if candidate is None or (candidate[0][1] not in providers and candidate[0][1] not in replacements):
                break
            candidate_reference = parse_ruleset_reference(rules[next_index])
            assert candidate_reference is not None
            if ruleset_routing_signature(candidate_reference) != signature:
                break
            block.append(candidate[0][1])
            next_index += 1
        seen: set[tuple[str, str]] = set()
        for offset, name in enumerate(block):
            target = replacements.get(name, name)
            behavior = providers.get(target, {}).get("behavior", "")
            key = (target, behavior)
            if key in seen:
                continue
            seen.add(key)
            rewritten_rules.append(rewrite(rules[index + offset]))
        index = next_index

    return {**config, "rule-providers": providers, "rules": rewritten_rules}

