"""Mihomo rule text layer: tokenizing, expressions, references and rewriting.

Everything here is pure text handling.  Providers, optimization and exporters
share this module so a rule is parsed the same way everywhere.
"""

from collections.abc import Iterator
from dataclasses import dataclass
from typing import Any, Callable

DOMAIN_KINDS = frozenset({"DOMAIN", "DOMAIN-SUFFIX", "DOMAIN-KEYWORD", "DOMAIN-REGEX", "DOMAIN-WILDCARD"})


@dataclass(frozen=True)
class RuleLine:
    raw: str
    kind: str
    parts: tuple[str, ...]

    def as_rule(self) -> str:
        return self.raw


@dataclass(frozen=True)
class RulesetReference:
    provider: str
    policy: str
    modifiers: tuple[str, ...]
    wrapper_kind: str

TARGET_IP_KINDS = frozenset({"IP-CIDR", "IP-CIDR6", "IP-ASN", "GEOIP"})
IPCIDR_RULES = frozenset({"IP-CIDR", "IP-CIDR6"})


def parse_ip_network(rule: str) -> Any | None:
    import ipaddress

    try:
        return ipaddress.ip_network(rule.strip(), strict=False)
    except ValueError:
        return None


def is_target_ip_kind(kind: str) -> bool:
    return kind.upper() in TARGET_IP_KINDS


def ensure_single_no_resolve(parts: list[str]) -> list[str]:
    return [*parts[:2], *(part for part in parts[2:] if part.lower() != "no-resolve"), "no-resolve"]


def iter_all_rules(config: dict[str, Any]) -> Iterator[Any]:
    """Yield top-level rules and every rule in named sub-rules in one pass."""
    yield from config.get("rules", []) or []
    sub_rules = config.get("sub-rules") or {}
    if not isinstance(sub_rules, dict):
        return
    for members in sub_rules.values():
        if isinstance(members, list):
            yield from members


def ruleset_suffix_for_behavior(suffix: tuple[str, ...], behavior: str) -> list[str]:
    """Normalize RULE-SET modifiers for the provider semantic behavior."""
    if behavior == "ipcidr":
        other = [modifier for modifier in suffix if modifier.lower() != "no-resolve"]
        if any(modifier.lower() == "no-resolve" for modifier in suffix):
            other.append("no-resolve")
        return other
    if behavior in {"domain", "classical"}:
        return [modifier for modifier in suffix if modifier.lower() != "no-resolve"]
    return list(suffix)


def split_top_level_commas(text: str) -> list[str]:
    """Split a Mihomo rule without treating commas in expressions or quotes as fields."""
    parts: list[str] = []
    start = 0
    depth = 0
    quote: str | None = None
    escaped = False
    for index, char in enumerate(text):
        if escaped:
            escaped = False
            continue
        if quote:
            if char == "\\":
                escaped = True
            elif char == quote:
                quote = None
            continue
        if char in {"'", '"'}:
            quote = char
        elif char == "(":
            depth += 1
        elif char == ")":
            depth -= 1
            if depth < 0:
                raise SystemExit(f"unbalanced parentheses in rule: {text}")
        elif char == "," and depth == 0:
            parts.append(text[start:index].strip())
            start = index + 1
    if quote:
        raise SystemExit(f"unterminated quote in rule: {text}")
    if depth:
        raise SystemExit(f"unbalanced parentheses in rule: {text}")
    parts.append(text[start:].strip())
    return parts


def strip_balanced_outer_parentheses(text: str) -> tuple[str, bool]:
    value = text.strip()
    if not (value.startswith("(") and value.endswith(")")):
        return value, False
    depth = 0
    quote: str | None = None
    escaped = False
    for index, char in enumerate(value):
        if escaped:
            escaped = False
        elif quote:
            if char == "\\":
                escaped = True
            elif char == quote:
                quote = None
        elif char in {"'", '"'}:
            quote = char
        elif char == "(":
            depth += 1
        elif char == ")":
            depth -= 1
            if depth == 0:
                return (value[1:-1].strip(), True) if index == len(value) - 1 else (value, False)
    # Also validates and gives the caller a useful error for malformed rules.
    split_top_level_commas(value)
    return value, False


def ruleset_parts(expression: str) -> list[str] | None:
    """Return the fields of a direct RULE-SET expression, if that is what it is."""
    inner, _ = strip_balanced_outer_parentheses(expression)
    parts = split_top_level_commas(inner)
    if parts and parts[0].upper() == "RULE-SET":
        if len(parts) < 2 or not parts[1]:
            raise SystemExit(f"RULE-SET is missing a provider name in rule: {expression}")
        return parts
    return None


RuleSetRewrite = Callable[[list[str], bool], "str | None"]


def rewrite_ruleset_expressions(text: str, rewrite: RuleSetRewrite) -> str:
    """Rewrite every RULE-SET expression inside a rule, preserving its structure.

    ``rewrite`` receives the RULE-SET fields and whether the expression was
    parenthesized; returning ``None`` keeps it untouched.  This is the single
    traversal used by reference collection, provider renaming and no-resolve
    normalization, so all three agree on what counts as a RULE-SET expression.
    """
    inner, wrapped = strip_balanced_outer_parentheses(text)
    direct = ruleset_parts(text)
    if direct is not None:
        replacement = rewrite(direct, wrapped)
        return text.strip() if replacement is None else replacement
    parts = split_top_level_commas(inner if wrapped else text)
    rewritten: list[str] = []
    for part in parts:
        _, nested = strip_balanced_outer_parentheses(part)
        rewritten.append(rewrite_ruleset_expressions(part, rewrite) if nested else part)
    result = ",".join(rewritten)
    return f"({result})" if wrapped else result


def find_ruleset_refs(rule: Any) -> list[str]:
    """Find provider names in a rule, including parenthesized Mihomo expressions."""
    if not isinstance(rule, str):
        return []
    references: list[str] = []

    def collect(parts: list[str], _wrapped: bool) -> None:
        references.append(parts[1])
        return None

    rewrite_ruleset_expressions(rule, collect)
    return references


def simple_ruleset_wrapper(rule: Any) -> tuple[list[str], str, str] | None:
    """Return direct RULE-SET parts plus a replaceable wrapper template, if simple."""
    if not isinstance(rule, str):
        return None
    direct = ruleset_parts(rule)
    if direct is not None:
        return direct, "", ""
    parts = split_top_level_commas(rule)
    for index, part in enumerate(parts):
        inner, wrapped = strip_balanced_outer_parentheses(part)
        inner_parts = split_top_level_commas(inner) if wrapped else []
        if wrapped and inner_parts and inner_parts[0].upper() == "RULE-SET":
            direct = ruleset_parts(inner)
            assert direct is not None  # checked above without stripping another layer
            return direct, ",".join(parts[:index]), ",".join(parts[index + 1:])
    return None


def parse_ruleset_reference(rule: Any) -> RulesetReference | None:
    """Parse a simple RULE-SET reference without confusing modifiers for policy."""
    wrapper = simple_ruleset_wrapper(rule)
    if wrapper is None:
        return None
    parts, prefix, suffix = wrapper
    if len(parts) < 2 or not parts[1]:
        raise SystemExit(f"invalid RULE-SET reference: {rule!r}")
    wrapper_kind = prefix.upper() if prefix else "RULE-SET"
    if prefix and prefix.upper() == "SUB-RULE":
        policy = suffix.strip()
        modifiers = tuple(parts[2:])
    elif suffix:
        policy = suffix.strip()
        modifiers = tuple(parts[2:])
    else:
        if len(parts) < 3 or not parts[2]:
            raise SystemExit(f"RULE-SET reference has no policy: {rule!r}")
        policy = parts[2]
        modifiers = tuple(parts[3:])
    unknown = [modifier for modifier in modifiers if modifier.lower() != "no-resolve"]
    if unknown:
        raise SystemExit(
            f"RULE-SET reference has unknown modifier(s) for provider {parts[1]!r}: "
            f"{', '.join(unknown)} in rule {rule!r}"
        )
    if not policy:
        raise SystemExit(f"RULE-SET reference has no policy: {rule!r}")
    return RulesetReference(parts[1], policy, tuple(modifiers), wrapper_kind)


def ruleset_routing_signature(reference: RulesetReference) -> tuple[str, str]:
    return reference.wrapper_kind, reference.policy


def egern_udp_and_ruleset(rule: Any) -> tuple[str, str] | None:
    """Recognize only Mihomo's exact RULE-SET + UDP AND form."""
    if not isinstance(rule, str):
        return None
    parts = split_top_level_commas(rule)
    if len(parts) != 3 or parts[0].upper() != "AND":
        return None
    expression_inner, expression_wrapped = strip_balanced_outer_parentheses(parts[1])
    expression_parts = split_top_level_commas(expression_inner if expression_wrapped else parts[1])
    if len(expression_parts) != 2:
        return None
    ruleset = ruleset_parts(expression_parts[0])
    network_inner, network_wrapped = strip_balanced_outer_parentheses(expression_parts[1])
    network = split_top_level_commas(network_inner if network_wrapped else expression_parts[1])
    if (
        ruleset is None
        or len(ruleset) != 2
        or len(network) != 2
        or network[0].upper() != "NETWORK"
        or network[1].upper() != "UDP"
    ):
        return None
    return ruleset[1], parts[2]


def parse_egern_network_rule(rule: Any) -> tuple[str, str] | None:
    """Recognize the conservative top-level/sub-rule NETWORK subset."""
    if not isinstance(rule, str):
        return None
    parts = split_top_level_commas(rule)
    if len(parts) != 3 or parts[0].upper() != "NETWORK" or parts[1].upper() not in {"UDP", "TCP"} or not parts[2]:
        return None
    return parts[1].lower(), parts[2]


def parse_egern_sub_rule_members(members: Any) -> list[tuple[str, str]] | None:
    """Parse the conservative NETWORK/MATCH subset used by Egern expansion."""
    if not isinstance(members, list):
        return None
    parsed: list[tuple[str, str]] = []
    for member in members:
        if not isinstance(member, str):
            return None
        network = parse_egern_network_rule(member)
        parts = split_top_level_commas(member)
        if network is not None:
            parsed.append(network)
        elif len(parts) == 2 and parts[0].upper() == "MATCH" and parts[1]:
            parsed.append(("match", parts[1]))
        else:
            return None
    return parsed


def wrap_ruleset_rule(rule: str, signature: tuple[str, str]) -> str:
    prefix, suffix = signature
    if not prefix and not suffix:
        return rule
    return ",".join(field for field in (prefix, f"({rule})", suffix) if field)


def parse_rule(raw: str) -> RuleLine:
    parts = tuple(split_top_level_commas(raw))
    kind = parts[0].upper() if parts else ""
    return RuleLine(raw=raw, kind=kind, parts=parts)


def rule_policy(raw: Any) -> str | None:
    """Return a rule's routing policy using the shared Mihomo parser."""
    if not isinstance(raw, str):
        return None
    try:
        reference = parse_ruleset_reference(raw)
    except SystemExit:
        reference = None
    if reference is not None:
        return reference.policy
    parsed = parse_rule(raw)
    parts = parsed.parts
    if parsed.kind == "MATCH" and len(parts) == 2:
        return parts[1]
    if parsed.kind in {
        "DOMAIN", "DOMAIN-SUFFIX", "DOMAIN-KEYWORD", "DOMAIN-REGEX", "DOMAIN-WILDCARD",
        "IP-CIDR", "IP-CIDR6", "IP-ASN", "GEOIP", "NETWORK", "PROCESS-NAME", "PROCESS-PATH",
        "PROCESS-PATH-REGEX", "DST-PORT", "SRC-PORT", "SRC-IP-CIDR", "SRC-IP-ASN",
    } and len(parts) >= 3:
        return parts[2] if parts[2].lower() != "no-resolve" else None
    if parsed.kind in {"AND", "OR", "NOT"}:
        candidates = [part.strip("()") for part in parts[1:] if part.strip("()")]
        for candidate in reversed(candidates):
            if candidate.lower() != "no-resolve" and not candidate.upper().startswith(("RULE-SET,", "NETWORK,", "DOMAIN,")):
                return candidate
    return None


def normalize(rule: str) -> str:
    return ",".join(split_top_level_commas(rule))


def source_domain_value(rule: RuleLine) -> str | None:
    if len(rule.parts) != 2:
        return None
    value = rule.parts[1]
    if rule.kind == "DOMAIN":
        return value
    if rule.kind == "DOMAIN-SUFFIX":
        return f"+.{value.lstrip('.')}"
    return None


def validate_source_domain_value(rule: RuleLine, converted: str) -> None:
    value = rule.parts[1]
    if rule.kind == "DOMAIN":
        expected = value
    elif rule.kind == "DOMAIN-SUFFIX":
        expected = f"+.{value.lstrip('.')}"
    else:
        return
    if converted != expected:
        raise SystemExit(
            f"{rule.raw}: domain conversion mismatch; got={converted!r} expected={expected!r}"
        )


def source_ip_value(rule: RuleLine) -> str | None:
    if len(rule.parts) != 2:
        return None
    return rule.parts[1] if rule.kind in IPCIDR_RULES else None


def _renamed_ruleset(
    parts: list[str], wrapped: bool, replacements: dict[str, list[str]], behaviors: dict[str, str]
) -> str | None:
    """Expand one RULE-SET reference into its generated provider variants."""
    name = parts[1]
    names = replacements.get(name)
    if not names:
        return None
    try:
        reference = parse_ruleset_reference(",".join(["RULE-SET", *parts[1:]]))
        policy = reference.policy if reference is not None else None
        suffix = reference.modifiers if reference is not None else tuple(parts[2:])
    except SystemExit:
        policy = None
        suffix = tuple(parts[2:])
    variants = [
        ",".join(["RULE-SET", generated, *([policy] if policy else []), *ruleset_suffix_for_behavior(suffix, behaviors[generated])])
        for generated in names
    ]
    if len(variants) == 1:
        return f"({variants[0]})" if wrapped else variants[0]
    # A provider split is a union.  Within a boolean expression it must remain
    # one predicate, rather than copying its containing AND/NOT/etc. rule.
    rewritten = "OR,(" + ",".join(f"({variant})" for variant in variants) + ")"
    return f"({rewritten})" if wrapped else rewritten


def rewrite_rules(rules: Any, replacements: dict[str, list[str]], behaviors: dict[str, str]) -> list[Any]:
    """Point every rule at the providers generated for its source provider."""
    output: list[Any] = []
    for item in rules:
        if not isinstance(item, str):
            output.append(item)
            continue
        wrapper = simple_ruleset_wrapper(item)
        if wrapper is not None and wrapper[0][1] in replacements:
            parts, prefix, suffix = wrapper
            reference = parse_ruleset_reference(item)
            if reference is None:
                raise ValueError(f"invalid ruleset reference: {item}")
            for name in replacements[parts[1]]:
                if prefix.upper() == "SUB-RULE":
                    nested = ",".join(["RULE-SET", name, *ruleset_suffix_for_behavior(tuple(parts[2:]), behaviors[name])])
                else:
                    nested = ",".join(["RULE-SET", name, reference.policy, *ruleset_suffix_for_behavior(reference.modifiers, behaviors[name])])
                output.append(",".join(part for part in (prefix, f"({nested})" if prefix or suffix else nested, suffix) if part))
            continue
        output.append(
            rewrite_ruleset_expressions(
                item, lambda parts, wrapped: _renamed_ruleset(parts, wrapped, replacements, behaviors)
            )
        )
    return output
