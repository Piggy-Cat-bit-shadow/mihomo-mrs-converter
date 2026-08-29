#!/usr/bin/env python3
import argparse
import hashlib
import os
import shutil
import ssl
import subprocess
import sys
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

try:
    import certifi
except ImportError:  # pragma: no cover - optional runtime fallback
    certifi = None


DOMAIN_RULES = {"DOMAIN", "DOMAIN-SUFFIX"}
IPCIDR_RULES = {"IP-CIDR", "IP-CIDR6"}


@dataclass(frozen=True)
class RuleLine:
    raw: str
    kind: str
    parts: tuple[str, ...]


@dataclass
class ProviderResult:
    original_name: str
    generated_names: list[str]
    providers: dict[str, dict[str, Any]]
    original_rules: set[str]
    rebuilt_rules: set[str]


def load_yaml(path: Path) -> dict[str, Any]:
    data = yaml.safe_load(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise SystemExit(f"{path} must be a YAML mapping")
    allowed = {"rule-providers", "rules"}
    extra = sorted(set(data) - allowed)
    if extra:
        raise SystemExit(
            f"{path} contains unsupported top-level keys: {', '.join(extra)}"
        )
    return data


def fetch_text(url: str, cache_dir: Path) -> str:
    cache_dir.mkdir(parents=True, exist_ok=True)
    cache_key = hashlib.sha256(url.encode("utf-8")).hexdigest()
    cached = cache_dir / f"{cache_key}.txt"
    if cached.exists():
        return cached.read_text(encoding="utf-8")

    request = urllib.request.Request(url, headers={"User-Agent": "mihomo-mrs-converter"})
    context = (
        ssl.create_default_context(cafile=certifi.where())
        if certifi is not None
        else ssl.create_default_context()
    )
    with urllib.request.urlopen(request, timeout=60, context=context) as response:
        body = response.read().decode("utf-8-sig")
    cached.write_text(body, encoding="utf-8")
    return body


def payload_from_remote(text: str) -> list[str]:
    parsed = yaml.safe_load(text)
    if isinstance(parsed, dict):
        for key in ("payload", "rules"):
            value = parsed.get(key)
            if isinstance(value, list):
                return [str(item).strip() for item in value if str(item).strip()]
    if isinstance(parsed, list):
        return [str(item).strip() for item in parsed if str(item).strip()]

    lines: list[str] = []
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        lines.append(stripped)
    return lines


def parse_rule(raw: str) -> RuleLine:
    parts = tuple(part.strip() for part in raw.split(","))
    kind = parts[0].upper() if parts else ""
    return RuleLine(raw=raw, kind=kind, parts=parts)


def normalize(rule: str) -> str:
    return ",".join(part.strip() for part in rule.split(","))


def source_domain_value(rule: RuleLine) -> str | None:
    if len(rule.parts) < 2:
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
    if len(rule.parts) < 2:
        return None
    return rule.parts[1] if rule.kind in IPCIDR_RULES else None


def write_yaml_payload(path: Path, rules: list[str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        yaml.safe_dump({"payload": rules}, allow_unicode=True, sort_keys=False),
        encoding="utf-8",
    )


def write_text_payload(path: Path, rules: list[str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(rules) + "\n", encoding="utf-8")


def convert_source_to_mrs(mihomo: str, behavior: str, source: Path, output: Path) -> None:
    output.parent.mkdir(parents=True, exist_ok=True)
    subprocess.run(
        [
            mihomo,
            "convert-ruleset",
            behavior,
            "yaml",
            str(source),
            str(output),
        ],
        check=True,
    )


def public_url(base_url: str, *parts: str) -> str:
    return "/".join([base_url.rstrip("/"), *[part.strip("/") for part in parts]])


def provider_interval(provider: dict[str, Any]) -> int | None:
    interval = provider.get("interval")
    return interval if isinstance(interval, int) else None


def make_provider(
    behavior: str,
    fmt: str,
    url: str,
    path: str,
    interval: int | None,
) -> dict[str, Any]:
    result: dict[str, Any] = {
        "type": "http",
        "behavior": behavior,
        "format": fmt,
        "url": url,
        "path": path,
    }
    if interval is not None:
        result["interval"] = interval
    return result


def split_provider_name(name: str, suffix: str, reserved_names: set[str]) -> str:
    candidate = f"{name}-{suffix}"
    if candidate not in reserved_names:
        return candidate
    return f"{name}-mrs-{suffix}"


def process_provider(
    name: str,
    provider: dict[str, Any],
    dist: Path,
    cache_dir: Path,
    base_url: str,
    mihomo: str | None,
    reserved_names: set[str],
) -> ProviderResult:
    url = provider.get("url")
    behavior = provider.get("behavior")
    if provider.get("type") != "http" or not isinstance(url, str):
        raise SystemExit(f"{name}: only http providers with url are supported")
    if behavior not in {"classical", "domain", "ipcidr"}:
        raise SystemExit(f"{name}: unsupported behavior {behavior!r}")

    interval = provider_interval(provider)
    remote_rules = [normalize(rule) for rule in payload_from_remote(fetch_text(url, cache_dir))]
    parsed = [parse_rule(rule) for rule in remote_rules]
    original_set = set(remote_rules)

    generated: dict[str, dict[str, Any]] = {}
    generated_names: list[str] = []
    rebuilt: set[str] = set()

    if behavior == "domain":
        source_values = [rule.raw for rule in parsed]
        source_path = dist / "source" / "domain" / f"{name}.yaml"
        mrs_path = dist / "domain" / f"{name}.mrs"
        write_yaml_payload(source_path, source_values)
        if mihomo:
            convert_source_to_mrs(mihomo, "domain", source_path, mrs_path)
        generated[name] = make_provider(
            "domain",
            "mrs",
            public_url(base_url, "dist/domain", f"{name}.mrs"),
            f"./ruleset/{name}.mrs",
            interval,
        )
        generated_names.append(name)
        rebuilt = original_set

    elif behavior == "ipcidr":
        source_values = [rule.raw for rule in parsed]
        source_path = dist / "source" / "ipcidr" / f"{name}.yaml"
        mrs_path = dist / "ipcidr" / f"{name}.mrs"
        write_yaml_payload(source_path, source_values)
        if mihomo:
            convert_source_to_mrs(mihomo, "ipcidr", source_path, mrs_path)
        generated[name] = make_provider(
            "ipcidr",
            "mrs",
            public_url(base_url, "dist/ipcidr", f"{name}.mrs"),
            f"./ruleset/{name}.mrs",
            interval,
        )
        generated_names.append(name)
        rebuilt = original_set

    else:
        domain_values: list[str] = []
        domain_originals: list[str] = []
        ip_values: list[str] = []
        ip_originals: list[str] = []
        fallback: list[str] = []

        for rule in parsed:
            domain_value = source_domain_value(rule)
            ip_value = source_ip_value(rule)
            if domain_value is not None:
                validate_source_domain_value(rule, domain_value)
                domain_values.append(domain_value)
                domain_originals.append(rule.raw)
            elif ip_value is not None:
                ip_values.append(ip_value)
                ip_originals.append(rule.raw)
            else:
                fallback.append(rule.raw)

        if domain_values:
            generated_name = split_provider_name(name, "domain", reserved_names)
            source_path = dist / "source" / "domain" / f"{name}.yaml"
            mrs_path = dist / "domain" / f"{name}.mrs"
            write_yaml_payload(source_path, domain_values)
            if mihomo:
                convert_source_to_mrs(mihomo, "domain", source_path, mrs_path)
            generated[generated_name] = make_provider(
                "domain",
                "mrs",
                public_url(base_url, "dist/domain", f"{name}.mrs"),
                f"./ruleset/{generated_name}.mrs",
                interval,
            )
            generated_names.append(generated_name)
            rebuilt.update(domain_originals)

        if ip_values:
            generated_name = split_provider_name(name, "ip", reserved_names)
            source_path = dist / "source" / "ipcidr" / f"{name}.yaml"
            mrs_path = dist / "ipcidr" / f"{name}.mrs"
            write_yaml_payload(source_path, ip_values)
            if mihomo:
                convert_source_to_mrs(mihomo, "ipcidr", source_path, mrs_path)
            generated[generated_name] = make_provider(
                "ipcidr",
                "mrs",
                public_url(base_url, "dist/ipcidr", f"{name}.mrs"),
                f"./ruleset/{generated_name}.mrs",
                interval,
            )
            generated_names.append(generated_name)
            rebuilt.update(ip_originals)

        if fallback:
            generated_name = split_provider_name(name, "classical", reserved_names)
            classical_path = dist / "classical" / f"{name}.yaml"
            write_yaml_payload(classical_path, fallback)
            generated[generated_name] = make_provider(
                "classical",
                "yaml",
                public_url(base_url, "dist/classical", f"{name}.yaml"),
                f"./ruleset/{generated_name}.yaml",
                interval,
            )
            generated_names.append(generated_name)
            rebuilt.update(fallback)

    missing = original_set - rebuilt
    unexpected = rebuilt - original_set
    if missing or unexpected:
        raise SystemExit(
            f"{name}: verification failed; missing={len(missing)} unexpected={len(unexpected)}"
        )

    return ProviderResult(name, generated_names, generated, original_set, rebuilt)


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
        parts = [part.strip() for part in item.split(",")]
        if len(parts) >= 3 and parts[0].upper() == "RULE-SET" and parts[1] in replacements:
            for replacement in replacements[parts[1]]:
                inherited = ["RULE-SET", replacement, *parts[2:]]
                # no-resolve is meaningful for ipcidr providers; keep it only there.
                if provider_behaviors.get(replacement) != "ipcidr":
                    inherited = [part for part in inherited if part != "no-resolve"]
                rewritten.append(",".join(inherited))
        else:
            rewritten.append(item)
    return rewritten


def main() -> None:
    parser = argparse.ArgumentParser(description="Convert Mihomo rule-providers to MRS safely.")
    parser.add_argument("input", type=Path)
    parser.add_argument("--dist", type=Path, default=Path("dist"))
    parser.add_argument(
        "--base-url",
        required=True,
        help="Public raw URL prefix for this repository, for example https://raw.githubusercontent.com/owner/repo/main",
    )
    parser.add_argument("--mihomo", default=os.environ.get("MIHOMO_BIN") or shutil.which("mihomo"))
    parser.add_argument("--allow-no-mihomo", action="store_true")
    args = parser.parse_args()

    if not args.mihomo and not args.allow_no_mihomo:
        raise SystemExit("mihomo binary not found; install it or pass --allow-no-mihomo for source-only output")

    data = load_yaml(args.input)
    providers = data.get("rule-providers") or {}
    rules = data.get("rules") or []
    if not isinstance(providers, dict) or not isinstance(rules, list):
        raise SystemExit("input must contain rule-providers mapping and rules list")

    args.dist.mkdir(parents=True, exist_ok=True)
    clean_targets = [args.dist / "classical", args.dist / "source", args.dist / "generated"]
    if args.mihomo:
        clean_targets.extend([args.dist / "domain", args.dist / "ipcidr"])
    for target in clean_targets:
        if target.exists():
            shutil.rmtree(target)

    generated_providers: dict[str, dict[str, Any]] = {}
    provider_behaviors: dict[str, str] = {}
    replacements: dict[str, list[str]] = {}
    cache_dir = Path(".cache") / "remote-rules"
    reserved_names = set(providers)

    for name, provider in providers.items():
        if not isinstance(provider, dict):
            raise SystemExit(f"{name}: provider must be a mapping")
        result = process_provider(
            name=name,
            provider=provider,
            dist=args.dist,
            cache_dir=cache_dir,
            base_url=args.base_url,
            mihomo=args.mihomo,
            reserved_names=reserved_names,
        )
        generated_providers.update(result.providers)
        for generated_name, generated_provider in result.providers.items():
            provider_behaviors[generated_name] = generated_provider["behavior"]
        replacements[name] = result.generated_names
        print(f"{name}: ok ({len(result.original_rules)} rules -> {', '.join(result.generated_names)})")

    generated = {
        "rule-providers": generated_providers,
        "rules": rewrite_rules(rules, replacements, provider_behaviors),
    }
    output = args.dist / "generated" / "mihomo-rules.yaml"
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(
        yaml.safe_dump(generated, allow_unicode=True, sort_keys=False),
        encoding="utf-8",
    )
    print(f"wrote {output}")


if __name__ == "__main__":
    main()
