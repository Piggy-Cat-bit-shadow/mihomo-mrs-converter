#!/usr/bin/env python3
import argparse
from pathlib import Path
from urllib.parse import parse_qsl, urlparse

import yaml


SENSITIVE_HEADER_NAMES = {
    "authorization",
    "proxy-authorization",
    "cookie",
    "x-api-key",
    "api-key",
}
SENSITIVE_QUERY_NAMES = {
    "token",
    "secret",
    "password",
    "passwd",
    "api_key",
    "apikey",
    "auth",
    "signature",
}


def check_sensitive_provider(name: str, provider: object) -> None:
    if not isinstance(provider, dict):
        return
    headers = provider.get("header")
    if isinstance(headers, dict):
        for key in headers:
            if isinstance(key, str) and key.lower() in SENSITIVE_HEADER_NAMES:
                raise SystemExit(f"{name}: sensitive provider header field {key}")
    url = provider.get("url")
    if not isinstance(url, str):
        return
    parsed = urlparse(url)
    if parsed.username or parsed.password:
        raise SystemExit(f"{name}: sensitive URL userinfo")
    for key, _value in parse_qsl(parsed.query, keep_blank_values=True):
        if key.lower() in SENSITIVE_QUERY_NAMES:
            raise SystemExit(f"{name}: sensitive URL query field {key}")


def check_sensitive_config(data: dict[str, object]) -> None:
    providers = data.get("rule-providers", {})
    if not isinstance(providers, dict):
        return
    for name, provider in providers.items():
        check_sensitive_provider(str(name), provider)


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Extract only rule-providers and rules from a Clash/Mihomo config."
    )
    parser.add_argument("source", type=Path)
    parser.add_argument("output", type=Path)
    parser.add_argument("--allow-sensitive", action="store_true")
    args = parser.parse_args()

    data = yaml.safe_load(args.source.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise SystemExit("source YAML must be a mapping")
    if not args.allow_sensitive:
        check_sensitive_config(data)

    extracted = {
        "rule-providers": data.get("rule-providers", {}),
        "rules": data.get("rules", []),
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        yaml.safe_dump(extracted, allow_unicode=True, sort_keys=False),
        encoding="utf-8",
    )


if __name__ == "__main__":
    main()
