#!/usr/bin/env python3
import argparse
from pathlib import Path

import yaml


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Extract only rule-providers and rules from a Clash/Mihomo config."
    )
    parser.add_argument("source", type=Path)
    parser.add_argument("output", type=Path)
    args = parser.parse_args()

    data = yaml.safe_load(args.source.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise SystemExit("source YAML must be a mapping")

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
