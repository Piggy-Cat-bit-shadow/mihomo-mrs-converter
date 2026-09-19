"""Command-line argument handling for the converter."""

import argparse
import os
import shutil
from pathlib import Path

from .model import BuildConfig
from .pipeline import build


def main() -> None:
    parser = argparse.ArgumentParser(description="Convert Mihomo rule-providers to final multi-client artifacts.")
    parser.add_argument("input", type=Path)
    parser.add_argument("--dist", type=Path, default=Path("dist"))
    parser.add_argument("--base-url", required=True)
    parser.add_argument("--mihomo", default=os.environ.get("MIHOMO_BIN") or shutil.which("mihomo"))
    parser.add_argument("--sing-box", default=os.environ.get("SING_BOX_BIN") or shutil.which("sing-box"))
    parser.add_argument("--complete-config", type=Path)
    parser.add_argument("--complete-output", type=Path)
    parser.add_argument("--segment-names", type=Path)
    args = parser.parse_args()
    if not args.mihomo:
        raise SystemExit("mihomo binary not found; install Mihomo and retry")
    if not args.sing_box:
        raise SystemExit("sing-box binary not found; install Sing-box and retry")
    segment_names = args.segment_names
    if segment_names is None:
        candidate = args.input.parent.parent / "segment-names.yaml"
        segment_names = candidate if candidate.exists() else None
    result = build(BuildConfig(
        args.input, args.dist, args.base_url, args.mihomo, args.sing_box,
        args.complete_config, args.complete_output, segment_names,
    ))
    print(f"wrote {args.dist / 'generated/mihomo-rules.yaml'}")
    print(f"final providers: {len(result.final_config['rule-providers'])}")
    print(f"MRS outputs: {sum(1 for provider in result.final_config['rule-providers'].values() if provider.get('format') == 'mrs')}")


if __name__ == "__main__":
    main()
