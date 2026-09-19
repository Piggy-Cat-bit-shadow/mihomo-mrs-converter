#!/usr/bin/env python3
"""Compare exporter worker counts without changing production defaults."""
from __future__ import annotations

import argparse
import os
import subprocess
import sys
import tempfile
import time
from pathlib import Path


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("input", type=Path)
    parser.add_argument("--segment-names", type=Path, required=True)
    parser.add_argument("--base-url", required=True)
    parser.add_argument("--mihomo", required=True)
    parser.add_argument("--sing-box", required=True)
    parser.add_argument("--workers", type=int, nargs="+", default=[1, 2, 3, 5])
    parser.add_argument("--repeat", type=int, default=2)
    args = parser.parse_args()
    with tempfile.TemporaryDirectory(prefix="mihomo-export-benchmark-") as tmp:
        root = Path(tmp)
        for workers in args.workers:
            elapsed: list[float] = []
            for run in range(args.repeat):
                dist = root / f"w{workers}-r{run}"
                env = os.environ.copy()
                env["CONVERTER_EXPORT_WORKERS"] = str(workers)
                started = time.perf_counter()
                subprocess.run([
                    sys.executable, "-m", "converter", str(args.input),
                    "--dist", str(dist), "--segment-names", str(args.segment_names),
                    "--base-url", args.base_url, "--mihomo", args.mihomo, "--sing-box", args.sing_box,
                ], check=True, env=env)
                elapsed.append(time.perf_counter() - started)
            print(f"workers={workers}: " + ", ".join(f"{value:.2f}s" for value in elapsed))


if __name__ == "__main__":
    main()
