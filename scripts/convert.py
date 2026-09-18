#!/usr/bin/env python3
"""Compatibility entrypoint for the converter CLI."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from converter.cli import main

if __name__ == "__main__":
    main()
