"""Build orchestration boundary. Lower-level implementations live in converter.core and owners.

This module is intentionally tiny; CLI code calls the owner modules directly.
"""

from .cli import main

__all__ = ["main"]
