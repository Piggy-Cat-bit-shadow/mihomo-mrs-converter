"""Network boundary facade; all request policy remains centralized here."""

from .pipeline import fetch_text, _retry_after_seconds

__all__ = ["fetch_text", "_retry_after_seconds"]
