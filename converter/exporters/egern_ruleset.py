"""Shared Egern rule-set primitives used by Egern and DNS exporters."""

# Kept as a narrow compatibility seam while the pure primitives remain owned
# by the Egern implementation; consumers do not depend on the full exporter.
from .egern import classify_egern_classical, network_covered_by_parent, optimize_egern_rule_set

__all__ = ["classify_egern_classical", "network_covered_by_parent", "optimize_egern_rule_set"]
