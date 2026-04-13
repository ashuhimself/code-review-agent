"""Backward-compatible shim for domain rule imports."""

from rules.rule_formatters import build_rules_context, get_forbidden_patterns
from rules.rule_models import Rule, Severity
from rules.rule_registry import (
    AIRFLOW_RULES,
    ALL_RULES,
    DATASET_RULES,
    PYTHON_RULES,
    SECURITY_RULES,
    TERADATA_RULES,
)

__all__ = [
    "Rule",
    "Severity",
    "SECURITY_RULES",
    "AIRFLOW_RULES",
    "PYTHON_RULES",
    "TERADATA_RULES",
    "DATASET_RULES",
    "ALL_RULES",
    "build_rules_context",
    "get_forbidden_patterns",
]
