"""Tests for rules registry and formatting helpers."""

from __future__ import annotations

from rules.domain_rules import (
    AIRFLOW_RULES,
    ALL_RULES,
    DATASET_RULES,
    PYTHON_RULES,
    SECURITY_RULES,
    TERADATA_RULES,
    Severity,
    build_rules_context,
    get_forbidden_patterns,
)


def test_all_rules_registers_every_rule_list() -> None:
    total_registry = sum(len(values) for values in ALL_RULES.values())
    expected = (
        len(SECURITY_RULES)
        + len(AIRFLOW_RULES)
        + len(PYTHON_RULES)
        + len(TERADATA_RULES)
        + len(DATASET_RULES)
    )
    assert total_registry == expected


def test_teradata_rules_category() -> None:
    assert TERADATA_RULES
    assert all(rule.category == "teradata" for rule in TERADATA_RULES)


def test_dataset_rules_category() -> None:
    assert DATASET_RULES
    assert all(rule.category == "dataset" for rule in DATASET_RULES)


def test_all_rules_includes_teradata_and_dataset() -> None:
    assert "teradata" in ALL_RULES
    assert "dataset" in ALL_RULES


def test_severity_enum_used_in_all_rules() -> None:
    for values in ALL_RULES.values():
        for rule in values:
            assert isinstance(rule.severity, Severity)


def test_build_rules_context_filters_categories() -> None:
    ctx = build_rules_context(["dataset"])
    assert "DATASET" in ctx
    assert "TERADATA" not in ctx


def test_forbidden_patterns_export_severity_as_string() -> None:
    patterns = get_forbidden_patterns()
    assert patterns
    assert all(item["severity"] in {s.value for s in Severity} for item in patterns)
