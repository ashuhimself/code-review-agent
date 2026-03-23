"""
Unit tests for domain_rules — rule registry, build_rules_context, get_forbidden_patterns.
"""

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

from rules.domain_rules import (
    ALL_RULES,
    AIRFLOW_RULES,
    PYTHON_RULES,
    SECURITY_RULES,
    Rule,
    build_rules_context,
    get_forbidden_patterns,
)

VALID_SEVERITIES = {"CRITICAL", "HIGH", "MEDIUM", "LOW"}
VALID_CATEGORIES = {"security", "airflow", "python"}


# ─── Rule dataclass ───────────────────────────────────────────────────────────

class TestRuleDataclass:
    def test_all_rules_have_required_fields(self):
        for cat, rules in ALL_RULES.items():
            for rule in rules:
                assert rule.id,          f"{cat}: rule missing id"
                assert rule.description, f"{rule.id}: missing description"
                assert rule.pattern,     f"{rule.id}: missing pattern"
                assert rule.severity in VALID_SEVERITIES, f"{rule.id}: bad severity '{rule.severity}'"
                assert rule.category in VALID_CATEGORIES, f"{rule.id}: bad category '{rule.category}'"

    def test_rule_ids_are_unique(self):
        ids = [r.id for rules in ALL_RULES.values() for r in rules]
        assert len(ids) == len(set(ids)), "Duplicate rule IDs found"

    def test_security_rules_are_all_security_category(self):
        for rule in SECURITY_RULES:
            assert rule.category == "security"

    def test_airflow_rules_are_all_airflow_category(self):
        for rule in AIRFLOW_RULES:
            assert rule.category == "airflow"

    def test_python_rules_are_all_python_category(self):
        for rule in PYTHON_RULES:
            assert rule.category == "python"

    def test_all_rules_registry_covers_all_lists(self):
        total_in_registry = sum(len(v) for v in ALL_RULES.values())
        total_direct = len(SECURITY_RULES) + len(AIRFLOW_RULES) + len(PYTHON_RULES)
        assert total_in_registry == total_direct


# ─── build_rules_context ──────────────────────────────────────────────────────

class TestBuildRulesContext:
    def test_returns_string(self):
        assert isinstance(build_rules_context(), str)

    def test_all_categories_included_by_default(self):
        ctx = build_rules_context()
        assert "SECURITY" in ctx
        assert "AIRFLOW" in ctx
        assert "PYTHON" in ctx

    def test_single_category_filter(self):
        ctx = build_rules_context(["security"])
        assert "### SECURITY Rules" in ctx
        assert "### AIRFLOW Rules" not in ctx
        assert "### PYTHON Rules" not in ctx

    def test_multiple_category_filter(self):
        ctx = build_rules_context(["airflow", "python"])
        assert "AIRFLOW" in ctx
        assert "PYTHON" in ctx
        assert "SECURITY" not in ctx

    def test_rule_ids_present_in_context(self):
        ctx = build_rules_context(["security"])
        for rule in SECURITY_RULES:
            assert rule.id in ctx, f"{rule.id} missing from context"

    def test_unknown_category_returns_empty_body(self):
        ctx = build_rules_context(["nonexistent"])
        # header line is still emitted, but no rule content
        assert "SEC-" not in ctx
        assert "AF-" not in ctx
        assert "PY-" not in ctx

    def test_empty_category_list_returns_header_only(self):
        ctx = build_rules_context([])
        assert ctx.strip() == "## Domain Rules"


# ─── get_forbidden_patterns ───────────────────────────────────────────────────

class TestGetForbiddenPatterns:
    def test_returns_list_of_dicts(self):
        patterns = get_forbidden_patterns()
        assert isinstance(patterns, list)
        assert all(isinstance(p, dict) for p in patterns)

    def test_count_matches_all_rules(self):
        total = sum(len(v) for v in ALL_RULES.values())
        assert len(get_forbidden_patterns()) == total

    def test_required_keys_present(self):
        required = {"id", "pattern", "severity", "description", "fix_hint"}
        for p in get_forbidden_patterns():
            assert required.issubset(p.keys()), f"Missing keys in {p.get('id')}"

    def test_all_severities_valid(self):
        for p in get_forbidden_patterns():
            assert p["severity"] in VALID_SEVERITIES, \
                f"{p['id']} has invalid severity '{p['severity']}'"

    def test_no_empty_patterns(self):
        for p in get_forbidden_patterns():
            assert p["pattern"].strip(), f"{p['id']} has empty pattern"
