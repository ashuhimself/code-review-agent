"""Formatting helpers for injecting domain rules into prompts."""

from rules.rule_registry import ALL_RULES


def build_rules_context(categories: list[str] | None = None) -> str:
    """Return formatted domain rule context for selected categories."""

    active = categories if categories is not None else list(ALL_RULES.keys())
    lines = ["## Domain Rules", ""]
    for category in active:
        rules = ALL_RULES.get(category, [])
        if not rules:
            continue
        lines.append(f"### {category.upper()} Rules")
        for rule in rules:
            lines.append(
                f"- [{rule.severity.value}] {rule.id}: {rule.description}\n"
                f"  Pattern: `{rule.pattern}`\n"
                f"  Fix: {rule.fix_hint}"
            )
        lines.append("")
    return "\n".join(lines).rstrip()


def get_forbidden_patterns() -> list[dict[str, str]]:
    """Return flattened list of rule metadata for programmatic checks."""

    result: list[dict[str, str]] = []
    for rules in ALL_RULES.values():
        for rule in rules:
            result.append(
                {
                    "id": rule.id,
                    "pattern": rule.pattern,
                    "severity": rule.severity.value,
                    "description": rule.description,
                    "fix_hint": rule.fix_hint,
                }
            )
    return result
