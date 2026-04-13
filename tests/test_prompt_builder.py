"""PromptBuilder-specific behavior tests."""

from __future__ import annotations

from core.agent_runner import AGENTS, ANZ_PLATFORM_CONTEXT, PromptBuilder
from rules.domain_rules import build_rules_context


def _agent(name: str):
    return next(agent for agent in AGENTS if agent.name == name)


def test_platform_context_injected_into_all_agents() -> None:
    builder = PromptBuilder(ANZ_PLATFORM_CONTEXT)
    for agent in AGENTS:
        prompt = builder.build(agent, "agent-prompt", "rules", "context")
        assert "## Platform Context" in prompt


def test_dataset_map_only_for_bug_and_consistency() -> None:
    dataset_map = {"project": "ccr", "datasets": {}, "warnings": [], "errors": ["broken"]}
    builder = PromptBuilder(ANZ_PLATFORM_CONTEXT, dataset_map=dataset_map)

    bug_prompt = builder.build(_agent("bug_detector"), "p", "r", "c")
    consistency_prompt = builder.build(_agent("consistency_checker"), "p", "r", "c")
    domain_prompt = builder.build(_agent("domain_linter"), "p", "r", "c")

    assert "## Dataset Map" in bug_prompt
    assert "## Dataset Map" in consistency_prompt
    assert "## Dataset Map" not in domain_prompt


def test_dataset_errors_are_prefixed() -> None:
    dataset_map = {"project": "ccr", "datasets": {}, "warnings": [], "errors": ["Consumer missing producer"]}
    builder = PromptBuilder(ANZ_PLATFORM_CONTEXT, dataset_map=dataset_map)
    prompt = builder.build(_agent("bug_detector"), "p", "r", "c")
    assert "[DATASET ERROR] Consumer missing producer" in prompt


def test_rules_context_uses_correct_categories_per_agent() -> None:
    bug = _agent("bug_detector")
    domain = _agent("domain_linter")

    bug_ctx = build_rules_context(bug.rule_categories)
    domain_ctx = build_rules_context(domain.rule_categories)

    assert "TERADATA" in bug_ctx
    assert "DATASET" in bug_ctx
    assert "PYTHON" not in domain_ctx
    assert "DATASET" in domain_ctx


def test_agent_config_lookup_for_all_five_agents() -> None:
    names = [agent.name for agent in AGENTS]
    assert names == [
        "security_scanner",
        "bug_detector",
        "test_coverage",
        "consistency_checker",
        "domain_linter",
    ]
