"""Unit tests for AgentRunner orchestration and parser behavior."""

from __future__ import annotations

import json
import tempfile
from pathlib import Path

from core.agent_runner import AGENT_ORDER, AGENTS, AgentRunner, OutputParser, PromptBuilder


def _write_prompt_files(tmp_path: Path) -> Path:
    prompts_dir = tmp_path / "prompts"
    prompts_dir.mkdir()
    for agent in AGENTS:
        payload = {"prompt": [f"Prompt for {agent.name}"]}
        (prompts_dir / agent.prompt_file).write_text(json.dumps(payload), encoding="utf-8")
    return prompts_dir


def test_output_parser_parses_jsonl() -> None:
    raw = "\n".join(
        [
            json.dumps({"type": "finding", "severity": "HIGH", "agent": "x", "file": "a.py"}),
            json.dumps({"type": "summary", "agent": "x", "highest_severity": "HIGH", "total_findings": 1}),
        ]
    )
    findings, summary = OutputParser.parse_jsonl(raw, "x")
    assert len(findings) == 1
    assert summary["total_findings"] == 1


def test_output_parser_extracts_nested_json_from_prose() -> None:
    prose = (
        "analysis text "
        '{"type":"finding","severity":"MEDIUM","file":"a.py","description":"uses {var}"}'
    )
    findings, _ = OutputParser.extract_json_from_prose(prose)
    assert len(findings) == 1


def test_run_subset_uses_selected_agents(monkeypatch) -> None:
    with tempfile.TemporaryDirectory() as tmp:
        prompts_dir = _write_prompt_files(Path(tmp))
        monkeypatch.setattr("core.agent_runner.PROMPTS_DIR", prompts_dir)

        def fake_runner(_cmd: list[str], _stdin: str) -> tuple[str, str]:
            payload = json.dumps({"type": "summary", "agent": "x", "total_findings": 0, "highest_severity": "NONE"})
            return payload, ""

        runner = AgentRunner(cli_runner=fake_runner)
        results = runner.run_subset(["security_scanner", "bug_detector"], "code")
        assert [result["agent"] for result in results] == ["security_scanner", "bug_detector"]


def test_run_all_matches_agent_order(monkeypatch) -> None:
    with tempfile.TemporaryDirectory() as tmp:
        prompts_dir = _write_prompt_files(Path(tmp))
        monkeypatch.setattr("core.agent_runner.PROMPTS_DIR", prompts_dir)

        def fake_runner(_cmd: list[str], _stdin: str) -> tuple[str, str]:
            payload = json.dumps({"type": "summary", "agent": "x", "total_findings": 0, "highest_severity": "NONE"})
            return payload, ""

        runner = AgentRunner(cli_runner=fake_runner)
        results = runner.run_all("code")
        assert [result["agent"] for result in results] == AGENT_ORDER


def test_prompt_builder_includes_platform_and_rules() -> None:
    builder = PromptBuilder("platform")
    prompt = builder.build(AGENTS[0], "agent", "rules", "context")
    assert "platform" in prompt
    assert "rules" in prompt
