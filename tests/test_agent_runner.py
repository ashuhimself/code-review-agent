"""
Unit tests for AgentRunner.

All subprocess calls are mocked — no actual copilot CLI invocation.
"""

import json
import subprocess
import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

# Ensure the package root is on the path
sys.path.insert(0, str(Path(__file__).parent.parent))

from core.agent_runner import AgentRunner, AGENT_ORDER, AGENT_PROMPTS


@pytest.fixture
def runner():
    return AgentRunner(timeout=30, copilot_bin="copilot")


def _mock_proc(stdout: str, stderr: str = "", returncode: int = 0):
    proc = MagicMock()
    proc.stdout = stdout
    proc.stderr = stderr
    proc.returncode = returncode
    return proc




class TestParseJsonl:
    def test_parses_finding_lines(self, runner):
        finding = {
            "type": "finding",
            "agent": "security_scanner",
            "severity": "HIGH",
            "line": 10,
            "file": "foo.py",
            "description": "Hardcoded password",
            "recommendation": "Use env var",
        }
        summary = {
            "type": "summary",
            "agent": "security_scanner",
            "total_findings": 1,
            "highest_severity": "HIGH",
        }
        raw = "\n".join([json.dumps(finding), json.dumps(summary)])
        findings, summ = runner._parse_jsonl(raw, "security_scanner")

        assert len(findings) == 1
        assert findings[0]["severity"] == "HIGH"
        assert summ["total_findings"] == 1

    def test_ignores_invalid_json_lines(self, runner):
        raw = "not json\n{\"type\": \"finding\", \"severity\": \"LOW\", \"agent\": \"x\", \"file\": \"f.py\", \"description\": \"d\", \"recommendation\": \"r\"}\nnot json either"
        findings, _ = runner._parse_jsonl(raw, "x")
        assert len(findings) == 1

    def test_empty_output_returns_empty(self, runner):
        findings, summary = runner._parse_jsonl("", "security_scanner")
        assert findings == []
        assert summary == {}

    def test_unwraps_claude_json_wrapper(self, runner):
        inner_finding = json.dumps({
            "type": "finding",
            "agent": "bug_detector",
            "severity": "MEDIUM",
            "line": 5,
            "file": "bar.py",
            "description": "None check missing",
            "recommendation": "Add guard",
        })
        wrapper = {"result": inner_finding, "cost": 0.001}
        raw = json.dumps(wrapper)
        findings, _ = runner._parse_jsonl(raw, "bug_detector")
        assert len(findings) == 1
        assert findings[0]["severity"] == "MEDIUM"

    def test_multiple_findings_different_severities(self, runner):
        lines = [
            json.dumps({"type": "finding", "agent": "a", "severity": "CRITICAL", "file": "a.py", "description": "x", "recommendation": "y"}),
            json.dumps({"type": "finding", "agent": "a", "severity": "LOW", "file": "b.py", "description": "x", "recommendation": "y"}),
        ]
        findings, _ = runner._parse_jsonl("\n".join(lines), "a")
        assert len(findings) == 2


class TestHighestSeverity:
    def test_critical_wins(self):
        findings = [
            {"severity": "LOW"},
            {"severity": "CRITICAL"},
            {"severity": "HIGH"},
        ]
        assert AgentRunner._highest_severity(findings) == "CRITICAL"

    def test_none_when_empty(self):
        assert AgentRunner._highest_severity([]) == "NONE"

    def test_medium_only(self):
        findings = [{"severity": "MEDIUM"}, {"severity": "MEDIUM"}]
        assert AgentRunner._highest_severity(findings) == "MEDIUM"

    def test_case_insensitive(self):
        findings = [{"severity": "high"}, {"severity": "low"}]
        assert AgentRunner._highest_severity(findings) == "HIGH"


class TestRunMethod:
    def test_run_returns_expected_structure(self, runner):
        finding_line = json.dumps({
            "type": "finding",
            "agent": "security_scanner",
            "severity": "HIGH",
            "line": 3,
            "file": "secrets.py",
            "description": "Hardcoded API key",
            "recommendation": "Use env var",
        })
        summary_line = json.dumps({
            "type": "summary",
            "agent": "security_scanner",
            "total_findings": 1,
            "highest_severity": "HIGH",
        })
        mock_output = f"{finding_line}\n{summary_line}\n"

        with patch("subprocess.run", return_value=_mock_proc(mock_output)):
            result = runner.run("security_scanner", "Check for secrets", "x = 'password123'")

        assert result["agent"] == "security_scanner"
        assert isinstance(result["findings"], list)
        assert len(result["findings"]) == 1
        assert result["severity"] == "HIGH"
        assert result["error"] is None
        assert "raw" in result

    def test_run_handles_timeout(self, runner):
        with patch("subprocess.run", side_effect=subprocess.TimeoutExpired(cmd="claude", timeout=30)):
            result = runner.run("security_scanner", "prompt", "context")

        assert result["error"] is not None
        assert "Timeout" in result["error"]
        assert result["findings"] == []

    def test_run_handles_missing_binary(self, runner):
        with patch("subprocess.run", side_effect=FileNotFoundError()):
            result = runner.run("security_scanner", "prompt", "context")

        assert result["error"] is not None
        assert "not found" in result["error"]

    def test_run_with_no_findings(self, runner):
        summary_line = json.dumps({
            "type": "summary",
            "agent": "domain_linter",
            "total_findings": 0,
            "highest_severity": "NONE",
        })
        with patch("subprocess.run", return_value=_mock_proc(summary_line)):
            result = runner.run("domain_linter", "prompt", "context")

        assert result["findings"] == []
        assert result["severity"] == "NONE"


class TestRunAll:
    def test_run_all_returns_five_results(self, runner):
        """All 5 agents should produce a result dict."""
        mock_output = json.dumps({
            "type": "summary",
            "agent": "x",
            "total_findings": 0,
            "highest_severity": "NONE",
        })
        with patch("subprocess.run", return_value=_mock_proc(mock_output)):
            results = runner.run_all("some python code")

        assert len(results) == 5
        agent_names = [r["agent"] for r in results]
        assert agent_names == AGENT_ORDER

    def test_run_all_each_has_required_keys(self, runner):
        mock_output = json.dumps({"type": "summary", "agent": "x", "total_findings": 0, "highest_severity": "NONE"})
        with patch("subprocess.run", return_value=_mock_proc(mock_output)):
            results = runner.run_all("code")

        required_keys = {"agent", "findings", "severity", "summary", "raw", "error"}
        for result in results:
            assert required_keys.issubset(result.keys()), f"Missing keys in {result['agent']}"


class TestAgentPrompts:
    def test_all_agents_have_prompts(self):
        for agent in AGENT_ORDER:
            assert agent in AGENT_PROMPTS, f"Missing prompt for {agent}"
            assert len(AGENT_PROMPTS[agent]) > 50, f"Prompt too short for {agent}"

    def test_security_prompt_covers_key_topics(self):
        prompt = AGENT_PROMPTS["security_scanner"].lower()
        for keyword in ("credential", "eval", "os.system", "secret", "airflow"):
            assert keyword in prompt, f"Security prompt missing '{keyword}'"

    def test_domain_linter_prompt_covers_airflow(self):
        prompt = AGENT_PROMPTS["domain_linter"].lower()
        for keyword in ("default_args", "retry", "sensor", "catchup", "schedule"):
            assert keyword in prompt, f"Domain linter prompt missing '{keyword}'"
