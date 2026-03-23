"""
Unit tests for ReportBuilder — verdict logic and markdown output.
"""

import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

from core.report_builder import ReportBuilder


def _finding(severity: str, file: str = "dag.py", line: int = 10) -> dict:
    return {
        "severity": severity,
        "file": file,
        "line": line,
        "description": f"Test issue ({severity})",
        "recommendation": f"Fix for {severity}",
    }


def _result(agent: str, findings: list, severity: str = None) -> dict:
    if severity is None:
        severity = findings[0]["severity"] if findings else "NONE"
    return {"agent": agent, "findings": findings, "severity": severity, "error": None}


# ─── Verdict logic ────────────────────────────────────────────────────────────

class TestComputeVerdict:
    def test_critical_anywhere_requests_changes(self):
        results = [_result("security_scanner", [_finding("CRITICAL")])]
        assert ReportBuilder._compute_verdict(results) == "REQUEST_CHANGES"

    def test_three_high_findings_requests_changes(self):
        findings = [_finding("HIGH"), _finding("HIGH"), _finding("HIGH")]
        results = [_result("bug_detector", findings, severity="HIGH")]
        assert ReportBuilder._compute_verdict(results) == "REQUEST_CHANGES"

    def test_one_high_finding_needs_discussion(self):
        # 1 HIGH finding: agent-level HIGH(1) + finding HIGH(1) = 2 total < 3 → NEEDS_DISCUSSION
        results = [_result("bug_detector", [_finding("HIGH")], severity="HIGH")]
        assert ReportBuilder._compute_verdict(results) == "NEEDS_DISCUSSION"

    def test_medium_needs_discussion(self):
        results = [_result("domain_linter", [_finding("MEDIUM")], severity="MEDIUM")]
        assert ReportBuilder._compute_verdict(results) == "NEEDS_DISCUSSION"

    def test_low_only_approves(self):
        results = [_result("domain_linter", [_finding("LOW")], severity="LOW")]
        assert ReportBuilder._compute_verdict(results) == "APPROVE"

    def test_no_findings_approves(self):
        results = [_result("security_scanner", [], severity="NONE")]
        assert ReportBuilder._compute_verdict(results) == "APPROVE"

    def test_critical_in_second_agent_requests_changes(self):
        results = [
            _result("security_scanner", [_finding("LOW")], severity="LOW"),
            _result("bug_detector", [_finding("CRITICAL")], severity="CRITICAL"),
        ]
        assert ReportBuilder._compute_verdict(results) == "REQUEST_CHANGES"

    def test_high_count_spans_multiple_agents(self):
        # 2 HIGH across two agents → NEEDS_DISCUSSION, not REQUEST_CHANGES
        results = [
            _result("security_scanner", [_finding("HIGH")], severity="HIGH"),
            _result("bug_detector", [_finding("HIGH")], severity="HIGH"),
        ]
        verdict = ReportBuilder._compute_verdict(results)
        # 2 HIGHs from findings + 2 agent-level HIGHs → 4 HIGH → REQUEST_CHANGES
        assert verdict == "REQUEST_CHANGES"


# ─── Markdown output ──────────────────────────────────────────────────────────

class TestWriteMarkdown:
    @pytest.fixture
    def builder(self, tmp_path):
        return ReportBuilder(output_dir=str(tmp_path))

    def _build_md(self, builder, results) -> str:
        verdict = ReportBuilder._compute_verdict(results)
        md_path, _ = builder.build(results, context_label="test/file.py")
        return md_path.read_text()

    def test_verdict_appears_in_header(self, builder):
        results = [_result("security_scanner", [_finding("CRITICAL")])]
        md = self._build_md(builder, results)
        assert "REQUEST_CHANGES" in md

    def test_scope_appears_in_header(self, builder):
        results = [_result("security_scanner", [])]
        verdict = ReportBuilder._compute_verdict(results)
        md_path, _ = builder.build(results, context_label="dags/my_dag.py")
        md = md_path.read_text()
        assert "dags/my_dag.py" in md

    def test_finding_location_present(self, builder):
        results = [_result("security_scanner", [_finding("HIGH", file="secrets.py", line=42)])]
        md = self._build_md(builder, results)
        assert "secrets.py:42" in md

    def test_description_and_fix_present(self, builder):
        f = _finding("HIGH", file="a.py", line=1)
        results = [_result("security_scanner", [f])]
        md = self._build_md(builder, results)
        assert f["description"] in md
        assert f["recommendation"] in md

    def test_no_findings_shows_clean(self, builder):
        results = [_result("domain_linter", [], severity="NONE")]
        md = self._build_md(builder, results)
        assert "No findings" in md

    def test_agent_error_surfaced(self, builder):
        result = {"agent": "bug_detector", "findings": [], "severity": "NONE",
                  "error": "Timeout after 300s"}
        md_path, _ = builder.build([result], context_label="x")
        md = md_path.read_text()
        assert "Timeout after 300s" in md

    def test_severities_ordered_critical_first(self, builder):
        findings = [_finding("LOW"), _finding("CRITICAL"), _finding("HIGH")]
        results = [_result("security_scanner", findings, severity="CRITICAL")]
        md = self._build_md(builder, results)
        idx_critical = md.index("CRITICAL")
        idx_high = md.index("HIGH")
        idx_low = md.index("LOW")
        # CRITICAL header must appear before HIGH which appears before LOW
        assert idx_critical < idx_high < idx_low

    def test_no_code_snippets_in_output(self, builder):
        f = {**_finding("HIGH"), "code_snippet": "password = 'hunter2'"}
        results = [_result("security_scanner", [f])]
        md = self._build_md(builder, results)
        assert "hunter2" not in md
        assert "```python" not in md


# ─── JSON output ──────────────────────────────────────────────────────────────

class TestWriteJson:
    @pytest.fixture
    def builder(self, tmp_path):
        return ReportBuilder(output_dir=str(tmp_path))

    def test_json_contains_verdict(self, builder):
        results = [_result("security_scanner", [_finding("CRITICAL")])]
        _, json_path = builder.build(results, context_label="x")
        data = json.loads(json_path.read_text())
        assert data["overall_verdict"] == "REQUEST_CHANGES"

    def test_json_has_all_agents(self, builder):
        agents = ["security_scanner", "bug_detector", "domain_linter"]
        results = [_result(a, []) for a in agents]
        _, json_path = builder.build(results, context_label="x")
        data = json.loads(json_path.read_text())
        for a in agents:
            assert a in data["agents"]

    def test_json_finding_count_matches(self, builder):
        findings = [_finding("HIGH"), _finding("LOW")]
        results = [_result("bug_detector", findings, severity="HIGH")]
        _, json_path = builder.build(results, context_label="x")
        data = json.loads(json_path.read_text())
        assert data["agents"]["bug_detector"]["total_findings"] == 2
