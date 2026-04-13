"""Tests for report formatting and output file generation."""

from __future__ import annotations

import json

from core.report_builder import ReportBuilder


def _finding(severity: str, file_name: str = "dag.py", line: int = 1) -> dict:
    return {
        "severity": severity,
        "file": file_name,
        "line": line,
        "description": f"issue-{severity}",
        "recommendation": "fix",
    }


def test_build_writes_markdown_and_json(tmp_path) -> None:
    builder = ReportBuilder(output_dir=str(tmp_path))
    results = [
        {
            "agent": "security_scanner",
            "display_name": "Security",
            "findings": [_finding("LOW")],
            "severity": "LOW",
            "error": None,
        }
    ]
    md_path, json_path = builder.build(results, context_label="scope")

    assert md_path.exists()
    assert json_path.exists()
    assert "scope" in md_path.read_text(encoding="utf-8")

    payload = json.loads(json_path.read_text(encoding="utf-8"))
    assert payload["agents"]["security_scanner"]["display_name"] == "Security"


def test_markdown_orders_by_severity(tmp_path) -> None:
    builder = ReportBuilder(output_dir=str(tmp_path))
    results = [
        {
            "agent": "bug_detector",
            "display_name": "Bug",
            "findings": [_finding("LOW"), _finding("CRITICAL"), _finding("HIGH")],
            "severity": "CRITICAL",
            "error": None,
        }
    ]
    md_path, _ = builder.build(results, context_label="x")
    content = md_path.read_text(encoding="utf-8")
    assert content.index("CRITICAL") < content.index("HIGH") < content.index("LOW")


def test_report_prefix_applied(tmp_path) -> None:
    builder = ReportBuilder(output_dir=str(tmp_path))
    results = [{"agent": "x", "display_name": "X", "findings": [], "severity": "NONE", "error": None}]
    md_path, _ = builder.build(results, context_label="x", markdown_prefix="review-ccr-ingest")
    assert md_path.name.startswith("review-ccr-ingest-")
