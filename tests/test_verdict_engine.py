"""VerdictEngine threshold and boundary tests."""

from __future__ import annotations

from core.models import Verdict
from core.report_builder import VerdictEngine


def _finding(severity: str) -> dict:
    return {"severity": severity, "file": "x.py", "description": "d"}


def _result(findings: list[dict]) -> dict:
    return {"agent": "a", "display_name": "A", "findings": findings, "severity": "NONE", "error": None}


def test_critical_anywhere_requests_changes() -> None:
    verdict = VerdictEngine.compute([_result([_finding("CRITICAL")])])
    assert verdict == Verdict.REQUEST_CHANGES


def test_exactly_two_high_needs_discussion() -> None:
    verdict = VerdictEngine.compute([_result([_finding("HIGH"), _finding("HIGH")])])
    assert verdict == Verdict.NEEDS_DISCUSSION


def test_exactly_three_high_requests_changes() -> None:
    verdict = VerdictEngine.compute([_result([_finding("HIGH"), _finding("HIGH"), _finding("HIGH")])])
    assert verdict == Verdict.REQUEST_CHANGES


def test_medium_without_high_needs_discussion() -> None:
    verdict = VerdictEngine.compute([_result([_finding("MEDIUM")])])
    assert verdict == Verdict.NEEDS_DISCUSSION


def test_low_only_approve() -> None:
    verdict = VerdictEngine.compute([_result([_finding("LOW")])])
    assert verdict == Verdict.APPROVE


def test_no_findings_approve() -> None:
    verdict = VerdictEngine.compute([_result([])])
    assert verdict == Verdict.APPROVE
