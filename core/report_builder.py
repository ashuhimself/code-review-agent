"""Report generation pipeline with pluggable formatters."""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Protocol

from core.models import Verdict
from rules.domain_rules import Severity


class VerdictEngine:
    """Pure verdict computation logic based on individual findings only."""

    @staticmethod
    def compute(agent_results: list[dict]) -> Verdict:
        high_count = 0
        saw_medium = False
        saw_high = False

        for result in agent_results:
            for finding in result.get("findings", []):
                severity = str(finding.get("severity", "")).upper()
                if severity == Severity.CRITICAL.value:
                    return Verdict.REQUEST_CHANGES
                if severity == Severity.HIGH.value:
                    high_count += 1
                    saw_high = True
                if severity == Severity.MEDIUM.value:
                    saw_medium = True

        if high_count >= 3:
            return Verdict.REQUEST_CHANGES
        if saw_high or saw_medium:
            return Verdict.NEEDS_DISCUSSION
        return Verdict.APPROVE


class ReportFormatter(Protocol):
    """Formatter contract for report output formats."""

    def format(self, agent_results: list[dict], verdict: Verdict, context_label: str) -> str:
        ...

    def file_extension(self) -> str:
        ...

    def output_name(self, timestamp: str) -> str:
        ...


@dataclass
class MarkdownFormatter:
    """Create human-readable markdown report."""

    prefix: str = "review"

    def format(self, agent_results: list[dict], verdict: Verdict, context_label: str) -> str:
        ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        lines = [
            f"# Code Review: `{context_label}`",
            f"**Verdict:** {self._verdict_badge(verdict)} · {ts}",
            "",
        ]

        for result in agent_results:
            agent_name = result.get("agent", "unknown")
            display_name = result.get("display_name", agent_name)
            findings = result.get("findings", [])
            error = result.get("error")
            lines.append(f"## {display_name} - {len(findings)} finding(s)")
            lines.append("")

            if error:
                lines.append(f"Agent error: `{error}`")
                lines.append("")
                continue

            if not findings:
                lines.append("_No findings._")
                lines.append("")
                continue

            for severity in (
                Severity.CRITICAL.value,
                Severity.HIGH.value,
                Severity.MEDIUM.value,
                Severity.LOW.value,
            ):
                for finding in findings:
                    if str(finding.get("severity", "")).upper() != severity:
                        continue
                    file_ref = finding.get("file", "")
                    line = finding.get("line")
                    loc = f"`{file_ref}:{line}`" if line else f"`{file_ref}`"
                    lines.append(f"**{self._severity_badge(severity)}** · {loc}")
                    lines.append(str(finding.get("description", "")))
                    recommendation = str(finding.get("recommendation", ""))
                    if recommendation:
                        lines.append(f"Fix: {recommendation}")
                    lines.append("")

        return "\n".join(lines)

    def file_extension(self) -> str:
        return "md"

    def output_name(self, timestamp: str) -> str:
        return f"{self.prefix}-{timestamp}.md"

    @staticmethod
    def _severity_badge(value: str) -> str:
        badges = {
            Severity.CRITICAL.value: "CRITICAL",
            Severity.HIGH.value: "HIGH",
            Severity.MEDIUM.value: "MEDIUM",
            Severity.LOW.value: "LOW",
            "NONE": "NONE",
        }
        return badges.get(value, value)

    @staticmethod
    def _verdict_badge(verdict: Verdict) -> str:
        return verdict.value


@dataclass
class JsonFormatter:
    """Create machine-readable summary json."""

    def format(self, agent_results: list[dict], verdict: Verdict, context_label: str) -> str:
        per_agent: dict[str, dict] = {}
        for result in agent_results:
            agent_name = result.get("agent", "unknown")
            per_agent[agent_name] = {
                "display_name": result.get("display_name", agent_name),
                "total_findings": len(result.get("findings", [])),
                "highest_severity": result.get("severity", "NONE"),
                "verdict": self._agent_verdict(str(result.get("severity", "NONE"))),
                "findings": result.get("findings", []),
                "error": result.get("error"),
            }

        payload = {
            "generated_at": datetime.now().isoformat(),
            "scope": context_label,
            "overall_verdict": verdict.value,
            "agents": per_agent,
        }
        return json.dumps(payload, indent=2, ensure_ascii=False)

    def file_extension(self) -> str:
        return "json"

    def output_name(self, timestamp: str) -> str:
        _ = timestamp
        return "summary.json"

    @staticmethod
    def _agent_verdict(highest_severity: str) -> str:
        if highest_severity == Severity.CRITICAL.value:
            return Verdict.REQUEST_CHANGES.value
        if highest_severity == Severity.HIGH.value:
            return Verdict.NEEDS_DISCUSSION.value
        return Verdict.APPROVE.value


class ReportBuilder:
    """Orchestrates verdict computation and formatter output file writes."""

    def __init__(
        self,
        output_dir: str = ".",
        verdict_engine: VerdictEngine | None = None,
    ):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self._timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        self.verdict_engine = verdict_engine or VerdictEngine()

    def build(
        self,
        agent_results: list[dict],
        context_label: str = "branch diff",
        formatters: list[ReportFormatter] | None = None,
        markdown_prefix: str = "review",
    ) -> tuple[Path, Path]:
        verdict = self.verdict_engine.compute(agent_results)
        active = formatters or [MarkdownFormatter(prefix=markdown_prefix), JsonFormatter()]

        markdown_path: Path | None = None
        json_path: Path | None = None

        for formatter in active:
            content = formatter.format(agent_results, verdict, context_label)
            output_path = self.output_dir / formatter.output_name(self._timestamp)
            output_path.write_text(content, encoding="utf-8")
            if formatter.file_extension() == "md":
                markdown_path = output_path
            if formatter.file_extension() == "json":
                json_path = output_path

        if markdown_path is None or json_path is None:
            raise ValueError("Both markdown and json formatters are required")

        return markdown_path, json_path

    @staticmethod
    def _compute_verdict(agent_results: list[dict]) -> str:
        """Backward-compatible wrapper retained for older callers/tests."""

        return VerdictEngine.compute(agent_results).value
