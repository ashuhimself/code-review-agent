"""
ReportBuilder: Generates Markdown and JSON reports from agent results.
"""

import json
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional


SEVERITY_BADGE = {
    "CRITICAL": "🔴 CRITICAL",
    "HIGH":     "🟠 HIGH",
    "MEDIUM":   "🟡 MEDIUM",
    "LOW":      "🔵 LOW",
    "NONE":     "✅ NONE",
}

AGENT_DISPLAY = {
    "security_scanner":    "Security & Secrets Scanner",
    "bug_detector":        "Bug & Logic Detector",
    "test_coverage":       "Test Coverage + TDD Suggester",
    "consistency_checker": "Cross-file Consistency Checker",
    "domain_linter":       "Airflow/PySpark Domain Linter",
}


class ReportBuilder:
    def __init__(self, output_dir: str = "."):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self._timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

    
    # Public API
    

    def build(
        self,
        agent_results: List[Dict],
        context_label: str = "branch diff",
    ) -> tuple[Path, Path]:
        """
        Generate both reports.

        Returns:
            (markdown_path, json_path)
        """
        verdict = self._compute_verdict(agent_results)
        md_path = self._write_markdown(agent_results, verdict, context_label)
        json_path = self._write_json(agent_results, verdict, context_label)
        return md_path, json_path

    
    # Verdict logic
    

    @staticmethod
    def _compute_verdict(agent_results: List[Dict]) -> str:
        """
        CRITICAL anywhere → REQUEST_CHANGES
        3+ HIGH overall   → REQUEST_CHANGES
        Any HIGH/MEDIUM   → NEEDS_DISCUSSION
        Otherwise         → APPROVE
        """
        high_count = 0
        for result in agent_results:
            sev = result.get("severity", "NONE")
            if sev == "CRITICAL":
                return "REQUEST_CHANGES"
            if sev == "HIGH":
                high_count += 1
            # Also count individual HIGH findings
            for f in result.get("findings", []):
                if f.get("severity", "").upper() == "HIGH":
                    high_count += 1

        if high_count >= 3:
            return "REQUEST_CHANGES"

        for result in agent_results:
            sev = result.get("severity", "NONE")
            if sev in ("HIGH", "MEDIUM"):
                return "NEEDS_DISCUSSION"

        return "APPROVE"

    
    # Markdown report
    

    def _write_markdown(
        self,
        agent_results: List[Dict],
        verdict: str,
        context_label: str,
    ) -> Path:
        ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        lines: List[str] = [
            f"# Code Review: `{context_label}`",
            f"**Verdict:** {self._verdict_badge(verdict)} · {ts}",
            "",
        ]

        for result in agent_results:
            agent = result.get("agent", "unknown")
            name = AGENT_DISPLAY.get(agent, agent)
            findings = result.get("findings", [])
            error = result.get("error")

            count = len(findings)
            lines.append(f"## {name} — {count} finding(s)")
            lines.append("")

            if error:
                lines.append(f"⚠️ Agent error: `{error}`")
                lines.append("")
                continue

            if not findings:
                lines.append("_No findings._")
                lines.append("")
                continue

            for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
                for f in findings:
                    if f.get("severity", "").upper() != sev:
                        continue
                    badge = SEVERITY_BADGE.get(sev, sev)
                    file_ref = f.get("file", "")
                    line_ref = f.get("line")
                    loc = f"`{file_ref}:{line_ref}`" if line_ref else f"`{file_ref}`"
                    desc = f.get("description", "")
                    rec = f.get("recommendation", "")
                    lines.append(f"**{badge}** · {loc}")
                    lines.append(desc)
                    if rec:
                        lines.append(f"Fix: {rec}")
                    lines.append("")

        md_path = self.output_dir / f"review-{self._timestamp}.md"
        md_path.write_text("\n".join(lines), encoding="utf-8")
        return md_path

    
    # JSON report
    

    def _write_json(
        self,
        agent_results: List[Dict],
        verdict: str,
        context_label: str,
    ) -> Path:
        per_agent = {}
        for result in agent_results:
            agent = result.get("agent", "unknown")
            sev = result.get("severity", "NONE")
            per_agent[agent] = {
                "display_name": AGENT_DISPLAY.get(agent, agent),
                "total_findings": len(result.get("findings", [])),
                "highest_severity": sev,
                "verdict": self._agent_verdict(sev),
                "findings": result.get("findings", []),
                "error": result.get("error"),
            }

        summary = {
            "generated_at": datetime.now().isoformat(),
            "scope": context_label,
            "overall_verdict": verdict,
            "agents": per_agent,
        }

        json_path = self.output_dir / "summary.json"
        json_path.write_text(
            json.dumps(summary, indent=2, ensure_ascii=False), encoding="utf-8"
        )
        return json_path

    
    # Helpers
    

    @staticmethod
    def _verdict_badge(verdict: str) -> str:
        badges = {
            "APPROVE": "✅ APPROVE",
            "NEEDS_DISCUSSION": "🟡 NEEDS_DISCUSSION",
            "REQUEST_CHANGES": "🔴 REQUEST_CHANGES",
        }
        return badges.get(verdict, verdict)

    @staticmethod
    def _agent_verdict(highest_severity: str) -> str:
        if highest_severity == "CRITICAL":
            return "REQUEST_CHANGES"
        if highest_severity == "HIGH":
            return "NEEDS_DISCUSSION"
        if highest_severity in ("MEDIUM", "LOW"):
            return "APPROVE"
        return "APPROVE"
