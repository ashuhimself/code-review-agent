#!/usr/bin/env python3
"""Orchestrates agents, report generation, and optional PR comment publishing."""

from __future__ import annotations

import argparse
import json
import logging
import subprocess
import sys
from pathlib import Path

from core.agent_runner import AGENTS, ANZ_PLATFORM_CONTEXT, AgentRunner, PromptBuilder
from core.bitbucket_client import BitbucketClient, PRClientProtocol
from core.models import Verdict
from core.report_builder import ReportBuilder

LOGGER = logging.getLogger(__name__)


class ConsoleReporter:
    """Handles user-facing console output for CLI execution."""

    def __init__(self, stream: object = sys.stdout):
        self.stream = stream

    def line(self, text: str = "") -> None:
        print(text, file=self.stream)

    def heading(self, scope: str) -> None:
        self.line("============================================================")
        self.line("  AI Code Review Agent")
        self.line(f"  Scope: {scope}")
        self.line("============================================================")

    def summarize(self, md_path: Path, json_path: Path, summary: dict) -> None:
        verdict = summary.get("overall_verdict", "UNKNOWN")
        self.line("")
        self.line(f"  Markdown report : {md_path}")
        self.line(f"  JSON summary    : {json_path}")
        self.line(f"  Overall verdict : {verdict}")
        self.line("")
        self.line("  Agent Results:")
        for agent_name, payload in summary.get("agents", {}).items():
            name = payload.get("display_name", agent_name)
            count = payload.get("total_findings", 0)
            highest = payload.get("highest_severity", "NONE")
            self.line(f"    {name}: {count} finding(s), highest={highest}")


def _setup_logging(verbose: bool) -> None:
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(level=level, format="%(levelname)s %(name)s: %(message)s")


def _scan_dataset_map(project: str, dags_root: str) -> dict | None:
    scanner = Path(__file__).parent / "dataset_scanner.py"
    if not scanner.exists():
        return None
    cmd = [
        sys.executable,
        str(scanner),
        "--project",
        project,
        "--dags-root",
        dags_root,
    ]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, check=False, timeout=120)
        if proc.returncode != 0:
            LOGGER.warning("dataset_scanner returned non-zero exit code: %s", proc.stderr.strip())
            return None
        return json.loads(proc.stdout)
    except Exception as exc:  # noqa: BLE001
        LOGGER.warning("Failed to run dataset scanner: %s", exc)
        return None


def _post_pr_comment(client: PRClientProtocol, pr_id: int, markdown_content: str) -> None:
    try:
        posted = client.post_pr_comment(pr_id, markdown_content)
        if not posted:
            LOGGER.warning("PR comment was not posted for PR #%s", pr_id)
    except Exception as exc:  # noqa: BLE001
        LOGGER.warning("PR comment failed for PR #%s: %s", pr_id, exc)


def main() -> None:
    parser = argparse.ArgumentParser(description="AI Code Review Agent")
    parser.add_argument("--context-file", required=True, help="Path to review context file")
    parser.add_argument("--context-label", default="unknown", help="Human-readable review scope")
    parser.add_argument("--output-dir", default=".", help="Directory for report output")
    parser.add_argument("--report-prefix", default="review", help="Prefix for markdown report filename")
    parser.add_argument("--project", help="Project key for dataset-aware review")
    parser.add_argument("--dags-root", default="dags", help="Root dags directory for project scan")
    parser.add_argument("--pr", type=int, help="Optional pull request id to comment on")
    parser.add_argument("--verbose", action="store_true", help="Enable debug logging")
    args = parser.parse_args()

    _setup_logging(args.verbose)
    reporter = ConsoleReporter()

    context_path = Path(args.context_file)
    if not context_path.exists():
        LOGGER.error("Context file not found: %s", args.context_file)
        sys.exit(1)

    context_content = context_path.read_text(encoding="utf-8")
    dataset_map = _scan_dataset_map(args.project, args.dags_root) if args.project else None

    prompt_builder = PromptBuilder(ANZ_PLATFORM_CONTEXT, dataset_map=dataset_map)
    runner = AgentRunner(prompt_builder=prompt_builder)

    reporter.line("")
    reporter.heading(args.context_label)
    reporter.line("")
    reporter.line(f"Running {len(AGENTS)} agents...")
    reporter.line("")

    results = runner.run_all(context_content)

    builder = ReportBuilder(output_dir=args.output_dir)
    md_path, json_path = builder.build(
        results,
        context_label=args.context_label,
        markdown_prefix=args.report_prefix,
    )

    summary = json.loads(json_path.read_text(encoding="utf-8"))
    reporter.summarize(md_path, json_path, summary)

    if args.pr:
        client: PRClientProtocol = BitbucketClient()
        markdown_content = md_path.read_text(encoding="utf-8")
        _post_pr_comment(client, args.pr, markdown_content)

    if summary.get("overall_verdict") == Verdict.REQUEST_CHANGES.value:
        sys.exit(1)


if __name__ == "__main__":
    main()
