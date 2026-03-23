#!/usr/bin/env python3
"""
run_review.py — Orchestrates all agents and builds reports.
Called by review.sh with context already assembled.
"""

import argparse
import json
import sys
from pathlib import Path

# Ensure project root is importable
sys.path.insert(0, str(Path(__file__).parent))

from core.agent_runner import AgentRunner
from core.report_builder import ReportBuilder


def main():
    parser = argparse.ArgumentParser(description="AI Code Review Agent")
    parser.add_argument("--context-file", required=True, help="Path to file containing code context")
    parser.add_argument("--context-label", default="unknown", help="Human-readable scope label")
    parser.add_argument("--output-dir", default=".", help="Directory for report output")
    args = parser.parse_args()

    context_path = Path(args.context_file)
    if not context_path.exists():
        print(f"Error: context file not found: {args.context_file}", file=sys.stderr)
        sys.exit(1)

    context_content = context_path.read_text(encoding="utf-8")

    # Run all 5 agents
    runner = AgentRunner()
    results = runner.run_all(context_content)

    # Build reports
    print()
    builder = ReportBuilder(output_dir=args.output_dir)
    md_path, json_path = builder.build(results, context_label=args.context_label)

    # Display results
    summary = json.loads(json_path.read_text())
    verdict = summary.get("overall_verdict", "UNKNOWN")
    verdict_icons = {
        "APPROVE": "✅",
        "NEEDS_DISCUSSION": "🟡",
        "REQUEST_CHANGES": "🔴",
    }
    icon = verdict_icons.get(verdict, "")

    print()
    print(f"  Markdown report : {md_path}")
    print(f"  JSON summary    : {json_path}")
    print(f"  Overall verdict : {icon} {verdict}")
    print()

    # Per-agent summary
    print("  Agent Results:")
    for agent_name, agent_data in summary.get("agents", {}).items():
        name = agent_data.get("display_name", agent_name)
        count = agent_data.get("total_findings", 0)
        sev = agent_data.get("highest_severity", "NONE")
        print(f"    {name}: {count} finding(s), highest={sev}")

    # Exit with non-zero if REQUEST_CHANGES
    if verdict == "REQUEST_CHANGES":
        sys.exit(1)


if __name__ == "__main__":
    main()
