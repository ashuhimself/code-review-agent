# Code Review Agent

This repository provides an AI-assisted code review pipeline for Apache Airflow 2.x DAGs used on the ANZ platform stack (Astronomer MACP, NetApp StorageGrid S3, Teradata via `teradatasql`, and Vault-managed credentials). It assembles code context, runs five specialized review agents, and produces Markdown plus JSON outputs suitable for local review and CI gating.

## Agents

| Agent | Purpose | Primary categories |
|---|---|---|
| `security_scanner` | Secrets, injection risks, insecure runtime config | security |
| `bug_detector` | Runtime defects, scheduler pitfalls, idempotency/data correctness | airflow, python, teradata, dataset |
| `test_coverage` | Missing tests and branch/edge-case coverage | python |
| `consistency_checker` | Cross-file conventions and ANZ-specific consistency checks | python, teradata, dataset |
| `domain_linter` | Airflow 2.x domain checks + dataset implementation correctness | airflow, dataset |

## Quick Start

Prerequisites:
- Python 3.10+
- `gh` CLI with Copilot access or legacy `copilot` CLI
- Authenticated CLI session (`gh auth login`, `gh copilot` enabled)

Install:

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
chmod +x review.sh resolve_imports.py dataset_scanner.py
```

## Invocation Modes

```bash
./review.sh
./review.sh --file dags/ingest/ccr/example_dag.py
./review.sh --dir dags/ingest/
./review.sh --project ccr
./review.sh --project ccr --stage ingest
./review.sh --project ccr --stage transform
./review.sh --project ccr --stage standardise
./review.sh --project ccr --stage publish
./review.sh --project ccr --pr 142
./review.sh --file dags/ingest/ccr/example_dag.py --pr 142
```

## Output

Generated files:
- Markdown report: `review-<timestamp>.md` or `review-<project>-<stage>-<timestamp>.md`
- JSON summary: `summary.json`

Verdicts:
- `APPROVE`
- `NEEDS_DISCUSSION`
- `REQUEST_CHANGES`

Exit codes:
- `0`: non-blocking verdict
- `1`: `REQUEST_CHANGES` verdict or fatal runtime error

## Dataset Scheduling Review

When `--project` is used, `dataset_scanner.py` builds a producer/consumer map from Dataset outlets and schedules. The map is injected into `bug_detector` and `consistency_checker` prompts, and detected dataset errors are prefixed with `[DATASET ERROR]` in prompt context.

## Adding Rules

Rule authoring and registration process is documented in `docs/ADDING_RULES.md`.

## Project Layout

```text
review.sh                     # CLI entrypoint, scope selection, context assembly
run_review.py                 # orchestration, dataset injection, report generation, PR commenting
resolve_imports.py            # recursive local import expansion for review context
dataset_scanner.py            # project dataset dependency map and validation
config.yaml                   # runtime config defaults
core/models.py                # Verdict enum
core/agent_runner.py          # agent configs, prompt builder, CLI invocation, output parsing
core/report_builder.py        # verdict engine + markdown/json formatter pipeline
core/bitbucket_client.py      # PR client protocol + Bitbucket implementation
rules/rule_models.py          # Rule dataclass + Severity enum
rules/rule_registry.py        # rule lists and ALL_RULES registry
rules/rule_formatters.py      # rule context builders
rules/domain_rules.py         # backward-compatible re-export shim
prompts/*.json                # externalized agent prompts
tests/                        # unit tests
```

## Running Tests

```bash
pytest tests/ -v
mypy core/ rules/ --strict
```

## Operating Guide

- Usage and hard quality gate: `docs/USAGE_AND_QUALITY_GATE.md`
