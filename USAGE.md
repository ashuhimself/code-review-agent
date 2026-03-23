# Code Review Agent — Usage Guide

An AI-powered code review tool that runs 5 specialist agents against your Python/Airflow code and
produces a concise Markdown report with findings, locations, and fixes.

---

## Prerequisites

| Requirement | Details |
|-------------|---------|
| Python | 3.10+ |
| Copilot CLI | Installed and authenticated (`copilot --version`) |
| pip packages | `pip install -r requirements.txt` |

### Install dependencies

```bash
cd code-review-agent
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

### Authenticate Copilot CLI

```bash
copilot login
```

---

## Running a Review

All reviews go through `review.sh`. Make it executable once:

```bash
chmod +x review.sh
```

### Review a single file

```bash
./review.sh --file dags/my_dag.py
```

### Review a directory (changed files only vs base branch)

```bash
./review.sh --dir dags/
```

If no git changes are found, it falls back to scanning all `.py` files in the directory (max 20).

### Review all changed files on the current branch

```bash
./review.sh
```

Diffs the current branch against `main` (configurable — see [Configuration](#configuration)).
Requires being inside a git repository.

### Override the base branch

```bash
./review.sh --base-branch develop
./review.sh --file dags/etl.py --base-branch release/2.1
```

---

## Output

Two files are written after every run:

| File | Contents |
|------|---------|
| `review-YYYYMMDD_HHMMSS.md` | Human-readable report (findings, locations, fixes) |
| `summary.json` | Machine-readable results (all findings, severities, verdicts) |

### Report format

```
# Code Review: `dags/my_dag.py`
**Verdict:** 🔴 REQUEST_CHANGES · 2026-03-23 14:05:01

## Security & Secrets Scanner — 1 finding(s)

**🔴 CRITICAL** · `dags/my_dag.py:12`
Hardcoded Fernet key — decrypts all Variables and Connections in the metadata DB.
Fix: Inject via Kubernetes Secret, not hardcoded in the DAG file.

## Bug & Logic Detector — 0 finding(s)
_No findings._
```

### Verdict levels

| Verdict | Meaning | Trigger |
|---------|---------|---------|
| `APPROVE` | No significant issues | Only LOW findings or none |
| `NEEDS_DISCUSSION` | Issues worth reviewing | Any HIGH or MEDIUM finding |
| `REQUEST_CHANGES` | Must fix before merge | Any CRITICAL, or 3+ HIGH findings |

The process exits with code `1` on `REQUEST_CHANGES` — safe to use as a CI gate.

---

## The 5 Agents

Each agent runs independently and focuses on a different concern:

| Agent | Checks |
|-------|--------|
| **Security Scanner** | Hardcoded secrets, AWS keys, injection (eval/exec/shell), SSL bypass, unsafe deserialization |
| **Bug Detector** | Airflow scheduler bugs, XCom misuse, branching/trigger rule errors, idempotency, exception handling |
| **Test Coverage** | Missing tests, untested edge cases, TDD suggestions |
| **Consistency Checker** | Cross-file naming, import conventions, shared patterns |
| **Domain Linter** | Airflow-specific: retries, catchup, sensors, deprecated APIs, resource pools, Jinja templates |

---

## Configuration

Edit `config.yaml` to adjust behaviour:

```yaml
base_branch: main          # branch to diff against by default
timeout_seconds: 300       # max seconds per agent call
max_tokens: 16000          # max tokens per Claude response
```

---

## Domain Rules

Rules live in `rules/domain_rules.py` and are injected into each agent's prompt.
Each rule has an ID, severity, pattern, and fix hint.

| Prefix | Category | Example |
|--------|----------|---------|
| `SEC-` | Security | SEC-001: hardcoded password |
| `AF-`  | Airflow  | AF-005: `start_date = datetime.now()` |
| `PY-`  | Python   | PY-003: mutable default argument |

To add a rule, append a `Rule(...)` to the relevant list in `domain_rules.py`:

```python
Rule(
    id="AF-031",
    description="My new rule",
    pattern=r"some_regex_pattern",
    severity="HIGH",       # CRITICAL / HIGH / MEDIUM / LOW
    category="airflow",
    fix_hint="How to fix it.",
)
```

The rule is automatically picked up by the matching agent on the next run.

---

## Running Tests

```bash
source .venv/bin/activate
pytest tests/ -v
```

| Test file | Covers |
|-----------|--------|
| `test_agent_runner.py` | JSON parsing, severity ranking, subprocess handling |
| `test_report_builder.py` | Verdict logic, Markdown output, JSON output |
| `test_domain_rules.py` | Rule integrity, `build_rules_context`, `get_forbidden_patterns` |

---

## Project Layout

```
code-review-agent/
├── review.sh               # entry point — builds context, calls run_review.py
├── run_review.py           # orchestrates agents, writes reports
├── config.yaml             # base_branch, timeout, token limits
├── core/
│   ├── agent_runner.py     # Claude CLI invocation + JSONL parsing
│   └── report_builder.py   # Markdown + JSON report generation
├── rules/
│   └── domain_rules.py     # SEC / AF / PY rule definitions
└── tests/
    ├── test_agent_runner.py
    ├── test_report_builder.py
    └── test_domain_rules.py
```
