# Usage And Quality Gate

This guide explains how to run the review agent correctly and how to enforce a strict gate so bad changes are blocked before merge.

## 1. Local Usage

Single file:

```bash
./review.sh --file dags/ingest/ccr/my_dag.py
```

Directory scope:

```bash
./review.sh --dir dags/ingest/
```

Project scope with dataset validation:

```bash
./review.sh --project ccr
./review.sh --project ccr --stage ingest
```

PR comment posting:

```bash
./review.sh --project ccr --pr 142
./review.sh --file dags/ingest/ccr/my_dag.py --pr 142
```

## 2. What Must Be Checked Every Time

Run these commands in order:

```bash
uvx ruff format --check .
./review.sh --project ccr
python -m pytest tests/ -v
python -m mypy core/ rules/ --strict
```

Interpretation:
- `review.sh` exit code `1` means `REQUEST_CHANGES` (hard fail).
- `uvx ruff format --check .` must pass for PEP8/style conformance.
- `pytest` must be fully green.
- `mypy --strict` must have zero type errors.

If formatting check fails, run:

```bash
uvx ruff format .
```

Alternative when using uv-managed project env:

```bash
uv run ruff format .
```

## 3. Hard Gate Policy (Recommended)

Treat the following as merge blockers:
- PEP8/format check failure
- Overall verdict is `REQUEST_CHANGES`
- Any `CRITICAL` finding in `summary.json`
- 3 or more `HIGH` findings in `summary.json`
- Any dataset scanner error in project mode
- Test failures
- Type-check failures

Additional policy:
- Dangerous general coding-principle violations (exception swallowing, unsafe resource handling, non-idempotent writes) are blockers when severity is HIGH/CRITICAL.
- Idempotency violations are always priority findings and should be treated as release risk.

## 4. CI Pipeline Example

```bash
#!/usr/bin/env bash
set -euo pipefail

./review.sh --project ccr
python -m pytest tests/ -v
python -m mypy core/ rules/ --strict

python - <<'PY'
import json
from pathlib import Path

summary = json.loads(Path('summary.json').read_text(encoding='utf-8'))
verdict = summary.get('overall_verdict', 'UNKNOWN')
if verdict == 'REQUEST_CHANGES':
    raise SystemExit('Blocking merge: overall verdict REQUEST_CHANGES')

critical = 0
high = 0
for agent in summary.get('agents', {}).values():
    for finding in agent.get('findings', []):
        sev = str(finding.get('severity', '')).upper()
        if sev == 'CRITICAL':
            critical += 1
        elif sev == 'HIGH':
            high += 1

if critical > 0:
    raise SystemExit(f'Blocking merge: {critical} CRITICAL findings')
if high >= 3:
    raise SystemExit(f'Blocking merge: {high} HIGH findings')

print('Quality gate passed')
PY
```

## 5. Avoiding False Negatives

To reduce the chance of incorrect code passing review:
- Use project mode (`--project`) for dataset-aware analysis instead of file-only runs.
- Ensure all affected DAGs and shared plugin files are included in review scope.
- Keep rules in `rules/rule_registry.py` updated when incidents happen.
- Tighten prompts in `prompts/*.json` with concrete failure patterns from production.
- Add regression tests for every escaped bug.

## 6. Branch Protection Settings

At repository level, require these checks before merge:
- `review-gate` job (runs `review.sh` and summary gate script)
- `pytest` job
- `mypy-strict` job

Do not allow bypass on protected branches except for designated release admins.

## 7. Operational Notes

No automated review system can guarantee 100% defect detection. The best practical protection is layered enforcement:
- AI review gate
- deterministic tests
- strict type checks
- protected branch policy
- incident-driven rule/test updates
