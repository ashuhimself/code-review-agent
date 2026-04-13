# Agents

## security_scanner
Purpose: detect exploitable security weaknesses in Airflow DAG and helper code.

Catches:
- hardcoded credentials and secret leakage vectors
- shell/SQL/code injection patterns
- unsafe TLS and insecure config exposure

Does not catch:
- non-security style issues
- scheduler-only performance issues

Severity guidance:
- `CRITICAL`: direct secret exposure or RCE-class path
- `HIGH`: realistic exploit path requiring limited access
- `MEDIUM/LOW`: hardening issues

Dataset awareness:
- no dataset topology validation (handled elsewhere)

## bug_detector
Purpose: detect runtime bugs, race conditions, retries/idempotency breakage.

Catches:
- Airflow scheduler pitfalls (`start_date`, `catchup`, triggers)
- ANZ-specific Teradata/S3 idempotency risks
- module-level parse-time performance hazards

Does not catch:
- naming/style consistency
- deep security hardening beyond bug impact

Severity guidance:
- `CRITICAL`: data corruption or systemic outage risk
- `HIGH`: likely production failure under retry/load
- `MEDIUM/LOW`: bounded failure modes

Dataset awareness:
- consumes dataset map when project scope is provided
- evaluates producer/consumer completeness and timing hazards

## test_coverage
Purpose: identify missing tests and provide concrete pytest additions.

Catches:
- missing DAG structure tests
- untested branches/failure handling/idempotency paths

Does not catch:
- runtime defects directly unless tied to missing tests

Severity guidance:
- `HIGH`: missing DAG-structure and critical failure-path tests
- `MEDIUM/LOW`: edge and helper gaps

Dataset awareness:
- indirect only via suggested test scenarios

## consistency_checker
Purpose: enforce cross-file consistency and ANZ platform conventions.

Catches:
- convention drift (`@task`, connection IDs, datetime usage)
- dataset URI mismatch between producers and consumers
- inconsistent imports and helper usage

Does not catch:
- low-level runtime bugs not related to consistency

Severity guidance:
- `CRITICAL`: producer/consumer dataset URI mismatches
- `HIGH`: convention violations likely to break production behavior
- `MEDIUM/LOW`: maintainability and consistency issues

Dataset awareness:
- validates URI convention and exact producer/consumer matching

## domain_linter
Purpose: run focused Airflow 2.x domain checks for approved team topics.

Catches:
- sensor configuration and mode issues
- deprecated/removed operators and imports
- callback safety, pools, dagrun timeout, SLA
- dataset usage correctness without treating Dataset scheduling as invalid

Does not catch:
- generic bug-detector concerns already delegated
- broad style or security checks

Severity guidance:
- `HIGH`: removed APIs or high-risk runtime misconfigurations
- `MEDIUM/LOW`: deprecated patterns and hygiene gaps

Dataset awareness:
- confirms Dataset scheduling pattern integrity
- flags consumer datasets without producers
