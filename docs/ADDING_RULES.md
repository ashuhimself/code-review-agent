# Adding Rules

## 1. Choose The Rule List

Edit `rules/rule_registry.py` and add your rule to one list:
- `SECURITY_RULES`
- `AIRFLOW_RULES`
- `PYTHON_RULES`
- `TERADATA_RULES`
- `DATASET_RULES`

## 2. Add A `Rule(...)` Entry

Example:

```python
Rule(
    id="AF-999",
    severity=Severity.HIGH,
    category="airflow",
    description="Example airflow anti-pattern",
    pattern=r"my_regex",
    fix_hint="Concrete fix guidance",
)
```

## 3. Severity Decision Table

| Impact | Likelihood | Severity |
|---|---|---|
| Data loss, secret leak, exploit path | High | `CRITICAL` |
| Production failure or repeated incident | High/Medium | `HIGH` |
| Bounded reliability issue | Medium | `MEDIUM` |
| Minor hygiene/refactor concern | Low | `LOW` |

## 4. Register In `ALL_RULES`

Ensure your category list appears in `ALL_RULES` in `rules/rule_registry.py`.

## 5. Test

```bash
pytest tests/test_domain_rules.py -v
pytest tests/ -v
```

## Regex Tips

- Use raw strings (`r"..."`)
- Anchor carefully for multiline scans
- Prefer explicit groups over greedy wildcards
- Test against both positive and negative samples

## End-To-End Example: Teradata

Rule goal: prevent duplicate rows on retry.

1. Add to `TERADATA_RULES`:
- detect plain `INSERT INTO` without merge/upsert strategy

2. Add/extend tests:
- ensure category registration
- ensure severity is enum-based

3. Validate prompt coverage:
- `bug_detector` should include `teradata` categories

## End-To-End Example: Dataset

Rule goal: catch consumer Dataset with no producer.

1. Add to `DATASET_RULES` with category `dataset`
2. Ensure `bug_detector`, `consistency_checker`, and `domain_linter` include `dataset` in `rule_categories`
3. Add scanner-driven tests in `tests/test_dataset_scanner.py`
