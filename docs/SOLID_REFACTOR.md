# SOLID Refactor Summary

## What Changed

- Split monolithic `AgentRunner` responsibilities into:
  - `PromptBuilder`
  - `OutputParser`
  - orchestration-focused `AgentRunner`
- Consolidated agent metadata into `AgentConfig` + `AGENTS`
- Introduced `PRClientProtocol` and typed against protocol in runner flow
- Added `run_subset()` to avoid forcing all-agent execution
- Injected `cli_runner` for testable CLI execution
- Split `ReportBuilder` internals into `VerdictEngine`, `MarkdownFormatter`, `JsonFormatter`
- Split rules module into model/registry/formatter files with compatibility shim

## Before / After

Single Responsibility:
- Before: one class handled prompt building, parsing, invocation, severity ranking.
- After: separate focused classes with narrow responsibilities.

Open/Closed:
- Before: adding an agent required updating multiple dictionaries.
- After: add one `AgentConfig` entry.

Liskov Substitution:
- Before: concrete client type assumptions.
- After: `PRClientProtocol` supports interchangeable PR clients.

Interface Segregation:
- Before: only `run_all` existed.
- After: `run_subset` enables targeted execution.

Dependency Inversion:
- Before: direct `subprocess.run` hard dependency.
- After: `cli_runner` injectable callable.

## Class Diagram

```text
AgentRunner
  uses -> PromptBuilder
  uses -> OutputParser
  depends on -> cli_runner(callable)

ReportBuilder
  uses -> VerdictEngine
  uses -> ReportFormatter (Protocol)
       -> MarkdownFormatter
       -> JsonFormatter

run_review.py
  depends on -> PRClientProtocol
             -> BitbucketClient
```

## Migration Guide

1. Existing `from rules.domain_rules import ...` imports remain valid.
2. `ReportBuilder.build(...)` still returns `(markdown_path, json_path)`.
3. If custom tools called `AgentRunner.run_all`, behavior is unchanged.
4. For partial runs, migrate to `AgentRunner.run_subset(["bug_detector"], context)`.
5. For custom CLI wrappers, pass `cli_runner` into `AgentRunner(...)`.
