# Architecture

## Data Flow

```text
review.sh
  -> builds code context (+ resolve_imports)
  -> run_review.py
      -> dataset_scanner.py (optional --project)
      -> AgentRunner
          -> PromptBuilder
              -> platform context + optional dataset map + rules context + code context
          -> gh/copilot CLI
          -> OutputParser
      -> ReportBuilder
          -> VerdictEngine
          -> MarkdownFormatter
          -> JsonFormatter
      -> BitbucketClient.post_pr_comment (optional --pr)
```

## Core Classes

- `AgentConfig`: single-source metadata for each agent (`name`, `display_name`, `prompt_file`, categories).
- `PromptBuilder`: constructs full agent prompts and injects dataset map for selected agents.
- `OutputParser`: parses JSONL and prose-wrapped JSON outputs.
- `AgentRunner`: orchestration and CLI invocation only.
- `VerdictEngine`: pure verdict decision logic.
- `MarkdownFormatter`: markdown string generation.
- `JsonFormatter`: summary JSON generation.
- `ReportBuilder`: file output orchestration.
- `PRClientProtocol`: abstraction for PR comment clients.
- `BitbucketClient`: protocol implementation for Bitbucket API.
- `ImportExtractor` / `ImportResolver` / `SourceCollector`: recursive local import expansion.
- `DatasetExtractor` / `S3PathExtractor` / `DependencyMapper` / `ValidationEngine`: dataset topology scan.
