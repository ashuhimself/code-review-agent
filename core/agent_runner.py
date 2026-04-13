"""Agent runner orchestration and CLI interaction for the review pipeline."""

from __future__ import annotations

import json
import logging
import os
import shutil
import subprocess
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Callable

import yaml

from rules.domain_rules import Severity, build_rules_context

LOGGER = logging.getLogger(__name__)

CONFIG_PATH = Path(__file__).parent.parent / "config.yaml"
PROMPTS_DIR = Path(__file__).parent.parent / "prompts"

ANZ_PLATFORM_CONTEXT = """## Platform Context

Stack: Apache Airflow 2.x on Astronomer MACP (Managed Airflow Control Plane)
Storage: S3-compatible NetApp StorageGrid - use boto3
Database: Teradata - use teradatasql directly (not SQLAlchemy)
Secrets: HashiCorp Vault injected via Astronomer - never os.environ for credentials
Infrastructure: Kubernetes/OpenShift (dos-build namespace)
CI/CD: Jenkins pipelines, Artifactory for image promotion

Team conventions (violations are HIGH severity):
- NO @task decorator - classic operators only (PythonOperator, BashOperator etc.)
- NO TaskFlow API - no @dag decorator either
- Dataset() scheduling IS used and encouraged - check it is implemented correctly
- ALL S3 reads must have a preceding S3KeySensor for each file
- ALL datetimes via pendulum.now('UTC') - never datetime.now() or datetime.utcnow()
- Vault for ALL credentials - Airflow connections for DB/S3, never hardcoded
- Connection ID pattern: {system}_{env} e.g. teradata_nonprod, s3_prod
- pendulum.datetime() for start_date - always static, never dynamic

Project structure:
  dags/{stage}/{project}/dag_file.py
  stages: ingest | transform | standardise | publish (transform/standardise/publish optional)
  shared utils: plugins/{project}/ and plugins/shared/

Dataset scheduling pattern used by this team:
  Producer DAG: task >> outlet task with outlets=[Dataset('s3://bucket/path')]
  Consumer DAG: schedule=[Dataset('s3://bucket/path')]
  URI convention: s3://{bucket}/{project}/{stage}/{entity}
"""


@dataclass(frozen=True)
class AgentConfig:
    """Single-source configuration for one review agent."""

    name: str
    display_name: str
    prompt_file: str
    rule_categories: list[str]


AGENTS: list[AgentConfig] = [
    AgentConfig(
        name="security_scanner",
        display_name="Security & Secrets Scanner",
        prompt_file="security_scanner.json",
        rule_categories=["security"],
    ),
    AgentConfig(
        name="bug_detector",
        display_name="Bug & Logic Detector",
        prompt_file="bug_detector.json",
        rule_categories=["airflow", "python", "teradata", "dataset"],
    ),
    AgentConfig(
        name="test_coverage",
        display_name="Test Coverage + TDD Suggester",
        prompt_file="test_coverage.json",
        rule_categories=["python"],
    ),
    AgentConfig(
        name="consistency_checker",
        display_name="Cross-file Consistency Checker",
        prompt_file="consistency_checker.json",
        rule_categories=["python", "teradata", "dataset"],
    ),
    AgentConfig(
        name="domain_linter",
        display_name="Airflow Domain Linter",
        prompt_file="domain_linter.json",
        rule_categories=["airflow", "dataset"],
    ),
]

AGENT_ORDER: list[str] = [agent.name for agent in AGENTS]


def _load_config() -> dict[str, object]:
    """Load YAML config, returning defaults on parse failure."""

    defaults: dict[str, object] = {
        "timeout_seconds": 300,
        "max_tokens": 16000,
        "base_branch": "main",
    }
    if not CONFIG_PATH.exists():
        return defaults
    try:
        with open(CONFIG_PATH, encoding="utf-8") as handle:
            raw = yaml.safe_load(handle) or {}
    except yaml.YAMLError:
        LOGGER.warning("Failed to parse config.yaml, using defaults", exc_info=True)
        return defaults
    if not isinstance(raw, dict):
        return defaults
    return {**defaults, **raw}


class PromptBuilder:
    """Build full prompts with platform/rules context and optional dataset map."""

    def __init__(self, platform_context: str, dataset_map: dict | None = None):
        self.platform_context = platform_context.strip()
        self.dataset_map = dataset_map

    def build(
        self,
        agent: AgentConfig,
        agent_prompt: str,
        rules_context: str,
        code_context: str,
    ) -> str:
        sections = [agent_prompt.strip(), "", self.platform_context, ""]
        if self.dataset_map and agent.name in {"bug_detector", "consistency_checker"}:
            sections.extend([self._dataset_context(), ""])
        sections.extend([rules_context.strip(), "", "## Code to Review", "", code_context])
        return "\n".join(sections)

    def _dataset_context(self) -> str:
        assert self.dataset_map is not None
        errors = [f"[DATASET ERROR] {msg}" for msg in self.dataset_map.get("errors", [])]
        payload = {
            "project": self.dataset_map.get("project"),
            "datasets": self.dataset_map.get("datasets", {}),
            "warnings": self.dataset_map.get("warnings", []),
            "errors": errors,
        }
        return "## Dataset Map\n\n```json\n" + json.dumps(payload, indent=2) + "\n```"


class OutputParser:
    """Parser helpers for JSONL and prose output from CLI agents."""

    @staticmethod
    def parse_jsonl(raw: str, agent_name: str) -> tuple[list[dict], dict]:
        findings: list[dict] = []
        summary: dict = {}
        if not raw.strip():
            return findings, summary

        for line in raw.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
            except json.JSONDecodeError:
                continue

            if isinstance(obj.get("result"), str):
                inner_f, inner_s = OutputParser.parse_jsonl(obj["result"], agent_name)
                findings.extend(inner_f)
                if inner_s:
                    summary = inner_s
                continue

            if obj.get("type") == "finding":
                findings.append(obj)
            elif obj.get("type") == "summary":
                summary = obj

        if not findings and not summary:
            findings, summary = OutputParser.extract_json_from_prose(raw)
        return findings, summary

    @staticmethod
    def extract_json_from_prose(text: str) -> tuple[list[dict], dict]:
        """Find balanced JSON objects in prose, including nested braces."""

        findings: list[dict] = []
        summary: dict = {}
        depth = 0
        start = -1
        in_string = False
        escaped = False

        for idx, ch in enumerate(text):
            if in_string:
                if escaped:
                    escaped = False
                elif ch == "\\":
                    escaped = True
                elif ch == '"':
                    in_string = False
                continue

            if ch == '"':
                in_string = True
                continue

            if ch == "{":
                if depth == 0:
                    start = idx
                depth += 1
            elif ch == "}":
                if depth == 0:
                    continue
                depth -= 1
                if depth == 0 and start >= 0:
                    candidate = text[start : idx + 1]
                    try:
                        obj = json.loads(candidate)
                    except json.JSONDecodeError:
                        continue
                    if obj.get("type") == "finding":
                        findings.append(obj)
                    elif obj.get("type") == "summary":
                        summary = obj
        return findings, summary

    @staticmethod
    def highest_severity(findings: list[dict]) -> Severity | None:
        ordered = [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW]
        found = {str(item.get("severity", "")).upper() for item in findings}
        for severity in ordered:
            if severity.value in found:
                return severity
        return None


class AgentRunner:
    """Run agent prompts through Copilot CLI and parse normalized outputs."""

    def __init__(
        self,
        timeout: int | None = None,
        max_tokens: int | None = None,
        copilot_bin: str = "copilot",
        cli_runner: Callable[[list[str], str], tuple[str, str]] | None = None,
        prompt_builder: PromptBuilder | None = None,
    ):
        config = _load_config()
        self.timeout = int(timeout or config.get("timeout_seconds", 300))
        self.max_tokens = int(max_tokens or config.get("max_tokens", 16000))
        self.copilot_bin = copilot_bin
        self.cli_runner = cli_runner or self._default_cli_runner
        self.prompt_builder = prompt_builder or PromptBuilder(ANZ_PLATFORM_CONTEXT)
        self._agent_index = {agent.name: agent for agent in AGENTS}
        self._prompts = self._load_prompts(PROMPTS_DIR)

    def run(self, agent_name: str, prompt: str | None, context: str) -> dict:
        """Run one configured agent and return normalized result payload."""

        agent = self._agent_index[agent_name]
        prompt_text = prompt or self._prompts[agent.name]
        rules_ctx = build_rules_context(agent.rule_categories)
        full_prompt = self.prompt_builder.build(agent, prompt_text, rules_ctx, context)
        raw_output, error = self._invoke_copilot(full_prompt)
        findings, summary = OutputParser.parse_jsonl(raw_output, agent_name)
        highest = OutputParser.highest_severity(findings)
        return {
            "agent": agent_name,
            "display_name": agent.display_name,
            "findings": findings,
            "severity": highest.value if highest else "NONE",
            "summary": summary,
            "raw": raw_output,
            "error": error,
        }

    def run_subset(self, agent_names: list[str], context: str) -> list[dict]:
        """Run a subset of agents in order."""

        results: list[dict] = []
        total = len(agent_names)
        for idx, name in enumerate(agent_names, start=1):
            agent = self._agent_index[name]
            LOGGER.info("[%s/%s] Running: %s", idx, total, agent.display_name)
            started = time.time()
            result = self.run(name, None, context)
            elapsed = time.time() - started
            timed_out = bool(result["error"] and "Timeout" in str(result["error"]))
            status = "TIMEOUT" if timed_out else "Done"
            LOGGER.info(
                "%s in %.1fs - %s finding(s), highest: %s",
                status,
                elapsed,
                len(result["findings"]),
                result["severity"],
            )
            results.append(result)
        return results

    def run_all(self, context: str) -> list[dict]:
        """Run all configured agents."""

        return self.run_subset([agent.name for agent in AGENTS], context)

    def _invoke_copilot(self, prompt: str) -> tuple[str, str | None]:
        """Invoke gh/copilot with robust fallback strategy."""

        gh_bin = shutil.which("gh")
        copilot_bin = shutil.which(self.copilot_bin)

        if gh_bin:
            try:
                # Prefer gh copilot with stdin to avoid command-line arg limits.
                return self.cli_runner([gh_bin, "copilot", "explain"], prompt)[0], None
            except Exception as exc:  # noqa: BLE001
                # If stdin pipe handling fails, retry using a temporary prompt file.
                if self._is_stdin_pipe_failure(exc):
                    temp_path: str | None = None
                    try:
                        with tempfile.NamedTemporaryFile(
                            mode="w", encoding="utf-8", delete=False
                        ) as handle:
                            handle.write(prompt)
                            temp_path = handle.name
                        output, stderr = self._default_cli_runner(
                            [gh_bin, "copilot", "explain", f"@{temp_path}"], ""
                        )
                        return output, stderr or None
                    except subprocess.TimeoutExpired:
                        return "", f"Timeout after {self.timeout}s"
                    except Exception as temp_exc:  # noqa: BLE001
                        return "", str(temp_exc)
                    finally:
                        if temp_path and os.path.exists(temp_path):
                            os.unlink(temp_path)
                return "", str(exc)

        if copilot_bin:
            # Fallback to legacy `copilot -p` for environments without GitHub CLI.
            cmd = [copilot_bin, "-p", prompt, "--output-format", "json"]
            try:
                stdout, stderr = self.cli_runner(cmd, "")
                return stdout, stderr or None
            except subprocess.TimeoutExpired:
                return "", f"Timeout after {self.timeout}s"
            except Exception as exc:  # noqa: BLE001
                return "", str(exc)

        return "", "Neither 'gh' nor 'copilot' CLI is available. Install one and authenticate first."

    def _default_cli_runner(self, cmd: list[str], stdin_input: str) -> tuple[str, str]:
        proc = subprocess.run(
            cmd,
            input=stdin_input,
            capture_output=True,
            text=True,
            timeout=self.timeout,
            check=False,
        )
        return proc.stdout, proc.stderr.strip()

    @staticmethod
    def _is_stdin_pipe_failure(exc: Exception) -> bool:
        message = str(exc).lower()
        return isinstance(exc, (BrokenPipeError, OSError)) or "broken pipe" in message

    @staticmethod
    def _load_prompts(prompts_dir: Path) -> dict[str, str]:
        prompts: dict[str, str] = {}
        for agent in AGENTS:
            path = prompts_dir / agent.prompt_file
            payload = json.loads(path.read_text(encoding="utf-8"))
            lines = payload.get("prompt")
            if isinstance(lines, list):
                prompts[agent.name] = "\n".join(str(line) for line in lines)
            elif isinstance(lines, str):
                prompts[agent.name] = lines
            else:
                raise ValueError(f"Invalid prompt format in {path}")
        return prompts
