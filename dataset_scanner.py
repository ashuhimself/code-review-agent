#!/usr/bin/env python3
"""
dataset_scanner.py
Scans all DAGs in a project and builds a cross-stage Dataset/S3
dependency map. Validates URI consistency between producers and consumers.

Usage:
    python dataset_scanner.py --project ccr --dags-root dags/
"""

from __future__ import annotations

import argparse
import ast
import json
import logging
import re
import sys
from dataclasses import dataclass
from pathlib import Path

LOGGER = logging.getLogger(__name__)
URI_PATTERN = re.compile(r"^s3://[^/]+/[^/]+/[^/]+/[^/]+/?$")


@dataclass(frozen=True)
class DatasetRef:
    uri: str
    role: str
    dag_id: str
    file_path: str


class DatasetExtractor:
    """Extract Dataset(uri) usage in schedules and outlets."""

    def extract(self, file_path: Path) -> list[DatasetRef]:
        try:
            tree = ast.parse(file_path.read_text(encoding="utf-8"), filename=str(file_path))
        except SyntaxError:
            LOGGER.warning("Skipping syntax error file: %s", file_path)
            return []

        dag_id = self._find_dag_id(tree) or file_path.stem
        refs: list[DatasetRef] = []

        for node in ast.walk(tree):
            if isinstance(node, ast.keyword) and node.arg == "schedule":
                refs.extend(self._extract_dataset_calls(node.value, "consumer", dag_id, str(file_path)))
            if isinstance(node, ast.keyword) and node.arg == "outlets":
                refs.extend(self._extract_dataset_calls(node.value, "producer", dag_id, str(file_path)))
            if isinstance(node, ast.Assign):
                target_names = {
                    target.id
                    for target in node.targets
                    if isinstance(target, ast.Name)
                }
                if "schedule" in target_names:
                    refs.extend(self._extract_dataset_calls(node.value, "consumer", dag_id, str(file_path)))
                if "outlets" in target_names:
                    refs.extend(self._extract_dataset_calls(node.value, "producer", dag_id, str(file_path)))

        return refs

    @staticmethod
    def _find_dag_id(tree: ast.AST) -> str | None:
        for node in ast.walk(tree):
            if isinstance(node, ast.keyword) and node.arg == "dag_id":
                if isinstance(node.value, ast.Constant) and isinstance(node.value.value, str):
                    return node.value.value
        return None

    def _extract_dataset_calls(self, node: ast.AST, role: str, dag_id: str, file_path: str) -> list[DatasetRef]:
        refs: list[DatasetRef] = []
        for candidate in ast.walk(node):
            if isinstance(candidate, ast.Call) and self._call_name(candidate.func) == "Dataset":
                if candidate.args and isinstance(candidate.args[0], ast.Constant):
                    value = candidate.args[0].value
                    if isinstance(value, str):
                        refs.append(DatasetRef(uri=value, role=role, dag_id=dag_id, file_path=file_path))
        return refs

    @staticmethod
    def _call_name(node: ast.AST) -> str:
        if isinstance(node, ast.Name):
            return node.id
        if isinstance(node, ast.Attribute):
            return node.attr
        return ""


class S3PathExtractor:
    """Extract S3 references from key sensor/hook patterns."""

    def extract(self, file_path: Path) -> list[str]:
        try:
            tree = ast.parse(file_path.read_text(encoding="utf-8"), filename=str(file_path))
        except SyntaxError:
            return []

        paths: list[str] = []
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                call_name = self._call_name(node.func)
                if call_name in {"S3KeySensor", "S3Hook", "get_key", "read_key", "check_for_key"}:
                    for arg in node.args:
                        if isinstance(arg, ast.Constant) and isinstance(arg.value, str) and arg.value.startswith("s3://"):
                            paths.append(arg.value)
                    for kw in node.keywords:
                        if isinstance(kw.value, ast.Constant) and isinstance(kw.value.value, str) and kw.value.value.startswith("s3://"):
                            paths.append(kw.value.value)
        return paths

    @staticmethod
    def _call_name(node: ast.AST) -> str:
        if isinstance(node, ast.Name):
            return node.id
        if isinstance(node, ast.Attribute):
            return node.attr
        return ""


class DependencyMapper:
    """Build dataset producer/consumer index."""

    def build(self, refs: list[DatasetRef]) -> dict[str, dict[str, list[dict[str, str]]]]:
        datasets: dict[str, dict[str, list[dict[str, str]]]] = {}
        for ref in refs:
            entry = datasets.setdefault(ref.uri, {"producers": [], "consumers": []})
            payload = {"dag": ref.dag_id, "file": ref.file_path}
            if ref.role == "producer":
                entry["producers"].append(payload)
            else:
                entry["consumers"].append(payload)
        return datasets


class ValidationEngine:
    """Validate producer/consumer consistency and naming conventions."""

    def validate(self, datasets: dict[str, dict[str, list[dict[str, str]]]]) -> tuple[list[str], list[str]]:
        warnings: list[str] = []
        errors: list[str] = []

        for uri, mapping in datasets.items():
            producers = mapping.get("producers", [])
            consumers = mapping.get("consumers", [])

            if not producers:
                for consumer in consumers:
                    errors.append(
                        f"Consumer {consumer['dag']} depends on Dataset but no producer found"
                    )
            if not consumers:
                warnings.append(f"No consumer found for {uri}")

            if not URI_PATTERN.match(uri):
                warnings.append(
                    f"Dataset URI does not follow convention s3://{{bucket}}/{{project}}/{{stage}}/{{entity}}: {uri}"
                )

        uris = list(datasets.keys())
        for uri in uris:
            for other in uris:
                if uri == other:
                    continue
                if uri.rstrip("/") == other.rstrip("/") and uri != other:
                    errors.append(
                        f"URI mismatch: producer '{uri}' vs consumer '{other}' (trailing slash)"
                    )

        return warnings, sorted(set(errors))


def project_files(project: str, dags_root: Path) -> list[Path]:
    files: list[Path] = []
    for stage in ("ingest", "transform", "standardise", "publish"):
        stage_dir = dags_root / stage / project
        if stage_dir.exists():
            files.extend(sorted(stage_dir.rglob("*.py")))
    return files


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Scan Dataset producer/consumer dependencies")
    parser.add_argument("--project", required=True, help="Project key (e.g. ccr)")
    parser.add_argument("--dags-root", default="dags", help="DAGs root directory")
    parser.add_argument("--verbose", action="store_true", help="Enable debug logging")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    logging.basicConfig(level=logging.DEBUG if args.verbose else logging.WARNING)

    files = project_files(args.project, Path(args.dags_root))
    extractor = DatasetExtractor()
    s3_extractor = S3PathExtractor()
    mapper = DependencyMapper()
    validator = ValidationEngine()

    refs: list[DatasetRef] = []
    for file_path in files:
        refs.extend(extractor.extract(file_path))
        _ = s3_extractor.extract(file_path)

    datasets = mapper.build(refs)
    warnings, errors = validator.validate(datasets)

    output = {
        "project": args.project,
        "datasets": datasets,
        "warnings": warnings,
        "errors": errors,
    }
    sys.stdout.write(json.dumps(output, indent=2) + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
