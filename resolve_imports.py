#!/usr/bin/env python3
"""
resolve_imports.py
Recursively resolves local imports from DAG files and returns all
reachable source file paths for review context.

Usage:
    python resolve_imports.py dag1.py dag2.py --repo-root /path/to/repo
"""

from __future__ import annotations

import argparse
import ast
import logging
import sys
from dataclasses import dataclass
from pathlib import Path

LOGGER = logging.getLogger(__name__)

KNOWN_THIRD_PARTY = {
    "airflow",
    "boto3",
    "botocore",
    "requests",
    "yaml",
    "pendulum",
    "pytest",
    "teradatasql",
}


@dataclass(frozen=True)
class ImportRef:
    """AST-extracted import reference."""

    module: str
    level: int


class ImportExtractor:
    """Extract import references from a Python source file using AST."""

    def extract(self, file_path: Path) -> list[ImportRef]:
        try:
            source = file_path.read_text(encoding="utf-8")
            tree = ast.parse(source, filename=str(file_path))
        except SyntaxError:
            LOGGER.warning("Skipping file with SyntaxError: %s", file_path)
            return []
        except OSError as exc:
            LOGGER.warning("Skipping unreadable file %s: %s", file_path, exc)
            return []

        refs: list[ImportRef] = []
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    refs.append(ImportRef(module=alias.name, level=0))
            elif isinstance(node, ast.ImportFrom):
                module_name = node.module or ""
                refs.append(ImportRef(module=module_name, level=node.level))
        return refs


class ImportResolver:
    """Resolve module names to local file paths using repo roots."""

    def __init__(self, repo_root: Path):
        self.repo_root = repo_root
        self.search_roots = [repo_root, repo_root / "dags", repo_root / "plugins"]

    def resolve(self, ref: ImportRef, source_file: Path) -> Path | None:
        top_level = ref.module.split(".")[0] if ref.module else ""
        if top_level in sys.stdlib_module_names or top_level in KNOWN_THIRD_PARTY:
            return None

        if ref.level > 0:
            base = source_file.parent
            for _ in range(ref.level - 1):
                base = base.parent
            suffix = Path(*ref.module.split(".")) if ref.module else Path()
            return self._resolve_candidate(base / suffix)

        module_path = Path(*ref.module.split(".")) if ref.module else Path()
        for root in self.search_roots:
            resolved = self._resolve_candidate(root / module_path)
            if resolved:
                return resolved
        return None

    @staticmethod
    def _resolve_candidate(path: Path) -> Path | None:
        file_candidate = path.with_suffix(".py")
        if file_candidate.exists():
            return file_candidate.resolve()
        init_candidate = path / "__init__.py"
        if init_candidate.exists():
            return init_candidate.resolve()
        return None


class SourceCollector:
    """Recursively collect all local source files reachable through imports."""

    def __init__(self, extractor: ImportExtractor, resolver: ImportResolver):
        self.extractor = extractor
        self.resolver = resolver
        self.visited: set[Path] = set()

    def collect(self, roots: list[Path]) -> list[Path]:
        for root in roots:
            self._walk(root.resolve())
        return sorted(self.visited)

    def _walk(self, file_path: Path) -> None:
        if file_path in self.visited:
            return
        if not file_path.exists() or file_path.suffix != ".py":
            return

        self.visited.add(file_path)
        for ref in self.extractor.extract(file_path):
            resolved = self.resolver.resolve(ref, file_path)
            if resolved:
                self._walk(resolved)


def find_repo_root(start: Path) -> Path:
    """Walk upward to locate .git marker and return repo root."""

    current = start.resolve()
    for candidate in [current, *current.parents]:
        if (candidate / ".git").exists():
            return candidate
    return start.resolve()


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Resolve local imports recursively")
    parser.add_argument("files", nargs="*", help="Seed Python files")
    parser.add_argument("--repo-root", help="Optional repository root")
    parser.add_argument("--verbose", action="store_true", help="Enable debug logging")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    logging.basicConfig(level=logging.DEBUG if args.verbose else logging.WARNING)

    if not args.files:
        return 0

    supplied = [Path(item) for item in args.files]
    root_hint = Path(args.repo_root) if args.repo_root else Path.cwd()
    repo_root = find_repo_root(root_hint)

    extractor = ImportExtractor()
    resolver = ImportResolver(repo_root=repo_root)
    collector = SourceCollector(extractor=extractor, resolver=resolver)
    collected = collector.collect(supplied)

    for path in collected:
        sys.stdout.write(f"{path}\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
