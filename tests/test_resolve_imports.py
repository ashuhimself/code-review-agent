"""Tests for resolve_imports.py components."""

from __future__ import annotations

from pathlib import Path

from resolve_imports import ImportExtractor, ImportRef, ImportResolver, SourceCollector


def test_stdlib_and_third_party_skipped(tmp_path: Path) -> None:
    repo = tmp_path
    resolver = ImportResolver(repo_root=repo)
    source = repo / "a.py"
    source.write_text("import os\nimport requests\n", encoding="utf-8")

    assert resolver.resolve(ImportRef(module="os", level=0), source) is None
    assert resolver.resolve(ImportRef(module="requests", level=0), source) is None


def test_local_import_resolved(tmp_path: Path) -> None:
    (tmp_path / ".git").mkdir()
    (tmp_path / "dags").mkdir()
    target = tmp_path / "dags" / "helper.py"
    target.write_text("VALUE = 1\n", encoding="utf-8")

    resolver = ImportResolver(repo_root=tmp_path)
    source = tmp_path / "dags" / "main.py"
    source.write_text("import helper\n", encoding="utf-8")

    resolved = resolver.resolve(ImportRef(module="helper", level=0), source)
    assert resolved == target.resolve()


def test_missing_file_handled_gracefully(tmp_path: Path) -> None:
    bad = tmp_path / "bad.py"
    bad.write_text("def broken(:\n", encoding="utf-8")
    extractor = ImportExtractor()
    assert extractor.extract(bad) == []


def test_cycle_detection(tmp_path: Path) -> None:
    (tmp_path / ".git").mkdir()
    a = tmp_path / "a.py"
    b = tmp_path / "b.py"
    a.write_text("import b\n", encoding="utf-8")
    b.write_text("import a\n", encoding="utf-8")

    collector = SourceCollector(ImportExtractor(), ImportResolver(tmp_path))
    files = collector.collect([a])
    assert a.resolve() in files
    assert b.resolve() in files


def test_relative_import_resolution(tmp_path: Path) -> None:
    (tmp_path / ".git").mkdir()
    pkg = tmp_path / "plugins" / "p"
    pkg.mkdir(parents=True)
    (pkg / "__init__.py").write_text("", encoding="utf-8")
    util = pkg / "util.py"
    util.write_text("", encoding="utf-8")
    main = pkg / "main.py"
    main.write_text("from . import util\n", encoding="utf-8")

    resolver = ImportResolver(repo_root=tmp_path)
    resolved = resolver.resolve(ImportRef(module="util", level=1), main)
    assert resolved == util.resolve()
