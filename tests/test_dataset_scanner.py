"""Tests for dataset_scanner components."""

from __future__ import annotations

from pathlib import Path

from dataset_scanner import DatasetExtractor, DependencyMapper, ValidationEngine


def _write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def test_schedule_dataset_extracted_as_consumer(tmp_path: Path) -> None:
    file_path = tmp_path / "dags" / "transform" / "ccr" / "consumer.py"
    _write(
        file_path,
        "from airflow.datasets import Dataset\n"
        "schedule=[Dataset('s3://bucket/ccr/ingest/entity')]\n",
    )
    refs = DatasetExtractor().extract(file_path)
    assert any(ref.role == "consumer" for ref in refs)


def test_outlets_dataset_extracted_as_producer(tmp_path: Path) -> None:
    file_path = tmp_path / "dags" / "ingest" / "ccr" / "producer.py"
    _write(
        file_path,
        "from airflow.datasets import Dataset\n"
        "outlets=[Dataset('s3://bucket/ccr/ingest/entity')]\n",
    )
    refs = DatasetExtractor().extract(file_path)
    assert any(ref.role == "producer" for ref in refs)


def test_uri_mismatch_detected(tmp_path: Path) -> None:
    mapper = DependencyMapper()
    refs = DatasetExtractor().extract(
        _seed_file(tmp_path / "producer.py", "outlets=[Dataset('s3://bucket/ccr/ingest/entity')]\n")
    )
    refs += DatasetExtractor().extract(
        _seed_file(tmp_path / "consumer.py", "schedule=[Dataset('s3://bucket/ccr/ingest/entity/')]\n")
    )
    datasets = mapper.build(refs)
    _, errors = ValidationEngine().validate(datasets)
    assert any("URI mismatch" in error for error in errors)


def test_consumer_without_producer_error(tmp_path: Path) -> None:
    refs = DatasetExtractor().extract(
        _seed_file(tmp_path / "consumer_only.py", "schedule=[Dataset('s3://bucket/ccr/publish/entity')]\n")
    )
    datasets = DependencyMapper().build(refs)
    _, errors = ValidationEngine().validate(datasets)
    assert any("no producer found" in error for error in errors)


def test_producer_without_consumer_warning(tmp_path: Path) -> None:
    refs = DatasetExtractor().extract(
        _seed_file(tmp_path / "producer_only.py", "outlets=[Dataset('s3://bucket/ccr/ingest/entity')]\n")
    )
    datasets = DependencyMapper().build(refs)
    warnings, _ = ValidationEngine().validate(datasets)
    assert any("No consumer found" in warning for warning in warnings)


def _seed_file(path: Path, body: str) -> Path:
    _write(path, "from airflow.datasets import Dataset\n" + body)
    return path
