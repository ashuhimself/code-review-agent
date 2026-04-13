# ANZ Conventions

## No TaskFlow API

Correct:
```python
from airflow.operators.python import PythonOperator

extract = PythonOperator(task_id="extract", python_callable=extract_fn)
```

Incorrect:
```python
from airflow.decorators import task

@task
def extract():
    ...
```

## Dataset Scheduling Pattern

Correct producer:
```python
from airflow.datasets import Dataset

publish = PythonOperator(
    task_id="publish",
    python_callable=publish_fn,
    outlets=[Dataset("s3://bucket/ccr/ingest/entity")],
)
```

Correct consumer:
```python
from airflow import DAG
from airflow.datasets import Dataset

with DAG(
    dag_id="transform_ccr",
    schedule=[Dataset("s3://bucket/ccr/ingest/entity")],
):
    ...
```

Incorrect (URI mismatch):
```python
schedule=[Dataset("s3://bucket/ccr/ingest/entity/")]
```

Incorrect (no producing task):
```python
schedule=[Dataset("s3://bucket/ccr/publish/entity")]
```

## S3KeySensor Required Before S3 Read

Correct:
```python
wait_file = S3KeySensor(task_id="wait_file", bucket_key="s3://bucket/ccr/ingest/entity")
read_file = PythonOperator(task_id="read", python_callable=read_fn)
wait_file >> read_file
```

Incorrect:
```python
read_file = PythonOperator(task_id="read", python_callable=read_fn)
```

## pendulum Datetimes

Correct:
```python
import pendulum

start_date = pendulum.datetime(2025, 1, 1, tz="UTC")
```

Incorrect:
```python
from datetime import datetime

start_date = datetime.now()
```

## Vault/Connections For Credentials

Correct:
```python
conn_id = "teradata_nonprod"
```

Incorrect:
```python
password = "hardcoded"
```

## Classic Operators Only

Correct:
```python
PythonOperator(task_id="run", python_callable=run_fn)
```

Incorrect:
```python
@task
def run_fn():
    ...
```

## Connection ID Naming

Correct:
```python
"teradata_nonprod"
"s3_prod"
```

Incorrect:
```python
"postgres_default"
"td"
```

## Project Folder Structure

Correct:
```text
dags/ingest/ccr/my_dag.py
dags/transform/ccr/my_dag.py
plugins/ccr/helpers.py
plugins/shared/common.py
```

Incorrect:
```text
dags/ccr/my_dag.py
utils/ccr_helpers.py
```
