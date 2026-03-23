"""
Domain-specific rules for Airflow and Python code review.

Written from the perspective of a Staff-level Data Engineer who understands Airflow scheduler
internals, executor semantics, metadata DB behaviour, and production operational concerns.
These rules are injected into agent prompts as structured reference context.
"""

from dataclasses import dataclass
from typing import Dict, List, Optional


@dataclass
class Rule:
    """A single domain-specific lint rule with its pattern, severity, and remediation hint."""
    id: str
    description: str
    pattern: str       # regex pattern or descriptive pattern for the LLM
    severity: str      # CRITICAL / HIGH / MEDIUM / LOW
    category: str
    fix_hint: str = ""



# Security Rules


SECURITY_RULES: List[Rule] = [
    Rule(
        id="SEC-001",
        description="Hardcoded password, token, or secret in source code",
        pattern=r"(?i)(password|passwd|pwd|secret|token|api_key|apikey|auth_token)\s*=\s*['\"][^'\"]{3,}['\"]",
        severity="CRITICAL",
        category="security",
        fix_hint="Use environment variables or a secrets manager. In Airflow, use Connections for credentials and mark Variables as sensitive.",
    ),
    Rule(
        id="SEC-002",
        description="Hardcoded AWS access key ID or secret access key",
        pattern=r"(?i)(AKIA[0-9A-Z]{16}|aws_access_key_id\s*=\s*['\"][^'\"]+['\"]|aws_secret_access_key\s*=\s*['\"][^'\"]+['\"])",
        severity="CRITICAL",
        category="security",
        fix_hint="Use IAM roles (instance profile / pod service account). Never hardcode AWS credentials — they appear in git history forever.",
    ),
    Rule(
        id="SEC-003",
        description="Airflow Fernet key hardcoded — decrypts all Variables and Connections",
        pattern=r"(?i)(fernet_key\s*=\s*['\"][^'\"]{20,}['\"]|AIRFLOW__CORE__FERNET_KEY\s*=\s*['\"][^'\"]+['\"])",
        severity="CRITICAL",
        category="security",
        fix_hint="The Fernet key decrypts all encrypted Variables and Connections in the metadata DB. Inject via Kubernetes Secret, not hardcoded.",
    ),
    Rule(
        id="SEC-004",
        description="Airflow webserver secret_key hardcoded — enables session token forgery",
        pattern=r"(?i)(secret_key\s*=\s*['\"][^'\"]{8,}['\"]|AIRFLOW__WEBSERVER__SECRET_KEY\s*=\s*['\"][^'\"]+['\"])",
        severity="CRITICAL",
        category="security",
        fix_hint="A known secret_key allows forging Airflow session cookies (admin access). Generate randomly and inject via K8s Secret.",
    ),
    Rule(
        id="SEC-005",
        description="Airflow metadata DB connection string with plaintext password",
        pattern=r"(?i)(sql_alchemy_conn\s*=\s*['\"][^'\"]*://[^'\"]*:[^'\"]+@[^'\"]+['\"]|AIRFLOW__DATABASE__SQL_ALCHEMY_CONN\s*=)",
        severity="CRITICAL",
        category="security",
        fix_hint="The DB connection string with password appears in `ps aux` and container inspect output. Use a secrets manager or K8s Secret.",
    ),
    Rule(
        id="SEC-006",
        description="Variable.get() result logged or pushed to XCom — secret in task logs",
        pattern=r"Variable\.get\s*\([^)]+\).*(?:log|print|xcom_push)",
        severity="HIGH",
        category="security",
        fix_hint="Airflow task logs are centralised and often searchable. Never log or XCom-push secret Variable values.",
    ),
    Rule(
        id="SEC-007",
        description="eval() or exec() on non-constant input — code injection risk",
        pattern=r"\b(eval|exec)\s*\(",
        severity="HIGH",
        category="security",
        fix_hint="eval/exec on XCom values, dag_run.conf, or env vars allows arbitrary code execution. Use ast.literal_eval for data only.",
    ),
    Rule(
        id="SEC-008",
        description="subprocess with shell=True — shell injection risk",
        pattern=r"subprocess\.(run|call|Popen|check_output)\s*\([^)]*shell\s*=\s*True",
        severity="HIGH",
        category="security",
        fix_hint="shell=True with string concatenation or f-strings is injectable. Pass a list of args and shell=False.",
    ),
    Rule(
        id="SEC-009",
        description="os.system() or os.popen() — shell injection and no output capture",
        pattern=r"os\.(system|popen)\s*\(",
        severity="HIGH",
        category="security",
        fix_hint="Use subprocess.run([...], shell=False, capture_output=True). os.system() cannot capture output and is injection-prone.",
    ),
    Rule(
        id="SEC-010",
        description="SSL certificate verification disabled",
        pattern=r"verify\s*=\s*False|ssl\._create_unverified_context|PYTHONHTTPSVERIFY\s*=\s*['\"]?0",
        severity="HIGH",
        category="security",
        fix_hint="Disabling certificate verification enables MITM attacks. Fix the cert trust issue instead of disabling verification.",
    ),
    Rule(
        id="SEC-011",
        description="Private key or certificate material embedded in source",
        pattern=r"-----BEGIN (RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----",
        severity="CRITICAL",
        category="security",
        fix_hint="Never commit private keys. Mount from Kubernetes Secret as a volume file, not an env var.",
    ),
    Rule(
        id="SEC-012",
        description="yaml.load() without SafeLoader — allows arbitrary Python object construction",
        pattern=r"yaml\.load\s*\([^)]*\)(?!.*Loader\s*=\s*yaml\.SafeLoader)",
        severity="HIGH",
        category="security",
        fix_hint="Use yaml.safe_load() or yaml.load(data, Loader=yaml.SafeLoader). Unsafe yaml.load() can execute arbitrary code.",
    ),
    Rule(
        id="SEC-013",
        description="pickle.loads() on data from external source — arbitrary code execution",
        pattern=r"\bpickle\.(loads|load)\s*\(",
        severity="HIGH",
        category="security",
        fix_hint="Never deserialize pickle from untrusted sources (S3, XCom, API). Use JSON or protobuf.",
    ),
    Rule(
        id="SEC-014",
        description="AIRFLOW__WEBSERVER__EXPOSE_CONFIG=True — exposes full config in UI",
        pattern=r"AIRFLOW__WEBSERVER__EXPOSE_CONFIG\s*=\s*['\"]?[Tt]rue",
        severity="HIGH",
        category="security",
        fix_hint="With EXPOSE_CONFIG=True, the Airflow web UI shows the full airflow.cfg including DB connection strings. Never set in production.",
    ),
    Rule(
        id="SEC-015",
        description="BashOperator command built from dag_run.conf — user-controlled input injection",
        pattern=r"bash_command\s*=\s*['\"].*\{\{.*dag_run\.conf",
        severity="HIGH",
        category="security",
        fix_hint="dag_run.conf is user-controlled via the Airflow UI trigger form. Validate and sanitize before using in shell commands.",
    ),
]


# Airflow Rules


AIRFLOW_RULES: List[Rule] = [

    #  Scheduler performance 
    Rule(
        id="AF-001",
        description="Variable.get() at module level — DB query on every scheduler heartbeat",
        pattern=r"^[^#\n]*Variable\.get\s*\(",
        severity="HIGH",
        category="airflow",
        fix_hint="The scheduler imports every DAG file every ~30s. Variable.get() at module level = N DB queries/min where N = DAG count. Move inside operator callables or use {{ var.value.KEY }} Jinja template.",
    ),
    Rule(
        id="AF-002",
        description="Hook instantiation or BaseHook.get_connection() at module level",
        pattern=r"^[^#\n]*(BaseHook\.get_connection|Hook\s*\(|hook\s*=\s*\w+Hook)",
        severity="HIGH",
        category="airflow",
        fix_hint="Hook instantiation at module level triggers a metadata DB query on every scheduler scan. Move inside execute() or operator callable.",
    ),
    Rule(
        id="AF-003",
        description="Network I/O or file I/O at module level in DAG file",
        pattern=r"^[^#\n]*(requests\.(get|post|put)|boto3\.|psycopg2\.connect|open\s*\(|pd\.read_csv|pd\.read_parquet)",
        severity="HIGH",
        category="airflow",
        fix_hint="Any I/O at module level blocks the scheduler on every DAG file scan. If the endpoint is down, the DAG disappears from the scheduler until the file parses cleanly again.",
    ),

    
    Rule(
        id="AF-004",
        description="default_args missing retries — transient failures permanently fail tasks",
        pattern=r"default_args\s*=\s*\{[^}]*\}",
        severity="HIGH",
        category="airflow",
        fix_hint="Without retries, a transient DB timeout or network blip permanently fails the task. Set retries >= 1 and retry_delay=timedelta(minutes=5) in default_args.",
    ),
    Rule(
        id="AF-005",
        description="start_date = datetime.now() — non-deterministic, DAG never schedules",
        pattern=r"start_date\s*=\s*(datetime\.now|datetime\.utcnow|timezone\.utcnow)\s*\(",
        severity="CRITICAL",
        category="airflow",
        fix_hint="datetime.now() is evaluated at parse time (~every 30s). The next scheduled run = start_date + interval, which is always 'just now', causing the DAG to never be scheduled. Use start_date=datetime(2024, 1, 1, tzinfo=timezone.utc).",
    ),
    Rule(
        id="AF-006",
        description="catchup=True without max_active_runs — DagRun explosion on first deploy",
        pattern=r"catchup\s*=\s*True",
        severity="HIGH",
        category="airflow",
        fix_hint="A DAG with start_date 6 months ago and schedule='@hourly' will queue 4,380 DagRuns on first deploy, saturating all executor slots. Always pair catchup=True with max_active_runs=1.",
    ),
    Rule(
        id="AF-007",
        description="schedule_interval= deprecated (Airflow 2.4+) — use schedule=",
        pattern=r"\bschedule_interval\s*=",
        severity="MEDIUM",
        category="airflow",
        fix_hint="schedule_interval= emits DeprecationWarning since Airflow 2.4. Replace with schedule=. The parameter will be removed in Airflow 3.x.",
    ),
    Rule(
        id="AF-008",
        description="Timezone-naive datetime in DAG — breaks comparisons with Airflow's aware datetimes",
        pattern=r"datetime\(\d{4},\s*\d+,\s*\d+\)(?!.*tzinfo)",
        severity="MEDIUM",
        category="airflow",
        fix_hint="Airflow 2.x is timezone-aware internally. Comparing naive datetime with aware raises TypeError. Use pendulum.datetime(2024, 1, 1, tz='UTC') or datetime(..., tzinfo=timezone.utc).",
    ),
    Rule(
        id="AF-009",
        description="depends_on_past=True + catchup=True — silent deadlock if first run fails",
        pattern=r"depends_on_past\s*=\s*True",
        severity="HIGH",
        category="airflow",
        fix_hint="If the first historical DagRun's task fails, ALL future runs of that task are blocked indefinitely. Requires manual 'airflow tasks clear' to unblock. Use with extreme caution.",
    ),
    Rule(
        id="AF-010",
        description="execution_date usage — deprecated in Airflow 2.2+",
        pattern=r"\bexecution_date\b",
        severity="MEDIUM",
        category="airflow",
        fix_hint="execution_date is an alias for logical_date in Airflow 2.2+. Use context['logical_date'] or {{ logical_date }}. For the data window, use data_interval_start / data_interval_end.",
    ),

    #  Sensors 
    Rule(
        id="AF-011",
        description="Sensor without explicit timeout — default is 7 days, holds worker slot",
        pattern=r"Sensor\s*\([^)]*\)(?!.*timeout)",
        severity="HIGH",
        category="airflow",
        fix_hint="Default sensor timeout is 7 days (604800s). A misconfigured sensor holds a CeleryExecutor worker slot for 7 days. Always set timeout=3600 (or appropriate max wait).",
    ),
    Rule(
        id="AF-012",
        description="Sensor mode='poke' for long waits — blocks CeleryExecutor worker slot",
        pattern=r"mode\s*=\s*['\"]poke['\"]",
        severity="MEDIUM",
        category="airflow",
        fix_hint="poke mode holds a worker slot for the full wait duration. With limited CeleryExecutor workers, long-poking sensors starve other tasks. Use mode='reschedule' to release the slot between pokes.",
    ),
    Rule(
        id="AF-013",
        description="ExternalTaskSensor without execution_delta or execution_date_fn",
        pattern=r"ExternalTaskSensor\s*\(",
        severity="MEDIUM",
        category="airflow",
        fix_hint="By default, ExternalTaskSensor looks for a DagRun in the external DAG with the SAME logical_date. If schedules differ (e.g., hourly vs daily), the dates never match. Set execution_delta or execution_date_fn.",
    ),

    #  Operators 
    Rule(
        id="AF-014",
        description="Deprecated Airflow 1.x import path",
        pattern=r"from airflow\.(operators|sensors|hooks)\.(bash_operator|python_operator|http_sensor|s3_hook|postgres_hook)\b",
        severity="HIGH",
        category="airflow",
        fix_hint="1.x import paths work via compatibility shim but emit DeprecationWarning and will break in Airflow 3.x. Update to: airflow.operators.bash, airflow.operators.python, airflow.providers.*",
    ),
    Rule(
        id="AF-015",
        description="SubDagOperator — removed in Airflow 2.x, causes CeleryExecutor deadlocks",
        pattern=r"\bSubDagOperator\b",
        severity="HIGH",
        category="airflow",
        fix_hint="SubDagOperator is removed. It caused deadlocks in CeleryExecutor. Replace with TaskGroup: from airflow.utils.task_group import TaskGroup.",
    ),
    Rule(
        id="AF-016",
        description="DummyOperator — renamed to EmptyOperator in Airflow 2.4+",
        pattern=r"\bDummyOperator\b",
        severity="LOW",
        category="airflow",
        fix_hint="DummyOperator is deprecated. Use EmptyOperator: from airflow.operators.empty import EmptyOperator.",
    ),
    Rule(
        id="AF-017",
        description="provide_context=True in PythonOperator — removed in Airflow 2.0",
        pattern=r"provide_context\s*=\s*True",
        severity="HIGH",
        category="airflow",
        fix_hint="provide_context=True was removed in Airflow 2.0. Context is always passed as **kwargs. Remove this argument entirely.",
    ),
    Rule(
        id="AF-018",
        description="airflow.utils.dates module — deprecated",
        pattern=r"from airflow\.utils\.dates import|airflow\.utils\.dates\.",
        severity="MEDIUM",
        category="airflow",
        fix_hint="airflow.utils.dates is deprecated. Replace days_ago(N) with pendulum.today('UTC').subtract(days=N).",
    ),

    #  XCom & data passing 
    Rule(
        id="AF-019",
        description="XCom push of large object — stored in metadata DB, causes bloat",
        pattern=r"xcom_push\s*\(",
        severity="MEDIUM",
        category="airflow",
        fix_hint="XCom is stored in the Airflow metadata DB. Pushing DataFrames, large lists, or file contents bloats the DB and slows xcom_clear operations. Push only S3/GCS paths or small metadata dicts.",
    ),
    Rule(
        id="AF-020",
        description="do_xcom_push not set to False on operators that don't share data",
        pattern=r"PythonOperator\s*\([^)]*python_callable\s*=",
        severity="LOW",
        category="airflow",
        fix_hint="PythonOperator defaults to do_xcom_push=True. Every return value is stored in the metadata DB. Set do_xcom_push=False on operators that don't need to share data downstream.",
    ),

    #  Branching & trigger rules 
    Rule(
        id="AF-021",
        description="BranchPythonOperator present — check downstream join task trigger_rule",
        pattern=r"\bBranchPythonOperator\b",
        severity="MEDIUM",
        category="airflow",
        fix_hint="After BranchPythonOperator, any join task must have trigger_rule=TriggerRule.NONE_FAILED_MIN_ONE_SUCCESS. Default ALL_SUCCESS means the join task is skipped when one branch is not taken.",
    ),
    Rule(
        id="AF-022",
        description="ShortCircuitOperator present — check downstream cleanup task trigger_rule",
        pattern=r"\bShortCircuitOperator\b",
        severity="MEDIUM",
        category="airflow",
        fix_hint="ShortCircuitOperator skips all downstream tasks when callable returns False. Any cleanup/notification task that must run regardless needs trigger_rule=TriggerRule.ALL_DONE.",
    ),

    #  Alerting & observability 
    Rule(
        id="AF-023",
        description="on_failure_callback not set — failed tasks alert nobody",
        pattern=r"DAG\s*\([^)]*\)(?!.*on_failure_callback)",
        severity="MEDIUM",
        category="airflow",
        fix_hint="Without on_failure_callback, task failures are silent unless someone checks the UI. Set a callback in default_args that notifies the owning team (Slack, PagerDuty).",
    ),
    Rule(
        id="AF-024",
        description="tags= missing from DAG — makes incident triage and ownership tracking impossible",
        pattern=r"DAG\s*\([^)]*\)(?!.*tags\s*=)",
        severity="LOW",
        category="airflow",
        fix_hint="Tags are the primary way to filter DAGs in the Airflow UI by team or domain. Add tags=['team-name', 'domain'] to every DAG.",
    ),
    Rule(
        id="AF-025",
        description="doc_md= missing — operators have no documentation in the UI",
        pattern=r"DAG\s*\([^)]*\)(?!.*doc_md\s*=)",
        severity="LOW",
        category="airflow",
        fix_hint="doc_md is rendered as HTML in the Airflow UI DAG detail view. It's the primary documentation for operators who need to understand a DAG without reading the code.",
    ),

    #  Resource management 
    Rule(
        id="AF-026",
        description="Heavy operator (Spark/EMR/BigQuery) without pool= — saturates executor slots",
        pattern=r"(SparkSubmitOperator|EmrAddStepsOperator|BigQueryInsertJobOperator|DataprocSubmitJobOperator)\s*\(",
        severity="MEDIUM",
        category="airflow",
        fix_hint="Without pool assignment, concurrent DagRuns each submit a cluster job simultaneously. Assign pool='spark_pool' with an appropriate slot count to bound concurrency.",
    ),
    Rule(
        id="AF-027",
        description="dagrun_timeout not set — hung tasks block max_active_runs slots indefinitely",
        pattern=r"DAG\s*\(",
        severity="LOW",
        category="airflow",
        fix_hint="Without dagrun_timeout, a hung task (waiting for a lock, infinite loop) keeps the DagRun RUNNING forever, consuming max_active_runs slots. Set dagrun_timeout=timedelta(hours=6).",
    ),
    Rule(
        id="AF-028",
        description="max_active_runs not explicitly set on resource-heavy DAGs",
        pattern=r"DAG\s*\([^)]*\)(?!.*max_active_runs\s*=)",
        severity="MEDIUM",
        category="airflow",
        fix_hint="Without max_active_runs, up to core.max_active_runs_per_dag (default 16) concurrent DagRuns run simultaneously. For Spark/EMR DAGs this means 16 concurrent cluster jobs. Set explicitly.",
    ),

    #  Jinja templating 
    Rule(
        id="AF-029",
        description="Jinja template {{ ... }} in attribute not listed in template_fields — silent no-op",
        pattern=r"['\"].*\{\{.*\}\}.*['\"]",
        severity="HIGH",
        category="airflow",
        fix_hint="Jinja templates only render in attributes listed in operator.template_fields. If {{ ds }} appears in an attribute NOT in template_fields, the literal string '{{ ds }}' is passed to the operator. No error is raised — silent wrong value.",
    ),
    Rule(
        id="AF-030",
        description="dag_run.conf['key'] in template without .get() — KeyError if conf not provided",
        pattern=r"\{\{.*dag_run\.conf\[['\"][^'\"]+['\"]\]",
        severity="HIGH",
        category="airflow",
        fix_hint="dag_run.conf is {} when the DAG runs on schedule (not triggered manually). conf['key'] raises KeyError. Use conf.get('key', 'default') or {{ dag_run.conf.get('key', 'default') }}.",
    ),
]


# Python Rules


PYTHON_RULES: List[Rule] = [
    Rule(
        id="PY-001",
        description="Missing None guard before attribute access or method call",
        pattern=r"(?<!\bif\s)\b\w+\.([\w]+)\s*(?!\s*is\s*(not\s*)?None)",
        severity="MEDIUM",
        category="python",
        fix_hint="dict.get(), function return values, and env vars can be None. Guard: if obj is not None: obj.method()",
    ),
    Rule(
        id="PY-002",
        description="Bare except: swallows all exceptions including KeyboardInterrupt",
        pattern=r"except\s*:",
        severity="MEDIUM",
        category="python",
        fix_hint="Catch specific exceptions. bare except: also catches SystemExit and KeyboardInterrupt, preventing clean shutdown.",
    ),
    Rule(
        id="PY-003",
        description="Mutable default argument — shared state across all calls",
        pattern=r"def\s+\w+\s*\([^)]*=\s*(\[\]|\{\}|set\(\))",
        severity="HIGH",
        category="python",
        fix_hint="def f(items=[]) creates one list shared across all calls. Use def f(items=None): if items is None: items = []",
    ),
    Rule(
        id="PY-004",
        description="os.environ['KEY'] — raises KeyError if env var unset",
        pattern=r"os\.environ\[['\"][^'\"]+['\"]\]",
        severity="MEDIUM",
        category="python",
        fix_hint="Use os.environ.get('KEY', 'default') or os.environ.get('KEY') with an explicit None check.",
    ),
    Rule(
        id="PY-005",
        description="print() in non-script code — output not captured in Airflow task logs",
        pattern=r"\bprint\s*\(",
        severity="LOW",
        category="python",
        fix_hint="print() output is not captured in Airflow task logs when running on a remote worker. Use logging.getLogger(__name__).info(...) instead.",
    ),
    Rule(
        id="PY-006",
        description="Root logger used instead of module-level logger",
        pattern=r"(?<!logger\s*=\s*)(?<!getLogger\()[^#\n]*\blogging\.(info|debug|warning|error|critical)\s*\(",
        severity="LOW",
        category="python",
        fix_hint="Use logger = logging.getLogger(__name__) at module level. Root logger messages may not appear in the correct Airflow log context in distributed execution.",
    ),
    Rule(
        id="PY-007",
        description="Broad Exception catch hides root cause",
        pattern=r"except\s+Exception\s*(as\s+\w+)?\s*:\s*\n\s*(pass|log|print)",
        severity="MEDIUM",
        category="python",
        fix_hint="Catch the most specific exception type. At minimum, log the exception with traceback: logger.exception('msg') or raise from the except block.",
    ),
    Rule(
        id="PY-008",
        description="Late binding closure in loop — all lambdas capture same variable",
        pattern=r"for\s+\w+\s+in\s+.*:\s*\n.*lambda\s*[^:]*:",
        severity="HIGH",
        category="python",
        fix_hint="lambda: x in a loop captures x by reference. At call time, x has the final loop value. Fix: lambda x=x: x (default argument captures current value).",
    ),

    # Error handling 
    Rule(
        id="PY-009",
        description="Exception swallowed silently — except block has only pass, return None, or return False",
        pattern=r"except\s+[\w\s,()]+:\s*\n\s*(pass|return\s+None|return\s+False)\s*$",
        severity="HIGH",
        category="python",
        fix_hint="Swallowed exceptions hide bugs permanently. At minimum: logger.exception('context msg') before return. If truly ignorable, add a comment explaining why and log at DEBUG level.",
    ),
    Rule(
        id="PY-010",
        description="Exception re-raised without chaining — original traceback lost",
        pattern=r"except\s+[\w\s,()]+\s+as\s+\w+\s*:\s*\n(?:(?!\s*raise\s+\w+.*\bfrom\b).)*?\s*raise\s+\w+\(",
        severity="HIGH",
        category="python",
        fix_hint="raise RuntimeError('msg') inside an except block loses the original traceback. Use raise RuntimeError('msg') from e to chain exceptions and preserve the root cause.",
    ),
    Rule(
        id="PY-011",
        description="logger.error() used instead of logger.exception() — traceback not captured",
        pattern=r"except\s+[\w\s,()]+\s*(?:as\s+\w+)?\s*:\s*\n(?:[^\n]*\n)*?\s*logger\.error\s*\(",
        severity="MEDIUM",
        category="python",
        fix_hint="logger.error('msg') inside an except block omits the stack trace. Use logger.exception('msg') which calls logger.error with exc_info=True automatically, or pass exc_info=True explicitly.",
    ),
    Rule(
        id="PY-012",
        description="assert used for runtime input validation — disabled by Python -O flag",
        pattern=r"^[^#\n]*\bassert\b(?!.*#\s*noqa).*(?:isinstance|len|type|is not None|!=|==)",
        severity="HIGH",
        category="python",
        fix_hint="assert statements are stripped when Python is run with -O or -OO (common in production containers). Use explicit if/raise ValueError for input validation in public APIs and class __init__.",
    ),
    Rule(
        id="PY-013",
        description="File or DB cursor opened without context manager — resource leak on exception",
        pattern=r"(?:^[^#\n]*(?:open\s*\(|cursor\s*=\s*\w+\.cursor\s*\(|conn\s*=\s*\w+\.connect\s*\())(?![^#\n]*\bwith\b))",
        severity="HIGH",
        category="python",
        fix_hint="open(), DB cursors, and connections outside a `with` block leak the resource if an exception is raised before .close(). Use `with open(...) as f:` and context managers for all resource acquisition.",
    ),
    Rule(
        id="PY-014",
        description="Exception raised inside finally block — replaces original exception, original lost",
        pattern=r"\bfinally\s*:\s*\n(?:[^\n]*\n)*?\s*raise\b",
        severity="HIGH",
        category="python",
        fix_hint="An exception raised in a finally block replaces the exception that was propagating — the original exception is permanently lost. Wrap finally body in try/except if it can raise.",
    ),
    Rule(
        id="PY-015",
        description="Over-broad try block wrapping business logic and unrelated code",
        pattern=r"\btry\s*:\s*\n(?:[^\n]*\n){10,}?\s*except\b",
        severity="MEDIUM",
        category="python",
        fix_hint="Large try blocks catch exceptions from unrelated lines, making the except handler's assumptions wrong. Wrap only the single statement that can raise the specific exception you're handling.",
    ),
    Rule(
        id="PY-016",
        description="requests / urllib call without exception handling — uncaught network errors",
        pattern=r"(?:requests\.(get|post|put|delete|patch|head)\s*\(|urllib\.request\.urlopen\s*\()(?![^;{]*except)",
        severity="MEDIUM",
        category="python",
        fix_hint="Network calls raise requests.exceptions.RequestException (timeout, connection error, DNS failure). Wrap in try/except requests.exceptions.RequestException and handle or re-raise with context.",
    ),
    Rule(
        id="PY-017",
        description="json.loads() / int() / float() without exception handling — crashes on bad input",
        pattern=r"(?:json\.loads\s*\(|int\s*\(|float\s*\()(?![^;{]*except)",
        severity="MEDIUM",
        category="python",
        fix_hint="json.loads raises json.JSONDecodeError; int()/float() raise ValueError on non-numeric strings. These are common with XCom values, env vars, and API responses. Wrap with try/except ValueError.",
    ),
    Rule(
        id="PY-018",
        description="boto3 / S3 / AWS call without ClientError handling",
        pattern=r"(?:boto3\.|s3_client\.|s3_resource\.|self\._s3\.)(?:get_object|put_object|head_object|delete_object|copy_object|list_objects)\s*\(",
        severity="MEDIUM",
        category="python",
        fix_hint="boto3 raises botocore.exceptions.ClientError for all S3/AWS errors (404, 403, throttle). Always wrap in try/except ClientError and check error_response['Error']['Code'] to distinguish recoverable errors.",
    ),
]


# Registry


ALL_RULES: Dict[str, List[Rule]] = {
    "security": SECURITY_RULES,
    "airflow":  AIRFLOW_RULES,
    "python":   PYTHON_RULES,
}

__all__ = [
    "Rule",
    "SECURITY_RULES",
    "AIRFLOW_RULES",
    "PYTHON_RULES",
    "ALL_RULES",
    "build_rules_context",
    "get_forbidden_patterns",
]


def build_rules_context(categories: Optional[List[str]] = None) -> str:
    """Return a formatted string of rules to inject into agent prompts."""
    if categories is None:
        categories = list(ALL_RULES.keys())

    lines = ["## Domain Rules\n"]
    for cat in categories:
        rules = ALL_RULES.get(cat, [])
        if not rules:
            continue
        lines.append(f"### {cat.upper()} Rules")
        for rule in rules:
            lines.append(
                f"- [{rule.severity}] {rule.id}: {rule.description}\n"
                f"  Pattern: `{rule.pattern}`\n"
                f"  Fix: {rule.fix_hint}"
            )
        lines.append("")

    return "\n".join(lines)


def get_forbidden_patterns() -> List[Dict]:
    """Return all rules as dicts for programmatic use."""
    result = []
    for rules in ALL_RULES.values():
        for rule in rules:
            result.append({
                "id": rule.id,
                "pattern": rule.pattern,
                "severity": rule.severity,
                "description": rule.description,
                "fix_hint": rule.fix_hint,
            })
    return result
