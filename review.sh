#!/usr/bin/env bash
# =============================================================================
# review.sh - AI Code Review Agent entry point
#
# Usage:
#   ./review.sh
#   ./review.sh --file path/to/file.py
#   ./review.sh --dir path/to/dir/
#   ./review.sh --project ccr [--stage ingest|transform|standardise|publish]
#   ./review.sh --project ccr --pr 142
# =============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CONFIG="${SCRIPT_DIR}/config.yaml"

pick_python() {
    local candidates=()
    if [[ -n "${PYTHON_BIN:-}" ]]; then
        candidates+=("$PYTHON_BIN")
    fi
    if command -v python3 &>/dev/null; then
        candidates+=("$(command -v python3)")
    fi
    if command -v python &>/dev/null; then
        candidates+=("$(command -v python)")
    fi
    if command -v pyenv &>/dev/null; then
        local pyenv_python
        pyenv_python="$(pyenv which python 2>/dev/null || true)"
        if [[ -n "$pyenv_python" ]]; then
            candidates+=("$pyenv_python")
        fi
    fi

    local candidate
    for candidate in "${candidates[@]}"; do
        if "$candidate" -c "import yaml" &>/dev/null; then
            echo "$candidate"
            return 0
        fi
    done

    if command -v python3 &>/dev/null; then
        command -v python3
        return 0
    fi
    command -v python
}

PYTHON_BIN="$(pick_python)"

BASE_BRANCH="main"
if [[ -x "$PYTHON_BIN" ]] && [[ -f "$CONFIG" ]]; then
    BASE_BRANCH="$("$PYTHON_BIN" -c "
import yaml
with open('$CONFIG', encoding='utf-8') as f:
    c = yaml.safe_load(f) or {}
print(c.get('base_branch', 'main'))
" 2>/dev/null || echo "main")"
fi

TARGET_FILE=""
TARGET_DIR=""
PROJECT=""
STAGE=""
PR_ID=""

while [[ $# -gt 0 ]]; do
    case "$1" in
        --file) TARGET_FILE="$2"; shift 2 ;;
        --dir) TARGET_DIR="$2"; shift 2 ;;
        --project) PROJECT="$2"; shift 2 ;;
        --stage) STAGE="$2"; shift 2 ;;
        --pr) PR_ID="$2"; shift 2 ;;
        --base-branch) BASE_BRANCH="$2"; shift 2 ;;
        -h|--help)
            grep '^# ' "$0" | head -12 | sed 's/^# //'
            exit 0
            ;;
        *)
            echo "Unknown option: $1" >&2
            exit 1
            ;;
    esac
done

safe_diff() {
    local file="$1"
    if git rev-parse --git-dir &>/dev/null 2>&1; then
        git diff "${BASE_BRANCH}...HEAD" -- "$file" 2>/dev/null || true
    fi
}

append_file_context() {
    local tmpfile="$1"
    local filepath="$2"
    [[ -f "$filepath" ]] || return
    local content diff_out
    content="$(cat "$filepath")"
    diff_out="$(safe_diff "$filepath")"
    {
        echo "### File: $filepath"
        echo ""
        echo '```python'
        echo "$content"
        echo '```'
        if [[ -n "$diff_out" ]]; then
            echo ""
            echo "### Diff vs ${BASE_BRANCH}:"
            echo ""
            echo '```diff'
            echo "$diff_out"
            echo '```'
        fi
        echo ""
    } >> "$tmpfile"
}

CONTEXT_FILE="$(mktemp /tmp/review_context.XXXXXX)"
trap 'rm -f "$CONTEXT_FILE"' EXIT

CONTEXT_LABEL=""
REPORT_PREFIX="review"
declare -a SELECTED_FILES=()

if [[ -n "$TARGET_FILE" ]]; then
    [[ -f "$TARGET_FILE" ]] || { echo "Error: file not found: $TARGET_FILE" >&2; exit 1; }
    CONTEXT_LABEL="$TARGET_FILE"
    SELECTED_FILES+=("$TARGET_FILE")
elif [[ -n "$TARGET_DIR" ]]; then
    [[ -d "$TARGET_DIR" ]] || { echo "Error: directory not found: $TARGET_DIR" >&2; exit 1; }
    CONTEXT_LABEL="directory: $TARGET_DIR"

    if git rev-parse --git-dir &>/dev/null 2>&1; then
        mapfile -t CHANGED_FILES < <(
            git diff "${BASE_BRANCH}...HEAD" --name-only 2>/dev/null \
            | grep "^${TARGET_DIR}" | grep '\.py$' || true
        )
    else
        CHANGED_FILES=()
    fi

    if [[ ${#CHANGED_FILES[@]} -eq 0 ]]; then
        echo "No changed files vs ${BASE_BRANCH}; scanning directory."
        mapfile -t CHANGED_FILES < <(find "$TARGET_DIR" -name '*.py' -maxdepth 4 | head -40)
    fi
    SELECTED_FILES=("${CHANGED_FILES[@]}")
elif [[ -n "$PROJECT" ]]; then
    REPORT_STAGE="${STAGE:-all}"
    REPORT_PREFIX="review-${PROJECT}-${REPORT_STAGE}"

    if [[ -n "$STAGE" ]]; then
        target_dir="dags/${STAGE}/${PROJECT}"
        if [[ -d "$target_dir" ]]; then
            mapfile -t STAGE_FILES < <(find "$target_dir" -name '*.py' | sort)
            SELECTED_FILES+=("${STAGE_FILES[@]}")
        else
            echo "[WARN] ${STAGE}/${PROJECT} not found - skipping"
        fi
        CONTEXT_LABEL="project ${PROJECT}, stage ${STAGE}"
    else
        found_any=0
        for s in ingest transform standardise publish; do
            target_dir="dags/${s}/${PROJECT}"
            if [[ -d "$target_dir" ]]; then
                found_any=1
                mapfile -t STAGE_FILES < <(find "$target_dir" -name '*.py' | sort)
                SELECTED_FILES+=("${STAGE_FILES[@]}")
            else
                echo "[WARN] ${s}/${PROJECT} not found - skipping"
            fi
        done
        [[ $found_any -eq 1 ]] || { echo "Error: no stage directories found for project '${PROJECT}'" >&2; exit 1; }
        CONTEXT_LABEL="project ${PROJECT} (all stages)"
    fi
else
    git rev-parse --git-dir &>/dev/null 2>&1 || { echo "Error: not in a git repo. Use --file, --dir, or --project." >&2; exit 1; }
    CONTEXT_LABEL="branch diff vs ${BASE_BRANCH}"
    mapfile -t CHANGED_FILES < <(
        git diff "${BASE_BRANCH}...HEAD" --name-only 2>/dev/null | grep '\.py$' || true
    )
    [[ ${#CHANGED_FILES[@]} -gt 0 ]] || { echo "No changed Python files found vs ${BASE_BRANCH}."; exit 0; }
    SELECTED_FILES=("${CHANGED_FILES[@]}")
fi

if [[ ${#SELECTED_FILES[@]} -eq 0 ]]; then
    echo "No files selected for review." >&2
    exit 1
fi

for f in "${SELECTED_FILES[@]}"; do
    [[ -f "$f" ]] || continue
    echo "Reading: $f"
    append_file_context "$CONTEXT_FILE" "$f"
done

if [[ -x "${SCRIPT_DIR}/resolve_imports.py" ]]; then
    mapfile -t RESOLVED_FILES < <(
        "$PYTHON_BIN" "${SCRIPT_DIR}/resolve_imports.py" "${SELECTED_FILES[@]}" --repo-root "${SCRIPT_DIR}" 2>/dev/null || true
    )
    for rf in "${RESOLVED_FILES[@]}"; do
        [[ -f "$rf" ]] || continue
        if ! grep -q "### File: $rf" "$CONTEXT_FILE"; then
            echo "Resolved import: $rf"
            append_file_context "$CONTEXT_FILE" "$rf"
        fi
    done
fi

[[ -s "$CONTEXT_FILE" ]] || { echo "No content to review." >&2; exit 1; }

echo ""
echo "============================================================"
echo "  AI Code Review Agent"
echo "  Scope: $CONTEXT_LABEL"
echo "============================================================"
echo ""

CMD=(
    "$PYTHON_BIN" "${SCRIPT_DIR}/run_review.py"
    --context-file "$CONTEXT_FILE"
    --context-label "$CONTEXT_LABEL"
    --report-prefix "$REPORT_PREFIX"
)

if [[ -n "$PROJECT" ]]; then
    CMD+=(--project "$PROJECT")
fi
if [[ -n "$PR_ID" ]]; then
    CMD+=(--pr "$PR_ID")
fi

"${CMD[@]}"
