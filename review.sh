#!/usr/bin/env bash
# =============================================================================
# review.sh — AI Code Review Agent entry point
#
# Usage:
#   ./review.sh                          # review current branch vs main
#   ./review.sh --file path/to/file.py   # review specific file
#   ./review.sh --dir path/to/dir/       # review all changed files in directory
# =============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CONFIG="${SCRIPT_DIR}/config.yaml"


# Parse config.yaml for base_branch

BASE_BRANCH="main"
if command -v python3 &>/dev/null && [[ -f "$CONFIG" ]]; then
    BASE_BRANCH="$(python3 -c "
import yaml, sys
with open('$CONFIG') as f:
    c = yaml.safe_load(f)
print(c.get('base_branch', 'main'))
" 2>/dev/null || echo "main")"
fi


# Argument parsing

TARGET_FILE=""
TARGET_DIR=""

while [[ $# -gt 0 ]]; do
    case "$1" in
        --file)        TARGET_FILE="$2"; shift 2 ;;
        --dir)         TARGET_DIR="$2";  shift 2 ;;
        --base-branch) BASE_BRANCH="$2"; shift 2 ;;
        -h|--help)
            grep '^# ' "$0" | head -10 | sed 's/^# //'
            exit 0
            ;;
        *)
            echo "Unknown option: $1" >&2
            exit 1
            ;;
    esac
done


# Helpers

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


# Build context into a temp file

CONTEXT_FILE="$(mktemp /tmp/review_context.XXXXXX)"
trap 'rm -f "$CONTEXT_FILE"' EXIT

CONTEXT_LABEL=""

if [[ -n "$TARGET_FILE" ]]; then
    #  File mode ---
    [[ -f "$TARGET_FILE" ]] || { echo "Error: file not found: $TARGET_FILE" >&2; exit 1; }
    CONTEXT_LABEL="$TARGET_FILE"
    echo "  Reading: $TARGET_FILE"
    append_file_context "$CONTEXT_FILE" "$TARGET_FILE"

elif [[ -n "$TARGET_DIR" ]]; then
    #  Directory mode ---
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
        echo "  No changed files vs ${BASE_BRANCH} — scanning directory."
        mapfile -t CHANGED_FILES < <(find "$TARGET_DIR" -name '*.py' -maxdepth 3 | head -20)
    fi

    for f in "${CHANGED_FILES[@]}"; do
        echo "  Reading: $f"
        append_file_context "$CONTEXT_FILE" "$f"
    done

else
    #  Default: all changed Python files vs base branch ---
    git rev-parse --git-dir &>/dev/null 2>&1 \
        || { echo "Error: not in a git repo. Use --file or --dir." >&2; exit 1; }

    CONTEXT_LABEL="branch diff vs ${BASE_BRANCH}"

    mapfile -t CHANGED_FILES < <(
        git diff "${BASE_BRANCH}...HEAD" --name-only 2>/dev/null \
        | grep '\.py$' || true
    )

    if [[ ${#CHANGED_FILES[@]} -eq 0 ]]; then
        echo "No changed Python files found vs ${BASE_BRANCH}."
        exit 0
    fi

    echo "  Changed files: ${CHANGED_FILES[*]}"
    for f in "${CHANGED_FILES[@]}"; do
        append_file_context "$CONTEXT_FILE" "$f"
    done
fi

[[ -s "$CONTEXT_FILE" ]] || { echo "No content to review." >&2; exit 1; }


# Run the Python review pipeline

echo ""
echo "============================================================"
echo "  AI Code Review Agent"
echo "  Scope: $CONTEXT_LABEL"
echo "============================================================"
echo ""
echo "Running 5 agents..."
echo ""

python3 "${SCRIPT_DIR}/run_review.py" \
    --context-file "$CONTEXT_FILE" \
    --context-label "$CONTEXT_LABEL"
