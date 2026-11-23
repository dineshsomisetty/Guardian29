#!/usr/bin/env bash
# Guardian test harness: lint, tests, security greps, UI typecheck + build.
#   bash scripts/harness.sh            # everything
#   SKIP_UI=1 bash scripts/harness.sh  # backend only
# Prints PASS/FAIL per step; on a failure prints the last 80 lines of that step's output. Exit 1 if any failed.
# Ruff runs on tracked Python files only, so local scratch files do not break the harness.
set -u
cd "$(dirname "$0")/.."
ROOT="$(pwd)"
LOG_DIR="${HARNESS_LOG_DIR:-$ROOT/.harness}"
mkdir -p "$LOG_DIR"
FAILED=()

step() {
  local name="$1"; shift
  local log="$LOG_DIR/${name//[^a-zA-Z0-9_]/_}.log"
  if "$@" >"$log" 2>&1; then
    printf 'PASS  %s\n' "$name"
  else
    printf 'FAIL  %s\n' "$name"
    echo "------ last 80 lines: $name ------"
    tail -n 80 "$log"
    echo "------------------------------------"
    FAILED+=("$name")
  fi
}

ruff_tracked() {
  local files
  mapfile -t files < <(git ls-files 'guardian/*.py' 'tests/*.py' 'scripts/*.py')
  uv run ruff check "${files[@]}"
}

# security greps: guardian/ and scripts/ must not shell out via a shell, push to targets or publish packages
security_grep() {
  local hits
  hits=$(grep -rnE 'shell[[:space:]]*=[[:space:]]*True|git[[:space:]]+push|npm[[:space:]]+publish' \
           --include='*.py' --include='*.ts' --include='*.tsx' guardian scripts ui/src 2>/dev/null \
         | grep -vE '^scripts/(harness\.sh|check_forbidden\.py|cp1_check\.py):' || true)
  if [ -n "$hits" ]; then echo "forbidden patterns:"; echo "$hits"; return 1; fi
  uv run python scripts/check_forbidden.py
}

step ruff ruff_tracked
step pytest uv run pytest -q --tb=short
step security_grep security_grep
if [ "${SKIP_UI:-0}" != "1" ]; then
  if [ ! -d ui/node_modules ]; then step ui_install bash -c 'cd ui && npm ci'; fi
  step ui_typecheck bash -c 'cd ui && npx tsc -b --noEmit'
  step ui_build bash -c 'cd ui && npm run build'
fi

if [ ${#FAILED[@]} -eq 0 ]; then
  echo "HARNESS: PASS"
  exit 0
fi
echo "HARNESS: FAIL (${FAILED[*]})"
exit 1
