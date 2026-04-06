#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"

if [[ $# -ge 1 ]] && [[ -f "$1" ]]; then
  ENV_FILE="$1"
  set -a
  # shellcheck disable=SC1090
  source "${ENV_FILE}"
  set +a
fi

if [[ -x "${REPO_ROOT}/.venv/bin/python" ]]; then
  PYTHON_BIN="${REPO_ROOT}/.venv/bin/python"
else
  PYTHON_BIN="${PYTHON_BIN:-python3}"
fi

CMD=(
  "${PYTHON_BIN}"
  "${REPO_ROOT}/knowledge-base/setup_security_threat_intel.py"
  --run-scheduled-sync
)

if [[ -n "${ONYX_URL:-}" ]]; then
  CMD+=(--url "${ONYX_URL}")
fi
if [[ -n "${ONYX_EMAIL:-}" ]]; then
  CMD+=(--email "${ONYX_EMAIL}")
fi
if [[ -n "${ONYX_PASSWORD:-}" ]]; then
  CMD+=(--password "${ONYX_PASSWORD}")
fi
if [[ -n "${THREAT_INTEL_SYNC_LIMIT:-}" ]]; then
  CMD+=(--limit "${THREAT_INTEL_SYNC_LIMIT}")
fi

exec "${CMD[@]}"
