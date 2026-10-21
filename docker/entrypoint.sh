#!/usr/bin/env bash
# =============================================================================
# AEGIS Hypervisor 4.0 — container entrypoint
# Pre-flight the environment (doctor is informational; it never blocks the
# interactive shell), then hand off to CMD.
# =============================================================================
set -uo pipefail

cd /app || exit 1

echo "================================================================"
echo " AEGIS Hypervisor 4.0 — container pre-flight"
echo " user  : $(id -un)   cwd : $(pwd)"
echo " build : 4.0.0a6 — PILOT-03 gate fix (Test-3 fingerprint d0b8b1b4 superseded; re-verify: scripts/run-tests.sh)"
echo "================================================================"

if [ -z "${AEGIS_OPENAI_BASE_URL:-}" ]; then
  echo "[entrypoint] WARN: AEGIS_OPENAI_BASE_URL not set — model calls will fail."
fi
if [ -z "${AEGIS_OPENAI_API_KEY:-}" ]; then
  echo "[entrypoint] WARN: AEGIS_OPENAI_API_KEY not set — model calls will fail."
fi

python3 -m hypervisor.cli --doctor || \
  echo "[entrypoint] doctor reported failures — see above (shell continues)."

exec "$@"
