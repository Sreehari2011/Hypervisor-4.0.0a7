"""Hermetic test environment for the loop/budget tuning knobs.

The engagement deployment pins model tuning via .env (docker compose
env_file) — e.g. AEGIS_CONTEXT_WINDOW_TOKENS=200000 for the cisai-ultra
gateway alias, AEGIS_MAX_OUTPUT_TOKENS matching the serving cap. Those
overrides are correct for the engagement runtime and must not change
test outcomes: the suite asserts code defaults (the registry windows,
the 8192 -> 65536 output ladder), and several knobs resolve once at
module import (hypervisor.query boot-once constants), so neutralizing
them per-test is too late for the import-time reads.

pytest imports this conftest before any test module imports the
package — the one place that reliably precedes those reads. Tests that
exercise override behavior set the vars explicitly via monkeypatch
(test_window_resolution_env_override, the P2 fold e2e gates) and are
unaffected; with the ambient value gone, monkeypatch teardown also
restores to "unset" instead of re-leaking the deployment pin into
later default-asserting tests.

Scope is deliberately surgical: only the knobs whose defaults the
suite asserts. Endpoint, model, debug and tool valves stay live so
doctor/adapter behavior is tested against real configuration.
"""
import os

_TUNING_KNOBS = (
    # budget.resolve_context_window deployment pin (call-time read)
    "AEGIS_CONTEXT_WINDOW_TOKENS",
    # hypervisor.query boot-once loop knobs (import-time reads)
    "AEGIS_CONTEXT_WINDOW",
    "AEGIS_MAX_OUTPUT_TOKENS",
    "AEGIS_MAX_OUTPUT_TOKENS_CEILING",
    "AEGIS_RECOVERY_CONTINUATIONS",
    "AEGIS_BLOCKING_RATIO",
    "AEGIS_TURN_BUDGET_S",
)

for _var in _TUNING_KNOBS:
    os.environ.pop(_var, None)
