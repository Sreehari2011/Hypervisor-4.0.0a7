#!/bin/sh
# Hermetic test runner: the engagement container pins operator config
# via AEGIS_* env vars (compose environment:). Tests exercise code
# defaults and registry tables, not operator overrides. Import-time
# constants (MAX_OUTPUT_TOKENS, query.py:74) are computed before
# pytest runs, so fixture-time delenv is too late — vars must be
# absent at process start. PYTEST_ADDOPTS (baked in image) keeps
# basetemp off noexec /tmp.
exec env -u AEGIS_CONTEXT_WINDOW_TOKENS \
        -u AEGIS_LLM_MAX_ATTEMPTS \
        -u AEGIS_LLM_TOTAL_TIMEOUT_S \
        -u AEGIS_MAX_OUTPUT_TOKENS \
        -u AEGIS_MAX_OUTPUT_TOKENS_CEILING \
        -u AEGIS_MODEL \
        -u AEGIS_OPENAI_API_KEY \
        -u AEGIS_OPENAI_BASE_URL \
    python3 -m pytest tests/ -q "$@"
