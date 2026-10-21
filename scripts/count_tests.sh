#!/usr/bin/env bash
set -e
cd /home/z/my-project/hypervisor-4.0
export PYTHONPATH="/home/z/my-project/hypervisor-4.0${PYTHONPATH:+:$PYTHONPATH}"
python -m pytest tests/ -W ignore::pytest.PytestUnraisableExceptionWarning \
  -q --tb=line 2>&1 | grep -E "passed|failed|error" | tail -3 || true
python -m pytest tests/ -W ignore::pytest.PytestUnraisableExceptionWarning \
  --co -q 2>/dev/null | tail -1
