#!/usr/bin/env bash
set -e
cd /home/z/my-project/hypervisor-4.0
export PYTHONPATH="/home/z/my-project/hypervisor-4.0${PYTHONPATH:+:$PYTHONPATH}"
out=$(python -m pytest tests/ --tb=short -q 2>&1 | tail -25)
echo "$out"
