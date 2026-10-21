#!/usr/bin/env bash
# P3 test runner — always runs from the project root (the package is
# not installed; tests import `hypervisor` off the rootdir cwd).
set -e
cd /home/z/my-project/hypervisor-4.0
export PYTHONPATH="/home/z/my-project/hypervisor-4.0${PYTHONPATH:+:$PYTHONPATH}"
python -m pytest tests/ -q "$@"
