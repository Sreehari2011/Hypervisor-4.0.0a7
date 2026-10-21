#!/usr/bin/env bash
set -e
cd /home/z/my-project/hypervisor-4.0
echo "=== git status (should be clean) ==="
git status --porcelain | wc -l
git log --oneline | head -3
echo "=== golden fixtures ==="
ls tests/golden/
echo "=== code counts ==="
wc -l hypervisor/agents/*.py hypervisor/memory/sidequery.py \
      hypervisor/tools/vapt/*.py hypervisor/persist/replay.py | tail -1
find hypervisor -name "*.py" | xargs wc -l | tail -1
find tests -name "*.py" | xargs wc -l | tail -1
echo "=== total python files ==="
find hypervisor tests -name "*.py" | wc -l
