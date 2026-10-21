#!/usr/bin/env bash
set -e
cd /home/z/my-project/hypervisor-4.0
git add -A
if ! git diff --cached --quiet; then
  git commit -q -m "P3: verification + runner scripts"
fi
echo "project repo:"
git log --oneline | head -3
git status --porcelain | wc -l
