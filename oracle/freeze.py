#!/usr/bin/env python3
"""Oracle freeze: pin the 3.7.3 tree as the frozen reference.

Generates (or verifies) a manifest of every file in the 3.7.3 clone:
path, bytes, sha256, line count. The manifest is the freeze — from P0
onward the 3.7.3 tree must never change; any drift fails --verify and
invalidates A/B comparisons taken against it.

Usage:
  python3 oracle/freeze.py                # generate oracle/MANIFEST.json
  python3 oracle/freeze.py --verify       # verify tree against manifest
  python3 oracle/freeze.py --verify --json  # machine-readable result

The clone's git commit is recorded alongside (338b646 at freeze time);
git identity is secondary to the content hashes, which are the actual
freeze surface.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import subprocess
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
ORACLE_DIR = REPO / "oracle"
MANIFEST = ORACLE_DIR / "MANIFEST.json"
# The frozen 3.7.3 clone, relative to this workspace.
TARGET = Path(os.environ.get(
    "AEGIS_ORACLE_TREE", "/home/z/my-project/Hypervisor-3.7.3"))

# Version-control metadata that is part of the clone but not of the tree.
SKIP_DIRS = {".git"}


def _git_commit(tree: Path) -> str:
    try:
        out = subprocess.run(
            ["git", "-C", str(tree), "rev-parse", "HEAD"],
            capture_output=True, text=True, timeout=30)
        return out.stdout.strip()
    except Exception:
        return ""


def _walk(tree: Path):
    for path in sorted(tree.rglob("*")):
        if any(part in SKIP_DIRS for part in path.relative_to(tree).parts):
            continue
        if path.is_file():
            yield path


def generate(tree: Path) -> dict:
    files = []
    total_bytes, total_lines = 0, 0
    for path in _walk(tree):
        rel = path.relative_to(tree).as_posix()
        raw = path.read_bytes()
        lines = raw.count(b"\n") + (1 if raw and not raw.endswith(b"\n") else 0)
        files.append({
            "path": rel,
            "bytes": len(raw),
            "lines": lines,
            "sha256": hashlib.sha256(raw).hexdigest(),
        })
        total_bytes += len(raw)
        total_lines += lines
    manifest = {
        "frozen": "2026-10-08",
        "what": "Hypervisor-3.7.3 (Sreehari2011), squashed commit 338b646",
        "git_commit": _git_commit(tree),
        "tree": str(tree),
        "role": ("frozen oracle for the 4.0 rebuild: port acceptance "
                 "tests and P3/P4 A/B verdicts derive from this tree; "
                 "it must not change"),
        "n_files": len(files),
        "total_bytes": total_bytes,
        "total_lines": total_lines,
        "files": files,
    }
    MANIFEST.write_text(json.dumps(manifest, indent=1) + "\n",
                         encoding="utf-8")
    return manifest


def verify(tree: Path) -> tuple:
    if not MANIFEST.exists():
        return False, {"error": "manifest missing — run without --verify first"}
    manifest = json.loads(MANIFEST.read_text(encoding="utf-8"))
    expected = {f["path"]: f for f in manifest["files"]}
    problems = []
    seen = set()
    for path in _walk(tree):
        rel = path.relative_to(tree).as_posix()
        seen.add(rel)
        exp = expected.get(rel)
        if exp is None:
            problems.append({"path": rel, "problem": "untracked new file"})
            continue
        raw = path.read_bytes()
        got = hashlib.sha256(raw).hexdigest()
        if got != exp["sha256"]:
            problems.append({"path": rel, "problem": "hash mismatch",
                             "expected": exp["sha256"], "got": got})
    for rel in set(expected) - seen:
        problems.append({"path": rel, "problem": "missing"})
    ok = not problems
    return ok, {"ok": ok, "checked": len(expected), "problems": problems,
                "git_commit_now": _git_commit(tree)}


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--verify", action="store_true",
                    help="verify the tree against the existing manifest")
    ap.add_argument("--json", action="store_true",
                    help="machine-readable output")
    args = ap.parse_args(argv)

    tree = TARGET
    if not tree.is_dir():
        print(f"[!] oracle tree not found: {tree}", file=sys.stderr)
        return 2

    if args.verify:
        ok, report = verify(tree)
        if args.json:
            print(json.dumps(report, indent=1))
        else:
            print(f"oracle tree : {tree}")
            print(f"checked     : {report.get('checked', 0)} files")
            if ok:
                print("status      : FROZEN — tree matches manifest")
            else:
                print("status      : DRIFT DETECTED")
                for p in report.get("problems", [])[:20]:
                    print(f"  - {p['path']}: {p['problem']}")
        return 0 if ok else 1

    manifest = generate(tree)
    if args.json:
        print(json.dumps({k: v for k, v in manifest.items() if k != "files"},
                         indent=1))
    else:
        print(f"oracle tree : {tree}")
        print(f"git commit  : {manifest['git_commit']}")
        print(f"files       : {manifest['n_files']}")
        print(f"lines       : {manifest['total_lines']:,}")
        print(f"bytes       : {manifest['total_bytes']:,}")
        print(f"manifest    : {MANIFEST}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
