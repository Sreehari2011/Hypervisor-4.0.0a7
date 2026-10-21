#!/usr/bin/env python3
"""Golden-trajectory capture harness (P3 kickoff executor; P0 deliverable).

Runs one scripted objective against the FROZEN 3.7.3 oracle with the
aegis_debug kit and journal active, then archives the run as a golden
trajectory (see README.md in this directory).

P0 scope: the harness itself + wiring validation (--dry-run). Actual
capture requires the cisai-ultra endpoint and an operator-signed scope
file, and executes at P3 kickoff per the phase plan.

Never writes into the 3.7.3 tree; reads it, runs it from its own
working copy of artifacts, and archives results under oracle/golden/.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import subprocess
import sys
import time
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent.parent   # hypervisor-4.0/
ORACLE_DIR = REPO / "oracle"
GOLDEN_DIR = ORACLE_DIR / "golden"
FREEZE = ORACLE_DIR / "freeze.py"
TARGET = Path(os.environ.get(
    "AEGIS_ORACLE_TREE", "/home/z/my-project/Hypervisor-3.7.3"))


def _tree_manifest_sha() -> str:
    man = json.loads((ORACLE_DIR / "MANIFEST.json").read_text(encoding="utf-8"))
    blob = json.dumps(man["files"], sort_keys=True).encode()
    return hashlib.sha256(blob).hexdigest()


def _require_frozen() -> None:
    ok = subprocess.run(
        [sys.executable, str(FREEZE), "--verify"],
        capture_output=True, text=True).returncode == 0
    if not ok:
        raise SystemExit(
            "[!] oracle tree has drifted — a capture against a drifted "
            "tree is invalid. Run: python3 oracle/freeze.py --verify")


def dry_run() -> int:
    print("golden capture harness — dry run")
    print(f"  oracle tree   : {TARGET}"
          + (" [present]" if TARGET.is_dir() else " [MISSING]"))
    src = TARGET / "src"
    print(f"  entrypoint    : {src / 'main.py'}"
          + (" [present]" if (src / "main.py").exists() else " [MISSING]"))
    kit = TARGET / "debug" / "sitecustomize.py"
    print(f"  debug kit     : {kit}"
          + (" [present]" if kit.exists() else " [MISSING]"))
    print(f"  freeze        : verified ok")
    print(f"  tree sha      : {_tree_manifest_sha()[:16]}…")
    print("dry run complete — no capture performed, nothing written.")
    return 0


def capture(objective_file: Path, scope_file: Path, out: Path,
            *, model: str = "", base_url: str = "") -> int:
    _require_frozen()
    if out.exists():
        raise SystemExit(f"[!] refusing to overwrite existing golden id: {out}")
    objective = objective_file.read_text(encoding="utf-8")
    scope_sha = hashlib.sha256(scope_file.read_bytes()).hexdigest()

    out.mkdir(parents=True)
    run_dir = out / "run"          # scratch; archived pieces move up after
    run_dir.mkdir()

    env = dict(os.environ)
    env.update({
        "AEGIS_DEBUG": "1",
        "AEGIS_DEBUG_DIR": str(run_dir / "debug"),
        # 3.7.3 scope enforcement was OFF by default — the standing
        # critical finding. A golden capture must run WITH it on, or the
        # comparison baseline legitimizes the defect. If the flag name
        # differs at capture time, fix here before P3.
        "SCOPE_ENFORCEMENT": "true",
        "AEGIS_SCOPE_FILE": str(scope_file),
    })
    if base_url:
        env["BASE_URL"] = base_url
    if model:
        env["MODEL_NAME"] = model

    entry = TARGET / "src" / "main.py"
    # PYTHONPATH precedence: the kit's sitecustomize dir first (auto-
    # installs the taps), then the oracle's src.
    env["PYTHONPATH"] = os.pathsep.join(
        [str(TARGET / "debug"), str(TARGET / "src")])

    print(f"[i] running oracle: {entry}")
    t0 = time.time()
    proc = subprocess.run(
        [sys.executable, str(entry)], input=objective, text=True,
        capture_output=True, env=env, cwd=str(run_dir), timeout=3600)
    elapsed = time.time() - t0

    # Archive the pieces the A/B verdict reads.
    debug_root = run_dir / "debug"
    timeline = None
    for run in sorted(debug_root.glob("run_*")) if debug_root.is_dir() else []:
        timeline = run / "timeline.jsonl"
    if timeline and timeline.exists():
        shutil.copy2(timeline, out / "timeline.jsonl")
    journal_src = run_dir / "journal"
    if journal_src.is_dir():
        shutil.copytree(journal_src, out / "journal")
    report = run_dir / "report.md"
    if report.exists():
        shutil.copy2(report, out / "report.md")

    manifest = {
        "captured_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "objective_file": objective_file.name,
        "objective_sha256": hashlib.sha256(
            objective.encode()).hexdigest(),
        "scope_file": scope_file.name,
        "scope_sha256": scope_sha,
        "oracle_git_commit": subprocess.run(
            ["git", "-C", str(TARGET), "rev-parse", "HEAD"],
            capture_output=True, text=True).stdout.strip(),
        "oracle_tree_manifest_sha": _tree_manifest_sha(),
        "env": {k: env[k] for k in
                ("SCOPE_ENFORCEMENT", "BASE_URL", "MODEL_NAME") if k in env},
        "returncode": proc.returncode,
        "elapsed_s": round(elapsed, 1),
        "stdout_chars": len(proc.stdout),
        "stderr_chars": len(proc.stderr),
    }
    (out / "manifest.json").write_text(
        json.dumps(manifest, indent=1) + "\n", encoding="utf-8")
    shutil.rmtree(run_dir, ignore_errors=True)

    print(f"[+] golden trajectory archived: {out}")
    print(f"    rc={proc.returncode} elapsed={elapsed:.1f}s")
    return 0 if proc.returncode == 0 else 1


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--objective-file", type=Path)
    ap.add_argument("--scope-file", type=Path)
    ap.add_argument("--out", type=Path)
    ap.add_argument("--model", default="")
    ap.add_argument("--base-url", default="")
    ap.add_argument("--dry-run", action="store_true")
    args = ap.parse_args(argv)

    if args.dry_run:
        return dry_run()
    for req in ("objective_file", "scope_file", "out"):
        if getattr(args, req) is None:
            ap.error(f"--{req.replace('_', '-')} is required "
                     "unless --dry-run")
    return capture(args.objective_file, args.scope_file, args.out,
                   model=args.model, base_url=args.base_url)


if __name__ == "__main__":
    raise SystemExit(main())
