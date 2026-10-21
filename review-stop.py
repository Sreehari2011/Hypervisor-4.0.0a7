#!/usr/bin/env python3.11
"""review-stop.py — operator review stop-hook (the Stage-6 seat belt).

Drafted against hypervisor/hooks.py (CC Stop parity):
  stdin : {"hook_event_name": "Stop", "stop_hook_active": bool,
           "last_assistant_message": str (<=8000), "session_path": str,
           "turn": int, "purpose": "main"}
  stdout: exit 0 + {"decision": "approve"|"block", "reason": str}
          exit 0 without JSON  -> approve
          exit 2               -> blocking error (reason from stderr/stdout)
          other exit           -> non-blocking error (journaled, never wedges)

Blocks the natural stop while the final summary is too thin for an
engagement record: no scope fingerprint, no evidence references, or
under 400 chars. Anti-recursion: approves its own continuation.
"""
import json
import sys


def emit(decision: str, reason: str = "") -> None:
    print(json.dumps({"decision": decision, "reason": reason}))


try:
    payload = json.load(sys.stdin)
except Exception:
    emit("approve", "unparseable stop payload - approving rather than wedging")
    sys.exit(0)

msg = (payload.get("last_assistant_message") or "").strip()

# CC parity: a hook that blocks its own continuation cannot recurse forever
if payload.get("stop_hook_active"):
    emit("approve", "review guidance already delivered once - accepting stop")
    sys.exit(0)

if len(msg) < 400:
    emit("block",
         "REVIEW: final summary too thin for an engagement record. Produce "
         "a structured findings summary: finding class, affected service "
         "and port, evidence path under the workspace, severity, and "
         "recommended remediation. Then stop.")
    sys.exit(0)

if "sha256:" not in msg:
    emit("block",
         "REVIEW: final summary lacks the engagement scope reference. Cite "
         "the scope fingerprint from the [scope] banner (the sha256:... "
         "value shown at engagement start) in your final summary.")
    sys.exit(0)

low = msg.lower()
if ("evidence" not in low) and ("/app/workspace" not in msg) \
        and ("ws/" not in msg) and ("workspace" not in low):
    emit("block",
         "REVIEW: no evidence references found. Cite at least one evidence "
         "artifact path under the engagement workspace for each finding "
         "class.")
    sys.exit(0)

emit("approve", "final summary carries scope ref + evidence - accepted")
