#!/usr/bin/env python3.11
"""review-stop-eng-01.py — ENG-01-DVWA-FULL operator stop-hook.

Contract (hypervisor/hooks.py, CC Stop parity):
  stdin : {"hook_event_name": "Stop", "stop_hook_active": bool,
           "last_assistant_message": str (<=8000), "turn": int,
           "purpose": "main"}
  stdout: exit 0 + {"decision": "approve"|"block", "reason": str}
          exit 0 without JSON  -> approve
          exit 2               -> blocking error
The loop's recursion guard means this hook gets AT MOST ONE effective
block for the whole engagement — so every check runs first and the
single block reason is cumulative.
"""
import json
import re
import sys


def emit(decision, reason=""):
    print(json.dumps({"decision": decision, "reason": reason}))
    sys.exit(0)


try:
    payload = json.load(sys.stdin)
except Exception:
    emit("approve", "unparseable stop payload - approving rather than wedging")

msg = (payload.get("last_assistant_message") or "").strip()

# CC parity: a hook that blocks its own continuation cannot recurse forever
if payload.get("stop_hook_active"):
    emit("approve", "review guidance already delivered once - accepting stop")

issues = []

# 1. substance
if len(msg) < 400:
    issues.append(
        "final summary too thin for an engagement record - produce a "
        "structured executive summary (severity counts, top findings with "
        "one-line proofs, highest-impact chain, per-class coverage "
        "verdicts, scope fingerprint, report paths)")

# 2. scope reference
if "sha256:" not in msg:
    issues.append(
        "final summary lacks the engagement scope reference - cite the "
        "scope fingerprint (the sha256:... value in this objective) "
        "verbatim")

# 3. evidence + deliverable references
low = msg.lower()
if not re.search(r"(/app/workspace|workspace/|evidence/|report\.md|"
                 r"final_report\.json)", low):
    issues.append(
        "no evidence or deliverable references found - cite the "
        "final_report.json path and at least one evidence path under the "
        "engagement workspace")
if "final_report" not in low:
    issues.append(
        "final_report.json not referenced - confirm it is written and "
        "cite its workspace path in the summary")

# 4. coverage signal: distinct vulnerability-class families referenced
FAMILIES = [
    (r"sql\s*injection|sqli", "SQL injection"),
    (r"xss|cross[- ]?site", "XSS"),
    (r"command\s*injection|rce|os\s*command", "command injection / RCE"),
    (r"file\s*upload|web\s?shell|webshell", "file upload / web shell"),
    (r"lfi|file\s*inclusion|path\s*traversal|rfi", "file inclusion / traversal"),
    (r"csrf|cross[- ]?site\s*request", "CSRF"),
    (r"brute|credential|auth\b|session|login", "auth / session"),
    (r"misconfig|header|disclosure|config", "misconfiguration / disclosure"),
]
found = [label for pat, label in FAMILIES
         if re.search(pat, low)]
missing = [label for _, label in FAMILIES if label not in found]
if len(found) < 6:
    issues.append(
        "coverage verdicts incomplete - the summary references only "
        f"{len(found)} vulnerability families ({', '.join(found)}); "
        "every tested class needs an explicit finding-or-negative "
        f"verdict; still unmentioned: {', '.join(missing)}")
if not re.search(r"negative|not\s+(?:vulnerable|exploitable|present)|"
                 r"no\s+finding|clean|hardened", low):
    issues.append(
        "no negative results mentioned - an engagement record must show "
        "which classes were tested and closed as not vulnerable")

if issues:
    emit("block",
         "ENG-01 REVIEW: " + " | ".join(issues) +
         " | Complete the coverage checklist, write final_report.json, "
         "run compile_report, then stop with the full summary.")

emit("approve", "final summary carries scope ref + coverage + evidence - accepted")
