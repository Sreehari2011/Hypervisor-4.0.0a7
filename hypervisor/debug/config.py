"""AEGIS Debug Kit — configuration knobs and run-directory management.

Ported from 3.7.3 (all knobs env-driven, same names and defaults — the
operator's runbooks carry over unchanged). The kit is INERT unless
AEGIS_DEBUG=1.
"""
import os
import time

# ── knobs ────────────────────────────────────────────────────────────
ENABLED = os.environ.get("AEGIS_DEBUG", "").strip().lower() in ("1", "true", "yes", "on")

# Where artifacts land. Default: ./logs/debug (one run dir per process).
OUT_ROOT = os.environ.get("AEGIS_DEBUG_DIR", "./logs/debug")

# A wall-clock span with ZERO timeline events longer than this triggers an
# all-thread stack dump (repeated every STALL_REPEAT seconds while the
# stall persists). Long hangs leave a full forensic trail.
STALL_SECONDS = float(os.environ.get("AEGIS_DEBUG_STALL_SECONDS", "30"))
STALL_REPEAT_SECONDS = float(os.environ.get("AEGIS_DEBUG_STALL_REPEAT", "60"))

# Max bytes of a captured HTTP body kept on disk (request and response
# each). 0 disables body capture (sizes/timing still recorded).
BODY_CAP_BYTES = int(os.environ.get("AEGIS_DEBUG_BODY_CAP", str(8 * 1024 * 1024)))

# asyncio loop debug mode (slow-callback warnings -> captured by logtap).
LOOP_DEBUG = os.environ.get("AEGIS_DEBUG_LOOP_DEBUG", "1").strip().lower() in ("1", "true", "yes", "on")

# Set openai/httpx/httpcore loggers to DEBUG (exposes SDK retry internals).
VERBOSE_LOG = os.environ.get("AEGIS_DEBUG_VERBOSE_LOG", "0").strip().lower() in ("1", "true", "yes", "on")

# Event-loop scheduling lag considered noteworthy (seconds).
LOOP_LAG_WARN = float(os.environ.get("AEGIS_DEBUG_LOOP_LAG_WARN", "0.25"))

# ── dead-stream reaper ──────────────────────────────────────────────
# Force-close a tapped LLM stream that has been silent (no SSE DATA
# lines) for this many seconds. The default (180s) is deliberately ABOVE
# the client stack's stream-chunk watchdog (120s on the 3.x stack): the
# reaper only ever closes streams the client has already given up on —
# it can never kill a live one. Observed healthy worst inter-chunk gap
# on real engagements: 90s. 0 disables the reaper entirely.
REAP_SECONDS = float(os.environ.get("AEGIS_DEBUG_REAP_SECONDS", "180"))

# Redact these request headers everywhere (comma separated, lowercase).
REDACT_HEADERS = [h.strip().lower() for h in
                  os.environ.get("AEGIS_DEBUG_REDACT_HEADERS",
                                  "authorization,x-api-key,cookie").split(",") if h.strip()]

# 1 = print a one-line boot banner to stderr (confirms the kit attached).
QUIET = os.environ.get("AEGIS_DEBUG_QUIET", "0").strip().lower() in (
    "1", "true", "yes", "on")


# ── run directory ────────────────────────────────────────────────────
_RUN_DIR = None


def run_dir() -> str:
    """Lazily create and return this process's artifact directory."""
    global _RUN_DIR
    if _RUN_DIR is None:
        stamp = time.strftime("%Y%m%d_%H%M%S", time.gmtime())
        _RUN_DIR = os.path.join(OUT_ROOT, f"run_{stamp}_pid{os.getpid()}")
        os.makedirs(os.path.join(_RUN_DIR, "wire"), exist_ok=True)
        os.makedirs(os.path.join(_RUN_DIR, "prompts"), exist_ok=True)
        os.makedirs(os.path.join(_RUN_DIR, "stalls"), exist_ok=True)
        with open(os.path.join(_RUN_DIR, "kit_meta.json"), "w") as f:
            import json
            json.dump({
                "started_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                "pid": os.getpid(),
                "python": os.sys.version,
                "endpoint": os.environ.get("BASE_URL", ""),
                "kit": "aegis-debug 2.0 (hypervisor-4.0 port)",
                "knobs": {
                    "STALL_SECONDS": STALL_SECONDS, "BODY_CAP_BYTES": BODY_CAP_BYTES,
                    "LOOP_DEBUG": LOOP_DEBUG, "VERBOSE_LOG": VERBOSE_LOG,
                    "REAP_SECONDS": REAP_SECONDS,
                },
            }, f, indent=2)
    return _RUN_DIR


def safe_cap(text: str) -> str:
    """Cap a captured body per BODY_CAP_BYTES."""
    if BODY_CAP_BYTES <= 0:
        return ""
    return text[:BODY_CAP_BYTES]
