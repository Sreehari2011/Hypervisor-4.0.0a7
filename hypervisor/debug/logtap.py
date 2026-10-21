"""AEGIS Debug Kit — log tap.

Ported from 3.7.3. Tees the entire process logging tree (hypervisor,
openai, httpx/httpx2, httpcore, asyncio) into <run>/run.log, and mirrors
WARNING+ records into the timeline as `log` events. This is where SDK
retry notices, asyncio slow-callback warnings ("Executing <Task> took
12.3 seconds"), and the platform's own error logs become part of the
unified timeline.
"""
import logging
import threading

from . import config, timeline

_LOCK = threading.Lock()
_FH = None


def _handle():
    global _FH
    if _FH is None:
        import os
        path = os.path.join(config.run_dir(), "run.log")
        _FH = open(path, "a", encoding="utf-8", buffering=1)  # line buffered
    return _FH


class _TimelineLogHandler(logging.Handler):
    def emit(self, record):
        try:
            line = self.format(record)
            with _LOCK:
                _handle().write(line + "\n")
            if record.levelno >= logging.WARNING:
                timeline.emit("log", record.levelname.lower(),
                              logger=record.name,
                              msg=line[:500])
        except Exception:
            pass


def install():
    h = _TimelineLogHandler()
    h.setFormatter(logging.Formatter(
        "[%(asctime)s.%(msecs)03d] %(levelname)-7s %(name)s | %(message)s",
        datefmt="%H:%M:%S"))
    root = logging.getLogger()
    root.addHandler(h)
    # Surface the noisy-but-diagnostic loggers (no behavior change: the
    # platform's own handler config is untouched; we only add ours).
    for name, lvl in (("asyncio", logging.INFO),
                      ("hypervisor", logging.INFO),
                      ("openai", logging.INFO),
                      ("httpx", logging.INFO),
                      ("httpx2", logging.INFO),
                      ("httpcore", logging.INFO)):
        try:
            logging.getLogger(name).setLevel(
                logging.DEBUG if config.VERBOSE_LOG else lvl)
        except Exception:
            pass
    timeline.emit("meta", "log_tap_installed",
                  verbose=config.VERBOSE_LOG)
