"""a7-batch1b — W1 resumed-boot window skip: flag AND legacy inference.

ENG-01 postmortem: every render on a resumed boot journaled a
degenerate window (msg_count=0) because the restored window comes
from the session store, not from journaled message events. Batch 1
taught replay to skip the window check when the boot event carries
resumed=true — but ENG-01's own journal predates the flag, so its
census stayed uncorrected (133 window count-mismatch failures
remained FAIL, 1 skipped). Batch1b adds the legacy inference: a boot
event beyond the first in the same append-only journal is by
definition a resumed boot.

Acceptance:
  1. legacy second boot (no flag)  -> window check skipped
  2. explicit resumed=false        -> still checked (an explicit
                                      value always beats inference)
  3. explicit resumed=true         -> skipped (batch-1 path, covered)
"""
import copy
import json
import shutil
import sys
from pathlib import Path

import pytest

HERE = Path(__file__).parent
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(HERE.parent))

from hypervisor.persist.replay import JournalReplay  # noqa: E402

GOLDEN = HERE / "golden"


def _copy_golden(tmp_path):
    dst = tmp_path / "golden-fold"
    shutil.copytree(GOLDEN / "golden-fold", dst)
    return dst


def _events(d: Path):
    return [json.loads(l) for l in
            (d / "journal.jsonl").read_text().splitlines() if l.strip()]


def _write(d: Path, evs):
    (d / "journal.jsonl").write_text(
        "".join(json.dumps(e, sort_keys=True) + "\n" for e in evs))


def _append_second_boot(evs, resumed=None):
    """Synthesize a resumed boot: a second boot event followed by a
    duplicate of the journal's last render (a well-formed render —
    carries window_hash/brief_hash/now). The duplicated render is
    the probe: under the not-resumed contract it gets window-checked;
    on a resumed boot it must be skipped instead."""
    out = list(evs)
    boot = copy.deepcopy(next(e for e in evs if e["type"] == "boot"))
    boot["seq"] = evs[-1]["seq"] + 1
    if resumed is not None:
        boot["data"]["resumed"] = resumed
    out.append(boot)
    render = copy.deepcopy(
        evs[-1] if evs[-1]["type"] == "brief_render"
        else next(e for e in reversed(evs)
                  if e["type"] == "brief_render"))
    render["seq"] = boot["seq"] + 1
    out.append(render)
    return out


def _window_checks(rep):
    return rep["renders"]["window_checks"]


@pytest.fixture()
def baseline(tmp_path):
    """The pristine golden trajectory's window census."""
    d = _copy_golden(tmp_path / "baseline")
    return _window_checks(JournalReplay(d).full_report())


def test_legacy_second_boot_infers_resumed(tmp_path, baseline):
    d = _copy_golden(tmp_path / "legacy")
    evs = _append_second_boot(_events(d))          # no resumed key
    _write(d, evs)
    w = _window_checks(JournalReplay(d).full_report())
    # the appended render is NOT window-checked — resumed inferred
    assert w["checked"] == baseline["checked"]
    assert w["skipped"] == baseline["skipped"] + 1


def test_explicit_resumed_false_still_checks(tmp_path, baseline):
    d = _copy_golden(tmp_path / "explicit-false")
    evs = _append_second_boot(_events(d), resumed=False)
    _write(d, evs)
    w = _window_checks(JournalReplay(d).full_report())
    # explicit false wins over inference — old contract preserved
    assert w["checked"] == baseline["checked"] + 1
    assert w["skipped"] == baseline["skipped"]


def test_explicit_resumed_true_skips(tmp_path, baseline):
    d = _copy_golden(tmp_path / "explicit-true")
    evs = _append_second_boot(_events(d), resumed=True)
    _write(d, evs)
    w = _window_checks(JournalReplay(d).full_report())
    assert w["checked"] == baseline["checked"]
    assert w["skipped"] == baseline["skipped"] + 1
