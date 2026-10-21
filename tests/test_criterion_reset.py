"""Container-mount safety for the exit-criterion harness reset.

Test-4 (engagement container, aegis-hypervisor:4.0.0a5 on Kali) exposed
that the harness startup wipe (``shutil.rmtree(OUTPUT)``) crashes with
``OSError: [Errno 16] Device or resource busy`` when OUTPUT is a bind
mount (docker-compose: ``./exit-criterion:/app/.exit-criterion``) —
rmdir(2) cannot remove a mountpoint. ``_reset_output()`` now clears the
CONTENTS of a mounted OUTPUT and only rmtree's plain directories, so the
same harness runs unchanged on the workstation (plain dir, full wipe)
and in the container (evidence volume survives, contents cleared).
"""
import importlib.util
import os
import sys
from pathlib import Path

PROJECT = Path(__file__).resolve().parent.parent

_spec = importlib.util.spec_from_file_location(
    "run_exit_criterion", PROJECT / "scripts" / "run_exit_criterion.py")
criterion = importlib.util.module_from_spec(_spec)
sys.modules["run_exit_criterion"] = criterion
_spec.loader.exec_module(criterion)


def test_reset_plain_directory_is_wiped_and_recreated(tmp_path):
    """Workstation path: a plain OUTPUT is removed and recreated empty."""
    out = tmp_path / "out"
    (out / "run-1-quiet-probe").mkdir(parents=True)
    (out / "run-1-quiet-probe" / "evidence.txt").write_text("x")
    (out / "exit-criterion.json").write_text("{}")

    criterion._reset_output(out)

    assert out.is_dir()
    assert list(out.iterdir()) == []


def test_reset_missing_directory_is_created(tmp_path):
    """Fresh checkout path: OUTPUT does not exist yet and is created."""
    out = tmp_path / "out"
    assert not out.exists()

    criterion._reset_output(out)

    assert out.is_dir()
    assert list(out.iterdir()) == []


def test_reset_mountpoint_survives_contents_cleared(tmp_path, monkeypatch):
    """Container path: OUTPUT is a mountpoint — the directory itself must
    survive (rmdir would EBUSY) while every child (dirs, files, symlinks)
    is cleared, and the harness may then write into it as usual."""
    out = tmp_path / "mounted"
    (out / "run-1-real").mkdir(parents=True)
    (out / "run-1-real" / "ws" / ".aegis").mkdir(parents=True)
    (out / "run-1-real" / "ws" / ".aegis" / "journal").mkdir()
    (out / "exit-criterion.json").write_text("{}")
    (out / "link-to-run").symlink_to("run-1-real")
    assert out.is_dir()

    monkeypatch.setattr(os.path, "ismount", lambda p: True)
    criterion._reset_output(out)

    # mountpoint itself intact, all contents (incl. symlink) cleared
    assert out.is_dir()
    assert list(out.iterdir()) == []
    # and it remains writable for the new invocation
    (out / "fresh").write_text("ok")
    assert (out / "fresh").read_text() == "ok"


def test_reset_ebusy_fallback_keeps_directory(tmp_path, monkeypatch):
    """Exotic mountpoint missed by ismount (st_dev matches parent): the
    rmtree raises EBUSY at the mountpoint rmdir AFTER clearing contents —
    the harness must swallow that, keep the directory, and stay usable.
    This pins the exact Test-4 failure signature (Errno 16) so it can
    never take the harness down again, whatever the mount flavor."""
    import errno
    import shutil as _shutil

    out = tmp_path / "sneaky-mount"
    (out / "run-2-fold-pressure").mkdir(parents=True)
    (out / "exit-criterion.json").write_text("{}")

    real_rmtree = _shutil.rmtree  # capture BEFORE patching

    def _rmtree_ebusy(path, *a, **kw):
        # simulate: contents removed, then rmdir(mountpoint) -> EBUSY
        target = Path(str(path))
        if target.is_dir():
            for child in target.iterdir():
                if child.is_dir() and not child.is_symlink():
                    real_rmtree(child)
                else:
                    child.unlink()
        raise OSError(errno.EBUSY, "Device or resource busy", str(path))

    monkeypatch.setattr(os.path, "ismount", lambda p: False)
    monkeypatch.setattr(criterion.shutil, "rmtree", _rmtree_ebusy)

    criterion._reset_output(out)  # must not raise

    assert out.is_dir()
    assert list(out.iterdir()) == []
    (out / "fresh").write_text("ok")
    assert (out / "fresh").read_text() == "ok"
