"""hypervisor.persist.sessions — 0o600 JSONL session writer (P1).

REFACTOR-06 adjacent (the CC sessionStorage analog; 3.7.3 had no
equivalent — sessions lived in the LangGraph sqlite checkpointer, which
dies with the grid). Contracts (blueprint 7.6 / 9.9):

  * append-only JSONL under a per-engagement directory, written through
    one ordered writer with 0o600 file permissions (0o700 dirs) and
    fsync durability
  * every record carries `parentUuid` so the transcript is a CHAIN;
    logical parents are preserved across compaction boundaries (the
    summary record's parentUuid points at the physical last record,
    while `logicalParentUuid` keeps the pre-fold chain head)
  * subagent transcripts are sidechain files with their own chain plus
    a metadata sidecar (P3 spawns them; the surface ships now)
  * special record types ride the same writer: meta records (boot /
    summary / phase), content replacements (P2), queue operations

The debug kit's sessions tap (patcher._patch_sessions) times this
class's append/fsync from the moment the module imports.
"""
from __future__ import annotations

import json
import os
import threading
import time
import uuid
from pathlib import Path
from typing import Any, Dict, Iterator, List, Optional

RECORD_TYPES = ("user", "assistant", "tool_result", "meta",
                "summary", "sidechain_start", "sidechain_end",
                "file_history", "content_replacement", "queue")

_META_KINDS = ("boot", "summary", "phase", "note")


class SessionStore:
    """One ordered append-only transcript writer (main chain or
    sidechain). The single-writer lock guarantees record order; every
    append fsyncs before returning."""

    def __init__(self, directory: Path | str, *,
                 session_id: Optional[str] = None,
                 sidechain: bool = False,
                 parent_session: Optional[str] = None,
                 parent_record: Optional[str] = None,
                 label: str = "main",
                 fsync: bool = True):
        self.directory = Path(directory)
        self.directory.mkdir(parents=True, exist_ok=True)
        try:
            os.chmod(self.directory, 0o700)
        except OSError:
            pass
        self.session_id = session_id or time.strftime(
            "%Y%m%d-%H%M%S") + "-" + uuid.uuid4().hex[:8]
        self.sidechain = bool(sidechain)
        self.label = str(label)
        self._fsync = bool(fsync)
        self._lock = threading.Lock()
        self._file = self.directory / f"{self.session_id}.jsonl"
        self._seq = 0
        self._chain_head: Optional[str] = None     # last record's uuid
        self._record_count = 0
        # resume continuation: an existing file continues its chain —
        # a restart instead of a continuation would fork the transcript
        if self._file.exists():
            for rec in self._iter_file():
                self._seq = max(self._seq, int(rec.get("seq") or 0))
                self._chain_head = rec.get("uuid") or self._chain_head
                self._record_count += 1
        # sidechain meta sidecar
        if sidechain:
            meta = {
                "session_id": self.session_id,
                "parent_session": parent_session,
                "parent_record": parent_record,
                "label": label,
                "started": round(time.time(), 3),
            }
            sidecar = self.directory / f"{self.session_id}.meta.json"
            self._write_sidecar(sidecar, meta)

    # ------------------------------------------------------------ write

    def append(self, record: Dict[str, Any]) -> Dict[str, Any]:
        """Append one record; assigns uuid / parentUuid / seq / ts.
        Returns the persisted record."""
        rtype = str(record.get("type") or "meta")
        with self._lock:
            self._seq += 1
            rec = dict(record)
            rec.setdefault("uuid", uuid.uuid4().hex)
            rec["parentUuid"] = record.get("parentUuid", self._chain_head)
            rec["sessionId"] = self.session_id
            rec["seq"] = self._seq
            rec.setdefault("ts", round(time.time(), 3))
            rec["type"] = rtype
            line = json.dumps(rec, ensure_ascii=True, sort_keys=True)
            fd = os.open(self._file,
                         os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o600)
            try:
                os.write(fd, (line + "\n").encode("utf-8"))
                if self._fsync:
                    os.fsync(fd)
            finally:
                os.close(fd)
            self._chain_head = rec["uuid"]
            self._record_count += 1
            return rec

    def append_many(self, records: List[Dict[str, Any]]
                    ) -> List[Dict[str, Any]]:
        return [self.append(r) for r in records]

    # ---------------------------------------------------- typed helpers

    def record_user(self, content: str, **extra) -> Dict[str, Any]:
        return self.append({"type": "user",
                            "message": {"role": "user", "content": content},
                            **extra})

    def record_assistant(self, message: Dict[str, Any],
                         **extra) -> Dict[str, Any]:
        return self.append({"type": "assistant", "message": message,
                            **extra})

    def record_tool_results(self, results: List[Dict[str, Any]]
                            ) -> List[Dict[str, Any]]:
        return [self.append({"type": "tool_result",
                             "message": {"role": "user", "content": [r]},
                             "tool_use_id": r.get("tool_use_id", "")})
                for r in results]

    def record_meta(self, kind: str, data: Optional[Dict[str, Any]] = None
                    ) -> Dict[str, Any]:
        if kind not in _META_KINDS:
            kind = "note"
        return self.append({"type": "meta", "kind": kind,
                            "data": data or {}})

    def append_summary(self, summary_text: str, *,
                       logical_parent: Optional[str] = None,
                       **extra) -> Dict[str, Any]:
        """Compaction boundary record (P2 drives it): parentUuid chains
        to the physical last record; logicalParentUuid preserves the
        pre-fold head so the transcript's logical order survives
        compaction (the CC boundary rule)."""
        with self._lock:
            physical_parent = self._chain_head
        return self.append({"type": "summary", "text": summary_text,
                            "logicalParentUuid": logical_parent,
                            "parentUuid": physical_parent, **extra})

    # -------------------------------------------------------- sidechain

    def spawn_sidechain(self, *, label: str = "child",
                        session_id: Optional[str] = None
                        ) -> "SessionStore":
        """A child transcript: own file, own chain, meta sidecar linking
        back to this record (P3's Task tool uses this surface)."""
        return SessionStore(
            self.directory, session_id=session_id, sidechain=True,
            parent_session=self.session_id,
            parent_record=self._chain_head, label=label,
            fsync=self._fsync)

    # ------------------------------------------------------------- read

    def chain_head(self) -> Optional[str]:
        return self._chain_head

    def record_count(self) -> int:
        return self._record_count

    def read_all(self) -> List[Dict[str, Any]]:
        return list(self._iter_file())

    def _iter_file(self) -> Iterator[Dict[str, Any]]:
        if not self._file.exists():
            return
        try:
            with self._file.open("r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        yield json.loads(line)
                    except json.JSONDecodeError:
                        continue    # torn tail: resume-safe by design
        except OSError:
            return

    def verify_chain(self) -> Dict[str, Any]:
        """Walk the transcript checking the parentUuid chain. Returns a
        report: total records, orphans (parentUuid pointing nowhere and
        not the first record / not a logical-parent reference), and the
        set of uuids."""
        uuids = set()
        records = self.read_all()
        for rec in records:
            uuids.add(rec.get("uuid"))
        orphans = []
        logical_refs = set()
        for i, rec in enumerate(records):
            parent = rec.get("parentUuid")
            if parent is None and i == 0:
                continue
            if parent is not None and parent in uuids:
                continue
            # summary boundaries may reference pre-fold heads
            logical = rec.get("logicalParentUuid")
            if logical is not None:
                logical_refs.add(logical)
            orphans.append({"seq": rec.get("seq"), "parentUuid": parent,
                            "type": rec.get("type")})
        return {"records": len(records), "orphans": orphans,
                "uuids": len(uuids),
                "logical_refs": len(logical_refs)}

    # ------------------------------------------------------------ misc

    @classmethod
    def resume(cls, directory: Path | str, session_id: str,
               *, fsync: bool = True) -> "SessionStore":
        """Continue an existing transcript: chain head and seq continue
        from the file's last record."""
        return cls(directory, session_id=session_id, fsync=fsync)

    @staticmethod
    def _write_sidecar(path: Path, meta: Dict[str, Any]) -> None:
        try:
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC,
                         0o600)
            try:
                os.write(fd, json.dumps(meta, indent=2,
                                        sort_keys=True).encode("utf-8"))
                os.fsync(fd)
            finally:
                os.close(fd)
        except OSError:
            pass
