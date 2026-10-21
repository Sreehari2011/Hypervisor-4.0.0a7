"""hypervisor.memory.ekd — the engagement knowledge DAG store (P2).

PORT-03: the 3.7.3 crown jewel (src/core/engagement_dag.py, 1,487 ln +
src/core/ekd_txn.py, 371 ln) ports with these 4.0 deltas:

  * the store keeps ONLY the graph; the render paths (render_brief_l2,
    render_node_detail) moved to memory/brief.py (PORT-11), and the
    semantic-store projection (project()/last_projected_rev) is DELETE-04
    — the store died, the EKD IS the memory surface now (memory_query
    queries the graph directly)
  * the state channel (ekd_serialized on a LangGraph channel) becomes
    the workspace file <workspace>/ekd.json written after each committed
    EkdBatch — same single-writer discipline, same J1 write-ahead
    (journal event BEFORE the state write; a crash between the two is
    exactly what recovery detects and repairs)
  * config decoupled to env (EKD snapshot retention); logging via the
    kit's logtap-safe stdlib logger
  * the debug kit's EKD tap was armed for this module's import in P0
    (hypervisor/debug/patcher.py install_ekd_tap) — born observed

Contracts preserved verbatim from the oracle (see docs/port-cards/
PORT-03-ekd.md): revision discipline (every mutation commits rev N+1
through record_ekd_mutation BEFORE the store write), EkdBatch
rollback-in-place semantics, bounded snapshot retention with journaled
prunes, canonical-key dedup, acyclicity-by-construction on the
provenance spine, Zep-style supersession (valid_to, never delete).
"""
from __future__ import annotations

import hashlib
import json
import logging
import os
import re
import time
import uuid
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Sequence, Set, Tuple

logger = logging.getLogger("AEGIS")

# ─── Taxonomies ──────────────────────────────────────────────────────


class NodeType:
    OBJECTIVE = "objective"
    TASK = "task"
    CALL = "call"
    ARTIFACT = "artifact"
    ENTITY = "entity"
    FINDING = "finding"
    HYPOTHESIS = "hypothesis"
    DECISION = "decision"
    AGENT_EVENT = "agent_event"
    NOTE = "note"
    ALL = (OBJECTIVE, TASK, CALL, ARTIFACT, ENTITY, FINDING, HYPOTHESIS,
           DECISION, AGENT_EVENT, NOTE)


class EdgeKind:
    DERIVED_FROM = "derived_from"
    TARGETS = "targets"
    OBSERVED_ON = "observed_on"
    SAME_AS = "same_as"
    PRODUCED = "produced"
    DEPENDS_ON = "depends_on"
    ASSIGNED_TO = "assigned_to"
    SUPPORTS = "supports"
    CONTRADICTS = "contradicts"
    ENABLES = "enables"
    INVALIDATES = "invalidates"
    MENTIONS = "mentions"
    ALL = (DERIVED_FROM, TARGETS, OBSERVED_ON, SAME_AS, PRODUCED,
           DEPENDS_ON, ASSIGNED_TO, SUPPORTS, CONTRADICTS, ENABLES,
           INVALIDATES, MENTIONS)


ENTITY_SUBTYPES = (
    "host", "net", "port_service", "endpoint", "domain", "tech",
    "credential", "user_account", "payload", "file", "mobile_app",
    "crypto_material",
)

FINDING_SEVERITIES = ("critical", "high", "medium", "low", "info")
FINDING_STATUSES = ("open", "verified", "exploited", "refuted")

# Typed short-id prefixes (case-sensitive; documented for memory_query).
_ID_PREFIX: Dict[str, str] = {
    NodeType.OBJECTIVE: "O",
    NodeType.TASK: "T",
    NodeType.CALL: "c",
    NodeType.ARTIFACT: "a",
    NodeType.ENTITY: "e",
    NodeType.FINDING: "F",
    NodeType.HYPOTHESIS: "H",
    NodeType.DECISION: "D",
    NodeType.AGENT_EVENT: "v",
    NodeType.NOTE: "n",
}

# Edge kinds that must point from a newer node to an older node (the
# provenance spine — enforcing this is what makes the EKD a DAG).
_BACKWARD_EDGE_KINDS = (EdgeKind.DERIVED_FROM, EdgeKind.PRODUCED,
                        EdgeKind.INVALIDATES)


def _TRACKED_ATTR(name: str) -> bool:
    """Attributes whose value change is recorded as supersession history."""
    return name in ("state", "status", "validity", "os", "os_guess",
                    "service_version")


# ─── Canonical keys ──────────────────────────────────────────────────

_IPV4_RE = re.compile(
    r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}"
    r"(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b")


def host_key(ip: str) -> str:
    return f"ip:{str(ip).strip()}"


def net_key(cidr: str) -> str:
    return f"cidr:{str(cidr).strip().lower()}"


def domain_key(domain: str) -> str:
    d = str(domain).strip().lower().rstrip(".")
    if d.startswith("www."):
        d = d[4:]
    return f"domain:{d}"


def url_key(url: str) -> str:
    """Scheme+host+port+normalized path+query (drops fragments)."""
    from urllib.parse import urlsplit, urlunsplit
    try:
        parts = urlsplit(str(url).strip())
        scheme = parts.scheme.lower() or "http"
        netloc = parts.netloc.lower()
        path = parts.path or "/"
        if path != "/" and path.endswith("/"):
            path = path.rstrip("/")
        return f"url:{urlunsplit((scheme, netloc, path, parts.query, ''))}"
    except Exception:
        return f"url:{str(url).strip().lower()}"


def port_service_key(ip: str, port: int, proto: str = "tcp") -> str:
    return f"port:{str(ip).strip()}:{int(port)}/{str(proto).lower()}"


def cve_key(cve: str) -> str:
    return f"cve:{str(cve).strip().upper()}"


def cred_key(kind: str, fingerprint: str) -> str:
    """Credential canonical key — value is NEVER stored, only the H4-style
    SHA-256 fingerprint (8 hex chars), same scheme as safe_execution."""
    return f"cred:fp:{str(kind).lower()}:{str(fingerprint).lower()}"


def user_key(account: str) -> str:
    return f"user:{str(account).strip().lower()}"


def pkg_key(package: str) -> str:
    return f"pkg:{str(package).strip().lower()}"


def tech_key(name: str, version: str = "") -> str:
    n = str(name).strip().lower()
    v = str(version).strip().lower()
    return f"tech:{n}" + (f"@{v}" if v else "")


def fingerprint_value(value: str) -> str:
    """SHA-256 fingerprint (8 hex) — matches safe_execution._fingerprint."""
    return hashlib.sha256(str(value).encode("utf-8", "ignore")).hexdigest()[:8]


# ─── Data model ──────────────────────────────────────────────────────


@dataclass
class DAGNode:
    id: str
    type: str
    title: str
    subtype: Optional[str] = None
    key: Optional[str] = None
    attrs: Dict[str, Any] = field(default_factory=dict)
    conf: float = 1.0
    ts: float = 0.0
    rev: int = 0
    valid_to: Optional[int] = None      # None while current
    provenance: List[str] = field(default_factory=list)  # node ids

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id, "type": self.type, "subtype": self.subtype,
            "key": self.key, "title": self.title, "attrs": self.attrs,
            "conf": self.conf, "ts": self.ts, "rev": self.rev,
            "valid_to": self.valid_to, "provenance": list(self.provenance),
        }

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "DAGNode":
        return cls(
            id=str(d.get("id", "")), type=str(d.get("type", "note")),
            title=str(d.get("title", "")),
            subtype=d.get("subtype"), key=d.get("key"),
            attrs=dict(d.get("attrs") or {}),
            conf=float(d.get("conf", 1.0)), ts=float(d.get("ts", 0.0)),
            rev=int(d.get("rev", 0)), valid_to=d.get("valid_to"),
            provenance=list(d.get("provenance") or []),
        )


@dataclass
class DAGEdge:
    kind: str
    src: str
    dst: str
    rev: int = 0
    valid_to: Optional[int] = None       # None while current

    def to_dict(self) -> Dict[str, Any]:
        return {"kind": self.kind, "src": self.src, "dst": self.dst,
                "rev": self.rev, "valid_to": self.valid_to}

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "DAGEdge":
        return cls(kind=str(d.get("kind", "")), src=str(d.get("src", "")),
                   dst=str(d.get("dst", "")), rev=int(d.get("rev", 0)),
                   valid_to=d.get("valid_to"))


# ─── The graph ───────────────────────────────────────────────────────


class EngagementDAG:
    """Append-only, provenance-connected engagement knowledge graph.

    Single-writer discipline: one instance per engagement, owned by the
    loop's context (ctx.extra['ekd']), persisted to the workspace state
    file after every committed EkdBatch. All mutation goes through
    add()/add_edge()/invalidate()/merge_entities().
    """

    def __init__(self) -> None:
        self.nodes: Dict[str, DAGNode] = {}
        self.edges: List[DAGEdge] = []
        self.rev: int = 0
        # per-type id counters (for typed short ids)
        self.counters: Dict[str, int] = {}
        # key -> node id index for O(1) canonical dedup
        self._key_index: Dict[str, str] = {}
        # src/dst adjacency (built lazily, rebuilt on from_json)
        self._adj_out: Dict[str, List[DAGEdge]] = {}
        self._adj_in: Dict[str, List[DAGEdge]] = {}
        # provenance walk memo invalidation token
        self._dirty = True

    # ---------------------------------------------------------- bookkeeping
    def _touch(self) -> None:
        # M2 (2026-10-06) carried: index dirtiness is decoupled from the
        # rev bump; every mutation path maintains the key/adjacency
        # indexes incrementally so a rev advance does not force the next
        # read to rebuild every index (the old flag made each add()
        # O(nodes+edges), quadratic across a 100-turn run).
        self.rev += 1

    def _mint_id(self, node_type: str) -> str:
        n = self.counters.get(node_type, 0) + 1
        self.counters[node_type] = n
        return f"{_ID_PREFIX.get(node_type, 'x')}{n}"

    def _rebuild_indexes(self) -> None:
        self._key_index = {n.key: nid for nid, n in self.nodes.items()
                           if n.key and n.valid_to is None}
        # keep invalid nodes out of the key index EXCEPT when no live node
        # holds the key (an invalidated fact still owns its history).
        for nid, n in self.nodes.items():
            if n.key and n.valid_to is not None and n.key not in self._key_index:
                self._key_index.setdefault(n.key, nid)
        self._adj_out = {}
        self._adj_in = {}
        for e in self.edges:
            self._adj_out.setdefault(e.src, []).append(e)
            self._adj_in.setdefault(e.dst, []).append(e)
        self._dirty = False

    def _ensure_indexes(self) -> None:
        if self._dirty:
            self._rebuild_indexes()

    # ------------------------------------------------------------ write path
    def add(self, node: DAGNode, edges: Optional[List[DAGEdge]] = None,
            merge_attrs: bool = True) -> str:
        """Add a node (canonical-key dedup) + its edges. Returns node id.

        Dedup: if a node with the same canonical `key` exists and is
        current, attributes merge (union for lists, latest-wins for scalars
        with an invalidation edge when a tracked value changes) and no
        duplicate node is created. Provenance lists union.
        """
        self._ensure_indexes()
        if node.key:
            existing_id = self._key_index.get(node.key)
            if existing_id is not None:
                existing = self.nodes[existing_id]
                if existing.valid_to is None:
                    self._merge_into(existing, node)
                    self._touch()
                    self._attach_edges(existing.id, edges)
                    return existing.id
                # else: superseded key holder — the new observation revives
                # the key as a NEW node; the old one stays as history.

        self._touch()
        node.id = node.id or self._mint_id(node.type)
        node.rev = self.rev
        if not node.ts:
            node.ts = time.time()
        node.provenance = list(dict.fromkeys(node.provenance))
        self.nodes[node.id] = node
        if node.key:
            self._key_index[node.key] = node.id
        self._adj_out.setdefault(node.id, [])
        self._adj_in.setdefault(node.id, [])
        self._attach_edges(node.id, edges)
        return node.id

    def _merge_into(self, existing: DAGNode, incoming: DAGNode) -> None:
        """Conservative attribute merge (exact-key match only — R2)."""
        for k, v in (incoming.attrs or {}).items():
            if v is None:
                continue
            old = existing.attrs.get(k)
            if isinstance(v, list) and isinstance(old, list):
                merged = list(old) + [x for x in v if x not in old]
                existing.attrs[k] = merged
            elif old is None or old == "" or old != v:
                if old is not None and old != "" and _TRACKED_ATTR(k):
                    # tracked value changed: record supersession on the node
                    existing.attrs.setdefault("history", []).append(
                        {"attr": k, "was": old, "now": v,
                         "rev": self.rev + 1})
                existing.attrs[k] = v
        if incoming.provenance:
            existing.provenance = list(dict.fromkeys(
                existing.provenance + incoming.provenance))
        existing.conf = max(existing.conf, incoming.conf)
        # H7b (2026-10-06) carried: a merged node must re-project — bump
        # node.rev so the merge is visible as a mutation (a finding
        # re-observed as 'exploited' kept its creation rev and the stale
        # row survived forever). Only when something actually changed.
        if incoming.attrs or incoming.provenance:
            existing.rev = max(existing.rev, self.rev + 1)

    def _attach_edges(self, node_id: str,
                      edges: Optional[List[DAGEdge]]) -> None:
        for e in (edges or []):
            if e.src is None or e.src == "":
                e.src = node_id
            self.add_edge(e.kind, e.src, e.dst, _bump=False)

    def add_edge(self, kind: str, src: str, dst: str,
                 _bump: bool = True) -> Optional[DAGEdge]:
        """Append an edge (deduped). Backward edge kinds must point from a
        newer revision to an older one — violations are dropped + logged,
        which structurally guarantees acyclicity of the provenance spine."""
        if not src or not dst or src == dst:
            return None
        if src not in self.nodes or dst not in self.nodes:
            logger.debug("[EKD] edge references unknown node (%s %s->%s) "
                         "dropped", kind, src, dst)
            return None
        if kind in _BACKWARD_EDGE_KINDS:
            s_rev = self.nodes[src].rev
            d_rev = self.nodes[dst].rev
            if s_rev < d_rev:
                logger.warning(
                    "[EKD] non-chronological %s edge %s(r%d) -> %s(r%d) "
                    "dropped (EKD stays a DAG by construction)",
                    kind, src, s_rev, dst, d_rev)
                return None
        for e in self.edges:
            if (e.kind == kind and e.src == src and e.dst == dst
                    and e.valid_to is None):
                return e  # dedup exact live edge
        edge = DAGEdge(kind=kind, src=src, dst=dst)
        if _bump:
            self._touch()
        edge.rev = self.rev
        self.edges.append(edge)
        self._adj_out.setdefault(src, []).append(edge)
        self._adj_in.setdefault(dst, []).append(edge)
        return edge

    def invalidate(self, node_id: str, reason_id: Optional[str] = None,
                   note: str = "") -> None:
        """Zep-style supersession: stamp valid_to, keep history derivable."""
        node = self.nodes.get(node_id)
        if node is None or node.valid_to is not None:
            return
        self._touch()
        node.valid_to = self.rev
        if note:
            node.attrs.setdefault("invalidations", []).append(
                {"rev": self.rev, "note": note})
        if reason_id and reason_id in self.nodes:
            # reason (newer) invalidates node (older) — backward edge
            self.add_edge(EdgeKind.INVALIDATES, reason_id, node_id,
                          _bump=False)
        if node.key:
            # M2 (2026-10-06) carried: the invalidated node remains the
            # key's history holder so by_key() can still find it for
            # entity history and fold-audit checks — WITHOUT a full
            # rebuild. A revival add() overwrites the holder; guard so a
            # late invalidate of an already-superseded node cannot
            # clobber the successor's ownership.
            if self._key_index.get(node.key) in (node.id, None):
                self._key_index[node.key] = node.id

    def invalidate_edge(self, kind: str, src: str, dst: str) -> None:
        for e in self.edges:
            if (e.kind == kind and e.src == src and e.dst == dst
                    and e.valid_to is None):
                self._touch()
                e.valid_to = self.rev
                return

    def merge_entities(self, a: str, b: str) -> Optional[str]:
        """same_as + attribute merge. `a` survives as canonical. Only
        called with evidence-backed pairs (never fuzzy — R2)."""
        na, nb = self.nodes.get(a), self.nodes.get(b)
        if not na or not nb or a == b:
            return None
        self._merge_into(na, nb)
        self._touch()
        self.add_edge(EdgeKind.SAME_AS, b, a, _bump=False)
        # retarget live edges pointing at b -> a
        for e in list(self.edges):
            if e.valid_to is None and e.dst == b and e.kind != EdgeKind.SAME_AS:
                self.invalidate_edge(e.kind, e.src, e.dst)
                self.add_edge(e.kind, e.src, a, _bump=False)
        self.invalidate(b, reason_id=a, note="merged into canonical entity")
        return a

    # ------------------------------------------------------------- read path
    def get(self, node_id: str) -> Optional[DAGNode]:
        return self.nodes.get(node_id)

    def by_key(self, key: str) -> Optional[DAGNode]:
        self._ensure_indexes()
        nid = self._key_index.get(key)
        return self.nodes.get(nid) if nid else None

    def current(self) -> List[DAGNode]:
        return [n for n in self.nodes.values() if n.valid_to is None]

    def nodes_of_type(self, node_type: str,
                      current_only: bool = True) -> List[DAGNode]:
        out = []
        for n in self.nodes.values():
            if n.type != node_type:
                continue
            if current_only and n.valid_to is not None:
                continue
            out.append(n)
        out.sort(key=lambda n: n.rev)
        return out

    def edges_of(self, kinds: Optional[Sequence[str]] = None,
                 current_only: bool = True) -> List[DAGEdge]:
        return [e for e in self.edges
                if (kinds is None or e.kind in kinds)
                and (not current_only or e.valid_to is None)]

    def neighbors(self, node_id: str,
                  kinds: Optional[Sequence[str]] = None,
                  direction: str = "both", depth: int = 1,
                  current_only: bool = True) -> List[DAGNode]:
        self._ensure_indexes()
        seen: Set[str] = {node_id}
        frontier = [node_id]
        out: List[DAGNode] = []
        for _ in range(max(1, depth)):
            nxt: List[str] = []
            for nid in frontier:
                cand: List[DAGEdge] = []
                if direction in ("out", "both"):
                    cand += self._adj_out.get(nid, [])
                if direction in ("in", "both"):
                    cand += self._adj_in.get(nid, [])
                for e in cand:
                    if kinds is not None and e.kind not in kinds:
                        continue
                    if current_only and e.valid_to is not None:
                        continue
                    other = e.dst if e.src == nid else e.src
                    if other in seen or other not in self.nodes:
                        continue
                    seen.add(other)
                    out.append(self.nodes[other])
                    nxt.append(other)
            frontier = nxt
        out.sort(key=lambda n: n.rev)
        return out

    def provenance_chain(self, node_id: str) -> List[DAGNode]:
        """Walk derived_from (denormalized on node.provenance) to the roots.
        Guarded against cycles by construction + a visited set anyway."""
        chain: List[DAGNode] = []
        seen: Set[str] = set()
        queue = [node_id]
        while queue:
            nid = queue.pop(0)
            if nid in seen:
                continue
            seen.add(nid)
            node = self.nodes.get(nid)
            if node is None:
                continue
            chain.append(node)
            queue.extend(p for p in node.provenance if p in self.nodes)
        # oldest-first (roots at the front)
        chain.sort(key=lambda n: n.rev)
        return chain

    def reaches_objective(self, node_id: str) -> bool:
        for n in self.provenance_chain(node_id):
            if n.type == NodeType.OBJECTIVE:
                return True
        # tasks/notes may be objective-rooted via assignment edges too
        for n in self.provenance_chain(node_id):
            for p in self.neighbors(n.id, kinds=(EdgeKind.DERIVED_FROM,),
                                    direction="in"):
                if p.type == NodeType.OBJECTIVE:
                    return True
        return False

    def query(self, q: str, limit: int = 10) -> List[DAGNode]:
        """Exact id -> exact key -> substring search over current nodes."""
        q = str(q).strip()
        if not q:
            return []
        # 1. exact id (case-sensitive then insensitive)
        node = self.nodes.get(q)
        if node is not None:
            return [node]
        for nid, n in self.nodes.items():
            if nid.lower() == q.lower() and n.valid_to is None:
                return [n]
        # 2. exact canonical key
        node = self.by_key(q) or self.by_key(q.lower())
        if node is not None:
            return [node]
        # 3. key/value/title substring over current nodes
        ql = q.lower()
        scored: List[Tuple[int, DAGNode]] = []
        for n in self.current():
            hay = f"{n.id} {n.key or ''} {n.title}".lower()
            if ql in hay:
                scored.append((3 if ql in (n.key or "").lower()
                               else 2 if ql in n.title.lower() else 1, n))
            else:
                blob = json.dumps(n.attrs, default=str).lower()
                if ql in blob:
                    scored.append((1, n))
        scored.sort(key=lambda t: (-t[0], t[1].rev))
        return [n for _, n in scored[:limit]]

    def entity_history(self, node_id: str) -> List[Dict[str, Any]]:
        """Every observation touching an entity, in revision order."""
        events: List[Dict[str, Any]] = []
        node = self.nodes.get(node_id)
        if node is None:
            return events
        for n in [node] + self.neighbors(
                node_id, kinds=(EdgeKind.TARGETS, EdgeKind.OBSERVED_ON,
                                EdgeKind.PRODUCED, EdgeKind.SAME_AS,
                                EdgeKind.MENTIONS, EdgeKind.ENABLES),
                direction="in", depth=1):
            events.append({"rev": n.rev, "id": n.id, "type": n.type,
                           "title": n.title, "ts": n.ts,
                           "current": n.valid_to is None})
        events.sort(key=lambda e: e["rev"])
        return events

    def calls_on(self, entity_id: str) -> List[DAGNode]:
        """Calls targeting an entity — the structural duplicate-scan guard."""
        calls = []
        for e in self.edges_of((EdgeKind.TARGETS,), current_only=True):
            if e.dst == entity_id:
                c = self.nodes.get(e.src)
                if c is not None and c.type == NodeType.CALL \
                        and c.valid_to is None:
                    calls.append(c)
        calls.sort(key=lambda c: c.ts)
        return calls

    def stats(self) -> Dict[str, Any]:
        by_type: Dict[str, int] = {}
        for n in self.current():
            by_type[n.type] = by_type.get(n.type, 0) + 1
        return {
            "rev": self.rev,
            "nodes_total": len(self.nodes),
            "nodes_current": len(self.current()),
            "edges_total": len(self.edges),
            "edges_current": len(self.edges_of()),
            "by_type": by_type,
        }

    # ------------------------------------------------------------- dot view
    def to_dot(self, max_nodes: int = 200) -> str:
        """Graphviz DOT export for the dag_overview debug surface (R6)."""
        current = self.current()
        if not current:
            return "digraph engagement {}"
        by_rev = sorted(current, key=lambda n: n.rev)
        keep = {n.id for n in by_rev[-max_nodes:]}
        out = ["digraph engagement {", "  rankdir=BT;",
               '  node [shape=box, fontsize=10];']
        for nid in sorted(keep):
            n = self.nodes[nid]
            color = {"finding": "red", "entity": "blue",
                     "objective": "gold", "call": "grey",
                     "artifact": "orange", "task": "green"}.get(n.type,
                                                                "black")
            label = f"{n.id} {n.title[:40]}".replace('"', "'")
            out.append(f'  "{nid}" [label="{label}", color={color}];')
        for e in self.edges:
            if e.valid_to is None and e.src in keep and e.dst in keep:
                out.append(f'  "{e.src}" -> "{e.dst}" '
                           f'[label="{e.kind}", fontsize=8];')
        out.append("}")
        return "\n".join(out)

    # ---------------------------------------------------------- persistence
    def to_json(self) -> str:
        payload = {
            "version": 2,
            "rev": self.rev,
            "counters": self.counters,
            "nodes": {nid: n.to_dict() for nid, n in self.nodes.items()},
            "edges": [e.to_dict() for e in self.edges],
        }
        return json.dumps(payload, separators=(",", ":"), default=str,
                          ensure_ascii=False)

    @classmethod
    def from_json(cls, blob: Optional[str],
                  *, journal: Any = None) -> "EngagementDAG":
        dag = cls()
        if not blob:
            return dag
        try:
            data = json.loads(blob)
        except (json.JSONDecodeError, TypeError):
            logger.warning("[EKD] corrupt ekd state payload — starting "
                           "a fresh graph (the journal snapshots retain "
                           "the old one)")
            # M8 (2026-10-06) carried: a corrupt state was silent outside
            # the log — the journal carries an error event so replay and
            # debug analysis see the recovery boundary.
            if journal is not None:
                try:
                    journal.append("error", {
                        "where": "ekd_state",
                        "reason": "corrupt payload — fresh graph "
                                  "(snapshots retain prior state)",
                        "blob_chars": len(blob)})
                except Exception:
                    pass
            return dag
        if not isinstance(data, dict):
            return dag
        try:
            dag.rev = int(data.get("rev", 0))
            dag.counters = {str(k): int(v)
                            for k, v in (data.get("counters") or {}).items()}
            for nid, nd in (data.get("nodes") or {}).items():
                node = DAGNode.from_dict(nd)
                dag.nodes[str(nid)] = node
            for ed in (data.get("edges") or []):
                dag.edges.append(DAGEdge.from_dict(ed))
            dag._rebuild_indexes()
        except Exception as exc:
            logger.error("[EKD] deserialization failed (%s) — fresh graph",
                         exc)
            if journal is not None:
                try:
                    journal.append("error", {
                        "where": "ekd_state",
                        "reason": f"deserialization failed: {exc}",
                        "blob_chars": len(blob)})
                except Exception:
                    pass
            return cls()
        return dag

    def __len__(self) -> int:
        return len(self.nodes)


# ─── EkdBatch: the one choke point every mutation passes through ─────
#
# ekd_txn.py (371 ln) carried with 4.0 deltas: the "engagement ctx" of
# 3.7.3 becomes the loop's ToolContext (journal + extractor failure
# counters ride ctx.extra); the state-channel write becomes the
# workspace ekd.json write performed by the batch's commit when a
# state path is supplied.

# Bounded delta: at most this many ids per category in the journal event
# (counts always accurate; lists are refs for forensics, not blobs).
DELTA_ID_CAP = 40

# M3 (2026-10-06) carried: bounded ekd/ snapshot retention. One
# full-graph JSON per rev-advancing batch, fsync'd — unbounded was GBs
# over a 100+ turn run. The newest SNAPSHOT_RETENTION files survive;
# older ones are pruned oldest-first (mtime order), each prune journaled
# as an ekd_snapshot_prune event so replay treats the references as
# pruned, not missing.
DEFAULT_SNAPSHOT_RETENTION = 40

EXTRACTOR_KEYS = ("tier_a", "task_sync", "fold_audit", "other")


def _env_int(name: str, default: int, floor: int = 0) -> int:
    try:
        return max(floor, int(os.environ.get(name, "") or default))
    except (TypeError, ValueError):
        return default


def _sha16(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8", "ignore")).hexdigest()[:16]


def _parse(blob: str) -> Optional[Dict[str, Any]]:
    try:
        return json.loads(blob) if blob else {}
    except (json.JSONDecodeError, TypeError):
        return None


def _node_index(parsed: Dict[str, Any]) -> Dict[str, Dict[str, Any]]:
    nodes = parsed.get("nodes") or {}
    return nodes if isinstance(nodes, dict) else {}


def compute_delta(before_blob: str, after_blob: str) -> Dict[str, Any]:
    """Bounded structural diff of two ekd JSON snapshots. Refs over
    blobs: ids + canonical keys, capped lists, exact counts."""
    before = _parse(before_blob) or {}
    after = _parse(after_blob) or {}
    b_nodes = _node_index(before)
    a_nodes = _node_index(after)

    created: List[str] = []
    updated: List[str] = []
    invalidated: List[str] = []
    keys: Dict[str, str] = {}
    for nid, n in a_nodes.items():
        old = b_nodes.get(nid)
        if old is None:
            created.append(nid)
        elif old != n:
            # whole-node compare: catches merges (attrs/provenance/conf
            # changed without a node-rev bump) as well as re-observations
            if old.get("valid_to") is None and n.get("valid_to") is not None:
                invalidated.append(nid)
            else:
                updated.append(nid)
        if nid in created or nid in updated:
            k = n.get("key")
            if k:
                keys[nid] = str(k)
    b_edges = before.get("edges") or []
    a_edges = after.get("edges") or []
    delta: Dict[str, Any] = {
        "created": created[:DELTA_ID_CAP],
        "created_total": len(created),
        "updated": updated[:DELTA_ID_CAP],
        "updated_total": len(updated),
        "invalidated": invalidated[:DELTA_ID_CAP],
        "invalidated_total": len(invalidated),
        "edges_added": max(0, len(a_edges) - len(b_edges)),
    }
    if keys:
        # capped key map for the first ids only (forensics)
        delta["keys"] = dict(list(keys.items())[:DELTA_ID_CAP])
    return delta


def new_extractor_failures() -> Dict[str, int]:
    """The per-engagement failure counter surface (Table 13 'flagged')."""
    return {k: 0 for k in EXTRACTOR_KEYS} | {"total": 0}


class EkdBatch:
    """One isolated, journaled, rollback-safe EKD mutation batch.

    Usage (the loop's tool post-hook and the fold's audit path):

        with EkdBatch(ekd, ctx, extractor="tier_a", reason=tool_name,
                      extra={"tool_call_id": tcid}) as b:
            extract_tool_result(ekd, ...)

    On success: journals ekd_mutation (delta + snapshot ref) when the
    rev advanced, writes the workspace state file (J1: journal event
    BEFORE the state write — a crash between the two is what recovery
    detects). On exception: restores ekd in place, journals an `error`
    event, bumps the extractor failure counters, suppresses. When no
    journal rides the context: pure passthrough (exceptions propagate
    exactly as the caller's own try/except would see).
    """

    def __init__(self, ekd: EngagementDAG, ctx: Any, *,
                 extractor: str,
                 reason: str = "",
                 extra: Optional[Dict[str, Any]] = None,
                 isolate: bool = True,
                 state_path: Optional[str] = None):
        self.ekd = ekd
        self.ctx = ctx
        self.extractor = extractor
        self.reason = reason
        self.extra = extra or {}
        # isolate=False: journal present but the site wants legacy crash
        # propagation (reserved; all current sites isolate).
        self.isolate = isolate
        self._journal = getattr(ctx, "journal", None)
        # 4.0: the state channel is the workspace ekd.json
        self._state_path = state_path or (
            (ctx.extra or {}).get("ekd_state_path")
            if getattr(ctx, "extra", None) else None)
        self._before_blob: Optional[str] = None
        self._rev_before = 0
        self.failed = False
        self.failure_exc: Optional[BaseException] = None
        self.snapshot_retention = _env_int(
            "AEGIS_EKD_SNAPSHOT_RETENTION", DEFAULT_SNAPSHOT_RETENTION, 2)

    # -- internals ----------------------------------------------------

    def _snapshot_dir(self) -> Optional[str]:
        j = self._journal
        if j is None:
            return None
        base = getattr(j, "path", None)
        return os.path.join(str(base), "ekd") if base else None

    def _write_snapshot(self, rev_after: int,
                        blob: Optional[str] = None
                        ) -> Tuple[Optional[str], Optional[str]]:
        """Durably store the full EKD at rev_after. Returns (filename,
        sha) or (None, None) on any failure (never raises — a missing
        snapshot degrades replay, it does not block the write path).

        Filenames are unique per batch (uuid suffix), NOT rev-derived:
        after an operator /reset the revision counter restarts at 0 and a
        rev-derived name would collide with the pre-reset snapshot. The
        journal event references the exact filename, so recovery never
        has to guess. M2 (2026-10-06) carried: accepts the
        already-serialized blob (one serialization serves delta +
        snapshot + sha); after a successful write, retention prunes the
        oldest snapshots (journaled first, unlinked after — write-ahead
        discipline).
        """
        try:
            d = self._snapshot_dir()
            if not d:
                return None, None
            os.makedirs(d, exist_ok=True)
            if blob is None:
                blob = self.ekd.to_json()
            name = f"ekd_snap_{int(rev_after)}_{uuid.uuid4().hex[:6]}.json"
            path = os.path.join(d, name)
            with open(path, "w", encoding="utf-8") as f:
                f.write(blob)
                f.flush()
                os.fsync(f.fileno())
            try:
                os.chmod(path, 0o600)
            except OSError:
                pass
            self._prune_snapshots(d)
            return name, _sha16(blob)
        except Exception as exc:  # snapshot failure must never gate
            logger.debug("[EKD-TXN] snapshot write skipped: %s", exc)
            return None, None

    def _prune_snapshots(self, directory: str) -> None:
        """M3 (2026-10-06) carried: bounded retention. Deletes oldest
        snapshots (mtime order — names are NOT zero-padded by rev, so
        lexical order lies after rev 9) beyond the retention window. The
        prune event is journaled BEFORE any unlink: replay pre-scans
        those events and treats pruned references as pruned, not
        missing. Idempotent on replay of the same directory.
        """
        try:
            entries = []
            for n in os.listdir(directory):
                if n.startswith("ekd_snap_") and n.endswith(".json"):
                    try:
                        entries.append(
                            (os.path.getmtime(os.path.join(directory, n)), n))
                    except OSError:
                        pass
            if len(entries) <= self.snapshot_retention:
                return
            entries.sort()
            excess = len(entries) - self.snapshot_retention
            doomed = [n for _, n in entries[:excess]]
            if self._journal is not None:
                try:
                    self._journal.append("ekd_snapshot_prune", {
                        "pruned": doomed,
                        "retained": len(entries) - excess,
                        "retention": self.snapshot_retention,
                        "reason": "bounded retention"})
                except Exception:
                    pass
            for n in doomed:
                try:
                    os.remove(os.path.join(directory, n))
                except OSError:
                    pass
        except Exception as exc:
            logger.debug("[EKD-TXN] snapshot prune skipped: %s", exc)

    def _write_state(self, blob: str) -> None:
        """The state-channel write the journal event precedes (J1).
        Atomic temp+rename so a crash mid-write never corrupts the
        state file (the journal's snapshots remain the recovery source
        either way)."""
        if not self._state_path:
            return
        try:
            path = os.path.abspath(self._state_path)
            os.makedirs(os.path.dirname(path), exist_ok=True)
            tmp = path + f".tmp.{uuid.uuid4().hex[:6]}"
            with open(tmp, "w", encoding="utf-8") as f:
                f.write(blob)
                f.flush()
                os.fsync(f.fileno())
            os.replace(tmp, path)
            try:
                os.chmod(path, 0o600)
            except OSError:
                pass
        except Exception as exc:
            logger.debug("[EKD-TXN] state write skipped: %s", exc)

    def _restore_in_place(self) -> bool:
        """Restore the pre-batch state onto the SAME object so every
        caller-held reference sees the rollback."""
        try:
            fresh = EngagementDAG.from_json(self._before_blob)
            self.ekd.__dict__.update(fresh.__dict__)
            return True
        except Exception as exc:
            logger.error("[EKD-TXN] rollback failed: %s", exc)
            return False

    def _bump_failure_counter(self) -> None:
        try:
            counters = (getattr(self.ctx, "extra", None) or {}).get(
                "extractor_failures")
            if isinstance(counters, dict):
                key = self.extractor if self.extractor in \
                    EXTRACTOR_KEYS else "other"
                counters[key] = int(counters.get(key, 0)) + 1
                counters["total"] = int(counters.get("total", 0)) + 1
        except Exception:
            pass

    # -- context manager ----------------------------------------------

    def __enter__(self) -> "EkdBatch":
        if self._journal is not None:
            self._before_blob = self.ekd.to_json()
            self._rev_before = int(self.ekd.rev)
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> bool:
        if exc_type is None:
            self._commit()
            return False
        # ── failure path (Table 13 row 1) ────────────────────────────
        self.failed = True
        self.failure_exc = exc_val
        if self._journal is None:
            # Legacy semantics: no rollback machinery — the exception
            # propagates to the site's own try/except.
            return False
        rolled = self._restore_in_place()
        try:
            self._journal.record_extractor_failure(
                self.extractor,
                reason=self.reason or "batch crashed",
                detail=f"{type(exc_val).__name__}: "
                       f"{str(exc_val)[:200]}",
                tool=str(self.extra.get("tool", "")))
        except Exception:
            pass
        self._bump_failure_counter()
        logger.warning(
            "[EKD-TXN] %s batch failed (%s) — batch skipped%s, "
            "ekd rev %d unchanged, continuing with next batch",
            self.extractor, self.reason or "",
            "" if rolled else " (ROLLBACK FAILED - graph may carry "
            "partial batch state)", self._rev_before)
        return self.isolate  # suppress -> caller's loop continues

    # -- success path --------------------------------------------------

    def _commit(self) -> None:
        if self._journal is None or self._before_blob is None:
            # no journal: still persist the state file so the workspace
            # graph survives restarts (best-effort, never gates)
            if self._state_path and self.ekd.rev > self._rev_before:
                try:
                    self._write_state(self.ekd.to_json())
                except Exception:
                    pass
            return
        try:
            rev_after = int(self.ekd.rev)
            if rev_after <= self._rev_before:
                return  # no-op batch: nothing to journal (J1 only
                        # covers actual state changes)
            after_blob = self.ekd.to_json()
            # M2 carried: one serialization serves delta + snapshot + sha
            snap, snap_sha = self._write_snapshot(rev_after, blob=after_blob)
            self._journal.record_ekd_mutation(
                self._rev_before, rev_after,
                extractor=self.extractor,
                nodes=len(getattr(self.ekd, "nodes", {}) or {}),
                edges=len(getattr(self.ekd, "edges", []) or []),
                reason=self.reason,
                delta=compute_delta(self._before_blob, after_blob),
                snapshot=snap,
                snapshot_sha=snap_sha,
                extra=self.extra or None)
            # J1 ordering: the journal event is durable BEFORE the state
            # write — a crash between the two leaves (journal rev N,
            # state rev N-1), exactly what recover() detects and repairs.
            self._write_state(after_blob)
            # the brief header names "the agent or extractor that
            # produced the latest mutation" (5.4) — track it on the
            # context so the next assembly renders the truth.
            try:
                who = str(self.extractor)
                if self.reason:
                    who += f":{self.reason}"
                if getattr(self.ctx, "extra", None) is not None:
                    self.ctx.extra["ekd_last_actor"] = who
            except Exception:
                pass
        except Exception as exc:
            # J4 discipline: the recorder never gates the write path.
            logger.debug("[EKD-TXN] journal commit skipped: %s", exc)


# ─── Workspace state + recovery (the 4.0 state channel) ───────────────


def state_path_for(workspace: str) -> str:
    """<workspace>/ekd.json — the single-writer state file."""
    return os.path.join(os.path.abspath(workspace), "ekd.json")


def save_state(ekd: EngagementDAG, workspace: str) -> None:
    """Persist the graph to the workspace state file (atomic, 0600)."""
    p = state_path_for(workspace)
    os.makedirs(os.path.dirname(p), exist_ok=True)
    tmp = p + f".tmp.{uuid.uuid4().hex[:6]}"
    blob = ekd.to_json()
    with open(tmp, "w", encoding="utf-8") as f:
        f.write(blob)
        f.flush()
        os.fsync(f.fileno())
    os.replace(tmp, p)
    try:
        os.chmod(p, 0o600)
    except OSError:
        pass


def load_or_create(workspace: str, *, journal: Any = None
                   ) -> EngagementDAG:
    """Boot path: load the workspace state file, or start fresh."""
    p = state_path_for(workspace)
    if os.path.exists(p):
        try:
            with open(p, "r", encoding="utf-8") as f:
                return EngagementDAG.from_json(f.read(), journal=journal)
        except OSError as exc:
            logger.warning("[EKD] state file unreadable (%s) — fresh "
                           "graph", exc)
    return EngagementDAG()


def recover(journal: Any, workspace: str) -> Tuple[EngagementDAG, bool]:
    """J1 crash repair: reconcile the workspace state against the
    journal's last committed ekd_mutation.

    Returns (ekd, repaired). When the journal's last committed rev is
    ahead of the state file's rev (crash between journal append and
    state write), the graph is rebuilt from the referenced snapshot —
    byte-reconstructible by construction. A journal BEHIND the state
    file (state written, journal append lost) cannot happen with the
    write-ahead ordering; treated as a no-op with the state trusted.
    """
    ekd = load_or_create(workspace, journal=journal)
    last_rev = -1
    snapshot = None
    try:
        for ev in journal.events_of_type("ekd_mutation"):
            rev = int(ev.get("data", {}).get("rev_after", -1))
            if rev > last_rev:
                last_rev = rev
                snapshot = ev.get("data", {}).get("snapshot")
    except Exception:
        return ekd, False
    if last_rev < 0 or last_rev <= ekd.rev:
        return ekd, False
    # journal ahead of state: rebuild from the snapshot artifact
    base = getattr(journal, "path", None)
    if base and snapshot:
        snap_path = os.path.join(str(base), "ekd", str(snapshot))
        try:
            with open(snap_path, "r", encoding="utf-8") as f:
                repaired = EngagementDAG.from_json(f.read(), journal=journal)
                if repaired.rev >= last_rev:
                    logger.warning(
                        "[EKD] crash detected (journal rev %d > state rev "
                        "%d) — recovered from snapshot %s",
                        last_rev, ekd.rev, snapshot)
                    save_state(repaired, workspace)
                    return repaired, True
        except Exception:
            pass
    logger.error("[EKD] journal rev %d ahead of state rev %d but the "
                 "referenced snapshot is unavailable — starting a fresh "
                 "graph (the journal remains the forensic truth)",
                 last_rev, ekd.rev)
    fresh = EngagementDAG()
    return fresh, True
