"""hypervisor.memory.extractors — Tier-A parsers as tool post-hooks (P2).

PORT-04: the deterministic regex/JSON parsers that turn tool results
into bounded EKD batch deltas (3.7.3 src/core/dag_extractors.py, 1,230
ln + the security-entity regex battery from semantic_store.py). NO LLM
IN THIS PATH — EVER: Tier-B (planner-model extraction at fold time)
does NOT port as an automatic behavior per the ratified card; if 4.0
ever wants it, it goes through the loop as an explicit side_query,
card-amended. The fold auditor (the MD-2 killer) covers hard-fact
preservation deterministically instead.

4.0 deltas:
  * attachment point: the dispatcher's post-hook (run_post_hook) runs
    the whole extraction inside an EkdBatch — crash isolation, journal
    write-ahead and rollback are the batch's, not the caller's
  * tool names: the parser table maps 4.0 names (run_command et al.);
    the oracle parser functions port unchanged for the P3+ VAPT tools
    (nmap/nuclei/mobile/http/headless) that will register under their
    own names
  * scope admission rides the 4.0 scope engine (ctx.permissions.scope)
    — classify_host/is_authorized, same SD-1 semantics
  * the task-DAG channel mirror becomes sync_todos (todo_write is the
    4.0 task surface)
"""
from __future__ import annotations

import hashlib
import json
import logging
import os
import re
import time
from typing import Any, Dict, List, Optional, Sequence, Tuple

from .ekd import (
    DAGEdge, DAGNode, EdgeKind, EngagementDAG, EkdBatch,
    cve_key, cred_key, domain_key, fingerprint_value, host_key, net_key,
    pkg_key, port_service_key, tech_key, url_key, user_key,
)

logger = logging.getLogger("AEGIS")

CVE_RE = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.IGNORECASE)
BUFFER_PATH_RE = re.compile(
    r"workspace/buffers/agent_buffer_([0-9a-fA-F]{4,16})\.log")
_MAX_ITEMS_PER_KIND = 200  # pathological-output guard


# ─── small helpers ───────────────────────────────────────────────────


def _sha12(text: str) -> str:
    """M1 fix (2026-10-06) carried: key hashes widened 8 -> 12 hex chars
    (32 -> 48 bits). At ~9.5K distinct hashed keys the old 32-bit space
    hit a ~1% collision rate — two objectives colliding silently merged
    nodes. 48 bits keeps the birthday bound under 0.0002% at the same
    scale. Keys are content addresses, not display ids."""
    return hashlib.sha256(str(text).encode("utf-8", "ignore")).hexdigest()[:12]


# A bare dotted-quad, used by key normalization for model-inferred titles
_IPV4Exact_RE = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")


def _mask_secret(value: str, keep: int = 2) -> str:
    v = str(value)
    if len(v) <= keep * 2:
        return "*" * len(v)
    return f"{v[:keep]}{'*' * max(4, min(12, len(v) - keep * 2))}{v[-keep:]}"


def _extract_json_blob(text: str) -> Optional[Any]:
    """Best-effort JSON extraction: whole text, then first balanced
    object or array (handles ```json fences and surrounding prose)."""
    text = text.strip()
    for candidate in (text, re.sub(r"^```(?:json)?|```$", "", text,
                                   flags=re.MULTILINE).strip()):
        try:
            return json.loads(candidate)
        except Exception:
            pass
    for opener, closer in (("{", "}"), ("[", "]")):
        start = text.find(opener)
        while start != -1:
            depth = 0
            for i in range(start, len(text)):
                if text[i] == opener:
                    depth += 1
                elif text[i] == closer:
                    depth -= 1
                    if depth == 0:
                        try:
                            return json.loads(text[start:i + 1])
                        except Exception:
                            break
            start = text.find(opener, start + 1)
    return None


def _scope_engine(ctx: Any):
    """The 4.0 scope engine rides the permission gate."""
    gate = getattr(ctx, "permissions", None)
    return getattr(gate, "scope", None)


def _scope_flag(ctx: Any, value: str) -> Optional[bool]:
    """Informational in_scope flag from the real scope engine (audit-mode
    semantics; enforcement stays at the gate, deny-by-default)."""
    try:
        scope = _scope_engine(ctx)
        if scope is None or not value:
            return None
        authorized, _ = scope.is_authorized(str(value).split(":")[0].split("/")[0])
        return bool(authorized)
    except Exception:
        return None


def _scope_admission(ctx: Any, host: Any) -> Optional[Dict[str, Any]]:
    """SD-1 carried: host classification at the extractor seam — the
    scope_reason travels with the entity into the brief and
    memory_query (expand: classified admission; strict: adjacent =
    visible, never targeted)."""
    try:
        scope = _scope_engine(ctx)
        if scope is None or not host:
            return None
        strict_classify = getattr(ctx, "journal", None) is not None
        return scope.classify_host(str(host), method="extraction",
                                   strict_classify=strict_classify)
    except Exception:
        return None


def _entity(ekd: EngagementDAG, subtype: str, key: str, title: str,
            attrs: Optional[Dict[str, Any]] = None,
            provenance: Optional[List[str]] = None,
            supersede_on: Sequence[str] = (),
            ctx: Any = None) -> str:
    """Upsert an entity with canonical-key dedup + explicit supersession
    on tracked attr changes (port state, credential validity, ...).
    Returns the node id (callers attach targets/produced edges)."""
    existing = ekd.by_key(key)
    superseded_id: Optional[str] = None
    if existing is not None and existing.valid_to is None:
        for attr in supersede_on:
            new_v = (attrs or {}).get(attr)
            old_v = existing.attrs.get(attr)
            if new_v is not None and old_v is not None and old_v != new_v:
                ekd.invalidate(existing.id, note=f"{attr}: {old_v} → {new_v}")
                superseded_id = existing.id
                break
    attrs = dict(attrs or {})
    if ctx is not None and attrs.get("in_scope") is None:
        host = attrs.get("host") or title
        rec = _scope_admission(ctx, host)
        if rec is not None:
            # SD-1 (expand) / strict-adjacent: the classification record
            # travels with the entity into the brief and memory_query.
            attrs["in_scope"] = bool(rec["in_scope"])
            attrs["scope_reason"] = rec["scope_reason"]
        else:
            flag = _scope_flag(ctx, host)
            if flag is not None:
                attrs["in_scope"] = flag
    node = DAGNode(id="", type="entity", subtype=subtype, key=key,
                   title=title[:200], attrs=attrs, conf=1.0,
                   provenance=provenance or [])
    nid = ekd.add(node)
    if superseded_id and nid != superseded_id:
        # M7 (2026-10-06) carried: supersession must carry the
        # INVALIDATES edge from the successor — entity_history walks
        # that chain, and a bare valid_to stamp split the history across
        # the boundary. Backward-edge check passes by construction: the
        # successor's rev is the graph head.
        ekd.add_edge(EdgeKind.INVALIDATES, nid, superseded_id, _bump=False)
    return nid


def _finding(ekd: EngagementDAG, key: str, title: str,
             severity: str = "info", status: str = "open",
             attrs: Optional[Dict[str, Any]] = None,
             observed_on_entity: Optional[str] = None,
             provenance: Optional[List[str]] = None,
             conf: float = 1.0) -> str:
    sev = str(severity or "info").lower()
    if sev not in ("critical", "high", "medium", "low", "info"):
        sev = "info"
    node = DAGNode(id="", type="finding", key=key, title=title[:200],
                   attrs={"severity": sev, "status": status,
                          **(attrs or {})}, conf=conf,
                   provenance=provenance or [])
    fid = ekd.add(node)
    if observed_on_entity:
        ekd.add_edge(EdgeKind.OBSERVED_ON, fid, observed_on_entity)
    return fid


def _note(ekd: EngagementDAG, key: Optional[str], title: str,
          attrs: Optional[Dict[str, Any]] = None,
          provenance: Optional[List[str]] = None) -> str:
    node = DAGNode(id="", type="note", key=key, title=title[:200],
                   attrs=dict(attrs or {}), provenance=provenance or [])
    return ekd.add(node)


# ─── objective / call / task / event scaffolding ─────────────────────


def ensure_objective(ekd: EngagementDAG, user_objective: str) -> str:
    """Root node: the verbatim operator prompt. One node per distinct
    objective text (follow-up rounds create O2, O3, ...)."""
    text = str(user_objective or "").strip()
    if not text:
        text = "(no objective recorded)"
    key = f"objective:{_sha12(text)}"
    existing = ekd.by_key(key)
    if existing is not None:
        return existing.id
    node = DAGNode(id="", type="objective", key=key,
                   title=text[:120], attrs={"text": text}, conf=1.0)
    return ekd.add(node)


def record_call(ekd: EngagementDAG, tool: str,
                args: Optional[Dict[str, Any]],
                agent: str, status: str = "ok",
                provenance: Optional[List[str]] = None) -> str:
    safe_args: Dict[str, Any] = {}
    for k, v in (args or {}).items():
        sv = json.dumps(v, default=str)[:300] if not isinstance(v, str) \
            else v[:300]
        safe_args[str(k)] = sv
    node = DAGNode(id="", type="call", key=None,
                   title=f"{tool}({', '.join(safe_args.keys())})",
                   attrs={"tool": tool, "args": safe_args, "agent": agent,
                          "status": status, "ts": time.time()},
                   conf=1.0, provenance=provenance or [])
    return ekd.add(node)


def record_agent_event(ekd: EngagementDAG, kind: str, agent: str,
                       detail: str = "",
                       provenance: Optional[List[str]] = None) -> str:
    node = DAGNode(id="", type="agent_event", key=None, title=kind,
                   attrs={"agent": agent, "detail": detail[:500],
                          "ts": time.time()},
                   provenance=provenance or [])
    return ekd.add(node)


def sync_todos(ekd: EngagementDAG, todos: Sequence[Dict[str, Any]],
               provenance: Optional[List[str]] = None) -> int:
    """Mirror the todo_write surface (the 4.0 task state) into EKD task
    nodes — the sync_task_nodes heir adapted to the todo shape. Status
    changes route through add() so the tracked-attr supersession history
    records them and the batch journals the mutation (H6 carried).
    Returns task nodes touched."""
    touched = 0
    anchor = provenance or []
    for t in todos:
        if not isinstance(t, dict):
            continue
        tid = str(t.get("id") or t.get("content", ""))[:80]
        if not tid:
            continue
        key = f"task:todo:{_sha12(tid)}"
        status = str(t.get("status", "pending"))
        existing = ekd.by_key(key)
        if existing is not None and existing.valid_to is None:
            if existing.attrs.get("status") != status:
                ekd.add(DAGNode(
                    id="", type="task", key=existing.key,
                    title=existing.title,
                    attrs={**existing.attrs, "status": status},
                    provenance=anchor))
        else:
            node = DAGNode(id="", type="task", key=key,
                           title=str(t.get("content", tid))[:200],
                           attrs={"status": status,
                                  "agent": "main",
                                  "priority": t.get("priority", "")},
                           provenance=anchor)
            ekd.add(node)
        touched += 1
    return touched


# ─── Tier-A: buffer artifacts ────────────────────────────────────────


def register_artifacts(ekd: EngagementDAG, output: str, ctx: Any,
                       provenance: Optional[List[str]] = None) -> List[str]:
    """Every advertised buffer path in a tool output becomes an artifact
    node (path, sha256, bytes, preview when readable)."""
    ids = []
    for m in BUFFER_PATH_RE.finditer(output or ""):
        buf_id = m.group(1)
        advertised = m.group(0)
        key = f"buffer:{buf_id}"
        if ekd.by_key(key) is not None:
            ids.append(ekd.by_key(key).id)
            continue
        attrs: Dict[str, Any] = {"path": advertised,
                                 "kind": "buffer"}
        if ctx is not None:
            phys = os.path.join(getattr(ctx, "workspace", ""),
                                "buffers", f"agent_buffer_{buf_id}.log")
            try:
                with open(phys, "r", encoding="utf-8",
                          errors="replace") as fh:
                    data = fh.read()
                attrs["sha256"] = hashlib.sha256(
                    data.encode("utf-8", "ignore")).hexdigest()
                attrs["bytes"] = len(data)
                attrs["preview"] = data[:200]
            except OSError:
                pass
        node = DAGNode(id="", type="artifact", key=key,
                       title=f"buffer {advertised}", attrs=attrs,
                       provenance=provenance or [])
        ids.append(ekd.add(node))
    return ids


def _full_output(output: str, ctx: Any) -> str:
    """When the renderer truncated the text, recover the full output
    from the advertised buffer file (C2 paths)."""
    if "OUTPUT TRUNCATED" not in output:
        return output
    m = BUFFER_PATH_RE.search(output)
    if not m or ctx is None:
        return output
    phys = os.path.join(getattr(ctx, "workspace", ""),
                        "buffers", f"agent_buffer_{m.group(1)}.log")
    try:
        with open(phys, "r", encoding="utf-8", errors="replace") as fh:
            return fh.read()
    except OSError:
        return output


# ─── the security-entity regex battery (semantic_store heir) ─────────
#
# Mechanical, LLM-free extraction of the security-critical inventory.
# Order follows pattern priority (jwt > credential > ...) and per-kind
# caps keep pathological tool output bounded. The audit surface can SAY
# when it stopped looking (M14: return_truncated lists every kind whose
# cap was actually reached — dedupe-aware, so hitting exactly the cap
# with no further distinct values does not false-positive).

_SECURITY_ENTITY_PATTERNS: List[Tuple[str, "re.Pattern", bool]] = [
    # (kind, compiled pattern, case-insensitive match?) - priority order
    ("jwt", re.compile(
        r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{5,}"), False),
    ("credential", re.compile(
        r"(?i)\b(?:password|passwd|pwd|secret|api[_-]?key|token|"
        r"session[_-]?id|auth[_-]?token)\s*[=:]\s*[\"']?"
        r"([A-Za-z0-9_\-./+=@!$*]{6,})"), True),
    ("private_key", re.compile(
        r"-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----"), False),
    ("url", re.compile(r"https?://[^\s'\"<>()\[\]{}]+"), False),
    ("host_port", re.compile(
        r"\b(?:\d{1,3}\.){3}\d{1,3}:\d{2,5}\b"), False),
    ("ipv4", re.compile(
        r"\b(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\."
        r"(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\."
        r"(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\."
        r"(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b"), False),
    ("vuln_class", re.compile(
        r"(?i)\b(?:sql[_ ]?injection|nosql[_ ]?injection|xss|"
        r"cross[_ ]?site[_ ]?scripting|ssrf|xxe|ssti|csrf|idor|"
        r"command[_ ]?injection|path[_ ]?traversal|"
        r"privilege[_ ]?escalation|rce|lfi|rfi)\b"), True),
    ("hex_token", re.compile(r"\b[0-9a-fA-F]{32,}\b"), False),
    ("b64_token", re.compile(r"\b[A-Za-z0-9+/]{40,}={0,2}\b"), False),
]


def extract_security_entities(text: str,
                              max_per_kind: int = 40,
                              return_truncated: bool = False
                              ) -> Any:
    """Extract deduplicated (kind, value) security entities from text."""
    seen = set()
    found: List[Tuple[str, str]] = []
    truncated: List[str] = []
    for kind, pattern, case_insensitive in _SECURITY_ENTITY_PATTERNS:
        count = 0
        for match in pattern.finditer(text):
            value = match.group(1) if (kind == "credential"
                                       and match.groups()) else match.group(0)
            value = value.strip().rstrip(".,;:")
            if not value:
                continue
            key = (kind, value.lower() if case_insensitive else value)
            if key in seen:
                continue
            seen.add(key)
            found.append((kind, value))
            count += 1
            if count >= max_per_kind:
                # confirm a further DISTINCT value exists past the cap
                for m2 in pattern.finditer(text, match.end()):
                    v2 = m2.group(1) if (kind == "credential"
                                         and m2.groups()) else m2.group(0)
                    v2 = v2.strip().rstrip(".,;:")
                    if v2 and (kind, v2.lower() if case_insensitive
                               else v2) not in seen:
                        truncated.append(kind)
                        break
                break
    if return_truncated:
        return found, truncated
    return found


# ─── Tier-A: per-tool parsers ────────────────────────────────────────


def parse_nmap(ekd: EngagementDAG, output: str, call_id: str,
               ctx: Any) -> int:
    """jc 'nmap' JSON → host / port_service / tech entities with
    state-change supersession (filtered → open = invalidate + append)."""
    full = _full_output(output, ctx)
    data = _extract_json_blob(full)
    hosts: List[Dict[str, Any]] = []
    if isinstance(data, list):
        hosts = [h for h in data if isinstance(h, dict)]
    elif isinstance(data, dict):
        hosts = [data]
    added = 0
    for h in hosts[:64]:
        raw_ips = h.get("host") or h.get("addresses") or []
        if isinstance(raw_ips, str):
            raw_ips = [raw_ips]
        ips = [str(ip) for ip in raw_ips if ip][:4]
        hostname = h.get("hostname") or None
        for ip in ips:
            hid = _entity(ekd, "host", host_key(ip), ip,
                          attrs={"host": ip, "state": "up",
                                 "dns": hostname or ""},
                          provenance=[call_id], ctx=ctx)
            ekd.add_edge(EdgeKind.TARGETS, call_id, hid)
            added += 1
            if hostname:
                did = _entity(ekd, "domain", domain_key(hostname), hostname,
                              attrs={"resolves_to": ip},
                              provenance=[call_id], ctx=ctx)
                ekd.add_edge(EdgeKind.SAME_AS, did, hid)
            for p in (h.get("ports") or [])[:_MAX_ITEMS_PER_KIND]:
                if not isinstance(p, dict):
                    continue
                port = p.get("port") or p.get("port_id")
                if port is None:
                    continue
                proto = str(p.get("protocol", "tcp")).lower()
                state = str(p.get("state", "unknown")).lower()
                svc = p.get("service") or {}
                if not isinstance(svc, dict):
                    svc = {}
                name = svc.get("name") or ""
                product = svc.get("product") or ""
                version = svc.get("version") or ""
                label = f"{ip}:{port}"
                if name:
                    label = f"{name} {label}".strip()
                pid = _entity(ekd, "port_service",
                              port_service_key(ip, int(port), proto), label,
                              attrs={"host": ip, "port": int(port),
                                     "proto": proto, "state": state,
                                     "service": name,
                                     "service_version":
                                         f"{product} {version}".strip()},
                              provenance=[call_id], supersede_on=("state",),
                              ctx=ctx)
                ekd.add_edge(EdgeKind.TARGETS, call_id, pid)
                if product:
                    tid = _entity(ekd, "tech", tech_key(product, version),
                                  f"{product} {version}".strip(),
                                  attrs={"version": version},
                                  provenance=[call_id], ctx=ctx)
                    ekd.add_edge(EdgeKind.MENTIONS, pid, tid)
                added += 1
    return added


def parse_nuclei(ekd: EngagementDAG, output: str, call_id: str,
                 ctx: Any) -> int:
    """nuclei -jsonl / -json output → finding nodes + observed_on links."""
    full = _full_output(output, ctx)
    added = 0
    for line in full.splitlines():
        line = line.strip()
        if not line.startswith("{"):
            continue
        try:
            rec = json.loads(line)
        except json.JSONDecodeError:
            continue
        if not isinstance(rec, dict):
            continue
        if not (rec.get("template-id") or rec.get("templateID")
                or rec.get("template")):
            continue
        info = rec.get("info") or {}
        if not isinstance(info, dict):
            info = {}
        template = str(rec.get("template-id") or rec.get("templateID")
                       or rec.get("template") or "nuclei")
        name = str(info.get("name") or template)
        severity = str(info.get("severity", "info")).lower()
        matched_at = str(rec.get("matched-at") or rec.get("matched_at")
                         or rec.get("host") or "")
        cves = CVE_RE.findall(json.dumps(rec, default=str))
        eid = None
        if matched_at:
            if matched_at.startswith("http"):
                eid = _entity(ekd, "endpoint", url_key(matched_at),
                              matched_at, attrs={"host":
                                                 matched_at.split("/")[2]},
                              provenance=[call_id], ctx=ctx)
            else:
                eid = _entity(ekd, "host", host_key(matched_at), matched_at,
                              provenance=[call_id], ctx=ctx)
        fid = _finding(
            ekd, f"finding:nuclei:{template}:{_sha12(matched_at)}",
            f"{template}: {name}", severity=severity, status="open",
            attrs={"cve": cves[0] if cves else None,
                   "matched_at": matched_at, "tags": info.get("tags")},
            observed_on_entity=eid, provenance=[call_id])
        if eid:
            ekd.add_edge(EdgeKind.TARGETS, call_id, eid)
        # CVE referenced in the template/reference becomes a node too, so
        # the fold auditor's cve-token guarantee holds for nuclei output.
        for cve in cves[:4]:
            if ekd.by_key(cve_key(cve.upper())) is None:
                _finding(ekd, cve_key(cve.upper()),
                         f"{cve.upper()} referenced",
                         severity="info", status="open",
                         attrs={"source": "nuclei_reference",
                                "cve": cve.upper(),
                                "template": template,
                                "template_severity": severity},
                         provenance=[call_id])
        added += 1
    return added


def parse_mobile_analysis(ekd: EngagementDAG, output: str, call_id: str,
                          ctx: Any, is_ipa: bool = False) -> int:
    """analyze_apk / analyze_ipa result JSON → mobile_app entity, finding
    nodes (the tools emit a findings list), secrets → masked
    credentials, urls → endpoints."""
    full = _full_output(output, ctx)
    data = _extract_json_blob(full)
    if not isinstance(data, dict):
        return 0
    added = 0
    path = str(data.get("apk_path") or data.get("ipa_path") or "")
    pkg_name = os.path.basename(path) or "unknown_app"
    app_id = _entity(ekd, "mobile_app", pkg_key(pkg_name), pkg_name,
                     attrs={"path": path, "platform":
                            "ios" if is_ipa else "android"},
                     provenance=[call_id], ctx=ctx)
    added += 1
    for f in (data.get("findings") or [])[:_MAX_ITEMS_PER_KIND]:
        if not isinstance(f, dict):
            continue
        ftype = str(f.get("type", "unknown"))
        title = str(f.get("detail") or f.get("name") or ftype)[:180]
        key = f"finding:{'ipa' if is_ipa else 'apk'}:{ftype}:{_sha12(title)}"
        fid = _finding(ekd, key, f"{ftype}: {title}",
                       severity=str(f.get("severity", "info")),
                       status="open",
                       attrs={"component": f.get("component"),
                              "name": f.get("name")},
                       observed_on_entity=app_id, provenance=[call_id])
        added += 1
    for sec in (data.get("secrets") or [])[:64]:
        if not sec:
            continue
        s = str(sec)
        cid = _entity(ekd, "credential",
                      cred_key("secret", fingerprint_value(s)),
                      f"secret {len(s)}ch (fp {fingerprint_value(s)})",
                      attrs={"masked": _mask_secret(s),
                             "fp": fingerprint_value(s), "from": pkg_name},
                      provenance=[call_id], ctx=ctx)
        ekd.add_edge(EdgeKind.MENTIONS, app_id, cid)
        added += 1
    for u in (data.get("urls") or [])[:64]:
        u = str(u)
        if not u.startswith("http"):
            continue
        uid = _entity(ekd, "endpoint", url_key(u), u,
                      provenance=[call_id], ctx=ctx)
        ekd.add_edge(EdgeKind.MENTIONS, app_id, uid)
        added += 1
    return added


def parse_http_response(ekd: EngagementDAG, output: str, call_id: str,
                        args: Optional[Dict[str, Any]],
                        ctx: Any) -> int:
    """http request output → endpoint entity + tech + status, passive
    SECURITY INDICATOR lines → findings."""
    full = _full_output(output, ctx)
    added = 0
    url = str((args or {}).get("url") or "")
    meta = None
    if "--- HTTP METADATA ---" in full:
        blob = full.split("--- HTTP METADATA ---", 1)[1] \
                   .split("--- HTTP BODY ---", 1)[0]
        meta = _extract_json_blob(blob)
    if url:
        host = url.split("/")[2] if "://" in url else url
        attrs: Dict[str, Any] = {"host": host}
        if isinstance(meta, dict):
            attrs["status"] = meta.get("status_code")
            headers = meta.get("headers") or {}
            if isinstance(headers, dict):
                attrs["server"] = headers.get("Server", "")
                attrs["powered_by"] = headers.get("X-Powered-By", "")
            if attrs.get("status"):
                attrs["state"] = f"http_{attrs['status']}"
        eid = _entity(ekd, "endpoint", url_key(url), url, attrs=attrs,
                      provenance=[call_id], supersede_on=("state",),
                      ctx=ctx)
        ekd.add_edge(EdgeKind.TARGETS, call_id, eid)
        added += 1
        if isinstance(meta, dict):
            headers = meta.get("headers") or {}
            for hname in ("Server", "X-Powered-By"):
                val = (headers or {}).get(hname)
                if val:
                    tid = _entity(ekd, "tech", tech_key(val), str(val),
                                  provenance=[call_id], ctx=ctx)
                    ekd.add_edge(EdgeKind.MENTIONS, eid, tid)
                    added += 1
    # passive scanner alert lines
    if "SECURITY INDICATORS DETECTED" in full:
        block = full.split("SECURITY INDICATORS DETECTED", 1)[1]
        for line in block.splitlines():
            line = line.strip("= -\u00a0 ")
            if not line or len(line) < 8:
                continue
            if line.startswith("HTTP BODY") or line.startswith("-"):
                break
            _enode = ekd.by_key(url_key(url)) if url else None
            eid = _enode.id if _enode else None
            _finding(ekd, f"finding:passive:{_sha12(line)}", line[:180],
                     severity="medium", status="open",
                     attrs={"source": "passive_scanner"},
                     observed_on_entity=eid, provenance=[call_id])
            added += 1
            if added > _MAX_ITEMS_PER_KIND:
                break
    return added


def parse_headless_dom(ekd: EngagementDAG, output: str, call_id: str,
                       ctx: Any) -> int:
    """headless_dom_navigate/interact JSON → endpoint + passive findings."""
    full = _full_output(output, ctx)
    data = _extract_json_blob(full)
    added = 0
    if not isinstance(data, dict):
        return 0
    url = str(data.get("url") or data.get("new_url") or "")
    eid = None
    if url:
        eid = _entity(ekd, "endpoint", url_key(url), url,
                      attrs={"host": url.split("/")[2] if "://" in url
                             else url},
                      provenance=[call_id], ctx=ctx)
        ekd.add_edge(EdgeKind.TARGETS, call_id, eid)
        added += 1
    for alert in (data.get("SECURITY_ALERTS") or [])[:32]:
        alert = str(alert)
        _finding(ekd, f"finding:passive:{_sha12(alert)}", alert[:180],
                 severity="medium", status="open",
                 attrs={"source": "passive_scanner"},
                 observed_on_entity=eid, provenance=[call_id])
        added += 1
    return added


def parse_free_text(ekd: EngagementDAG, text: str, call_id: str,
                    ctx: Any) -> int:
    """Deterministic entity extraction from arbitrary tool output (shell,
    code, exploit scripts): the security-entity regex battery — IPs,
    URLs, host:port, credentials, JWTs, private keys — plus CVE
    references."""
    added = 0
    entities = extract_security_entities(text or "")
    for kind, value in entities[:_MAX_ITEMS_PER_KIND]:
        if kind == "ipv4":
            nid = _entity(ekd, "host", host_key(value), value,
                          attrs={"host": value}, provenance=[call_id],
                          ctx=ctx)
        elif kind == "url":
            nid = _entity(ekd, "endpoint", url_key(value), value,
                          attrs={"host": value.split("/")[2]},
                          provenance=[call_id], ctx=ctx)
        elif kind == "host_port":
            ip, _, port = value.rpartition(":")
            hid = _entity(ekd, "host", host_key(ip), ip,
                          attrs={"host": ip}, provenance=[call_id], ctx=ctx)
            nid = _entity(ekd, "port_service",
                          port_service_key(ip, int(port)), f"{ip}:{port}",
                          attrs={"host": ip, "port": int(port),
                                 "state": "referenced"},
                          provenance=[call_id], ctx=ctx)
            ekd.add_edge(EdgeKind.MENTIONS, nid, hid)
        elif kind == "credential":
            fp = fingerprint_value(value)
            nid = _entity(ekd, "credential", cred_key("cred", fp),
                          f"credential fp:{fp}",
                          attrs={"masked": _mask_secret(value), "fp": fp},
                          provenance=[call_id], ctx=ctx)
        elif kind in ("jwt", "hex_token", "b64_token"):
            fp = fingerprint_value(value)
            nid = _entity(ekd, "crypto_material",
                          cred_key("crypto", fp),
                          f"{kind} fp:{fp}",
                          attrs={"masked": _mask_secret(value, 4), "fp": fp,
                                 "kind": kind},
                          provenance=[call_id], ctx=ctx)
        elif kind == "private_key":
            fp = fingerprint_value(value[:64])
            nid = _entity(ekd, "crypto_material", cred_key("key", fp),
                          f"private key fp:{fp}",
                          attrs={"fp": fp}, provenance=[call_id], ctx=ctx)
        elif kind == "vuln_class":
            nid = None  # soft token: findings reference it, no entity
            blob = json.dumps([n.title for n in ekd.nodes_of_type("finding")])
            if value.lower() not in blob.lower():
                _finding(ekd, f"finding:class:{_sha12(value)}",
                         f"{value} (class referenced)",
                         severity="info", status="open",
                         attrs={"source": "text_reference",
                                "class": value},
                         provenance=[call_id])
                added += 1
            continue
        else:
            continue
        if nid:
            ekd.add_edge(EdgeKind.TARGETS, call_id, nid)
            added += 1
    for cve in CVE_RE.findall(text or "")[:64]:
        if ekd.by_key(cve_key(cve.upper())) is None:
            _finding(ekd, cve_key(cve.upper()), f"{cve.upper()} referenced",
                     severity="info", status="open",
                     attrs={"source": "text_reference", "cve": cve.upper()},
                     provenance=[call_id])
            added += 1
    return added


# ─── Tier-A dispatcher (per-tool) ────────────────────────────────────
#
# 4.0 tool-name mapping: run_command replaces execute_shell_command as
# the free-text + command-target path; the dedicated VAPT parsers keep
# their oracle names for the P3+ tool registrations that will call them.

_TIER_A_PARSERS = {
    "network_scan_nmap": lambda ekd, out, cid, args, ctx:
        parse_nmap(ekd, out, cid, ctx),
    "analyze_apk": lambda ekd, out, cid, args, ctx:
        parse_mobile_analysis(ekd, out, cid, ctx, is_ipa=False),
    "analyze_ipa": lambda ekd, out, cid, args, ctx:
        parse_mobile_analysis(ekd, out, cid, ctx, is_ipa=True),
    "advanced_http_request": parse_http_response,
    "headless_dom_navigate": lambda ekd, out, cid, args, ctx:
        parse_headless_dom(ekd, out, cid, ctx),
    "headless_dom_interact": lambda ekd, out, cid, args, ctx:
        parse_headless_dom(ekd, out, cid, ctx),
}

# 4.0 tools whose output goes through the free-text regex battery
_FREE_TEXT_TOOLS = {
    "run_command", "execute_code", "execute_exploit_script",
    "ssh_interactive_exec", "retrieve_url_content", "detect_waf",
    "web_search_osint", "map_vhost", "grep_file", "read_file_lines",
    "adb_command", "frida_hook", "objection_hook", "mitm_intercept",
    "check_port_listener",
}


def _looks_like_nuclei_jsonl(output: str) -> bool:
    """Content sniff: JSONL records carrying nuclei fields (template-id /
    info.severity / matched-at) — nuclei usually arrives through the
    shell tool, not a dedicated tool."""
    for line in output.splitlines()[:6]:
        line = line.strip()
        if not line.startswith("{"):
            continue
        try:
            rec = json.loads(line)
        except json.JSONDecodeError:
            return False
        if isinstance(rec, dict) and ("template-id" in rec or
                                      "templateID" in rec
                                      or "template" in rec):
            return True
        return False
    return False


def extract_tool_result(ekd: EngagementDAG, tool: str,
                        args: Optional[Dict[str, Any]], output: str,
                        agent: str, ctx: Any,
                        objective_id: Optional[str] = None
                        ) -> Optional[str]:
    """Tier-A extraction for ONE tool result. Creates the call node, runs
    the tool-specific parser, registers buffer artifacts, and returns the
    call node id (provenance anchor for everything the call produced).

    Runs INSIDE the caller's EkdBatch: an exception rolls the whole
    batch back ("EKD revision unchanged"), the batch flags it, and the
    post-hook moves on — extraction NEVER breaks the tool path."""
    if ekd is None or output is None:
        return None
    prov = [objective_id] if objective_id else []
    call_id = record_call(ekd, tool, args, agent,
                          status="ok" if output else "empty",
                          provenance=prov)
    out = str(output)
    parser = _TIER_A_PARSERS.get(tool)
    if parser is not None:
        parser(ekd, out, call_id, args, ctx)
    elif _looks_like_nuclei_jsonl(out):
        parse_nuclei(ekd, out, call_id, ctx)
    else:
        # free-text battery for every shell-class and unknown tool —
        # unknown tools still harvest artifacts + entities
        parse_free_text(ekd, out, call_id, ctx)
    register_artifacts(ekd, out, ctx, provenance=[call_id])
    # command-string targets (run_command etc.) — the scope engine's
    # parser, so extraction and enforcement agree on what was targeted
    cmd = (args or {}).get("command") or ""
    if cmd:
        from ..permissions import extract_targets_from_command
        for t in extract_targets_from_command(str(cmd))[:16]:
            if _IPV4Exact_RE.match(t):
                tid = _entity(ekd, "host", host_key(t), t,
                              attrs={"host": t}, provenance=[call_id],
                              ctx=ctx)
                ekd.add_edge(EdgeKind.TARGETS, call_id, tid)
            elif "/" in t:
                _entity(ekd, "net", net_key(t), t, provenance=[call_id],
                        ctx=ctx)
            else:
                tid = _entity(ekd, "domain", domain_key(t), t,
                              provenance=[call_id], ctx=ctx)
                ekd.add_edge(EdgeKind.TARGETS, call_id, tid)
    return call_id


def run_post_hook(ctx: Any, tool: str, args: Optional[Dict[str, Any]],
                  output: str, *, tool_call_id: str = ""
                  ) -> Optional[str]:
    """The dispatcher's post-hook: one EkdBatch per tool result, tier_a
    extraction inside. Duration-bounded by the caller (the turn
    watchdog); crash-contained by the batch."""
    ekd = (ctx.extra or {}).get("ekd") if ctx.extra else None
    if ekd is None:
        return None
    label = getattr(ctx, "label", "main")
    with EkdBatch(ekd, ctx, extractor="tier_a", reason=str(tool),
                  extra={"tool": str(tool),
                         "tool_call_id": str(tool_call_id)}) as b:
        call_id = extract_tool_result(
            ekd, str(tool), args, output, label, ctx,
            objective_id=(ctx.extra or {}).get("objective_id"))
    return call_id if not b.failed else None


# ─── Fold auditor (the MD-2 killer) ──────────────────────────────────


def _token_nodeified(ekd: EngagementDAG, kind: str, value: str) -> bool:
    """Does this hard fact token exist in the graph?"""
    if kind == "ipv4":
        return ekd.by_key(host_key(value)) is not None
    if kind == "url":
        return ekd.by_key(url_key(value)) is not None
    if kind == "host_port":
        ip, _, port = value.rpartition(":")
        return (ekd.by_key(port_service_key(ip, int(port))) is not None
                or ekd.by_key(host_key(ip)) is not None)
    if kind == "credential":
        fp = fingerprint_value(value)
        for n in ekd.nodes_of_type("entity", current_only=False):
            if n.subtype == "credential" and (
                    n.attrs.get("fp") == fp
                    or n.key == cred_key("cred", fp)):
                return True
        return False
    if kind in ("jwt", "hex_token", "b64_token"):
        fp = fingerprint_value(value)
        return any(n.subtype == "crypto_material"
                   and n.attrs.get("fp") == fp for n in
                   ekd.nodes_of_type("entity", current_only=False))
    if kind == "private_key":
        fp = fingerprint_value(value[:64])
        return any(n.subtype == "crypto_material"
                   and n.attrs.get("fp") == fp for n in
                   ekd.nodes_of_type("entity", current_only=False))
    if kind == "cve":
        return ekd.by_key(cve_key(value.upper())) is not None
    if kind == "vuln_class":
        blob = json.dumps([n.title for n in ekd.nodes_of_type("finding")])
        return value.lower() in blob.lower()
    return True


def _force_add_token(ekd: EngagementDAG, kind: str, value: str,
                     provenance: Optional[List[str]] = None) -> None:
    """Deterministic node creation for a bare fact token (no regex
    context needed) — the fold auditor's completion path. Each kind maps
    to exactly the node the _token_nodeified check looks for."""
    prov = provenance or []
    if kind == "ipv4":
        _entity(ekd, "host", host_key(value), value,
                attrs={"host": value}, provenance=prov)
    elif kind == "url":
        _entity(ekd, "endpoint", url_key(value), value,
                attrs={"host": value.split("/")[2] if "://" in value
                       else value}, provenance=prov)
    elif kind == "host_port":
        ip, _, port = value.rpartition(":")
        _entity(ekd, "port_service", port_service_key(ip, int(port)),
                f"{ip}:{port}",
                attrs={"host": ip, "port": int(port), "state": "referenced"},
                provenance=prov)
    elif kind == "credential":
        fp = fingerprint_value(value)
        _entity(ekd, "credential", cred_key("cred", fp),
                f"credential fp:{fp}",
                attrs={"masked": _mask_secret(value), "fp": fp},
                provenance=prov)
    elif kind in ("jwt", "hex_token", "b64_token"):
        fp = fingerprint_value(value)
        _entity(ekd, "crypto_material", cred_key("crypto", fp),
                f"{kind} fp:{fp}",
                attrs={"masked": _mask_secret(value, 4), "fp": fp,
                       "kind": kind}, provenance=prov)
    elif kind == "private_key":
        fp = fingerprint_value(value[:64])
        _entity(ekd, "crypto_material", cred_key("key", fp),
                f"private key fp:{fp}", attrs={"fp": fp},
                provenance=prov)
    elif kind == "cve":
        if ekd.by_key(cve_key(value.upper())) is None:
            _finding(ekd, cve_key(value.upper()),
                     f"{value.upper()} referenced", severity="info",
                     status="open",
                     attrs={"source": "fold_audit", "cve": value.upper()},
                     provenance=prov)
    elif kind == "vuln_class":
        _finding(ekd, f"finding:class:{_sha12(value)}",
                 f"{value} (class referenced)", severity="info",
                 status="open", attrs={"source": "fold_audit",
                                        "class": value}, provenance=prov)


def audit_fold(ekd: EngagementDAG, texts: Sequence[str],
               force_add: bool = True,
               provenance: Optional[List[str]] = None
               ) -> Dict[str, Any]:
    """Every hard fact token in the fold slice must be a graph node
    before the slice may be dropped. Missing tokens are force-added
    (deterministic Tier-A) so the guarantee holds BY CONSTRUCTION, then
    re-verified. `texts` are the content strings of the messages being
    folded (4.0 shape: the caller flattens block content)."""
    text = "\n".join(str(t) for t in texts)
    text += "\n" + " ".join(CVE_RE.findall(text))
    # M14 (2026-10-06) carried: cap raised to the parse_free_text guard
    # scale (200) and any cap hit is reported by kind in the return dict
    # — the audit surface must be able to SAY when it stopped looking.
    tokens, capped_kinds = extract_security_entities(
        text, max_per_kind=200, return_truncated=True)
    tokens += [("cve", c.upper()) for c in CVE_RE.findall(text)[:200]]
    if capped_kinds:
        logger.warning("[EKD] fold audit: per-kind token cap reached "
                       "(%s) — the slice carries more distinct tokens "
                       "than audited", ", ".join(capped_kinds))
    missing: List[Tuple[str, str]] = []
    for kind, value in tokens:
        if kind in ("hex_token", "b64_token"):
            # soft tokens: noisy hashes — logged, not enforced
            if not _token_nodeified(ekd, kind, value):
                logger.debug("[EKD] fold audit: soft token %s not nodeified",
                             kind)
            continue
        if not _token_nodeified(ekd, kind, value):
            missing.append((kind, value))
    forced = 0
    if force_add and missing:
        prov = provenance or []
        anchor = _note(ekd, None, "fold-audit completion",
                       attrs={"added": len(missing)}, provenance=prov)
        for kind, value in missing:
            _force_add_token(ekd, kind, value, [anchor])
            forced += 1
        # re-verify
        still = [v for k, v in missing
                 if not _token_nodeified(ekd, k, v)]
        if still:
            logger.error("[EKD] fold audit: %d tokens could not be "
                         "nodeified: %s", len(still), still[:8])
    return {"tokens": len(tokens), "missing": len(missing),
            "force_added": forced, "capped_kinds": capped_kinds}
