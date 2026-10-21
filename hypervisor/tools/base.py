"""hypervisor.tools.base — Tool protocol and dispatcher (P1).

Skeleton 9-2 of the ratified blueprint; disposition family REFACTOR-05
(3.7.3 tools/safe_execution.py + toolset). Design contracts:

  * a tool is pure data: name, arg schema, concurrency class, safety
    class, renderer — never control flow (principle 2)
  * the dispatcher combines the concurrency class with the permission
    engine at gate time; execution runs on bounded executors —
    Semaphore-class channels, CC's concurrency model
    (toolOrchestration.ts:91-177): runs of consecutive concurrency-safe
    tools execute in parallel under a cap of ten (env-overridable), any
    unsafe tool serializes its batch, and a shell-class tool error
    cancels its pending siblings (StreamingToolExecutor.ts:354-363)
  * every dispatch emits tool start/end/error spans through the debug
    kit's LoopObserver and permission_decision events through the
    journal
  * tool results are data with budgets (preview caps, truncation
    markers, buffer files) — the context engine (P2) applies the
    cascade, not the tool

The registry freezes tool order and schema serialization at boot — the
byte-stability rule (principle 8): the wire tool array is serialized
once and never re-derived, so the endpoint's prefix cache hits.

Pipeline per call (CC toolExecution.ts order, P1 subset): name
resolution with aliases -> abort check -> schema validation ->
semantic validation -> permission gate -> bounded execution -> result
mapping with size caps and disk persistence for oversized results.
"""
from __future__ import annotations

import asyncio
import hashlib
import json
import os
import re
import stat
import threading
import time
import uuid
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Sequence, Tuple

from ..permissions import SafetyClass

DEFAULT_CONCURRENCY = 10
DEFAULT_TOOL_TIMEOUT_S = 120.0
INF_RESULT_CHARS = -1           # negative = exempt from budgeting (rule 9-2)


def _env_int(name: str, default: int) -> int:
    try:
        return int(os.environ.get(name, "") or default)
    except (TypeError, ValueError):
        return default


# ─── results ───────────────────────────────────────────────────────────

@dataclass
class ToolResult:
    """What a tool returns. `content` is the model-facing text (already
    rendered, already capped); `is_error` routes it as an error result;
    `metadata` carries tool-specific diagnostics (exit codes, counts)."""
    content: str = ""
    is_error: bool = False
    metadata: Dict[str, Any] = field(default_factory=dict)

    @classmethod
    def error(cls, message: str, **meta) -> "ToolResult":
        return cls(content=str(message), is_error=True, metadata=meta)


# ─── the context a tool executes within ────────────────────────────────

class ToolContext:
    """Everything a tool may touch. Carried by the loop's params and
    passed to every call (CC's ToolUseContext analog, VAPT-shaped)."""

    def __init__(self, *, workspace: str, registry: "ToolRegistry",
                 permissions: Any = None, journal: Any = None,
                 observer: Any = None, abort: Optional[asyncio.Event] = None,
                 turn: int = 0, depth: int = 0, label: str = "main",
                 extra: Optional[Dict[str, Any]] = None):
        self.workspace = os.path.abspath(workspace)
        self.registry = registry
        self.permissions = permissions
        self.journal = journal
        self.observer = observer
        self.abort = abort if abort is not None else asyncio.Event()
        self.turn = int(turn)
        self.depth = int(depth)
        self.label = str(label)
        self.extra: Dict[str, Any] = dict(extra or {})

    def child(self, **kw) -> "ToolContext":
        """Spawn a child context (subagents, P3): scoped tools, own
        permissions, shared workspace + abort tree."""
        c = ToolContext(workspace=kw.get("workspace", self.workspace),
                        registry=kw.get("registry", self.registry),
                        permissions=kw.get("permissions", self.permissions),
                        journal=kw.get("journal", self.journal),
                        observer=kw.get("observer", self.observer),
                        abort=kw.get("abort", self.abort),
                        turn=kw.get("turn", self.turn),
                        depth=kw.get("depth", self.depth + 1),
                        label=kw.get("label", self.label + "-child"),
                        extra=kw.get("extra", dict(self.extra)))
        return c


# ─── the protocol ──────────────────────────────────────────────────────

class Tool(ABC):
    """A tool is pure data (principle 2): it receives arguments and a
    context, returns a ToolResult, and NEVER mutates loop state, routes
    or spawns on its own behalf."""

    #: unique, stable name (model-facing)
    name: str = ""
    #: deprecated-name tolerance (Table 7-4 'aliases')
    aliases: Tuple[str, ...] = ()
    #: JSON Schema for the input; validated before the gate runs
    #: (subclasses replace this with their own dict; never mutated)
    input_schema: Dict[str, Any] = {"type": "object",
                                    "properties": {}}

    #: wall-clock bound for one execution (principle 9)
    timeout_s: float = DEFAULT_TOOL_TIMEOUT_S
    #: cancel pending siblings when this errors inside a parallel batch
    #: (the Bash rule: shell commands carry implicit dependency chains)
    cancel_siblings_on_error: bool = False

    # ------------------------------------------------------------ surface

    @abstractmethod
    def prompt(self) -> str:
        """The model-facing description (stable; part of the frozen
        wire serialization)."""

    @abstractmethod
    async def call(self, args: Dict[str, Any], ctx: ToolContext
                   ) -> ToolResult:
        """Execute. Pure function of (args, ctx)."""

    def safety_class(self, args: Dict[str, Any]) -> SafetyClass:
        """Classify THIS invocation (not the tool): the same tool can be
        READ for a local grep and EXPLOIT for a network scan."""
        return SafetyClass.READ

    def concurrency_safe(self, args: Dict[str, Any]) -> bool:
        """Parallel-lane ticket. False serializes the batch."""
        return True

    def is_persistent(self, args: Dict[str, Any]) -> bool:
        """RoE hook: True when this invocation installs persistence."""
        return False

    def extract_targets(self, args: Dict[str, Any]) -> List[str]:
        """Network targets this invocation will touch (scope gate
        input). Local tools return []."""
        return []

    def validate_input(self, args: Dict[str, Any]) -> Optional[str]:
        """Semantic validation (schema already checked). Return an
        error string or None."""
        return None

    def max_result_chars(self) -> int:
        """Preview cap for the model-facing render; negative exempts
        from budgeting (Table 7-4 'max_result_chars')."""
        return 8000

    def description(self, args: Dict[str, Any]) -> str:
        """One-line result label (timeline rendering)."""
        return self.name


# ─── minimal JSON-Schema validation (stdlib-only, fixed subset) ────────

_TYPE_CHECKS = {
    "string": lambda v: isinstance(v, str),
    "integer": lambda v: isinstance(v, int) and not isinstance(v, bool),
    "number": lambda v: isinstance(v, (int, float)) and not isinstance(v, bool),
    "boolean": lambda v: isinstance(v, bool),
    "array": lambda v: isinstance(v, list),
    "object": lambda v: isinstance(v, dict),
    "null": lambda v: v is None,
}


def validate_schema(schema: Dict[str, Any], data: Any,
                    path: str = "$") -> Optional[str]:
    """Validate `data` against the schema subset every 4.0 tool uses:
    type, required, properties, enum, minimum/maximum, min/maxLength,
    pattern, items, minItems, additionalProperties. Returns the first
    error string or None. Deterministic (sorted keys) so error text is
    stable across runs."""
    if not isinstance(schema, dict):
        return None
    t = schema.get("type")
    if isinstance(t, str) and t in _TYPE_CHECKS:
        if not _TYPE_CHECKS[t](data):
            return f"{path}: expected {t}, got {type(data).__name__}"
    if isinstance(t, list):
        if not any(_TYPE_CHECKS[x](data) for x in t if x in _TYPE_CHECKS):
            return f"{path}: expected one of {t}, got {type(data).__name__}"
    if "enum" in schema and data not in schema["enum"]:
        return f"{path}: {data!r} not in enum"
    if isinstance(data, str):
        if "minLength" in schema and len(data) < schema["minLength"]:
            return f"{path}: shorter than minLength {schema['minLength']}"
        if "maxLength" in schema and len(data) > schema["maxLength"]:
            return f"{path}: longer than maxLength {schema['maxLength']}"
        if "pattern" in schema:
            try:
                if not re.search(schema["pattern"], data):
                    return (f"{path}: does not match pattern "
                            f"{schema['pattern']!r}")
            except re.error:
                pass
    if isinstance(data, (int, float)) and not isinstance(data, bool):
        if "minimum" in schema and data < schema["minimum"]:
            return f"{path}: below minimum {schema['minimum']}"
        if "maximum" in schema and data > schema["maximum"]:
            return f"{path}: above maximum {schema['maximum']}"
    if isinstance(data, list):
        if "minItems" in schema and len(data) < schema["minItems"]:
            return f"{path}: fewer than minItems {schema['minItems']}"
        if "items" in schema:
            for i, item in enumerate(data):
                err = validate_schema(schema["items"], item,
                                      f"{path}[{i}]")
                if err:
                    return err
    if isinstance(data, dict):
        for req in sorted(schema.get("required") or []):
            if req not in data:
                return f"{path}: missing required property {req!r}"
        props = schema.get("properties") or {}
        if schema.get("additionalProperties") is False:
            for k in sorted(set(data) - set(props)):
                return f"{path}: additional property {k!r} not allowed"
        for k in sorted(set(data) & set(props)):
            err = validate_schema(props[k], data[k], f"{path}.{k}")
            if err:
                return err
    return None


# ─── registry ──────────────────────────────────────────────────────────

class ToolRegistry:
    """Freezes tool order and schema serialization at boot (principle
    8). After freeze(), registration raises; the wire array is computed
    once and cached."""

    def __init__(self):
        self._tools: Dict[str, Tool] = {}
        self._order: List[str] = []
        self._frozen_wire: Optional[List[Dict[str, Any]]] = None

    def register(self, tool: Tool) -> None:
        if self._frozen_wire is not None:
            raise RuntimeError("registry is frozen; cannot register "
                               f"{tool.name!r}")
        if not tool.name:
            raise ValueError("tool without a name")
        if tool.name in self._tools:
            raise ValueError(f"duplicate tool name {tool.name!r}")
        for alias in tool.aliases:
            if alias and alias in self._tools:
                raise ValueError(f"duplicate tool alias {alias!r}")
        self._tools[tool.name] = tool
        self._order.append(tool.name)

    def resolve(self, name: str) -> Optional[Tool]:
        t = self._tools.get(name)
        if t is not None:
            return t
        for tool in self._tools.values():
            if name in tool.aliases:
                return tool
        return None

    def names(self) -> List[str]:
        return list(self._order)

    def __len__(self) -> int:
        return len(self._order)

    def __iter__(self):
        return iter(self._tools[t] for t in self._order)

    def freeze(self) -> List[Dict[str, Any]]:
        """Compute the byte-stable wire tool array exactly once."""
        if self._frozen_wire is None:
            from ..adapters.openai import wire_tools
            self._frozen_wire = wire_tools(
                [self._tools[n] for n in self._order])
        return self._frozen_wire

    def validate(self, name: str, args: Any) -> Optional[str]:
        tool = self.resolve(name)
        if tool is None:
            return f"unknown tool {name!r}"
        return validate_schema(tool.input_schema, args, f"${name}")


# ─── secret redaction (H4, ported from safe_execution) ─────────────────

_REDACT_PATTERNS = [
    ("AWS_KEY",
     r'(?:A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}',
     0),
    ("PRIVATE_KEY",
     r'-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----'
     r'[\s\S]*?-----END (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----', 0),
    ("JWT", r'eyJ[a-zA-Z0-9_-]{5,}\.[a-zA-Z0-9_-]{5,}\.[a-zA-Z0-9_-]+', 0),
    ("BEARER", r'(?i)\bbearer\s+([A-Za-z0-9\-_.=]{20,})', 1),
    ("CRED_PAIR",
     r'(?i)\b((?:password|passwd|pwd|secret|api[_-]?key|token)\s*[=:]\s*'
     r'["\']?)([A-Za-z0-9_\-./+=@!$*]{6,})(["\']?)', 2),
]


def _fingerprint(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8", "ignore")).hexdigest()[:8]


def redact_secrets(text: str) -> str:
    """Redact secret VALUES from persisted audit text, keeping the kind
    and an 8-char sha256 fingerprint so operators can correlate findings
    without the audit log becoming a credential dump. Raw evidence stays
    in the 0600 workspace buffers (ported from 3.7.3 H4)."""
    if not text:
        return text
    for kind, pattern, group in _REDACT_PATTERNS:
        compiled = re.compile(pattern)

        def _repl(m, _kind=kind, _group=group):
            if _group == 0:
                return f"[REDACTED:{_kind}:{_fingerprint(m.group(0))}]"
            whole = m.group(0)
            rel_start = m.start(_group) - m.start(0)
            rel_end = m.end(_group) - m.start(0)
            secret = whole[rel_start:rel_end]
            return (whole[:rel_start]
                    + f"[REDACTED:{_kind}:{_fingerprint(secret)}]"
                    + whole[rel_end:])

        try:
            text = compiled.sub(_repl, text)
        except re.error:
            continue
    return text


# ─── oversized-output management (REFACTOR-05, ported + B2 char caps) ──

_audit_lock = threading.Lock()
AUDIT_LOG_MAX_BYTES = 10 * 1024 * 1024


def _append_audit_log(buffers_dir: str, label: str, output: str) -> None:
    """Rotated (one generation), secret-redacted append-only audit trail
    under {workspace}/buffers/audit.log (ported M7+H4)."""
    path = os.path.join(buffers_dir, "audit.log")
    with _audit_lock:
        try:
            if os.path.exists(path) and \
                    os.path.getsize(path) > AUDIT_LOG_MAX_BYTES:
                os.replace(path, path + ".1")
        except OSError:
            pass
        try:
            with open(path, "a", encoding="utf-8", errors="replace") as f:
                f.write(f"\n[{time.strftime('%Y-%m-%dT%H:%M:%S')}] "
                        f"TOOL: {redact_secrets(label)}\n"
                        f"OUTPUT:\n{redact_secrets(output)}\n"
                        + "=" * 40 + "\n")
        except OSError:
            pass


def render_capped(content: str, *, tool: Tool, label: str,
                  ctx: Optional[ToolContext] = None) -> str:
    """Apply the tool's preview cap. Oversized output is written WHOLE
    to a 0o600 buffer file under {workspace}/buffers/ (manifest'd,
    audit-logged) and the model sees a char-capped head+tail excerpt
    that advertises the pagination path — the B2 fix carried from
    2026-10-06: head <= 60% and tail <= 15% of the cap, regardless of
    line count, so a single-line payload cannot ride through whole."""
    max_chars = tool.max_result_chars()
    if max_chars < 0 or len(content) <= max_chars or not content.strip():
        return content
    if ctx is not None:
        buffers_dir = os.path.join(ctx.workspace, "buffers")
        try:
            os.makedirs(buffers_dir, exist_ok=True)
            os.chmod(buffers_dir, stat.S_IRWXU)
        except OSError:
            pass
        file_id = uuid.uuid4().hex[:8]
        advertised = f"workspace/buffers/agent_buffer_{file_id}.log"
        full_path = os.path.join(buffers_dir, f"agent_buffer_{file_id}.log")
        try:
            with open(full_path, "w", encoding="utf-8",
                      errors="replace") as f:
                f.write(content)
            os.chmod(full_path, stat.S_IRUSR | stat.S_IWUSR)
            _append_audit_log(buffers_dir, label, content)
            manifest_path = os.path.join(buffers_dir, "manifest.json")
            with _audit_lock:
                manifest = []
                if os.path.exists(manifest_path):
                    try:
                        with open(manifest_path, "r",
                                  encoding="utf-8") as f:
                            manifest = json.load(f)
                    except Exception:
                        manifest = []
                manifest.append({
                    "buffer_id": file_id,
                    "tool": tool.name,
                    "label": str(label)[:200],
                    "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S"),
                    "chars": len(content)})
                tmp = manifest_path + ".tmp"
                with open(tmp, "w", encoding="utf-8") as f:
                    json.dump(manifest, f, indent=2)
                os.replace(tmp, manifest_path)
        except OSError:
            advertised = "(buffer write failed)"
    else:
        advertised = "(no workspace attached)"

    head_cap = max(400, int(max_chars * 0.60))
    tail_cap = max(200, int(max_chars * 0.15))
    lines = content.splitlines()
    total_lines = len(lines)
    head = "\n".join(lines[:25])[:head_cap]
    tail = "\n".join(lines[-5:])[-tail_cap:] if total_lines > 30 else ""
    hidden = total_lines - 30 if total_lines > 30 else 0
    hidden_chars = max(0, len(content) - len(head) - len(tail))
    return (
        f"OUTPUT TRUNCATED (context management)\n"
        f"Tool: {tool.name} | Total lines: {total_lines} | "
        f"Total chars: {len(content)} | Buffer: {advertised}\n\n"
        f"--- HEAD (first 25 lines) ---\n{head}\n\n"
        f"... [{hidden} lines hidden, ~{hidden_chars} chars elided — "
        f"use read_file/grep on the buffer path] ...\n"
        f"--- TAIL (last 5 lines) ---\n{tail}\n")


# ─── the dispatcher (Skeleton 9-2) ─────────────────────────────────────

def partition_batches(calls: Sequence[Dict[str, Any]],
                      registry: ToolRegistry
                      ) -> List[Tuple[bool, List[Dict[str, Any]]]]:
    """Runs of consecutive concurrency-safe tools -> parallel batches;
    any unsafe tool serializes its own batch (toolOrchestration.ts)."""
    batches: List[Tuple[bool, List[Dict[str, Any]]]] = []
    for call in calls:
        tool = registry.resolve(str(call.get("name", "")))
        safe = bool(tool and tool.concurrency_safe(call.get("input", {})))
        if safe and batches and batches[-1][0]:
            batches[-1][1].append(call)
        else:
            batches.append((safe, [call]))
    return batches


async def dispatch_tools(tool_uses: Sequence[Dict[str, Any]],
                         ctx: ToolContext) -> List[Dict[str, Any]]:
    """Execute one assistant turn's tool_use blocks through the full
    pipeline; returns tool_result blocks in call order."""
    registry = ctx.registry
    out: List[Dict[str, Any]] = []
    sem = asyncio.Semaphore(_env_int("AEGIS_TOOL_CONCURRENCY",
                                     DEFAULT_CONCURRENCY))
    for parallel, batch in partition_batches(tool_uses, registry):
        if parallel and len(batch) > 1:
            async def _run(c, _sem=sem):
                async with _sem:
                    return await run_one(c, ctx, parallel=True)

            tasks = [asyncio.ensure_future(_run(c)) for c in batch]
            try:
                results = list(await asyncio.gather(*tasks))
            except _SiblingCancelled:
                # a shell-class sibling errored: cancel pending siblings
                # (StreamingToolExecutor.ts:354-363 — commands carry
                # implicit dependency chains), keep completed results
                for t in tasks:
                    if not t.done():
                        t.cancel()
                await asyncio.gather(*tasks, return_exceptions=True)
                results = []
                for c, t in zip(batch, tasks):
                    if t.done() and not t.cancelled():
                        exc = t.exception()
                        if exc is None:
                            results.append(t.result())
                        elif isinstance(exc, _SiblingCancelled):
                            results.append(_cancelled_result(c))
                        else:
                            results.append(_exception_result(c, exc))
                    else:
                        results.append(_cancelled_result(c))
            out.extend(results)
        else:
            for call in batch:
                out.append(await run_one(call, ctx, parallel=False))
    return out


class _SiblingCancelled(Exception):
    """Internal: a shell-class sibling errored; pending tools cancel."""


def _cancelled_result(call: Dict[str, Any]) -> Dict[str, Any]:
    return {"type": "tool_result",
            "tool_use_id": call.get("id", ""),
            "content": "Cancelled: a sibling shell tool failed (implicit "
                       "dependency chain — shell commands are not safe to "
                       "run after an unexplained failure).",
            "is_error": True}


def _exception_result(call: Dict[str, Any], exc: BaseException
                      ) -> Dict[str, Any]:
    return {"type": "tool_result",
            "tool_use_id": call.get("id", ""),
            "content": f"Tool error: {type(exc).__name__}: {exc}",
            "is_error": True}


def _synthetic_error(call: Dict[str, Any], message: str) -> Dict[str, Any]:
    return {"type": "tool_result",
            "tool_use_id": call.get("id", ""),
            "content": str(message),
            "is_error": True}


async def run_one(call: Dict[str, Any], ctx: ToolContext,
                  *, parallel: bool = False) -> Dict[str, Any]:
    """The full pipeline for one tool_use block (Skeleton 9-6 shape,
    EKD post-hook lands in P2): resolve -> abort -> schema -> semantic
    -> permission gate -> bounded execution -> capped render. Raises
    _SiblingCancelled only when executing inside a parallel batch and
    the tool's error demands sibling cancellation."""
    from ..adapters.openai import frozen_json
    name = str(call.get("name", ""))
    args = call.get("input") or {}
    span = uuid.uuid4().hex[:12]

    # 1. name resolution (deprecated aliases included)
    tool = ctx.registry.resolve(name)
    if tool is None:
        return _synthetic_error(call, f"unknown tool {name!r}")

    # 2. abort check
    if ctx.abort.is_set():
        return _synthetic_error(call, "aborted before execution")

    # 3. schema validation
    err = ctx.registry.validate(name, args)
    if err:
        ctx.observer and _obs_tool(ctx, span, tool, call, None)
        return _synthetic_error(call, f"invalid arguments: {err}")

    # 4. semantic validation
    err = tool.validate_input(args)
    if err:
        return _synthetic_error(call, f"invalid input: {err}")

    # 5. permission gate
    if ctx.permissions is not None:
        decision = await ctx.permissions.check_permission(
            tool, args, ctx, turn=ctx.turn)
        if not decision.allowed:
            return _synthetic_error(
                call, f"PERMISSION DENIED [{decision.rule}]: "
                      f"{decision.reason or 'target out of scope'}")

    # 6. bounded execution (principle 9)
    if ctx.observer is not None:
        try:
            ctx.observer.on_tool_start(span, tool=tool.name,
                                       turn=ctx.turn,
                                       args=json.loads(frozen_json(args)))
        except Exception:
            pass
    t0 = time.monotonic()
    try:
        result = await asyncio.wait_for(tool.call(args, ctx),
                                        timeout=tool.timeout_s)
    except asyncio.TimeoutError:
        if ctx.observer is not None:
            try:
                ctx.observer.on_tool_error(
                    span, TimeoutError(
                        f"{tool.name} exceeded {tool.timeout_s:.0f}s"))
            except Exception:
                pass
        if parallel and tool.cancel_siblings_on_error:
            raise _SiblingCancelled()
        return _synthetic_error(
            call, f"tool timeout: {tool.name} exceeded "
                  f"{tool.timeout_s:.0f}s wall-clock bound")
    except _SiblingCancelled:
        raise
    except Exception as exc:
        if ctx.observer is not None:
            try:
                ctx.observer.on_tool_error(span, exc)
            except Exception:
                pass
        if parallel and tool.cancel_siblings_on_error:
            raise _SiblingCancelled()
        return _exception_result(call, exc)

    # 7. result mapping with size caps + disk persistence
    content = str(getattr(result, "content", result))
    is_error = bool(getattr(result, "is_error", False))
    rendered = render_capped(content, tool=tool,
                             label=tool.description(args), ctx=ctx)
    if ctx.observer is not None:
        try:
            ctx.observer.on_tool_end(span, output=rendered)
        except Exception:
            pass
    if ctx.journal is not None:
        try:
            ctx.journal.append("tool_call", {
                "tool": tool.name, "args": frozen_json(args)[:400]},
                actor="dispatcher")
            ctx.journal.append("tool_result", {
                "tool": tool.name, "is_error": is_error,
                "elapsed_ms": round((time.monotonic() - t0) * 1000, 1),
                "content_chars": len(content),
                "rendered_chars": len(rendered)},
                actor="dispatcher")
        except Exception:
            pass
    if parallel and tool.cancel_siblings_on_error and is_error:
        raise _SiblingCancelled()

    # 8. EKD post-hook (P2, PORT-04): Tier-A extraction feeds the graph
    #    after every non-error result — crash-contained by the batch,
    #    duration-bounded by the turn watchdog, never on the hot path
    #    the model waits on beyond this point in the same task.
    if not is_error and (ctx.extra or {}).get("ekd") is not None:
        try:
            from ..memory.extractors import run_post_hook
            call_node_id = run_post_hook(
                ctx, tool.name, args, rendered,
                tool_call_id=str(call.get("id", "")))
            if call_node_id and ctx.extra is not None:
                cmap = ctx.extra.setdefault("ekd_call_ids", {})
                cmap[str(call.get("id", ""))] = call_node_id
        except Exception:
            pass  # extraction NEVER breaks the tool path

    return {"type": "tool_result",
            "tool_use_id": call.get("id", ""),
            "content": rendered,
            "is_error": is_error}


def _obs_tool(ctx, span, tool, call, output):
    try:
        ctx.observer.on_tool_start(span, tool=tool.name, turn=ctx.turn,
                                   args=call.get("input"))
    except Exception:
        pass
