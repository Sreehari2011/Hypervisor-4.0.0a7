"""hypervisor.adapters.openai — the cisai-ultra client (P1).

OpenAI-compatible chat.completions client for the locally hosted model
(vLLM-class endpoint). Rides httpx — which the debug kit's wire tap
already patches, so every call is captured RAW from the adapter's first
day (blueprint 9.10).

Design contracts (blueprint 7.5, 8.3):

  * STREAMING ONLY — the loop consumes an async generator of chunks;
    the wire tap tees streams, and the guard bounds them.
  * Retry ladder: up to 10 attempts, exponential backoff capped at 32s
    with jitter, Retry-After honored verbatim (withRetry.ts:170-517).
    A retry is TRANSPARENT only when the failed attempt yielded no
    deltas yet; a mid-stream failure after visible output escalates
    (the guard owns the logical retry at its level).
  * Model hot-swap: three consecutive 529-class responses switch the
    active model to the configured fallback for the rest of the call.
  * Byte-stable serialization: the request body is serialized once via
    frozen_json (sort_keys, tight separators) — the discipline that
    makes vLLM prefix caching actually hit (blueprint 8.3).
  * Transport timeouts from the guard's line-1 bounds (connect 5s,
    read = max(idle, 30s), write 60s, pool 10s) so a dead peer dies
    even inside an abandoned attempt.

The adapter never touches loop state; it converts internal Message
blocks (CC-shaped: text / tool_use / tool_result) to and from the
OpenAI wire format and yields Chunk events. It does NOT enforce total
duration bounds — that is the guard's caller-side job (PORT-07).
"""
from __future__ import annotations

import asyncio
import json
import os
import random
from dataclasses import dataclass, field
from typing import Any, AsyncIterator, Dict, List, Optional, Sequence

BASE_URL_ENV = "AEGIS_OPENAI_BASE_URL"
API_KEY_ENV = "AEGIS_OPENAI_API_KEY"
MODEL_ENV = "AEGIS_MODEL"
FALLBACK_MODEL_ENV = "AEGIS_MODEL_FALLBACK"

DEFAULT_MODEL = "cisai-ultra"

# Retryable statuses (withRetry.ts semantics): request-timeout, ratelimit,
# gateway/server class, and vLLM's 529 overloaded.
RETRYABLE_STATUSES = frozenset({408, 429, 500, 502, 503, 504, 529})
OVERLOADED_STATUS = 529

DEFAULT_MAX_ATTEMPTS = 10
DEFAULT_BACKOFF_CAP_S = 32.0
DEFAULT_SWAP_AFTER_529 = 3


class OpenAICompatError(RuntimeError):
    """Transport/protocol failure from the OpenAI-compatible endpoint."""

    def __init__(self, message: str, *, status: Optional[int] = None,
                 retryable: bool = False, attempt: int = 0,
                 mid_stream: bool = False):
        self.status = status
        self.retryable = bool(retryable)
        self.attempt = attempt
        self.mid_stream = bool(mid_stream)
        super().__init__(message)


def frozen_json(obj: Any) -> str:
    """THE deterministic JSON serialization (byte-stability rule).
    The request body, tool schemas and tool_call arguments must
    round-trip through exactly this form so identical logical requests
    produce byte-identical prefixes (vLLM prefix-cache discipline)."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False)


# ─── chunk / reply model ──────────────────────────────────────────────

@dataclass
class Chunk:
    """One streaming event from the model.

    kind: "text"      — a content delta (loop re-yields outward)
          "reasoning" — a reasoning-content delta (kept out of content)
          "reply"     — the final assembled ModelReply (always last)
    """
    kind: str
    text: str = ""
    reply: Optional["ModelReply"] = None


@dataclass
class ModelReply:
    """The assembled result of one logical model call."""
    message: Dict[str, Any]                      # internal Message dict
    tool_uses: List[Dict[str, Any]] = field(default_factory=list)
    text: str = ""
    usage: Dict[str, int] = field(default_factory=dict)
    finish_reason: str = ""
    model: str = ""
    attempts: int = 1
    swapped_model: bool = False                  # 529 hot-swap fired


# ─── internal Message blocks -> OpenAI wire format ────────────────────

def _blocks(m: Dict[str, Any]) -> List[Dict[str, Any]]:
    c = m.get("content")
    if isinstance(c, list):
        return c
    if isinstance(c, str) and c:
        return [{"type": "text", "text": c}]
    return []


def to_wire(messages: Sequence[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Deterministic internal -> wire conversion (fixed field order,
    frozen JSON for tool arguments)."""
    out: List[Dict[str, Any]] = []
    for m in messages:
        role = m.get("role", "user")
        blocks = _blocks(m)
        if role == "assistant":
            texts = [b.get("text", "") for b in blocks
                     if b.get("type") == "text"]
            uses = [b for b in blocks if b.get("type") == "tool_use"]
            msg: Dict[str, Any] = {"role": "assistant",
                                   "content": "\n".join(t for t in texts if t)
                                   or None}
            if uses:
                msg["tool_calls"] = [
                    {"id": b.get("id", ""),
                     "type": "function",
                     "function": {"name": b.get("name", ""),
                                  "arguments": frozen_json(
                                      b.get("input", {}))}}
                    for b in uses]
            out.append(msg)
        elif role == "user":
            results = [b for b in blocks if b.get("type") == "tool_result"]
            if results:
                for b in results:
                    out.append({"role": "tool",
                                "tool_call_id": b.get("tool_use_id", ""),
                                "content": _result_text(b)})
                texts = [b.get("text", "") for b in blocks
                         if b.get("type") == "text"]
                if any(texts):
                    out.append({"role": "user",
                                "content": "\n".join(t for t in texts if t)})
            else:
                texts = [b.get("text", "") for b in blocks
                         if b.get("type") == "text"]
                out.append({"role": "user",
                            "content": "\n".join(t for t in texts if t)})
        else:  # system
            texts = [b.get("text", "") for b in blocks
                     if b.get("type") == "text"]
            out.append({"role": role,
                        "content": "\n".join(t for t in texts if t)})
    return out


def _result_text(b: Dict[str, Any]) -> str:
    c = b.get("content", "")
    if isinstance(c, list):
        parts = []
        for x in c:
            if isinstance(x, dict):
                parts.append(str(x.get("text", "")))
            else:
                parts.append(str(x))
        return "\n".join(p for p in parts if p)
    return str(c)


def wire_tools(tools: Sequence[Any]) -> List[Dict[str, Any]]:
    """Registry tool objects -> wire tool array. Serialized through
    frozen_json so the endpoint sees byte-identical tool blocks for
    identical registries (prefix-cache discipline)."""
    out = []
    for t in tools:
        out.append({"type": "function",
                    "function": {"name": t.name,
                                 "description": t.prompt(),
                                 "parameters": json.loads(
                                     frozen_json(t.input_schema))}})
    return out


# ─── the client ───────────────────────────────────────────────────────

class OpenAICompatClient:
    """Streaming chat.completions client for one OpenAI-compatible
    endpoint. Retry and hot-swap live HERE (transport-level); total
    duration bounds live in the guard (caller-side, PORT-07)."""

    def __init__(self, base_url: str, *, api_key: str = "",
                 model: str = DEFAULT_MODEL,
                 fallback_model: str = "",
                 timeout: Any = None,
                 max_attempts: int = DEFAULT_MAX_ATTEMPTS,
                 backoff_cap_s: float = DEFAULT_BACKOFF_CAP_S,
                 swap_after_529: int = DEFAULT_SWAP_AFTER_529,
                 transport: Any = None):
        self.base_url = base_url.rstrip("/")
        self.api_key = api_key or os.environ.get("API_KEY", "") or "sk-local"
        self.fallback_model = fallback_model
        self._active_model = model
        self.max_attempts = max(1, int(max_attempts))
        self.backoff_cap_s = float(backoff_cap_s)
        self.swap_after_529 = max(1, int(swap_after_529))
        self._transport = transport
        self._consecutive_529 = 0
        self._client: Any = None
        self._timeout = timeout
        self._swapped = False

    # ------------------------------------------------------------ factory

    @classmethod
    def from_env(cls, **overrides) -> "OpenAICompatClient":
        kw = dict(
            base_url=os.environ.get(BASE_URL_ENV, "http://127.0.0.1:8000/v1"),
            api_key=os.environ.get(API_KEY_ENV, ""),
            model=os.environ.get(MODEL_ENV, DEFAULT_MODEL),
            fallback_model=os.environ.get(FALLBACK_MODEL_ENV, ""),
        )
        kw.update(overrides)
        return cls(**kw)

    @property
    def model(self) -> str:
        return self._active_model

    def _http(self) -> Any:
        if self._client is None:
            try:
                import httpx  # optional at import time; required at call time
            except ImportError as exc:
                # Refuse honestly (platform discipline): a missing
                # transport is an environment defect, not a model error.
                # Test-4's clean engagement container caught exactly this
                # — the image shipped without the undeclared dependency
                # and the first model call died here.
                raise RuntimeError(
                    "adapter transport missing: httpx is required at "
                    "call time (OpenAICompatClient._http) but not "
                    "installed in this interpreter — every model call "
                    "will fail. Fix: pip install 'httpx>=0.27' on this "
                    "host (or rebuild the engagement image); the doctor "
                    "check 'adapter transport: httpx' reports this") from exc
            timeout = self._timeout
            if timeout is None:
                # Guard line-1 defaults: a dead peer dies at the transport
                # even if the caller-side bound already abandoned the task.
                idle = max(float(os.environ.get(
                    "AEGIS_LLM_IDLE_TIMEOUT_S", "90")), 30.0)
                timeout = httpx.Timeout(connect=5.0, read=idle,
                                        write=60.0, pool=10.0)
            kwargs: Dict[str, Any] = dict(
                base_url=self.base_url, timeout=timeout)
            if self._transport is not None:
                kwargs["transport"] = self._transport
            self._client = httpx.AsyncClient(**kwargs)
        return self._client

    async def aclose(self) -> None:
        if self._client is not None:
            try:
                await self._client.aclose()
            except Exception:
                pass
            self._client = None

    # ------------------------------------------------------ retry ladder

    def _backoff_s(self, attempt: int, retry_after: Optional[float]) -> float:
        if retry_after is not None:
            # honored verbatim, capped at the ladder ceiling (withRetry.ts)
            return min(max(retry_after, 0.0), self.backoff_cap_s)
        base = min(1.0 * (2 ** (attempt - 1)), self.backoff_cap_s)
        return base * random.uniform(0.75, 1.25)

    @staticmethod
    def _parse_retry_after(resp: Any) -> Optional[float]:
        try:
            raw = resp.headers.get("Retry-After")
            if raw is None:
                return None
            return float(raw)
        except Exception:
            return None

    def _maybe_hot_swap(self) -> bool:
        """Three consecutive 529s -> switch to the fallback model for
        the remainder of this call (the CC mid-stream hot-swap analog)."""
        if self._consecutive_529 >= self.swap_after_529 and \
                self.fallback_model and \
                self._active_model != self.fallback_model:
            self._active_model = self.fallback_model
            self._consecutive_529 = 0
            self._swapped = True
            return True
        return False

    # ------------------------------------------------------- the stream

    async def stream_chat(self, *, messages: Sequence[Dict[str, Any]],
                          tools: Optional[Sequence[Any]] = None,
                          max_tokens: Optional[int] = None,
                          temperature: Optional[float] = None,
                          ) -> AsyncIterator[Chunk]:
        """Stream one logical completion. Yields text/reasoning deltas as
        they arrive, then exactly one final Chunk(kind="reply"). Retries
        are transparent only while nothing has been yielded; after the
        first visible delta any failure raises (the guard owns logical
        retries). Raises OpenAICompatError after the final failed
        attempt."""
        attempt = 0
        while True:
            attempt += 1
            body: Dict[str, Any] = {
                "model": self._active_model,
                "messages": to_wire(messages),
                "stream": True,
                "stream_options": {"include_usage": True},
            }
            if tools:
                body["tools"] = wire_tools(tools)
                body["tool_choice"] = "auto"
            if max_tokens is not None:
                body["max_tokens"] = int(max_tokens)
            if temperature is not None:
                body["temperature"] = float(temperature)
            wire_body = frozen_json(body)

            yielded_any = False

            def _mk_error(msg: str, *, status: Optional[int] = None,
                          retryable: bool = False) -> OpenAICompatError:
                return OpenAICompatError(
                    msg, status=status, retryable=retryable,
                    attempt=attempt, mid_stream=yielded_any)

            try:
                reply = None
                async for chunk in self._stream_once(
                        wire_body, messages, attempt, _mk_error):
                    if chunk.kind == "reply":
                        reply = chunk.reply
                    else:
                        yielded_any = True
                        yield chunk
            except OpenAICompatError as exc:
                if exc.status == OVERLOADED_STATUS:
                    self._consecutive_529 += 1
                retryable = exc.retryable and not exc.mid_stream
                if not retryable or attempt >= self.max_attempts:
                    raise
                self._maybe_hot_swap()
                await asyncio.sleep(self._backoff_s(
                    attempt, getattr(exc, "_retry_after", None)))
                continue
            except (asyncio.CancelledError, GeneratorExit):
                raise
            except Exception as exc:  # transport class: connect/read/parse
                if yielded_any or attempt >= self.max_attempts:
                    raise _mk_error(f"{type(exc).__name__}: {exc}")
                await asyncio.sleep(self._backoff_s(attempt, None))
                continue

            if reply is not None:
                reply.attempts = attempt
                reply.swapped_model = self._swapped
                self._consecutive_529 = 0
                yield Chunk(kind="reply", reply=reply)
                return
            raise _mk_error("stream ended without an assembled reply")

    async def _stream_once(self, wire_body: str,
                           messages: Sequence[Dict[str, Any]],
                           attempt: int,
                           mk_error) -> AsyncIterator[Chunk]:
        """One HTTP attempt. Yields deltas; returns the assembled reply
        as a final Chunk(kind='reply'). Raises OpenAICompatError with
        .retryable/.mid_stream decided by the caller-supplied factory
        (which tracks yield state)."""
        http = self._http()
        headers = {"Content-Type": "application/json"}
        if self.api_key:
            headers["Authorization"] = f"Bearer {self.api_key}"

        text_parts: List[str] = []
        reasoning_parts: List[str] = []
        tc: Dict[int, Dict[str, Any]] = {}
        usage: Dict[str, int] = {}
        finish_reason = ""
        saw_done = False

        async with http.stream("POST", "/chat/completions",
                               content=wire_body, headers=headers) as resp:
            if resp.status_code != 200:
                raw = (await resp.aread())[:512]
                exc = mk_error(
                    f"HTTP {resp.status_code} from {self.base_url}: "
                    f"{raw.decode('utf-8', 'replace')!r}",
                    status=resp.status_code,
                    retryable=resp.status_code in RETRYABLE_STATUSES)
                exc._retry_after = self._parse_retry_after(resp)
                raise exc
            async for line in resp.aiter_lines():
                if not line or not line.startswith("data:"):
                    continue
                payload = line[5:].strip()
                if payload == "[DONE]":
                    saw_done = True
                    break
                try:
                    ev = json.loads(payload)
                except json.JSONDecodeError:
                    continue  # keepalive / comment noise
                u = ev.get("usage")
                if isinstance(u, dict):
                    usage = {"prompt_tokens": int(u.get("prompt_tokens", 0)),
                             "completion_tokens": int(
                                 u.get("completion_tokens", 0)),
                             "total_tokens": int(u.get("total_tokens", 0))}
                choices = ev.get("choices") or []
                if not choices:
                    continue
                ch = choices[0]
                if ch.get("finish_reason"):
                    finish_reason = ch["finish_reason"]
                delta = ch.get("delta") or {}
                c = delta.get("content")
                if isinstance(c, str) and c:
                    text_parts.append(c)
                    yield Chunk(kind="text", text=c)
                r = delta.get("reasoning_content") or delta.get("reasoning")
                if isinstance(r, str) and r:
                    reasoning_parts.append(r)
                    yield Chunk(kind="reasoning", text=r)
                for frag in delta.get("tool_calls") or []:
                    idx = int(frag.get("index", 0))
                    slot = tc.setdefault(idx, {
                        "id": "", "name": "", "arguments": ""})
                    if frag.get("id"):
                        slot["id"] = frag["id"]
                    fn = frag.get("function") or {}
                    if fn.get("name"):
                        slot["name"] = fn["name"]
                    if fn.get("arguments"):
                        slot["arguments"] += fn["arguments"]

        if not saw_done:
            # the SSE stream closed without [DONE]: an aborted stream,
            # never a completed reply (the CC aborted_streaming rule)
            raise mk_error(
                "stream closed without [DONE] (aborted stream)",
                retryable=True)

        yield Chunk(kind="reply", reply=self._assemble(
            text_parts, reasoning_parts, tc, usage, finish_reason))

    # ------------------------------------------------------- assembling

    def _assemble(self, text_parts, reasoning_parts, tc, usage,
                  finish_reason) -> ModelReply:
        text = "".join(text_parts)
        tool_uses: List[Dict[str, Any]] = []
        for idx in sorted(tc):
            slot = tc[idx]
            if not slot["name"]:
                continue
            try:
                args = json.loads(slot["arguments"] or "{}")
            except json.JSONDecodeError:
                args = {"_raw_arguments": slot["arguments"]}
            tool_uses.append({"type": "tool_use",
                              "id": slot["id"] or f"call_{idx}",
                              "name": slot["name"], "input": args})
        blocks: List[Dict[str, Any]] = []
        if text:
            blocks.append({"type": "text", "text": text})
        blocks.extend(tool_uses)
        message = {"role": "assistant", "content": blocks}
        if reasoning_parts:
            message["reasoning"] = "".join(reasoning_parts)
        return ModelReply(message=message, tool_uses=tool_uses, text=text,
                          usage=usage, finish_reason=finish_reason,
                          model=self._active_model)
