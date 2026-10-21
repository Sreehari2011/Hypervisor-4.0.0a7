"""AEGIS Debug Kit — HTTP wire tap.

Ported from 3.7.3, mechanism verbatim (this is the subsystem that made
the 24-minute-hang post-mortem possible — it earns its keep unchanged).
Patches the HTTP client layer so every request the LLM stack makes is
captured RAW (headers redacted, body verbatim), with full timing
decomposition:

  * request written to disk BEFORE the call — a hung request is visible
    as an "open" wire request with no completion event
  * non-streaming: send() duration = full request time (TTFB ≈ total)
  * streaming: send() duration = TTFB, then the response's
    iter_bytes/aiter_bytes are wrapped to tee every chunk — first-chunk
    time, chunk count, bytes, worst inter-chunk gap, SSE data-line
    silence, accumulated body. Mid-stream server stalls show up as
    large inter-chunk gaps.

Transports tapped, whichever are importable:

  * httpx2  — openai SDK >= 3.x ships with the httpx2 fork (3.x-era
              stack; retained for oracle-parity captures)
  * httpx   — everything else, INCLUDING the 4.0 adapters/openai client
              (blueprint 9.10: "the wire tap adds the OpenAI-client path
              it already handles" — the adapter rides httpx)
  * requests— VAPT web tools talking to TARGET systems; a hung tool-side
              HTTP call is a prime inter-tool-gap suspect

Tee guard: httpx(hx2) iter_lines/aiter_lines/read/aread all route
through self.iter_bytes()/aiter_bytes(), so we wrap the *iter_bytes
family with an "active tee" flag — the first consumer path tees, any
nested path passes through silently. Without this, chunks would be
double-counted.

Files per request (under <run>/wire/):
  req_<seq>.json    method, url, redacted headers, body, parsed summary
  resp_<seq>.json   status, headers, body (capped), ttfb_ms, total_ms,
                    chunks, max_gap_ms (streaming)
"""
import json
import threading
import time

from . import config, timeline

try:
    import httpx2 as _httpx2                # openai >= 3.x transport
except Exception:                           # pragma: no cover
    _httpx2 = None
try:
    import httpx as _httpx
except Exception:                           # pragma: no cover
    _httpx = None
try:
    import requests as _requests
except Exception:                           # pragma: no cover
    _requests = None

_open = {}   # seq -> request summary (closed on completion)


def _redact_headers(headers) -> dict:
    out = {}
    try:
        for k, v in headers.items():
            lk = k.lower()
            out[k] = "***REDACTED***" if lk in config.REDACT_HEADERS else v
    except Exception:
        pass
    return out


def _summarize_body(body_bytes) -> dict:
    """Extract the diagnostic essentials from a chat-completions payload."""
    info = {"bytes": len(body_bytes) if body_bytes else 0}
    try:
        payload = json.loads(body_bytes)
        if isinstance(payload, dict):
            msgs = payload.get("messages") or []
            info["model"] = payload.get("model")
            info["stream"] = bool(payload.get("stream"))
            info["n_messages"] = len(msgs)
            info["chars"] = sum(len(str(m.get("content", ""))) for m in msgs
                                if isinstance(m, dict))
            info["tools"] = len(payload.get("tools") or [])
            info["max_tokens"] = payload.get("max_tokens")
    except Exception:
        info["parse"] = "non-json"
    return info


def _write_json(name: str, obj: dict):
    try:
        with open(f"{config.run_dir()}/wire/{name}", "w", encoding="utf-8") as f:
            json.dump(obj, f, ensure_ascii=False, indent=1, default=str)
    except Exception:
        pass


def _begin(body, method, url, headers, is_async: bool, transport: str) -> int:
    seq = timeline.seq_next()
    summary = _summarize_body(body or b"")
    _write_json(f"req_{seq:04d}.json", {
        "seq": seq, "async": is_async, "transport": transport,
        "method": str(method), "url": str(url),
        "headers": _redact_headers(headers or {}),
        "body": config.safe_cap((body or b"").decode("utf-8", "replace")),
        "summary": summary,
    })
    timeline.emit("wire", "request", id=str(seq), transport=transport,
                  url=str(url),
                  model=summary.get("model"),
                  n_messages=summary.get("n_messages"),
                  chars=summary.get("chars"), tools=summary.get("tools"),
                  stream=summary.get("stream"), body_bytes=summary.get("bytes"))
    _open[seq] = {"t0": time.monotonic(), "summary": summary,
                  "url": str(url), "transport": transport}
    return seq


def _fail(seq: int, exc: BaseException):
    ent = _open.pop(seq, None)
    if ent is not None:
        # The tee wrapper (and the reaper) checks this to re-raise the
        # TRUE error instead of re-iterating an already-dead stream.
        ent["failed"] = True
    dur = (time.monotonic() - ent["t0"]) * 1000 if ent else None
    timeline.emit("wire", "request_error", dur_ms=dur, id=str(seq),
                  exc=f"{type(exc).__name__}: {exc}")
    _write_json(f"resp_{seq:04d}.json",
                {"seq": seq, "error": f"{type(exc).__name__}: {exc}",
                 "total_ms": dur,
                 # whether the reaper closed this stream, and the
                 # per-request chunk count at failure (authoritative,
                 # unlike the SDK's cumulative process-wide counter)
                 "reaped": bool(ent.get("reaped")) if ent else None,
                 "chunks": ent.get("chunks") if ent else None})


def _finish_nonstream(seq: int, response):
    ent = _open.pop(seq, None)
    if not ent:
        return
    total_ms = (time.monotonic() - ent["t0"]) * 1000
    body = b""
    try:
        body = response.content or b""
    except Exception:
        pass
    usage = {}
    try:
        j = json.loads(body)
        usage = (j or {}).get("usage", {}) if isinstance(j, dict) else {}
    except Exception:
        pass
    _write_json(f"resp_{seq:04d}.json", {
        "seq": seq, "status": response.status_code,
        "headers": _redact_headers(response.headers),
        "body": config.safe_cap(body.decode("utf-8", "replace")),
        "ttfb_ms": round(total_ms, 1), "total_ms": round(total_ms, 1),
        "usage": usage,
    })
    timeline.emit("wire", "response", dur_ms=round(total_ms, 1), id=str(seq),
                  status=response.status_code, usage=usage or None,
                  model=ent["summary"].get("model"))


def _tee_stream(seq: int, response, is_async: bool):
    """Wrap the response's byte-iterator methods to observe chunks.

    Only iter_bytes/iter_raw (+ async) are wrapped; lines/read route
    through them internally. The active-tee flag guarantees exactly one
    layer counts, whichever entry point the consumer picks.
    """
    ent = _open.setdefault(seq, {})
    ent.setdefault("t0", time.monotonic())
    ent.setdefault("summary", {})
    ent.setdefault("url", "")
    ent.setdefault("first_chunk", None)
    ent.setdefault("last_chunk", None)
    ent.setdefault("chunks", 0)
    ent.setdefault("max_gap_ms", 0.0)
    ent.setdefault("parts", [])
    ent.setdefault("tee_active", False)
    # reaper bookkeeping: what to close, how, and since when.
    ent["response"] = response
    ent["is_async"] = bool(is_async)
    ent.setdefault("tee_t0", time.monotonic())
    ent.setdefault("reaped", False)

    def on_chunk(data):
        now = time.monotonic()
        if ent.get("first_chunk") is None:
            ent["first_chunk"] = now
            timeline.emit("wire", "stream_first_chunk", id=str(seq),
                          ttfb_ms=round((now - ent["t0"]) * 1000, 1))
        gap = 0.0 if ent.get("last_chunk") is None else (now - ent["last_chunk"]) * 1000
        ent["last_chunk"] = now
        ent["chunks"] += 1
        # Track SSE DATA lines separately from raw bytes: gateway
        # keepalive comments (`: ping`) keep resetting byte silence, so
        # `data:` lines are the semantic heartbeat of an SSE chat stream
        # (the blind spot the 2026-10-06 hardening closed).
        try:
            if b"data:" in (data if isinstance(data, (bytes, bytearray))
                            else str(data).encode()):
                ent["last_data"] = now
        except Exception:
            pass
        if gap > ent["max_gap_ms"]:
            ent["max_gap_ms"] = round(gap, 1)
        if config.BODY_CAP_BYTES > 0 and sum(len(p) for p in ent["parts"]) < config.BODY_CAP_BYTES:
            ent["parts"].append(data if isinstance(data, (bytes, bytearray))
                                else str(data).encode())

    def on_done(closed_early=False):
        total_ms = (time.monotonic() - ent["t0"]) * 1000
        body = b"".join(p for p in ent["parts"] if isinstance(p, (bytes, bytearray)))
        usage = {}
        # SSE bodies: scan data: lines for the last usage chunk
        try:
            for line in body.decode("utf-8", "replace").splitlines():
                if line.startswith("data:") and "usage" in line:
                    payload = json.loads(line[5:].strip())
                    u = (payload or {}).get("usage")
                    if u:
                        usage = u
        except Exception:
            pass
        _write_json(f"resp_{seq:04d}.json", {
            "seq": seq, "status": response.status_code, "streamed": True,
            "closed_early": closed_early,
            "ttfb_ms": round((ent["first_chunk"] - ent["t0"]) * 1000, 1)
                       if ent.get("first_chunk") else None,
            "total_ms": round(total_ms, 1), "chunks": ent["chunks"],
            "max_gap_ms": ent["max_gap_ms"], "usage": usage,
            "body": config.safe_cap(body.decode("utf-8", "replace")),
        })
        timeline.emit("wire", "stream_end", dur_ms=round(total_ms, 1),
                      id=str(seq), status=response.status_code,
                      chunks=ent["chunks"], max_gap_ms=ent["max_gap_ms"],
                      closed_early=closed_early or None,
                      usage=usage or None)
        _open.pop(seq, None)

    meths = ("aiter_bytes", "aiter_raw") if is_async else ("iter_bytes", "iter_raw")
    for meth in meths:
        try:
            orig = getattr(response, meth)
        except Exception:
            continue

        if is_async:
            async def wrapper(orig=orig):
                try:
                    if ent.get("tee_active"):
                        async for piece in orig():
                            yield piece
                        return
                    ent["tee_active"] = True
                    try:
                        async for piece in orig():
                            on_chunk(piece)
                            yield piece
                        on_done()
                    except GeneratorExit:
                        # Consumer closed the iterator after seeing SSE
                        # [DONE] (the client decoder does exactly this) —
                        # a NORMAL completion, not a failure.
                        on_done(closed_early=True)
                        raise
                    except BaseException as exc:
                        _fail(seq, exc)
                        raise
                except Exception:
                    if ent.get("failed"):
                        # The underlying stream itself errored (or the
                        # reaper closed it) — propagate the true error
                        # instead of re-iterating a dead stream.
                        raise
                    # Kit telemetry must NEVER break the stream: passthrough.
                    async for piece in orig():
                        yield piece
        else:
            def wrapper(orig=orig):
                try:
                    if ent.get("tee_active"):
                        for piece in orig():
                            yield piece
                        return
                    ent["tee_active"] = True
                    try:
                        for piece in orig():
                            on_chunk(piece)
                            yield piece
                        on_done()
                    except GeneratorExit:
                        on_done(closed_early=True)
                        raise
                    except BaseException as exc:
                        _fail(seq, exc)
                        raise
                except Exception:
                    if ent.get("failed"):
                        # Underlying stream errored / reaper closed it —
                        # propagate the true error, don't re-iterate.
                        raise
                    for piece in orig():
                        yield piece
        try:
            setattr(response, meth, wrapper)
        except Exception:
            pass


def open_requests_snapshot():
    """Currently in-flight (or never-completed) wire requests — the hang
    detector's data source."""
    now = time.monotonic()
    return [{"seq": s, "open_ms": round((now - e["t0"]) * 1000, 1),
             "url": e.get("url", "?"),
             "transport": e.get("transport", "?"),
             "model": e.get("summary", {}).get("model")}
            for s, e in _open.items()]


# ── dead-stream reaper ──────────────────────────────────────────
# Field evidence (3.x VM, 2026-09-29): the gateway backend drops a
# stream ~once per engagement-hour; the connection stays open; the
# client stack's 120s stream watchdog fires on schedule but its
# cancellation CANNOT complete while the peer holds the socket — so the
# error surfaces only when the peer finally closes, 31-62 minutes later.
# The reaper inverts that: if a tapped stream has been silent past
# REAP_SECONDS (default 180s — strictly above the client watchdog, so
# only already-condemned streams are ever touched), close the response
# from here. The blocked read unblocks, the error surfaces within
# seconds, the retry proceeds. Worst case per incident drops from ~an
# hour to ~REAP_SECONDS.

_REAP_THREAD = None


def _close_response(resp, is_async: bool):
    """Best-effort close from the reaper thread. Async responses are
    closed ON their own event loop (run_coroutine_threadsafe via
    loop_monitor); sync responses close directly. Never raises.
    NON-BLOCKING: the close is scheduled; failures surface via a
    done-callback as `reap_failed` events without blocking the next
    scan (the old fut.result(timeout=10) parked the whole reaper thread
    behind one slow aclose — that is why a live run once showed neither
    `reaped` nor `reap_failed`)."""
    if is_async:
        import asyncio
        loop = None
        try:
            from . import loop_monitor
            loop = loop_monitor.running_loop()
        except Exception:
            loop = None
        if loop is not None and not loop.is_closed():
            async def _aclose(r=resp):
                await r.aclose()
            try:
                fut = asyncio.run_coroutine_threadsafe(_aclose(), loop)

                def _report(f, seq_hint=None):
                    try:
                        exc = f.exception()
                    except Exception:
                        exc = None
                    if exc is not None:
                        try:
                            timeline.emit("wire", "reap_failed",
                                          exc=f"{type(exc).__name__}: {exc}")
                        except Exception:
                            pass
                fut.add_done_callback(_report)
                return "aclose_scheduled"
            except Exception as exc:
                timeline.emit("wire", "reap_failed",
                              exc=f"schedule: {type(exc).__name__}: {exc}")
                # fall through to the sync close as a last resort
        else:
            pass  # no loop available — sync close below
    try:
        resp.close()
        return "close"
    except Exception as exc:
        try:
            timeline.emit("wire", "reap_failed",
                          exc=f"sync close: {type(exc).__name__}: {exc}")
        except Exception:
            pass
        return "close_failed"


def _reap_scan():
    now = time.monotonic()
    for seq, ent in list(_open.items()):
        try:
            if ent.get("reaped") or "response" not in ent:
                continue                    # not a teed stream / already handled
            # Reap on SSE DATA-line silence (the semantic stream),
            # falling back to byte silence only when no data line was
            # ever seen. Keepalive comments no longer postpone the reap;
            # a trickling content stream is handled by the app-layer
            # total bound (guard.py, P1) instead.
            last_data = ent.get("last_data")
            last_byte = ent.get("last_chunk") or ent.get("tee_t0")
            if last_data is not None:
                silent = now - last_data
            elif last_byte is not None:
                silent = now - last_byte
            else:
                continue
            if silent < config.REAP_SECONDS:
                continue
            ent["reaped"] = True
            how = _close_response(ent["response"], ent.get("is_async", False))
            timeline.emit("wire", "reaped", id=str(seq),
                          silent_s=round(silent, 1),
                          chunks=ent.get("chunks", 0), method=how,
                          url=ent.get("url", "?"),
                          model=ent.get("summary", {}).get("model"))
        except Exception as exc:
            try:
                timeline.emit("wire", "reap_failed", id=str(seq),
                              exc=f"{type(exc).__name__}: {exc}")
            except Exception:
                pass


def _reap_loop():
    while True:
        try:
            if config.REAP_SECONDS > 0:
                _reap_scan()
        except Exception:
            pass
        time.sleep(1.0)


def _start_reaper():
    global _REAP_THREAD
    if config.REAP_SECONDS <= 0:
        timeline.emit("meta", "reaper_disabled", reap_seconds=0)
        return
    if _REAP_THREAD is not None and _REAP_THREAD.is_alive():
        return
    _REAP_THREAD = threading.Thread(target=_reap_loop,
                                    name="aegis-debug-reaper", daemon=True)
    _REAP_THREAD.start()
    timeline.emit("meta", "reaper_started",
                  reap_seconds=config.REAP_SECONDS,
                  note="force-closes streams silent past the client watchdog")


def _install_httpx_module(mod, label):
    """Patch Client.send / AsyncClient.send on one httpx-flavored module."""
    if mod is None:
        return False
    orig_async = mod.AsyncClient.send
    orig_sync = mod.Client.send

    async def tapped_async_send(self, request, *args, stream=False, **kwargs):
        url = str(getattr(request, "url", ""))
        if url.startswith("http"):
            try:
                from .loop_monitor import ensure_started
                ensure_started()
            except Exception:
                pass
            seq = _begin(request.content, request.method, url, request.headers,
                         is_async=True, transport=label)
            try:
                resp = await orig_async(self, request, *args, stream=stream, **kwargs)
            except BaseException as exc:
                _fail(seq, exc)
                raise
            ent = _open.get(seq)
            if ent is not None:
                timeline.emit("wire", "response_headers",
                              dur_ms=round((time.monotonic() - ent["t0"]) * 1000, 1),
                              id=str(seq), status=resp.status_code)
            if stream:
                _tee_stream(seq, resp, is_async=True)
            else:
                _finish_nonstream(seq, resp)
            return resp
        return await orig_async(self, request, *args, stream=stream, **kwargs)

    def tapped_sync_send(self, request, *args, stream=False, **kwargs):
        url = str(getattr(request, "url", ""))
        if url.startswith("http"):
            seq = _begin(request.content, request.method, url, request.headers,
                         is_async=False, transport=label)
            try:
                resp = orig_sync(self, request, *args, stream=stream, **kwargs)
            except BaseException as exc:
                _fail(seq, exc)
                raise
            if stream:
                _tee_stream(seq, resp, is_async=False)
            else:
                _finish_nonstream(seq, resp)
            return resp
        return orig_sync(self, request, *args, stream=stream, **kwargs)

    mod.AsyncClient.send = tapped_async_send
    mod.Client.send = tapped_sync_send
    timeline.emit("meta", "wire_tap_installed",
                  transport=label, note="Client/AsyncClient.send patched")
    return True


def _install_requests():
    """VAPT web tools talk to TARGET systems via requests — a hung
    request there is a tool-gap suspect, so capture it too (lighter: no
    SSE tee)."""
    if _requests is None:
        return
    orig = _requests.Session.request

    def tapped(self, method, url, *a, **kw):
        seq = timeline.seq_next()
        stream = bool(kw.get("stream"))
        t0 = time.monotonic()
        _write_json(f"req_{seq:04d}.json", {
            "seq": seq, "async": False, "transport": "requests",
            "method": str(method), "url": str(url),
            "headers": _redact_headers(kw.get("headers") or {}),
            "body": config.safe_cap(str(kw.get("data") or kw.get("json") or "")),
            "summary": {"bytes": len(str(kw.get("data") or ""))},
        })
        timeline.emit("wire", "request", id=str(seq), transport="requests",
                      url=str(url), stream=stream)
        _open[seq] = {"t0": t0, "summary": {}, "url": str(url),
                      "transport": "requests"}
        try:
            resp = orig(self, method, url, *a, **kw)
        except BaseException as exc:
            _fail(seq, exc)
            raise
        ent = _open.pop(seq, None)
        dur = round((time.monotonic() - t0) * 1000, 1)
        body = b""
        if not stream:
            try:
                body = resp.content or b""
            except Exception:
                pass
        _write_json(f"resp_{seq:04d}.json", {
            "seq": seq, "status": resp.status_code, "transport": "requests",
            "total_ms": dur,
            "body": config.safe_cap(body.decode("utf-8", "replace")) if body else "",
        })
        timeline.emit("wire", "response", dur_ms=dur, id=str(seq),
                      transport="requests", status=resp.status_code,
                      body_bytes=len(body) if body else None)
        return resp

    _requests.Session.request = tapped
    timeline.emit("meta", "requests_tap_installed")


def install():
    # openai >= 3.x rides on httpx2; classic httpx covers everything else
    # (including the 4.0 adapter, once it lands in P1).
    _install_httpx_module(_httpx2, "httpx2")
    _install_httpx_module(_httpx, "httpx")
    if _httpx2 is None and _httpx is None:
        timeline.emit("meta", "wire_tap_unavailable", reason="no httpx flavor")
    _install_requests()
    _start_reaper()      # dead-stream reaper (no-op if REAP=0)
