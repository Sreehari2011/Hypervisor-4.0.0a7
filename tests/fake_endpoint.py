"""Fake OpenAI-compatible SSE endpoint for P1 E2E tests.

Serves POST /chat/completions with scripted streaming replies so the
REAL adapter + guard + loop + dispatcher + tools run end-to-end with
zero external dependencies. Behavior is selected by the objective text
the agent sends (the fake inspects the last user message):

  objective containing "e2e-happy"  -> turn 1: tool_use (in-scope
     run_command), turn 2: final summary
  objective containing "e2e-deny"   -> turn 1: tool_use (out-of-scope
     nmap), turn 2: final summary acknowledging the denial
  objective containing "e2e-multi"  -> three parallel read tools in one
     turn, then final
  otherwise                         -> one final text reply
"""
from __future__ import annotations

import asyncio
import json
import sys


def _sse(chunks):
    out = []
    for payload in chunks:
        out.append(f"data: {json.dumps(payload)}\n\n")
    out.append("data: [DONE]\n\n")
    return "".join(out).encode("utf-8")


def _delta(content=None, tool_calls=None, finish=None):
    d = {}
    if content is not None:
        d["content"] = content
    if tool_calls is not None:
        d["tool_calls"] = tool_calls
    ch = {"index": 0, "delta": d}
    if finish is not None:
        ch["finish_reason"] = finish
    return {"id": "x", "object": "chat.completion.chunk", "choices": [ch]}


def _usage_chunk(pt, ct):
    return {"id": "x", "object": "chat.completion.chunk", "choices": [],
            "usage": {"prompt_tokens": pt, "completion_tokens": ct,
                      "total_tokens": pt + ct}}


def _tc_start(i, name):
    return {"index": i, "id": f"call_{i}", "type": "function",
            "function": {"name": name, "arguments": ""}}


def _tc_args(i, args_json):
    return {"index": i, "function": {"arguments": args_json}}


SCRIPTS = {
    "e2e-happy": [
        ("tool", "run_command",
         {"command": "echo nmap-probe 10.10.0.5"}),
        ("final", "Scan complete: host 10.10.0.5 is up (in scope). "
                  "No findings.", None),
    ],
    "e2e-deny": [
        ("tool", "run_command",
         {"command": "nmap -sV 192.168.77.77"}),
        ("final", "The platform denied the out-of-scope target "
                  "192.168.77.77; engagement stays inside the signed "
                  "scope.", None),
    ],
    "e2e-multi": [
        ("tools3", None, None),
        ("final", "Collected workspace files in parallel.", None),
    ],
}


def _script_key(body):
    try:
        req = json.loads(body)
    except json.JSONDecodeError:
        return None
    last_user = ""
    for m in req.get("messages", []):
        if m.get("role") == "user":
            c = m.get("content")
            last_user = c if isinstance(c, str) else str(c)
    for key in SCRIPTS:
        if key in last_user:
            return key
    return None


def script_for(body):
    try:
        req = json.loads(body)
    except json.JSONDecodeError:
        return None
    last_user = ""
    for m in req.get("messages", []):
        if m.get("role") == "user":
            c = m.get("content")
            last_user = c if isinstance(c, str) else str(c)
    for key, script in SCRIPTS.items():
        if key in last_user:
            return script
    return None


def build_reply(script, n_calls):
    if script is None:
        return _sse([
            _delta(content="No script matched; single final reply.",
                   finish="stop"),
            _usage_chunk(64, 12),
        ])
    if n_calls >= len(script):
        return _sse([_delta(content="(unexpected extra call) done.",
                            finish="stop"), _usage_chunk(64, 8)])
    kind, name, args = script[n_calls]

    if kind == "tool":
        return _sse([
            _delta(content="Working.\n"),
            _delta(tool_calls=[_tc_start(0, name)]),
            _delta(tool_calls=[_tc_args(0, json.dumps(args))],
                   finish="tool_calls"),
            _usage_chunk(120, 24),
        ])
    if kind == "tools3":
        calls = [
            ("write_file", {"path": "e2e/a.txt", "content": "alpha\n"}),
            ("write_file", {"path": "e2e/b.txt", "content": "beta\n"}),
            ("ls", {"path": "e2e"}),
        ]
        chunks = [_delta(content="Three parallel calls.\n")]
        for i, (n, a) in enumerate(calls):
            chunks.append(_delta(tool_calls=[_tc_start(i, n)]))
        for i, (n, a) in enumerate(calls):
            chunks.append(_delta(tool_calls=[_tc_args(i, json.dumps(a))]))
        chunks.append(_delta(finish="tool_calls"))
        chunks.append(_usage_chunk(140, 30))
        return _sse(chunks)
    # final
    return _sse([
        _delta(content=name, finish="stop"),
        _usage_chunk(200, 40),
    ])


class FakeEndpoint:
    def __init__(self):
        self.calls = 0
        self.calls_by_key = {}
        self.bodies = []

    async def handle(self, reader, writer):
        try:
            while True:
                line = await reader.readline()
                if not line:
                    break
                if line.startswith(b"POST "):
                    path = line.split()[1].decode()
                    headers = {}
                    while True:
                        h = await reader.readline()
                        if h in (b"\r\n", b"\n", b""):
                            break
                        k, _, v = h.decode().partition(":")
                        headers[k.strip().lower()] = v.strip()
                    n = int(headers.get("content-length", 0))
                    body = await reader.readexactly(n) if n else b""
                    self.bodies.append(body)
                    if path not in ("/chat/completions",
                                    "/v1/chat/completions"):
                        writer.write(
                            b"HTTP/1.1 404 Not Found\r\n"
                            b"Content-Length: 0\r\n\r\n")
                        await writer.drain()
                        continue
                    self.calls += 1
                    # per-script call index: each objective's script
                    # starts at its own turn 0 regardless of how many
                    # calls other objectives already made on this
                    # server instance
                    key = _script_key(body)
                    n_idx = self.calls_by_key.get(key, 0)
                    self.calls_by_key[key] = n_idx + 1
                    payload = build_reply(script_for(body), n_idx)
                    writer.write(
                        b"HTTP/1.1 200 OK\r\n"
                        b"Content-Type: text/event-stream\r\n"
                        b"Cache-Control: no-cache\r\n"
                        b"Connection: keep-alive\r\n"
                        b"Content-Length: " +
                        str(len(payload)).encode() + b"\r\n\r\n" + payload)
                    await writer.drain()
        except (ConnectionError, asyncio.IncompleteReadError):
            pass
        finally:
            try:
                writer.close()
            except Exception:
                pass


async def serve(port: int):
    ep = FakeEndpoint()
    server = await asyncio.start_server(ep.handle, "127.0.0.1", port)
    print(f"READY {port}", flush=True)
    async with server:
        await server.serve_forever()


if __name__ == "__main__":
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 8901
    try:
        asyncio.run(serve(port))
    except KeyboardInterrupt:
        pass
