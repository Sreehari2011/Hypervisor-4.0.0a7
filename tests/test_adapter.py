"""P1 acceptance tests — adapters/openai.py (Skeleton 9-1's model plane).

Covers: wire conversion, frozen serialization (byte-stability), SSE
streaming + tool_call fragment assembly, the retry ladder (Retry-After,
backoff cap, no-retry on 4xx, mid-stream escalation) and the 529
model hot-swap. Uses httpx.MockTransport so the REAL adapter code path
runs with zero network."""
import asyncio
import json

import httpx
import pytest

from hypervisor.adapters.openai import (Chunk, ModelReply, OpenAICompatClient,
                                        OpenAICompatError, frozen_json,
                                        to_wire, wire_tools)

# ─── helpers ───────────────────────────────────────────────────────────


def sse(events):
    out = []
    for ev in events:
        out.append(f"data: {json.dumps(ev)}\n\n")
    out.append("data: [DONE]\n\n")
    return "".join(out).encode()


def delta(content=None, tool_calls=None, finish=None):
    d = {}
    if content is not None:
        d["content"] = content
    if tool_calls is not None:
        d["tool_calls"] = tool_calls
    ch = {"index": 0, "delta": d}
    if finish is not None:
        ch["finish_reason"] = finish
    return {"id": "x", "object": "chat.completion.chunk",
            "choices": [ch]}


def usage_chunk(pt, ct):
    return {"id": "x", "object": "chat.completion.chunk", "choices": [],
            "usage": {"prompt_tokens": pt, "completion_tokens": ct,
                      "total_tokens": pt + ct}}


class ToolStub:
    def __init__(self, name, schema=None, prompt="p"):
        self.name = name
        self.input_schema = schema or {"type": "object",
                                       "properties": {}}
        self._prompt = prompt

    def prompt(self):
        return self._prompt


def client_with(handler, **kw):
    transport = httpx.MockTransport(handler)
    return OpenAICompatClient("http://fake/v1", transport=transport, **kw)


# ─── wire conversion ───────────────────────────────────────────────────


def test_to_wire_tool_round_trip():
    msgs = [
        {"role": "system", "content": "sys"},
        {"role": "user", "content": "scan 10.0.0.5"},
        {"role": "assistant", "content": [
            {"type": "text", "text": "Running."},
            {"type": "tool_use", "id": "call_1", "name": "run_command",
             "input": {"command": "nmap -sV 10.0.0.5"}}]},
        {"role": "user", "content": [
            {"type": "tool_result", "tool_use_id": "call_1",
             "content": "22/tcp open ssh"},
            {"type": "text", "text": "continue"}]},
    ]
    w = to_wire(msgs)
    assert w[0] == {"role": "system", "content": "sys"}
    assert w[2]["tool_calls"][0]["function"]["name"] == "run_command"
    assert w[2]["tool_calls"][0]["function"]["arguments"] == \
        '{"command":"nmap -sV 10.0.0.5"}'
    assert w[3] == {"role": "tool", "tool_call_id": "call_1",
                    "content": "22/tcp open ssh"}
    assert w[4] == {"role": "user", "content": "continue"}


def test_frozen_json_byte_stability():
    a = {"z": 1, "a": {"b": [2, 3], "c": "x"}}
    assert frozen_json(a) == frozen_json(json.loads(frozen_json(a)))
    assert frozen_json(a) == '{"a":{"b":[2,3],"c":"x"},"z":1}'


def test_wire_tools_frozen_serialization():
    t1, t2 = ToolStub("b_tool"), ToolStub("a_tool")
    w = wire_tools([t1, t2])
    assert [t["function"]["name"] for t in w] == ["b_tool", "a_tool"]
    assert json.dumps(w) == json.dumps(wire_tools([t1, t2]))


# ─── streaming + assembly ──────────────────────────────────────────────


def test_stream_assembles_text_tools_usage():
    body = sse([
        delta(content="Hel"),
        delta(content="lo "),
        delta(tool_calls=[{"index": 0, "id": "call_9",
                           "type": "function",
                           "function": {"name": "run_command",
                                        "arguments": ""}}]),
        delta(tool_calls=[{"index": 0,
                           "function": {"arguments": '{"comm'}}]),
        delta(tool_calls=[{"index": 0,
                           "function": {"arguments": 'and":"ls"}'}}]),
        delta(finish="tool_calls"),
        usage_chunk(101, 7),
    ])

    def handler(request):
        return httpx.Response(200, headers={
            "Content-Type": "text/event-stream"}, content=body)

    async def run():
        c = client_with(handler)
        try:
            texts, reply = [], None
            async for ch in c.stream_chat(
                    messages=[{"role": "user", "content": "x"}],
                    max_tokens=99):
                if ch.kind == "text":
                    texts.append(ch.text)
                elif ch.kind == "reply":
                    reply = ch.reply
            assert "".join(texts) == "Hello "
            assert reply.finish_reason == "tool_calls"
            assert reply.usage == {"prompt_tokens": 101,
                                   "completion_tokens": 7,
                                   "total_tokens": 108}
            assert len(reply.tool_uses) == 1
            tu = reply.tool_uses[0]
            assert tu["id"] == "call_9" and tu["name"] == "run_command"
            assert tu["input"] == {"command": "ls"}
            assert reply.message["role"] == "assistant"
            assert reply.message["content"][0]["text"] == "Hello "
        finally:
            await c.aclose()
    asyncio.run(run())


def test_stream_reasoning_kept_out_of_content():
    body = sse([
        delta(content=None),  # role-only
        {"id": "x", "object": "chat.completion.chunk", "choices": [
            {"index": 0, "delta": {"reasoning_content": "thinking..."}}]},
        delta(content="answer", finish="stop"),
        usage_chunk(10, 4),
    ])

    def handler(request):
        return httpx.Response(200, content=body)

    async def run():
        c = client_with(handler)
        try:
            reply = None
            async for ch in c.stream_chat(
                    messages=[{"role": "user", "content": "x"}]):
                if ch.kind == "reply":
                    reply = ch.reply
            assert reply.text == "answer"
            assert reply.message.get("reasoning") == "thinking..."
            assert reply.message["content"] == [
                {"type": "text", "text": "answer"}]
        finally:
            await c.aclose()
    asyncio.run(run())


# ─── retry ladder ──────────────────────────────────────────────────────


def test_retry_429_honors_retry_after_then_succeeds():
    calls = {"n": 0}

    def handler(request):
        calls["n"] += 1
        if calls["n"] == 1:
            return httpx.Response(429, headers={"Retry-After": "0.05"})
        return httpx.Response(200, content=sse(
            [delta(content="ok", finish="stop"), usage_chunk(1, 1)]))

    async def run():
        c = client_with(handler)
        try:
            reply = None
            async for ch in c.stream_chat(
                    messages=[{"role": "user", "content": "x"}]):
                if ch.kind == "reply":
                    reply = ch.reply
            assert calls["n"] == 2 and reply.text == "ok"
        finally:
            await c.aclose()
    asyncio.run(run())


def test_no_retry_on_client_error():
    calls = {"n": 0}

    def handler(request):
        calls["n"] += 1
        return httpx.Response(400, json={"error": "bad request"})

    async def run():
        c = client_with(handler)
        try:
            with pytest.raises(OpenAICompatError) as ei:
                async for _ in c.stream_chat(
                        messages=[{"role": "user", "content": "x"}]):
                    pass
            assert ei.value.status == 400 and not ei.value.retryable
            assert calls["n"] == 1
        finally:
            await c.aclose()
    asyncio.run(run())


def test_529_hot_swap_after_three():
    calls = {"n": 0}

    def handler(request):
        calls["n"] += 1
        body = json.loads(request.content)
        if calls["n"] <= 3:
            return httpx.Response(529, json={"error": "overloaded"})
        # the swapped model must be the fallback
        assert body["model"] == "fallback-model", body["model"]
        return httpx.Response(200, content=sse(
            [delta(content="recovered", finish="stop"),
             usage_chunk(1, 1)]))

    async def run():
        c = client_with(handler, fallback_model="fallback-model",
                        backoff_cap_s=0.05)
        try:
            reply = None
            async for ch in c.stream_chat(
                    messages=[{"role": "user", "content": "x"}]):
                if ch.kind == "reply":
                    reply = ch.reply
            assert calls["n"] == 4
            assert reply.model == "fallback-model"
            assert reply.swapped_model is True
        finally:
            await c.aclose()
    asyncio.run(run())


def test_midstream_failure_after_deltas_is_not_transparently_retried():
    """A failure after visible output escalates to the guard rather than
    restarting the stream (the consumer already saw bytes). Simulated
    as an SSE body that ends WITHOUT [DONE] after a real delta."""
    calls = {"n": 0}

    def handler(request):
        calls["n"] += 1
        if calls["n"] == 1:
            body = (f"data: {json.dumps(delta(content='partial'))}\n\n"
                    ).encode() + b""   # stream just closes — no [DONE]
            return httpx.Response(200, headers={
                "Content-Type": "text/event-stream"}, content=body)
        return httpx.Response(200, content=sse(
            [delta(content="second", finish="stop")]))

    async def run():
        c = client_with(handler)
        try:
            with pytest.raises(OpenAICompatError) as ei:
                async for _ in c.stream_chat(
                        messages=[{"role": "user", "content": "x"}]):
                    pass
            assert ei.value.mid_stream is True
            assert calls["n"] == 1
        finally:
            await c.aclose()
    asyncio.run(run())


def test_request_body_is_frozen_json():
    seen = {}

    def handler(request):
        seen["raw"] = request.content
        seen["parsed"] = json.loads(request.content)
        return httpx.Response(200, content=sse(
            [delta(content="ok", finish="stop")]))

    async def run():
        c = client_with(handler)
        try:
            async for _ in c.stream_chat(
                    messages=[{"role": "user", "content": "x"}],
                    tools=[ToolStub("t")], max_tokens=123):
                pass
        finally:
            await c.aclose()
    asyncio.run(run())
    body = seen["parsed"]
    assert body["stream"] is True and body["model"]
    assert body["tools"][0]["function"]["name"] == "t"
    assert body["max_tokens"] == 123
    # byte-stable: re-serializing the parsed body reproduces the wire
    assert seen["raw"].decode() == frozen_json(body)
