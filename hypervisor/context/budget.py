"""hypervisor.context.budget — token budget manager (P2).

REFACTOR-01's budget-trigger half: the 3.7.3 model-window registry +
memory budget (src/core/model_windows.py + src/core/memory_budget.py)
dissolved into the loop's pre-flight pipeline as the window authority.
Nothing else in the system guesses the context window.

Resolution order (carried):
  1. AEGIS_CONTEXT_WINDOW_TOKENS env override ("26624", "26k", "1m")
  2. Longest substring match of the model name in the registry
  3. Conservative 32k default for unknown models — with a LOUD warning
     naming the override (the B3 fix: a gateway alias silently resolved
     to 32k and the engagement compressed at ~18k against a real ~141k
     window — the P9 storm root cause; being wrong conservatively only
     costs extra cheap compressions, never API failures)

BudgetManager derives everything from the resolved window (carried
semantics): reserve (headroom for the system prompt, the next reply and
in-flight tool growth) = max(8000, 25%); trigger (fold fires when
estimated tokens exceed this) = window - reserve; target (post-fold
state) = 35%; chunk_budget (per summarizer call so the FOLD ITSELF
fits the window) = max(500, (window-4000)/2); per-message cap for kept
tool results = window/16.

The CC cascade ordering wraps the oracle's MemoryBudget: the
microcompact threshold fires BELOW the fold trigger (cheap in-place
stubs first), the blocking threshold (window * 0.985) is the hard stop
the loop checks last. Message shaping helpers (chunking, history
formatting, head+tail truncation) are carried from memory_budget.py
adapted to 4.0's dict messages.
"""
from __future__ import annotations

import json
import logging
import os
from typing import Any, Callable, Dict, List, Optional, Sequence

logger = logging.getLogger("AEGIS")

# ─── model context-window registry (model_windows.py carried) ────────

MODEL_CONTEXT_WINDOWS = {
    # OpenAI
    "gpt-4.1": 1_048_576,
    "gpt-4o": 128_000,
    "gpt-4-turbo": 128_000,
    "gpt-3.5-turbo": 16_385,
    "o1": 200_000,
    "o3": 200_000,
    "o4": 200_000,
    # Anthropic (longest keys first matters: claude-2 before claude)
    "claude-opus-4": 200_000,
    "claude-sonnet-4": 200_000,
    "claude-3-7": 200_000,
    "claude-3-5": 200_000,
    "claude-3": 200_000,
    "claude-2": 100_000,
    # Google
    "gemini-1.5-pro": 2_097_152,
    "gemini-1.5-flash": 1_048_576,
    "gemini-2.5-pro": 2_097_152,
    "gemini-2.0": 2_097_152,
    "gemini": 1_048_576,
    # DeepSeek
    "deepseek-reasoner": 64_000,
    "deepseek-chat": 64_000,
    "deepseek": 64_000,
    # Alibaba / Qwen
    "qwen-max": 32_768,
    "qwen": 131_072,
    "qwq": 131_072,
    # Meta
    "llama-3.1": 128_000,
    "llama-3.2": 128_000,
    "llama-3.3": 128_000,
    "codellama": 16_384,
    "llama-3": 8_192,
    "llama-2": 4_096,
    # Mistral
    "mistral-large": 128_000,
    "mixtral": 32_768,
    "mistral": 32_768,
    # Others
    "glm-4": 128_000,
    "glm": 128_000,
    "kimi": 128_000,
    "kemi": 128_000,
    "moonshot": 128_000,
    "gemma": 8_192,
    "command-r": 128_000,
}

# Unknown models: assume a conservative window rather than a permissive
# one (B3 carried). cisai-ultra / Kemi K2.7 is a gateway alias — pin it
# explicitly at deployment via AEGIS_CONTEXT_WINDOW_TOKENS.
DEFAULT_CONTEXT_WINDOW = 32_768

ENV_OVERRIDE = "AEGIS_CONTEXT_WINDOW_TOKENS"
MIN_SUPPORTED_WINDOW = 2_048  # below this the loop cannot function

MIN_WINDOW_WARNING = 8_192  # below this the engagement is impaired


def _parse_window_spec(spec: str):
    """Parse '26624', '26k', '1m', '128K' -> token count (or None)."""
    s = spec.strip().lower()
    if not s:
        return None
    multiplier = 1
    if s.endswith("k"):
        multiplier, s = 1_000, s[:-1]
    elif s.endswith("m"):
        multiplier, s = 1_000_000, s[:-1]
    try:
        return int(float(s) * multiplier)
    except ValueError:
        return None


def resolve_context_window(model_name: str) -> int:
    """Resolve the context window (tokens) for a model name.

    Env override AEGIS_CONTEXT_WINDOW_TOKENS always wins, so an unusual
    or proxied model (e.g. 'cisai-ultra') can be pinned explicitly
    ('200000' or '200k').
    """
    raw = os.environ.get(ENV_OVERRIDE, "")
    if raw:
        value = _parse_window_spec(raw)
        if value is None:
            logger.warning("[MEMORY] Ignoring unparseable %s=%r",
                           ENV_OVERRIDE, raw)
        elif value < MIN_SUPPORTED_WINDOW:
            logger.warning("[MEMORY] Ignoring %s=%r below minimum %d "
                           "tokens", ENV_OVERRIDE, raw,
                           MIN_SUPPORTED_WINDOW)
        else:
            return value

    name = (model_name or "").lower()
    if name:
        # Longest keys first so "llama-3.1-70b" matches "llama-3.1"
        # (128k) instead of the shorter "llama-3" (8k).
        for key in sorted(MODEL_CONTEXT_WINDOWS, key=len, reverse=True):
            if key in name:
                return MODEL_CONTEXT_WINDOWS[key]

    # B3 fix (2026-10-06) carried: the silent conservative fallback was
    # the P9 storm root cause — an unknown model name resolved to 32k
    # with NO signal. Warn loudly and name the override.
    logger.warning(
        "[MEMORY] model %r not in the context-window registry — using "
        "the conservative default %d tokens. If the real window is "
        "larger, set %s (e.g. '200000' or '200k') to pin it.",
        model_name, DEFAULT_CONTEXT_WINDOW, ENV_OVERRIDE)
    return DEFAULT_CONTEXT_WINDOW


# ─── 4.0 message helpers (dict-shaped; the 3.x duck-typed .content/
# .type helpers adapt to the loop's message dicts) ────────────────────


def blocks_of(m: Dict[str, Any]) -> List[Dict[str, Any]]:
    c = m.get("content")
    if isinstance(c, list):
        return c
    if isinstance(c, str) and c:
        return [{"type": "text", "text": c}]
    return []


def is_tool_result_msg(m: Dict[str, Any]) -> bool:
    """A user message whose content carries tool_result blocks (the
    4.0 tool-result carrier — the ToolMessage analog)."""
    if not isinstance(m, dict) or m.get("role") != "user":
        return False
    return any(b.get("type") == "tool_result" for b in blocks_of(m)
               if isinstance(b, dict))


def tool_result_ids(m: Dict[str, Any]) -> List[str]:
    out = []
    for b in blocks_of(m):
        if isinstance(b, dict) and b.get("type") == "tool_result":
            tid = b.get("tool_use_id")
            if tid:
                out.append(str(tid))
    return out


def tool_call_ids(m: Dict[str, Any]) -> List[str]:
    out = []
    for tc in (m.get("tool_calls") or []):
        if isinstance(tc, dict) and tc.get("id"):
            out.append(str(tc["id"]))
    # assistant content may carry tool_use blocks (internal format)
    for b in blocks_of(m):
        if isinstance(b, dict) and b.get("type") == "tool_use" and b.get("id"):
            out.append(str(b["id"]))
    return out


def text_of(m: Dict[str, Any]) -> str:
    """Flatten a message's human-readable text (blocks joined, tool
    results included — the fold summarizes tool evidence too)."""
    c = m.get("content")
    if isinstance(c, str):
        return c
    parts: List[str] = []
    for b in (c or []):
        if not isinstance(b, dict):
            continue
        if b.get("type") in ("text", "tool_result"):
            t = b.get("text") if b.get("type") == "text" else b.get("content")
            if isinstance(t, str) and t:
                parts.append(t)
    return "\n".join(parts)


def role_of(m: Dict[str, Any]) -> str:
    return str(m.get("role", "?"))


# ─── the budget manager ──────────────────────────────────────────────


def estimate_tokens(messages: Sequence[Dict[str, Any]]) -> int:
    """~4 chars/token + per-message overhead (the loop's P1 heuristic,
    hoisted here as the single estimate). Coarser than a real encoder
    but directionally safe — it over-estimates short messages, which
    only makes compression fire slightly earlier."""
    total = 0
    for m in messages:
        total += len(text_of(m)) // 4 + 8
        # tool_use blocks carry arguments the text flatten misses
        for b in blocks_of(m):
            if isinstance(b, dict) and b.get("type") == "tool_use":
                try:
                    total += len(json.dumps(b.get("input", {}),
                                            default=str)) // 4
                except Exception:
                    pass
    return total


def counter_of(budget: "BudgetManager") -> Callable[[Sequence], int]:
    """The budget's token counter as a bare callable (the shaping
    helpers take counters; this binds the manager's)."""
    return budget.counter


class BudgetManager:
    """All context-engine thresholds for one engagement, derived from
    the model's resolved window (REFACTOR-01: the Memory_Manager's
    budget half; the ladder half lives in context/compact.py)."""

    def __init__(self, window_tokens: int,
                 counter: Optional[Callable[[Sequence], int]] = None):
        w = int(window_tokens)
        if w < MIN_WINDOW_WARNING:
            logger.warning(
                "[MEMORY] Context window of %d tokens is very small — "
                "expect frequent compression and possible truncation. "
                "A >= 32k window is recommended.", w)
        self.window = w
        self.reserve = max(8_000, int(w * 0.25))
        self.trigger = max(2_000, w - self.reserve)          # fold fires
        self.target = max(2_000, int(w * 0.35))              # post-fold
        self.chunk_budget = max(500, int((w - 4_000) * 0.5))  # fold input
        self.per_message_cap = max(300, w // 16)   # tokens per kept msg
        self.counter = counter or estimate_tokens
        # CC cascade ordering around the oracle trigger: cheap in-place
        # stubs fire BELOW the fold threshold (microcompact first),
        # the blocking limit is the hard stop the loop checks last.
        self.microcompact_at = max(
            2_000, int(self.trigger * 0.92))
        self.blocking_at = max(self.trigger + 1, int(w * 0.985))

    # ---------------------------------------------------------------- api
    def should_microcompact(self, messages: Sequence[Dict[str, Any]]) -> bool:
        return self.counter(messages) > self.microcompact_at

    def should_compress(self, messages: Sequence[Dict[str, Any]]) -> bool:
        """True when the channel has crossed the fold trigger."""
        return self.counter(messages) > self.trigger

    def should_block(self, messages: Sequence[Dict[str, Any]]) -> bool:
        return self.counter(messages) >= self.blocking_at

    def per_message_char_cap(self) -> int:
        """Character cap for truncating a single kept message (~4
        chars/token)."""
        return max(1_200, self.per_message_cap * 4)

    def describe(self) -> str:
        return (f"window={self.window:,} trigger={self.trigger:,} "
                f"target={self.target:,} chunk={self.chunk_budget:,} "
                f"per_msg_cap={self.per_message_cap:,} "
                f"micro={self.microcompact_at:,} "
                f"blocking={self.blocking_at:,}")

    def __repr__(self) -> str:  # pragma: no cover
        return f"BudgetManager({self.describe()})"


# ─── Pure slicing / formatting helpers (memory_budget.py carried,
#     dict-message shaped) ────────────────────────────────────────────


def chunk_messages(messages: Sequence[Dict[str, Any]],
                   chunk_token_budget: int,
                   counter: Callable[[Sequence], int]
                   ) -> List[List[Dict[str, Any]]]:
    """Split messages into token-bounded chunks for sequential
    summarization. Each chunk's estimated cost stays under
    chunk_token_budget so a single summarizer call (chunk text +
    previous summary + prompt) fits a small window. An oversized single
    message becomes its own chunk (its content is truncated later by
    format_history_text)."""
    if chunk_token_budget <= 0:
        return [list(messages)] if messages else []
    chunks: List[List[Dict[str, Any]]] = []
    current: List[Dict[str, Any]] = []
    current_tokens = 0
    for m in messages:
        cost = counter([m])
        if current and current_tokens + cost > chunk_token_budget:
            chunks.append(current)
            current, current_tokens = [], 0
        current.append(m)
        current_tokens += cost
    if current:
        chunks.append(current)
    return chunks


def head_tail_truncate(content: str, char_cap: int) -> str:
    """Keep head (~65%) + tail (~25%) of content within char_cap (the
    tail is where tool evidence, hashes and session tokens usually
    live)."""
    if len(content) <= char_cap:
        return content
    head = int(char_cap * 0.65)
    tail = int(char_cap * 0.25)
    marker = (f"\n[...aegis truncated: original {len(content)} chars — "
              f"full text preserved in workspace buffers and the "
              f"engagement knowledge graph...]\n")
    return content[:head] + marker + content[-tail:]


def format_history_text(messages: Sequence[Dict[str, Any]],
                        per_message_char_limit: int = 2000) -> str:
    """Render messages as 'ROLE: content' lines for the summarizer
    prompt. Per-message truncation keeps head+tail (the 2000-char
    behavior preserved from the oracle, tail kept verbatim)."""
    lines = []
    for m in messages:
        role = role_of(m).upper()
        content = text_of(m)
        if len(content) > per_message_char_limit:
            head = int(per_message_char_limit * 0.75)
            tail = per_message_char_limit - head
            content = (content[:head]
                       + "\n...[TRUNCATED]...\n"
                       + content[-tail:])
        lines.append(f"{role}: {content}")
    return "\n".join(lines)
