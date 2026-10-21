"""hypervisor.tools.core — the CC-parity core tool set (P1).

Disposition family REFACTOR-05 (3.7.3 tools/safe_execution.py): command
sanitization, path security, output management and the shell surface
port into the 4.0 Tool protocol. The VAPT-specific registry (recon /
exploit / fs / shell / report under tools/vapt/) lands in P3; these are
the platform tools every engagement and every subagent shares.

Safety model per tool (gate composes with the scope engine):

  run_command   EXPLOIT-class when it touches the network (targets
                extracted, scope-checked), READ-class when purely local,
                DESTRUCTIVE-class on dangerous patterns (also blocked
                outright in validation, oracle parity); shell tools
                serialize their batch and cancel siblings on error.
  read/ls/glob/grep   READ, concurrency-safe.
  write/edit/todo     WRITE (context-modifying), serial lane.

All path arguments are declared via `path_args` so the permission gate
enforces the workspace-bound resolver for every WRITE-class call.
"""
from __future__ import annotations

import asyncio
import json
import os
import re
import stat
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from ..permissions import (SafetyClass, extract_targets_from_command,
                           resolve_safe_path)
from .base import Tool, ToolContext, ToolResult

# ─── command sanitization (ported from 3.7.3 safe_execution) ───────────

DANGEROUS_PATTERNS = [
    # Destructive
    (r"rm\s+-rf\s+/(?!\w)", "Recursive delete of root filesystem"),
    (r"rm\s+-rf\s+/\*", "Recursive delete of root with wildcard"),
    (r"rm\s+-rf\s+~", "Recursive delete of home directory"),
    (r"mkfs", "Filesystem format"),
    (r"dd\s+if=.*of=/dev/(sd|nvme|hd)", "Direct disk write"),
    (r">\s*/dev/sd", "Write to raw disk"),
    (r"chmod\s+-R\s+777\s+/", "Recursive 777 on root"),
    (r"chown\s+-R\s+.*\s+/", "Recursive chown on root"),
    # Fork bombs
    (r":\(\)\s*\{\s*:\|:\&\s*\}\s*;?\s*:", "Fork bomb"),
    (r"fork\s+bomb", "Fork bomb (text)"),
    # Remote code execution via pipe
    (r"curl\s+.*\|\s*(sh|bash)", "Remote code execution via curl pipe"),
    (r"wget\s+.*\|\s*(sh|bash)", "Remote code execution via wget pipe"),
    # Kernel modules
    (r"rmmod", "Kernel module removal"),
    # Process killing (critical system processes)
    (r"killall\s+-9\s+(init|systemd|sshd)", "Killing critical system process"),
    (r"kill\s+-9\s+1\b", "Killing init process"),
]

INTERACTIVE_PREFIXES = ("ssh ", "sshpass ", "telnet ", "ftp ",
                        "mysql -u", "psql -U")

LOCAL_ONLY_CMDS = frozenset({
    # exactly the oracle's local-only set (safe_execution.py L176) —
    # widening this list widens the scope bypass surface, so new
    # commands go through target extraction, not around it
    "grep", "cat", "find", "ls", "tail", "head", "awk", "sed"})

# ─── PILOT-03 fail-closed guard (run-1 turn-6 class) ──────────────────
# A shell command that invokes a network-facing binary but yields NO
# extractable target is DENIED by the gate (rule scope:no-target)
# instead of allowed — the targetless-egress class closes here.
# Binaries are matched only at command position (segment-initial
# token, after VAR= assignments and wrapper prefixes), so prose
# mentions such as 'echo "run nmap later"' do not trip it.
# Deliberately excluded: apt/pip — fixed-infrastructure indexes, and
# any custom index host is still caught by ordinary scope extraction.
NETWORK_BINARIES = frozenset({
    "curl", "wget", "dig", "nslookup", "host", "nc", "ncat", "netcat",
    "nmap", "masscan", "ssh", "scp", "sftp", "ping", "ping6",
    "traceroute", "tracepath", "whois", "telnet", "ftp", "smbclient",
    "rpcclient", "nikto", "gobuster", "dirb", "dirsearch", "ffuf",
    "wfuzz", "sqlmap", "hydra", "medusa", "amass", "subfinder",
    "dnsrecon", "dnsenum", "fierce",
})

_GUARD_WRAPPERS = frozenset({
    "sudo", "nohup", "env", "stdbuf", "watch", "xargs", "nice",
    "command", "proxychains", "proxychains4",
})

# aggressive split: only segment-INITIAL tokens are ever inspected, so
# also splitting on '$', '(', ')' and backtick is safe — and it catches
# command substitutions ("echo $(curl http://x/)")
_GUARD_SEGMENT_RE = re.compile(r"[\n;|&()$`]+")
_GUARD_ASSIGN_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_]*=.*")
_GUARD_NUM_RE = re.compile(r"\d+(?:\.\d+)?[a-zA-Z]*")


def _invokes_network_binary(command: str) -> bool:
    """True when a command-position token is a network binary."""
    for seg in _GUARD_SEGMENT_RE.split(command):
        tokens = seg.strip().split()
        while tokens:
            tok = tokens.pop(0)
            if _GUARD_ASSIGN_RE.fullmatch(tok):
                continue                    # leading VAR=value
            if tok == "timeout":
                if tokens and _GUARD_NUM_RE.fullmatch(tokens[0]):
                    tokens.pop(0)           # 'timeout 10 curl ...'
                continue
            if tok in _GUARD_WRAPPERS:
                continue
            if tok.rsplit("/", 1)[-1] in NETWORK_BINARIES:
                return True
            break                           # first real command seen
    return False


# Commands that install persistence (RoE poc_only gate input).
PERSISTENCE_PATTERNS = [
    r"crontab\s", r"/etc/cron", r"systemctl\s+enable",
    r"update-rc\.d", r"chkconfig\s+on", r"reg\s+add",
    r"authorized_keys", r"msfvenom.*-p\s+(linux|windows)",
    r"/etc/init\.d", r"/etc/systemd/system",
]


def _first_pattern(command: str
                   ) -> Tuple[Optional[str], Optional[str]]:
    for pattern, description in DANGEROUS_PATTERNS:
        if re.search(pattern, command, re.IGNORECASE):
            return pattern, description
    return None, None


def get_proxy_env() -> Dict[str, str]:
    """Construct proxy environment variables from SOCKS5 config
    (ported: the engagement's egress routing stays operator-owned)."""
    host = os.environ.get("SOCKS5_HOST")
    port = os.environ.get("SOCKS5_PORT")
    user = os.environ.get("SOCKS5_USER")
    pwd = os.environ.get("SOCKS5_PASS")
    if host and port:
        if user and pwd:
            proxy_url = f"socks5://{user}:{pwd}@{host}:{port}"
        else:
            proxy_url = f"socks5://{host}:{port}"
        return {
            "HTTP_PROXY": proxy_url, "HTTPS_PROXY": proxy_url,
            "ALL_PROXY": proxy_url, "http_proxy": proxy_url,
            "https_proxy": proxy_url, "all_proxy": proxy_url,
        }
    return {}


# ─── run_command (the Bash surface) ────────────────────────────────────

class RunCommandTool(Tool):
    name = "run_command"
    aliases = ("bash", "shell")
    input_schema = {
        "type": "object",
        "properties": {
            "command": {"type": "string", "minLength": 1,
                        "maxLength": 32000},
            "timeout_s": {"type": "integer", "minimum": 1,
                          "maximum": 3600},
        },
        "required": ["command"],
        "additionalProperties": False,
    }
    timeout_s = 300.0
    cancel_siblings_on_error = True

    def prompt(self) -> str:
        return ("Execute a shell command in the engagement workspace "
                "(Kali toolchain). Output beyond the preview cap is "
                "paginated to a buffer file. Commands touching network "
                "targets are scope-gated; destructive patterns are "
                "blocked. Interactive commands (ssh/telnet/ftp) are "
                "rejected — use non-interactive flags or dedicated "
                "tools.")

    def concurrency_safe(self, args: Dict[str, Any]) -> bool:
        return False            # shell commands serialize their batch

    def safety_class(self, args: Dict[str, Any]) -> SafetyClass:
        command = str(args.get("command", ""))
        if _first_pattern(command)[0] is not None:
            return SafetyClass.DESTRUCTIVE
        first = command.strip().split(" ")[0] if command.strip() else ""
        if first in LOCAL_ONLY_CMDS and not any(
                t in command for t in ("curl", "wget", "nc ", "ssh")):
            return SafetyClass.READ
        return SafetyClass.EXPLOIT

    def target_required(self, args: Dict[str, Any]) -> bool:
        """Fail-closed marker for the gate: when True and target
        extraction yields nothing, check_permission denies with rule
        scope:no-target (PILOT-03 guard)."""
        return _invokes_network_binary(str(args.get("command", "")))

    def extract_targets(self, args: Dict[str, Any]) -> List[str]:
        command = str(args.get("command", ""))
        # Oracle parity (safe_execution.validate_command): local-only
        # commands ("cat notes/x.md") are Authorized as local file
        # operations BEFORE target extraction — the domain heuristic
        # must not scope-check workspace filenames that merely look
        # like hostnames.
        first = command.strip().split(" ")[0] if command.strip() else ""
        if self.safety_class(args) is SafetyClass.READ:
            return []
        return extract_targets_from_command(command)

    def is_persistent(self, args: Dict[str, Any]) -> bool:
        command = str(args.get("command", ""))
        return any(re.search(p, command) for p in PERSISTENCE_PATTERNS)

    def validate_input(self, args: Dict[str, Any]) -> Optional[str]:
        command = str(args.get("command", ""))
        if not command.strip():
            return "Empty command"
        _, description = _first_pattern(command)
        if description is not None:
            return f"BLOCKED: {description}"
        stripped = command.strip()
        for prefix in INTERACTIVE_PREFIXES:
            if stripped.startswith(prefix):
                return (f"BLOCKED: Interactive command {prefix.strip()!r} "
                        f"will trap the terminal. Use non-interactive "
                        f"flags (e.g. ssh -o BatchMode=yes) or a "
                        f"dedicated tool.")
        return None

    def description(self, args: Dict[str, Any]) -> str:
        return str(args.get("command", ""))[:120]

    async def call(self, args: Dict[str, Any],
                   ctx: ToolContext) -> ToolResult:
        command = str(args.get("command", ""))
        timeout = min(float(args.get("timeout_s") or self.timeout_s),
                      self.timeout_s)
        env = dict(os.environ)
        env.update(get_proxy_env())
        try:
            proc = await asyncio.create_subprocess_shell(
                command,
                cwd=ctx.workspace,
                env=env,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.STDOUT,
                preexec_fn=os.setsid,   # process group for clean kill
            )
        except OSError as exc:
            return ToolResult.error(f"failed to spawn: {exc}",
                                    exit_code=-1)
        try:
            out, _ = await asyncio.wait_for(proc.communicate(),
                                            timeout=timeout)
        except asyncio.TimeoutError:
            try:
                os.killpg(os.getpgid(proc.pid), 9)
            except (ProcessLookupError, PermissionError, OSError):
                pass
            return ToolResult.error(
                f"command exceeded {timeout:.0f}s wall-clock bound "
                f"(process group killed)", exit_code=-9)
        text = out.decode("utf-8", "replace") if out else ""
        code = proc.returncode
        if code == 0 and not text.strip():
            return ToolResult("Command executed (no output).",
                              metadata={"exit_code": 0})
        # exit-code marker so the model sees failures explicitly
        content = text if code == 0 else (
            f"{text}\n[exit code {code}]" if text.strip()
            else f"[exit code {code}]")
        return ToolResult(content, is_error=code != 0,
                          metadata={"exit_code": code})


# ─── file tools ────────────────────────────────────────────────────────

class ReadFileTool(Tool):
    name = "read_file"
    aliases = ("read",)
    input_schema = {
        "type": "object",
        "properties": {
            "path": {"type": "string", "minLength": 1},
            "offset": {"type": "integer", "minimum": 1},
            "limit": {"type": "integer", "minimum": 1, "maximum": 2000},
        },
        "required": ["path"],
        "additionalProperties": False,
    }
    path_args = ("path",)

    def prompt(self) -> str:
        return ("Read a text file from the engagement workspace. Returns "
                "numbered lines; use offset/limit to page through large "
                "files and buffer outputs.")

    def description(self, args: Dict[str, Any]) -> str:
        return str(args.get("path", ""))

    def max_result_chars(self) -> int:
        return 16000

    async def call(self, args: Dict[str, Any],
                   ctx: ToolContext) -> ToolResult:
        resolved = resolve_safe_path(str(args.get("path", "")),
                                     ctx.workspace)
        if resolved is None:
            return ToolResult.error("path escapes the workspace")
        p = Path(resolved)
        if not p.exists():
            return ToolResult.error(f"file not found: {args.get('path')}")
        if p.is_dir():
            return ToolResult.error(f"is a directory: {args.get('path')}")
        offset = int(args.get("offset") or 1)
        limit = int(args.get("limit") or 2000)
        try:
            raw = p.read_bytes()
        except OSError as exc:
            return ToolResult.error(f"read failed: {exc}")
        if b"\x00" in raw[:8192]:
            return ToolResult.error(
                "binary file — use run_command (strings/xxd/objdump) "
                "to inspect it")
        text = raw.decode("utf-8", "replace")
        lines = text.splitlines()
        total = len(lines)
        if total > (offset - 1) and (offset > 1 or limit < total):
            sel = lines[offset - 1:offset - 1 + limit]
            body = "\n".join(
                f"{n:>6}\t{line}"
                for n, line in enumerate(sel, start=offset))
            header = (f"[{args.get('path')} | lines {offset}-"
                      f"{offset + len(sel) - 1} of {total}]\n")
            return ToolResult(header + body,
                              metadata={"total_lines": total})
        body = "\n".join(f"{n:>6}\t{line}"
                         for n, line in enumerate(lines, start=1))
        return ToolResult(body, metadata={"total_lines": total})


class WriteFileTool(Tool):
    name = "write_file"
    aliases = ("write",)
    input_schema = {
        "type": "object",
        "properties": {
            "path": {"type": "string", "minLength": 1},
            "content": {"type": "string"},
        },
        "required": ["path", "content"],
        "additionalProperties": False,
    }
    path_args = ("path",)
    timeout_s = 30.0

    def prompt(self) -> str:
        return ("Write a file inside the engagement workspace (creates "
                "parent directories; overwrites existing files).")

    def description(self, args: Dict[str, Any]) -> str:
        return str(args.get("path", ""))

    def concurrency_safe(self, args: Dict[str, Any]) -> bool:
        return False            # context-modifying -> serial lane

    def safety_class(self, args: Dict[str, Any]) -> SafetyClass:
        return SafetyClass.WRITE

    def max_result_chars(self) -> int:
        return 2000

    async def call(self, args: Dict[str, Any],
                   ctx: ToolContext) -> ToolResult:
        resolved = resolve_safe_path(str(args.get("path", "")),
                                     ctx.workspace)
        if resolved is None:
            return ToolResult.error("path escapes the workspace")
        content = str(args.get("content", ""))
        p = Path(resolved)
        existed = p.exists()
        try:
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text(content, encoding="utf-8")
            try:
                os.chmod(p, stat.S_IRUSR | stat.S_IWUSR)
            except OSError:
                pass
        except OSError as exc:
            return ToolResult.error(f"write failed: {exc}")
        n_lines = content.count("\n") + (1 if content else 0)
        return ToolResult(
            f"{'Overwrote' if existed else 'Wrote'} {args.get('path')} "
            f"({len(content)} chars, {n_lines} lines)",
            metadata={"chars": len(content)})


class EditFileTool(Tool):
    name = "edit_file"
    aliases = ("edit",)
    input_schema = {
        "type": "object",
        "properties": {
            "path": {"type": "string", "minLength": 1},
            "old_str": {"type": "string"},
            "new_str": {"type": "string"},
            "replace_all": {"type": "boolean"},
        },
        "required": ["path", "old_str"],
        "additionalProperties": False,
    }
    path_args = ("path",)
    timeout_s = 30.0

    def prompt(self) -> str:
        return ("Edit a file with an exact string replacement. old_str "
                "must match uniquely (or set replace_all); the edit "
                "fails rather than guessing when the match is ambiguous.")

    def description(self, args: Dict[str, Any]) -> str:
        return str(args.get("path", ""))

    def concurrency_safe(self, args: Dict[str, Any]) -> bool:
        return False

    def safety_class(self, args: Dict[str, Any]) -> SafetyClass:
        return SafetyClass.WRITE

    def max_result_chars(self) -> int:
        return 4000

    def validate_input(self, args: Dict[str, Any]) -> Optional[str]:
        if args.get("old_str") == args.get("new_str"):
            return "old_str and new_str are identical"
        return None

    async def call(self, args: Dict[str, Any],
                   ctx: ToolContext) -> ToolResult:
        resolved = resolve_safe_path(str(args.get("path", "")),
                                     ctx.workspace)
        if resolved is None:
            return ToolResult.error("path escapes the workspace")
        p = Path(resolved)
        if not p.exists():
            return ToolResult.error(f"file not found: {args.get('path')}")
        try:
            text = p.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError) as exc:
            return ToolResult.error(f"read failed: {exc}")
        old = str(args.get("old_str", ""))
        new = str(args.get("new_str", ""))
        count = text.count(old)
        if count == 0:
            return ToolResult.error(
                "old_str not found in file — read the file and retry "
                "with the exact text")
        if count > 1 and not args.get("replace_all"):
            return ToolResult.error(
                f"old_str matches {count} locations; provide more "
                f"surrounding context for a unique match, or set "
                f"replace_all=true")
        updated = text.replace(old, new) if args.get("replace_all") \
            else text.replace(old, new, 1)
        try:
            p.write_text(updated, encoding="utf-8")
        except OSError as exc:
            return ToolResult.error(f"write failed: {exc}")
        snippet = updated[max(0, updated.find(new) - 80):
                          updated.find(new) + len(new) + 80]
        return ToolResult(
            f"Edited {args.get('path')} "
            f"({count if args.get('replace_all') else 1} replacement(s)). "
            f"Context:\n---\n{snippet}\n---",
            metadata={"replacements": count})


class LsTool(Tool):
    name = "ls"
    input_schema = {
        "type": "object",
        "properties": {
            "path": {"type": "string"},
        },
        "additionalProperties": False,
    }
    path_args = ("path",)

    def prompt(self) -> str:
        return ("List a directory in the engagement workspace (directories "
                "first, with type markers).")

    def description(self, args: Dict[str, Any]) -> str:
        return str(args.get("path") or ".")

    def max_result_chars(self) -> int:
        return 8000

    async def call(self, args: Dict[str, Any],
                   ctx: ToolContext) -> ToolResult:
        raw = str(args.get("path") or ".")
        resolved = resolve_safe_path(raw, ctx.workspace)
        if resolved is None:
            return ToolResult.error("path escapes the workspace")
        p = Path(resolved)
        if not p.exists():
            return ToolResult.error(f"not found: {raw}")
        if not p.is_dir():
            return ToolResult.error(f"not a directory: {raw}")
        try:
            entries = sorted(p.iterdir(),
                             key=lambda e: (not e.is_dir(), e.name.lower()))
        except OSError as exc:
            return ToolResult.error(f"list failed: {exc}")
        lines = []
        for e in entries[:500]:
            marker = "d" if e.is_dir() else ("l" if e.is_symlink() else "-")
            try:
                size = "-" if e.is_dir() else e.stat().st_size
            except OSError:
                size = "?"
            lines.append(f"{marker} {size:>10}  {e.name}")
        if len(entries) > 500:
            lines.append(f"... [{len(entries) - 500} more entries]")
        return ToolResult("\n".join(lines) or "(empty directory)",
                          metadata={"entries": len(entries)})


class GlobTool(Tool):
    name = "glob"
    input_schema = {
        "type": "object",
        "properties": {
            "pattern": {"type": "string", "minLength": 1},
            "path": {"type": "string"},
        },
        "required": ["pattern"],
        "additionalProperties": False,
    }
    path_args = ("path",)

    def prompt(self) -> str:
        return ("Find files by glob pattern (e.g. **/*.py) under a "
                "workspace directory; results sorted by modification "
                "time, newest first.")

    def description(self, args: Dict[str, Any]) -> str:
        return str(args.get("pattern", ""))

    def max_result_chars(self) -> int:
        return 8000

    async def call(self, args: Dict[str, Any],
                   ctx: ToolContext) -> ToolResult:
        raw_root = str(args.get("path") or ".")
        root = resolve_safe_path(raw_root, ctx.workspace)
        if root is None:
            return ToolResult.error("path escapes the workspace")
        pattern = str(args.get("pattern", ""))
        p = Path(root)
        try:
            matches = [m for m in p.glob(pattern)
                       if m.is_file()][:1000]
        except (OSError, ValueError) as exc:
            return ToolResult.error(f"glob failed: {exc}")
        try:
            matches.sort(key=lambda m: m.stat().st_mtime, reverse=True)
        except OSError:
            pass
        if not matches:
            return ToolResult("no matches")
        rel = [str(m.relative_to(ctx.workspace)) for m in matches]
        body = "\n".join(rel)
        note = "" if len(matches) < 1000 else \
            f"\n... [showing first 1000 of {len(matches)}]"
        return ToolResult(body + note, metadata={"matches": len(matches)})


class GrepTool(Tool):
    name = "grep"
    input_schema = {
        "type": "object",
        "properties": {
            "pattern": {"type": "string", "minLength": 1},
            "path": {"type": "string"},
            "glob": {"type": "string"},
            "output_mode": {"enum": ["content", "files_with_matches",
                                     "count"]},
            "ignore_case": {"type": "boolean"},
        },
        "required": ["pattern"],
        "additionalProperties": False,
    }
    path_args = ("path",)
    timeout_s = 60.0

    def prompt(self) -> str:
        return ("Search file contents with a regex under a workspace "
                "directory (recursive, text files only, binary-skipped). "
                "output_mode: content (default, with line numbers), "
                "files_with_matches, or count.")

    def description(self, args: Dict[str, Any]) -> str:
        return str(args.get("pattern", ""))

    def max_result_chars(self) -> int:
        return 12000

    async def call(self, args: Dict[str, Any],
                   ctx: ToolContext) -> ToolResult:
        raw_root = str(args.get("path") or ".")
        root = resolve_safe_path(raw_root, ctx.workspace)
        if root is None:
            return ToolResult.error("path escapes the workspace")
        pattern = str(args.get("pattern", ""))
        flags = re.IGNORECASE if args.get("ignore_case") else 0
        try:
            rx = re.compile(pattern, flags)
        except re.error as exc:
            return ToolResult.error(f"invalid regex: {exc}")
        mode = str(args.get("output_mode") or "content")
        name_glob = str(args.get("glob") or "**/*")

        files: List[Path] = []
        try:
            files = [f for f in Path(root).glob(name_glob) if f.is_file()]
        except (OSError, ValueError) as exc:
            return ToolResult.error(f"glob failed: {exc}")
        files = files[:2000]

        matched_files = 0
        out_lines: List[str] = []
        total_matches = 0
        try:
            for f in files:
                try:
                    if f.stat().st_size > 5 * 1024 * 1024:
                        continue
                    with f.open("rb") as fh:
                        head = fh.read(8192)
                    if b"\x00" in head:
                        continue                    # binary — skip
                    text = f.read_text(encoding="utf-8", errors="replace")
                except OSError:
                    continue
                hits = []
                for ln, line in enumerate(text.splitlines(), start=1):
                    if rx.search(line):
                        hits.append(ln)
                        total_matches += 1
                if not hits:
                    continue
                matched_files += 1
                rel = str(f.relative_to(ctx.workspace))
                if mode == "files_with_matches":
                    out_lines.append(rel)
                elif mode == "count":
                    out_lines.append(f"{len(hits):>6}  {rel}")
                else:
                    for ln in hits[:50]:
                        out_lines.append(f"{rel}:{ln}")
                    if len(hits) > 50:
                        out_lines.append(f"{rel}:... "
                                         f"[{len(hits) - 50} more in file]")
                if len(out_lines) >= 200:
                    out_lines.append(
                        f"... [output truncated at 200 lines — "
                        f"narrow the pattern or path]")
                    break
        except OSError as exc:
            return ToolResult.error(f"search failed: {exc}")
        if not out_lines:
            return ToolResult("no matches",
                              metadata={"files_searched": len(files)})
        return ToolResult("\n".join(out_lines),
                          metadata={"matched_files": matched_files,
                                    "matches": total_matches,
                                    "files_searched": len(files)})


# ─── todo_write (the engagement's visible spine) ───────────────────────

class TodoWriteTool(Tool):
    name = "todo_write"
    aliases = ("todowrite",)
    input_schema = {
        "type": "object",
        "properties": {
            "todos": {
                "type": "array",
                "minItems": 1,
                "items": {
                    "type": "object",
                    "properties": {
                        "id": {"type": "string", "minLength": 1},
                        "content": {"type": "string", "minLength": 1},
                        "status": {"enum": ["pending", "in_progress",
                                            "completed"]},
                        "priority": {"enum": ["high", "medium", "low"]},
                    },
                    "required": ["id", "content", "status"],
                    "additionalProperties": False,
                },
            },
        },
        "required": ["todos"],
        "additionalProperties": False,
    }
    timeout_s = 15.0

    def prompt(self) -> str:
        return ("Replace the engagement todo list (recon -> enumerate -> "
                "verify -> exploit -> report templates ship as data in "
                "P3). Every item: id, content, status "
                "(pending/in_progress/completed), priority.")

    def concurrency_safe(self, args: Dict[str, Any]) -> bool:
        return False

    def safety_class(self, args: Dict[str, Any]) -> SafetyClass:
        return SafetyClass.WRITE

    def max_result_chars(self) -> int:
        return 4000

    def validate_input(self, args: Dict[str, Any]) -> Optional[str]:
        todos = args.get("todos") or []
        seen = set()
        for t in todos:
            tid = str(t.get("id", ""))
            if tid in seen:
                return f"duplicate todo id {tid!r}"
            seen.add(tid)
        in_progress = [t for t in todos
                       if t.get("status") == "in_progress"]
        if len(in_progress) > 1:
            return ("multiple in_progress todos — exactly one task may "
                    "be in_progress at a time")
        return None

    async def call(self, args: Dict[str, Any],
                   ctx: ToolContext) -> ToolResult:
        todos = args.get("todos") or []
        store = Path(ctx.workspace) / ".aegis" / "todos.json"
        try:
            store.parent.mkdir(parents=True, exist_ok=True)
            store.write_text(json.dumps(
                {"todos": todos}, indent=2), encoding="utf-8")
        except OSError as exc:
            return ToolResult.error(f"persist failed: {exc}")
        # P2: mirror the task state into the EKD (task nodes feed the
        # brief's TASKS section; status changes journal through the
        # batch as tracked-attr supersessions — H6 carried)
        ekd = (ctx.extra or {}).get("ekd") if ctx.extra else None
        if ekd is not None:
            try:
                from ..memory.ekd import EkdBatch
                from ..memory.extractors import sync_todos
                with EkdBatch(ekd, ctx, extractor="task_sync",
                              reason="todo_write"):
                    sync_todos(ekd, todos,
                               provenance=[(ctx.extra or {}).get(
                                   "objective_id")]
                               if ctx.extra else None)
            except Exception:
                pass  # the todo surface never gates on the graph
        counts = {"completed": 0, "in_progress": 0, "pending": 0}
        for t in todos:
            counts[str(t.get("status"))] = \
                counts.get(str(t.get("status")), 0) + 1
        bar = "".join("x" if t.get("status") == "completed" else " "
                      for t in todos)
        return ToolResult(
            f"Todos updated: [{bar}] "
            f"{counts['completed']}/{len(todos)} completed, "
            f"{counts['in_progress']} in_progress",
            metadata={"total": len(todos), **counts})


# ─── registry builder ──────────────────────────────────────────────────

def build_registry(tools: Optional[List[Tool]] = None,
                   *, include_vapt: bool = False,
                   include_task: bool = False
                   ) -> "ToolRegistry":
    """Assemble the registry. Defaults to the PLATFORM set (P1 tools
    + P2 memory tools) so library callers — subagent child registries,
    tests, embeddings — get the stable base; the composition root
    (CLI boot) opts into the P3 families: `build_registry(
    include_vapt=True, include_task=True)`. AEGIS_VAPT_TOOLS=0 trims
    the VAPT family entirely at boot."""
    from .base import ToolRegistry
    from .memory import MemoryQueryTool
    reg = ToolRegistry()
    for tool in (tools if tools is not None else [
            RunCommandTool(), ReadFileTool(), WriteFileTool(),
            EditFileTool(), LsTool(), GlobTool(), GrepTool(),
            TodoWriteTool(), MemoryQueryTool()]):
        reg.register(tool)
    if include_vapt:
        from .vapt import build_vapt_tools, vapt_enabled
        if vapt_enabled():
            for tool in build_vapt_tools():
                reg.register(tool)
    if include_task:
        from ..agents.task import TaskTool
        reg.register(TaskTool())
    return reg


def _memory_tool_classes() -> Tuple[type, ...]:
    from .memory import MEMORY_TOOLS
    return MEMORY_TOOLS


CORE_TOOLS: Tuple[type, ...] = (
    RunCommandTool, ReadFileTool, WriteFileTool, EditFileTool,
    LsTool, GlobTool, GrepTool, TodoWriteTool) + _memory_tool_classes()
