"""hypervisor.tools.vapt.exec — the bounded code-execution harness (P3,
REFACTOR-05).

The oracle's execute_code / execute_exploit_script (system_tools_v2.py
L147/L282) re-hosted: code is written to a 0600 workspace scratch file,
executed as [sys.executable, file] in a process group with a hard
wall-clock bound, output captured whole then capped through the shared
render path (oversized output lands in the 0600 buffers with the
manifest + audit discipline).

Class discipline: EXPLOIT class with command-string target extraction
over the code text (the PORT-09 scope engine sees the IPs/domains/URLs
the code will touch); execute_exploit_script additionally runs the
persistence-marker battery, so a PoC-only RoE refuses anything that
installs (the 3.7 oracle parity).
"""
from __future__ import annotations

import asyncio
import os
import re
import sys
import uuid
from typing import Any, Dict, List, Optional

from ...permissions import (SafetyClass, extract_targets_from_command,
                            resolve_safe_path)
from ..base import Tool, ToolContext, ToolResult

# Patterns that install or leave persistent state on ANY machine
# (ported from the 3.7 PoC-only battery).
PERSISTENCE_PATTERNS = [
    r"useradd|adduser|passwd\s+-\w|chage\s+-\w",
    r"crontab|/etc/cron|schtasks|CreateScheduledTask",
    r"systemctl\s+(enable|start)|chkconfig|sc\s+config",
    r"authorized_keys|/root/\.ssh|id_rsa",
    r"reg\s+add|New-ItemProperty.*HKLM|registry.*Run",
    r"/etc/rc\.local|/etc/init\.d/|systemd/system",
    r"gem install|pip install .*--user.*--editable",
    r"nc\s+-e|ncat\s+-e|bash\s+-i\s+>&\s*/dev/tcp",
    r"Set-ExecutionPolicy|schtasks\s+/create",
    r"webshell|c99shell|wso\.php",
]

MAX_CODE_CHARS = 100_000


class ExecuteCodeTool(Tool):
    """Execute Python code in the engagement workspace (bounded,
    audited). The generic harness — analysis tooling, parsers, PoC
    scaffolding."""

    name = "execute_code"
    aliases = ("run_python",)
    input_schema = {
        "type": "object",
        "properties": {
            "python_code": {"type": "string", "minLength": 10,
                            "maxLength": MAX_CODE_CHARS},
            "timeout": {"type": "integer", "minimum": 1, "maximum": 600,
                        "default": 120},
        },
        "required": ["python_code"],
        "additionalProperties": False,
    }
    timeout_s = 620.0

    def prompt(self) -> str:
        return ("Execute Python code in the engagement workspace "
                "(stdlib of the harness interpreter). The code runs as "
                "a subprocess with a hard timeout; stdout+stderr return "
                "capped (oversized output paginates to a buffer file). "
                "Code touching network targets is scope-gated on the "
                "addresses it references.")

    def safety_class(self, args: Dict[str, Any]) -> SafetyClass:
        return SafetyClass.EXPLOIT

    def concurrency_safe(self, args: Dict[str, Any]) -> bool:
        return False

    def is_persistent(self, args: Dict[str, Any]) -> bool:
        code = str(args.get("python_code", ""))
        return any(re.search(p, code, re.I)
                   for p in PERSISTENCE_PATTERNS)

    def extract_targets(self, args: Dict[str, Any]) -> List[str]:
        return extract_targets_from_command(str(args.get(
            "python_code", "")))

    def validate_input(self, args: Dict[str, Any]) -> Optional[str]:
        code = str(args.get("python_code", ""))
        if not code.strip():
            return "empty code"
        return None

    def description(self, args: Dict[str, Any]) -> str:
        first = str(args.get("python_code", "")).strip().splitlines()
        return (first[0][:100] if first else "execute_code")

    async def call(self, args: Dict[str, Any],
                   ctx: ToolContext) -> ToolResult:
        return await _run_code(args, ctx, label="execute_code")


class ExecuteExploitTool(Tool):
    """Execute an exploit PoC script under the PoC-only RoE: the same
    bounded harness, with the persistence battery enforced BEFORE
    execution (a persistent payload is refused, not executed then
    regretted)."""

    name = "execute_exploit_script"
    aliases = ("run_exploit",)
    input_schema = {
        "type": "object",
        "properties": {
            "python_code": {"type": "string", "minLength": 10,
                            "maxLength": MAX_CODE_CHARS},
            "timeout": {"type": "integer", "minimum": 1, "maximum": 600,
                        "default": 120},
        },
        "required": ["python_code"],
        "additionalProperties": False,
    }
    timeout_s = 620.0

    def prompt(self) -> str:
        return ("Execute an exploit proof-of-concept script in the "
                "engagement workspace. Same bounded harness as "
                "execute_code; under a PoC-only RoE anything matching "
                "the persistence battery (user creation, cron, "
                "authorized_keys, shells, webshells...) is REFUSED "
                "before execution. Proof the finding, leave the estate "
                "unchanged.")

    def safety_class(self, args: Dict[str, Any]) -> SafetyClass:
        return SafetyClass.EXPLOIT

    def concurrency_safe(self, args: Dict[str, Any]) -> bool:
        return False

    def is_persistent(self, args: Dict[str, Any]) -> bool:
        code = str(args.get("python_code", ""))
        return any(re.search(p, code, re.I)
                   for p in PERSISTENCE_PATTERNS)

    def extract_targets(self, args: Dict[str, Any]) -> List[str]:
        return extract_targets_from_command(str(args.get(
            "python_code", "")))

    def description(self, args: Dict[str, Any]) -> str:
        first = str(args.get("python_code", "")).strip().splitlines()
        return ("exploit: " + first[0][:90] if first else "exploit")

    async def call(self, args: Dict[str, Any],
                   ctx: ToolContext) -> ToolResult:
        return await _run_code(args, ctx, label="execute_exploit_script")


async def _run_code(args: Dict[str, Any], ctx: ToolContext, *,
                    label: str) -> ToolResult:
    code = str(args.get("python_code", ""))
    timeout = min(int(args.get("timeout") or 120), 600)
    scratch_dir = os.path.join(ctx.workspace, ".aegis", "scratch")
    try:
        os.makedirs(scratch_dir, exist_ok=True)
        os.chmod(scratch_dir, 0o700)
    except OSError:
        pass
    file_id = uuid.uuid4().hex[:10]
    script_path = os.path.join(scratch_dir, f"{label}_{file_id}.py")
    try:
        with open(script_path, "w", encoding="utf-8") as f:
            f.write(code)
        os.chmod(script_path, 0o600)
    except OSError as exc:
        return ToolResult.error(f"scratch write failed: {exc}",
                                label=label)
    try:
        proc = await asyncio.create_subprocess_exec(
            sys.executable, "-I", script_path,
            cwd=ctx.workspace,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.STDOUT,
            preexec_fn=os.setsid)
    except OSError as exc:
        return ToolResult.error(f"spawn failed: {exc}", label=label)
    try:
        out, _ = await asyncio.wait_for(proc.communicate(),
                                        timeout=timeout)
    except asyncio.TimeoutError:
        try:
            os.killpg(os.getpgid(proc.pid), 9)
        except (ProcessLookupError, PermissionError, OSError):
            pass
        return ToolResult.error(
            f"execution exceeded {timeout}s wall-clock bound "
            f"(process group killed)", exit_code=-9, label=label)
    text = out.decode("utf-8", "replace") if out else ""
    code_rc = proc.returncode
    body = (text if code_rc == 0 else
            (f"{text}\n[exit code {code_rc}]" if text.strip()
             else f"[exit code {code_rc}]"))
    return ToolResult(body, is_error=code_rc != 0,
                      metadata={"exit_code": code_rc,
                                "script": script_path,
                                "chars": len(text)})
