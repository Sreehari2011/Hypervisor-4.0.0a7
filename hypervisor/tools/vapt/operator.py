"""hypervisor.tools.vapt.operator — the operator-attached runtimes (P4,
REFACTOR-05 final disposition).

The three tools deferred from P3 need operator-side runtimes a
stdlib-only bounded harness cannot itself host: a mobile device with
the frida server (frida_hook), a mitmproxy install (mitm_intercept),
and an ssh client + optional sshpass for password auth
(ssh_interactive_exec). The 4.0 contract for each:

  * availability is probed HONESTLY at call time (shutil.which) — a
    missing runtime returns a plain error naming the attachment, never
    a fabricated result;
  * execution rides the bounded subprocess discipline everywhere
    (0600 workspace scratch, process groups, hard wall-clock, output
    captured whole then capped through the shared render path);
  * the oracle's unbounded background sessions (SafeShellSession +
    sleep + poll) become BOUNDED capture windows: run for `duration`
    seconds, harvest stdout, kill the process group — principle 9
    (no organ may park the system silently) beats the oracle's
    interactive convenience, and the model gets the window's capture
    in one honest result;
  * scope/class discipline: ssh is EXPLOIT with the target extracted
    for the PORT-09 gate + the PoC-only persistence battery; frida /
    mitm are EXPLOIT device/daemon operations (the oracle scope-gates
    neither — device-local transports), both journaled with their
    full argv so replay + analyst review see exactly what ran.

Oracle sources (frozen 3.7.3 @ 338b646): mobile_tools.py L279-525
(frida_hook: the 4-script battery) and L529-614 (mitm_intercept: the
InterceptApp addon); system_tools_v2.py L387-452 (ssh_interactive_exec:
PTY + sudo responders via fabric — replaced here by the system ssh
binary under the bounded harness, password auth via sshpass when the
operator provides it, key auth otherwise).
"""
from __future__ import annotations

import asyncio
import os
import re
import shlex
import shutil
import uuid
from typing import Any, Dict, List, Optional

from ...permissions import SafetyClass, extract_targets_from_command
from ..base import Tool, ToolContext, ToolResult

MAX_CAPTURE_S = 120          # bounded capture window ceiling
DEFAULT_CAPTURE_S = 20
SSH_MAX_TIMEOUT_S = 300

# The PoC-only persistence battery is shared with exec.py (one source
# of truth for the RoE refusal classes).
from .exec import PERSISTENCE_PATTERNS

# ─── the frida script battery (verbatim from the oracle) ────────────────

FRIDA_SCRIPTS: Dict[str, str] = {
    "ssl_pinning": """
// Universal SSL Pinning Bypass
Java.perform(function() {
    console.log('[*] SSL Pinning Bypass Active');

    // OkHttp3 CertificatePinner
    try {
        var CertificatePinner = Java.use('okhttp3.CertificatePinner');
        CertificatePinner.check.overload('java.lang.String', 'java.util.List').implementation = function(a, b) {
            console.log('[+] OkHttp3 CertificatePinner bypassed: ' + a);
            return;
        };
    } catch (e) {}

    // TrustManagerImpl
    try {
        var TrustManagerImpl = Java.use('com.android.org.conscrypt.TrustManagerImpl');
        TrustManagerImpl.checkTrustedRecursive.implementation = function(a, b, c, d, e, f) {
            console.log('[+] TrustManagerImpl bypassed');
            return Java.use('java.util.ArrayList').$new();
        };
    } catch (e) {}

    // X509TrustManager
    try {
        var X509TrustManager = Java.use('javax.net.ssl.X509TrustManager');
        var SSLContext = Java.use('javax.net.ssl.SSLContext');
        var TrustManager = Java.registerClass({
            name: 'org.aegis.TrustManager',
            implements: [X509TrustManager],
            methods: {
                checkClientTrusted: function(chain, authType) {},
                checkServerTrusted: function(chain, authType) {},
                getAcceptedIssuers: function() { return []; }
            }
        });
        SSLContext.init.overload(
            '[Ljavax.net.ssl.KeyManager;',
            '[Ljavax.net.ssl.TrustManager;',
            'java.security.SecureRandom'
        ).implementation = function(km, tm, sr) {
            this.init(km, [TrustManager.$new()], sr);
        };
    } catch (e) {}
});

// Native SSL bypass (BoringSSL/OpenSSL)
Interceptor.attach(Module.findExportByName(null, 'SSL_CTX_set_verify'), {
    onEnter: function(args) {
        args[1] = ptr(0);  // SSL_VERIFY_NONE
    }
});
""",
    "root_detect": """
// Root Detection Bypass
Java.perform(function() {
    console.log('[*] Root Detection Bypass Active');

    // Common root detection methods
    var RootDetectionMethods = [
        'com/scottyab/rootbeer/RootBeer',
        'eu/chainfire/libsuperuser/Shell',
    ];

    // File existence checks
    var File = Java.use('java.io.File');
    File.exists.implementation = function() {
        var path = this.getAbsolutePath();
        var rootPaths = ['/sbin/su', '/system/bin/su', '/system/xbin/su',
                        '/data/local/xbin/su', '/data/local/bin/su',
                        '/system/sd/xbin/su', '/system/bin/failsafe/su',
                        '/data/local/su', '/su/bin/su', '/magisk/.core/bin/su',
                        '/system/app/Superuser.apk', '/sbin/.magisk'];
        if (rootPaths.indexOf(path) >= 0) {
            console.log('[+] Hidden root file: ' + path);
            return false;
        }
        return this.exists();
    };

    // Runtime exec su check
    var Runtime = Java.use('java.lang.Runtime');
    Runtime.exec.overload('java.lang.String').implementation = function(cmd) {
        if (cmd.indexOf('su') >= 0) {
            console.log('[+] Blocked su exec: ' + cmd);
            throw Java.use('java.io.IOException').$new('su not found');
        }
        return this.exec(cmd);
    };

    // System property checks
    var System = Java.use('java.lang.System');
    System.getProperty.implementation = function(key) {
        if (key === 'ro.build.tags' || key === 'ro.build.type') {
            console.log('[+] Spoofed property: ' + key);
            return 'release-key';
        }
        return this.getProperty(key);
    };
});
""",
    "crypto_intercept": """
// Crypto Interception
Java.perform(function() {
    console.log('[*] Crypto Interception Active');

    // Intercept Cipher.doFinal
    var Cipher = Java.use('javax.crypto.Cipher');
    Cipher.doFinal.overload('[B').implementation = function(input) {
        var result = this.doFinal(input);
        var mode = this.getOpmode ? this.getOpmode() : this.init ? 'unknown' : 'unknown';
        console.log('[CRYPTO] Mode: ' + mode);
        console.log('[CRYPTO] Input: ' + bytesToHex(input));
        console.log('[CRYPTO] Output: ' + bytesToHex(result));
        return result;
    };

    // Intercept SecretKeySpec
    var SecretKeySpec = Java.use('javax.crypto.spec.SecretKeySpec');
    SecretKeySpec.$init.overload('[B', 'java.lang.String').implementation = function(key, algo) {
        console.log('[KEY] Algorithm: ' + algo);
        console.log('[KEY] Key: ' + bytesToHex(key));
        return this.$init(key, algo);
    };

    // Intercept MessageDigest
    var MessageDigest = Java.use('java.security.MessageDigest');
    MessageDigest.digest.overload().implementation = function() {
        var result = this.digest();
        console.log('[HASH] Algorithm: ' + this.getAlgorithm());
        console.log('[HASH] Output: ' + bytesToHex(result));
        return result;
    };

    function bytesToHex(bytes) {
        var hex = [];
        for (var i = 0; i < bytes.length; i++) {
            hex.push(('0' + (bytes[i] & 0xFF).toString(16)).slice(-2));
        }
        return hex.join('');
    }
});
""",
    "api_monitor": """
// API Monitor - Intercept all HTTP/HTTPS calls
Java.perform(function() {
    console.log('[*] API Monitor Active');

    // HttpURLConnection
    try {
        var URL = Java.use('java.net.URL');
        URL.$init.overload('java.lang.String').implementation = function(url) {
            console.log('[URL] ' + url);
            return this.$init(url);
        };
    } catch(e) {}

    // OkHttp
    try {
        var OkHttpClient = Java.use('okhttp3.OkHttpClient');
        OkHttpClient.newCall.implementation = function(request) {
            console.log('[OKHTTP] ' + request.method() + ' ' + request.url().toString());
            var headers = request.headers();
            for (var i = 0; i < headers.size(); i++) {
                console.log('[OKHTTP] Header: ' + headers.name(i) + ': ' + headers.value(i));
            }
            return this.newCall(request);
        };
    } catch(e) {}

    // WebView
    try {
        var WebView = Java.use('android.webkit.WebView');
        WebView.loadUrl.overload('java.lang.String').implementation = function(url) {
            console.log('[WEBVIEW] ' + url);
            return this.loadUrl(url);
        };
    } catch(e) {}
});
""",
}

# The mitmproxy addon (verbatim from the oracle's mitm_intercept).
MITM_ADDON_SCRIPT = """
import os
import sys
from mitmproxy import http

class InterceptApp:
    def __init__(self):
        self.requests = []
        self.responses = []

    def request(self, flow: http.HTTPFlow):
        if flow.request.pretty_url:
            print(f"[REQ] {flow.request.method} {flow.request.pretty_url}")
            for k, v in flow.request.headers.items():
                print(f"[REQ-H] {k}: {v}")
            if flow.request.content:
                print(f"[REQ-B] {flow.request.content[:500]}")

    def response(self, flow: http.HTTPFlow):
        if flow.response:
            print(f"[RES] {flow.response.status_code} {flow.request.pretty_url}")
            for k, v in flow.response.headers.items():
                print(f"[RES-H] {k}: {v}")
            if flow.response.content:
                print(f"[RES-B] {flow.response.content[:500]}")

addons = [InterceptApp()]
"""


# ─── the bounded capture harness (shared by frida / mitmdump) ──────────

async def _bounded_capture(argv: List[str], *, cwd: str,
                           duration_s: float,
                           label: str) -> ToolResult:
    """Run argv as a process group for at most duration_s seconds,
    harvest stdout+stderr, then SIGKILL the group. The oracle ran
    these as unbounded background sessions polled by session_action;
    principle 9 (nothing parks silently) turns that into an explicit
    bounded capture window whose harvest returns in ONE result."""
    try:
        proc = await asyncio.create_subprocess_exec(
            *argv, cwd=cwd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.STDOUT,
            preexec_fn=os.setsid)
    except OSError as exc:
        return ToolResult.error(f"spawn failed: {exc}", label=label)

    async def _harvest() -> tuple[bytes, int]:
        """Reader-task harvest: chunks land in a list AS THEY ARRIVE, so
        a window-close kill never loses already-produced output (a
        cancelled communicate() discards its partial read — found by
        the P4 fixtures)."""
        chunks: list[bytes] = []

        async def _reader() -> None:
            try:
                while True:
                    b = await proc.stdout.read(65536)
                    if not b:
                        break
                    chunks.append(b)
            except Exception:
                pass

        reader = asyncio.ensure_future(_reader())
        try:
            await asyncio.wait_for(asyncio.shield(reader),
                                   timeout=duration_s)
            # process ended on its own inside the window
            return b"".join(chunks), proc.returncode or 0
        except asyncio.TimeoutError:
            pass
        # window closed: kill the group, then drain to EOF
        try:
            os.killpg(os.getpgid(proc.pid), 9)
        except (ProcessLookupError, PermissionError, OSError):
            pass
        try:
            await asyncio.wait_for(reader, timeout=5)
        except asyncio.TimeoutError:
            reader.cancel()
        return b"".join(chunks), -9

    out, rc = await _harvest()
    text = out.decode("utf-8", "replace")
    meta = {"exit_code": rc, "argv": argv, "chars": len(text),
            "window_s": duration_s}
    if rc == -9:
        body = (f"[capture window closed at {duration_s:.0f}s "
                f"(process group killed)]\n{text}")
        return ToolResult(body, metadata=meta)
    body = text if text.strip() else f"[no output, exit {rc}]"
    return ToolResult(body, is_error=rc not in (0,), metadata=meta)


def _operator_missing(binary: str, tool: str, hint: str) -> ToolResult:
    return ToolResult.error(
        f"operator runtime not attached: `{binary}` was not found on "
        f"PATH. {tool} shells out to the operator-installed "
        f"{binary!r}; install it on the engagement host"
        f"{' ' + hint if hint else ''} and re-run.",
        label=tool)


def _scratch_write(ctx: ToolContext, name: str, content: str) -> Optional[str]:
    scratch_dir = os.path.join(ctx.workspace, ".aegis", "scratch")
    try:
        os.makedirs(scratch_dir, exist_ok=True)
        os.chmod(scratch_dir, 0o700)
    except OSError:
        pass
    path = os.path.join(scratch_dir, f"{name}_{uuid.uuid4().hex[:8]}")
    try:
        with open(path, "w", encoding="utf-8") as f:
            f.write(content)
        os.chmod(path, 0o600)
        return path
    except OSError:
        return None


# ─── frida_hook ─────────────────────────────────────────────────────────

class FridaHookTool(Tool):
    """Dynamic instrumentation of a mobile app through the operator's
    frida runtime, as a bounded capture window."""

    name = "frida_hook"
    aliases = ("frida",)
    input_schema = {
        "type": "object",
        "properties": {
            "package_name": {"type": "string", "minLength": 3,
                             "maxLength": 200},
            "script_path": {"type": "string", "maxLength": 400,
                            "default": ""},
            "hook_type": {"type": "string",
                          "enum": ["ssl_pinning", "root_detect",
                                   "crypto_intercept", "api_monitor",
                                   "custom"],
                          "default": "ssl_pinning"},
            "device": {"type": "string", "enum": ["usb", "emulator"],
                       "default": "usb"},
            "spawn": {"type": "boolean", "default": True},
            "duration": {"type": "integer", "minimum": 3,
                         "maximum": MAX_CAPTURE_S,
                         "default": DEFAULT_CAPTURE_S},
        },
        "required": ["package_name"],
        "additionalProperties": False,
    }
    timeout_s = float(MAX_CAPTURE_S + 30)

    def prompt(self) -> str:
        return ("Hook a mobile app with Frida (operator-attached runtime): "
                "ssl_pinning / root_detect / crypto_intercept / "
                "api_monitor script battery or a custom workspace script. "
                "Runs a BOUNDED capture window (default 20s, max 120s) and "
                "returns the intercepted output in one result; the process "
                "group is killed when the window closes. Requires the "
                "operator-hosted frida binary + a device/emulator with the "
                "frida server.")

    def safety_class(self, args: Dict[str, Any]) -> SafetyClass:
        return SafetyClass.EXPLOIT

    def concurrency_safe(self, args: Dict[str, Any]) -> bool:
        return False

    def description(self, args: Dict[str, Any]) -> str:
        return (f"frida:{args.get('hook_type', 'ssl_pinning')}@"
                f"{str(args.get('package_name', ''))[:60]}")

    def validate_input(self, args: Dict[str, Any]) -> Optional[str]:
        hook_type = str(args.get("hook_type", "ssl_pinning"))
        if hook_type == "custom" and not str(
                args.get("script_path", "")).strip():
            return ("hook_type=custom requires script_path (a workspace "
                    "Frida script)")
        return None

    async def call(self, args: Dict[str, Any],
                   ctx: ToolContext) -> ToolResult:
        binary = shutil.which("frida")
        if binary is None:
            return _operator_missing(
                "frida", self.name,
                "(pip install frida-tools; device needs frida-server)")
        package = str(args.get("package_name", ""))
        hook_type = str(args.get("hook_type", "ssl_pinning"))
        spawn = bool(args.get("spawn", True))
        device = str(args.get("device", "usb"))
        duration = min(int(args.get("duration") or DEFAULT_CAPTURE_S),
                       MAX_CAPTURE_S)

        script_path = ""
        if str(args.get("script_path", "")).strip():
            from ...permissions import resolve_safe_path
            script_path = resolve_safe_path(
                str(args.get("script_path")), ctx.workspace) or ""
            if not script_path:
                return ToolResult.error(
                    "script_path resolves outside the engagement "
                    "workspace", label=self.name)
            try:
                with open(script_path, "r", encoding="utf-8") as f:
                    script_content = f.read()
            except OSError as exc:
                return ToolResult.error(
                    f"script read failed: {exc}", label=self.name)
        else:
            script_content = FRIDA_SCRIPTS.get(hook_type,
                                               FRIDA_SCRIPTS["ssl_pinning"])
            written = _scratch_write(ctx, "frida_hook", script_content)
            if written is None:
                return ToolResult.error("scratch write failed",
                                        label=self.name)
            script_path = written

        argv = [binary,
                "-f" if spawn else "-p", package,
                "-l", script_path]
        if device == "emulator":
            argv += ["-H", "127.0.0.1:27042"]
        # NOTE: no --no-pause. The oracle (3.7.3) rode old frida, where
        # a spawned process stayed paused without the flag; current
        # frida-tools (what the engagement image's Kali rolling ships)
        # auto-resume once scripts load and REJECT the flag outright —
        # Test-4's clean container caught the live "unrecognized
        # arguments: --no-pause" refusal. Dropping it is correct for
        # every frida the platform rides; ancient CLIs merely harvest a
        # quieter window (honest degradation, never a fabricated one).
        return await _bounded_capture(
            argv, cwd=ctx.workspace, duration_s=float(duration),
            label=self.name)


# ─── mitm_intercept ─────────────────────────────────────────────────────

class MitmInterceptTool(Tool):
    """Bounded mitmproxy capture window for mobile app traffic."""

    name = "mitm_intercept"
    aliases = ("mitm",)
    input_schema = {
        "type": "object",
        "properties": {
            "port": {"type": "integer", "minimum": 1024, "maximum": 65535,
                     "default": 8082},
            "capture_filter": {"type": "string", "maxLength": 300,
                               "default": ""},
            "target_app": {"type": "string", "maxLength": 200,
                           "default": ""},
            "duration": {"type": "integer", "minimum": 3,
                         "maximum": MAX_CAPTURE_S,
                         "default": DEFAULT_CAPTURE_S},
        },
        "additionalProperties": False,
    }
    timeout_s = float(MAX_CAPTURE_S + 30)

    def prompt(self) -> str:
        return ("Start a bounded mitmproxy capture window (operator-attached "
                "runtime): an intercepting proxy on a local port logging "
                "every request/response line ([REQ]/[REQ-H]/[REQ-B]/[RES]/"
                "[RES-H]/[RES-B]). Returns the window's capture plus the "
                "device proxy + CA-cert configuration steps. Requires the "
                "operator-hosted mitmdump binary; pair with "
                "frida_hook(hook_type='ssl_pinning') when the app pins.")

    def safety_class(self, args: Dict[str, Any]) -> SafetyClass:
        return SafetyClass.EXPLOIT

    def concurrency_safe(self, args: Dict[str, Any]) -> bool:
        return False

    def description(self, args: Dict[str, Any]) -> str:
        return f"mitm:{args.get('port', 8082)}"

    async def call(self, args: Dict[str, Any],
                   ctx: ToolContext) -> ToolResult:
        binary = shutil.which("mitmdump")
        if binary is None:
            return _operator_missing(
                "mitmdump", self.name,
                "(pip install mitmproxy)")
        port = int(args.get("port") or 8082)
        duration = min(int(args.get("duration") or DEFAULT_CAPTURE_S),
                       MAX_CAPTURE_S)
        capture_filter = str(args.get("capture_filter", "") or "")

        addon = _scratch_write(ctx, "mitm_addon", MITM_ADDON_SCRIPT)
        if addon is None:
            return ToolResult.error("scratch write failed",
                                    label=self.name)
        argv = [binary, "-s", addon, "--listen-port", str(port), "-q"]
        if capture_filter:
            argv += ["--set", f"flow_filter={capture_filter}"]

        result = await _bounded_capture(
            argv, cwd=ctx.workspace, duration_s=float(duration),
            label=self.name)

        # the oracle's configuration block rides along (the operator
        # still has to point the device at the proxy + trust the CA)
        host = "127.0.0.1"
        cfg = (
            f"\n--- proxy configuration ---\n"
            f"android: adb shell settings put global http_proxy "
            f"{host}:{port}\n"
            f"ios: Settings > Wi-Fi > Configure Proxy > Manual > "
            f"{host}:{port}\n"
            f"CA certificate: http://mitm.it (from the device)\n"
            f"SSL pinning: pair with frida_hook "
            f"hook_type='ssl_pinning'")
        result.content = (result.content or "") + cfg
        return result


# ─── ssh_interactive_exec ───────────────────────────────────────────────

class SshExecTool(Tool):
    """Execute a command on an in-scope host over SSH (operator-attached
    ssh client; password auth via sshpass when provided, key auth
    otherwise)."""

    name = "ssh_interactive_exec"
    aliases = ("ssh_exec",)
    input_schema = {
        "type": "object",
        "properties": {
            "target_ip": {"type": "string", "minLength": 3,
                          "maxLength": 200},
            "username": {"type": "string", "minLength": 1,
                         "maxLength": 100},
            "command": {"type": "string", "minLength": 1,
                        "maxLength": 8000},
            "password": {"type": "string", "maxLength": 500,
                         "default": ""},
            "use_sudo": {"type": "boolean", "default": False},
            "port": {"type": "integer", "minimum": 1, "maximum": 65535,
                     "default": 22},
            "timeout": {"type": "integer", "minimum": 5,
                        "maximum": SSH_MAX_TIMEOUT_S, "default": 60},
        },
        "required": ["target_ip", "username", "command"],
        "additionalProperties": False,
    }
    timeout_s = float(SSH_MAX_TIMEOUT_S + 60)

    def prompt(self) -> str:
        return ("Run a command on an in-scope target over SSH. The target "
                "is scope-gated (deny-by-default) and the command runs the "
                "PoC-only persistence battery BEFORE execution. Uses the "
                "operator's ssh binary: key auth by default; password auth "
                "requires the operator-hosted sshpass. sudo wraps the "
                "command with password plumbing when requested. Bounded "
                "wall-clock, captured output, capped render.")

    def safety_class(self, args: Dict[str, Any]) -> SafetyClass:
        return SafetyClass.EXPLOIT

    def concurrency_safe(self, args: Dict[str, Any]) -> bool:
        return False

    def is_persistent(self, args: Dict[str, Any]) -> bool:
        return any(re.search(p, str(args.get("command", "")), re.I)
                   for p in PERSISTENCE_PATTERNS)

    def extract_targets(self, args: Dict[str, Any]) -> List[str]:
        # bare-host convention (every P3 tool): the gate's
        # is_authorized() matches CIDR/wildcard rules on the host; the
        # connection port rides the journal's args digest instead
        target = str(args.get("target_ip", "")).strip()
        return [target] if target else []

    def description(self, args: Dict[str, Any]) -> str:
        return (f"ssh:{args.get('username', '')}@"
                f"{str(args.get('target_ip', ''))[:40]}: "
                f"{str(args.get('command', ''))[:60]}")

    def validate_input(self, args: Dict[str, Any]) -> Optional[str]:
        command = str(args.get("command", ""))
        if not command.strip():
            return "empty command"
        if any(re.search(p, command, re.I)
               for p in PERSISTENCE_PATTERNS):
            return ("PoC-only RoE: command matches the persistence "
                    "battery (user creation / cron / authorized_keys / "
                    "webshell / ...) — refused before execution")
        if not str(args.get("username", "")).strip():
            return "username required"
        return None

    async def call(self, args: Dict[str, Any],
                   ctx: ToolContext) -> ToolResult:
        binary = shutil.which("ssh")
        if binary is None:
            return _operator_missing(
                "ssh", self.name, "(an OpenSSH client)")

        target = str(args.get("target_ip", ""))
        username = str(args.get("username", ""))
        command = str(args.get("command", ""))
        password = str(args.get("password", "") or "")
        use_sudo = bool(args.get("use_sudo", False))
        port = int(args.get("port") or 22)
        timeout = min(int(args.get("timeout") or 60),
                      SSH_MAX_TIMEOUT_S)

        # the RoE battery already ran in validate_input (pre-gate);
        # re-assert here so direct callers get the same refusal
        if any(re.search(p, command, re.I)
               for p in PERSISTENCE_PATTERNS):
            return ToolResult.error(
                "PoC-only RoE: persistence battery match — refused",
                label=self.name)

        remote = command
        if use_sudo:
            if password:
                # sudo -S reads the password from stdin; the prompt
                # string is emptied so the stream is exactly one line
                remote = (f"printf '%s\\n' {shlex.quote(password)} | "
                          f"sudo -S -p '' -- {command}")
            else:
                remote = f"sudo -p '' -- {command}"

        argv = [binary,
                "-p", str(port),
                "-o", "ConnectTimeout=15",
                "-o", "StrictHostKeyChecking=accept-new",
                "-o", "ForwardAgent=no",
                "-o", "ClearAllForwardings=yes",
                "-o", "BatchMode=yes" if not password else "BatchMode=no",
                "-o", "NumberOfPasswordPrompts=1",
                f"{username}@{target}",
                "--", remote]

        sshpass_bin = None
        if password:
            sshpass_bin = shutil.which("sshpass")
            if sshpass_bin is None:
                return ToolResult.error(
                    "operator runtime not attached: password auth needs "
                    "`sshpass` on PATH (or use key-based auth with "
                    "password='')", label=self.name)
            argv = [sshpass_bin, "-p", password] + argv
            # sshpass provides the password; keep ssh non-interactive
            for i, a in enumerate(argv):
                if a == "BatchMode=no":
                    argv[i] = "BatchMode=yes"

        try:
            proc = await asyncio.create_subprocess_exec(
                *argv, cwd=ctx.workspace,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.STDOUT,
                preexec_fn=os.setsid)
        except OSError as exc:
            return ToolResult.error(f"spawn failed: {exc}",
                                    label=self.name)
        try:
            out, _ = await asyncio.wait_for(proc.communicate(),
                                            timeout=timeout)
        except asyncio.TimeoutError:
            try:
                os.killpg(os.getpgid(proc.pid), 9)
            except (ProcessLookupError, PermissionError, OSError):
                pass
            return ToolResult.error(
                f"ssh exceeded {timeout}s wall-clock bound "
                f"(process group killed)", exit_code=-9, label=self.name)

        text = (out or b"").decode("utf-8", "replace")
        text = text.replace("\x00", "")
        rc = proc.returncode or 0
        # the password never rides the result even if the remote echoed it
        if password:
            text = text.replace(password, "[redacted-credential]")
        body = (text if text.strip() else f"[no output, exit {rc}]")
        if rc != 0 and text.strip():
            body = f"{text}\n[exit code {rc}]"
        return ToolResult(body, is_error=rc != 0,
                          metadata={"exit_code": rc,
                                    "target": f"{target}:{port}",
                                    "chars": len(text)})


OPERATOR_TOOLS = (FridaHookTool, MitmInterceptTool, SshExecTool)
