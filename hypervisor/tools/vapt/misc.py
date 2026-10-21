"""hypervisor.tools.vapt.misc — local analysis tools (P3, REFACTOR-05).

sequential_thinking (oracle), analyze_entropy (oracle), crypto_analyzer
(oracle, stdlib-truthful subset), list_buffers (oracle) and the mobile
static analyzers analyze_apk / analyze_ipa (oracle mobile_tools.py,
re-hosted as zipfile-based static analysis with the workspace-bound
path resolver closing the traversal class at gate time).

Honest scoping: crypto_analyzer supports the transformations the
stdlib can do correctly (xor, base64, hex, rot13/rot47, reverse) and
REFUSES AES/DES/3DES/RC4 with a clear message (no crypto library in
the stdlib-only dependency contract — an operator-side attachment can
add them later); frida/mitm runtime hooks need devices and daemons and
stay P4 (documented in the port card).
"""
from __future__ import annotations

import base64
import binascii
import codecs
import hashlib
import json
import math
import os
import re
import string
import zipfile
from typing import Any, Dict, List, Optional, Tuple

from ...permissions import SafetyClass, resolve_safe_path
from ..base import Tool, ToolContext, ToolResult


# ─── sequential_thinking (oracle system_tools_v2) ─────────────────────

class SequentialThinkingTool(Tool):
    name = "sequential_thinking"
    input_schema = {
        "type": "object",
        "properties": {
            "thought": {"type": "string", "minLength": 1,
                        "maxLength": 32000},
            "next_thought_needed": {"type": "boolean"},
            "thought_number": {"type": "integer", "minimum": 1},
            "total_thoughts": {"type": "integer", "minimum": 1},
        },
        "required": ["thought", "next_thought_needed",
                     "thought_number", "total_thoughts"],
        "additionalProperties": False,
    }
    timeout_s = 10.0

    def prompt(self) -> str:
        return ("A structured scratchpad for chain-of-thought "
                "reasoning: record one numbered thought at a time, "
                "flag whether the next step needs more thinking. "
                "Pure bookkeeping — no state beyond your transcript.")

    def safety_class(self, args: Dict[str, Any]) -> SafetyClass:
        return SafetyClass.READ

    def concurrency_safe(self, args: Dict[str, Any]) -> bool:
        return True

    async def call(self, args: Dict[str, Any],
                   ctx: ToolContext) -> ToolResult:
        n = int(args.get("thought_number", 0))
        total = int(args.get("total_thoughts", 0))
        need = bool(args.get("next_thought_needed"))
        done = not need or n >= total
        return ToolResult(
            json.dumps({"thought_number": n, "total_thoughts": total,
                        "next_thought_needed": need,
                        "status": ("complete" if done
                                   else "continue")},
                       indent=2))


# ─── analyze_entropy (oracle) ─────────────────────────────────────────

def _shannon_entropy(data: str) -> float:
    if not data:
        return 0.0
    freq: Dict[str, int] = {}
    for ch in data:
        freq[ch] = freq.get(ch, 0) + 1
    n = len(data)
    return -sum((c / n) * math.log2(c / n) for c in freq.values())


class EntropyTool(Tool):
    name = "analyze_entropy"
    input_schema = {
        "type": "object",
        "properties": {
            "data_string": {"type": "string", "minLength": 4,
                            "maxLength": 500000},
        },
        "required": ["data_string"],
        "additionalProperties": False,
    }
    timeout_s = 15.0

    def prompt(self) -> str:
        return ("Analyze a string's Shannon entropy and character "
                "composition: useful to distinguish keys, tokens, "
                "ciphertexts and encoded data from natural language. "
                "Returns bits/char, char-class breakdown and base64/hex "
                "plausibility with decoded previews.")

    def safety_class(self, args: Dict[str, Any]) -> SafetyClass:
        return SafetyClass.READ

    def concurrency_safe(self, args: Dict[str, Any]) -> bool:
        return True

    async def call(self, args: Dict[str, Any],
                   ctx: ToolContext) -> ToolResult:
        data = str(args.get("data_string", ""))
        ent = _shannon_entropy(data)
        classes = {
            "lower": sum(c.islower() for c in data),
            "upper": sum(c.isupper() for c in data),
            "digits": sum(c.isdigit() for c in data),
            "symbols": sum(not c.isalnum() for c in data),
        }
        b64ish = all(c in (string.ascii_letters + string.digits
                           + "+/=") for c in data)
        hexish = all(c in string.hexdigits for c in data)
        decoded = ""
        if b64ish and len(data) % 4 == 0:
            try:
                raw = base64.b64decode(data, validate=True)
                if raw and all(32 <= b < 127 or b in (9, 10, 13)
                               for b in raw[:512]):
                    decoded = raw[:512].decode("utf-8", "replace")
            except (binascii.Error, ValueError):
                pass
        return ToolResult(json.dumps({
            "chars": len(data),
            "shannon_entropy_bits_per_char": round(ent, 4),
            "max_possible": round(math.log2(len(set(data)) or 1), 4)
            if len(set(data)) > 1 else 0.0,
            "char_classes": classes,
            "looks_base64": b64ish,
            "looks_hex": hexish and len(data) % 2 == 0,
            "base64_preview": decoded[:200],
            "assessment": (
                "very high (random/key-like)" if ent > 4.5 else
                "high (encoded/compressed)" if ent > 3.5 else
                "moderate" if ent > 2.5 else
                "low (natural language-ish)"),
        }, indent=2), metadata={"entropy": round(ent, 4)})


# ─── crypto_analyzer (oracle, stdlib-truthful subset) ─────────────────

class CryptoTool(Tool):
    name = "crypto_analyzer"
    input_schema = {
        "type": "object",
        "properties": {
            "ciphertext": {"type": "string", "minLength": 1,
                           "maxLength": 200000},
            "key_string": {"type": "string", "maxLength": 4096,
                           "default": ""},
            "algorithm": {"type": "string",
                          "enum": ["xor", "base64", "hex", "rot13",
                                   "rot47", "reverse"],
                          "default": "xor"},
        },
        "required": ["ciphertext"],
        "additionalProperties": False,
    }
    timeout_s = 15.0

    def prompt(self) -> str:
        return ("Symmetric crypto helper for CTF-style VAPT work: xor "
                "(repeating key), base64, hex, rot13, rot47, reverse. "
                "Block ciphers (AES/DES/3DES/RC4) are NOT supported — "
                "the stdlib-only harness has no crypto library; ask "
                "the operator for the crypto attachment.")

    def safety_class(self, args: Dict[str, Any]) -> SafetyClass:
        return SafetyClass.READ

    def concurrency_safe(self, args: Dict[str, Any]) -> bool:
        return True

    async def call(self, args: Dict[str, Any],
                   ctx: ToolContext) -> ToolResult:
        ct = str(args.get("ciphertext", ""))
        key = str(args.get("key_string", "") or "")
        algo = str(args.get("algorithm", "xor"))
        try:
            if algo == "xor":
                if not key:
                    return ToolResult.error(
                        "xor needs key_string (the repeating key)")
                out = "".join(
                    chr(ord(a) ^ ord(b)) for a, b in
                    zip(ct, (key * (len(ct) // len(key) + 1))))
                printable = sum(c.isprintable() or c in "\n\r\t"
                                for c in out) / max(len(out), 1)
                return ToolResult(json.dumps({
                    "algorithm": "xor", "key": key[:60],
                    "result": out[:4000], "printable_ratio":
                        round(printable, 3),
                    "assessment": ("likely correct" if printable > 0.85
                                   else "likely wrong key")},
                    indent=2))
            if algo == "base64":
                raw = base64.b64decode(ct, validate=False)
                return ToolResult(json.dumps({
                    "algorithm": "base64", "bytes": len(raw),
                    "hex": raw.hex()[:4000],
                    "text_preview": raw[:1000].decode(
                        "utf-8", "replace")}, indent=2))
            if algo == "hex":
                raw = binascii.unhexlify(
                    "".join(c for c in ct if c in string.hexdigits))
                return ToolResult(json.dumps({
                    "algorithm": "hex", "bytes": len(raw),
                    "text_preview": raw[:1000].decode(
                        "utf-8", "replace")}, indent=2))
            if algo == "rot13":
                return ToolResult(json.dumps({
                    "algorithm": "rot13",
                    "result": codecs.encode(ct, "rot13")[:4000]},
                    indent=2))
            if algo == "rot47":
                out = "".join(
                    chr(33 + ((ord(c) - 33 + 47) % 94)) if 33 <= ord(c)
                    <= 126 else c for c in ct)
                return ToolResult(json.dumps({
                    "algorithm": "rot47", "result": out[:4000]},
                    indent=2))
            if algo == "reverse":
                return ToolResult(json.dumps({
                    "algorithm": "reverse", "result": ct[::-1][:4000]},
                    indent=2))
            return ToolResult.error(f"unsupported algorithm {algo!r}")
        except (binascii.Error, ValueError) as exc:
            return ToolResult.error(f"decode failed: {exc}")


# ─── list_buffers (oracle) ────────────────────────────────────────────

class ListBuffersTool(Tool):
    name = "list_buffers"
    input_schema = {"type": "object",
                    "properties": {}, "additionalProperties": False}
    timeout_s = 10.0

    def prompt(self) -> str:
        return ("List the oversized-output buffer files the tools have "
                "paginated under workspace/buffers/ (the manifest the "
                "caps write): buffer ids, tools, labels, sizes, times. "
                "Read a buffer back with read_file.")

    def safety_class(self, args: Dict[str, Any]) -> SafetyClass:
        return SafetyClass.READ

    def concurrency_safe(self, args: Dict[str, Any]) -> bool:
        return True

    async def call(self, args: Dict[str, Any],
                   ctx: ToolContext) -> ToolResult:
        manifest_path = os.path.join(ctx.workspace, "buffers",
                                     "manifest.json")
        rows: List[Dict[str, Any]] = []
        if os.path.exists(manifest_path):
            try:
                with open(manifest_path, "r", encoding="utf-8") as f:
                    rows = json.load(f)
            except (OSError, json.JSONDecodeError):
                rows = []
        if not rows:
            return ToolResult("No buffered outputs recorded.")
        return ToolResult(
            json.dumps({"buffers": rows[-200:], "count": len(rows)},
                       indent=2), metadata={"count": len(rows)})


# ─── mobile static analysis (oracle mobile_tools, zipfile-based) ──────

_APK_PERMISSION_RE = re.compile(
    r"android\.permission\.([A-Z_]+)")
_URL_RE = re.compile(r"https?://[a-zA-Z0-9._/-]{4,120}")


def _binary_strings(blob: bytes, min_len: int = 5,
                    cap: int = 20000) -> List[str]:
    """Extract printable ASCII strings from a binary blob (the
    strings(1) equivalent, bounded)."""
    out: List[str] = []
    cur = bytearray()
    for b in blob[:4_000_000]:
        if 32 <= b < 127:
            cur.append(b)
            if len(cur) > 8192:
                cur = cur[:8192]
        else:
            if len(cur) >= min_len:
                out.append(cur.decode("ascii", "replace"))
                if len(out) >= cap:
                    break
            cur = bytearray()
    if len(cur) >= min_len and len(out) < cap:
        out.append(cur.decode("ascii", "replace"))
    return out


def _analyze_zip_app(path: str, *, is_ipa: bool
                     ) -> Dict[str, Any]:
    """Static analysis of a packaged mobile app (APK/IPA) through the
    zip container: inventory, manifest strings, permissions/bundle
    flags, embedded URLs, passive-scanner alerts. Pure stdlib; deep
    disassembly (apktool/aapt class dumps, frida traces) is the
    operator-side attachment."""
    from .recon import PassiveScanner
    sha = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            sha.update(chunk)
    report: Dict[str, Any] = {
        "file": os.path.basename(path),
        "size_bytes": os.path.getsize(path),
        "sha256": sha.hexdigest(),
        "package_type": "ipa" if is_ipa else "apk",
    }
    with zipfile.ZipFile(path) as zf:
        names = zf.namelist()
        report["entries"] = len(names)
        exts: Dict[str, int] = {}
        for n in names:
            ext = os.path.splitext(n)[1].lower() or "(none)"
            exts[ext] = exts.get(ext, 0) + 1
        report["entry_types"] = dict(sorted(exts.items(),
                                            key=lambda kv: -kv[1])[:15])
        # the manifest / plist blob (binary XML strings carry the
        # load-bearing facts: permissions, ids, flags)
        candidates = (["Info.plist"] if is_ipa else
                      ["AndroidManifest.xml",
                       "res/AndroidManifest.xml", "manifest/AndroidManifest.xml"])
        manifest_blob = b""
        for cand in candidates:
            try:
                manifest_blob = zf.read(cand)
                report["manifest_entry"] = cand
                break
            except (KeyError, zipfile.BadZipFile):
                continue
        text = manifest_blob.decode("utf-8", "replace")
        if is_ipa:
            report["bundle_id"] = (re.search(
                r"CFBundleIdentifier</key>\s*<string>([^<]+)",
                text) or [None, ""])[1] if "CFBundleIdentifier" in text \
                else _binary_strings(manifest_blob, 8, 2000)
            report["ats_flags"] = sorted(set(
                re.findall(r"NS[A-Za-z]*Allows[A-Za-z]*", text)))
        else:
            report["package"] = (re.search(
                r"com\.[a-zA-Z0-9._]{3,80}", text).group(0)
                if re.search(r"com\.[a-zA-Z0-9._]{3,80}", text) else "")
            perms = sorted(set(_APK_PERMISSION_RE.findall(
                text))) or sorted(set(_APK_PERMISSION_RE.findall(
                    " ".join(_binary_strings(manifest_blob, 8, 5000)))))
            report["permissions"] = perms
        # embedded URLs + secrets across the whole archive (bounded)
        urls: set = set()
        secrets_hits: List[str] = []
        scanned = 0
        for n in names:
            if scanned >= 40:
                break
            ext = os.path.splitext(n)[1].lower()
            if ext in (".so", ".dex", ".xml", ".plist", ".json",
                       ".properties", ".txt", ".js", ".html", ""):
                try:
                    blob = zf.read(n)[:2_000_000]
                except (KeyError, zipfile.BadZipFile,
                        NotImplementedError):
                    continue
                scanned += 1
                s = blob.decode("utf-8", "replace")
                urls.update(_URL_RE.findall(s))
                secrets_hits.extend(PassiveScanner.scan_text(
                    s[:100_000]))
        report["embedded_urls"] = sorted(urls)[:60]
        report["security_alerts"] = sorted(set(secrets_hits))[:40]
    return report


class AnalyzeApkTool(Tool):
    name = "analyze_apk"
    input_schema = {
        "type": "object",
        "properties": {
            "apk_path": {"type": "string", "minLength": 4,
                         "maxLength": 400,
                         "description": "Workspace-relative path to "
                                        "the APK."},
            "analysis_type": {"type": "string",
                              "enum": ["full", "manifest", "secrets"],
                              "default": "full"},
        },
        "required": ["apk_path"],
        "additionalProperties": False,
    }
    timeout_s = 120.0
    path_args = ("apk_path",)

    def prompt(self) -> str:
        return ("Static analysis of an Android APK in the workspace: "
                "inventory, package id, permission list, embedded URLs, "
                "secret-pattern alerts. The path is workspace-resolved "
                "(traversal is refused). Deep disassembly requires the "
                "operator's apktool/aapt attachment.")

    def safety_class(self, args: Dict[str, Any]) -> SafetyClass:
        return SafetyClass.READ

    def concurrency_safe(self, args: Dict[str, Any]) -> bool:
        return True

    async def call(self, args: Dict[str, Any],
                   ctx: ToolContext) -> ToolResult:
        resolved = resolve_safe_path(str(args.get("apk_path", "")),
                                     ctx.workspace)
        if resolved is None:
            return ToolResult.error(
                "path escapes the engagement workspace")
        try:
            report = _analyze_zip_app(resolved, is_ipa=False)
        except zipfile.BadZipFile:
            return ToolResult.error("not a valid zip/APK container")
        except OSError as exc:
            return ToolResult.error(f"unreadable: {exc}")
        kind = str(args.get("analysis_type", "full"))
        if kind == "manifest":
            report = {k: report.get(k) for k in
                      ("file", "sha256", "package", "permissions",
                       "entries")}
        elif kind == "secrets":
            report = {k: report.get(k) for k in
                      ("file", "sha256", "security_alerts",
                       "embedded_urls")}
        return ToolResult(json.dumps(report, indent=2),
                          metadata={"entries": report.get("entries", 0)})


class AnalyzeIpaTool(Tool):
    name = "analyze_ipa"
    input_schema = {
        "type": "object",
        "properties": {
            "ipa_path": {"type": "string", "minLength": 4,
                         "maxLength": 400,
                         "description": "Workspace-relative path to "
                                        "the IPA."},
            "analysis_type": {"type": "string",
                              "enum": ["full", "manifest", "secrets"],
                              "default": "full"},
        },
        "required": ["ipa_path"],
        "additionalProperties": False,
    }
    timeout_s = 120.0
    path_args = ("ipa_path",)

    def prompt(self) -> str:
        return ("Static analysis of an iOS IPA in the workspace: "
                "inventory, bundle id, ATS flags, embedded URLs, "
                "secret-pattern alerts. Workspace-resolved path; "
                "class-dump analysis requires the operator attachment.")

    def safety_class(self, args: Dict[str, Any]) -> SafetyClass:
        return SafetyClass.READ

    def concurrency_safe(self, args: Dict[str, Any]) -> bool:
        return True

    async def call(self, args: Dict[str, Any],
                   ctx: ToolContext) -> ToolResult:
        resolved = resolve_safe_path(str(args.get("ipa_path", "")),
                                     ctx.workspace)
        if resolved is None:
            return ToolResult.error(
                "path escapes the engagement workspace")
        try:
            report = _analyze_zip_app(resolved, is_ipa=True)
        except zipfile.BadZipFile:
            return ToolResult.error("not a valid zip/IPA container")
        except OSError as exc:
            return ToolResult.error(f"unreadable: {exc}")
        kind = str(args.get("analysis_type", "full"))
        if kind == "manifest":
            report = {k: report.get(k) for k in
                      ("file", "sha256", "bundle_id", "ats_flags",
                       "entries")}
        elif kind == "secrets":
            report = {k: report.get(k) for k in
                      ("file", "sha256", "security_alerts",
                       "embedded_urls")}
        return ToolResult(json.dumps(report, indent=2),
                          metadata={"entries": report.get("entries", 0)})
