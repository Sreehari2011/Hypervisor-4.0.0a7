"""hypervisor.tools.vapt.web — web interaction tools (P3, REFACTOR-05).

The oracle's web_tools_v2.py re-hosted on the tool plane. Names pinned
by the Tier-A extractor routing: advanced_http_request /
retrieve_url_content / detect_waf / headless_dom_navigate /
headless_dom_interact / web_search_osint / map_vhost.

Honest scoping notes (documented in the prompts, not hidden):
  * headless_dom_* are STATIC-DOM approximations (fetch + link/form
    extraction + the passive scanner) — a JS-rendering engine is an
    operator-side P4 attachment, and the prompts say so;
  * web_search_osint requires AEGIS_OSINT_ENDPOINT (an operator-owned
    search proxy); without it the tool returns a clear unavailable
    result instead of silently inventing results.
"""
from __future__ import annotations

import asyncio
import json
import re
import socket
import urllib.error
import urllib.parse
import urllib.request
from typing import Any, Dict, List, Optional, Tuple

from ...permissions import SafetyClass
from ..base import Tool, ToolContext, ToolResult
from .recon import PassiveScanner

DEFAULT_TIMEOUT_S = 30.0
MAX_REDIRECTS = 5


def _url_host(url: str) -> str:
    try:
        return urllib.parse.urlsplit(url).hostname or ""
    except ValueError:
        return ""


def _proxy_handler() -> urllib.request.OpenerDirector:
    """A redirect-bounded opener honoring the operator's SOCKS proxy
    env (same env the shell tools see)."""
    handlers: List[urllib.request.BaseHandler] = []
    import os
    proxy_line = None
    for var in ("HTTPS_PROXY", "https_proxy", "HTTP_PROXY",
                "http_proxy", "ALL_PROXY", "all_proxy"):
        val = os.environ.get(var)
        if val:
            proxy_line = val
            break
    if proxy_line:
        proxies = {"http": proxy_line, "https": proxy_line}
        handlers.append(urllib.request.ProxyHandler(proxies))
    else:
        handlers.append(urllib.request.ProxyHandler({}))
    return urllib.request.build_opener(*handlers)


async def _http_call(url: str, method: str = "GET",
                     data: Optional[bytes] = None,
                     headers: Optional[Dict[str, str]] = None,
                     timeout: float = DEFAULT_TIMEOUT_S,
                     allow_redirects: bool = True
                     ) -> Tuple[int, Dict[str, str], bytes, List[str]]:
    """One bounded HTTP call on a worker thread (urllib is blocking).
    Returns (status, headers, body, redirects_followed)."""
    def _run() -> Tuple[int, Dict[str, str], bytes, List[str]]:
        req = urllib.request.Request(url, data=data, method=method)
        for k, v in (headers or {}).items():
            req.add_header(k, v)
        opener = _proxy_handler()
        chain: List[str] = []
        current = url
        for _ in range(MAX_REDIRECTS + 1):
            try:
                resp = opener.open(
                    urllib.request.Request(current, data=data,
                                           method=method,
                                           headers=dict(req.headers)),
                    timeout=timeout)
            except urllib.error.HTTPError as exc:
                return exc.code, dict(exc.headers or {}), \
                    exc.read(2_000_000) or b"", chain
            if resp.status in (301, 302, 303, 307, 308) and \
                    allow_redirects and resp.headers.get("Location"):
                chain.append(resp.headers["Location"])
                current = urllib.parse.urljoin(current,
                                               resp.headers["Location"])
                continue
            return resp.status, dict(resp.headers or {}), \
                resp.read(2_000_000) or b"", chain
        return 0, {}, b"", chain        # redirect budget exhausted

    return await asyncio.to_thread(_run)


def _render_response(status: int, headers: Dict[str, str], body: bytes,
                     url: str, redirects: List[str]) -> str:
    text = body.decode("utf-8", "replace")
    header_lines = "\n".join(f"{k}: {v}" for k, v in sorted(
        headers.items()))
    head = text[:4000]
    note = (f"\n[body {len(text)} chars total — first 4000 shown]"
            if len(text) > 4000 else "")
    redir = (f"\nredirects: {' -> '.join(redirects)}" if redirects
             else "")
    return (f"HTTP {status} {url}\n{header_lines}\n\n{head}{note}{redir}")


# ─── advanced_http_request (oracle name; the primary web surface) ─────

class HttpRequestTool(Tool):
    name = "advanced_http_request"
    aliases = ("http_request",)
    input_schema = {
        "type": "object",
        "properties": {
            "method": {"type": "string",
                       "enum": ["GET", "POST", "PUT", "PATCH", "DELETE",
                                "HEAD", "OPTIONS"],
                       "default": "GET"},
            "url": {"type": "string", "minLength": 8, "maxLength": 2000},
            "data": {"type": "string", "maxLength": 100000,
                     "description": "Request body (raw)."},
            "headers": {"type": "string", "maxLength": 8000,
                        "description": "JSON object of headers."},
            "cookies": {"type": "string", "maxLength": 4000,
                        "description": "Cookie header value."},
            "allow_redirects": {"type": "boolean", "default": True},
            "timeout_s": {"type": "integer", "minimum": 1,
                          "maximum": 120, "default": 30},
        },
        "required": ["url"],
        "additionalProperties": False,
    }
    timeout_s = 150.0

    def prompt(self) -> str:
        return ("Send an HTTP request to an in-scope URL with full "
                "control over method, headers, cookies and body. "
                "Returns status, response headers, and the body (first "
                "4000 chars; oversized bodies paginate to a buffer). "
                "Redirects are followed up to 5 times and reported.")

    def safety_class(self, args: Dict[str, Any]) -> SafetyClass:
        # GET/HEAD/OPTIONS are reconnaissance reads; state-changing
        # methods are exploit-class actions on the estate.
        m = str(args.get("method", "GET")).upper()
        return (SafetyClass.READ if m in ("GET", "HEAD", "OPTIONS")
                else SafetyClass.EXPLOIT)

    def concurrency_safe(self, args: Dict[str, Any]) -> bool:
        return True

    def extract_targets(self, args: Dict[str, Any]) -> List[str]:
        host = _url_host(str(args.get("url", "")))
        return [host] if host else []

    def validate_input(self, args: Dict[str, Any]) -> Optional[str]:
        url = str(args.get("url", ""))
        if not url.startswith(("http://", "https://")):
            return "url must be http(s)"
        if args.get("headers"):
            try:
                json.loads(str(args["headers"]))
            except json.JSONDecodeError as exc:
                return f"headers must be a JSON object: {exc}"
        return None

    def description(self, args: Dict[str, Any]) -> str:
        return (f"{args.get('method', 'GET')} {args.get('url', '')}"
                )[:120]

    async def call(self, args: Dict[str, Any],
                   ctx: ToolContext) -> ToolResult:
        url = str(args.get("url", ""))
        method = str(args.get("method", "GET")).upper()
        timeout = min(float(args.get("timeout_s") or 30), 120)
        headers: Dict[str, str] = {
            "User-Agent": "AEGIS-Hypervisor/4.0 (VAPT; scoped)"}
        if args.get("headers"):
            try:
                headers.update(json.loads(str(args["headers"])))
            except json.JSONDecodeError:
                pass
        if args.get("cookies"):
            headers["Cookie"] = str(args["cookies"])
        data = (str(args["data"]).encode("utf-8")
                if args.get("data") is not None else None)
        if data is not None and "Content-Type" not in {
                k.title() for k in headers}:
            headers.setdefault("Content-Type", "application/octet-stream")
        try:
            status, rheaders, body, redirs = await _http_call(
                url, method=method, data=data, headers=headers,
                timeout=timeout,
                allow_redirects=bool(args.get("allow_redirects", True)))
        except (urllib.error.URLError, socket.timeout, OSError,
                ValueError) as exc:
            return ToolResult.error(f"request failed: {exc}",
                                    url=url)
        alerts = PassiveScanner.scan_headers(rheaders) + \
            PassiveScanner.scan_text(body.decode("utf-8", "replace")
                                     [:100_000])
        content = _render_response(status, rheaders, body, url, redirs)
        if alerts:
            content += ("\n\npassive scanner alerts:\n"
                        + "\n".join(alerts[:40]))
        return ToolResult(content, metadata={
            "status": status, "url": url, "method": method,
            "body_chars": len(body), "alerts": len(alerts)})


# ─── retrieve_url_content (oracle name; the simple fetch) ─────────────

class FetchUrlTool(Tool):
    name = "retrieve_url_content"
    aliases = ("fetch_url",)
    input_schema = {
        "type": "object",
        "properties": {
            "url": {"type": "string", "minLength": 8, "maxLength": 2000},
            "max_chars": {"type": "integer", "minimum": 200,
                          "maximum": 100000, "default": 8000},
        },
        "required": ["url"],
        "additionalProperties": False,
    }
    timeout_s = 60.0

    def prompt(self) -> str:
        return ("Fetch an in-scope URL and return its body text "
                "(capped; oversized bodies paginate to a buffer). A "
                "simple read surface for content review — use "
                "advanced_http_request when you need header/method "
                "control.")

    def safety_class(self, args: Dict[str, Any]) -> SafetyClass:
        return SafetyClass.READ

    def concurrency_safe(self, args: Dict[str, Any]) -> bool:
        return True

    def extract_targets(self, args: Dict[str, Any]) -> List[str]:
        host = _url_host(str(args.get("url", "")))
        return [host] if host else []

    def validate_input(self, args: Dict[str, Any]) -> Optional[str]:
        if not str(args.get("url", "")).startswith(("http://",
                                                    "https://")):
            return "url must be http(s)"
        return None

    def description(self, args: Dict[str, Any]) -> str:
        return f"GET {args.get('url', '')}"[:120]

    async def call(self, args: Dict[str, Any],
                   ctx: ToolContext) -> ToolResult:
        url = str(args.get("url", ""))
        try:
            status, rheaders, body, _ = await _http_call(url)
        except (urllib.error.URLError, socket.timeout, OSError,
                ValueError) as exc:
            return ToolResult.error(f"fetch failed: {exc}", url=url)
        text = body.decode("utf-8", "replace")
        cap = int(args.get("max_chars") or 8000)
        content = text[:cap] + (
            f"\n[body {len(text)} chars — first {cap} shown]"
            if len(text) > cap else "")
        return ToolResult(content,
                          metadata={"status": status, "chars": len(text)})


# ─── detect_waf (oracle) ──────────────────────────────────────────────

_WAF_SIGNS = [
    (r"cloudflare|cf-ray|__cfduid", "Cloudflare"),
    (r"akamai|x-akamai", "Akamai"),
    (r"x-sucuri-id|sucuri", "Sucuri"),
    (r"x-cached-response|x-awselb|awselb", "AWS ELB / CloudFront"),
    (r"x-iinfo|imperva|incapsula|visid_incap", "Imperva / Incapsula"),
    (r"fortinet|fortiweb", "FortiWeb"),
    (r"x-f5-cookie|f5|bigipserver", "F5 BIG-IP"),
    (r"x-denied-by|x-waf", "Generic WAF"),
]


class DetectWafTool(Tool):
    name = "detect_waf"
    input_schema = {
        "type": "object",
        "properties": {
            "url": {"type": "string", "minLength": 8, "maxLength": 2000},
        },
        "required": ["url"],
        "additionalProperties": False,
    }
    timeout_s = 45.0

    def prompt(self) -> str:
        return ("Probe an in-scope URL for web application firewall "
                "signatures (response headers + server banner + cookie "
                "names). Returns the detected WAF or none.")

    def safety_class(self, args: Dict[str, Any]) -> SafetyClass:
        return SafetyClass.READ

    def concurrency_safe(self, args: Dict[str, Any]) -> bool:
        return True

    def extract_targets(self, args: Dict[str, Any]) -> List[str]:
        host = _url_host(str(args.get("url", "")))
        return [host] if host else []

    async def call(self, args: Dict[str, Any],
                   ctx: ToolContext) -> ToolResult:
        url = str(args.get("url", ""))
        try:
            status, rheaders, body, _ = await _http_call(url)
        except (urllib.error.URLError, socket.timeout, OSError,
                ValueError) as exc:
            return ToolResult.error(f"probe failed: {exc}", url=url)
        hay = json.dumps(rheaders).lower()
        set_cookie = str(rheaders.get("Set-Cookie", "")
                         or rheaders.get("set-cookie", "")).lower()
        hay += " " + set_cookie
        detected = [name for pat, name in _WAF_SIGNS
                    if re.search(pat, hay)]
        return ToolResult(
            json.dumps({"url": url, "status": status,
                        "waf_detected": bool(detected),
                        "waf": detected[0] if detected else None,
                        "server": rheaders.get("Server", "")},
                       indent=2),
            metadata={"waf": detected[0] if detected else ""})


# ─── headless_dom_* (static-DOM approximations) ───────────────────────

def _extract_links(base: str, html: str) -> List[str]:
    out: List[str] = []
    for m in re.finditer(
            r'href=["\']([^"\']+)["\']|src=["\']([^"\']+)["\']',
            html):
        raw = m.group(1) or m.group(2) or ""
        if not raw or raw.startswith(("javascript:", "data:", "#")):
            continue
        out.append(urllib.parse.urljoin(base, raw))
    return out[:100]


def _extract_forms(html: str) -> List[Dict[str, str]]:
    forms: List[Dict[str, str]] = []
    for fm in re.finditer(r"<form\b([^>]*)>(.*?)</form>",
                          html, re.I | re.S):
        attrs, inner = fm.group(1), fm.group(2)
        am = re.search(r'action=["\']([^"\']*)["\']', attrs)
        mm = re.search(r'method=["\']([^"\']*)["\']', attrs)
        fields = re.findall(
            r'<input\b[^>]*name=["\']([^"\']+)["\'][^>]*>', inner)
        forms.append({
            "action": am.group(1) if am else "",
            "method": (mm.group(1) if mm else "GET").upper(),
            "fields": fields[:20]})
        if len(forms) >= 20:
            break
    return forms


class HeadlessDomNavigateTool(Tool):
    name = "headless_dom_navigate"
    input_schema = {
        "type": "object",
        "properties": {
            "url": {"type": "string", "minLength": 8, "maxLength": 2000},
        },
        "required": ["url"],
        "additionalProperties": False,
    }
    timeout_s = 60.0

    def prompt(self) -> str:
        return ("Navigate to an in-scope URL and return a static-DOM "
                "summary as JSON: title, links, forms (action/method/"
                "fields) and passive-scanner alerts. NOTE: this is a "
                "static fetch — JavaScript rendering requires the "
                "operator's renderer attachment; scripts do not run.")

    def safety_class(self, args: Dict[str, Any]) -> SafetyClass:
        return SafetyClass.READ

    def concurrency_safe(self, args: Dict[str, Any]) -> bool:
        return True

    def extract_targets(self, args: Dict[str, Any]) -> List[str]:
        host = _url_host(str(args.get("url", "")))
        return [host] if host else []

    async def call(self, args: Dict[str, Any],
                   ctx: ToolContext) -> ToolResult:
        url = str(args.get("url", ""))
        try:
            status, rheaders, body, _ = await _http_call(url)
        except (urllib.error.URLError, socket.timeout, OSError,
                ValueError) as exc:
            return ToolResult.error(f"navigation failed: {exc}", url=url)
        html = body.decode("utf-8", "replace")
        tm = re.search(r"<title[^>]*>(.*?)</title>", html,
                       re.I | re.S)
        payload = {
            "url": url, "status": status,
            "title": (tm.group(1).strip()[:200] if tm else ""),
            "links": _extract_links(url, html),
            "forms": _extract_forms(html),
            "passive_alerts": PassiveScanner.scan_text(html[:200_000]),
        }
        return ToolResult(json.dumps(payload, indent=2),
                          metadata={"status": status,
                                    "links": len(payload["links"])})


class HeadlessDomInteractTool(Tool):
    name = "headless_dom_interact"
    input_schema = {
        "type": "object",
        "properties": {
            "url": {"type": "string", "minLength": 8, "maxLength": 2000},
            "action": {"type": "string", "enum": ["click", "fill",
                                                  "submit"]},
            "selector": {"type": "string", "minLength": 1,
                         "maxLength": 500,
                         "description": "CSS-ish selector or form field "
                                        "name the static engine "
                                        "understands."},
            "value": {"type": "string", "maxLength": 8000,
                      "default": ""},
        },
        "required": ["url", "action", "selector"],
        "additionalProperties": False,
    }
    timeout_s = 60.0

    def prompt(self) -> str:
        return ("Interact with a form on an in-scope page (static-DOM "
                "engine): fill a field or submit the form that contains "
                "the named selector. Submission performs the form's "
                "method against its action with the filled values. "
                "JavaScript event handlers do not run.")

    def safety_class(self, args: Dict[str, Any]) -> SafetyClass:
        # submit/fill may change remote state -> exploit class unless
        # the action is a plain GET
        return (SafetyClass.READ
                if str(args.get("action", "")) == "click"
                else SafetyClass.EXPLOIT)

    def extract_targets(self, args: Dict[str, Any]) -> List[str]:
        host = _url_host(str(args.get("url", "")))
        return [host] if host else []

    async def call(self, args: Dict[str, Any],
                   ctx: ToolContext) -> ToolResult:
        url = str(args.get("url", ""))
        action = str(args.get("action", ""))
        selector = str(args.get("selector", ""))
        value = str(args.get("value", "") or "")
        try:
            status, rheaders, body, _ = await _http_call(url)
        except (urllib.error.URLError, socket.timeout, OSError,
                ValueError) as exc:
            return ToolResult.error(f"page fetch failed: {exc}", url=url)
        html = body.decode("utf-8", "replace")
        forms = _extract_forms(html)
        target_form = None
        for f in forms:
            if selector in f["fields"] or selector in f["action"]:
                target_form = f
                break
        if target_form is None:
            return ToolResult.error(
                f"no form containing selector {selector!r} on {url}")
        if action in ("fill", "click"):
            return ToolResult(
                json.dumps({"action": action, "selector": selector,
                            "form": target_form, "filled": value[:200]},
                           indent=2))
        # submit
        fields = dict.fromkeys(target_form["fields"], "")
        fields[selector] = value
        form_url = urllib.parse.urljoin(url, target_form["action"] or url)
        if target_form["method"] == "GET":
            sep = "&" if "?" in form_url else "?"
            submit_url = (form_url + sep +
                          urllib.parse.urlencode(fields))
            try:
                s2, h2, b2, r2 = await _http_call(submit_url)
            except (urllib.error.URLError, socket.timeout, OSError,
                    ValueError) as exc:
                return ToolResult.error(f"submit failed: {exc}")
            return ToolResult(_render_response(s2, h2, b2, submit_url, r2),
                              metadata={"status": s2})
        data = urllib.parse.urlencode(fields).encode()
        headers = {"Content-Type": "application/x-www-form-urlencoded"}
        try:
            s2, h2, b2, r2 = await _http_call(form_url, method="POST",
                                              data=data,
                                              headers=headers)
        except (urllib.error.URLError, socket.timeout, OSError,
                ValueError) as exc:
            return ToolResult.error(f"submit failed: {exc}")
        return ToolResult(_render_response(s2, h2, b2, form_url, r2),
                          metadata={"status": s2})


# ─── web_search_osint (operator-provided search proxy) ────────────────

class WebSearchOsintTool(Tool):
    name = "web_search_osint"
    input_schema = {
        "type": "object",
        "properties": {
            "query": {"type": "string", "minLength": 2, "maxLength": 400},
        },
        "required": ["query"],
        "additionalProperties": False,
    }
    timeout_s = 45.0

    def prompt(self) -> str:
        return ("OSINT web search through the operator-provided search "
                "endpoint (AEGIS_OSINT_ENDPOINT). Without an endpoint "
                "configured this tool reports unavailable — AEGIS does "
                "not invent search results.")

    def safety_class(self, args: Dict[str, Any]) -> SafetyClass:
        return SafetyClass.READ          # queries an external service

    def concurrency_safe(self, args: Dict[str, Any]) -> bool:
        return True

    def extract_targets(self, args: Dict[str, Any]) -> List[str]:
        # the search endpoint is operator infrastructure, not an
        # engagement target — no scope targets
        return []

    async def call(self, args: Dict[str, Any],
                   ctx: ToolContext) -> ToolResult:
        import os
        endpoint = os.environ.get("AEGIS_OSINT_ENDPOINT", "").strip()
        if not endpoint:
            return ToolResult.error(
                "OSINT search unavailable: no AEGIS_OSINT_ENDPOINT "
                "configured. Ask the operator to attach a search proxy "
                "or use retrieve_url_content against known sources.")
        query = str(args.get("query", ""))
        url = (endpoint + ("&" if "?" in endpoint else "?")
               + urllib.parse.urlencode({"q": query}))
        try:
            status, rheaders, body, _ = await _http_call(url)
        except (urllib.error.URLError, socket.timeout, OSError,
                ValueError) as exc:
            return ToolResult.error(f"search failed: {exc}")
        return ToolResult(body.decode("utf-8", "replace"),
                          metadata={"status": status})


# ─── map_vhost (oracle) ───────────────────────────────────────────────

class MapVhostTool(Tool):
    name = "map_vhost"
    input_schema = {
        "type": "object",
        "properties": {
            "ip_address": {"type": "string", "minLength": 7,
                           "maxLength": 45},
            "hostname": {"type": "string", "minLength": 2,
                         "maxLength": 253},
        },
        "required": ["ip_address", "hostname"],
        "additionalProperties": False,
    }
    timeout_s = 20.0

    def prompt(self) -> str:
        return ("Record a virtual-host mapping: resolve the hostname "
                "and confirm it points at the given IP. Returns the "
                "resolution result — the EKD extractor records the "
                "mapping as entities.")

    def safety_class(self, args: Dict[str, Any]) -> SafetyClass:
        return SafetyClass.READ

    def extract_targets(self, args: Dict[str, Any]) -> List[str]:
        return [str(args.get("ip_address", "")),
                str(args.get("hostname", ""))]

    async def call(self, args: Dict[str, Any],
                   ctx: ToolContext) -> ToolResult:
        ip = str(args.get("ip_address", ""))
        hostname = str(args.get("hostname", ""))
        try:
            infos = await asyncio.to_thread(
                socket.getaddrinfo, hostname, None, socket.AF_INET)
            resolved = sorted({i[4][0] for i in infos})
        except (socket.gaierror, OSError) as exc:
            return ToolResult(
                json.dumps({"ip_address": ip, "hostname": hostname,
                            "resolves": False, "error": str(exc)[:200]},
                           indent=2),
                metadata={"resolves": False})
        return ToolResult(
            json.dumps({"ip_address": ip, "hostname": hostname,
                        "resolves": True,
                        "resolved_ips": resolved,
                        "mapping_confirmed": ip in resolved},
                       indent=2),
            metadata={"resolves": True,
                      "confirmed": ip in resolved})
