"""hypervisor.permissions — the scope engine (P1).

Port card: PORT-09 (3.7.3 core/engagement_context.py — ScopeManager,
target/CIDR/wildcard/port-window semantics preserved) composed with
Skeleton 9-3 (the safety-class gate). THE STANDING CRITICAL FIX of the
entire 4.0 program:

  * enforcement ON by default. In every 3.x release through 3.7.3 it
    shipped OFF: SCOPE_ENFORCEMENT defaulted false and check_scope
    returned True under a "TEST MODE" banner (oracle
    src/core/engagement_context.py L338-340 — the base repo's most
    dangerous finding). 4.0 inverts the default and the bypass code
    DOES NOT PORT AT ALL: there is no flag, no test mode, no call-time
    opt-out anywhere in this module.
  * deny-by-default: anything not explicitly authorized by the
    engagement scope file is refused.
  * the scope file IS the authorization model (scoped full-auto): one
    operator-signed, versioned artifact; in-scope actions auto-approve
    and are AUDITED rather than interrupted; out-of-scope actions are
    denied and audited. Its fingerprint rides every permission_decision
    event (scope_ref).
  * every decision — allow AND deny — writes a journal audit record;
    the debug kit mirrors it into the timeline as cat='perm'.

Check semantics preserved from the oracle (PORT-09 acceptance): the
P0-B order — (1) SCOPE_EXCLUDE hard-block beats every include in both
modes; (2) declared rules with port-window/protocol/expiry filtering;
(3) expand-mode DNS-subtree auto-admissions (capped, journaled); (4)
deny. Live tightening (scope_mode), admission outcomes
(scope_expansion) and the once-per-engagement cap event (scope_cap)
journal exactly as in 3.7.3.

The mobile-tool path-traversal class (analyze_apk raw join) is
structurally closed: ALL path-bearing tools resolve through
resolve_safe_path, which the gate enforces for every WRITE-class call.
"""
from __future__ import annotations

import hashlib
import ipaddress
import json
import os
import re
import time
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Tuple

from .adapters.openai import frozen_json


# ─── safety classes (Skeleton 9-3 / REFACTOR-05 composition) ──────────

class SafetyClass(str, Enum):
    READ = "read"            # recon: observe, read, enumerate
    WRITE = "write"          # creates/changes state in-workspace
    EXPLOIT = "exploit"      # touches the target estate
    DESTRUCTIVE = "destructive"  # deny-by-RoE class


@dataclass
class RoE:
    """Rules of Engagement profile carried by the scope file."""
    poc_only: bool = True
    allow_persistent_payloads: bool = False
    destructive_allowed: bool = False


@dataclass
class Decision:
    """One gate outcome. `audit` names the evidence class the journal
    record carries ("recon" for READ allows, "action" for state-changing
    allows); `rule` names the deciding clause for replay/audit."""
    allowed: bool
    rule: str
    reason: str = ""
    audit: str = ""                       # recon | action | ""
    targets: Tuple[str, ...] = ()
    safety: str = ""
    scope_ref: str = ""
    args_digest: str = ""

    @classmethod
    def allow(cls, rule: str, *, audit: str = "recon", **kw) -> "Decision":
        return cls(True, rule, audit=audit, **kw)

    @classmethod
    def deny(cls, rule: str, reason: str = "", **kw) -> "Decision":
        return cls(False, rule, reason=reason, **kw)


# ─── scope rules (oracle ScopeRule, verbatim semantics) ────────────────

@dataclass
class ScopeRule:
    """Single scope authorization rule (ported from 3.7.3)."""
    target: str                       # IP, CIDR, domain, or wildcard
    target_type: str                  # ip | cidr | domain | wildcard
    ports: List[int] = field(default_factory=list)     # [] = all ports
    protocols: List[str] = field(
        default_factory=lambda: ["tcp", "udp", "http", "https"])
    authorized: bool = True
    authorization_token: str = ""     # signed proof of authorization
    expires_at: Optional[float] = None

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "ScopeRule":
        tt = str(d.get("type", "auto")).strip().lower()
        target = str(d.get("target", "")).strip()
        if not target:
            raise ValueError("scope rule without a target")
        if tt == "auto":
            tt = infer_target_type(target)
        if tt not in ("ip", "cidr", "domain", "wildcard"):
            raise ValueError(f"unknown scope target type {tt!r}")
        return cls(
            target=target, target_type=tt,
            ports=[int(p) for p in (d.get("ports") or [])],
            protocols=[str(p).lower() for p in
                       (d.get("protocols") or
                        ["tcp", "udp", "http", "https"])],
            authorized=bool(d.get("authorized", True)),
            authorization_token=str(d.get("authorization_token", "")),
            expires_at=(float(d["expires_at"])
                        if d.get("expires_at") is not None else None))


def infer_target_type(target: str) -> str:
    t = str(target or "").strip().lower().rstrip(".")
    if "/" in t:
        return "cidr"
    if "*" in t:
        return "wildcard"
    try:
        ipaddress.ip_address(t)
        return "ip"
    except ValueError:
        return "domain"


# ─── the scope file: the single authorization truth ────────────────────

@dataclass
class ScopeFile:
    """Operator-authored engagement scope. The sha256 of the canonical
    body (frozen_json minus the authorization block) is the scope_ref
    that rides every permission_decision; `signed_sha256` must match it
    when present (the operator signing convention for 4.0)."""
    path: Optional[Path]
    version: int
    engagement_id: str
    rules: List[ScopeRule]
    mode: str                                  # strict | expand
    excludes: List[str]
    expansion_cap: int
    roe: RoE
    fingerprint: str                           # sha256 hex of canonical body
    signed: bool

    @classmethod
    def load(cls, path: Path | str) -> "ScopeFile":
        path = Path(path)
        raw = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(raw, dict):
            raise ValueError(f"scope file {path} is not a JSON object")
        body = {k: v for k, v in raw.items() if k != "authorization"}
        canonical = frozen_json(body)
        fingerprint = hashlib.sha256(
            canonical.encode("utf-8")).hexdigest()
        auth = raw.get("authorization") or {}
        signed_sha = str(auth.get("signed_sha256", "") or "").lower()
        if signed_sha and signed_sha != fingerprint:
            raise ValueError(
                f"scope file signature mismatch: authorization says "
                f"{signed_sha[:16]}..., canonical body hashes to "
                f"{fingerprint[:16]}... — refusing to load")
        mode = str(raw.get("mode", "strict")).strip().lower()
        if mode not in ("strict", "expand"):
            mode = "strict"
        roe_raw = raw.get("roe") or {}
        rules = [ScopeRule.from_dict(r)
                 for r in (raw.get("targets") or [])]
        if not rules:
            raise ValueError(
                "scope file declares no targets — deny-by-default would "
                "refuse everything; refusing to load an empty scope")
        return cls(
            path=path,
            version=int(raw.get("version", 1)),
            engagement_id=str(raw.get("engagement_id", "")),
            rules=rules, mode=mode,
            excludes=[str(x).strip() for x in (raw.get("excludes") or [])
                      if str(x).strip()],
            expansion_cap=int(raw.get("expansion_cap", 256) or 256),
            roe=RoE(poc_only=bool(roe_raw.get("poc_only", True)),
                    allow_persistent_payloads=bool(
                        roe_raw.get("allow_persistent_payloads", False)),
                    destructive_allowed=bool(
                        roe_raw.get("destructive_allowed", False))),
            fingerprint=fingerprint,
            signed=bool(signed_sha))

    def scope_ref(self) -> str:
        tag = "signed" if self.signed else "unsigned"
        return (f"sha256:{self.fingerprint[:16]}@v{self.version}({tag})")


# ─── the scope manager (oracle check semantics, ported) ────────────────

class ScopeManager:
    """Port of the 3.7.3 ScopeManager: compile/include/exclude matching,
    expand-mode DNS-subtree admission with cap, live tightening.
    The TEST-MODE bypass that lived in EngagementContext.check_scope
    does not exist here — there is nothing to bypass."""

    def __init__(self, scope_file: ScopeFile, *, journal: Any = None):
        self.file = scope_file
        self.rules = scope_file.rules
        self.mode = scope_file.mode
        self.journal = journal
        self._compiled = self._compile_rules()
        self.excludes = list(scope_file.excludes)
        self._compiled_excludes = self._compile_patterns(self.excludes)
        self.cap = scope_file.expansion_cap
        # DNS root domains for expand mode: declared domains + the base
        # domain of wildcards (*.target.com -> target.com).
        roots: List[str] = []
        for r in self.rules:
            t = str(r.target or "").strip().lower().rstrip(".")
            if not t:
                continue
            if r.target_type == "domain":
                roots.append(t)
            elif r.target_type == "wildcard" and t.startswith("*."):
                roots.append(t[2:])
        self.roots = sorted(set(roots))
        self.admitted: Dict[str, Dict[str, Any]] = {}
        self._admission_cache: Dict[str, Dict[str, Any]] = {}
        self._cap_event: Optional[Dict[str, Any]] = None

    # ------------------------------------------------------ compilation

    @staticmethod
    def _compile_patterns(patterns: Sequence[str]) -> List[Dict]:
        """Compile bare host / wildcard / CIDR strings (the SCOPE_EXCLUDE
        grammar) using the same matcher semantics as the rules."""
        compiled = []
        for raw in patterns:
            t = str(raw or "").strip().lower().rstrip(".")
            if not t:
                continue
            entry: Dict[str, Any] = {}
            if "/" in t:
                try:
                    entry["network"] = ipaddress.ip_network(t, strict=False)
                    entry["type"] = "cidr"
                except ValueError:
                    continue
            elif "*" in t:
                base = t[1:] if t.startswith("*.") else t
                entry["regex"] = re.compile(
                    "^" + re.escape(t).replace(r"\*", ".*") + "$",
                    re.IGNORECASE)
                entry["base"] = base
                entry["type"] = "wildcard"
            else:
                try:
                    entry["ip"] = ipaddress.ip_address(t)
                    entry["type"] = "ip"
                except ValueError:
                    entry["domain"] = t
                    entry["type"] = "domain"
            compiled.append(entry)
        return compiled

    def _compile_rules(self) -> List[Dict]:
        compiled = []
        for rule in self.rules:
            entry = {
                "authorized": rule.authorized,
                "ports": set(rule.ports) if rule.ports else None,
                "protocols": set(p.lower() for p in rule.protocols),
                "expires_at": rule.expires_at,
            }
            if rule.target_type == "cidr":
                entry["network"] = ipaddress.ip_network(
                    rule.target, strict=False)
                entry["type"] = "cidr"
            elif rule.target_type == "ip":
                entry["ip"] = ipaddress.ip_address(rule.target)
                entry["type"] = "ip"
            elif rule.target_type == "wildcard":
                entry["regex"] = re.compile(
                    "^" + re.escape(rule.target).replace(r"\*", ".*") + "$",
                    re.IGNORECASE)
                entry["type"] = "wildcard"
            else:
                entry["domain"] = rule.target.lower()
                entry["type"] = "domain"
            compiled.append(entry)
        return compiled

    # ------------------------------------------------------- exclusion

    def _matches_excluded(self, host: str) -> Optional[str]:
        h = str(host or "").strip().lower().rstrip(".")
        if not h:
            return None
        for entry in self._compiled_excludes:
            kind = entry.get("type")
            try:
                if kind == "cidr" and \
                        ipaddress.ip_address(h) in entry["network"]:
                    return h
                if kind == "ip" and ipaddress.ip_address(h) == entry["ip"]:
                    return h
            except ValueError:
                pass
            if kind == "wildcard" and entry["regex"].match(h):
                return h
            if kind == "domain" and (h == entry["domain"] or
                                     h.endswith("." + entry["domain"])):
                return h
        return None

    # ---------------------------------------------------- mode surface

    def tighten_strict(self, source: str = "operator") -> bool:
        """Live tightening to strict. The ONLY runtime mode mutation;
        there is deliberately no runtime expand. Journaled (scope_mode)."""
        if self.mode == "strict":
            return False
        self.mode = "strict"
        self._j("scope_mode", {"mode": "strict", "source": source,
                               "note": "live tightening"})
        return True

    def _root_for(self, host: str) -> Optional[str]:
        h = str(host or "").strip().lower().rstrip(".")
        if not h:
            return None
        for root in self.roots:
            if h == root or h.endswith("." + root):
                return root
        return None

    def _explicit_match(self, host: str) -> bool:
        """True when an entry EXPLICITLY declares this host (ip/cidr
        match or the domain IS the root). Suffix semantics do NOT count
        here: in expand mode a subdomain under a declared root is an
        ADMISSION (audited, capped) — the report can show why any host
        was touched (SD-1)."""
        h = str(host or "").strip().lower().rstrip(".")
        if not h:
            return False
        for r in self.rules:
            t = str(r.target or "").strip().lower().rstrip(".")
            tt = r.target_type
            if tt == "ip" and t == h:
                return True
            if tt == "cidr":
                try:
                    if "/" in t and ipaddress.ip_address(h) in \
                            ipaddress.ip_network(t, strict=False):
                        return True
                except ValueError:
                    pass
            if tt == "domain" and t == h:
                return True
        return False

    def admit_discovered_host(self, host: str, method: str = "extraction",
                              evidence: Optional[str] = None
                              ) -> Optional[Dict[str, Any]]:
        """SD-1 admission (expand mode): excluded -> explicit declaration
        -> DNS-subtree admission (cap-bounded, journaled) -> non-subdomain
        adjacency. Cached per host; every decision journaled once
        (scope_expansion); the cap emits scope_cap exactly once."""
        h = str(host or "").strip().lower().rstrip(".")
        h = h.split(":")[0].split("/")[0]
        if not h or self.mode != "expand":
            return None
        cached = self._admission_cache.get(h)
        if cached is not None:
            return dict(cached)

        rec: Dict[str, Any]
        if self._matches_excluded(h) is not None:
            rec = {"in_scope": False, "outcome": "excluded",
                   "scope_reason": "excluded: SCOPE_EXCLUDE"}
        elif self._explicit_match(h):
            rec = {"in_scope": True, "outcome": "rule",
                   "scope_reason": "declared-rule"}
        else:
            root = self._root_for(h)
            if root is None:
                rec = {"in_scope": False, "outcome": "non-subdomain",
                       "scope_reason":
                           "adjacent: not a subdomain of any declared root"}
            elif len(self.admitted) >= self.cap:
                rec = {"in_scope": False, "outcome": "cap",
                       "scope_reason": "expansion capped"}
                if self._cap_event is None:
                    self._cap_event = {"cap": self.cap,
                                       "at": len(self.admitted)}
                    self._j("scope_cap", {"cap": self.cap, "host": h,
                                          "root": root})
            else:
                rec = {"in_scope": True, "outcome": "admitted",
                       "scope_reason": f"subdomain-of:{root}", "root": root}
                self.admitted[h] = {"host": h, "root": root,
                                    "method": method, "evidence": evidence}
        self._admission_cache[h] = rec
        if rec["outcome"] != "rule":
            self._j("scope_expansion",
                    {"host": h, "method": method, "evidence": evidence,
                     "outcome": rec["outcome"],
                     "scope_reason": rec["scope_reason"],
                     "admitted_total": len(self.admitted)},
                    actor="scope")
        return dict(rec)

    def classify_host(self, host: str, method: str = "extraction",
                      evidence: Optional[str] = None, *,
                      strict_classify: bool = True
                      ) -> Optional[Dict[str, Any]]:
        """Host classification in both modes (3.7 Phase 2 semantics):
        expand -> admission record; strict -> rule / adjacent / excluded
        (adjacent is a CLASSIFICATION, never an authorization)."""
        h = str(host or "").strip().lower().rstrip(".")
        h = h.split(":")[0].split("/")[0]
        if not h:
            return None
        if self.mode != "strict":
            return self.admit_discovered_host(h, method=method,
                                              evidence=evidence)
        if not strict_classify:
            return None
        cached = self._admission_cache.get(h)
        if cached is not None:
            return dict(cached)
        rec: Dict[str, Any]
        if self._matches_excluded(h) is not None:
            rec = {"in_scope": False, "outcome": "excluded",
                   "scope_reason": "excluded: SCOPE_EXCLUDE"}
        else:
            try:
                authorized, _ = self.is_authorized(h)
            except Exception:
                authorized = False
            if authorized:
                rec = {"in_scope": True, "outcome": "rule",
                       "scope_reason": "declared-rule"}
            else:
                rec = {"in_scope": False, "outcome": "adjacent",
                       "scope_reason":
                           "adjacent: matches no scope entry (strict)"}
        self._admission_cache[h] = rec
        return dict(rec)

    def scope_status(self) -> Dict[str, Any]:
        """Boot banner / /scope status surface."""
        return {
            "mode": self.mode,
            "roots": list(self.roots),
            "excludes": list(self.excludes),
            "cap": self.cap,
            "admitted": len(self.admitted),
            "admitted_hosts": sorted(self.admitted)[:20],
            "cap_event": dict(self._cap_event) if self._cap_event else None,
            "rules": len(self.rules),
            "scope_ref": self.file.scope_ref(),
        }

    # --------------------------------------------------- the check API

    def is_authorized(self, target: str, port: Optional[int] = None,
                      protocol: str = "tcp") -> Tuple[bool, str]:
        """Check if target:port:protocol is within authorized scope.

        P0-B order (oracle parity): (1) exclude hard-block, beats every
        include; (2) declared rules (expiry, protocol, port window);
        (3) expand-mode auto-admitted hosts; (4) deny. There is no
        enforcement flag — this method IS the gate."""
        host = str(target or "").strip().lower().rstrip(".")
        if not host:
            return False, "empty target"
        if self._matches_excluded(host) is not None:
            return False, f"Target {target} is excluded by SCOPE_EXCLUDE"

        now = time.time()
        for rule in self._compiled:
            if rule["expires_at"] and now > rule["expires_at"]:
                continue
            if protocol.lower() not in rule["protocols"]:
                continue
            if rule["ports"] and port and port not in rule["ports"]:
                continue

            matched = False
            if rule["type"] == "cidr":
                try:
                    if ipaddress.ip_address(target) in rule["network"]:
                        matched = True
                except ValueError:
                    pass
            elif rule["type"] == "ip":
                try:
                    if ipaddress.ip_address(target) == rule["ip"]:
                        matched = True
                except ValueError:
                    pass
            elif rule["type"] == "wildcard":
                if rule["regex"].match(target):
                    matched = True
            elif rule["type"] == "domain":
                if target.lower() == rule["domain"] or \
                        target.lower().endswith("." + rule["domain"]):
                    matched = True

            if matched:
                if rule["authorized"]:
                    return True, "Authorized"
                return False, f"Target {target} is explicitly out of scope"

        if self.mode == "expand" and host in self.admitted:
            rec = self.admitted[host]
            return True, (f"Authorized (auto-admitted "
                          f"subdomain-of:{rec.get('root', '?')} "
                          f"via {rec.get('method', 'extraction')})")

        return False, f"Target {target}:{port} is not in authorized scope"

    def _j(self, kind: str, data: Dict[str, Any], *,
           actor: Optional[str] = None) -> None:
        if self.journal is None:
            return
        try:
            self.journal.append(kind, data, actor=actor or "scope-gate")
        except Exception:
            pass


# ─── path security (REFACTOR-05: all path-bearing tools route here) ────

def resolve_safe_path(file_path: str, workspace: str,
                      allow_buffers: bool = True) -> Optional[str]:
    """Bulletproof path validation (ported from 3.7.3 safe_execution):
    resolves symlinks, ../ and ./ sequences; returns the absolute real
    path if it stays inside the workspace, None otherwise. Buffer paths
    are advertised workspace-relative ("workspace/buffers/...") and map
    to {workspace}/buffers/. This closes the analyze_apk raw-join class
    structurally: no tool may open a path that did not pass here."""
    real_workspace = os.path.realpath(workspace)
    real_buffers = os.path.realpath(os.path.join(real_workspace, "buffers"))

    if allow_buffers and file_path.startswith("workspace/buffers/"):
        rel_path = file_path[len("workspace/buffers/"):]
        if rel_path.startswith("/"):
            return None
        abs_path = os.path.realpath(os.path.join(real_buffers, rel_path))
        if os.path.commonpath([abs_path, real_buffers]) == real_buffers:
            return abs_path
        return None

    normalized = os.path.normpath(file_path).lstrip(os.sep)
    abs_path = os.path.realpath(os.path.join(real_workspace, normalized))

    if os.path.commonpath([abs_path, real_workspace]) == real_workspace:
        return abs_path
    return None


# ─── command target extraction (REFACTOR-05, ported) ──────────────────
# PILOT-03 fix: the third label was optional-SINGLE ('?'), capping
# matches at three labels — a 4-label host (dppmsserchhip.mizoram.gov.in)
# could only match its first three, the word boundary fired between
# 'gov' and '.in', and the gate received a truncated host: every
# sanctioned bare-hostname shell action was denied while URL-form and
# structured tool params carried the full host. Greedy '*' consumes all
# labels; the truncation class cannot occur. Trade-off: 4+ label dotted
# chains in CODE TEXT (java packages, deep module paths) may now extract
# as targets and DENY — fail-safe, consistent with the deny-by-default
# doctrine recorded at _CODE_ATTR_SUFFIXES.

_IP_RE = re.compile(
    r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}'
    r'(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b')
_URL_RE = re.compile(r'https?://([a-zA-Z0-9.-]+)')
_DOMAIN_RE = re.compile(
    r'\b([a-zA-Z0-9][-a-zA-Z0-9]*\.[a-zA-Z]{2,}(?:\.[a-zA-Z]{2,})*)\b')
_CIDR_RE = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}/\d{1,2}\b')
_DOMAIN_FALSE_POSITIVES = frozenset({
    "example.com", "test.com", "localhost", "w3.org", "schema.org"})

# Dotted tokens whose final label is a common code attribute or a
# never-delegated file extension are not hostnames ("subprocess.run",
# "os.path", "socket.timeout", "results.txt" — the 4.0 exec tools run
# command-target extraction over CODE TEXT and tool output, where
# these idioms are ubiquitous). A curated attr set, not a TLD oracle.
# PILOT-02 additions: exception/message attrs ("socket.timeout" denied
# a live engagement turn) and file extensions that are NOT delegated
# TLDs. Deliberately EXCLUDED despite looking like files: py (Paraguay),
# sh (St. Helena), md (Moldova), app, dev, zip, mov, io — real TLDs; a
# bare "host.py" connection target must stay gated (deny-by-default
# wins ties with filename false positives).
_CODE_ATTR_SUFFIXES = frozenset({
    "run", "path", "argv", "environ", "getenv", "sleep", "compile",
    "search", "findall", "match", "sub", "loads", "dumps", "load",
    "dump", "format", "join", "append", "extend", "strip", "split",
    "rsplit", "encode", "decode", "write", "read", "readlines",
    "open", "close", "socket", "request", "urlopen", "hexdigest",
    "b64decode", "b64encode", "unhexlify", "hexlify", "startswith",
    "endswith", "replace", "lower", "upper", "keys", "values",
    "items", "get", "pop", "update", "copy", "name", "mode",
    # PILOT-02: exception/message attrs + never-delegated extensions
    "timeout", "refused", "reset", "unreachable", "gaierror",
    "txt", "log", "json", "yaml", "yml", "conf", "cfg", "ini",
    "csv", "html", "xml", "pcap", "pcapng", "nmap", "gnmap", "nse",
    "sql", "sqlite", "db", "pyc", "pyo", "gz", "bz2", "xz", "tar",
    "png", "jpg", "jpeg", "gif", "svg", "pdf", "doc", "docx",
    "xls", "xlsx", "ppt", "pptx", "pem", "crt", "csr", "key",
    "out", "err", "pid", "lock", "bak", "swp", "dat", "raw",
    "service", "sock", "pub", "asc", "hosts", "list", "rules",
})


def _path_embedded(command: str, start: int) -> bool:
    """True when the token at `start` rides inside a URL or file path
    rather than starting a shell argument: the immediately preceding
    character is a path separator ("curl http://10.0.0.5/22" path
    suffix, "python3 ws/probe.py", "nmap -iL /tmp/hosts.txt"). URL
    hosts are gated via _URL_RE; file paths are not connection
    targets."""
    return start > 0 and command[start - 1] == "/"


def extract_targets_from_command(command: str) -> List[str]:
    """Extract IP addresses, CIDRs, domains and URL hosts from a command
    string (ported heuristics from 3.7.3 safe_execution).

    PILOT-02 hardening — the first live engagement surfaced two
    false-positive classes, both fixed WITHOUT loosening the strict
    side:
      * IP/nnn tokens not in argument position are URL/path suffixes,
        not CIDRs ("curl http://10.10.0.5/22"): the bare IP and the
        URL host are extracted separately and carry the gate;
      * an IP/nnn suffix over 32 can never be a prefix length — host/
        port or path notation ("10.10.0.5/80"): the bare IP carries
        the gate;
      * argument-position CIDRs stay STRICT, including sloppy
        host-bits-set notation ("nmap 10.10.0.5/22" is network-scan
        intent under nmap semantics) — deny-by-default is correct
        there;
      * domain-shaped tokens in path position are file references
        ("python3 ws/probe.py"), never bare connection targets.
    """
    targets: set = set()
    for m in _IP_RE.finditer(command):
        targets.add(m.group())
    for m in _URL_RE.finditer(command):
        targets.add(m.group(1))
    for m in _DOMAIN_RE.finditer(command):
        if _path_embedded(command, m.start(1)):
            continue
        domain = m.group(1)
        if domain in _DOMAIN_FALSE_POSITIVES:
            continue
        # code-attribute dotted tokens are not hostnames
        last = domain.rsplit(".", 1)[-1].lower()
        if last in _CODE_ATTR_SUFFIXES:
            continue
        targets.add(domain)
    for m in _CIDR_RE.finditer(command):
        if _path_embedded(command, m.start()):
            continue
        token = m.group()
        try:
            prefix = int(token.rsplit("/", 1)[1])
        except ValueError:
            prefix = 0
        if prefix > 32:
            # never a prefix length: host/port or path notation; the
            # bare IP token (extracted above) carries the gate
            continue
        targets.add(token)
    return [t.rstrip(".") for t in targets if t.rstrip(".")]


# ─── the permission engine (Skeleton 9-3) ──────────────────────────────

class PermissionEngine:
    """The gate every tool call passes through. Composes the tool's
    safety class with the scope manager; scoped full-auto: in-scope
    actions auto-approve WITH audit, out-of-scope actions deny WITH
    audit. There is no interactive prompt path and no bypass."""

    def __init__(self, scope: ScopeManager, *, journal: Any = None,
                 observer: Any = None):
        self.scope = scope
        self.journal = journal
        self.observer = observer
        self.decisions = 0
        self.denials = 0

    # ------------------------------------------------------------ gate

    async def check_permission(self, tool: Any, args: Dict[str, Any],
                               ctx: Any = None, *,
                               turn: int = 0) -> Decision:
        safety = _safety_of(tool, args)
        args_digest = hashlib.sha256(
            frozen_json(args).encode("utf-8")).hexdigest()[:16]
        base = dict(safety=safety.value, args_digest=args_digest,
                    scope_ref=self.scope.file.scope_ref())

        targets = _targets_of(tool, args)

        # Path-bearing tools (REFACTOR-05): every declared path argument
        # must resolve inside the engagement workspace through the shared
        # resolver — the analyze_apk raw-join class is closed HERE, at
        # gate time, not left to individual tools.
        workspace = getattr(ctx, "workspace", None)
        path_args = tuple(getattr(tool, "path_args", ()) or ())
        if workspace and path_args:
            for key in path_args:
                raw_path = args.get(key)
                if raw_path is None or raw_path == "":
                    continue
                if resolve_safe_path(str(raw_path), workspace) is None:
                    d = Decision.deny(
                        "path-escape",
                        f"path {raw_path!r} escapes the engagement "
                        f"workspace",
                        targets=tuple(targets), **base)
                    self.decisions += 1
                    self.denials += 1
                    self._audit(tool, d, turn=turn)
                    return d

        # PILOT-03 fail-closed (run-1 turn-6 class): a command that
        # invokes a network-facing binary but extracts NO target is a
        # denial, not a pass — targetless egress closes here.
        _needs_target = getattr(tool, "target_required", None)
        if (not targets and safety is not SafetyClass.READ
                and callable(_needs_target) and _needs_target(args)):
            d = Decision.deny(
                "scope:no-target",
                "network-facing command produced no extractable "
                "target (fail-closed)",
                targets=(), **base)
            self.decisions += 1
            self.denials += 1
            self._audit(tool, d, turn=turn)
            return d

        # DESTRUCTIVE: the RoE profile owns this class outright.
        if safety is SafetyClass.DESTRUCTIVE:
            d = Decision.deny("roe:destructive-disabled",
                              "destructive class disabled by RoE profile",
                              targets=tuple(targets), **base)
        # READ / WRITE / EXPLOIT all require in-scope targets first.
        else:
            denied_by = self._first_denied_target(targets)
            if denied_by is not None:
                host, reason = denied_by
                d = Decision.deny("scope:out-of-scope",
                                  f"target {host} out of scope: {reason}",
                                  targets=tuple(targets), **base)
            elif safety is SafetyClass.READ:
                d = Decision.allow("scope:read-in-scope", audit="recon",
                                   targets=tuple(targets), **base)
            else:  # WRITE or EXPLOIT
                if self.scope.file.roe.poc_only and _is_persistent(tool, args):
                    d = Decision.deny(
                        "roe:poc-only",
                        "persistent payload under PoC-only RoE",
                        targets=tuple(targets), **base)
                else:
                    d = Decision.allow(
                        "scope:action-in-scope", audit="action",
                        reason="evidence:" + ",".join(targets[:4]),
                        targets=tuple(targets), **base)

        self.decisions += 1
        if not d.allowed:
            self.denials += 1
        self._audit(tool, d, turn=turn)
        return d

    def _first_denied_target(self, targets: Sequence[str]
                             ) -> Optional[Tuple[str, str]]:
        for t in targets:
            host = str(t).strip().lower().rstrip(".")
            if not host:
                continue
            ok, reason = self.scope.is_authorized(host)
            if not ok:
                return host, reason
        return None

    # ---------------------------------------------------------- audit

    def _audit(self, tool: Any, d: Decision, *, turn: int = 0) -> None:
        name = getattr(tool, "name", str(tool))
        if self.journal is not None:
            try:
                self.journal.record_permission_decision(
                    name, allowed=d.allowed, rule=d.rule,
                    args_digest=d.args_digest,
                    scope_ref=d.scope_ref, reason=d.reason or d.audit)
            except Exception:
                pass
        if self.observer is not None:
            try:
                self.observer.on_permission_decision(
                    tool=name, allowed=d.allowed, rule=d.rule, turn=turn)
            except Exception:
                pass


def _safety_of(tool: Any, args: Dict[str, Any]) -> SafetyClass:
    try:
        sc = tool.safety_class(args)
        return sc if isinstance(sc, SafetyClass) else SafetyClass(str(sc))
    except Exception:
        return SafetyClass.DESTRUCTIVE  # unclassifiable -> safest class


def _targets_of(tool: Any, args: Dict[str, Any]) -> List[str]:
    try:
        out = list(tool.extract_targets(args) or [])
    except Exception:
        return []
    return [str(t) for t in out if str(t or "").strip()]


def _is_persistent(tool: Any, args: Dict[str, Any]) -> bool:
    try:
        return bool(tool.is_persistent(args))
    except Exception:
        return False
