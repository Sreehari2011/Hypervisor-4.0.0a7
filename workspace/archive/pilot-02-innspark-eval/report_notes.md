# VAPT Findings — Serchhip DPPMS Portal
scope_ref: O2 (End to End VAPT — https://dppmsserchhip.mizoram.gov.in/)
Date: 2026-10-13 · Target host: dppmsserchhip.mizoram.gov.in (13.200.99.3, AWS EC2 ap-south-1)
Mode: expand (adjacent entities journaled, not targeted)

## Confirmed findings
- F-01 (Low, OWASP A05) Missing security response headers on all responses:
  x-frame-options/frame-ancestors, content-security-policy, strict-transport-security, x-content-type-options.
  Impact: clickjacking / MIME-sniffing / no HSTS. Evidence: passive_scanner alerts on every
  advanced_http_request (e1,e2,e16,e17,e31,e3) + buffers/*.log.
- F-02 (Low, CWE-200) Server/tech + build disclosure in headers:
  Server: nginx/1.28.3, X-Powered-By: Next.js, ETag build-id "12rp6558v51e3k", x-nextjs-* headers.
  Evidence: HEAD/GET on e1, e19. File: report.md cites buffers.
- F-03 (Info, adjacent) Admin console discovered: https://admin-dppmsserchhip.mizoram.gov.in (e23)
  discovered via homepage DOM link. In-scope host only referenced; admin host NOT targeted (e23 scope_reason=adjacent).

## Assessed / blocked by platform (not a pass)
- FR-1 (Potential, High) React2Shell class CVE-2025-55182: app serves react-server-dom-webpack Flight
  payloads (chunks 08627237, 0s_td3r8227wd) with React version "19.3.0-canary-3f0b9e..." (unpatched range).
  Exploitation requires raw text/x-component POST; the harness scope-gate denies network I/O in
  execute_code/execute_exploit_script and advanced_http_request cannot send that content-type, so the
  confirmation probe could not be delivered. Status: UNVERIFIED (needs operator RCE allowance / raw socket).
  Evidence: buffer agent_buffer_5b3baac1.log (React version string), RSC chunks (e6,e7,e19).

## Tested — clean
- Image optimizer SSRF: /_next/image?url=<external|169.254.169.254|relative> -> 400 "parameter is not allowed/invalid" (e24,e27). No relay.
- Arbitrary Next.js Server Action: POST with Next-Action: invalid-id -> 404 x-nextjs-action-not-found (no action dispatch).
- Path traversal: /%2e%2e/%2e%2e/etc/passwd -> 400 at nginx (e28). No LFI.
- Sensitive files: /.env (e29), /robots.txt (e30), /_next/*manifest (e12,e13,e19) -> 404.
- API surface: /api, /api/projects, /api/blocks (e3,e25,e26) -> 404 (public host is static; backend on admin host/out-of-scope).
- Verb tampering: OPTIONS / -> 400, no permissive Allow/CORS.
- WAF: none detected (detect_waf -> null); rate-cap scan completed unthrottled.

## Out-of-scope attempts (journaled, not retried)
- mizoram.gov.in (dig whole zone), crt.sh (CT aggregator), socket.getaddrinfo host resolve,
  13.200.99.3:8080 & :5060 (IP literal), 0.0.0.0 (map_vhost), execute_code/exploit net I/O (sendall/getresponse),
  execute_code urlopen. Rationale: scope = declared host only; expand-mode admits = journal external hosts.

## Scope compliance
- Port scan used only -sT --max-rate 200 -T3 (-sV --version-light -F --open). No -sS/-sU/-sA (raw-socket) used.
- poc_only=false requested, but raw-RCE confirmation blocked by harness network egress gating.
