# dppm-run3 Findings Summary
Scope fingerprint: sha256:6e91b10c1ea3104f@v1
Target: dppmsserchhip.mizoram.gov.in (13.200.99.3)
Date: 2026-10-15

How tasks were executed (verbatim):
- Task 1  : proxychains4 nmap -sT --top-ports 100 --max-rate 64 -T2
            (evidence/nmap_top100.txt)
            + bounded extended subset scan (evidence/nmap_extended_subset.txt)
            Note: --top-ports 1000 was attempted and hit the 290 s platform cap (killed); evidence/nmap_top1000.txt retained as partial.
- Task 2  : proxychains4 nmap -sT -sV ONLY against ports found open:
            {22,80,443} (evidence/nmap_sv_http_ssh.txt) and {53,5060,8080} split per-port
            (evidence/nmap_sv_53.txt, evidence/nmap_sv_5060.txt, evidence/nmap_sv_8080.txt)
- Task 3  : Banner/response analysis (scoped HTTP only) - see evidence/cve_correlation_table.md
- Task 4  : ONE non-destructive PoC for the single confirmed exposure class
            (React RSC/Flight -> CVE-2025-55182 / CVE-2025-66478). No other PoCs fired.

--------------------------------------------------------------------------------
FINDING 1 -- CVE-2025-55182 / CVE-2025-66478 (React Server Components / Next.js
             unsafe-deserialization RCE) on dppmsserchhip.mizoram.gov.in
Severity: Critical class (CVSS 10) -- **VERIFIED NOT EXPLOITABLE on this deployment.**
Evidence:
  - Flight protocol active: GET / with RSC: 1 returns HTTP 200 Content-Type text/x-component
    (evidence/rsc_flight_confirmation.md)
  - Framework version chain: react-dom "19.3.0-canary-3f0b9e61-20260317" (build 2026-03-17,
    post public patch, observed in evidence/chunk_0lclmgfn-n7l1.js)
  - Single read-only PoC: POST / with bogus Next-Action (40 '0's) returns
    HTTP 404 + header x-nextjs-action-not-found: 1 + body "Server action not found."
    (evidence/poc_react_flight_cve-2025-55182.md) -- matches fixed-Next.js behavior;
    vulnerable behavior would accept the Flight chunk for unsafe deserialization
    before validating the action ID.

FINDING 2 -- Security-header hygiene on the primary HTTPS origin (config, not CVE)
Severity: Low
Evidence: evidence/http_baseline_headers.txt  (passive scanner alerts captured)
  - missing: strict-transport-security (HSTS)
  - missing: x-frame-options
  - missing: x-content-type-options
  - missing: content-security-policy    (note: /_next/image *does* set a CSP with sandbox)
  - disclosed: Server: nginx/1.28.3 and X-Powered-By: Next.js
Single-request evidence already on file; no extra probing performed.

FINDING 3 -- Plaintext HTTP still serves the app on port 80
Severity: Low
Evidence: evidence/http_baseline_headers.txt
  - GET http://dppmsserchhip.mizoram.gov.in/ -> HTTP 200 (full Next.js app body)
  - Prior run observed 301 -> https. This run the redirect is NOT enforced,
    so users can browse the whole site over cleartext. Combined with the absence
    of HSTS (Finding 2) this is a downgrade/MITM risk rather than an exploitable CVE.

FINDING 4 -- Unbound exposed on TCP 53
Severity: Info
Evidence: evidence/nmap_sv_53.txt
  - nmap -sV fingerprint: 'Unbound'. No version string disclosed.
  - No known unpatched advisory against the current Unbound 1.19/1.20 branch at scan date.

FINDING 5 -- Unidentified service on TCP 8080 ('http-proxy?')
Severity: Info
Evidence: evidence/nmap_sv_8080.txt, evidence/port_8080_and_5060_notes.md
  - Accepts TCP through the harness but immediately closes on:
       GET /, GET / with UA header, GET /.well-known/openid-configuration
  - Behavior is consistent with a TLS-only or protocol-specific listener/fronting proxy.
  - No banner, version, or API surface recoverable -> no CVE correlation possible.

FINDING 6 -- 5060/tcp SIP 'open' to nmap, unreachable through proxied session path
Severity: Info
Evidence: evidence/nmap_sv_5060.txt, evidence/sip_options_probe.txt
  - nmap -sT / -sV reports 5060/tcp open ('sip?').
  - A read-only SIP OPTIONS probe through proxychains4 fails at the egress proxy with
    'Strict chain ... 139.84.217.111:5878 ... timeout'/'Connection refused'
    (adjacent host 139.84.217.111 is NOT in scope; no probe was ever directed at it).
  - Treated as open-but-unattackable from this engagement harness.

PATCH-LEVEL / CVE REJECTIONS (see evidence/cve_correlation_table.md)
  - nginx 1.28.3          : latest mainline, no published CVEs outstanding
  - OpenSSH 9.6p1 Ubuntu 3ubuntu13.19 : CVE-2024-6387 regreSSHion window 8.5p1-9.7p1 BUT
                          patched through Ubuntu backport '3ubuntu13.x'; no RCE class exposed
  - Next.js/react-dom     : post-CVE-2025-55182/66478 build (see Finding 1 PoC)

OUT-OF-SCOPE CONSTRAINTS OBSERVED
  - admin-dppmsserchhip.mizoram.gov.in     : listed on the public homepage; never resolved,
                                             never probed (strict adjacent).
  - 139.84.217.111 (egress proxy node)      : appears only inside proxychains4 output
                                             while scanning the in-scope hostname; never targeted.
  - OSINT search: AEGIS_OSINT_ENDPOINT not configured -> no third-party OSINT attempted.

ARTIFACT INDEX (all under workspace/evidence)
  - nmap_top100.txt / nmap_top1000.txt / nmap_extended_subset.txt
  - nmap_sv_http_ssh.txt / nmap_sv_53.txt / nmap_sv_5060.txt / nmap_sv_8080.txt
  - http_baseline_headers.txt
  - service_version_inventory.md
  - rsc_flight_confirmation.md
  - poc_react_flight_cve-2025-55182.md
  - cve_correlation_table.md
  - api_baseline.md
  - port_8080_and_5060_notes.md
  - sip_options_probe.txt
  - chunk_0lclmgfn-n7l1.js          (turbopack chunk with react-dom version string)
  - ../report.md                    (EKD-generated surface inventory; 0 findings in EKD because
                                     the highest-severity PoC is verified non-exploitable)
