# Task 3 - Version / patch-level vs known CVEs (banners + scoped response analysis)
# Scope fingerprint: sha256:6e91b10c1ea3104f@v1
# Target: dppmsserchhip.mizoram.gov.in (13.200.99.3)
#
# | Service / Component (banner)                    | Banner verdict / patch state | Known-CVE status at scan time | Evidence |
# |-------------------------------------------------|------------------------------|-------------------------------|----------|
# | nginx 1.28.3 (Server: nginx/1.28.3, port 80/443)| Latest mainline (Apr 2025); TLS 1.3, Let's Encrypt | No published CVEs outstanding for 1.28.3 (incl. mp4/H.263 2024 fixes already absorbed) | evidence/nmap_sv_http_ssh.txt, evidence/http_baseline_headers.txt |
# | OpenSSH 9.6p1 Ubuntu 3ubuntu13.19 (port 22)     | Ubuntu noble pkg; "3ubuntu13.x" backport track | CVE-2024-6387 regreSSHion (affects 8.5p1-9.7p1) patched via Ubuntu backport; CVE-2025-26465/26466 are client-side for 9.9p2, mitigations landed via same backports. No direct RCE class exposed. | evidence/nmap_sv_http_ssh.txt |
# | Unbound (TCP 53)                                | version string not disclosed, queried over TCP | No un-patched advisory known for the latest 1.19/1.20 branch; recursion client off-scope | evidence/nmap_sv_53.txt |
# | Next.js (X-Powered-By, RSC/Flight)              | App Router; server-action endpoint present | CVE-2025-55182 + CVE-2025-66478 class => PoC shows fixed behavior (404 x-nextjs-action-not-found). NOT exploitable. | evidence/poc_react_flight_cve-2025-55182.md, evidence/rsc_flight_confirmation.md |
# | react-dom 19.3.0-canary-3f0b9e61-20260317       | Build dated 2026-03-17, post public patch    | Matches fixed react-dom line for CVE-2025-55182                        | evidence/chunk_0lclmgfn-n7l1.js |
# | 8080/tcp 'http-proxy?'                          | unidentified (closes on HTTP GETs)           | No banner => no CVE correlation possible                                | evidence/nmap_sv_8080.txt, evidence/port_8080_and_5060_notes.md |
# | 5060/tcp 'sip?'                                  | nmap sees open; proxied path blocked by harness (see note) | No banner => no CVE correlation | evidence/nmap_sv_5060.txt, evidence/sip_options_probe.txt |
# | TLS stack (nginx 1.28.3, TLS 1.3, Let's Encrypt)| Prior run: TLS 1.3 + LE cert                 | No TLS-specific weakness evident; HSTS missing is a config gap, not a CVE | evidence/http_baseline_headers.txt |
#
# Header-hygiene observations (not CVEs, captured for the report):
#   missing: x-frame-options, x-content-type-options, strict-transport-security, content-security-policy
#   disclosed: Server: nginx/1.28.3, X-Powered-By: Next.js
#   port 80 now serves the app HTTP 200 directly (no 301 to HTTPS this run) -> plaintext risk
