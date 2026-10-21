# AEGIS Engagement Report

**Objective:** Scoped engagement dppm-run3 on dppmsserchhip.mizoram.gov.in within signed scope sha256:6e91b10c1ea3104f@v1, continuation of the assessment with NIC coordination acknowledged. Established in the prior run, verified and not to be re-derived: DNS A record 13.200.99.3; nginx 1.28.3; HTTP 80 redirects 301 to HTTPS; TLS 1.3 with Let's Encrypt certificate; a Next.js application; robots.txt and sitemap.xml 404; /api/ returns 308; favicon 200. The subdomain admin-dppmsserchhip.mizoram.gov.in is ADJACENT and out of scope in strict mode - never probe it. Tasks this run: (1) enumerate authorized TCP services with nmap -sT connect scans ONLY wrapped as proxychains4 nmap, sized to complete well under 300 seconds per call - start with --top-ports 100 at --max-rate 64 and -T2, never attempt a full 65535-port range in one call; (2) run nmap -sV version detection ONLY against ports found open, same wrapping and sizing; (3) identify versions and patch levels against known CVEs from banners and response analysis; (4) verify at most one non-destructive PoC per confirmed exposure class, PoC-only per RoE: no destructive actions, no persistent payloads, no denial of service. Third-party OSINT sites are out of scope by platform design - do not attempt them. Prefix every command that touches the target with proxychains4. Use mkdir -p before writing evidence files. Keep every artifact under the workspace, track the plan with todo_write, begin the port scan immediately, and finish with a structured findings summary citing scope fingerprint sha256:6e91b10c1ea3104f@v1 and per-finding evidence paths. Then stop.
**EKD revision:** 134 · **Findings:** 0

## Findings
_No findings recorded in the engagement graph._

## Attack Surface Inventory
- e1 (entity/endpoint): https://nmap.org
- e4 (entity/endpoint): https://nmap.org/submit/
- e2 (entity/host): 13.200.99.3
- e6 (entity/endpoint): http://dppmsserchhip.mizoram.gov.in/
- e7 (entity/endpoint): https://dppmsserchhip.mizoram.gov.in/_next/static/chunks/0lclmgfn-n7l1.js
- e8 (entity/endpoint): https://dppmsserchhip.mizoram.gov.in/about-us
- e9 (entity/endpoint): https://react.dev/errors/
- e10 (entity/endpoint): https://dppmsserchhip.mizoram.gov.in/contact-us
- e11 (entity/endpoint): https://dppmsserchhip.mizoram.gov.in/_next/static/0lclmgfn-n7l1/_buildManifest.js
- e12 (entity/endpoint): https://dppmsserchhip.mizoram.gov.in/_next/image?url=%2Fserchhip-block.png&w=1080&q=75
- e14 (entity/port_service): 139.84.217.111:5878
- e13 (entity/host): 139.84.217.111
- e3 (entity/domain): dppmsserchhip.mizoram.gov.in
- e15 (entity/endpoint): https://dppmsserchhip.mizoram.gov.in/api/
- e16 (entity/endpoint): https://dppmsserchhip.mizoram.gov.in/_next/static/chunks/turbopack-0f.dkyl2fpr3m.js
- e17 (entity/endpoint): https://dppmsserchhip.mizoram.gov.in/_next/static/chunks/0pqt~8bl3ukh4.js
- e5 (entity/endpoint): https://dppmsserchhip.mizoram.gov.in/
