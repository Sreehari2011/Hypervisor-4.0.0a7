# Service & version inventory (dppm-run3)
# Target: dppmsserchhip.mizoram.gov.in (13.200.99.3) - scope sha256:6e91b10c1ea3104f@v1
#
# Port plan executed (all via `proxychains4 nmap -sT`, bounded <300s/call):
#  - --top-ports 100 @ --max-rate 64 -T2           => evidence/nmap_top100.txt
#  - --top-ports 1000 (killed: exceeded 290s cap, partial only => evidence/nmap_top1000.txt)
#  - extended 43-port subset @ -T2 --max-rate 64   => evidence/nmap_extended_subset.txt (0 extra open)
#
# Open TCP services (6), verified by -sT connect scan:
#  22/tcp   open  ssh        OpenSSH 9.6p1 Ubuntu 3ubuntu13.19 (protocol 2.0)   [evidence/nmap_sv_http_ssh.txt]
#  53/tcp   open  domain     Unbound (TCP)                                      [evidence/nmap_sv_53.txt]
#  80/tcp   open  http       nginx 1.28.3  (Server: nginx/1.28.3; NOW returns HTTP 200 app directly) [evidence/nmap_sv_http_ssh.txt + evidence/http_baseline_headers.txt]
#  443/tcp  open  ssl/http   nginx (TLS1.3, LE cert; version banner suppressed on TLS) [evidence/nmap_sv_http_ssh.txt]
#  5060/tcp open  sip?       no SIP banner/response via connect scan            [evidence/nmap_sv_5060.txt]
#  8080/tcp open  http-proxy? accepts TCP, closes on HTTP GET (unknown service) [evidence/nmap_sv_8080.txt]
#
# Application fingerprint:
#  nginx/1.28.3 (stable/mainline; released Apr 2025). No CVEs known against 1.28.3 as of scan date.
#  X-Powered-By: Next.js  + turbopack chunk + Vary: rsc,next-router-state-tree,...  => Next.js 15.x App Router (RSC enabled)
#  React version "19.3.0-canary-3f0b9e9fe" observed in served chunk 0lclmgfn-n7l1.js (build id 0lclmgfn-n7l1)
#  => RSC 'Flight' protocol in use; consistent with the CVE-2025-55182 / CVE-2025-66478 (React2Shell) exposure class.
#  nginx serves both 80 and 443 directly on this box (EC2 ap-south-1, Ubuntu 24.04 'noble' from OpenSSH pkg tag).
