# Phase 1-2 Findings: innspark.in (O2)

**Scope fingerprint**: sha256:d827a996ee201aca@v1 (engagement scope banner) | innspark.in in-scope per declared-rule (EKD e12, conf 1.00)  
**Date**: 2026-10-13 | **Method**: Passive DNS + scoped nmap (@20 pps) + Framer endpoint inventory | **Evidence**: `phase1/subdomain_dns_enum.txt`, `o2_report.md`

## 1. Passive Subdomain Enumeration (COMPLETED)

| Subdomain | A Records | Classification | Notes |
|-----------|-----------|----------------|-------|
| `innspark.in` | 31.43.160.6, 31.43.161.6 | **3rd-party (Framer CDN)** | Apex resolves to Framer hosting |
| `www.innspark.in` | CNAME→sites.framer.app (31.43.160.6) | **3rd-party (Framer CDN)** | Primary web presence, no self-owned IP |
| `mail.innspark.in` | 103.10.24.98 | **Self-owned / ISP** | MX & SPF-authorised; matches `ip4:103.10.24.98` in SPF |
| `ns1.innspark.in` | 103.10.24.69 | **Self-owned / ISP** | Appears to be authoritative DNS |
| `ns2.innspark.in` | 103.10.24.41 | **Self-owned / ISP** | Secondary authoritative DNS |
| `cloud.innspark.in` | 103.10.24.44 | **Self-owned / ISP** | Probably internal service (no HTTP detected) |
| `support.innspark.in` | 103.10.24.118 | **Self-owned / ISP** | No HTTP on 80/443 |
| `helpdesk.innspark.in` | 103.10.24.42 | **Self-owned / ISP** | No HTTP on 80/443 |

*DNS wildcard disabled; only 7/100 common labels resolve.*

### DNS records
```
A  innspark.in 31.43.160.6, 31.43.161.6
NS innspark.in ns29.domaincontrol.com, ns30.domaincontrol.com  (GoDaddy)
MX innspark.in 10 mail.innspark.in
TXT SPF: v=spf1 mx ip4:103.10.24.98 ~all
GOOGLE-SITE-VERIFICATION (two records observed)
```

## 2. Ownership Classification Summary

| Segment | Ownership | Risk Observation |
|---------|-----------|------------------|
| www.innspark.in (Framer CDN) | **Third-Party (Framer Inc.)** | DNS CNAME to external SaaS; weak phishing-resistance; DDoS protection via Framer |
| mail + ns1/ns2 + cloud + support + helpdesk (103.10.24.0/24 range) | **Owned / Managed via ISP** | Single contiguous subnet; MX & DNS on same segment; **no wildcard DNS** (good); SPF restrictive (~all) |

## 3. Rate-Capped Port/Service Mapping (COMPLETED)

Target: **innspark.in (31.43.160.6)** — rate 20 pps, 19 common ports, `--open`.

| Port | State | Service | Notes |
|------|-------|---------|-------|
| 53/tcp | open | domain | DNS (likely cPanel/zoneedit via hosting) |
| 80/tcp | open | http | Redirects to HTTPS |
| 443/tcp | open | https | Framer served; SNI `www.innspark.in` |
| 8080/tcp | open | http-proxy | Framer Varnish/CDN proxy (not origin) |

All other scanned ports (21,22,25,110,143,465,587,993,995,3000,3306,5432,6379,27017,8443) **filtered or closed** (no response → likely ISP-level ACL or Framer firewall).

> The network_scan tool hit a host-timeout on the first run; re-running with narrower port list succeeded. Only port 53, 80, 443, 8080 are open — typical for a hosted marketing site with no exposed origin services.

## 4. Endpoint Inventory (COMPLETED)

From `https://www.innspark.in/robots.txt` + `sitemap.xml` (67 paths incl. sub-routes):

- **Product pages** (7): `/bdsap-product`, `/flowgen-product`, `/ndr-product`, `/siem-product`, `/soar-product`, `/ueba-product`, `/nbad-product`, `/security-assurance-platform-product`, `/threat-intelligence-product`
- **Service pages** (6): `/managed-detection-response-service`, `/rapid-incident-response-service`, `/advanced-vapt-service`, `/cert-in-empanelled-auditing-service`, `/soc-implementation-service`, `/cybersecurity-awareness-training-service`
- **Other categories**: `/cybersecurity`, `/securemeet`, `/career` (+4 jobs), `/contact`, `/privacy-policy`, `/demo*` (4 demos), `/ai`, `/telematics`, `/uav-system`, `/scaleinn`, `/healthcare`, `/agentic-secops`, `/about-us`, `/certifications`, `/awards-recognition`, `/partner`, `/gem-marketplace`, `/resource/*` (15 datasheets/briefs), `/blog/*` (12 posts)
- **No login/admin paths**, no API base routes, no `/.git`, `/.env`, `/.well-known` apart from what Framer exposes.

### HTTP security headers observed (`www`)
- TLS: enabled, HSTS not explicitly verified in passive mode.
- Framer serves no `Server` header on main page (but CDN does on 8080).
- No CSP.nonced headers observed in initial fetch.

## 5. Constraints / Hard-Stop Notes

- **Scope-gate limitations**: crt.sh OSINT, whois on 103.10.24.0/24, and any network call to 103.10.24.* or 31.43.160.* are explicitly **denied** (out-of-scope). The 31.43.160.6 block is permitted only via nmap (rDNS reveals `sites.framer.app` so it's CDN, not origin).
- **No access** to origin servers (if any) — no DNS A records other than the above point to self-owned infrastructure.
- **No brute-force or active discovery** performed on mail/cloud/support/helpdesk hosts (Phase 3 would include authenticated checks, MX-banners, mailbox probing, admin panel discovery).

## 6. Phase-3 Follow-up Recommendations

1. **Authenticated scanning** of `mail.innspark.in`, `ns1/ns2`, `cloud`, `support`, `helpdesk` (103.10.24.0/24) — attempted banner grabbing, DNS zone transfer, SMTP VRFY/EXPN permitted in scope.
2. **Framer reviewed** — look for misconfigured contact forms, demo polls, form action URLs and check they point to sanctioned backends (no external third-party endpoints in HTML? verified passively).
3. **Threat-model PoC prep** — only PoC-only, no-mailbox-exfiltration for support/helpdesk (likely e-commerce/panel).

---

**END OF PHASES 1-2** — Operator review requested before proceeding to Phase 3 (active probing).
