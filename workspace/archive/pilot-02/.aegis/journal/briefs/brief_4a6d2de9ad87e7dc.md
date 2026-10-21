=== ENGAGEMENT KNOWLEDGE (rev 223 · updated 0s ago by tier_a:network_scan_nmap · budget 700) ===

OBJECTIVE
  O2 (verbatim): "Phases 1-2 on innspark.in (self-owned, full scope): passive subdomain enumeration and ownership classification, then rate-capped port/service mapping and endpoint inventory. Hard stop for operator review before Phase 3."
  O1 (follow-up): "Scoped pilot PILOT-01, scope fingerprint sha256:d827a996ee201aca@v1: assess 10.10.0.5 within the signed scope only. Start immediately with service enumeration of the authorized ports (22, 80, 443); spend at most one turn on workspace setup. (1) enumerate authorized services with full-notice scans; (2) identify versions and patch levels against known CVEs; (3) verify at most one non-destructive PoC per confirmed exposure class, PoC-only per RoE. Keep every artifact under the workspace, track the plan with todo_write, and finish with a structured findings summary citing the scope fingerprint sha256:d827a996ee201aca@v1 and per-finding evidence paths. Then stop."

TASKS (5 done)
  T10 pending main "Compile pre-Phase-3 findings summary and HARD STOP for operator review"
  T9 pending main "Phase 2b: Endpoint inventory of web services (robots.txt, sitemap, links/forms)"
  T8 pending main "Phase 2a: Rate-capped port/service mapping of innspark.in host(s)"
  T7 pending main "Phase 1b: Ownership classification of discovered subdomains (IP/ASN/provider vs "
  +1 more tasks — memory_query('T6')

ATTACK SURFACE (64 entities · 41 in scope · 23 adjacent · mode=strict)
  e1 host 10.10.0.5 · 80 · 7 calls · ADJACENT (visible, never targeted)
  e19 endpoint https://www.innspark.in/ · 3 calls
  e12 domain innspark.in · 3 calls
  e26 crypto_material b64_token fp:8c705089 · 2 calls · ADJACENT (visible, never targeted)
  e25 endpoint https://fonts.gstatic.com/s/onest/v11/gNMZW3F-SZuj7zOT0IfSjTS16cPh9R-p · 2 calls · ADJACENT (visible, never targeted)
  e24 endpoint https://framerusercontent.com/assets/fuvfFxOBtgp8dpxfKfflt3JU.png · 2 calls · ADJACENT (visible, never targeted)
  e23 endpoint https://framerusercontent.com/images/ntSXOGW59KPlB56PcqctVW32cE.png · 2 calls · ADJACENT (visible, never targeted)
  e22 endpoint https://framerusercontent.com/images/pS1ymlNOpU54mcgilwB7aIJ7g.svg · 2 calls · ADJACENT (visible, never targeted)
  +56 more entities — memory_query('e21')

RESIDUAL NOTES: none recorded.

DRILLDOWN: every id above is queryable via memory_query.