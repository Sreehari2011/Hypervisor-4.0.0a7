=== ENGAGEMENT KNOWLEDGE (rev 338 · updated 8s ago by tier_a:ls · budget 700) ===

OBJECTIVE
  O2 (verbatim): "Phases 1-2 on innspark.in (self-owned, full scope): passive subdomain enumeration and ownership classification, then rate-capped port/service mapping and endpoint inventory. Hard stop for operator review before Phase 3."
  O1 (follow-up): "Scoped pilot PILOT-01, scope fingerprint sha256:d827a996ee201aca@v1: assess 10.10.0.5 within the signed scope only. Start immediately with service enumeration of the authorized ports (22, 80, 443); spend at most one turn on workspace setup. (1) enumerate authorized services with full-notice scans; (2) identify versions and patch levels against known CVEs; (3) verify at most one non-destructive PoC per confirmed exposure class, PoC-only per RoE. Keep every artifact under the workspace, track the plan with todo_write, and finish with a structured findings summary citing the scope fingerprint sha256:d827a996ee201aca@v1 and per-finding evidence paths. Then stop."

TASKS (6 done)
  T11 pending main "Write consolidated Phase 1-2 artifacts to workspace; hard stop before Phase 3"
  T5 pending main "Compile structured findings summary citing scope fingerprint sha256:d827a996ee20"
  T4 pending main "Run at most one non-destructive PoC per confirmed exposure class (PoC-only RoE)"
  T3 pending main "Map identified versions to known CVEs / patch levels"
  +1 more tasks — memory_query('T2')

ATTACK SURFACE (64 entities · 41 in scope · 23 adjacent · mode=strict)
  e1 host 10.10.0.5 · 80 · 7 calls · ADJACENT (visible, never targeted)
  e19 endpoint https://www.innspark.in/ · 5 calls
  e32 endpoint https://www.innspark.in/privacy-policy · 3 calls
  e31 endpoint https://www.innspark.in/contact · 3 calls
  e30 endpoint https://www.innspark.in/career · 3 calls
  e29 endpoint https://www.innspark.in/securemeet · 3 calls
  e28 endpoint https://www.innspark.in/cybersecurity · 3 calls
  e18 endpoint https://www.innspark.in/sitemap.xml · 3 calls
  e12 domain innspark.in · 3 calls
  e65 endpoint https://www.innspark.in/resource · 2 calls
  e64 endpoint https://www.innspark.in/healthcare · 2 calls
  e63 endpoint https://www.innspark.in/telematics · 2 calls
  +52 more entities — memory_query('e62')

RESIDUAL NOTES: none recorded.

DRILLDOWN: every id above is queryable via memory_query.