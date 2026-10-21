=== ENGAGEMENT KNOWLEDGE (rev 315 · updated 3s ago by tier_a:edit_file · budget 700) ===

OBJECTIVE
  O2 (verbatim): "Phases 1-2 on innspark.in (self-owned, full scope): passive subdomain enumeration and ownership classification, then rate-capped port/service mapping and endpoint inventory. Hard stop for operator review before Phase 3."
  O1 (follow-up): "Scoped pilot PILOT-01, scope fingerprint sha256:d827a996ee201aca@v1: assess 10.10.0.5 within the signed scope only. Start immediately with service enumeration of the authorized ports (22, 80, 443); spend at most one turn on workspace setup. (1) enumerate authorized services with full-notice scans; (2) identify versions and patch levels against known CVEs; (3) verify at most one non-destructive PoC per confirmed exposure class, PoC-only per RoE. Keep every artifact under the workspace, track the plan with todo_write, and finish with a structured findings summary citing the scope fingerprint sha256:d827a996ee201aca@v1 and per-finding evidence paths. Then stop."

TASKS: 0 running · 0 blocked · 10 done

ATTACK SURFACE (64 entities · 41 in scope · 23 adjacent · mode=strict)
  e1 host 10.10.0.5 · 80 · 7 calls · ADJACENT (visible, never targeted)
  e19 endpoint https://www.innspark.in/ · 4 calls
  e12 domain innspark.in · 3 calls
  e65 endpoint https://www.innspark.in/resource · 2 calls
  e64 endpoint https://www.innspark.in/healthcare · 2 calls
  e63 endpoint https://www.innspark.in/telematics · 2 calls
  e62 endpoint https://www.innspark.in/demo · 2 calls
  e61 endpoint https://www.innspark.in/awards-recognition · 2 calls
  e60 endpoint https://www.innspark.in/certifications · 2 calls
  e59 endpoint https://www.innspark.in/gem-marketplace · 2 calls
  e58 endpoint https://www.innspark.in/about-us · 2 calls
  e57 endpoint https://www.innspark.in/nbad-product · 2 calls
  +52 more entities — memory_query('e56')

RESIDUAL NOTES: none recorded.

DRILLDOWN: every id above is queryable via memory_query.