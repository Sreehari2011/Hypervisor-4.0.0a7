=== ENGAGEMENT KNOWLEDGE (rev 525 · updated 14s ago by tier_a:run_command · budget 700) ===

OBJECTIVE
  O2 (verbatim): "Phases 1-2 on innspark.in (self-owned, full scope): passive subdomain enumeration and ownership classification, then rate-capped port/service mapping and endpoint inventory. Hard stop for operator review before Phase 3."
  O1 (follow-up): "Scoped pilot PILOT-01, scope fingerprint sha256:d827a996ee201aca@v1: assess 10.10.0.5 within the signed scope only. Start immediately with service enumeration of the authorized ports (22, 80, 443); spend at most one turn on workspace setup. (1) enumerate authorized services with full-notice scans; (2) identify versions and patch levels against known CVEs; (3) verify at most one non-destructive PoC per confirmed exposure class, PoC-only per RoE. Keep every artifact under the workspace, track the plan with todo_write, and finish with a structured findings summary citing the scope fingerprint sha256:d827a996ee201aca@v1 and per-finding evidence paths. Then stop."

TASKS (6 done)
  T11 pending main "Write consolidated Phase 1-2 artifacts to workspace; hard stop before Phase 3"
  T5 pending main "Compile structured findings summary citing scope fingerprint sha256:d827a996ee20"
  T4 pending main "Run at most one non-destructive PoC per confirmed exposure class (PoC-only RoE)"
  T3 pending main "Map identified versions to known CVEs / patch levels"
  +1 more tasks — memory_query('T2')

ATTACK SURFACE (72 entities · 48 in scope · 24 adjacent · mode=strict)
  e1 host 10.10.0.5 · 80 · 8 calls · ADJACENT (visible, never targeted)
  e10 host 103.10.24.98 · 6 calls · ADJACENT (visible, never targeted)
  e9 host 31.43.161.6 · 6 calls · ADJACENT (visible, never targeted)
  e8 host 31.43.160.6 · 6 calls · ADJACENT (visible, never targeted)
  e19 endpoint https://www.innspark.in/ · 6 calls
  e17 host 103.10.24.42 · 5 calls · ADJACENT (visible, never targeted)
  e16 host 103.10.24.118 · 5 calls · ADJACENT (visible, never targeted)
  e15 host 103.10.24.44 · 5 calls · ADJACENT (visible, never targeted)
  e14 host 103.10.24.41 · 5 calls · ADJACENT (visible, never targeted)
  e13 host 103.10.24.69 · 5 calls · ADJACENT (visible, never targeted)
  e12 domain innspark.in · 4 calls
  e32 endpoint https://www.innspark.in/privacy-policy · 4 calls
  +60 more entities — memory_query('e31')

RESIDUAL NOTES: none recorded.

DRILLDOWN: every id above is queryable via memory_query.