# PORT-09 — Scope manager → permission engine

**Status: ✅ DONE (P1)** · Target: `hypervisor/permissions.py`
· Source: `src/core/engagement_context.py` (892 lines) → 700 lines
  (ScopeManager check semantics + Skeleton 9-3 gate)

## What ports

The engagement scope manager — target ranges, CIDRs, hostnames, port
windows, exclusion lists, the check API, live tightenings
(scope_mode/scope_expansion/scope_cap journal events).

## The standing critical fix (this card is why 4.0 exists)

In every 3.x release through 3.7.3, **enforcement shipped OFF**:
`SCOPE_ENFORCEMENT` defaulted false and `check_scope` returned True
under a "TEST MODE" banner (oracle src/core/engagement_context.py
L338-340; the base repo's most dangerous finding). 4.0 inverts the
default: **enforcement ON, deny-by-default, no test-mode bypass — the
bypass code does not port at all.**

## Contracts preserved

- Scope artifact semantics: what an engagement may touch, expressed as
  the single authorization truth (scoped full-auto: in-scope →
  auto-approve + audit; out-of-scope → deny + audit).
- Live tightenings mid-engagement (scope_mode events).
- Auto-admission candidates + outcomes (scope_expansion), expansion
  cap once-per-engagement (scope_cap).

## 4.0 deltas

- Deny-by-default; every decision (allow AND deny) writes a
  `permission_decision` journal event with the deciding rule, args
  digest, and scope-file sha — the SLO-1 instrument (zero scope
  violations) and the P4 audit exhibit.
- The scope file is operator-signed and versioned; its sha rides every
  event (scope_ref).
- Gate-time composition with tool safety classes (REFACTOR-05).
- Mobile-tool path-traversal gap (analyze_apk raw join) structurally
  closed: all path-bearing tools resolve through the workspace-bound
  resolver the gate enforces.

## Acceptance tests (write on landing)

1. Default-deny: unset/absent scope → every tool refused, journaled.
2. In-scope auto-approve with audit; out-of-scope deny with audit.
3. CIDR/range/host/port-window matrix — oracle parity on the check
   semantics (fixtures from engagement_context's own tests).
4. Live tightening narrows mid-engagement; expansions capped.
5. Path traversal: `../../` payloads rejected by the resolver.

## Landing results (P1)

- **THE STANDING CRITICAL FIX IS CLOSED**: enforcement is ON, deny-by-default,
  and the bypass code DID NOT PORT — an ast-based test scans the module's
  CODE (docstrings excluded) for `SCOPE_ENFORCEMENT` / `TEST MODE` and
  proves no toggle exists (test_unset_scope_means_every_tool_refused).
  Structurally stronger than 3.x: a PermissionEngine cannot even be
  CONSTRUCTED without a loaded scope file, and an empty scope file
  refuses to load.
- Scope file = single authorization truth: sha256-of-canonical-body
  fingerprint, optional operator signature (mismatch refuses to load),
  `scope_ref` rides every permission_decision event.
- Oracle-parity matrix green (17 cases): excludes beat includes in both
  modes, port windows, protocols, expiry, wildcard subtrees, CIDR,
  deny-by-default, malformed targets.
- P0-B admission order preserved: excluded → declared rule →
  expand-mode DNS-subtree admission (capped, journaled scope_expansion,
  once-per-engagement scope_cap) → non-subdomain adjacency.
  Live tightening journals scope_mode and is the ONLY runtime mutation.
- Gate composition (Skeleton 9-3): READ→recon audit, WRITE/EXPLOIT→
  action audit + poc_only persistent-payload veto, DESTRUCTIVE→RoE deny,
  unclassifiable→safest class; path_args declared per tool and resolved
  through the workspace-bound resolver AT GATE TIME (the analyze_apk
  raw-join class is closed structurally, not per-tool).
- All five acceptance items above pass; deny flows back to the model as
  a tool_result error and the engagement continues (scoped full-auto,
  proven E2E against a real socket endpoint).
