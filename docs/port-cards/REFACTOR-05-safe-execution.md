# REFACTOR-05 — safe_execution + toolset → VAPT tools + gate

**Status: ✅ DONE (P1) for dispatcher/gate + core tools · ✅ DONE (P3)
for the VAPT toolset (tools/vapt/) · ✅ DONE (P4) for the
operator-attached runtimes (tools/vapt/operator.py)**
· Target: `hypervisor/tools/base.py`, `hypervisor/tools/core.py`,
  `hypervisor/tools/vapt/`, `hypervisor/permissions.py`
· Source: `src/tools/safe_execution.py` (600 lines) + the toolset
  (system_tools_v2, web_tools_v2, network_tools, mobile_tools,
  passive_scanner, memory_tools_v2)

Tools become data with a single dispatcher (Skeleton 9-2): name,
schema, concurrency class, safety class, renderer. The gate
(permissions.py, PORT-09) is the sole authority — safe_execution's
scattered checks consolidate there. Every tool: duration-bounded,
journal-audited (tool_call/tool_result + permission_decision),
observer-spanned. Known 3.x gaps close structurally: path resolution
through the workspace-bound resolver (mobile_tools traversal), shell
output caps (CC's 30K-cap/BashTool discipline), no scope check may
ever default-open. Acceptance: each tool's oracle-parity fixtures pass
inside scope and are refused outside it; traversal payloads rejected;
output caps enforced with truncation markers.

## Landing results (P1)

- Skeleton 9-2 landed: Tool protocol (name/aliases/input_schema/
  safety_class/concurrency_safe/is_persistent/extract_targets/
  validate_input/max_result_chars/timeout_s/cancel_siblings_on_error/
  path_args), ToolRegistry with boot-time freeze (byte-stable wire
  array — identical registries serialize identically), stdlib JSON
  Schema validator (deterministic error text).
- Dispatcher: 7-step pipeline per call (resolve → abort → schema →
  semantic → permission gate → bounded execute via wait_for → capped
  render); batching per toolOrchestration.ts (runs of concurrency-safe
  tools parallel under Semaphore(10), unsafe tools serialize their
  batch); a shell-class error cancels pending siblings
  (StreamingToolExecutor.ts rule).
- Core tools shipped: run_command (process groups, per-command
  timeout, dangerous patterns + interactive traps + local-only
  semantics at ORACLE parity — the local-only list stays exactly the
  3.7.3 eight), read/write/edit (unique-match contract), ls, glob
  (mtime order), grep (3 modes, binary-skip, bounded), todo_write
  (single in_progress invariant).
- Output management ported with the B2 char-cap fix: head ≤60% /
  tail ≤15% regardless of line count; oversized output lands WHOLE in
  a 0600 buffer under {workspace}/buffers/ with manifest + rotated
  redacted audit log (M7+H4); the advertised path is readable back
  through the resolver.
- All acceptance items green in test_tools.py (36 tests) and E2E.

## Landing results (P3 — the VAPT toolset)

- tools/vapt/recon.py: network_scan_nmap (the oracle's N5 argument
  blocklist: ; | & ` $ newlines; scope-gated on the target; a 4.0
  plain-text structured parse with the raw fallback — jc is not a
  dependency), check_port_listener, passive_scan (the FULL oracle
  pattern battery as an explicit local tool), generate_oob_payload /
  poll_oob_interactions (AEGIS_OOB_DOMAIN, workspace/oob receiver
  contract).
- tools/vapt/web.py: advanced_http_request (method/url/data/headers/
  cookies/redirects; GET/HEAD/OPTIONS read-class, others exploit;
  response + headers through the passive scanner),
  retrieve_url_content, detect_waf, headless_dom_navigate/interact
  (STATIC-DOM engine — link/form extraction + form submission; the
  prompts state plainly that JS does not run), web_search_osint
  (AEGIS_OSINT_ENDPOINT-gated — no invented results), map_vhost.
- tools/vapt/exec.py: execute_code / execute_exploit_script — the
  bounded harness (0600 workspace scratch, [sys.executable, -I],
  process-group kill on timeout) with command-target scope extraction
  over the code text and the persistence battery (PoC-only RoE
  refuses useradd/cron/authorized_keys/webshell classes BEFORE
  execution).
- tools/vapt/report.py: compile_report — the evidence-chained
  engagement report from the EKD (severity-ordered findings with
  evidence ids + affected entities; every claim carries its id —
  Table 11's reporting bar made mechanical).
- tools/vapt/misc.py: sequential_thinking, analyze_entropy (Shannon
  + class breakdown + base64/hex plausibility), crypto_analyzer
  (xor/base64/hex/rot13/rot47/reverse — block ciphers REFUSED: the
  stdlib-only dependency contract carries no crypto library),
  list_buffers, analyze_apk / analyze_ipa (zipfile static analysis:
  inventory, manifest strings, permissions/ATS flags, embedded URLs,
  secret-pattern alerts, sha256; paths workspace-resolved).
- Tool names pinned by the Tier-A extractor routing
  (memory/extractors.py _TIER_A_PARSERS / _FREE_TEXT_TOOLS) so
  extraction parity holds unchanged.
- Gate hardening found by the fixtures: extract_targets_from_command
  gained the code-attribute suffix rule ("subprocess.run", "os.path"
  et al. are not hostnames — the curated _CODE_ATTR_SUFFIXES set).
- build_registry() defaults to the PLATFORM set; the composition
  root (CLI) opts in with include_vapt=True, include_task=True;
  AEGIS_VAPT_TOOLS=0 trims the family at boot.
- Deferred with rationale: frida_hook / mitm_intercept /
  ssh_interactive_exec need devices, daemons or interactive
  transports a stdlib-only bounded harness cannot host honestly —
  they land with the operator-side runtime attachment (P4 — landed,
  see the P4 section below).
- Acceptance green: test_vapt_tools.py (22 tests) — oracle-parity
  fixtures pass inside scope and refuse outside; traversal payloads
  rejected; output caps enforced with truncation markers; N5
  sanitization; PoC-only battery; local-server HTTP round-trip.

## Landing results (P4 — the operator-attached runtimes)

- tools/vapt/operator.py: frida_hook, mitm_intercept,
  ssh_interactive_exec — the three tools deferred from P3, landed
  as operator-attached runtimes. The contract per tool: binary
  availability probed HONESTLY at call time (shutil.which; a
  missing runtime returns a plain error naming the attachment,
  never a fabricated result); execution rides the bounded-subprocess
  discipline (0600 workspace scratch for generated scripts, process
  groups, hard wall-clock, captured-whole-then-capped output).
- The oracle's unbounded background sessions (SafeShellSession +
  sleep + poll) became BOUNDED CAPTURE WINDOWS: run for `duration`
  seconds (default 20, max 120), harvest stdout through a
  reader-task (chunks land as they arrive — a cancelled
  communicate() would silently discard partial output; the P4
  fixtures caught this), then SIGKILL the group. Principle 9 beats
  interactive convenience; the model gets the window in one honest
  result.
- frida_hook: the oracle's 4-script battery ported verbatim
  (ssl_pinning / root_detect / crypto_intercept / api_monitor,
  byte-anchored in tests) + custom workspace scripts resolved
  through the shared resolver (traversal refused at the gate);
  emulator transport via -H 127.0.0.1:27042.
- mitm_intercept: the InterceptApp addon ported verbatim; the
  oracle's proxy-configuration block (android/ios proxy commands,
  mitm.it CA step, frida pairing hint) rides the result.
- ssh_interactive_exec: the oracle's fabric/invoke implementation
  (third-party PTY plumbing) replaced by the system ssh binary
  under the bounded harness — key auth by default, password auth
  via operator-hosted sshpass when provided (honestly gated),
  hardened -o options (ForwardAgent=no, ClearAllForwardings=yes,
  StrictHostKeyChecking=accept-new, ConnectTimeout=15,
  BatchMode), sudo with -S password plumbing, scope-gated on the
  bare-host convention (the gate's is_authorized matches rules on
  the host), PoC-only persistence battery in validate_input AND at
  call time, password redacted from any result text.
- Registry composition: build_vapt_tools(include_operator=True)
  default; AEGIS_OPERATOR_TOOLS=0 trims the family at boot; the
  doctor probes all four binaries (frida/mitmdump/ssh/sshpass) and
  reports their attachment state.
- Acceptance green: test_operator_tools.py (18 tests) + the P4
  E2E (fake frida runtime, stop-hook, replay, SLO in one
  engagement).
