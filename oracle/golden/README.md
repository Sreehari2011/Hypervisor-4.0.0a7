# oracle/golden/ — golden trajectory capture (executes from P3 A/B)

The frozen 3.7.3 tree is the oracle; golden trajectories are its
*recorded behavior* — the runs the 4.0 rebuild is compared against in
P3 (parallel-run) and P4 (A/B verdict).

## What a golden trajectory is

One scripted objective run against 3.7.3 **with the debug kit and
journal active**, archived as:

```
golden/<objective-id>/
  manifest.json        # objective, scope file sha, model cfg, kit knobs,
                       # 3.7.3 git commit + tree manifest sha
  timeline.jsonl       # the unified aegis_debug timeline (copy)
  journal/             # the engagement journal dir (events + sidecars)
  wire/                # raw LLM wire captures (redacted headers)
  report.md            # the engagement's final report artifact
```

## Why capture is deferred to P3 kickoff

Running the oracle needs the cisai-ultra endpoint and the engagement
scope files — the same inputs the 4.0 side needs. Capturing earlier
would burn model budget against placeholder scopes. The harness below
is complete and dry-runnable today; execution is a P3-kickoff task
(Blueprint Ch. 12: "golden-trajectory capture can extend into P1").

## Running it (P3 kickoff)

```bash
# from the workspace root, with the endpoint up and a scope file ready:
python3 hypervisor-4.0/oracle/golden/capture_golden.py \
    --objective-file <obj.md> --scope-file <scope.yaml> \
    --out hypervisor-4.0/oracle/golden/<objective-id>

# dry-run (validates wiring, writes nothing into the oracle tree):
python3 hypervisor-4.0/oracle/golden/capture_golden.py --dry-run
```

## Discipline

- Golden trajectories are APPEND-ONLY: never edit, never re-run an
  objective-id. A new capture gets a new id.
- Every capture records the tree manifest sha — a capture against a
  drifted tree is invalid by definition (freeze.py --verify gates this).
- Headers are redacted by the wire tap (authorization/x-api-key/cookie);
  bodies are verbatim. Treat the archive as sensitive.
