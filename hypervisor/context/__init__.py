"""hypervisor.context — the context engine (P2).

budget.py    window resolution + token budget manager (REFACTOR-01's
             budget half: model_windows.py + memory_budget.py carried;
             the window authority — nothing else guesses the window)
compact.py   the tier ladder (PORT-02 + REFACTOR-01: tier 0 hygiene,
             tier 1 window trim, tier 2 microcompact, tier 3 fold)
             with the 3-failure breaker, direction planner and the
             id-preservation review gate
compact_prompts.py  the verbatim prompt family (PORT-01, byte-frozen)
assemble.py  byte-stable zone assembly (REFACTOR-02: zones S/W/T, the
             single Zone-T injector, pairing-safe grouping, the frozen
             message_sig adapter)
fingerprint.py  the zone drift guard (PORT-10: the M5 triple per
             assembly, per-actor baselines, strict C1 mode)
"""
