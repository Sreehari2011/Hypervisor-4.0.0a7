"""hypervisor.persist — append-only durability (P0: journal; P1: sessions).

journal.py  engagement journal, PORTED in P0 from 3.7.3 src/journal.py
            (port card PORT-05; J1-J4 contracts preserved, schema v2).
sessions.py 0o600 JSONL session writer with parentUuid chains and
            sidechains (P1, port card REFACTOR-06 references).
"""
