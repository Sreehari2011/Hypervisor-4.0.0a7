"""hypervisor.memory — engagement memory (P2).

ekd.py         the engagement knowledge DAG store (PORT-03: 3.7.3
               src/core/engagement_dag.py + ekd_txn.py — revision
               discipline, EkdBatch write-ahead through the journal,
               bounded snapshots, workspace state + crash recovery).
               Born observed: the debug kit's import hook was armed for
               this module since P0.
extractors.py  Tier-A parsers as tool post-hooks (PORT-04: 3.7.3
               core/dag_extractors.py + the security-entity regex
               battery from semantic_store.py). No LLM in this path —
               ever; the fold auditor (the MD-2 killer) lives here.
brief.py       the EKD brief renderer (PORT-11: the Table 8 L2
               contract carried from engagement_dag.render_brief_l2;
               memory_tiered and the semantic store are DELETE-04 —
               the EKD supersedes them).
"""
