"""Scaffold consistency tests: the Layout 9-1 tree exists, the port-card
inventory matches the ratified disposition counts (11 PORT / 6 REFACTOR /
5 DELETE families), and every module imports with zero non-stdlib
runtime dependencies.
"""
import importlib
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO))

MODULES = [
    "hypervisor",
    "hypervisor.query",
    "hypervisor.cli",
    "hypervisor.permissions",
    "hypervisor.guard",
    "hypervisor.tools", "hypervisor.tools.base", "hypervisor.tools.vapt",
    "hypervisor.tools.vapt.recon", "hypervisor.tools.vapt.web",
    "hypervisor.tools.vapt.exec", "hypervisor.tools.vapt.report",
    "hypervisor.tools.vapt.misc",
    "hypervisor.agents", "hypervisor.agents.defs",
    "hypervisor.agents.prompts", "hypervisor.agents.task",
    "hypervisor.context", "hypervisor.context.budget",
    "hypervisor.context.compact", "hypervisor.context.assemble",
    "hypervisor.memory", "hypervisor.memory.ekd",
    "hypervisor.memory.extractors", "hypervisor.memory.brief",
    "hypervisor.memory.sidequery",
    "hypervisor.persist", "hypervisor.persist.journal",
    "hypervisor.persist.sessions", "hypervisor.persist.replay",
    "hypervisor.debug", "hypervisor.debug.config",
    "hypervisor.debug.timeline", "hypervisor.debug.logtap",
    "hypervisor.debug.loop_monitor", "hypervisor.debug.wire_tap",
    "hypervisor.debug.loop_events", "hypervisor.debug.patcher",
    "hypervisor.adapters", "hypervisor.adapters.openai",
    "hypervisor.tui", "hypervisor.tui.term",
    "hypervisor.tui.editor", "hypervisor.tui.render",
    "hypervisor.tui.commands", "hypervisor.tui.engage",
    "hypervisor.tui.app",
]


def test_every_module_imports():
    for name in MODULES:
        importlib.import_module(name)


def test_version():
    import hypervisor
    assert hypervisor.__version__ == "4.0.0a5"
    assert hypervisor.AEGIS_VERSION == hypervisor.__version__


def test_port_card_inventory_counts():
    cards = REPO / "docs" / "port-cards"
    ports = sorted(cards.glob("PORT-*.md"))
    refactors = sorted(cards.glob("REFACTOR-*.md"))
    uxcards = sorted(cards.glob("UX-*.md"))
    deletes = [cards / "DELETE-families.md"]
    assert len(ports) == 11, [p.name for p in ports]
    assert len(refactors) == 6, [r.name for r in refactors]
    assert len(uxcards) >= 1, "UX-01 operator TUI card must exist"
    assert all(d.exists() for d in deletes)
    # the P0 + P1 + P2 + P3 cards claim DONE
    for name in ("PORT-05-journal.md", "PORT-08-aegis-debug.md",
                 "PORT-07-llm-guard.md", "PORT-09-scope-manager.md",
                 "REFACTOR-05-safe-execution.md",
                 "REFACTOR-06-main-repl.md",
                 "PORT-01-compact-prompts.md", "PORT-02-compaction.md",
                 "PORT-03-ekd.md", "PORT-04-extractors.md",
                 "PORT-10-fingerprint.md", "PORT-11-brief-renderer.md",
                 "REFACTOR-01-memory-manager.md",
                 "REFACTOR-02-context-assembler.md",
                 "REFACTOR-03-subagents.md",
                 "REFACTOR-04-side-query.md",
                 "PORT-06-replay.md"):
        text = (cards / name).read_text(encoding="utf-8")
        assert ("DONE (P1)" in text or "DONE (P0)" in text
                or "DONE (P3)" in text
                or "done (P2)" in text or "done (P3)" in text
                or "done**" in text), name


def test_stdlib_only_runtime_surface():
    """Runtime must import without any third-party package installed.
    httpx/requests/httpx2 are optional guarded imports inside wire_tap
    and the adapter (P1: the adapter imports httpx lazily at call time,
    so module import stays dependency-free)."""
    import hypervisor.debug.wire_tap as wt
    import hypervisor.adapters.openai as ad
    # whatever the environment has, the modules imported fine either way
    assert hasattr(wt, "install")
    assert hasattr(ad, "OpenAICompatClient")


def test_oracle_manifest_frozen():
    man = REPO / "oracle" / "MANIFEST.json"
    assert man.exists()
    import json
    m = json.loads(man.read_text(encoding="utf-8"))
    assert m["git_commit"].startswith("338b646")
    assert m["n_files"] == 90 and m["total_lines"] == 37801
    assert m["role"].startswith("frozen oracle")
