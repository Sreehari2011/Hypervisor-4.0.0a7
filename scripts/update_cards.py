#!/usr/bin/env python3
"""Update the port-card README statuses for the P3 closeout."""
from pathlib import Path

p = Path("/home/z/my-project/hypervisor-4.0/docs/port-cards/README.md")
t = p.read_text(encoding="utf-8")
t = t.replace(
    'armed since P0), and Table 12-6 lists the side-query as deferrable\n'
    '("optimization layer, never gates"). The Zone-T expansion seam\n'
    '(tail_attachments + tier-0 hygiene) is in place for it.',
    'armed since P0), and Table 12-6 lists the side-query as deferrable\n'
    '("optimization layer, never gates"). The Zone-T expansion seam\n'
    '(tail_attachments + tier-0 hygiene) is in place for it. Both landed\n'
    'in P3 — see the cards.*')
t = t.replace('| persist/replay.py | P3* | ☐ |',
              '| persist/replay.py | P3 | ✅ |')
t = t.replace('| agents/ Task tool + run_agent | P3 |',
              '| agents/ Task tool + run_agent | P3 | ✅ |')
t = t.replace('| loop pre-assembly step | P3* |',
              '| loop pre-assembly step | P3 | ✅ |')
t = t.replace('| tools/vapt/* + permissions.py | P1/P3 | ✅ P1 / ☐ P3 |',
              '| tools/vapt/* + permissions.py | P1/P3 | ✅ P1 / ✅ P3 |')
p.write_text(t, encoding="utf-8")
print("README updated")
