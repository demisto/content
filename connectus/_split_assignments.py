#!/usr/bin/env python3
"""One-off helper: split jlevypaloalto's connectus-migration assignments into
13 balanced branches (keeping every connector's integrations together) and
emit one prompt file per branch for parallel CLI runs.

Run from the content-repo root:  python3 connectus/_split_assignments.py
"""
import csv
import os
from collections import defaultdict

ASSIGNEE = "jlevypaloalto"
NUM_BRANCHES = 13
CSV_PATH = "connectus/connectus-migration-pipeline.csv"
OUT_DIR = "connectus/migration-prompts"

# 1. Load this assignee's rows, grouped by connector (preserve CSV order).
by_connector = defaultdict(list)
order = []
with open(CSV_PATH, newline="") as f:
    for row in csv.DictReader(f):
        if row.get("assignee", "").strip() == ASSIGNEE:
            conn = row["Connector ID"].strip()
            if conn not in by_connector:
                order.append(conn)
            by_connector[conn].append(row["Integration ID"].strip())

total = sum(len(v) for v in by_connector.values())

# 2. Bin-pack connectors into NUM_BRANCHES branches, largest-connector-first,
#    always dropping the next connector into the currently-smallest branch.
#    This keeps every connector intact and balances branch sizes (~10 each).
connectors_sorted = sorted(by_connector.items(), key=lambda kv: (-len(kv[1]), kv[0]))
branches = [[] for _ in range(NUM_BRANCHES)]          # list of (connector, [ints])
branch_sizes = [0] * NUM_BRANCHES
for conn, ints in connectors_sorted:
    j = branch_sizes.index(min(branch_sizes))
    branches[j].append((conn, ints))
    branch_sizes[j] += len(ints)

# 3. Emit a prompt file per branch.
os.makedirs(OUT_DIR, exist_ok=True)
summary = []
for idx, branch in enumerate(branches, start=1):
    # sort connectors within a branch alphabetically for readability
    branch_sorted = sorted(branch, key=lambda kv: kv[0].lower())
    all_ints = [i for _, ints in branch_sorted for i in ints]
    n = len(all_ints)
    summary.append((idx, n, branch_sorted))

    bullet_lines = []
    for conn, ints in branch_sorted:
        bullet_lines.append(f"- **{conn}** ({len(ints)})")
        for i in ints:
            bullet_lines.append(f"  - {i}")
    integrations_block = "\n".join(bullet_lines)

    # quoted, comma-separated id list for easy copy/paste
    id_csv = ", ".join(f'"{i}"' for i in all_ints)

    content = f"""# ConnectUs Migration — Branch {idx} of {NUM_BRANCHES}

> Generated batch prompt for parallel migration runs. Assignee: `{ASSIGNEE}`.
> This branch contains **{n} integrations** across **{len(branch_sorted)} connector(s)**.

## Your task

Load the **connectus-migration** skill and migrate the integrations listed
below, one at a time, following the full 15-step per-integration workflow.
Work connector-by-connector (auth/params are similar within a connector, so
doing them back-to-back compounds learning). After each integration, print a
short progress recap (`X/{n} done — next: <integration id>`).

Use a dedicated git branch for this batch, e.g.:

```bash
git checkout -b jl-connectus-migration-{idx:02d}
```

## Integrations to migrate (in this order)

{integrations_block}

## Machine-readable id list (for the skill's batch flow)

```
[{id_csv}]
```

## Operating notes

- Source of truth for workflow state is the `workflow_state.py` CLI against
  `connectus/connectus-migration-pipeline.csv`. NEVER edit the CSV directly.
- Start each integration with `python3 content/connectus/workflow_state.py context "<Integration ID>"`.
- Pause-and-confirm only on the 4 JSON-write setters (`set-auth`,
  `set-params-to-commands`, `set-param-defaults`, `set-params-to-capabilities`).
- All other steps (reads, `markpass`, `set-capabilities`, analyzer/validate runs)
  run straight through.
- Run all `workflow_state.py` commands from the idex parent cwd (the dir that
  contains `content/` and `unified-connectors-content/` as siblings), hence the
  `content/` path prefix.
"""
    out_path = os.path.join(OUT_DIR, f"branch-{idx:02d}.md")
    with open(out_path, "w") as fh:
        fh.write(content)

# 4. Print a console summary.
print(f"Assignee: {ASSIGNEE}")
print(f"Total integrations: {total}")
print(f"Branches: {NUM_BRANCHES}")
print(f"Prompt files written to: {OUT_DIR}/branch-01.md ... branch-{NUM_BRANCHES:02d}.md")
print()
for idx, n, branch_sorted in summary:
    conns = ", ".join(f"{c}({len(i)})" for c, i in branch_sorted)
    print(f"  Branch {idx:2d}: {n:2d} integrations | {conns}")
print()
print(f"Sum check: {sum(n for _, n, _ in summary)} == {total}")
