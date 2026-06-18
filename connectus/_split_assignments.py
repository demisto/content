#!/usr/bin/env python3
"""Split jlevypaloalto's connectus-migration assignments into 13 balanced
GROUPS (keeping every connector's integrations together), write one prompt file
per group, and optionally LAUNCH all 13 idex runs in parallel terminals.

Each prompt simply tells idex to load the connectus-migration skill and run
steps 8-10 for the group's integrations, fully autonomously (no confirmations).

Usage (run from the content-repo root):
    python3 connectus/_split_assignments.py            # just (re)generate prompt files
    python3 connectus/_split_assignments.py --launch   # generate + open 13 terminals running idex
    python3 connectus/_split_assignments.py --print     # generate + print the 13 idex commands (copy/paste)
"""
import csv
import os
import subprocess
import sys
from collections import defaultdict

ASSIGNEE = "jlevypaloalto"
NUM_GROUPS = 13
CSV_PATH = "connectus/connectus-migration-pipeline.csv"
OUT_DIR = "connectus/migration-prompts"
REPO_ROOT = os.path.abspath(os.path.dirname(os.path.dirname(__file__)))  # content repo root


def load_groups():
    """Return a list (len NUM_GROUPS) of [(connector, [integration_ids]), ...]."""
    by_connector = defaultdict(list)
    with open(CSV_PATH, newline="") as f:
        for row in csv.DictReader(f):
            if row.get("assignee", "").strip() == ASSIGNEE:
                by_connector[row["Connector ID"].strip()].append(row["Integration ID"].strip())

    # Bin-pack connectors largest-first into the currently-smallest group.
    connectors_sorted = sorted(by_connector.items(), key=lambda kv: (-len(kv[1]), kv[0]))
    groups = [[] for _ in range(NUM_GROUPS)]
    sizes = [0] * NUM_GROUPS
    for conn, ints in connectors_sorted:
        j = sizes.index(min(sizes))
        groups[j].append((conn, ints))
        sizes[j] += len(ints)
    # sort connectors within each group alphabetically for readability
    return [sorted(g, key=lambda kv: kv[0].lower()) for g in groups]


def write_prompts(groups):
    os.makedirs(OUT_DIR, exist_ok=True)
    summary = []
    for idx, group in enumerate(groups, start=1):
        all_ints = [i for _, ints in group for i in ints]
        n = len(all_ints)
        summary.append((idx, n, group))

        id_list = "\n".join(f"- {i}" for i in all_ints)

        content = f"""I am {ASSIGNEE}, running as worker #{idx:02d} of {NUM_GROUPS} \
(use "worker-{idx:02d}" as your identity for any uniquely-named output files). \
Load the connectus-migration skill and run **steps 8-10 only** (generate \
manifest, handler param coverage, run manifest make validate) for each of the \
integrations listed below, one at a time. Run fully autonomously — do NOT ask me \
to confirm anything; do your best on every decision. When done, print a short \
tally of which integrations passed steps 8-10 and any that were blocked.

Integrations ({n}):
{id_list}
"""
        with open(os.path.join(OUT_DIR, f"worker-{idx:02d}.md"), "w") as fh:
            fh.write(content)
    return summary


def worker_idex_command(idx: int) -> str:
    """The shell command that runs idex for one worker, seeded with its prompt."""
    prompt_path = os.path.join(OUT_DIR, f"worker-{idx:02d}.md")
    return f'cd {REPO_ROOT!r} && idex --prompt "$(cat {prompt_path})"'


def launch_all(summary):
    """Open one macOS Terminal.app window per worker, each running idex interactively."""
    if sys.platform != "darwin":
        print("--launch uses macOS Terminal.app via osascript; on other OSes use --print "
              "and paste the commands into your own terminals.", file=sys.stderr)
        return
    for idx, _n, _group in summary:
        cmd = worker_idex_command(idx)
        escaped = cmd.replace("\\", "\\\\").replace('"', '\\"')
        osa = f'tell application "Terminal" to do script "{escaped}"'
        subprocess.run(["osascript", "-e", osa], check=False)
    subprocess.run(["osascript", "-e", 'tell application "Terminal" to activate'], check=False)
    print(f"Launched {len(summary)} Terminal windows, each running idex on its worker prompt.")


def main():
    groups = load_groups()
    summary = write_prompts(groups)

    total = sum(n for _, n, _ in summary)
    print(f"Assignee: {ASSIGNEE} | Total: {total} | Workers: {NUM_GROUPS}")
    print(f"Prompt files: {OUT_DIR}/worker-01.md ... worker-{NUM_GROUPS:02d}.md  (steps 8-10, autonomous)")
    for idx, n, group in summary:
        conns = ", ".join(f"{c}({len(i)})" for c, i in group)
        print(f"  Worker {idx:2d}: {n:2d} | {conns}")
    print(f"Sum check: {total} == {total}")

    if "--launch" in sys.argv:
        print()
        launch_all(summary)
    elif "--print" in sys.argv:
        print("\n# Copy/paste — one idex run per worker:")
        for idx, _n, _g in summary:
            print(worker_idex_command(idx))


if __name__ == "__main__":
    main()
