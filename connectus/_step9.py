#!/usr/bin/env python3
"""Step 9 driver: handler param coverage for each id.
PASS -> markpass 'handler param coverage'. FAIL -> report, do NOT markpass.
Usage: _step9.py <id1> [<id2> ...]
"""
import json
import re
import subprocess
import sys

ROOT = "/Users/yhayun/dev/demisto/content"


def run(cmd):
    return subprocess.run(cmd, cwd=ROOT, capture_output=True, text=True)


def _extract_json(text):
    """Return the last valid top-level JSON object in text, or None.

    The coverage script emits diagnostic lines (containing Python set
    literals like {'a', 'b'}) before the real JSON, so we scan for the
    last balanced {...} block that actually parses as JSON.
    """
    starts = [i for i, ch in enumerate(text) if ch == "{"]
    for start in reversed(starts):
        depth = 0
        for end in range(start, len(text)):
            if text[end] == "{":
                depth += 1
            elif text[end] == "}":
                depth -= 1
                if depth == 0:
                    chunk = text[start:end + 1]
                    try:
                        return json.loads(chunk)
                    except json.JSONDecodeError:
                        break
    return None


def main(ids):
    passed, failed, errored = [], [], []
    for iid in ids:
        cov = run([
            "python3", "connectus/check_handler_param_coverage.py",
            "--integration-id", iid, "--json",
        ])
        j = _extract_json(cov.stdout)
        if j is None:
            errored.append((iid, (cov.stderr or cov.stdout).strip()[-300:]))
            continue
        if j.get("pass"):
            mp = run(["python3", "connectus/workflow_state.py", "markpass", iid, "handler param coverage"])
            if mp.returncode == 0:
                passed.append(iid)
            else:
                errored.append((iid, "markpass failed: " + mp.stderr.strip()[-200:]))
        else:
            failed.append((iid, j.get("missing", []), j.get("ignored_params", [])))

    print("\n==== STEP 9 RESULTS ====")
    for iid in passed:
        print(f"[PASS] {iid}")
    for iid, miss, ign in failed:
        print(f"[FAIL] {iid} :: missing={miss} ignored={ign}")
    for iid, err in errored:
        print(f"[ERR ] {iid} :: {err}")
    print(f"\n{len(passed)} passed, {len(failed)} failed, {len(errored)} errored (of {len(ids)})")
    return 0 if not failed and not errored else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
