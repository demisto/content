#!/usr/bin/env python3
"""Step 8 driver: generate manifest, set-connector-path, markpass for each id.
Processes ids in the given order (so first of a connector group scaffolds, rest append).
Usage: _step8.py <id1> [<id2> ...]
Prints a per-id PASS/FAIL line; exits 0 if all passed.
"""
import json
import subprocess
import sys

ROOT = "/Users/yhayun/dev/demisto/content"
CONNECTORS_ROOT = "../unified-connectors-content/connectors"


def run(cmd, **kw):
    return subprocess.run(cmd, cwd=ROOT, capture_output=True, text=True, **kw)


def ws(*args):
    return run(["python3", "connectus/workflow_state.py", *args])


def slug_of(connector_id):
    s = connector_id.lower()
    # collapse internal whitespace runs to single dash
    parts = [p for p in s.split()]
    return "-".join(parts)


def main(ids):
    results = []
    for iid in ids:
        try:
            ctx = json.loads(ws("context", iid).stdout)
            cid = ctx["connector_id"]
            yml = ctx["file_paths"]["yml"]
            mapped = ws("show-step", "--raw", iid, "Params to Capabilities").stdout.strip()
            auth = ws("show-step", "--raw", iid, "Auth Details").stdout.strip()

            gen = run([
                "python3", "connectus/connectus_migration/manifest_generator.py",
                yml, cid, mapped, auth,
                "--connectors-root", CONNECTORS_ROOT,
            ])
            if gen.returncode != 0:
                results.append((iid, "FAIL-GEN", gen.stderr.strip()[-600:] or gen.stdout.strip()[-600:]))
                continue

            slug = slug_of(cid)
            scp = ws("set-connector-path", iid, f"connectors/{slug}")
            if scp.returncode != 0:
                results.append((iid, "FAIL-SETPATH", scp.stderr.strip()[-400:] or scp.stdout.strip()[-400:]))
                continue

            mp = ws("markpass", iid, "generated manifest")
            if mp.returncode != 0:
                results.append((iid, "FAIL-MARKPASS", mp.stderr.strip()[-400:] or mp.stdout.strip()[-400:]))
                continue

            results.append((iid, "PASS", f"connectors/{slug}"))
        except Exception as e:  # noqa: BLE001
            results.append((iid, "ERROR", repr(e)))

    print("\n==== STEP 8 RESULTS ====")
    failed = 0
    for iid, status, detail in results:
        if status != "PASS":
            failed += 1
        print(f"[{status}] {iid}  :: {detail}")
    print(f"\n{len(results) - failed}/{len(results)} passed; {failed} failed")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
