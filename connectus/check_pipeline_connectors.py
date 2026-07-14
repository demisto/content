#!/usr/bin/env python3
"""check_pipeline_connectors — integrity check of the ConnectUs pipeline against disk.

For every integration row in ``connectus-migration-pipeline.csv`` this verifies:

  1. CONNECTOR EXISTS — the connector directory named by the row's
     ``Connector Folder Path`` (relative to ``CONNECTUS_REPO_DIR``) exists on
     disk and contains a ``connector.yaml`` at its root.

  2. HANDLER EXISTS — a handler directory for the integration exists under
     ``<connector>/components/handlers/`` containing a ``handler.yaml``. The
     handler dir name is resolved with the SAME rule the runtime resolver uses:
     ``xsoar-`` + slugify(Integration ID), falling back to the
     underscore-preserving slug variant (see resolver.handler_dir_candidates).

Exit code: 0 if everything is present, 1 if any connector or handler is missing.

Run from the idex PARENT cwd:
    python3 content/connectus/check_pipeline_connectors.py
    python3 content/connectus/check_pipeline_connectors.py --json
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

# Make the package + the params_parity package importable.
_HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(_HERE))                                   # connectus/
sys.path.insert(0, str(_HERE / "runtime_demisto.params_parity"))  # resolver, env_loader

from env_loader import load_env  # noqa: E402
from workflow_state import load_csv  # noqa: E402
# Reuse the resolver's canonical handler-dir candidate logic (slug + underscore
# fallback) so this check matches what the parity preflight actually does.
from resolver import handler_dir_candidates  # noqa: E402


def _repo_dir() -> Path:
    """Resolve the unified-connectors repo dir (where connectors/ lives)."""
    load_env()
    raw = (os.environ.get("CONNECTUS_REPO_DIR") or "").strip()
    if not raw:
        raise SystemExit(
            "CONNECTUS_REPO_DIR is not set. Source content/.env first "
            "(set -a; . content/.env; set +a)."
        )
    return Path(os.path.expanduser(raw)).resolve()


def check(rows: list[dict], repo_dir: Path) -> dict:
    """Run both checks; return a structured result dict."""
    # Connector-level results (deduped by Connector Folder Path).
    connectors: dict[str, dict] = {}
    # Per-integration handler results.
    integrations: list[dict] = []

    missing_connectors: set[str] = set()
    missing_handlers: list[dict] = []

    for r in rows:
        iid = (r.get("Integration ID") or "").strip()
        if not iid:
            continue
        cfp = (r.get("Connector Folder Path") or "").strip()
        cid = (r.get("Connector ID") or "").strip()

        # ---- Connector existence (once per folder path) ----
        if not cfp:
            # No folder path recorded — flag the integration's connector as unknown.
            con_status = {"exists": False, "reason": "no Connector Folder Path in CSV"}
            connectors.setdefault(f"<missing-cfp:{cid or iid}>", con_status)
            connector_ok = False
            connector_dir = None
        else:
            connector_dir = (repo_dir / cfp).resolve()
            if cfp not in connectors:
                con_yaml = connector_dir / "connector.yaml"
                exists = connector_dir.is_dir()
                has_yaml = con_yaml.is_file()
                connectors[cfp] = {
                    "connector_id": cid,
                    "path": str(connector_dir),
                    "dir_exists": exists,
                    "connector_yaml_exists": has_yaml,
                    "exists": exists and has_yaml,
                }
                if not (exists and has_yaml):
                    missing_connectors.add(cfp)
            connector_ok = connectors[cfp]["exists"]

        # ---- Handler existence ----
        handler_found = None
        candidates_abs: list[str] = []
        if connector_dir is not None:
            handlers_root = connector_dir / "components" / "handlers"
            for cand in handler_dir_candidates(iid):
                cand_yaml = handlers_root / cand / "handler.yaml"
                candidates_abs.append(str(cand_yaml))
                if cand_yaml.is_file():
                    handler_found = str(cand_yaml)
                    break

        handler_ok = handler_found is not None
        rec = {
            "integration_id": iid,
            "connector_id": cid,
            "connector_folder_path": cfp,
            "connector_ok": connector_ok,
            "handler_ok": handler_ok,
            "handler_path": handler_found,
            "handler_candidates_tried": candidates_abs,
        }
        integrations.append(rec)
        if not handler_ok:
            missing_handlers.append(rec)

    return {
        "repo_dir": str(repo_dir),
        "n_integrations": len(integrations),
        "n_connectors": len(connectors),
        "missing_connectors": sorted(missing_connectors),
        "n_missing_connectors": len(missing_connectors),
        "missing_handlers": missing_handlers,
        "n_missing_handlers": len(missing_handlers),
        "connectors": connectors,
        "integrations": integrations,
    }


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--json", action="store_true", help="Emit full JSON result.")
    args = ap.parse_args(argv)

    repo_dir = _repo_dir()
    rows = load_csv()
    result = check(rows, repo_dir)

    if args.json:
        print(json.dumps(result, indent=2))
        return 0 if (result["n_missing_connectors"] == 0 and result["n_missing_handlers"] == 0) else 1

    # Human-readable report.
    print("=" * 70)
    print("ConnectUs pipeline ⇄ disk integrity check")
    print("=" * 70)
    print(f"Repo dir          : {result['repo_dir']}")
    print(f"Integrations      : {result['n_integrations']}")
    print(f"Distinct connectors: {result['n_connectors']}")
    print(f"Missing connectors : {result['n_missing_connectors']}")
    print(f"Missing handlers   : {result['n_missing_handlers']}")

    if result["missing_connectors"]:
        print("\n--- MISSING CONNECTORS (dir or connector.yaml absent) ---")
        for cfp in result["missing_connectors"]:
            info = result["connectors"][cfp]
            why = []
            if not info.get("dir_exists"):
                why.append("dir missing")
            elif not info.get("connector_yaml_exists"):
                why.append("connector.yaml missing")
            print(f"  ✗ {cfp}  [{info.get('connector_id')}]  ({', '.join(why)})")
            print(f"      {info.get('path')}")

    if result["missing_handlers"]:
        print("\n--- MISSING HANDLERS (no handler.yaml found) ---")
        for rec in result["missing_handlers"]:
            tag = "" if rec["connector_ok"] else "  (connector also missing)"
            print(f"  ✗ {rec['integration_id']}  [{rec['connector_id']}]{tag}")
            for c in rec["handler_candidates_tried"]:
                print(f"      tried: {c}")

    if result["n_missing_connectors"] == 0 and result["n_missing_handlers"] == 0:
        print("\n✅ ALL GOOD — every connector and every handler is present.")
        return 0
    print("\n❌ Integrity issues found (see above).")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
