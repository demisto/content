#!/usr/bin/env python3
"""results_ledger — Phase 7 results persistence for the param-parity test.

Persists each :mod:`check_param_parity` run to disk as TWO artifacts under
``RESULTS_DIR`` (``<package>/results/``, git-ignored):

  * ``<connector-slug>__<integration-slug>__<UTC-timestamp>.json`` — the full
    envelope written verbatim (append-only audit detail; never overwritten).
  * ``ledger.csv`` — an append-only tracking index, one row per run.

Design of record: ``plans/param-parity-pipeline-integration.md`` (Phase 7) and
``plans/deploy-wave-param-parity-design.md``.

This module is importable + unit-testable in isolation (see
``results_ledger_test.py``). It deliberately has NO dependency on the live
capture machinery — only on :func:`resolver.slugify` so a single slug rule is
shared across the package.
"""

from __future__ import annotations

import copy
import csv
import json
from datetime import datetime, timezone
from pathlib import Path

# Reuse the ONE slug rule from the resolver so connector/integration slugs match
# everywhere in the package.
from resolver import slugify

# ── Where results live ────────────────────────────────────────────────────────
# ``<package dir>/results``. Created lazily on first write. Git-ignored (see the
# package .gitignore). Tests monkeypatch this to a tmp_path.
RESULTS_DIR = Path(__file__).resolve().parent / "results"


# Exact ledger columns. One row PER VARIANT (the multi-capability variant matrix
# — see ``multi_capability_variant_design.md``), so ``variant_id`` is included.
LEDGER_COLUMNS = [
    "timestamp",
    "integration_id",
    "connector_slug",
    "variant_id",
    "status",
    "n_fail",
    "result_file",
]

LEDGER_FILENAME = "ledger.csv"

# UTC timestamp format used for BOTH the JSON filename and the ledger row, e.g.
# ``20260607T170006Z``.
_TIMESTAMP_FMT = "%Y%m%dT%H%M%SZ"


def _utc_stamp(when: datetime | None = None) -> str:
    """Return the canonical ``YYYYMMDDTHHMMSSZ`` UTC stamp.

    ``when`` is injectable for deterministic tests. A naive ``when`` is treated
    as UTC; an aware ``when`` is converted to UTC.
    """
    if when is None:
        when = datetime.now(timezone.utc)
    elif when.tzinfo is not None:
        when = when.astimezone(timezone.utc)
    return when.strftime(_TIMESTAMP_FMT)


def result_filename(
    connector_id: str,
    integration_id: str,
    when: datetime | None = None,
) -> str:
    """Build the per-run JSON filename.

    ``<connector-slug>__<integration-slug>__<UTC-timestamp>.json``
    e.g. ``salesforce__salesforce-iam__20260607T170006Z.json``.

    ``when`` is injectable for tests.
    """
    connector_slug = slugify(connector_id)
    integration_slug = slugify(integration_id)
    return f"{connector_slug}__{integration_slug}__{_utc_stamp(when)}.json"



def write_result(
    envelope: dict,
    *,
    connector_id: str,
    integration_id: str,
    when: datetime | None = None
) -> Path:
    """Write ``envelope`` JSON to ``RESULTS_DIR/<result_filename>``.

    ``when`` is injectable so the filename + ledger row share one timestamp.
    Returns the :class:`~pathlib.Path` of the written file.
    """
    RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    payload =  envelope
    out_path = RESULTS_DIR / result_filename(connector_id, integration_id, when=when)
    out_path.write_text(json.dumps(payload, indent=2, sort_keys=False, default=str))
    return out_path


def _ledger_rows_for(envelope: dict) -> list[dict]:
    """Build the per-VARIANT ledger rows from an aggregate envelope.

    The aggregate envelope carries a ``variants[]`` list; we emit ONE row per
    variant (with its own ``variant_id``/``status``/``n_fail``). For backward
    compatibility, an envelope WITHOUT ``variants`` (a legacy single-diff shape)
    yields a single row with an empty ``variant_id``.
    """
    variants = envelope.get("variants")
    if isinstance(variants, list) and variants:
        rows = []
        for v in variants:
            rows.append(
                {
                    "variant_id": v.get("variant_id", ""),
                    "status": v.get("status"),
                    "n_fail": (v.get("summary") or {}).get("n_fail"),
                }
            )
        return rows
    # Legacy / single-diff envelope.
    return [
        {
            "variant_id": "",
            "status": envelope.get("status"),
            "n_fail": (envelope.get("summary") or {}).get("n_fail"),
        }
    ]


def append_ledger(
    envelope: dict,
    *,
    integration_id: str,
    connector_id: str,
    result_file: str,
    when: datetime | None = None,
) -> None:
    """Append one row PER VARIANT to ``RESULTS_DIR/ledger.csv`` (header if new).

    Columns (exact):
    ``timestamp,integration_id,connector_slug,variant_id,status,n_fail,result_file``.

    * one row per ``envelope["variants"][]`` (its ``variant_id``/``status``/
      ``summary.n_fail``); a legacy envelope without ``variants`` yields one row
      with an empty ``variant_id``.
    * ``result_file`` = the JSON filename (basename only — pass ``path.name``).
    * ``timestamp`` = the UTC stamp; pass the SAME ``when`` used for the filename.
    """
    RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    ledger_path = RESULTS_DIR / LEDGER_FILENAME
    write_header = not ledger_path.exists()

    stamp = _utc_stamp(when)
    connector_slug = slugify(connector_id)
    rows = [
        {
            "timestamp": stamp,
            "integration_id": integration_id,
            "connector_slug": connector_slug,
            "variant_id": r["variant_id"],
            "status": r["status"],
            "n_fail": r["n_fail"],
            "result_file": result_file,
        }
        for r in _ledger_rows_for(envelope)
    ]

    with ledger_path.open("a", newline="") as fh:
        writer = csv.DictWriter(fh, fieldnames=LEDGER_COLUMNS, quoting=csv.QUOTE_MINIMAL)
        if write_header:
            writer.writeheader()
        for row in rows:
            writer.writerow(row)
