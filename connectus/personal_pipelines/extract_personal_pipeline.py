#!/usr/bin/env python3
"""Extract a personal subset of the ConnectUs migration pipeline CSV.

The ConnectUs migration tooling reads a single pipeline CSV
(``connectus/connectus-migration-pipeline.csv``) that tracks every
integration's migration state. That bundled file is shared by everyone and
must never be hand-edited row-by-row.

This script lets you carve out a PERSONAL copy containing only the rows you
care about (your assignments, a connector you own, a handful of explicit
integration IDs, ...) and writes it as a standalone, valid pipeline CSV. You
then point the ``CONNECTUS_PIPELINE_CSV`` environment variable at that file so
the rest of the migration tooling operates on *your* copy instead of the
bundled default.

Workflow
--------
1. Extract your subset::

       python3 connectus/personal_pipelines/extract_personal_pipeline.py --mine

2. Add the printed line to your repo-root ``.env`` (the script never edits
   ``.env`` for you)::

       CONNECTUS_PIPELINE_CSV=connectus/personal_pipelines/joey-schwartz.csv

3. From then on the workflow tooling (``workflow_state.py`` and the
   param-parity resolver) reads your personal file. Relative paths in that
   env var resolve against the repo root; an absolute path works too.

This script only ever READS the main CSV. It never modifies it.

Selectors (at least one is REQUIRED; they are additive / unioned)
-----------------------------------------------------------------
* ``--mine``                rows whose ``assignee`` == ``git config user.name``
* ``--assignee NAME``       rows for a specific assignee (case-insensitive)
* ``--connector ID``        rows for a specific ``Connector ID`` (case-insensitive)
* ``--integration-id ID``   explicit ``Integration ID`` (repeatable, case-insensitive)

The union is de-duplicated by ``Integration ID`` and preserves the row order
of the main file.
"""
from __future__ import annotations

import argparse
import csv
import io
import os
import re
import sys
from pathlib import Path
from typing import Optional

# ---------------------------------------------------------------------------
# Import plumbing — mirror connectus scripts (gates.py / workflow_state.py):
# connectus/ is not a package, so add it to sys.path then import the
# workflow_state package and the shared env loader directly.
# ---------------------------------------------------------------------------
_CONNECTUS_DIR = Path(__file__).resolve().parent.parent
if str(_CONNECTUS_DIR) not in sys.path:
    sys.path.insert(0, str(_CONNECTUS_DIR))

import workflow_state  # noqa: E402
from workflow_state import _git_user_name, list_by_assignee, list_by_connector  # noqa: E402
from workflow_state.config_loader import get_config  # noqa: E402
from workflow_state.csv_io import BASE_DIR  # noqa: E402


#: Directory that homes personal pipeline CSVs (this file's own folder).
PERSONAL_PIPELINES_DIR = Path(__file__).resolve().parent

#: Fallback filename stem when no ``--name`` is given and the git user cannot
#: be determined.
_DEFAULT_STEM = "personal-pipeline"


class ExtractError(Exception):
    """Raised for any user-facing extraction failure (mapped to exit code 1)."""


# ---------------------------------------------------------------------------
# Row selection
# ---------------------------------------------------------------------------

def _list_by_integration_id(
    rows: list[dict[str, str]], integration_id: str
) -> list[dict[str, str]]:
    """Filter rows whose ``Integration ID`` matches (case-insensitive)."""
    target = integration_id.strip().lower()
    return [
        row for row in rows
        if row.get("Integration ID", "").strip().lower() == target
    ]


def select_rows(
    rows: list[dict[str, str]],
    *,
    mine: bool = False,
    assignee: Optional[str] = None,
    connector: Optional[str] = None,
    integration_ids: Optional[list[str]] = None,
    git_user_name: Optional[str] = None,
) -> list[dict[str, str]]:
    """Return the additive union of all selector matches.

    The result is de-duplicated by ``Integration ID`` and preserves the
    order of ``rows`` (the main file). At least one selector must be
    provided — callers should validate that before calling, but this
    function also raises :class:`ExtractError` defensively.

    ``git_user_name`` is the resolved name to use for ``--mine``. When
    ``mine`` is set it must be a non-empty string (the CLI resolves it via
    :func:`workflow_state._git_user_name` and errors out earlier when it is
    unavailable).
    """
    integration_ids = integration_ids or []
    if not (mine or assignee or connector or integration_ids):
        raise ExtractError("No selector provided; nothing to extract.")

    matched: list[dict[str, str]] = []
    if mine:
        if not git_user_name:
            raise ExtractError(
                "--mine requires a git user name but none was resolved."
            )
        matched.extend(list_by_assignee(rows, git_user_name))
    if assignee:
        matched.extend(list_by_assignee(rows, assignee))
    if connector:
        matched.extend(list_by_connector(rows, connector))
    for integration_id in integration_ids:
        matched.extend(_list_by_integration_id(rows, integration_id))

    return _dedup_by_integration_id_preserving_order(rows, matched)


def _dedup_by_integration_id_preserving_order(
    main_rows: list[dict[str, str]],
    matched: list[dict[str, str]],
) -> list[dict[str, str]]:
    """De-dup ``matched`` by ``Integration ID``, ordered as in ``main_rows``."""
    selected_ids = {
        row.get("Integration ID", "").strip().lower()
        for row in matched
        if row.get("Integration ID", "").strip()
    }
    out: list[dict[str, str]] = []
    seen: set[str] = set()
    for row in main_rows:
        key = row.get("Integration ID", "").strip().lower()
        if key and key in selected_ids and key not in seen:
            out.append(row)
            seen.add(key)
    return out


# ---------------------------------------------------------------------------
# CSV writing (mirror csv_io.save_csv settings)
# ---------------------------------------------------------------------------

def render_subset_csv(rows: list[dict[str, str]], header: list[str]) -> str:
    """Render ``rows`` as a CSV string with ``header`` in canonical order.

    Uses the same :class:`csv.DictWriter` configuration as
    :func:`workflow_state.csv_io.save_csv` (``QUOTE_MINIMAL`` quoting,
    ``\\n`` line terminator) so the output is byte-compatible with files
    the workflow tooling produces. Cells are emitted in ``header`` order;
    any keys not in ``header`` are dropped (``extrasaction="ignore"``) and
    missing keys are written as empty strings.
    """
    output = io.StringIO()
    writer = csv.DictWriter(
        output,
        fieldnames=header,
        quoting=csv.QUOTE_MINIMAL,
        lineterminator="\n",
        extrasaction="ignore",
    )
    writer.writeheader()
    for row in rows:
        writer.writerow({col: row.get(col, "") for col in header})
    return output.getvalue()


def write_subset_csv(path: Path, content: str) -> None:
    """Write ``content`` to ``path`` (parent dir created if needed)."""
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8", newline="") as f:
        f.write(content)


# ---------------------------------------------------------------------------
# Destination resolution
# ---------------------------------------------------------------------------

_SLUG_INVALID_RE = re.compile(r"[^a-z0-9]+")


def slugify(value: str) -> str:
    """Lowercase ``value`` and collapse non-alphanumerics into single ``-``.

    e.g. ``"Joey Schwartz"`` -> ``"joey-schwartz"``. Returns ``""`` when
    nothing usable remains (caller falls back to a default stem).
    """
    return _SLUG_INVALID_RE.sub("-", value.lower()).strip("-")


def default_stem(git_user_name: Optional[str]) -> str:
    """Return the default filename stem: slugified git user, else fallback."""
    if git_user_name:
        slug = slugify(git_user_name)
        if slug:
            return slug
    return _DEFAULT_STEM


def resolve_destination(
    *,
    output: Optional[str],
    name: Optional[str],
    git_user_name: Optional[str],
) -> Path:
    """Resolve the absolute destination path.

    Precedence:
      1. ``--output`` (absolute, or relative to the repo root) wins entirely.
      2. ``--name`` (sanitized to a safe filename stem) -> file inside
         :data:`PERSONAL_PIPELINES_DIR`.
      3. Otherwise derive a stem from the git user name (slugified) or fall
         back to ``personal-pipeline``.
    """
    if output:
        expanded = os.path.expanduser(output)
        if os.path.isabs(expanded):
            return Path(expanded).resolve()
        return (Path(BASE_DIR) / expanded).resolve()

    if name:
        stem = slugify(name) or _DEFAULT_STEM
    else:
        stem = default_stem(git_user_name)

    return (PERSONAL_PIPELINES_DIR / f"{stem}.csv").resolve()


def relative_to_repo_root(path: Path) -> str:
    """Return ``path`` relative to the repo root if possible, else absolute."""
    try:
        return str(path.resolve().relative_to(Path(BASE_DIR).resolve()))
    except ValueError:
        return str(path.resolve())


# ---------------------------------------------------------------------------
# Orchestration
# ---------------------------------------------------------------------------

def _selectors_summary(
    *,
    mine: bool,
    assignee: Optional[str],
    connector: Optional[str],
    integration_ids: list[str],
    git_user_name: Optional[str],
) -> str:
    """Human-readable description of which selectors were applied."""
    parts: list[str] = []
    if mine:
        parts.append(f"--mine (git user: {git_user_name!r})")
    if assignee:
        parts.append(f"--assignee {assignee!r}")
    if connector:
        parts.append(f"--connector {connector!r}")
    for integration_id in integration_ids:
        parts.append(f"--integration-id {integration_id!r}")
    return ", ".join(parts) if parts else "(none)"


def _load_main_rows() -> list[dict[str, str]]:
    """Load rows from the main pipeline CSV, converting a missing/unreadable
    file into a clean :class:`ExtractError` (rather than letting a raw
    ``FileNotFoundError`` / ``OSError`` traceback reach the user).

    The message references the path the workflow tooling is actually reading
    (``workflow_state.CSV_PATH`` — the bundled default unless overridden by
    ``CONNECTUS_PIPELINE_CSV``), so the user knows exactly which file is
    missing.
    """
    try:
        return workflow_state.load_csv()
    except (FileNotFoundError, OSError) as exc:
        csv_path = getattr(workflow_state, "CSV_PATH", "<unknown>")
        raise ExtractError(
            f"could not read the pipeline CSV at {csv_path!r}: {exc}.\n"
            "  Expected the bundled file at "
            "connectus/connectus-migration-pipeline.csv (or the path set in "
            "CONNECTUS_PIPELINE_CSV). Check that it exists and is readable."
        ) from exc


def run_extract(
    *,
    mine: bool,
    assignee: Optional[str],
    connector: Optional[str],
    integration_ids: list[str],
    name: Optional[str],
    output: Optional[str],
    force: bool,
    dry_run: bool,
) -> int:
    """Execute the extraction. Returns a process exit code (0 = success).

    Prints all user-facing output. Raises nothing for expected error
    conditions — they are converted to a non-zero return value with a
    clear message on stderr.
    """
    if not (mine or assignee or connector or integration_ids):
        print(
            "ERROR: at least one selector is required "
            "(--mine, --assignee, --connector, or --integration-id).\n"
            "  This tool copies only the rows you select; it will not "
            "duplicate the entire pipeline.",
            file=sys.stderr,
        )
        return 1

    git_user_name: Optional[str] = None
    if mine:
        git_user_name = _git_user_name()
        if not git_user_name:
            print(
                "ERROR: --mine could not determine your git user name "
                "(`git config user.name` returned nothing).\n"
                "  Set it with: git config user.name \"Your Name\"\n"
                "  Or select rows explicitly with --assignee/--connector/"
                "--integration-id.",
                file=sys.stderr,
            )
            return 1

    cfg = get_config()
    header = list(cfg.all_columns)
    rows = _load_main_rows()

    selected = select_rows(
        rows,
        mine=mine,
        assignee=assignee,
        connector=connector,
        integration_ids=integration_ids,
        git_user_name=git_user_name,
    )

    selectors_desc = _selectors_summary(
        mine=mine,
        assignee=assignee,
        connector=connector,
        integration_ids=integration_ids,
        git_user_name=git_user_name,
    )

    if not selected:
        print(
            f"ERROR: no rows matched the selectors used: {selectors_desc}.\n"
            "  Nothing was written (an empty pipeline file is never created).\n"
            "  Check the available assignees / connectors with:\n"
            "    python3 connectus/workflow_state.py list\n"
            "    python3 connectus/workflow_state.py list-connectors",
            file=sys.stderr,
        )
        return 1

    destination = resolve_destination(
        output=output, name=name, git_user_name=git_user_name
    )

    if destination.exists() and not force and not dry_run:
        print(
            f"ERROR: destination already exists: {destination}\n"
            "  Refusing to overwrite. Pass --force to overwrite it, or "
            "choose a different --name/--output.",
            file=sys.stderr,
        )
        return 1

    rel_path = relative_to_repo_root(destination)
    integration_id_list = [r.get("Integration ID", "") for r in selected]

    if dry_run:
        print("DRY-RUN: no file written.")
        print(f"  Selectors:   {selectors_desc}")
        print(f"  Rows:        {len(selected)}")
        print(f"  Destination: {destination}")
        print(f"  Integration IDs: {integration_id_list}")
        return 0

    content = render_subset_csv(selected, header)
    write_subset_csv(destination, content)

    _print_success(
        row_count=len(selected),
        destination=destination,
        rel_path=rel_path,
    )
    return 0


def _print_success(*, row_count: int, destination: Path, rel_path: str) -> None:
    """Print the success summary, including the copy-pasteable .env line."""
    print(f"Wrote {row_count} row(s) to: {destination}")
    print("")
    print("Next step — add this line to your repo-root .env "
          "(this tool will NOT edit .env for you):")
    print("")
    print(f"    CONNECTUS_PIPELINE_CSV={rel_path}")
    print("")
    print(
        "  The path is shown relative to the repo root (relative paths in "
        "CONNECTUS_PIPELINE_CSV resolve against the repo root). You may also "
        "use an absolute path:"
    )
    print("")
    print(f"    CONNECTUS_PIPELINE_CSV={destination}")
    print("")
    print(
        "  Once set, the migration tooling (workflow_state.py and the "
        "param-parity resolver) reads your personal copy instead of the "
        "bundled pipeline."
    )


# ---------------------------------------------------------------------------
# Argparse
# ---------------------------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    """Build the argparse parser for the CLI."""
    parser = argparse.ArgumentParser(
        prog="extract_personal_pipeline.py",
        description=(
            "Extract a personal subset of the ConnectUs migration pipeline "
            "CSV into your own file, then point CONNECTUS_PIPELINE_CSV at it."
        ),
        epilog=(
            "At least one selector is required. Selectors are additive "
            "(the union of all matched rows, de-duplicated by Integration "
            "ID, in main-file order).\n\n"
            "Examples:\n"
            "  extract_personal_pipeline.py --mine\n"
            "  extract_personal_pipeline.py --assignee YuvHayun\n"
            "  extract_personal_pipeline.py --connector \"Cisco Security\"\n"
            "  extract_personal_pipeline.py --integration-id AMP "
            "--integration-id APIVoid\n"
            "  extract_personal_pipeline.py --mine --connector APIVoid "
            "--name my-work\n"
            "  extract_personal_pipeline.py --assignee noydavidi --dry-run\n"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    selectors = parser.add_argument_group(
        "selectors (at least one required; additive)"
    )
    selectors.add_argument(
        "--mine",
        action="store_true",
        help="select rows whose assignee matches `git config user.name`.",
    )
    selectors.add_argument(
        "--assignee",
        metavar="NAME",
        help="select rows for this assignee (case-insensitive).",
    )
    selectors.add_argument(
        "--connector",
        metavar="ID",
        help="select rows for this Connector ID (case-insensitive).",
    )
    selectors.add_argument(
        "--integration-id",
        metavar="ID",
        action="append",
        default=[],
        dest="integration_ids",
        help=(
            "select this Integration ID (case-insensitive). Repeatable: "
            "pass --integration-id multiple times."
        ),
    )

    dest = parser.add_argument_group("destination")
    dest.add_argument(
        "--name",
        metavar="NAME",
        help=(
            "filename stem for the output (sanitized). The file is created "
            "in connectus/personal_pipelines/. Defaults to your slugified "
            "git user name, else 'personal-pipeline'."
        ),
    )
    dest.add_argument(
        "--output",
        metavar="PATH",
        help=(
            "full destination path (absolute or repo-root-relative). "
            "Overrides --name entirely."
        ),
    )
    dest.add_argument(
        "--force",
        action="store_true",
        help="overwrite the destination file if it already exists.",
    )

    parser.add_argument(
        "--dry-run",
        action="store_true",
        help=(
            "print what would be written (count, destination, Integration "
            "IDs) without creating any file."
        ),
    )
    return parser


def main(argv: Optional[list[str]] = None) -> int:
    """CLI entrypoint. Returns an exit code (0 = success)."""
    parser = build_parser()
    args = parser.parse_args(argv)

    try:
        return run_extract(
            mine=args.mine,
            assignee=args.assignee,
            connector=args.connector,
            integration_ids=list(args.integration_ids),
            name=args.name,
            output=args.output,
            force=args.force,
            dry_run=args.dry_run,
        )
    except ExtractError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
