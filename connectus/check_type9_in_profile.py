#!/usr/bin/env python3
"""ConnectUs type-9 (Credentials) auth-placement validator.

In XSOAR/XSIAM a ``type: 9`` configuration param is a **Credentials**
widget — a compound ``identifier`` + ``password`` secret. Under ConnectUs
these credential secrets must live inside an auth profile, i.e. they MUST
be consumed via an ``auth_types[].xsoar_param_map`` leaf
(``<name>.identifier`` / ``<name>.password``). They must **NOT** be parked
in ``other_connection``: ``other_connection`` is for purely transport /
connection-wide metadata (url, proxy, insecure, port, region, …) that is
shared across every connection, whereas a type-9 secret belongs to a
specific auth profile. A credential that lands in ``other_connection``
leaks the secret out of the profile and into shared connection config.

If the same credential is genuinely needed by more than one auth profile,
it must be **manually duplicated into each profile's** ``xsoar_param_map``
— it still may not be hoisted into ``other_connection`` as a shortcut.
(This script does NOT enforce the "present in every profile" rule — that
is a per-integration judgment call; see the skill. It enforces only the
hard rule: a type-9 param's id must never appear in ``other_connection``,
and it must be present in at least one profile's ``xsoar_param_map``.)

The check reads two sources of truth:

* the integration **YML** ``configuration`` section — to discover which
  params are ``type: 9`` (non-hidden), and
* the **Auth Details** cell — either the persisted CSV value (resolved via
  ``--integration-id``) or a literal payload passed with ``--auth-details``
  / ``--auth-details-file``.

It then classifies every non-hidden type-9 param into one of:

* **MISPLACED** — a provable break: the param's id appears in
  ``other_connection``. Hard failure.
* **MISSING** — the param is type-9 but appears in **neither**
  ``other_connection`` nor any profile's ``xsoar_param_map``. This means a
  declared credential was dropped entirely from the auth classification —
  surfaced as a failure so it is not silently lost.
* **OK** — the param is consumed via at least one profile's
  ``xsoar_param_map`` leaf and is absent from ``other_connection``.

Output: a single JSON envelope on stdout::

    {
      "integration": "<name>",
      "pass": <bool>,            # true only when misplaced AND missing empty
      "misplaced": [{"param","reason"}, ...],
      "missing":   [{"param","reason"}, ...],
      "ok": ["<param>", ...],
      "note": "<optional, e.g. no type-9 params>"
    }

Exit code is ``0`` when ``pass`` is true, ``1`` when a placement problem is
found, and ``2`` on usage / resolution errors — so the script drops
straight into an exit-code gate runner.

Usage::

    python3 connectus/check_type9_in_profile.py --integration-id <id>
    python3 connectus/check_type9_in_profile.py --integration-id <id> --human
    python3 connectus/check_type9_in_profile.py \
        --integration-yml PATH --auth-details '<json>'
    python3 connectus/check_type9_in_profile.py \
        --integration-yml PATH --auth-details-file PATH
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Optional

try:  # PyYAML is available across the connectus tooling; degrade gracefully.
    import yaml  # type: ignore
except Exception:  # pragma: no cover - exercised only when PyYAML is absent
    yaml = None  # type: ignore

# Make sibling connectus modules importable regardless of CWD.
sys.path.insert(0, str(Path(__file__).resolve().parent))

_REPO_ROOT = Path(__file__).resolve().parent.parent

# --------------------------------------------------------------------------
# Constants
# --------------------------------------------------------------------------

#: YML configuration ``type`` code for the Credentials widget.
YML_TYPE_CREDENTIALS = 9

EXIT_PASS = 0
EXIT_FAIL = 1
EXIT_USAGE = 2

REASON_MISPLACED = (
    "type-9 (Credentials) param {param!r} appears in 'other_connection'. "
    "Credentials secrets must live inside an auth profile "
    "(auth_types[].xsoar_param_map via {param}.identifier / "
    "{param}.password), not in shared connection config. If it is needed by "
    "more than one profile, add it manually to each profile's "
    "xsoar_param_map — never hoist it into other_connection."
)
REASON_MISSING = (
    "type-9 (Credentials) param {param!r} is declared in the YML but is "
    "absent from every auth profile's xsoar_param_map (and from "
    "other_connection). The credential was dropped from the auth "
    "classification — add it to the relevant profile(s)' xsoar_param_map "
    "as {param}.identifier / {param}.password."
)


class Type9Error(Exception):
    """Raised for usage / resolution errors that should exit with EXIT_USAGE."""


# --------------------------------------------------------------------------
# YML handling
# --------------------------------------------------------------------------


def _load_yaml(path: Path) -> dict:
    """Load a YAML file into a dict; raise :class:`Type9Error` on problems."""
    if yaml is None:
        raise Type9Error("PyYAML is not available; cannot read the integration YML.")
    if not path.is_file():
        raise Type9Error(f"integration YML not found: {path}")
    try:
        doc = yaml.safe_load(path.read_text(encoding="utf-8"))
    except yaml.YAMLError as exc:  # type: ignore[union-attr]
        raise Type9Error(f"could not parse YAML at {path}: {exc}") from exc
    if doc is None:
        return {}
    if not isinstance(doc, dict):
        raise Type9Error(
            f"expected a mapping at the top of {path}, got {type(doc).__name__}"
        )
    return doc


def _is_hidden(param: dict) -> bool:
    """Return True when a YML configuration param is hidden on the Platform.

    Mirrors :func:`check_handler_param_coverage._is_hidden`. Hidden means
    any of: ``hidden: true``; ``hidden: <non-empty string>`` (e.g.
    ``platform``); ``hidden: [..]`` (non-empty per-marketplace list).
    """
    hidden = param.get("hidden")
    if hidden is True:
        return True
    if isinstance(hidden, str) and hidden:
        return True
    return isinstance(hidden, list) and len(hidden) > 0


def collect_type9_params(integration_yml: dict) -> set[str]:
    """Collect non-hidden ``type: 9`` credentials param names from a YML.

    Only non-hidden params are returned — hidden/deprecated credentials are
    not part of the live auth surface, matching the handler-coverage
    collector.
    """
    creds: set[str] = set()
    for param in integration_yml.get("configuration", []) or []:
        if not isinstance(param, dict):
            continue
        if _is_hidden(param):
            continue
        if param.get("type") != YML_TYPE_CREDENTIALS:
            continue
        name = param.get("name")
        if name:
            creds.add(name)
    return creds


# --------------------------------------------------------------------------
# Auth Details handling
# --------------------------------------------------------------------------


def _project_to_base_id(xsoar_param: str) -> str:
    """Collapse a dotted XSOAR field path to its base YML param id.

    ``'credentials.password'`` -> ``'credentials'``; bare ids pass through.
    Mirrors :func:`auth_config_parser.utils.project_xsoar_param_to_yml_id`
    but is inlined so this script has no hard dependency on that package.
    """
    if not isinstance(xsoar_param, str):
        return ""
    return xsoar_param.split(".", 1)[0]


def _parse_auth_details(raw: str) -> dict:
    """Parse the Auth Details JSON string into a dict; validate top shape."""
    try:
        parsed = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise Type9Error(f"Auth Details is not valid JSON: {exc}") from exc
    if not isinstance(parsed, dict):
        raise Type9Error(
            f"Auth Details must be a JSON object, got {type(parsed).__name__}."
        )
    return parsed


def _profile_base_ids(auth_details: dict) -> set[str]:
    """Base YML param ids consumed via any profile's ``xsoar_param_map``."""
    ids: set[str] = set()
    for entry in auth_details.get("auth_types", []) or []:
        if not isinstance(entry, dict):
            continue
        xpm = entry.get("xsoar_param_map")
        if not isinstance(xpm, dict):
            continue
        for key in xpm:
            base = _project_to_base_id(key)
            if base:
                ids.add(base)
    return ids


def _other_connection_ids(auth_details: dict) -> set[str]:
    """Param ids parked in ``other_connection`` (already bare YML ids)."""
    ids: set[str] = set()
    for item in auth_details.get("other_connection", []) or []:
        if isinstance(item, str) and item:
            ids.add(item)
    return ids


# --------------------------------------------------------------------------
# Core check
# --------------------------------------------------------------------------


def check_type9_placement(integration_yml: dict, auth_details: dict) -> dict:
    """Classify every non-hidden type-9 param's auth placement.

    Returns a verdict envelope (see module docstring). Pure function — no
    filesystem / CSV access — so it is trivially unit-testable.
    """
    type9 = collect_type9_params(integration_yml)
    profile_ids = _profile_base_ids(auth_details)
    other_ids = _other_connection_ids(auth_details)

    misplaced: list[dict] = []
    missing: list[dict] = []
    ok: list[str] = []

    for param in sorted(type9):
        in_profile = param in profile_ids
        in_other = param in other_ids
        if in_other:
            # Misplaced regardless of whether it's also in a profile: the
            # secret must never appear in shared connection config.
            misplaced.append(
                {"param": param, "reason": REASON_MISPLACED.format(param=param)}
            )
        elif not in_profile:
            missing.append(
                {"param": param, "reason": REASON_MISSING.format(param=param)}
            )
        else:
            ok.append(param)

    verdict: dict = {
        "pass": not misplaced and not missing,
        "misplaced": misplaced,
        "missing": missing,
        "ok": ok,
    }
    if not type9:
        verdict["note"] = "no type-9 (Credentials) params in the integration YML"
    return verdict


# --------------------------------------------------------------------------
# CLI plumbing
# --------------------------------------------------------------------------


def _resolve_from_id(integration_id: str) -> tuple[Path, str]:
    """Resolve ``(yml_path, raw_auth_details)`` from a workflow-CSV id."""
    try:
        from workflow_state import get_integration_files  # type: ignore
        from workflow_state.csv_io import find_row, load_csv  # type: ignore
    except Exception as exc:  # noqa: BLE001
        raise Type9Error(
            f"could not import workflow_state to resolve "
            f"--integration-id {integration_id!r}: {type(exc).__name__}: {exc}"
        ) from exc

    files = get_integration_files(integration_id)
    if "error" in files:
        raise Type9Error(f"--integration-id {integration_id!r}: {files['error']}")
    yml_rel = files.get("yml")
    if not yml_rel:
        raise Type9Error(
            f"--integration-id {integration_id!r}: workflow row has no YML path."
        )
    yml_path = (_REPO_ROOT / yml_rel).resolve()

    rows = load_csv()
    idx = find_row(rows, integration_id)
    if idx is None:
        raise Type9Error(
            f"integration {integration_id!r} not found in the pipeline CSV."
        )
    raw_auth = rows[idx].get("Auth Details", "").strip()
    if not raw_auth:
        raise Type9Error(
            f"'Auth Details' is not set for integration {integration_id!r}. "
            f"Run 'set-auth' first."
        )
    return yml_path, raw_auth


def _render_human(verdict: dict, integration: str) -> str:
    """Human-readable summary printed to stderr under ``--human``."""
    lines = [f"Integration: {integration}"]
    if verdict.get("note"):
        lines.append(f"  {verdict['note']}")
    lines.append(f"  PASS: {verdict['pass']}")
    if verdict["misplaced"]:
        lines.append(
            f"  MISPLACED (type-9 cred in other_connection) "
            f"[{len(verdict['misplaced'])}]:"
        )
        for e in verdict["misplaced"]:
            lines.append(f"    - {e['param']}")
            lines.append(f"        {e['reason']}")
    if verdict["missing"]:
        lines.append(
            f"  MISSING (type-9 cred absent from all profiles) "
            f"[{len(verdict['missing'])}]:"
        )
        for e in verdict["missing"]:
            lines.append(f"    - {e['param']}")
            lines.append(f"        {e['reason']}")
    lines.append(f"  OK (in a profile): {len(verdict['ok'])}")
    return "\n".join(lines)


def _parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Validate that XSOAR type-9 (Credentials) params land in an auth "
            "profile's xsoar_param_map, never in other_connection."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "--integration-id",
        help="Resolve the YML + Auth Details cell from the workflow CSV id.",
    )
    parser.add_argument(
        "--integration-yml",
        help="Path to the integration YML (standalone mode).",
    )
    parser.add_argument(
        "--auth-details",
        help="Literal Auth Details JSON string (standalone mode).",
    )
    parser.add_argument(
        "--auth-details-file",
        help="Path to a file containing the Auth Details JSON (standalone mode).",
    )
    parser.add_argument(
        "--human",
        action="store_true",
        help="Also print a human-readable summary to stderr.",
    )
    return parser.parse_args(argv)


def _resolve_inputs(args: argparse.Namespace) -> tuple[Path, str]:
    """Resolve ``(yml_path, raw_auth_details)`` from the parsed args."""
    if args.integration_id:
        if args.integration_yml or args.auth_details or args.auth_details_file:
            raise Type9Error(
                "--integration-id is mutually exclusive with "
                "--integration-yml / --auth-details / --auth-details-file."
            )
        return _resolve_from_id(args.integration_id)

    if not args.integration_yml:
        raise Type9Error(
            "provide --integration-id, or --integration-yml together with "
            "--auth-details / --auth-details-file."
        )
    yml_path = Path(args.integration_yml)
    if not yml_path.is_file():
        alt = (_REPO_ROOT / args.integration_yml).resolve()
        yml_path = alt if alt.is_file() else yml_path

    if args.auth_details and args.auth_details_file:
        raise Type9Error(
            "--auth-details and --auth-details-file are mutually exclusive."
        )
    if args.auth_details:
        raw_auth = args.auth_details
    elif args.auth_details_file:
        ad_path = Path(args.auth_details_file)
        if not ad_path.is_file():
            raise Type9Error(f"auth-details file not found: {ad_path}")
        raw_auth = ad_path.read_text(encoding="utf-8")
    else:
        raise Type9Error(
            "standalone mode requires --auth-details or --auth-details-file."
        )
    return yml_path, raw_auth


def main(argv: Optional[list[str]] = None) -> int:
    args = _parse_args(argv if argv is not None else sys.argv[1:])

    try:
        yml_path, raw_auth = _resolve_inputs(args)
        integration_yml = _load_yaml(yml_path)
        auth_details = _parse_auth_details(raw_auth)
    except Type9Error as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_USAGE

    integration = (
        args.integration_id
        or integration_yml.get("name")
        or yml_path.stem
    )

    verdict = check_type9_placement(integration_yml, auth_details)
    verdict = {"integration": integration, **verdict}

    print(json.dumps(verdict, indent=2, sort_keys=True))
    if args.human:
        print(_render_human(verdict, integration), file=sys.stderr)

    return EXIT_PASS if verdict["pass"] else EXIT_FAIL


if __name__ == "__main__":
    raise SystemExit(main())
