"""Auto-runner harness for the ConnectUs migration pre-manifest steps (0–3c).

Runs every deterministic pre-step needed before exercising
``manifest_generator.py``, one function per step, no interactive approval.

Steps (each persists its raw output to a temp folder):
    0  — Identify the integration            (workflow_state.py context)
    1  — Classify auth + set Auth Details     (heuristic → workflow_state.py set-auth)
    2  — Set Params to Commands               (check_command_params.py → set-params-to-commands)
    3a — Set Params for test default in code  (test-module-params → set-param-defaults)
    3b — Set Params to Capabilities           (connector_param_mapper.py → set-params-to-capabilities)
    3c — Generate connector manifest          (manifest_generator.py → <out_dir>/generated_manifest)

Output files are written as ``<step>_<script_name>_outputs.json`` where
``<script_name>`` is the underlying script the step primarily invokes.

NOTE: The auth classification in step 1 is a best-effort HEURISTIC. It is
intended to produce a structurally-valid, gate-passing Auth Details cell so
the downstream manifest generator has something to consume — it is NOT a
substitute for the real per-integration auth analysis and may be wrong.

Usage:
    python3 connectus/connectus_migration/run_pre_manifest_steps.py "Akamai WAF"
    python3 connectus/connectus_migration/run_pre_manifest_steps.py "Akamai WAF" --out-dir .tmp_premanifest
"""

from __future__ import annotations

import argparse
import csv
import json
import subprocess
import sys
from pathlib import Path
from typing import Any

import yaml

# ---------------------------------------------------------------------------
# Constants — repo-relative script locations and tuning knobs.
# ---------------------------------------------------------------------------
REPO_ROOT = Path(__file__).resolve().parents[2]
WORKFLOW_STATE = REPO_ROOT / "connectus" / "workflow_state.py"
ANALYZER = REPO_ROOT / "connectus" / "check_command_params.py"
MAPPER = REPO_ROOT / "connectus" / "connectus_migration" / "connector_param_mapper.py"
MANIFEST_GENERATOR = (
    REPO_ROOT / "connectus" / "connectus_migration" / "manifest_generator.py"
)
IGNORE_PARAMS_FILE = REPO_ROOT / "connectus" / "default_ignore_params.txt"
AUTHOR_IMAGE_CSV = REPO_ROOT / "connectus" / "connector-id-to-author-image.csv"

DEFAULT_OUT_DIR = REPO_ROOT / ".tmp_premanifest"

# Assignee used only when the row has none yet (so set-auth's ordering gate
# — which requires the 'assignee' step done first — is satisfied).
DEFAULT_ASSIGNEE = "premanifest-harness"

# set-params-to-commands re-runs the auth-parity overlap check and can be slow.
LONG_TIMEOUT = 300
SHORT_TIMEOUT = 60

# XSOAR YML param type codes (subset relevant to auth classification).
TYPE_ENCRYPTED = 4  # encrypted text (api keys / tokens / secrets)
TYPE_CREDENTIALS = 9  # credentials widget (identifier + password)


# ---------------------------------------------------------------------------
# Generic helpers
# ---------------------------------------------------------------------------
def _run(cmd: list[str], *, timeout: int) -> subprocess.CompletedProcess:
    """Run a subprocess from the repo root, capturing stdout/stderr as text."""
    return subprocess.run(
        cmd,
        cwd=str(REPO_ROOT),
        capture_output=True,
        text=True,
        timeout=timeout,
    )


def _save_output(out_dir: Path, step: str, script_name: str, payload: Any) -> Path:
    """Persist a step's output as ``<step>_<script_name>_outputs.json``."""
    out_dir.mkdir(parents=True, exist_ok=True)
    path = out_dir / f"{step}_{script_name}_outputs.json"
    path.write_text(json.dumps(payload, indent=2, sort_keys=True))
    print(f"  [saved] {path.relative_to(REPO_ROOT)}")
    return path


def _parse_json_stdout(proc: subprocess.CompletedProcess) -> Any:
    """Parse JSON from a process's stdout, raising with context on failure."""
    try:
        return json.loads(proc.stdout)
    except json.JSONDecodeError as exc:
        raise RuntimeError(
            f"Expected JSON on stdout but failed to parse: {exc}\n"
            f"--- stdout ---\n{proc.stdout}\n--- stderr ---\n{proc.stderr}"
        ) from exc


def _visible(param: dict) -> bool:
    """Return True if a YML param is neither hidden nor deprecated."""
    if param.get("deprecated"):
        return False
    hidden = param.get("hidden")
    # hidden may be a bool or a non-empty list of marketplaces — both hide it.
    return not bool(hidden)


def _lookup_author_image(connector_id: str) -> Path | None:
    """Resolve the author image path for ``connector_id`` from the CSV.

    ``connector_id`` is the workflow's connector id (``context.connector_id``)
    — which is what the CSV is keyed by — and may differ from the workflow
    ``integration_id`` (e.g. integration ``"Microsoft Graph"`` maps to
    connector ``"Microsoft Security"``).

    The CSV (``connector-id-to-author-image.csv``) maps a "Connector ID"
    to a repo-relative "Author image path". Matching is best-effort:

      1. Exact match on Connector ID (case-insensitive).
      2. Fallback: case-insensitive substring/contains match in either
         direction (e.g. ``"Microsoft Graph"`` → ``"Microsoft MS Graph"``).

    Returns the resolved absolute :class:`Path` to the image, or ``None``
    when no row matches or the mapped image file does not exist (a warning
    is printed in both skip cases — the manifest is still generated, just
    without an author image).
    """
    if not AUTHOR_IMAGE_CSV.is_file():
        print(f"  [author-image] CSV not found: {AUTHOR_IMAGE_CSV} — skipping")
        return None

    target = connector_id.strip().lower()
    rows: list[tuple[str, str]] = []
    with open(AUTHOR_IMAGE_CSV, newline="") as fh:
        reader = csv.DictReader(fh)
        for row in reader:
            csv_connector_id = (row.get("Connector ID") or "").strip()
            image_path = (row.get("Author image path") or "").strip()
            if csv_connector_id and image_path:
                rows.append((csv_connector_id, image_path))

    # 1. Exact (case-insensitive) match.
    image_rel: str | None = None
    for csv_connector_id, image_path in rows:
        if csv_connector_id.lower() == target:
            image_rel = image_path
            break

    # 2. Fallback: case-insensitive substring/contains match.
    if image_rel is None:
        for csv_connector_id, image_path in rows:
            cid = csv_connector_id.lower()
            if target in cid or cid in target:
                image_rel = image_path
                print(
                    f"  [author-image] no exact match for '{connector_id}'; "
                    f"using closest '{csv_connector_id}'"
                )
                break

    if image_rel is None:
        print(
            f"  [author-image] no Connector ID match for '{connector_id}' "
            f"in CSV — skipping author image"
        )
        return None

    image_path = (REPO_ROOT / image_rel).resolve()
    if not image_path.is_file():
        print(
            f"  [author-image] mapped image not found: {image_path} — "
            f"skipping author image"
        )
        return None

    print(f"  [author-image] {image_path.relative_to(REPO_ROOT)}")
    return image_path


# ---------------------------------------------------------------------------
# Step 0 — Identify the integration
# ---------------------------------------------------------------------------
def step_0_identify(integration_id: str, out_dir: Path) -> dict:
    """Resolve the integration context (state + file paths + data columns).

    Also ensures an ``assignee`` is set: the workflow's ordering gate
    requires the ``assignee`` step done before ``set-auth``, so a freshly
    ``reset`` row (assignee wiped) would otherwise block step 1. We only
    assign a placeholder when none exists — an existing owner is preserved.
    """
    print(f"[0] Identify '{integration_id}'")
    proc = _run(
        [sys.executable, str(WORKFLOW_STATE), "context", integration_id],
        timeout=SHORT_TIMEOUT,
    )
    if proc.returncode != 0:
        raise RuntimeError(f"context failed:\n{proc.stderr or proc.stdout}")
    context = _parse_json_stdout(proc)

    if not context.get("assignee"):
        print(f"  [assignee] none set — assigning '{DEFAULT_ASSIGNEE}'")
        assign = _run(
            [
                sys.executable,
                str(WORKFLOW_STATE),
                "set-assignee",
                integration_id,
                DEFAULT_ASSIGNEE,
            ],
            timeout=SHORT_TIMEOUT,
        )
        if assign.returncode != 0:
            raise RuntimeError(
                f"set-assignee failed:\n{assign.stderr or assign.stdout}"
            )
        context["assignee"] = DEFAULT_ASSIGNEE

    _save_output(out_dir, "0", "workflow_state", context)
    return context


# ---------------------------------------------------------------------------
# Step 1 — Classify auth (heuristic) + set Auth Details
# ---------------------------------------------------------------------------
def _classify_auth(yml_path: Path) -> dict:
    """Best-effort heuristic auth classification from the integration YML.

    Heuristic ladder:
      - EdgeGrid / multi-token (3+ visible credential-ish params) → one
        interpolated ``Passthrough`` profile holding every secret.
      - Exactly one visible type-9 credentials widget with BOTH leaves
        live → ``Plain`` (username + password).
      - Exactly one visible type-4 encrypted param → ``APIKey``.
      - Anything else → interpolated ``Passthrough`` fallback.

    Connection-adjacent params (url/host/proxy/insecure/port/region/...)
    go into ``other_connection``. All auth profiles are emitted
    ``interpolated: true`` so the parity gate cleanly short-circuits
    (ERROR_ALL_INTERPOLATED) regardless of classification accuracy.
    """
    with open(yml_path) as fh:
        yml = yaml.safe_load(fh) or {}
    config = yml.get("configuration", []) or []

    connection_names = {
        "url", "server_url", "server", "host", "endpoint", "base_url",
        "port", "insecure", "unsecure", "trust_any_certificate",
        "verify_certificate", "verify_ssl", "proxy", "use_proxy",
        "use_system_proxy", "region", "data_center", "cloud", "api_version",
    }

    secret_params: list[dict] = []
    other_connection: set[str] = set()

    for param in config:
        if not _visible(param):
            continue
        name = param.get("name", "")
        ptype = param.get("type")
        if name in connection_names:
            other_connection.add(name)
        elif ptype in (TYPE_ENCRYPTED, TYPE_CREDENTIALS):
            secret_params.append(param)
        # Other types (checkboxes, free text, selects) are neither secrets
        # nor connection-routing → ignored for auth purposes.

    auth_types = _build_auth_types(secret_params)
    return {
        "auth_types": auth_types,
        "other_connection": sorted(other_connection),
    }


def _password_leaf(name: str) -> str:
    return f"{name}.password"


def _build_auth_types(secret_params: list[dict]) -> list[dict]:
    """Build the ``auth_types`` list from the visible secret params."""
    if not secret_params:
        # No secrets at all → NoneRequired (empty auth_types).
        return []

    # Multi-token / EdgeGrid-style: 3+ secrets used together → one Passthrough.
    if len(secret_params) >= 3:
        return [_passthrough_profile(secret_params)]

    # Single type-9 credentials widget with both leaves live → Plain.
    if len(secret_params) == 1 and secret_params[0].get("type") == TYPE_CREDENTIALS:
        param = secret_params[0]
        name = param.get("name", "")
        has_user = not param.get("hiddenusername")
        has_pass = not param.get("hiddenpassword")
        if has_user and has_pass:
            return [
                {
                    "type": "Plain",
                    "name": name,
                    "interpolated": True,
                    "xsoar_param_map": {
                        f"{name}.identifier": "username",
                        f"{name}.password": "password",
                    },
                }
            ]
        # hiddenusername (api-key-in-credentials) → APIKey on the password leaf.
        if has_pass:
            return [
                {
                    "type": "APIKey",
                    "name": name,
                    "interpolated": True,
                    "xsoar_param_map": {f"{name}.password": "key"},
                }
            ]

    # Single type-4 encrypted param → APIKey.
    if len(secret_params) == 1 and secret_params[0].get("type") == TYPE_ENCRYPTED:
        name = secret_params[0].get("name", "")
        return [
            {
                "type": "APIKey",
                "name": name,
                "interpolated": True,
                "xsoar_param_map": {name: "key"},
            }
        ]

    # Fallback: 2 secrets, or anything else → one interpolated Passthrough.
    return [_passthrough_profile(secret_params)]


def _passthrough_profile(secret_params: list[dict]) -> dict:
    """Build a single interpolated Passthrough profile holding all secrets."""
    xsoar_param_map: dict[str, str] = {}
    for param in secret_params:
        name = param.get("name", "")
        if param.get("type") == TYPE_CREDENTIALS:
            if not param.get("hiddenpassword"):
                xsoar_param_map[_password_leaf(name)] = name
            if not param.get("hiddenusername"):
                xsoar_param_map[f"{name}.identifier"] = f"{name}_identifier"
        else:
            xsoar_param_map[name] = name
    # xsoar_param_map must be non-empty for every entry.
    if not xsoar_param_map:
        xsoar_param_map = {secret_params[0].get("name", "secret"): "secret"}
    return {
        "type": "Passthrough",
        "name": "passthrough",
        "interpolated": True,
        "xsoar_param_map": xsoar_param_map,
    }


def step_1_auth(integration_id: str, context: dict, out_dir: Path) -> dict:
    """Heuristically classify auth and persist it via set-auth."""
    print(f"[1] Classify auth + set-auth '{integration_id}'")
    yml_path = REPO_ROOT / context["file_paths"]["yml"]
    auth_details = _classify_auth(yml_path)
    payload = json.dumps(auth_details)

    proc = _run(
        [sys.executable, str(WORKFLOW_STATE), "set-auth", integration_id, payload],
        timeout=LONG_TIMEOUT,
    )
    result = {
        "auth_details": auth_details,
        "returncode": proc.returncode,
        "stdout": proc.stdout.strip(),
        "stderr": proc.stderr.strip(),
    }
    _save_output(out_dir, "1", "workflow_state", result)
    if proc.returncode != 0:
        raise RuntimeError(f"set-auth failed:\n{proc.stderr or proc.stdout}")
    return auth_details


# ---------------------------------------------------------------------------
# Step 2 — Set Params to Commands
# ---------------------------------------------------------------------------
def step_2_params_to_commands(integration_id: str, out_dir: Path) -> dict:
    """Run the analyzer (static-only) and persist Params to Commands."""
    print(f"[2] Analyze + set-params-to-commands '{integration_id}'")
    analyze = _run(
        [
            sys.executable,
            str(ANALYZER),
            "--ignore-params-file",
            str(IGNORE_PARAMS_FILE),
            "--integration-id",
            integration_id,
            "--static-only",
        ],
        timeout=LONG_TIMEOUT,
    )
    if analyze.returncode != 0:
        raise RuntimeError(f"analyzer failed:\n{analyze.stderr or analyze.stdout}")
    params_to_commands = _parse_json_stdout(analyze)
    _save_output(out_dir, "2", "check_command_params", params_to_commands)

    proc = _run(
        [
            sys.executable,
            str(WORKFLOW_STATE),
            "set-params-to-commands",
            integration_id,
            json.dumps(params_to_commands),
        ],
        timeout=LONG_TIMEOUT,
    )
    if proc.returncode != 0:
        raise RuntimeError(
            f"set-params-to-commands failed:\n{proc.stderr or proc.stdout}"
        )
    return params_to_commands


# ---------------------------------------------------------------------------
# Step 3a — Set Params for test with default in code
# ---------------------------------------------------------------------------
def step_3a_param_defaults(integration_id: str, out_dir: Path) -> dict:
    """Persist Params-for-test defaults.

    Heuristic-friendly: the harness records ``{}`` (the most common case)
    unless ``test-module-params`` reports required params. Since this is a
    structural-test harness, we keep it empty — the manifest generator
    consumes the cell but does not require non-empty values here.
    """
    print(f"[3a] test-module-params + set-param-defaults '{integration_id}'")
    tm_proc = _run(
        [
            sys.executable,
            str(WORKFLOW_STATE),
            "test-module-params",
            integration_id,
            "--format=json",
        ],
        timeout=SHORT_TIMEOUT,
    )
    test_module_params: list[str] = []
    if tm_proc.returncode == 0 and tm_proc.stdout.strip():
        try:
            test_module_params = json.loads(tm_proc.stdout)
        except json.JSONDecodeError:
            test_module_params = []

    # Structural harness: default to empty object regardless of list contents.
    param_defaults: dict[str, Any] = {}
    result = {
        "test_module_params": test_module_params,
        "param_defaults": param_defaults,
    }
    _save_output(out_dir, "3a", "workflow_state", result)

    proc = _run(
        [
            sys.executable,
            str(WORKFLOW_STATE),
            "set-param-defaults",
            integration_id,
            json.dumps(param_defaults),
        ],
        timeout=SHORT_TIMEOUT,
    )
    if proc.returncode != 0:
        raise RuntimeError(
            f"set-param-defaults failed:\n{proc.stderr or proc.stdout}"
        )
    return param_defaults


# ---------------------------------------------------------------------------
# Step 3b — Set Params to Capabilities
# ---------------------------------------------------------------------------
def step_3b_params_to_capabilities(
    integration_id: str,
    context: dict,
    params_to_commands: dict,
    param_defaults: dict,
    out_dir: Path,
) -> dict:
    """Run the connector-param mapper and persist Params to Capabilities."""
    print(f"[3b] mapper + set-params-to-capabilities '{integration_id}'")
    yml_path = context["file_paths"]["yml"]
    mapping_out = out_dir / "_param_mapping.json"

    mapper = _run(
        [
            sys.executable,
            str(MAPPER),
            json.dumps(params_to_commands),
            json.dumps(param_defaults),
            yml_path,
            "{}",
            "-o",
            str(mapping_out),
        ],
        timeout=LONG_TIMEOUT,
    )
    if mapper.returncode != 0:
        raise RuntimeError(f"mapper failed:\n{mapper.stderr or mapper.stdout}")
    if not mapping_out.is_file():
        raise RuntimeError(
            f"mapper did not produce output file {mapping_out}\n"
            f"--- stdout ---\n{mapper.stdout}\n--- stderr ---\n{mapper.stderr}"
        )
    params_to_capabilities = json.loads(mapping_out.read_text())
    _save_output(out_dir, "3b", "connector_param_mapper", params_to_capabilities)

    proc = _run(
        [
            sys.executable,
            str(WORKFLOW_STATE),
            "set-params-to-capabilities",
            integration_id,
            json.dumps(params_to_capabilities),
        ],
        timeout=SHORT_TIMEOUT,
    )
    if proc.returncode != 0:
        raise RuntimeError(
            f"set-params-to-capabilities failed:\n{proc.stderr or proc.stdout}"
        )
    return params_to_capabilities


# ---------------------------------------------------------------------------
# Step 3c — Generate connector manifest
# ---------------------------------------------------------------------------
def step_3c_generate_manifest(
    integration_id: str,
    context: dict,
    params_to_capabilities: dict,
    auth_details: dict,
    out_dir: Path,
) -> dict:
    """Run ``manifest_generator.py`` to scaffold the connector manifest.

    The generated connector folder is written under
    ``<out_dir>/generated_manifest/connectors/<slug>/`` (the generator
    appends ``<slug>`` beneath the ``--connectors-root`` we hand it).

    Inputs are derived entirely from earlier steps / the step-0 context:

      * ``integration_path`` ← ``context['file_paths']['yml']`` (resolved
        to an absolute path — the generator declares ``exists=True``).
      * ``connector_title``  ← ``context['integration_id']`` (display name).
      * ``mapped_params``    ← step 3b ``params_to_capabilities``.
      * ``auth_methods``     ← step 1 ``auth_details``
        (shape: ``{auth_types, other_connection}``).
    """
    print(f"[3c] generate manifest '{integration_id}'")

    file_paths = context.get("file_paths") or {}
    yml_rel = file_paths.get("yml")
    if not yml_rel:
        raise RuntimeError(
            "context is missing file_paths.yml — cannot locate the "
            "integration YML for manifest generation."
        )
    yml_path = (REPO_ROOT / yml_rel).resolve()
    if not yml_path.is_file():
        raise RuntimeError(f"integration YML not found: {yml_path}")

    connector_title = context.get("integration_id") or integration_id

    generated_root = out_dir / "generated_manifest"
    generated_root.mkdir(parents=True, exist_ok=True)

    # Author image is keyed by the connector id (context.connector_id),
    # not the workflow integration_id — they can differ (e.g. integration
    # 'Microsoft Graph' → connector 'Microsoft Security').
    connector_id = context.get("connector_id") or integration_id
    author_image_path = _lookup_author_image(connector_id)

    cmd = [
        sys.executable,
        str(MANIFEST_GENERATOR),
        str(yml_path),
        connector_title,
        json.dumps(params_to_capabilities),
        json.dumps(auth_details),
        "--connectors-root",
        str(generated_root),
    ]
    if author_image_path is not None:
        cmd += ["--author-image-path", str(author_image_path)]

    proc = _run(cmd, timeout=LONG_TIMEOUT)
    result = {
        "connector_title": connector_title,
        "connectors_root": str(generated_root),
        "integration_path": str(yml_path),
        "author_image_path": str(author_image_path) if author_image_path else "",
        "returncode": proc.returncode,
        "stdout": proc.stdout.strip(),
        "stderr": proc.stderr.strip(),
    }
    _save_output(out_dir, "3c", "manifest_generator", result)
    if proc.returncode != 0:
        raise RuntimeError(
            f"manifest generation failed:\n{proc.stderr or proc.stdout}"
        )
    return result


# ---------------------------------------------------------------------------
# Orchestration
# ---------------------------------------------------------------------------
def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--out-dir",
        default=str(DEFAULT_OUT_DIR),
        help="Folder for per-step *_outputs.json files.",
    )
    args = parser.parse_args()
    
    integration_id = "Microsoft Graph"
    out_dir = Path(args.out_dir)
    if not out_dir.is_absolute():
        out_dir = REPO_ROOT / out_dir

    print(f"=== Pre-manifest setup for '{integration_id}' → {out_dir} ===")
    context = step_0_identify(integration_id, out_dir)
    auth_details = step_1_auth(integration_id, context, out_dir)
    params_to_commands = step_2_params_to_commands(integration_id, out_dir)
    param_defaults = step_3a_param_defaults(integration_id, out_dir)
    params_to_capabilities = step_3b_params_to_capabilities(
        integration_id, context, params_to_commands, param_defaults, out_dir
    )
    step_3c_generate_manifest(
        integration_id, context, params_to_capabilities, auth_details, out_dir
    )
    print(f"=== Done. Outputs in {out_dir} ===")
    return 0


if __name__ == "__main__":
    sys.exit(main())
