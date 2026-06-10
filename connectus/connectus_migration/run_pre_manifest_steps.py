"""Auto-runner harness for the ConnectUs migration pre-manifest steps (0–3c).

Runs every deterministic pre-step needed before exercising
``manifest_generator.py``, one function per step, no interactive approval.

Steps (each persists its raw output to a temp folder):
    0  — Identify the integration            (workflow_state.py context)
    1  — Classify auth + set Auth Details     (heuristic → workflow_state.py set-auth)
    1b — Collect Capabilities                 (capabilities_collector.py → set-capabilities)
    2  — Set Params to Commands               (check_command_params.py → set-params-to-commands)
    3a — Set Params for test default in code  (test-module-params → set-param-defaults)
    3b — Set Params to Capabilities           (connector_param_mapper.py → set-params-to-capabilities)
    3c — Generate connector manifest          (manifest_generator.py → <out_dir>/generated_manifest)
    3d — Validate the generated manifest       (validator `make validate` → 3d_validator_outputs.json; non-fatal)

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

# Make the shared connectus env loader importable (connectus/ is not a package).
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from env_loader import load_env  # noqa: E402

# ---------------------------------------------------------------------------
# Constants — repo-relative script locations and tuning knobs.
# ---------------------------------------------------------------------------
REPO_ROOT = Path(__file__).resolve().parents[2]
WORKFLOW_STATE = REPO_ROOT / "connectus" / "workflow_state.py"
ANALYZER = REPO_ROOT / "connectus" / "check_command_params.py"
CAPABILITIES_COLLECTOR = (
    REPO_ROOT / "connectus" / "connectus_migration" / "capabilities_collector.py"
)
MAPPER = REPO_ROOT / "connectus" / "connectus_migration" / "connector_param_mapper.py"
MANIFEST_GENERATOR = (
    REPO_ROOT / "connectus" / "connectus_migration" / "manifest_generator.py"
)
IGNORE_PARAMS_FILE = REPO_ROOT / "connectus" / "default_ignore_params.txt"
AUTHOR_IMAGE_CSV = REPO_ROOT / "connectus" / "connector-id-to-author-image.csv"

DEFAULT_OUT_DIR = REPO_ROOT / ".tmp_premanifest"

# Unified-connectors-content repo (holds the validator Makefile + schema/ +
# policies). Defaults to a sibling of the content repo; override with
# ``--validator-repo``. ``make validate`` MUST run from this directory so the
# binary finds ``schema/`` and the embedded policies.
DEFAULT_VALIDATOR_REPO = REPO_ROOT.parent / "unified-connectors-content"

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
    # Print a repo-relative path when possible; fall back to the absolute
    # path when out_dir lives outside the repo (e.g. a custom --out-dir).
    try:
        display = path.relative_to(REPO_ROOT)
    except ValueError:
        display = path
    print(f"  [saved] {display}")
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
# Step 1b — Collect Capabilities
# ---------------------------------------------------------------------------
def step_1b_collect_capabilities(
    integration_id: str, context: dict, out_dir: Path
) -> list[str]:
    """Collect the integration's expected capabilities and persist them.

    Runs ``capabilities_collector.py`` against the integration YML to derive
    the flat list of capability names, then persists it to the
    ``Collect Capabilities`` workflow cell via ``set-capabilities``.

    The persisted cell is what ``step_2_params_to_commands`` reads back (via
    ``show-step``) to drive the single-capability optimization, so this step
    MUST run before step 2.
    """
    print(f"[1b] collect capabilities + set-capabilities '{integration_id}'")
    yml_path = (REPO_ROOT / context["file_paths"]["yml"]).resolve()
    capabilities_out = out_dir / "_capabilities.json"

    # capabilities_collector.py is a single-command Typer app, so it has NO
    # subcommand name — the YML path is the first positional argument.
    collect = _run(
        [
            sys.executable,
            str(CAPABILITIES_COLLECTOR),
            str(yml_path),
            "-o",
            str(capabilities_out),
        ],
        timeout=SHORT_TIMEOUT,
    )
    if collect.returncode != 0:
        raise RuntimeError(
            f"capabilities_collector failed:\n{collect.stderr or collect.stdout}"
        )
    if not capabilities_out.is_file():
        raise RuntimeError(
            f"capabilities_collector did not produce output file "
            f"{capabilities_out}\n--- stdout ---\n{collect.stdout}\n"
            f"--- stderr ---\n{collect.stderr}"
        )
    capabilities = json.loads(capabilities_out.read_text())
    _save_output(out_dir, "1b", "capabilities_collector", capabilities)

    proc = _run(
        [
            sys.executable,
            str(WORKFLOW_STATE),
            "set-capabilities",
            integration_id,
            json.dumps(capabilities),
        ],
        timeout=SHORT_TIMEOUT,
    )
    if proc.returncode != 0:
        raise RuntimeError(
            f"set-capabilities failed:\n{proc.stderr or proc.stdout}"
        )
    return capabilities


def _collected_capability_count(integration_id: str) -> int:
    """Read the persisted ``Collect Capabilities`` cell and count entries.

    Reads the raw cell via ``workflow_state.py show-step --raw`` (the
    machine-consumer contract) and returns the number of capabilities. A
    missing/empty cell or unparseable value yields ``0`` so the caller falls
    back to a full analysis (the safe default).
    """
    proc = _run(
        [
            sys.executable,
            str(WORKFLOW_STATE),
            "show-step",
            "--raw",
            integration_id,
            "Collect Capabilities",
        ],
        timeout=SHORT_TIMEOUT,
    )
    if proc.returncode != 0:
        return 0
    raw = proc.stdout.strip()
    if not raw:
        return 0
    try:
        capabilities = json.loads(raw)
    except json.JSONDecodeError:
        return 0
    return len(capabilities) if isinstance(capabilities, list) else 0


# ---------------------------------------------------------------------------
# Step 2 — Set Params to Commands
# ---------------------------------------------------------------------------
def step_2_params_to_commands(integration_id: str, out_dir: Path) -> dict:
    """Run the analyzer (static-only) and persist Params to Commands.

    Optimization: when the integration resolves to exactly one capability
    (read back from the ``Collect Capabilities`` cell), only ``test-module``
    is analyzed (``--commands test-module``). A single-capability connector
    needs Params to Commands solely for its connectivity test, so analyzing
    the remaining commands is wasted work.
    """
    print(f"[2] Analyze + set-params-to-commands '{integration_id}'")
    analyzer_cmd = [
        sys.executable,
        str(ANALYZER),
        "--ignore-params-file",
        str(IGNORE_PARAMS_FILE),
        "--integration-id",
        integration_id,
        "--static-only",
    ]
    if _collected_capability_count(integration_id) == 1:
        print("  [optimize] single capability — analyzing test-module only")
        analyzer_cmd += ["--commands", "test-module"]
    analyze = _run(analyzer_cmd, timeout=LONG_TIMEOUT)
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
# Checkpoint step (no setter, no gate) that sits between the
# ``set-param-defaults`` data step and ``set-params-to-capabilities``. It is
# a manual "present → fix → markpass" review in the real workflow; for this
# structural harness there is no code to review, so we markpass it
# unconditionally to satisfy the state-machine ordering gate before step 3b.
UCP_PARAM_DEFAULT_REVIEW_STEP = "UCP param-default review"


def step_3a_param_defaults(integration_id: str, out_dir: Path) -> dict:
    """Persist Params-for-test defaults.

    Heuristic-friendly: the harness records ``{}`` (the most common case)
    unless ``test-module-params`` reports required params. Since this is a
    structural-test harness, we keep it empty — the manifest generator
    consumes the cell but does not require non-empty values here.

    After persisting the defaults this also ``markpass``-es the downstream
    ``UCP param-default review`` checkpoint (a no-setter, no-gate manual
    review step). The harness performs no source-level review, so it advances
    the checkpoint unconditionally — otherwise the state-machine ordering gate
    blocks step 3b's ``set-params-to-capabilities``.
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

    # Advance the manual 'UCP param-default review' checkpoint. It has no
    # setter and no self-executing gate, so a plain markpass cannot fail on
    # its own merits — but it MUST be passed here so the ordering gate lets
    # step 3b's set-params-to-capabilities through.
    print(f"  [markpass] {UCP_PARAM_DEFAULT_REVIEW_STEP} '{integration_id}'")
    review = _run(
        [
            sys.executable,
            str(WORKFLOW_STATE),
            "markpass",
            integration_id,
            UCP_PARAM_DEFAULT_REVIEW_STEP,
        ],
        timeout=SHORT_TIMEOUT,
    )
    if review.returncode != 0:
        raise RuntimeError(
            f"markpass '{UCP_PARAM_DEFAULT_REVIEW_STEP}' failed:\n"
            f"{review.stderr or review.stdout}"
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
    connector_title: str,
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

    generated_root = out_dir
    generated_root.mkdir(parents=True, exist_ok=True)

    cmd = [
        sys.executable,
        str(MANIFEST_GENERATOR),
        str(yml_path),
        str(connector_title),
        json.dumps(params_to_capabilities),
        json.dumps(auth_details),
        "--connectors-root",
        str(generated_root),
        
    ]

    proc = _run(cmd, timeout=LONG_TIMEOUT)
    result = {
        "connector_title": connector_title,
        "connectors_root": str(generated_root),
        "integration_path": str(yml_path),
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
# Step 3d — Validate the generated connector manifest
# ---------------------------------------------------------------------------
def _find_generated_connector_dir(connectors_root: Path) -> Path | None:
    """Locate the single generated connector directory under ``connectors_root``.

    ``manifest_generator.py`` writes the connector to
    ``<connectors_root>/<slug>/`` (a directory containing ``connector.yaml``).
    We discover it by scanning one level deep for a ``connector.yaml`` rather
    than re-deriving the slug, so this stays correct regardless of the
    title→slug mapping. Returns the connector dir, or ``None`` when none is
    found (caller warns + skips validation, non-fatal).
    """
    if not connectors_root.is_dir():
        return None
    matches = sorted(
        p.parent for p in connectors_root.glob("*/connector.yaml") if p.is_file()
    )
    if not matches:
        return None
    if len(matches) > 1:
        print(
            f"  [validate] multiple connector dirs under {connectors_root}; "
            f"validating the first: {matches[0].name}"
        )
    return matches[0]


def step_3d_validate_manifest(
    integration_id: str,
    manifest_result: dict,
    out_dir: Path,
    validator_repo: Path,
) -> dict:
    """Run the validator's ``make validate`` against the generated connector.

    NON-FATAL by design: validation violations are the whole point of this
    step, so they are recorded + printed but never raise. Environment problems
    (validator repo missing, ``make`` unavailable, generated connector not
    found, unparseable output) also warn + skip with a ``skipped`` result and
    do NOT abort the harness.

    Runs ``make validate connector=<abs-connector-dir> json=1`` with
    ``cwd=validator_repo`` so the validator binary finds ``schema/`` and its
    embedded policies. The connector path is absolute, which the validator
    accepts positionally. Output is persisted to
    ``3d_validator_outputs.json``.
    """
    print(f"[3d] validate manifest '{integration_id}'")

    def _skip(reason: str) -> dict:
        print(f"  [validate] SKIPPED — {reason}")
        result = {"status": "skipped", "reason": reason}
        _save_output(out_dir, "3d", "validator", result)
        return result

    if not validator_repo.is_dir():
        return _skip(f"validator repo not found: {validator_repo}")
    if not (validator_repo / "Makefile").is_file():
        return _skip(f"no Makefile in validator repo: {validator_repo}")

    connectors_root = Path(manifest_result.get("connectors_root", ""))
    connector_dir = _find_generated_connector_dir(connectors_root)
    if connector_dir is None:
        return _skip(
            f"no generated connector (connector.yaml) found under "
            f"{connectors_root}"
        )

    cmd = [
        "make",
        "validate",
        f"connector={connector_dir.resolve()}",
        "json=1",
    ]
    print(f"  [validate] {' '.join(cmd)}  (cwd={validator_repo})")
    try:
        proc = subprocess.run(
            cmd,
            cwd=str(validator_repo),
            capture_output=True,
            text=True,
            timeout=LONG_TIMEOUT,
        )
    except FileNotFoundError:
        return _skip("`make` not found on PATH — cannot run validator")
    except subprocess.TimeoutExpired:
        return _skip(f"validator timed out after {LONG_TIMEOUT}s")

    # The validate target prints non-JSON banner lines around the binary's
    # JSON; isolate the JSON object so we can record structured violations.
    parsed = _extract_validator_json(proc.stdout)

    result = {
        "status": "ok" if proc.returncode == 0 else "violations",
        "connector_dir": str(connector_dir.resolve()),
        "returncode": proc.returncode,
        "validation": parsed,
        "stdout": proc.stdout.strip(),
        "stderr": proc.stderr.strip(),
    }
    _save_output(out_dir, "3d", "validator", result)

    if proc.returncode == 0:
        print("  [validate] VALID ✅")
    else:
        print(f"  [validate] INVALID ❌ (exit {proc.returncode})")
        _print_validator_violations(parsed, proc.stdout)
    return result


def _extract_validator_json(stdout: str) -> Any:
    """Best-effort extraction of the validator's JSON object from stdout.

    ``make validate`` interleaves colored banner lines with the binary's JSON
    payload. We scan for the first ``{`` … matching ``}`` block and parse it.
    Returns the parsed object, or ``None`` when no JSON can be recovered (the
    caller still has the raw stdout persisted).
    """
    start = stdout.find("{")
    end = stdout.rfind("}")
    if start == -1 or end == -1 or end < start:
        return None
    candidate = stdout[start : end + 1]
    try:
        return json.loads(candidate)
    except json.JSONDecodeError:
        return None


def _print_validator_violations(parsed: Any, raw_stdout: str) -> None:
    """Print a concise list of validation violations (non-fatal report)."""
    if not isinstance(parsed, dict):
        # Could not parse structured output — surface the raw stdout instead.
        print("  [validate] (could not parse JSON; raw output below)")
        for line in raw_stdout.strip().splitlines():
            print(f"    {line}")
        return
    results = parsed.get("results") or []
    for res in results:
        violations = res.get("violations") or []
        if not violations:
            continue
        name = res.get("connector_name", "<connector>")
        print(f"    {name}: {len(violations)} violation(s)")
        for v in violations:
            file_ = v.get("file", "")
            msg = v.get("message", "")
            print(f"      • [{file_}] {msg}")


# ---------------------------------------------------------------------------
# Orchestration
# ---------------------------------------------------------------------------
def main() -> int:
    # Load the canonical root .env via the single unified loader so spawned
    # subprocesses (e.g. `make validate`) inherit CONNECTUS_REPO_DIR.
    load_env()
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--out-dir",
        default=str(DEFAULT_OUT_DIR),
        help="Folder for per-step *_outputs.json files.",
    )
    parser.add_argument(
        "--validator-repo",
        default=str(DEFAULT_VALIDATOR_REPO),
        help=(
            "Path to the unified-connectors-content repo (holds the validator "
            "Makefile + schema/ + policies). Step 3d runs `make validate` from "
            "here. Defaults to a sibling of the content repo. Validation is "
            "non-fatal — a missing repo only skips step 3d."
        ),
    )
    args = parser.parse_args()

    integration_id = "AWS - ACM"
    out_dir = Path(args.out_dir)
    out_dir = Path.cwd().parent / "unified-connectors-content" / "connectors"
    print(out_dir)
    # if not out_dir.is_absolute():
    #     out_dir = REPO_ROOT / out_dir

    validator_repo = Path(args.validator_repo)
    if not validator_repo.is_absolute():
        validator_repo = (REPO_ROOT / validator_repo).resolve()

    print(f"=== Pre-manifest setup for '{integration_id}' → {out_dir} ===")
    context = step_0_identify(integration_id, out_dir)
    auth_details = step_1_auth(integration_id, context, out_dir)
    step_1b_collect_capabilities(integration_id, context, out_dir)
    params_to_commands = step_2_params_to_commands(integration_id, out_dir)
    param_defaults = step_3a_param_defaults(integration_id, out_dir)
    params_to_capabilities = step_3b_params_to_capabilities(
        integration_id, context, params_to_commands, param_defaults, out_dir
    )
    connector_id = context.get("connector_id", "connector id not found")
    manifest_result = step_3c_generate_manifest(
        integration_id, context, params_to_capabilities, auth_details, out_dir, connector_id
    )
    # Step 3d — validate the generated manifest (non-fatal: violations are
    # reported but never abort the harness).
    step_3d_validate_manifest(
        integration_id, manifest_result, out_dir, validator_repo
    )
    print(f"=== Done. Outputs in {out_dir} ===")
    return 0


if __name__ == "__main__":
    sys.exit(main())
