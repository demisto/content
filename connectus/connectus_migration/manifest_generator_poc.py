"""POC inputs for the connector_param_mapper.py — CrowdStrikeFalcon integration.

Holds the two dicts (``COMMAND_PARAMS`` and ``PARAM_DEFAULTS``) that feed
:func:`connector_param_mapper.map_params_to_capabilities` for the
CrowdStrikeFalcon integration.

Construction methodology (per the user's brief):
  1. **Auth / connection params are excluded** from ``COMMAND_PARAMS`` lists.
     These were identified from the YML's "Connect" section and from
     ``PARAMS.get`` reads at the top of CrowdStrikeFalcon.py (line 75).
     Excluded set: ``url``, ``credentials``, ``client_id``, ``secret``,
     ``legacy_version``, ``insecure``, ``proxy``.
  2. **Per-command param lists** are derived by reading the integration's
     Python source — each command's list contains only the *config* params
     (not command args) that the corresponding Python function actually
     reads via ``PARAMS.get(...)`` / ``demisto.params().get(...)``.
  3. **Scope: ~20 flagship commands** — the fetch family + the mirroring
     family + a handful of representative Automation commands. Not exhaustive.
  4. **PARAM_DEFAULTS** lists only the params that have a default supplied in
     the **code** (e.g. ``PARAMS.get("incidents_per_fetch", 15)``). Params
     read without a default (``demisto.params().get("fetch_query")``) are
     NOT in this dict — they will end up in ``general_configurations`` per
     Step 2.1's logic.
"""

import json
import subprocess
import sys
from pathlib import Path

import typer

# Integration name as it appears in the YAML.
INTEGRATION_NAME = "CrowdstrikeFalcon"

# ---------------------------------------------------------------------------
# COMMAND_PARAMS — per-command lists of integration *config* params that each
# command consumes (auth params excluded).
#
# Shape: {integration: str, commands: {command_name: [param_name, ...]}}.
# ---------------------------------------------------------------------------
COMMAND_PARAMS: dict = {
    "integration": INTEGRATION_NAME,
    "commands": {
        # -------------------------------------------------------------------
        # test-module — only checks one functional flag (whether fetching is
        # enabled, gates the test suite at line 7578 of the integration).
        # -------------------------------------------------------------------
        "test-module": [
            "isFetch",
        ],
        # -------------------------------------------------------------------
        # Fetch family — the heavyweight commands.
        # fetch-incidents drives the XSOAR side, fetch-events drives XSIAM.
        # Both walk every detection-type fetch_query when the corresponding
        # type is selected in fetch_incidents_or_detections / fetch_events_or_detections.
        # -------------------------------------------------------------------
        "fetch-incidents": [
            "fetch_query",
            "fetch_time",
            "incidents_per_fetch",
            "look_back",
            "fetch_incidents_or_detections",
            "idp_detections_fetch_query",
            "mobile_detections_fetch_query",
            "on_demand_fetch_query",
            "ofp_detection_fetch_query",
            "ngsiem_incidents_fetch_query",
            "automated_leads_fetch_query",
            "ngsiem_cases_fetch_query",
            "ngsiem_detection_fetch_query",
            "third_party_detection_fetch_query",
            "iom_fetch_query",
            "ioa_fetch_query",
            "recon_fetch_query",
            "incidentFetchInterval",
            "mirror_direction",
            "incidentType",
        ],
        "fetch-events": [
            "fetch_query",
            "fetch_time",
            "incidents_per_fetch",
            "look_back_xsiam",
            "fetch_events_or_detections",
            "idp_detections_fetch_query",
            "mobile_detections_fetch_query",
            "on_demand_fetch_query",
            "ofp_detection_fetch_query",
            "iom_fetch_query",
            "ioa_fetch_query",
            "recon_fetch_query",
            "ngsiem_incidents_fetch_query",
            "automated_leads_fetch_query",
            "ngsiem_cases_fetch_query",
            "ngsiem_detection_fetch_query",
            "third_party_detection_fetch_query",
            "eventFetchInterval",
        ],
        "fetch-assets": [
            "fetch_assets_type",
            "assetsFetchInterval",
        ],
        # -------------------------------------------------------------------
        # Mirroring family — read mirror_direction + close-related flags.
        # -------------------------------------------------------------------
        "get-remote-data": [
            "reopen_statuses",
            "close_incident",
            "mirror_direction",
            "fetch_incidents_or_detections",
        ],
        "get-modified-remote-data": [
            "mirror_direction",
            "fetch_incidents_or_detections",
        ],
        "update-remote-system": [
            "close_in_cs_falcon",
            "mirror_direction",
        ],
        "get-mapping-fields": [],
        # -------------------------------------------------------------------
        # Automation family — representative non-fetch commands.
        # Most CS Falcon commands rely on auth alone; a handful read Reliability
        # for CVE enrichment.
        # -------------------------------------------------------------------
        "cve": [
            "Reliability",
        ],
        "cs-falcon-search-detection": [],
        "cs-falcon-resolve-detection": [],
        "cs-falcon-contain-host": [],
        "cs-falcon-lift-host-containment": [],
        "cs-falcon-search-device": [],
        "cs-falcon-get-host-by-id": [],
        "cs-falcon-list-host-groups": [],
        "cs-falcon-run-command": [],
        "cs-falcon-upload-script": [],
        "cs-falcon-list-detection-summaries": [],
    },
}


# ---------------------------------------------------------------------------
# PARAM_DEFAULTS — params with a default supplied in the integration's
# Python source (not just the YAML).
#
# These are the second arg to ``PARAMS.get(name, DEFAULT)`` /
# ``demisto.params().get(name, DEFAULT)`` reads in CrowdStrikeFalcon.py.
#
# Used by Step 2.1 of the mapper to skip these params from
# ``general_configurations`` (since they're already defaulted in code).
# ---------------------------------------------------------------------------
PARAM_DEFAULTS: dict = {
    # From PARAMS.get reads at the top of the integration script
    "fetch_time": "3 days",
    "incidents_per_fetch": 15,
    # From params.get reads inside the per-detection-type fetch helpers
    # (lines 3424-3429 + 3460-3601) — all default to "" or 2.
    "look_back": 2,
    "look_back_xsiam": 2,
    "fetch_incidents_or_detections": "",
    "fetch_events_or_detections": "",
    "idp_detections_fetch_query": "",
    "mobile_detections_fetch_query": "",
    "on_demand_fetch_query": "",
    "ofp_detection_fetch_query": "",
    "ngsiem_incidents_fetch_query": "",
    "automated_leads_fetch_query": "",
    "ngsiem_cases_fetch_query": "",
    "ngsiem_detection_fetch_query": "",
    "third_party_detection_fetch_query": "",
    "iom_fetch_query": "",
    "ioa_fetch_query": "",
    "recon_fetch_query": "",
    # From the get_remote_data + asset fetch flows
    "reopen_statuses": "",
    "fetch_assets_type": "",
    "isFetch": False
}


# ===========================================================================
# Akamai WAF SIEM
# ===========================================================================
# Source: Packs/Akamai_SIEM/Integrations/Akamai_SIEM/Akamai_SIEM.yml +
#         Packs/Akamai_SIEM/Integrations/Akamai_SIEM/Akamai_SIEM.py
#
# Auth/connection params (excluded from per-command lists):
#   host, clientToken, clienttoken_creds, accessToken, accesstoken_creds,
#   clientSecret, clientsecret_creds, insecure, proxy
# ===========================================================================

INTEGRATION_NAME_AKAMAI_SIEM = "Akamai WAF SIEM"

# ---------------------------------------------------------------------------
# COMMAND_PARAMS_AKAMAI_SIEM — per-command lists of integration *config*
# params that each command consumes (auth params excluded).
# ---------------------------------------------------------------------------
COMMAND_PARAMS_AKAMAI_SIEM: dict = {
    "integration": INTEGRATION_NAME_AKAMAI_SIEM,
    "commands": {
        # -------------------------------------------------------------------
        # test-module — validates fetchLimit + configIds + the isFetch gate
        # (see Akamai_SIEM.py:1250).
        # -------------------------------------------------------------------
        "test-module": [
            "isFetch",
            "fetchLimit",
            "configIds",
            "incidentType",
        ],
        # -------------------------------------------------------------------
        # fetch-incidents (XSOAR side) — Akamai_SIEM.py:1253-1262.
        # Reads fetchTime, fetchLimit, configIds.
        # -------------------------------------------------------------------
        "fetch-incidents": [
            "fetchTime",
            "fetchLimit",
            "configIds",
            "incidentFetchInterval",
            "incidentType",
        ],
        # -------------------------------------------------------------------
        # fetch-events (XSIAM side) — Akamai_SIEM.py:1263-1330.
        # Reads longRunning (as a guard), page_size, fetchLimit, fetchTime,
        # should_skip_decode_events, configIds.
        # -------------------------------------------------------------------
        "fetch-events": [
            "fetchTime",
            "fetchLimit",
            "page_size",
            "should_skip_decode_events",
            "configIds",
            "eventFetchInterval",
            "longRunning",
        ],
        # -------------------------------------------------------------------
        # long-running-execution (XSIAM beta path) — Akamai_SIEM.py:1331-1354.
        # Reads isFetchEvents (guard), beta_page_size, should_skip_decode_events,
        # max_concurrent_tasks, fetchTime, configIds.
        # -------------------------------------------------------------------
        "long-running-execution": [
            "fetchTime",
            "beta_page_size",
            "should_skip_decode_events",
            "max_concurrent_tasks",
            "configIds",
            "isFetchEvents",
            "longRunning",
        ],
        # -------------------------------------------------------------------
        # akamai-siem-reset-offset — clears last-run state, no config params.
        # -------------------------------------------------------------------
        "akamai-siem-reset-offset": [],
        # -------------------------------------------------------------------
        # akamai-siem-get-events — uses command args (config_ids, offset,
        # limit, from_epoch, to_epoch, time_stamp), no config params.
        # -------------------------------------------------------------------
        "akamai-siem-get-events": [],
    },
}


# ---------------------------------------------------------------------------
# PARAM_DEFAULTS_AKAMAI_SIEM — params with a default supplied in the
# integration's Python source (the second arg to params.get(name, DEFAULT)).
#
# Defaults sourced from Akamai_SIEM.py lines 1264-1346.
# ---------------------------------------------------------------------------
PARAM_DEFAULTS_AKAMAI_SIEM: dict = {
    # Long-running guard flags (boolean)
    "longRunning": False,
    "isFetchEvents": False,
    "should_skip_decode_events": False,
    # Page size + fetch limit defaults (in fetch-events branch)
    "page_size": 0,  # actual default is FETCH_EVENTS_MAX_PAGE_SIZE constant in code
    "fetchLimit": 300000,  # in fetch-events branch; YML defaultvalue is "20"
    # Long-running branch defaults
    "beta_page_size": 0,  # actual default is BETA_FETCH_EVENTS_MAX_PAGE_SIZE constant
    "max_concurrent_tasks": 100,
    # Default timestamp string used in fetch-events + long-running branches
    "fetchTime": "5 minutes",
}


# ---------------------------------------------------------------------------
# POC harness — drives the two scripts end-to-end.
# ---------------------------------------------------------------------------

# Repo root: 3 levels up from this file (connectus_migration/poc.py → content/)
REPO_ROOT = Path(__file__).resolve().parent.parent.parent

# Default output dir = the root of the connectus directory
DEFAULT_OUTPUT_DIR = REPO_ROOT / "connectus"

# Integration YML paths
CS_FALCON_YML = (
    REPO_ROOT / "Packs" / "CrowdStrikeFalcon" / "Integrations"
    / "CrowdStrikeFalcon" / "CrowdStrikeFalcon.yml"
)
AKAMAI_SIEM_YML = (
    REPO_ROOT / "Packs" / "Akamai_SIEM" / "Integrations"
    / "Akamai_SIEM" / "Akamai_SIEM.yml"
)

# Sibling scripts (same directory)
PARAM_MAPPER_SCRIPT = Path(__file__).resolve().parent / "connector_param_mapper.py"
MANIFEST_GENERATOR_SCRIPT = Path(__file__).resolve().parent / "manifest_generator.py"

# Connector title — both runs use the same title so the second appends.
CONNECTOR_TITLE = "Generator POC"

# Hardcoded auth_methods (Q4 = B): a single api_key auth profile.
AUTH_METHODS_JSON = json.dumps({"auth_types": [{"name": "api_key"}]})

# Typer app for the CLI.
app = typer.Typer()


def _run_param_mapper(
    integration_yml: Path,
    command_params: dict,
    param_defaults: dict,
    output_json_path: Path,
    manual_command_to_capability_json: dict = {}
) -> None:
    """Run connector_param_mapper.py as a subprocess.

    Writes the mapping result to output_json_path.
    """
    cmd = [
        sys.executable,
        str(PARAM_MAPPER_SCRIPT),
        json.dumps(command_params),
        json.dumps(param_defaults),
        str(integration_yml),
        json.dumps(manual_command_to_capability_json),
        "-o",
        str(output_json_path),
    ]
    print(f"[POC] Running: {' '.join(cmd[:3])} ... (-o {output_json_path})")
    subprocess.run(cmd, check=True)


def _run_manifest_generator(
    integration_yml: Path,
    connector_title: str,
    mapped_params_json_file: Path,
    connectors_root: Path,
) -> None:
    """Run manifest_generator.py as a subprocess.

    Reads the mapped_params JSON written by the param mapper and inlines it.
    """
    mapped_params_str = mapped_params_json_file.read_text()
    cmd = [
        sys.executable,
        str(MANIFEST_GENERATOR_SCRIPT),
        str(integration_yml),
        connector_title,
        mapped_params_str,
        AUTH_METHODS_JSON,
        "--connectors-root",
        str(connectors_root),
    ]
    print(
        f"[POC] Running: {' '.join(cmd[:3])} ... "
        f"title={connector_title!r} root={connectors_root}"
    )
    subprocess.run(cmd, check=True)


@app.command()
def main(
    output: Path = typer.Option(
        DEFAULT_OUTPUT_DIR,
        "-o",
        "--output",
        help=(
            "Output directory for the param-mapping JSONs and the generated "
            "connector tree. Defaults to the root of the connectus repo."
        ),
    ),
) -> None:
    """End-to-end POC: maps params for two integrations and generates one
    shared connector with two handlers (CrowdStrikeFalcon then Akamai WAF SIEM).
    """
    output.mkdir(parents=True, exist_ok=True)
    connectors_root = output / "connectors"
    cs_falcon_mapping = output / "cs_falcon_param_mapping.json"
    akamai_siem_mapping = output / "akamai_siem_param_mapping.json"

    print(f"[POC] Output directory: {output}")
    print(f"[POC] Connectors root:  {connectors_root}")

    print("\n=== Step 1/4: CrowdStrikeFalcon — connector_param_mapper ===")
    _run_param_mapper(
        integration_yml=CS_FALCON_YML,
        command_params=COMMAND_PARAMS,
        param_defaults=PARAM_DEFAULTS,
        output_json_path=cs_falcon_mapping,
    )

    print("\n=== Step 2/4: CrowdStrikeFalcon — manifest_generator (from scratch) ===")
    _run_manifest_generator(
        integration_yml=CS_FALCON_YML,
        connector_title=CONNECTOR_TITLE,
        mapped_params_json_file=cs_falcon_mapping,
        connectors_root=connectors_root,
    )

    print("\n=== Step 3/4: Akamai WAF SIEM — connector_param_mapper ===")
    _run_param_mapper(
        integration_yml=AKAMAI_SIEM_YML,
        command_params=COMMAND_PARAMS_AKAMAI_SIEM,
        param_defaults=PARAM_DEFAULTS_AKAMAI_SIEM,
        output_json_path=akamai_siem_mapping,
        manual_command_to_capability_json={"longRunning": ["Log Collection"]}
        
    )

    print("\n=== Step 4/4: Akamai WAF SIEM — manifest_generator (append handler) ===")
    _run_manifest_generator(
        integration_yml=AKAMAI_SIEM_YML,
        connector_title=CONNECTOR_TITLE,
        mapped_params_json_file=akamai_siem_mapping,
        connectors_root=connectors_root,
    )

    print(f"\n[POC] Done. Connector at: {connectors_root / 'generatorpoc'}")


if __name__ == "__main__":
    app()
