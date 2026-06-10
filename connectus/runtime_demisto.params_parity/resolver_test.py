"""Unit tests for resolver.py (Phase 1 + multi-capability/auth-mapping revision).

Covers:
  * slugify / handler_dir_name helpers,
  * resolve() happy path against a fixture connector,
  * MULTI-capability enumeration (parent + sub-capability + a second capability),
  * profile enumeration across capabilities (de-duped, ordered),
  * Auth Details parsing (xsoar leaf → connector field via role + serializer),
  * empty Connector Folder Path → clear ResolverError,
  * missing handler dir → clear ResolverError,
  * handler label mismatch → ResolverError,
  * param discovery (integration YML → connector),
  * serializer disambiguation (renamed field),
  * interpolated-profile inclusion vs default-ignore (per profile),
  * hard ignore-list always dropped.

The tests build a minimal on-disk fixture (CSV + connector tree + integration
YML) under tmp_path so they are hermetic and don't touch the real repos.
"""
from __future__ import annotations

import csv
import json
from pathlib import Path

import pytest

import resolver
from resolver import (
    HARD_IGNORE_PARAMS,
    AuthMappingSpec,
    CapabilitySpec,
    ParityInputs,
    ProfileSpec,
    ResolverError,
    SubCapabilitySpec,
    handler_dir_name,
    resolve,
    slugify,
)


# ---------------------------------------------------------------------------
# Fixture builders
# ---------------------------------------------------------------------------

_INTEGRATION_ID = "Salesforce IAM"
_CONNECTOR_FOLDER = "connectors/salesforce"

# A handler that subscribes to MULTIPLE capabilities + a sub-capability:
#   - automation-and-remediation_salesforce-iam (sub of automation-and-remediation)
#   - fetch-secrets (a bare top-level capability)
_AUTH_DETAILS = json.dumps(
    {
        "auth_types": [
            {
                "type": "APIKey",
                "name": "credentials",
                "xsoar_param_map": {
                    "client_key": "client_key",
                    "client_secret": "client_secret",
                },
            }
        ],
        "other_connection": ["url", "insecure", "proxy"],
    }
)


def _write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def _make_integration_yml(path: Path) -> None:
    _write(
        path,
        """
name: Salesforce IAM
configuration:
  - name: url
    type: 0
  - name: domain
    type: 0
  - name: client_key
    type: 4
  - name: client_secret
    type: 4
  - name: create_user_enabled
    type: 8
  - name: fetch_secret_path
    type: 0
  - name: brand
    type: 0
  - name: integrationLogLevel
    type: 0
  - name: only_in_integration
    type: 0
""",
    )


def _make_connector(repo_dir: Path, *, interpolated: bool) -> None:
    base = repo_dir / "connectors" / "salesforce"
    # connection.yaml: general_configurations (domain) + a profile with prefixed
    # auth field ids carrying metadata.auth.parameter roles.
    interp_block = (
        """
    metadata:
      xsoar:
        interpolated: "true"
"""
        if interpolated
        else ""
    )
    _write(
        base / "connection.yaml",
        f"""
general_configurations:
  configurations:
    - fields:
        - id: "domain"
profiles:
  - id: "oauth2_client_credentials.salesforce"
    type: "oauth2_client_credentials"{interp_block}
    configurations:
      - fields:
          - id: "sfdc_client_key"
            metadata:
              auth:
                parameter: "client_key"
          - id: "sfdc_client_secret"
            metadata:
              auth:
                parameter: "client_secret"
""",
    )
    # configurations.yaml: per-capability behavioral fields for BOTH capabilities.
    _write(
        base / "configurations.yaml",
        """
configurations:
  - id: "automation-and-remediation"
    configurations:
      - fields:
          - id: "create_user_enabled"
  - id: "fetch-secrets"
    configurations:
      - fields:
          - id: "fetch_secret_path"
""",
    )
    # capabilities.yaml: instance-level field + parent capabilities with a
    # sub-capability under automation-and-remediation.
    _write(
        base / "capabilities.yaml",
        """
general_configurations:
  configurations:
    - fields:
        - id: "instance_name"
capabilities:
  - id: "automation-and-remediation"
    sub_capabilities:
      - id: "automation-and-remediation_salesforce-iam"
  - id: "fetch-secrets"
""",
    )
    # handler.yaml: subscribes to the SUB-capability AND a bare top-level capability.
    handler = base / "components" / "handlers" / "xsoar-salesforce-iam"
    _write(
        handler / "handler.yaml",
        """
id: "xsoar-salesforce-iam"
triggering:
  labels:
    xsoar-integration-id: "Salesforce IAM"
capabilities:
  - id: "automation-and-remediation_salesforce-iam"
    auth_options:
      - id: "oauth2_client_credentials.salesforce"
  - id: "fetch-secrets"
    auth_options:
      - id: "oauth2_client_credentials.salesforce"
""",
    )
    # serializer.yaml: renames domain -> url, and the prefixed auth fields back.
    _write(
        handler / "serializer.yaml",
        """
field_mappings:
  - id: "domain"
    field_name: "url"
  - id: "sfdc_client_key"
    field_name: "client_key"
  - id: "sfdc_client_secret"
    field_name: "client_secret"
""",
    )


def _make_csv(
    csv_path: Path,
    integration_yml_rel: str,
    connector_folder: str,
    *,
    auth_details: str = _AUTH_DETAILS,
) -> None:
    header = [
        "Integration ID",
        "Integration File Path",
        "Connector ID",
        "Connector Folder Path",
        "assignee",
        "Auth Details",
    ]
    with open(csv_path, "w", encoding="utf-8", newline="") as f:
        w = csv.writer(f)
        w.writerow(header)
        w.writerow(
            [
                _INTEGRATION_ID,
                integration_yml_rel,
                "Salesforce",
                connector_folder,
                "",
                auth_details,
            ]
        )


@pytest.fixture
def env(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    """Build a hermetic fixture and point the resolver at it."""
    workspace = tmp_path / "content"
    repo_dir = tmp_path / "unified-connectors-content"
    yml_rel = "Packs/Salesforce/Integrations/Salesforce_IAM/Salesforce_IAM.yml"
    _make_integration_yml(workspace / yml_rel)
    csv_path = tmp_path / "pipeline.csv"

    monkeypatch.setattr(resolver, "_WORKSPACE_ROOT", workspace)
    monkeypatch.setenv("CONNECTUS_REPO_DIR", str(repo_dir))

    def _build(
        *,
        interpolated: bool = False,
        connector_folder: str = _CONNECTOR_FOLDER,
        auth_details: str = _AUTH_DETAILS,
    ):
        _make_connector(repo_dir, interpolated=interpolated)
        _make_csv(csv_path, yml_rel, connector_folder, auth_details=auth_details)
        return csv_path

    return _build


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------

def test_slugify():
    assert slugify("Salesforce IAM") == "salesforce-iam"
    assert slugify("  ServiceNow v2 ") == "servicenow-v2"


def test_handler_dir_name():
    assert handler_dir_name("Salesforce IAM") == "xsoar-salesforce-iam"


# ---------------------------------------------------------------------------
# resolve() — happy path + multi-capability + discovery + serializer + policy
# ---------------------------------------------------------------------------

def test_resolve_happy_path(env):
    csv_path = env(interpolated=False)
    out = resolve(_INTEGRATION_ID, csv_path=csv_path)
    assert isinstance(out, ParityInputs)
    assert out.connector_id == "salesforce"
    assert out.connector_folder_path == _CONNECTOR_FOLDER
    assert out.serializer_path is not None


def test_multi_capability_enumeration(env):
    """The handler subscribes to a sub-capability AND a bare top-level capability;
    both must be enumerated and the sub normalized to its parent."""
    csv_path = env(interpolated=False)
    out = resolve(_INTEGRATION_ID, csv_path=csv_path)
    parent_ids = {cap.id for cap in out.capabilities}
    assert parent_ids == {"automation-and-remediation", "fetch-secrets"}

    automation = next(c for c in out.capabilities if c.id == "automation-and-remediation")
    sub_ids = {sc.id for sc in automation.sub_capabilities}
    assert sub_ids == {"automation-and-remediation_salesforce-iam"}

    fetch = next(c for c in out.capabilities if c.id == "fetch-secrets")
    assert fetch.sub_capabilities == []  # bare top-level capability, no subs


def test_capability_config_fields_collected(env):
    csv_path = env(interpolated=False)
    out = resolve(_INTEGRATION_ID, csv_path=csv_path)
    automation = next(c for c in out.capabilities if c.id == "automation-and-remediation")
    assert "create_user_enabled" in automation.config_field_ids
    fetch = next(c for c in out.capabilities if c.id == "fetch-secrets")
    assert "fetch_secret_path" in fetch.config_field_ids


def test_profiles_deduped_across_capabilities(env):
    """Both capabilities advertise the same profile id; it appears ONCE."""
    csv_path = env(interpolated=False)
    out = resolve(_INTEGRATION_ID, csv_path=csv_path)
    assert [p.id for p in out.profiles] == ["oauth2_client_credentials.salesforce"]
    prof = out.profiles[0]
    assert prof.type == "oauth2_client_credentials"
    # auth_field_to_role maps the prefixed connector field id → canonical role.
    assert prof.auth_field_to_role.get("sfdc_client_key") == "client_key"
    assert prof.auth_field_to_role.get("sfdc_client_secret") == "client_secret"


def test_auth_details_parsed(env):
    """xsoar_param_map values (roles) resolve to prefixed connector field ids."""
    csv_path = env(interpolated=False)
    out = resolve(_INTEGRATION_ID, csv_path=csv_path)
    assert len(out.auth_mappings) == 1
    am = out.auth_mappings[0]
    assert am.name == "credentials"
    assert am.type == "APIKey"
    # role "client_key" → prefixed connector field "sfdc_client_key" via profile role.
    assert am.xsoar_to_connector_field.get("client_key") == "sfdc_client_key"
    assert am.xsoar_to_connector_field.get("client_secret") == "sfdc_client_secret"
    assert out.other_connection == ["url", "insecure", "proxy"]


def test_auth_details_empty_tolerated(env):
    csv_path = env(interpolated=False, auth_details="")
    out = resolve(_INTEGRATION_ID, csv_path=csv_path)
    assert out.auth_mappings == []
    assert out.other_connection == []


def test_auth_details_invalid_json_tolerated(env):
    csv_path = env(interpolated=False, auth_details="{not-json")
    out = resolve(_INTEGRATION_ID, csv_path=csv_path)
    assert out.auth_mappings == []


def test_serializer_disambiguation(env):
    """domain→url serializer means the integration `url` param maps to connector `domain`."""
    csv_path = env(interpolated=False)
    out = resolve(_INTEGRATION_ID, csv_path=csv_path)
    assert out.serializer_by_xsoar.get("url") == "domain"
    assert out.param_to_connector_field.get("url") == "domain"
    assert "url" in out.compare_params


def test_hard_ignore_list_dropped(env):
    csv_path = env(interpolated=False)
    out = resolve(_INTEGRATION_ID, csv_path=csv_path)
    assert "brand" in out.ignored_params
    assert out.ignored_params["brand"] == "hard_ignore_list"
    assert "integrationLogLevel" in out.ignored_params
    assert "brand" not in out.compare_params
    assert "integrationLogLevel" not in out.compare_params


def test_profile_params_ignored_by_default(env):
    csv_path = env(interpolated=False)
    out = resolve(_INTEGRATION_ID, csv_path=csv_path)
    assert out.ignored_params.get("client_key") == "profile_not_interpolated"
    assert out.ignored_params.get("client_secret") == "profile_not_interpolated"
    assert "client_key" not in out.compare_params


def test_profile_params_compared_when_interpolated(env):
    csv_path = env(interpolated=True)
    out = resolve(_INTEGRATION_ID, csv_path=csv_path)
    assert "client_key" in out.compare_params
    assert "client_secret" in out.compare_params
    assert "client_key" not in out.ignored_params
    # And the mapped connector field is the prefixed id.
    assert out.param_to_connector_field.get("client_key") == "sfdc_client_key"


def test_param_only_in_integration_is_still_compared(env):
    """A YML param with no connector field still gets compared (→ MISSING_IN_CONNECTOR)."""
    csv_path = env(interpolated=False)
    out = resolve(_INTEGRATION_ID, csv_path=csv_path)
    assert "only_in_integration" in out.compare_params
    assert "only_in_integration" not in out.param_to_connector_field


def test_capability_and_general_fields_compared(env):
    csv_path = env(interpolated=False)
    out = resolve(_INTEGRATION_ID, csv_path=csv_path)
    # create_user_enabled is a configurations.yaml[capability] field.
    assert out.param_to_connector_field.get("create_user_enabled") == "create_user_enabled"
    assert "create_user_enabled" in out.compare_params
    # fetch_secret_path is from the SECOND capability — proves the union works.
    assert out.param_to_connector_field.get("fetch_secret_path") == "fetch_secret_path"
    assert "fetch_secret_path" in out.compare_params
    # domain is a connection.yaml general field.
    assert out.param_to_connector_field.get("domain") == "domain"


# ---------------------------------------------------------------------------
# resolve() — error paths
# ---------------------------------------------------------------------------

def test_empty_connector_folder_path_raises(env):
    csv_path = env(interpolated=False, connector_folder="")
    with pytest.raises(ResolverError, match="Connector Folder Path"):
        resolve(_INTEGRATION_ID, csv_path=csv_path)


def test_unknown_integration_raises(env):
    csv_path = env(interpolated=False)
    with pytest.raises(ResolverError, match="not found"):
        resolve("Does Not Exist", csv_path=csv_path)


def test_missing_handler_dir_raises(env, tmp_path):
    csv_path = env(interpolated=False, connector_folder="connectors/empty")
    # Create the connector dir but NOT the handler.
    (tmp_path / "unified-connectors-content" / "connectors" / "empty").mkdir(parents=True)
    with pytest.raises(ResolverError, match="Handler not found"):
        resolve(_INTEGRATION_ID, csv_path=csv_path)


def test_handler_label_mismatch_raises(env, tmp_path):
    csv_path = env(interpolated=False)
    # Corrupt the handler label.
    handler = (
        tmp_path / "unified-connectors-content" / "connectors" / "salesforce"
        / "components" / "handlers" / "xsoar-salesforce-iam" / "handler.yaml"
    )
    handler.write_text(
        """
id: "xsoar-salesforce-iam"
triggering:
  labels:
    xsoar-integration-id: "Some Other Integration"
capabilities:
  - id: "automation-and-remediation_salesforce-iam"
    auth_options:
      - id: "oauth2_client_credentials.salesforce"
""",
        encoding="utf-8",
    )
    with pytest.raises(ResolverError, match="label mismatch"):
        resolve(_INTEGRATION_ID, csv_path=csv_path)


def test_missing_repo_dir_raises(env, monkeypatch):
    csv_path = env(interpolated=False)
    monkeypatch.delenv("CONNECTUS_REPO_DIR", raising=False)
    with pytest.raises(ResolverError, match="CONNECTUS_REPO_DIR"):
        resolve(_INTEGRATION_ID, csv_path=csv_path)
