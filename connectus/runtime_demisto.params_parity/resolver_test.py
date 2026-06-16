"""Unit tests for resolver.py (Phase 1 + multi-capability/interpolation revision).

Covers:
  * slugify / handler_dir_name helpers,
  * resolve() happy path against a fixture connector,
  * MULTI-capability enumeration (parent + sub-capability + a second capability),
  * profile enumeration across capabilities (de-duped, ordered),
  * interpolation_mapping parsing (role → xsoar path) + role → connector field,
  * empty Connector Folder Path → clear ResolverError,
  * missing handler dir → clear ResolverError,
  * handler label mismatch → ResolverError,
  * param discovery (integration YML → connector),
  * serializer disambiguation (renamed field),
  * interpolated-profile inclusion vs default-ignore (per profile, by mapping
    PRESENCE),
  * a credentials.identifier + credentials.password pair collapses to ONE
    top-level `credentials` compare param,
  * param_to_connector_field points the xsoar param at the right connector field,
  * malformed/blank interpolation pairs are tolerated,
  * hard ignore-list always dropped.

The interpolation contract (NEW format):
  * interpolation is signaled by a non-empty
    ``profiles[].metadata.xsoar.interpolation_mapping`` (a comma-separated list
    of ``ROLE:XSOAR_PATH`` pairs). The old boolean ``interpolated`` flag and the
    CSV ``Auth Details`` column are GONE.
  * LEFT (ROLE) matches a profile field's ``metadata.auth.parameter``.
  * RIGHT (XSOAR_PATH) is the demisto.params() key path; the compared param is
    its TOP-LEVEL segment (before the first ``.``).

The tests build a minimal on-disk fixture (CSV + connector tree + integration
YML) under tmp_path so they are hermetic and don't touch the real repos.
"""
from __future__ import annotations

import csv
from pathlib import Path

import pytest

import resolver
from resolver import (
    HARD_IGNORE_PARAMS,
    CapabilitySpec,
    ParityInputs,
    ProfileSpec,
    ResolverError,
    SubCapabilitySpec,
    _is_hidden_param,
    handler_dir_name,
    resolve,
    slugify,
)


# ---------------------------------------------------------------------------
# Fixture builders
# ---------------------------------------------------------------------------

_INTEGRATION_ID = "Salesforce IAM"
_CONNECTOR_FOLDER = "connectors/salesforce"

# The interpolation_mapping LEFT values are the connector auth ROLES (which match
# each profile field's metadata.auth.parameter); RIGHT values are the xsoar param
# PATHS. Here both client_key and client_secret are flat top-level xsoar params.
_INTERPOLATION_MAPPING = (
    "sfdc_client_key_role:client_key,sfdc_client_secret_role:client_secret"
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
  - name: legacy_hidden_flat
    type: 4
    hidden: true
""",
    )


def _make_connector(
    repo_dir: Path,
    *,
    interpolation_mapping: str | None = _INTERPOLATION_MAPPING,
) -> None:
    base = repo_dir / "connectors" / "salesforce"
    # connection.yaml: general_configurations (domain) + a profile with prefixed
    # auth field ids carrying metadata.auth.parameter roles. Interpolation is
    # signaled by a non-empty metadata.xsoar.interpolation_mapping.
    interp_block = (
        f"""
    metadata:
      xsoar:
        interpolation_mapping: {interpolation_mapping}
"""
        if interpolation_mapping is not None
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
                parameter: "sfdc_client_key_role"
          - id: "sfdc_client_secret"
            metadata:
              auth:
                parameter: "sfdc_client_secret_role"
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
    # serializer.yaml: renames domain -> url, and maps the prefixed profile auth
    # field ids back to the integration's flat param ids (so a non-interpolated
    # profile's auth params can be traced to their owning profile field).
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
) -> None:
    # The resolver reads ONLY Integration File Path + Connector Folder Path from
    # the CSV — no Auth Details column anymore.
    header = [
        "Integration ID",
        "Integration File Path",
        "Connector ID",
        "Connector Folder Path",
        "assignee",
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
        interpolation_mapping: str | None = _INTERPOLATION_MAPPING,
        connector_folder: str = _CONNECTOR_FOLDER,
    ):
        _make_connector(repo_dir, interpolation_mapping=interpolation_mapping)
        _make_csv(csv_path, yml_rel, connector_folder)
        return csv_path

    return _build


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------

def test_slugify():
    assert slugify("Salesforce IAM") == "salesforce-iam"
    assert slugify("  ServiceNow v2 ") == "servicenow-v2"
    assert slugify("AWS - ACM") == "aws-acm"


def test_handler_dir_name():
    assert handler_dir_name("Salesforce IAM") == "xsoar-salesforce-iam"
    assert handler_dir_name("AWS - ACM") == "xsoar-aws-acm"


def test_instance_name_in_hard_ignore_params():
    """The connector-injected `instance_name` is on the hard ignore-list so it is
    never flagged EXTRA_IN_CONNECTOR."""
    assert "instance_name" in HARD_IGNORE_PARAMS


# ---------------------------------------------------------------------------
# resolve() — happy path + multi-capability + discovery + serializer + policy
# ---------------------------------------------------------------------------

def test_resolve_happy_path(env):
    csv_path = env(interpolation_mapping=None)
    out = resolve(_INTEGRATION_ID, csv_path=csv_path)
    assert isinstance(out, ParityInputs)
    assert out.connector_id == "salesforce"
    assert out.connector_folder_path == _CONNECTOR_FOLDER
    assert out.serializer_path is not None


def test_multi_capability_enumeration(env):
    """The handler subscribes to a sub-capability AND a bare top-level capability;
    both must be enumerated and the sub normalized to its parent."""
    csv_path = env(interpolation_mapping=None)
    out = resolve(_INTEGRATION_ID, csv_path=csv_path)
    parent_ids = {cap.id for cap in out.capabilities}
    assert parent_ids == {"automation-and-remediation", "fetch-secrets"}

    automation = next(c for c in out.capabilities if c.id == "automation-and-remediation")
    sub_ids = {sc.id for sc in automation.sub_capabilities}
    assert sub_ids == {"automation-and-remediation_salesforce-iam"}

    fetch = next(c for c in out.capabilities if c.id == "fetch-secrets")
    assert fetch.sub_capabilities == []  # bare top-level capability, no subs


def test_capability_config_fields_collected(env):
    csv_path = env(interpolation_mapping=None)
    out = resolve(_INTEGRATION_ID, csv_path=csv_path)
    automation = next(c for c in out.capabilities if c.id == "automation-and-remediation")
    assert "create_user_enabled" in automation.config_field_ids
    fetch = next(c for c in out.capabilities if c.id == "fetch-secrets")
    assert "fetch_secret_path" in fetch.config_field_ids


def test_profiles_deduped_across_capabilities(env):
    """Both capabilities advertise the same profile id; it appears ONCE."""
    csv_path = env(interpolation_mapping=None)
    out = resolve(_INTEGRATION_ID, csv_path=csv_path)
    assert [p.id for p in out.profiles] == ["oauth2_client_credentials.salesforce"]
    prof = out.profiles[0]
    assert prof.type == "oauth2_client_credentials"
    # auth_field_to_role maps the prefixed connector field id → canonical role.
    assert prof.auth_field_to_role.get("sfdc_client_key") == "sfdc_client_key_role"
    assert prof.auth_field_to_role.get("sfdc_client_secret") == "sfdc_client_secret_role"


def test_serializer_disambiguation(env):
    """domain→url serializer means the integration `url` param maps to connector `domain`."""
    csv_path = env(interpolation_mapping=None)
    out = resolve(_INTEGRATION_ID, csv_path=csv_path)
    assert out.serializer_by_xsoar.get("url") == "domain"
    assert out.param_to_connector_field.get("url") == "domain"
    assert "url" in out.compare_params


def test_hard_ignore_list_dropped(env):
    csv_path = env(interpolation_mapping=None)
    out = resolve(_INTEGRATION_ID, csv_path=csv_path)
    assert "brand" in out.ignored_params
    assert out.ignored_params["brand"] == "hard_ignore_list"
    assert "integrationLogLevel" in out.ignored_params
    assert "brand" not in out.compare_params
    assert "integrationLogLevel" not in out.compare_params


def test_is_hidden_param():
    """`_is_hidden_param` is True only when a param is hidden ON THE PLATFORM:
    `hidden: true` (hidden everywhere) or a `hidden:` list that includes
    "platform". A list naming only non-platform marketplaces (e.g. ["xsoar"],
    ["marketplacev2"]) means the param is still on the platform → False. False
    for `hidden: false`, an empty list, and an absent `hidden` key."""
    assert _is_hidden_param({"name": "x", "hidden": True}) is True
    assert _is_hidden_param({"name": "x", "hidden": ["platform"]}) is True
    assert _is_hidden_param({"name": "x", "hidden": ["xsoar", "platform"]}) is True
    assert _is_hidden_param({"name": "x", "hidden": ["xsoar"]}) is False
    assert _is_hidden_param({"name": "x", "hidden": ["marketplacev2"]}) is False
    assert _is_hidden_param({"name": "x", "hidden": False}) is False
    assert _is_hidden_param({"name": "x", "hidden": []}) is False
    assert _is_hidden_param({"name": "x"}) is False


def test_hidden_yml_param_is_ignored_as_hidden(env):
    """POLICY: a YML param marked `hidden: true` is NOT migrated to the connector,
    so it is IGNORED with the DISTINCT reason "hidden" — and is NOT compared."""
    csv_path = env(interpolation_mapping=None)
    out = resolve(_INTEGRATION_ID, csv_path=csv_path)
    assert "legacy_hidden_flat" in out.ignored_params
    assert out.ignored_params["legacy_hidden_flat"] == "hidden"
    assert "legacy_hidden_flat" not in out.compare_params


def test_non_hidden_params_still_compared(env):
    """Non-hidden params (incl type-9 credentials handled elsewhere, type-4 auth,
    and plain config) remain compared — only hard-ignore + hidden are dropped."""
    csv_path = env(interpolation_mapping=None)
    out = resolve(_INTEGRATION_ID, csv_path=csv_path)
    assert "url" in out.compare_params
    assert "client_key" in out.compare_params
    assert "client_secret" in out.compare_params
    assert "only_in_integration" in out.compare_params


# ---------------------------------------------------------------------------
# Interpolation — by mapping PRESENCE (the NEW format)
# ---------------------------------------------------------------------------

def test_interpolation_mapping_parsed(env):
    """A non-empty interpolation_mapping ⇒ ProfileSpec.interpolated is True and
    the role → xsoar path mapping is parsed."""
    csv_path = env()
    out = resolve(_INTEGRATION_ID, csv_path=csv_path)
    prof = out.profiles[0]
    assert prof.interpolated is True
    assert prof.interpolation_mapping == {
        "sfdc_client_key_role": "client_key",
        "sfdc_client_secret_role": "client_secret",
    }
    # connector_field_to_xsoar_param derives field id → top-level xsoar param.
    f2x = prof.connector_field_to_xsoar_param()
    assert f2x == {
        "sfdc_client_key": "client_key",
        "sfdc_client_secret": "client_secret",
    }


def test_connector_field_to_xsoar_path_returns_full_dotted_paths(env):
    """connector_field_to_xsoar_path() preserves the FULL dotted xsoar destination
    path (NOT collapsed to the top-level segment), so the connector-side value can
    be dug out of the shared instance_values at the exact leaf the integration
    sees. connector_field_to_xsoar_param() must STILL return the collapsed
    top-level form (unchanged) for compare-scoping."""
    csv_path = env(
        interpolation_mapping=(
            "sfdc_client_key_role:credentials.identifier,"
            "sfdc_client_secret_role:credentials.password"
        ),
    )
    out = resolve(_INTEGRATION_ID, csv_path=csv_path)
    prof = out.profiles[0]

    # FULL dotted paths preserved.
    assert prof.connector_field_to_xsoar_path() == {
        "sfdc_client_key": "credentials.identifier",
        "sfdc_client_secret": "credentials.password",
    }
    # Collapsed top-level form UNCHANGED.
    assert prof.connector_field_to_xsoar_param() == {
        "sfdc_client_key": "credentials",
        "sfdc_client_secret": "credentials",
    }


def test_connector_field_to_xsoar_path_flat_paths(env):
    """For a flat (non-dotted) mapping the full path equals the top-level segment;
    both methods agree."""
    csv_path = env()  # default mapping: flat client_key / client_secret
    out = resolve(_INTEGRATION_ID, csv_path=csv_path)
    prof = out.profiles[0]
    assert prof.connector_field_to_xsoar_path() == {
        "sfdc_client_key": "client_key",
        "sfdc_client_secret": "client_secret",
    }
    assert prof.connector_field_to_xsoar_param() == {
        "sfdc_client_key": "client_key",
        "sfdc_client_secret": "client_secret",
    }


def test_profile_params_compared_even_when_no_mapping(env):
    """NEW POLICY: there is no 'profile_not_interpolated' ignore anymore. A
    profile's auth params are COMPARED verbatim regardless of whether the profile
    is interpolated — only HARD_IGNORE_PARAMS are dropped. The interpolation
    mapping is retained ONLY for value-seeding, not for compare-scope."""
    csv_path = env(interpolation_mapping=None)
    out = resolve(_INTEGRATION_ID, csv_path=csv_path)
    prof = out.profiles[0]
    assert prof.interpolated is False
    assert "client_key" not in out.ignored_params
    assert "client_secret" not in out.ignored_params
    assert "client_key" in out.compare_params
    assert "client_secret" in out.compare_params


def test_profile_params_compared_when_interpolated(env):
    """Presence of interpolation_mapping ⇒ the mapped xsoar params are compared,
    and param_to_connector_field points each at the contributing connector field."""
    csv_path = env()
    out = resolve(_INTEGRATION_ID, csv_path=csv_path)
    assert "client_key" in out.compare_params
    assert "client_secret" in out.compare_params
    assert "client_key" not in out.ignored_params
    # The mapped connector field is the prefixed id.
    assert out.param_to_connector_field.get("client_key") == "sfdc_client_key"
    assert out.param_to_connector_field.get("client_secret") == "sfdc_client_secret"


def test_credentials_pair_collapses_to_one_top_level_param(env):
    """A `credentials.identifier` + `credentials.password` mapping pair collapses
    to ONE top-level `credentials` compare param (AWS-style)."""
    csv_path = env(
        interpolation_mapping=(
            "sfdc_client_key_role:credentials.identifier,"
            "sfdc_client_secret_role:credentials.password"
        ),
    )
    out = resolve(_INTEGRATION_ID, csv_path=csv_path)
    prof = out.profiles[0]
    # Both fields map to the SAME top-level xsoar param `credentials`.
    f2x = prof.connector_field_to_xsoar_param()
    assert f2x == {
        "sfdc_client_key": "credentials",
        "sfdc_client_secret": "credentials",
    }
    # This test asserts only the connector_field_to_xsoar_param() de-dupe behavior
    # (retained method): both fields collapse to the same top-level `credentials`.
    # `credentials` is not a YML param in this fixture, so it is NOT compared.
    # Under the NEW policy the YML flat params (client_key/client_secret) ARE
    # compared verbatim (they are not on the hard ignore-list).
    assert "credentials" not in out.compare_params
    assert "client_key" in out.compare_params
    assert "client_secret" in out.compare_params


def _build_credentials_type9_fixture(tmp_path, monkeypatch, *, cred_type: int = 9):
    """Build a hermetic fixture whose integration YML carries a top-level
    `credentials` param (configurable type) and an INTERPOLATED profile whose
    mapping targets `credentials.identifier` AND `credentials.password`. Returns
    the csv_path so the caller can resolve()."""
    workspace = tmp_path / "content"
    repo_dir = tmp_path / "unified-connectors-content"
    yml_rel = "Packs/X/Integrations/X/X.yml"
    _write(
        workspace / yml_rel,
        f"""
name: Salesforce IAM
configuration:
  - name: credentials
    type: {cred_type}
""",
    )
    base = repo_dir / "connectors" / "salesforce"
    _write(
        base / "connection.yaml",
        """
general_configurations:
  configurations:
    - fields: []
profiles:
  - id: "p.x"
    type: "passthrough"
    metadata:
      xsoar:
        interpolation_mapping: key_role:credentials.identifier,secret_role:credentials.password
    configurations:
      - fields:
          - id: "f_key"
            metadata:
              auth:
                parameter: "key_role"
          - id: "f_secret"
            metadata:
              auth:
                parameter: "secret_role"
""",
    )
    _write(base / "configurations.yaml", "configurations: []\n")
    _write(
        base / "capabilities.yaml",
        """
general_configurations:
  configurations:
    - fields: []
capabilities:
  - id: "automation-and-remediation"
""",
    )
    handler = base / "components" / "handlers" / "xsoar-salesforce-iam"
    _write(
        handler / "handler.yaml",
        """
id: "xsoar-salesforce-iam"
triggering:
  labels:
    xsoar-integration-id: "Salesforce IAM"
capabilities:
  - id: "automation-and-remediation"
    auth_options:
      - id: "p.x"
""",
    )
    csv_path = tmp_path / "pipeline.csv"
    _make_csv(csv_path, yml_rel, "connectors/salesforce")

    monkeypatch.setattr(resolver, "_WORKSPACE_ROOT", workspace)
    monkeypatch.setenv("CONNECTUS_REPO_DIR", str(repo_dir))
    return csv_path


def test_credentials_type9_is_compared(tmp_path, monkeypatch):
    """NEW POLICY: a type-9 (credentials) param is COMPARED verbatim like
    everything else — there is no 'credentials_type9_interpolated' exclusion. The
    full credentials object on the integration side vs the connector's delivered
    {identifier,password} MUST surface as a real VALUE_MISMATCH at diff time; the
    resolver no longer masks it. So `credentials` is in compare_params and NOT in
    ignored_params, for ANY type."""
    csv_path = _build_credentials_type9_fixture(tmp_path, monkeypatch, cred_type=9)

    out = resolve(_INTEGRATION_ID, csv_path=csv_path)
    assert "credentials" in out.compare_params
    assert "credentials" not in out.ignored_params


def test_credentials_compared_once_regardless_of_type(tmp_path, monkeypatch):
    """The interpolated-mapped top-level `credentials` param is compared exactly
    once whether it is type 9 or type 0 — type no longer changes the policy."""
    for cred_type in (9, 0):
        csv_path = _build_credentials_type9_fixture(
            tmp_path / f"t{cred_type}", monkeypatch, cred_type=cred_type
        )
        out = resolve(_INTEGRATION_ID, csv_path=csv_path)
        assert "credentials" in out.compare_params
        creds_count = sum(1 for p in out.compare_params if p == "credentials")
        assert creds_count == 1
        assert "credentials" not in out.ignored_params


def test_malformed_interpolation_pairs_tolerated(env):
    """Blank / malformed pairs (no colon, empty side) are silently ignored; the
    valid pairs still parse."""
    csv_path = env(
        interpolation_mapping=(
            "sfdc_client_key_role:client_key, ,no_colon_here,:emptyleft,emptyright:,"
            "sfdc_client_secret_role:client_secret"
        ),
    )
    out = resolve(_INTEGRATION_ID, csv_path=csv_path)
    prof = out.profiles[0]
    assert prof.interpolation_mapping == {
        "sfdc_client_key_role": "client_key",
        "sfdc_client_secret_role": "client_secret",
    }
    assert "client_key" in out.compare_params
    assert "client_secret" in out.compare_params


def test_blank_interpolation_mapping_is_not_interpolated(env):
    """An empty / whitespace interpolation_mapping ⇒ NOT interpolated. Under the
    new policy the profile's auth params are still COMPARED (not ignored)."""
    csv_path = env(interpolation_mapping="   ")
    out = resolve(_INTEGRATION_ID, csv_path=csv_path)
    prof = out.profiles[0]
    assert prof.interpolated is False
    assert "client_key" not in out.ignored_params
    assert "client_key" in out.compare_params


def test_param_only_in_integration_is_still_compared(env):
    """A YML param with no matching connector field is STILL compared. Under the
    new policy param_to_connector_field records the identity mapping (serializer
    rename → identity) for attribution; the absence of a real connector field
    surfaces as MISSING_IN_CONNECTOR at diff time, which is correct."""
    csv_path = env(interpolation_mapping=None)
    out = resolve(_INTEGRATION_ID, csv_path=csv_path)
    assert "only_in_integration" in out.compare_params
    assert out.param_to_connector_field.get("only_in_integration") == "only_in_integration"
    assert "only_in_integration" not in out.ignored_params


def test_capability_and_general_fields_compared(env):
    csv_path = env(interpolation_mapping=None)
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
    csv_path = env(interpolation_mapping=None, connector_folder="")
    with pytest.raises(ResolverError, match="Connector Folder Path"):
        resolve(_INTEGRATION_ID, csv_path=csv_path)


def test_unknown_integration_raises(env):
    csv_path = env(interpolation_mapping=None)
    with pytest.raises(ResolverError, match="not found"):
        resolve("Does Not Exist", csv_path=csv_path)


def test_missing_handler_dir_raises(env, tmp_path):
    csv_path = env(interpolation_mapping=None, connector_folder="connectors/empty")
    # Create the connector dir but NOT the handler.
    (tmp_path / "unified-connectors-content" / "connectors" / "empty").mkdir(parents=True)
    with pytest.raises(ResolverError, match="Handler not found"):
        resolve(_INTEGRATION_ID, csv_path=csv_path)


def test_handler_label_mismatch_raises(env, tmp_path):
    csv_path = env(interpolation_mapping=None)
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
    csv_path = env(interpolation_mapping=None)
    monkeypatch.delenv("CONNECTUS_REPO_DIR", raising=False)
    with pytest.raises(ResolverError, match="CONNECTUS_REPO_DIR"):
        resolve(_INTEGRATION_ID, csv_path=csv_path)


# ===========================================================================
# Variant expansion (_expand_variants) — the per-capability matrix logic.
#
# These are PURE-LOGIC tests (no I/O): they build CapabilitySpec lists directly
# and assert the legal variant matrix, per multi_capability_variant_design.md.
# ===========================================================================

from resolver import (  # noqa: E402
    CAPABILITY_FETCH_FLAG,
    FETCH_FLAG_NAMES,
    CapabilityVariant,
    _expand_variants,
    fetch_flag_for_capability,
)


def _cap(parent_id: str) -> CapabilitySpec:
    return CapabilitySpec(id=parent_id)


def _active_flags(variant: CapabilityVariant) -> list[str]:
    return [name for name, on in variant.fetch_flags.items() if on]


def test_fetch_flag_classifier():
    # VALUES are the EXACT XSOAR instance-creation toggle param names.
    assert fetch_flag_for_capability("fetch-issues") == "isFetch"
    assert fetch_flag_for_capability("log-collection") == "isFetchEvents"
    assert fetch_flag_for_capability("fetch-assets-and-vulnerabilities") == "isFetchAssets"
    assert fetch_flag_for_capability("threat-intelligence-and-enrichment") == "feed"
    assert fetch_flag_for_capability("fetch-secrets") == "isFetchCredentials"
    # Always-on caps map to None.
    assert fetch_flag_for_capability("automation-and-remediation") is None
    assert fetch_flag_for_capability("unknown-capability") is None


def test_capabilityspec_fetch_flag_property():
    assert _cap("fetch-issues").fetch_flag == "isFetch"
    assert _cap("automation-and-remediation").fetch_flag is None


def test_expand_variants_akamai_siem_two_fetch_plus_automation():
    """Automation + fetch-issues + log-collection → exactly 2 LEGAL variants."""
    caps = [
        _cap("automation-and-remediation"),
        _cap("fetch-issues"),
        _cap("log-collection"),
    ]
    variants = _expand_variants(caps)
    assert len(variants) == 2

    by_id = {v.id: v for v in variants}
    fi = by_id["automation-and-remediation+fetch-issues"]
    lc = by_id["automation-and-remediation+log-collection"]

    # Each variant bundles automation + EXACTLY ONE fetch capability.
    assert fi.enabled_capability_ids == [
        "automation-and-remediation",
        "fetch-issues",
    ]
    assert lc.enabled_capability_ids == [
        "automation-and-remediation",
        "log-collection",
    ]

    # Exactly one fetch flag true per variant; the illegal pair never co-occurs.
    assert _active_flags(fi) == ["isFetch"]
    assert _active_flags(lc) == ["isFetchEvents"]
    assert fi.fetch_flags["isFetchEvents"] is False
    assert lc.fetch_flags["isFetch"] is False

    # Every variant carries the COMPLETE flag set (all keys present).
    for v in variants:
        assert set(v.fetch_flags) == set(FETCH_FLAG_NAMES)


def test_expand_variants_automation_only_single_variant():
    variants = _expand_variants([_cap("automation-and-remediation")])
    assert len(variants) == 1
    v = variants[0]
    assert v.enabled_capability_ids == ["automation-and-remediation"]
    # No fetch flag enabled.
    assert _active_flags(v) == []
    assert all(val is False for val in v.fetch_flags.values())


def test_expand_variants_single_fetch_no_automation():
    """A pure event collector (log-collection only, no automation) → 1 variant."""
    variants = _expand_variants([_cap("log-collection")])
    assert len(variants) == 1
    v = variants[0]
    assert v.enabled_capability_ids == ["log-collection"]
    assert _active_flags(v) == ["isFetchEvents"]


def test_expand_variants_multi_fetch_no_automation():
    """Multiple fetch caps, no always-on → one SINGLE-cap variant each."""
    variants = _expand_variants(
        [_cap("fetch-issues"), _cap("log-collection"), _cap("fetch-secrets")]
    )
    assert len(variants) == 3
    for v in variants:
        # Each variant has exactly ONE capability and ONE active fetch flag.
        assert len(v.capabilities) == 1
        assert len(_active_flags(v)) == 1
    active = sorted(_active_flags(v)[0] for v in variants)
    assert active == sorted(["isFetch", "isFetchEvents", "isFetchCredentials"])


def test_expand_variants_empty_raises():
    with pytest.raises(ResolverError, match="no capabilities"):
        _expand_variants([])


# ===========================================================================
# general_configurations field collection (view_group-scoped).
# ===========================================================================

from resolver import (  # noqa: E402
    _capabilities_from_handler,
    _general_config_fields_for_view_groups,
    _view_groups_for_capability,
)


_CONFIG_DOC = {
    "general_configurations": {
        "configurations": [
            {"view_group": "siem", "fields": [{"id": "fetchTime"}, {"id": "fetchLimit"}]},
            {"view_group": "other", "fields": [{"id": "other_field"}]},
        ]
    },
    "configurations": [
        {
            "id": "fetch-issues_x",
            "view_group": "siem",
            "configurations": [{"fields": [{"id": "incidentType"}]}],
        },
        {
            "id": "log-collection_x",
            "view_group": "siem",
            "configurations": [{"fields": [{"id": "isFetchEvents"}]}],
        },
    ],
}


def test_view_groups_for_capability():
    assert _view_groups_for_capability(_CONFIG_DOC, "fetch-issues_x") == {"siem"}
    assert _view_groups_for_capability(_CONFIG_DOC, "missing") == set()


def test_general_config_fields_for_view_groups():
    got = _general_config_fields_for_view_groups(_CONFIG_DOC, {"siem"})
    assert set(got) == {"fetchTime", "fetchLimit"}
    # A different view_group's general fields are NOT included.
    assert "other_field" not in got
    # No view groups → nothing.
    assert _general_config_fields_for_view_groups(_CONFIG_DOC, set()) == []


def test_capabilities_include_general_config_for_view_group():
    """A fetch-issues capability must pick up the SIEM general-config fields
    (fetchTime/fetchLimit) via its shared view_group — not just its own
    capability-scoped fields."""
    handler_doc = {"capabilities": [{"id": "fetch-issues_x"}]}
    capabilities_doc = {
        "capabilities": [
            {"id": "fetch-issues", "sub_capabilities": [{"id": "fetch-issues_x"}]}
        ]
    }
    caps = _capabilities_from_handler(handler_doc, capabilities_doc, _CONFIG_DOC)
    assert len(caps) == 1
    fields = caps[0].config_field_ids
    # capability-scoped field + the view_group-scoped general-config fields.
    assert "incidentType" in fields
    assert "fetchTime" in fields
    assert "fetchLimit" in fields
    # log-collection-only field must NOT leak into the fetch-issues capability.
    assert "isFetchEvents" not in fields


# ===========================================================================
# field_specs collection (field_type / default_value / enum_values).
# ===========================================================================

from resolver import _collect_field_specs  # noqa: E402


def test_collect_field_specs_from_configurations_and_connection():
    configurations_doc = {
        "general_configurations": {
            "configurations": [
                {
                    "fields": [
                        {
                            "id": "integrationLogLevel",
                            "field_type": "select",
                            "options": {
                                "default_value": "Off",
                                "values": [{"key": "Off"}, {"key": "Debug"}],
                            },
                        }
                    ]
                }
            ]
        },
        "configurations": [
            {
                "id": "log-collection_x",
                "configurations": [
                    {"fields": [{"id": "alertFetchInterval", "field_type": "duration"}]},
                    {"fields": [{"id": "defaultIgnore", "field_type": "checkbox"}]},
                    {
                        "fields": [
                            {
                                "id": "incidentType",
                                "field_type": "select",
                                # Real manifest nesting: metadata.xsoar.config_type.
                                "metadata": {"xsoar": {"config_type": "backend"}},
                            }
                        ]
                    },
                ],
            }
        ],
    }
    connection_doc = {
        "profiles": [
            {
                "id": "plain.x",
                "configurations": [
                    {
                        "fields": [
                            {
                                "id": "plain.x_engine",
                                "field_type": "input",
                                "xsoar": {"config_type": "backend"},
                            }
                        ]
                    },
                ],
            }
        ]
    }

    specs = _collect_field_specs(configurations_doc, connection_doc)

    # select carries enum keys + default.
    assert specs["integrationLogLevel"]["field_type"] == "select"
    assert specs["integrationLogLevel"]["default_value"] == "Off"
    assert specs["integrationLogLevel"]["enum_values"] == ["Off", "Debug"]
    # plain (non-backend) field has no config_type.
    assert specs["integrationLogLevel"]["config_type"] is None
    # per-capability fields captured with their types.
    assert specs["alertFetchInterval"]["field_type"] == "duration"
    assert specs["defaultIgnore"]["field_type"] == "checkbox"
    # config_type: backend captured from xsoar.config_type (entity-reference field).
    assert specs["incidentType"]["config_type"] == "backend"
    # connection.yaml profile fields captured too, including config_type: backend.
    assert specs["plain.x_engine"]["field_type"] == "input"
    assert specs["plain.x_engine"]["config_type"] == "backend"


def test_collect_field_specs_tolerates_missing_docs():
    assert _collect_field_specs(None, None) == {}
    assert _collect_field_specs({}, {}) == {}
