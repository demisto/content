"""Unit tests for ucp_capture._build_instance_payload (Phase 2).

These test the PURE payload-builder logic (no network/k8s): given a fake UCP
``creation_view`` and resolved ``CapabilitySpec`` / ``ProfileSpec`` objects, the
builder must:

  * enable ALL parent capabilities + their subscribed sub-capabilities,
  * union the configuration scope over every enabled (sub-)capability — the
    accepted config field ids come from the CONNECTOR MANIFEST
    (CapabilitySpec.config_field_ids parsed from configurations.yaml), NOT the
    live GET /creation view (which is now only a logged cross-check),
  * push the SHARED instance_values into the configuration (never connector defaults),
  * skip config keys the connector doesn't declare (→ MISSING_IN_CONNECTOR later),
  * set interpolated-profile auth fields to the SAME instance values (the
    connector-field ↔ xsoar param mapping is derived from the ProfileSpec's
    interpolation_mapping + the fields' metadata.auth.parameter roles),
  * dummy-fill non-interpolated-profile auth fields.
"""
from __future__ import annotations

import pytest

from resolver import (
    CapabilitySpec,
    ProfileSpec,
    SubCapabilitySpec,
)
from ucp_capture import (
    _ENGINE_FIELD_VALUES,
    _build_instance_payload,
    _dig,
)


# ---------------------------------------------------------------------------
# Fake creation view
# ---------------------------------------------------------------------------

def _creation_view():
    """A creation view exposing two capabilities, methods for one profile, and
    a configuration step with fields scoped per (sub-)capability."""
    return {
        "instance_id": "inst-123",
        "connector_id": "salesforce",
        "steps": [
            # steps[0] — capabilities
            {
                "capabilities": [
                    {"id": "automation-and-remediation"},
                    {"id": "fetch-secrets"},
                    {"id": "identity"},  # available but NOT subscribed
                ]
            },
            # steps[1] — connection methods + connection-general sections
            {
                "methods": [
                    {
                        "method_unique_id": "m-auto",
                        "capability_id": "automation-and-remediation",
                        "options": [{"profile_id": "oauth2.salesforce"}],
                    },
                    {
                        "method_unique_id": "m-fetch",
                        "capability_id": "fetch-secrets",
                        "options": [{"profile_id": "oauth2.salesforce"}],
                    },
                ],
                "sections": [
                    {"data": [{"fields": [{"id": "domain"}]}]},
                ],
            },
            # steps[2] — configuration sections, keyed by capability_id
            {
                "sections": [
                    {
                        "capability_id": "automation-and-remediation",
                        "data": [
                            {
                                "fields": [
                                    {
                                        "id": "create_user_enabled",
                                        "options": {"default_value": "true"},
                                    }
                                ]
                            }
                        ],
                    },
                    {
                        "capability_id": "fetch-secrets",
                        "data": [{"fields": [{"id": "fetch_secret_path"}]}],
                    },
                    {
                        "capability_id": "identity",  # NOT enabled → excluded
                        "data": [{"fields": [{"id": "identity_only_field"}]}],
                    },
                ]
            },
        ],
    }


def _capabilities():
    return [
        CapabilitySpec(
            id="automation-and-remediation",
            sub_capabilities=[
                SubCapabilitySpec(id="automation-and-remediation_salesforce-iam")
            ],
            config_field_ids={"create_user_enabled"},
            profile_ids=["oauth2.salesforce"],
        ),
        CapabilitySpec(
            id="fetch-secrets",
            sub_capabilities=[],
            config_field_ids={"fetch_secret_path"},
            profile_ids=["oauth2.salesforce"],
        ),
    ]


# ---------------------------------------------------------------------------
# _dig — generic dotted-path digger
# ---------------------------------------------------------------------------

def test_dig_nested_hit():
    src = {"credentials": {"identifier": "AKIA", "password": "secret"}}
    assert _dig(src, "credentials.identifier") == "AKIA"
    assert _dig(src, "credentials.password") == "secret"


def test_dig_single_segment():
    assert _dig({"roleArn": "arn:aws:iam::123"}, "roleArn") == "arn:aws:iam::123"


def test_dig_missing_segment_returns_none():
    assert _dig({"credentials": {"identifier": "AKIA"}}, "credentials.password") is None
    assert _dig({"a": {"b": 1}}, "a.c") is None
    assert _dig({}, "missing") is None


def test_dig_non_dict_segment_returns_none():
    # Walking past a non-dict leaf must yield None, not raise.
    assert _dig({"a": "scalar"}, "a.b") is None
    assert _dig({"a": ["list"]}, "a.b") is None


def test_dig_deep_path():
    src = {"a": {"b": {"c": "deep"}}}
    assert _dig(src, "a.b.c") == "deep"


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

def test_enables_all_capabilities_and_subs():
    payload = _build_instance_payload(
        _creation_view(),
        instance_name="My Instance",
        capabilities=_capabilities(),
        profiles=[],
        instance_values={},
        connector_id="salesforce",
    )
    values = payload["capabilities"]["values"]
    assert set(values.keys()) == {"automation-and-remediation", "fetch-secrets"}
    assert values["automation-and-remediation"] == [
        "automation-and-remediation_salesforce-iam"
    ]
    assert values["fetch-secrets"] == []
    assert payload["instance_id"] == "inst-123"
    assert payload["connector_id"] == "salesforce"
    assert payload["capabilities"]["general_configurations"]["instance_name"] == "My Instance"


def test_unknown_capability_raises():
    caps = [CapabilitySpec(id="does-not-exist")]
    with pytest.raises(RuntimeError, match="not in creation view"):
        _build_instance_payload(
            _creation_view(),
            instance_name="x",
            capabilities=caps,
            profiles=[],
            instance_values={},
            connector_id="salesforce",
        )


def test_configuration_union_and_no_defaults():
    """Config scope spans BOTH enabled capabilities; connector defaults are NOT
    seeded (only pushed instance_values / dummies land)."""
    payload = _build_instance_payload(
        _creation_view(),
        instance_name="x",
        capabilities=_capabilities(),
        profiles=[],
        instance_values={"create_user_enabled": "false", "fetch_secret_path": "/x"},
        connector_id="salesforce",
    )
    cfg = payload["configuration"]
    # Pushed values land; the connector default_value ("true") is NOT used.
    assert cfg["create_user_enabled"] == "false"
    assert cfg["fetch_secret_path"] == "/x"
    # A field from a non-enabled capability must NOT appear.
    assert "identity_only_field" not in cfg


def test_unknown_config_key_is_skipped():
    """An instance_values key that is NOT a manifest-declared connector config
    field is not pushed into the configuration block (handled by another block
    or simply noise)."""
    payload = _build_instance_payload(
        _creation_view(),
        instance_name="x",
        capabilities=_capabilities(),
        profiles=[],
        instance_values={"create_user_enabled": "v", "not_a_connector_field": "z"},
        connector_id="salesforce",
    )
    assert "create_user_enabled" in payload["configuration"]
    assert "not_a_connector_field" not in payload["configuration"]


def test_orphan_config_field_gets_dummy_for_extra_detection():
    """CONTRACT: every manifest-declared connector config field is SET in the
    payload. A field WITH a matching integration param gets the shared value; a
    field WITHOUT one (an orphan / undeclared-rename, e.g. cisco-security's
    ``incidentType``) gets a DUMMY so it surfaces at runtime on the connector side
    only -> the diff reports EXTRA_IN_CONNECTOR instead of hiding it."""
    caps = [
        CapabilitySpec(
            id="fetch-secrets",  # present in _creation_view() steps[0]
            sub_capabilities=[],
            config_field_ids={"fetch_secret_path", "orphan_field"},
            profile_ids=[],
        ),
    ]
    payload = _build_instance_payload(
        _creation_view(),
        instance_name="x",
        capabilities=caps,
        profiles=[],
        instance_values={"fetch_secret_path": "/x"},  # no value for orphan_field
        connector_id="salesforce",
    )
    cfg = payload["configuration"]
    # Matched field -> shared value.
    assert cfg["fetch_secret_path"] == "/x"
    # Orphan field -> set to a recognizable dummy, NOT omitted.
    assert cfg["orphan_field"] == "dummy_config_orphan_field"


def test_configuration_is_manifest_authoritative_not_creation_view():
    """Regression: a config field declared in the connector MANIFEST
    (CapabilitySpec.config_field_ids) must land in the configuration block EVEN
    WHEN it is ABSENT from the live creation view's steps[2] sections.

    This is the cisco-security/AMPv2 bug: capability-gated / not-yet-deployed
    fields were missing from the live creation view, so the old creation-view-
    driven accepted_field_ids collapsed and configuration came out ``{}``.
    """
    # A creation view whose config step (steps[2]) declares NO fields at all —
    # simulating a tenant where the connector's config schema isn't deployed.
    # (The capability id must still exist in steps[0]; this test isolates the
    # CONFIG-FIELD sourcing, not the capability-enablement guard.)
    cv = _creation_view()
    cv["steps"][2] = {"sections": []}

    caps = [
        CapabilitySpec(
            id="fetch-secrets",  # present in _creation_view() steps[0]
            sub_capabilities=[],
            config_field_ids={"first_fetch", "max_fetch", "event_types"},
            profile_ids=[],
        ),
    ]
    payload = _build_instance_payload(
        cv,
        instance_name="x",
        capabilities=caps,
        profiles=[],
        instance_values={
            "first_fetch": "3 days",
            "max_fetch": "50",
            "event_types": "abc",
            "not_declared": "z",
        },
        connector_id="cisco-security",
    )
    cfg = payload["configuration"]
    # All manifest-declared fields land despite the empty creation view.
    assert cfg["first_fetch"] == "3 days"
    assert cfg["max_fetch"] == "50"
    assert cfg["event_types"] == "abc"
    # A value not declared by the manifest is still skipped.
    assert "not_declared" not in cfg


def test_interpolated_profile_uses_instance_values():
    # Interpolated: a non-empty interpolation_mapping (role → xsoar path) +
    # metadata.auth.parameter roles on the fields. The builder derives the
    # connector-field → xsoar-top-level-param map from the ProfileSpec itself.
    profile = ProfileSpec(
        id="oauth2.salesforce",
        type="oauth2_client_credentials",
        interpolation_mapping={
            "client_key_role": "client_key",
            "client_secret_role": "client_secret",
        },
        auth_field_to_role={
            "sfdc_client_key": "client_key_role",
            "sfdc_client_secret": "client_secret_role",
        },
        field_ids=["sfdc_client_key", "sfdc_client_secret"],
    )
    payload = _build_instance_payload(
        _creation_view(),
        instance_name="x",
        capabilities=_capabilities(),
        profiles=[profile],
        instance_values={"client_key": "REAL_KEY", "client_secret": "REAL_SECRET"},
        connector_id="salesforce",
    )
    profs = payload["connection"]["profiles"]
    assert len(profs) == 1
    p = profs[0]
    assert p["profile_id"] == "oauth2.salesforce"
    # Interpolated → connector auth fields equal the integration instance values
    # (looked up by each field's mapped xsoar top-level param).
    assert p["values"]["sfdc_client_key"] == "REAL_KEY"
    assert p["values"]["sfdc_client_secret"] == "REAL_SECRET"
    # applied_for spans both enabled capabilities' methods, de-duped.
    assert set(p["applied_for"]) == {"m-auto", "m-fetch"}


def test_interpolated_profile_uncovered_field_is_dummy():
    """An interpolated profile field whose role is NOT in the interpolation_mapping
    falls back to a dummy value."""
    profile = ProfileSpec(
        id="oauth2.salesforce",
        type="oauth2_client_credentials",
        interpolation_mapping={"client_key_role": "client_key"},  # only ONE field mapped
        auth_field_to_role={
            "sfdc_client_key": "client_key_role",
            "sfdc_client_secret": "client_secret_role",  # role NOT in the mapping
        },
        field_ids=["sfdc_client_key", "sfdc_client_secret"],
    )
    payload = _build_instance_payload(
        _creation_view(),
        instance_name="x",
        capabilities=_capabilities(),
        profiles=[profile],
        instance_values={"client_key": "REAL_KEY", "client_secret": "REAL_SECRET"},
        connector_id="salesforce",
    )
    p = payload["connection"]["profiles"][0]
    assert p["values"]["sfdc_client_key"] == "REAL_KEY"
    # Uncovered field → dummy, never the real value.
    assert p["values"]["sfdc_client_secret"] == "dummy_sfdc_client_secret"


def test_non_interpolated_profile_is_dummy_filled():
    # No interpolation_mapping ⇒ NOT interpolated ⇒ all fields dummy-filled.
    profile = ProfileSpec(
        id="oauth2.salesforce",
        type="oauth2_client_credentials",
        interpolation_mapping={},
        auth_field_to_role={"sfdc_client_key": "client_key_role"},
        field_ids=["sfdc_client_key", "sfdc_client_secret"],
    )
    payload = _build_instance_payload(
        _creation_view(),
        instance_name="x",
        capabilities=_capabilities(),
        profiles=[profile],
        instance_values={"client_key": "REAL_KEY"},
        connector_id="salesforce",
    )
    p = payload["connection"]["profiles"][0]
    # Non-interpolated → dummy, never the real value.
    assert p["values"]["sfdc_client_key"] == "dummy_sfdc_client_key"
    assert p["values"]["sfdc_client_secret"] == "dummy_sfdc_client_secret"
    assert p["values"]["sfdc_client_key"] != "REAL_KEY"


def test_profile_without_supporting_method_is_skipped():
    profile = ProfileSpec(
        id="profile-with-no-method",
        type="x",
        interpolation_mapping={},
        field_ids=["f1"],
    )
    payload = _build_instance_payload(
        _creation_view(),
        instance_name="x",
        capabilities=_capabilities(),
        profiles=[profile],
        instance_values={},
        connector_id="salesforce",
    )
    assert payload["connection"]["profiles"] == []


def test_connection_general_pushed():
    payload = _build_instance_payload(
        _creation_view(),
        instance_name="x",
        capabilities=_capabilities(),
        profiles=[],
        instance_values={"domain": "test.salesforce.com"},
        connector_id="salesforce",
    )
    assert payload["connection"]["general_configurations"]["domain"] == "test.salesforce.com"


# ---------------------------------------------------------------------------
# Engine fields are INCLUDED as the real UI sends them (no_engine / null / null)
# ---------------------------------------------------------------------------
#
# For the AWS connector's passthrough.aws_acm profile the field_ids include
# engine_mode / engine / engine_group. The non-interpolated fallback used to set
# values["engine"] = "dummy_engine", and UCP rejected instance creation with
# "engine with id [dummy_engine] does not exist (909)". The real UI payload does
# NOT omit them either — it sends engine_mode:"no_engine", engine:null,
# engine_group:null, keeping the instance on "No Engine". So they must be present
# with those canonical values (never a dummy).

_ENGINE_FIELDS = ("engine", "engine_group", "engine_mode", "engineGroup")


def _creation_view_with_profile(*profile_ids: str):
    """A creation view whose connection methods bind ALL ``profile_ids`` so each
    profile actually lands in the payload (the default view only binds
    ``oauth2.salesforce``). Accepts one or more profile ids — pass several to
    exercise multi-profile genericness."""
    view = _creation_view()
    options = [{"profile_id": pid} for pid in profile_ids]
    for method in view["steps"][1]["methods"]:
        method["options"] = list(options)
    return view


def test_non_interpolated_profile_sets_canonical_engine_values():
    """The non-interpolated branch must emit engine_mode/engine/engine_group with
    the canonical no-engine values (never engine=dummy_engine)."""
    profile = ProfileSpec(
        id="passthrough.aws_acm",
        type="passthrough",
        interpolation_mapping={},  # non-interpolated → dummy-fill branch
        auth_field_to_role={},
        field_ids=[
            "engine_mode",
            "engine",
            "engine_group",
            "aws_access_key_id",  # a normal auth field
        ],
    )
    payload = _build_instance_payload(
        _creation_view_with_profile("passthrough.aws_acm"),
        instance_name="x",
        capabilities=_capabilities(),
        profiles=[profile],
        instance_values={},
        connector_id="aws",
    )
    p = payload["connection"]["profiles"][0]
    values = p["values"]
    # Engine fields present with canonical values; never the literal dummy_engine.
    assert values["engine_mode"] == "no_engine"
    assert values["engine"] is None
    assert values["engine_group"] is None
    assert values.get("engine") != "dummy_engine"
    # The normal auth field IS still dummy-filled.
    assert values["aws_access_key_id"] == "dummy_aws_access_key_id"


def test_interpolated_profile_sets_canonical_engine_values():
    """An interpolated profile also sets the canonical no-engine engine values."""
    profile = ProfileSpec(
        id="passthrough.aws_acm",
        type="passthrough",
        interpolation_mapping={"access_key_role": "access_key"},
        auth_field_to_role={"aws_access_key_id": "access_key_role"},
        field_ids=[
            "engine_mode",
            "engine",
            "engine_group",
            "aws_access_key_id",  # a normal, interpolated auth field
        ],
    )
    payload = _build_instance_payload(
        _creation_view_with_profile("passthrough.aws_acm"),
        instance_name="x",
        capabilities=_capabilities(),
        profiles=[profile],
        instance_values={"access_key": "REAL_ACCESS_KEY"},
        connector_id="aws",
    )
    p = payload["connection"]["profiles"][0]
    values = p["values"]
    assert values["engine_mode"] == "no_engine"
    assert values["engine"] is None
    assert values["engine_group"] is None
    # The normal interpolated auth field still resolves to the real value.
    assert values["aws_access_key_id"] == "REAL_ACCESS_KEY"


def test_engine_field_not_pushed_to_connection_general():
    """An engine field declared as a connection-general field must not be pushed."""
    view = _creation_view()
    # Declare an engine field among the connection-general fields.
    view["steps"][1]["sections"] = [
        {"data": [{"fields": [{"id": "domain"}, {"id": "engine"}]}]},
    ]
    payload = _build_instance_payload(
        view,
        instance_name="x",
        capabilities=_capabilities(),
        profiles=[],
        instance_values={"domain": "test.salesforce.com", "engine": "dummy_engine"},
        connector_id="salesforce",
    )
    general = payload["connection"]["general_configurations"]
    assert general["domain"] == "test.salesforce.com"
    assert "engine" not in general


# ---------------------------------------------------------------------------
# Profile-NESTED non-auth CONFIG fields must receive the SHARED instance_values
# ---------------------------------------------------------------------------
#
# For the AWS connector, connection-level params (defaultRegion, retries, timeout,
# sts_regional_endpoint, proxy, insecure) are declared as fields INSIDE the auth
# profile's `configurations:` block (NOT a top-level general_configurations). They
# are NOT auth fields (absent from auth_field_to_role). The integration side gets
# the real shared value; the connector side must get the SAME shared value — not a
# "dummy_<fid>" and not a connector default — otherwise every one VALUE_MISMATCHes.


def test_non_auth_profile_config_field_gets_shared_value():
    """A NON-auth profile field (not in auth_field_to_role) is set to the shared
    instance_values value (matched by field id == xsoar param), NOT a dummy."""
    profile = ProfileSpec(
        id="passthrough.aws_acm",
        type="passthrough",
        interpolation_mapping={"access_key_role": "access_key"},
        auth_field_to_role={"aws_access_key_id": "access_key_role"},
        field_ids=[
            "aws_access_key_id",  # auth field → interpolated
            "defaultRegion",      # non-auth config field
            "retries",            # non-auth config field
            "insecure",           # non-auth boolean config field
            "proxy",              # non-auth boolean config field
        ],
    )
    payload = _build_instance_payload(
        _creation_view_with_profile("passthrough.aws_acm"),
        instance_name="x",
        capabilities=_capabilities(),
        profiles=[profile],
        instance_values={
            "access_key": "REAL_ACCESS_KEY",
            "defaultRegion": "us-east-1",
            "retries": 5,
            "insecure": True,
            "proxy": True,
        },
        connector_id="aws",
    )
    values = payload["connection"]["profiles"][0]["values"]
    # Auth field still interpolated to the shared value via its xsoar param.
    assert values["aws_access_key_id"] == "REAL_ACCESS_KEY"
    # Non-auth config fields receive the SAME shared values (NOT dummies/defaults).
    assert values["defaultRegion"] == "us-east-1"
    assert values["retries"] == 5
    assert values["insecure"] is True
    assert values["proxy"] is True


def test_non_auth_profile_config_field_absent_falls_back_to_dummy():
    """A non-auth profile config field NOT present in instance_values still gets a
    dummy fallback (never silently dropped)."""
    profile = ProfileSpec(
        id="passthrough.aws_acm",
        type="passthrough",
        interpolation_mapping={},  # non-interpolated profile
        auth_field_to_role={},
        field_ids=["someField"],  # non-auth, absent from instance_values
    )
    payload = _build_instance_payload(
        _creation_view_with_profile("passthrough.aws_acm"),
        instance_name="x",
        capabilities=_capabilities(),
        profiles=[profile],
        instance_values={"defaultRegion": "us-east-1"},  # does NOT contain someField
        connector_id="aws",
    )
    values = payload["connection"]["profiles"][0]["values"]
    assert values["someField"] == "dummy_someField"


def test_non_interpolated_profile_auth_field_still_dummy_with_shared_values_present():
    """Regression: a NON-interpolated profile's AUTH field must still be a dummy
    even when an identically-named key exists in instance_values (auth fields are
    keyed by their xsoar param mapping, which is empty for non-interpolated)."""
    profile = ProfileSpec(
        id="passthrough.aws_acm",
        type="passthrough",
        interpolation_mapping={},  # non-interpolated → field_to_xsoar is {}
        auth_field_to_role={"aws_access_key_id": "access_key_role"},
        field_ids=["aws_access_key_id"],
    )
    payload = _build_instance_payload(
        _creation_view_with_profile("passthrough.aws_acm"),
        instance_name="x",
        capabilities=_capabilities(),
        profiles=[profile],
        # Even though a key literally named the auth field id exists, an auth field
        # on a non-interpolated profile must NOT pick it up — it stays a dummy.
        instance_values={"aws_access_key_id": "LEAKED"},
        connector_id="aws",
    )
    values = payload["connection"]["profiles"][0]["values"]
    assert values["aws_access_key_id"] == "dummy_aws_access_key_id"


# ---------------------------------------------------------------------------
# Auth-field LEAF resolution (regression: nested-shape credentials bug)
# ---------------------------------------------------------------------------
#
# An interpolated auth field maps to a FULL dotted xsoar destination path
# (e.g. credentials_username -> credentials.identifier). The connector-side value
# must be the LEAF scalar dug out of the shared instance_values at that exact
# sub-path — NOT the whole top-level object. Previously both credentials_username
# and credentials_password collapsed to instance_values["credentials"] (the WHOLE
# type-9 dict), which the UI never shows.


def _interpolated_credentials_profile():
    """An interpolated profile whose two auth fields map to credentials.identifier
    and credentials.password, plus a flat roleArn -> roleArn auth field."""
    return ProfileSpec(
        id="passthrough.aws_acm",
        type="passthrough",
        interpolation_mapping={
            "username_role": "credentials.identifier",
            "password_role": "credentials.password",
            "role_arn_role": "roleArn",
        },
        auth_field_to_role={
            "credentials_username": "username_role",
            "credentials_password": "password_role",
            "roleArn": "role_arn_role",
        },
        field_ids=["credentials_username", "credentials_password", "roleArn"],
    )


def test_auth_field_resolves_flat_leaf_not_whole_object():
    """Interpolated auth fields get the FLAT leaf scalar dug from the nested
    instance_values, NOT the whole credentials dict (the nested-shape bug)."""
    profile = _interpolated_credentials_profile()
    payload = _build_instance_payload(
        _creation_view_with_profile("passthrough.aws_acm"),
        instance_name="x",
        capabilities=_capabilities(),
        profiles=[profile],
        instance_values={
            "credentials": {"identifier": "AKIAEXAMPLE", "password": "secretvalue"},
            "roleArn": "arn:aws:iam::123:role/r",
        },
        connector_id="aws",
    )
    values = payload["connection"]["profiles"][0]["values"]
    # FLAT scalars dug out at the exact leaf — NOT the whole dict.
    assert values["credentials_username"] == "AKIAEXAMPLE"
    assert values["credentials_password"] == "secretvalue"
    assert values["roleArn"] == "arn:aws:iam::123:role/r"
    # Explicitly prove no whole-object leakage.
    assert values["credentials_username"] != {
        "identifier": "AKIAEXAMPLE",
        "password": "secretvalue",
    }


def test_auth_field_missing_leaf_falls_back_to_dummy():
    """If the dotted path can't be dug (missing/None leaf), the auth field falls
    back to a non-empty dummy (never None, never the whole object)."""
    profile = _interpolated_credentials_profile()
    payload = _build_instance_payload(
        _creation_view_with_profile("passthrough.aws_acm"),
        instance_name="x",
        capabilities=_capabilities(),
        profiles=[profile],
        # `credentials` present but missing the `password` sub-key; roleArn absent.
        instance_values={"credentials": {"identifier": "AKIAEXAMPLE"}},
        connector_id="aws",
    )
    values = payload["connection"]["profiles"][0]["values"]
    assert values["credentials_username"] == "AKIAEXAMPLE"
    assert values["credentials_password"] == "dummy_credentials_password"
    assert values["roleArn"] == "dummy_roleArn"


# ---------------------------------------------------------------------------
# Engine fields are INCLUDED with canonical "no engine" values (CHANGE C)
# ---------------------------------------------------------------------------
#
# The real UI payload INCLUDES engine fields: engine_mode:"no_engine",
# engine:null, engine_group:null. They must be present (not skipped, not dummied).


def test_engine_fields_present_with_canonical_no_engine_values():
    profile = ProfileSpec(
        id="passthrough.aws_acm",
        type="passthrough",
        interpolation_mapping={"access_key_role": "access_key"},
        auth_field_to_role={"aws_access_key_id": "access_key_role"},
        field_ids=["engine_mode", "engine", "engine_group", "aws_access_key_id"],
    )
    payload = _build_instance_payload(
        _creation_view_with_profile("passthrough.aws_acm"),
        instance_name="x",
        capabilities=_capabilities(),
        profiles=[profile],
        instance_values={"access_key": "REAL_ACCESS_KEY"},
        connector_id="aws",
    )
    values = payload["connection"]["profiles"][0]["values"]
    # Engine fields PRESENT with canonical no-engine values.
    assert values["engine_mode"] == "no_engine"
    assert values["engine"] is None
    assert values["engine_group"] is None
    # The normal auth field still resolves to the real value.
    assert values["aws_access_key_id"] == "REAL_ACCESS_KEY"


def test_engine_field_values_map_constant():
    assert _ENGINE_FIELD_VALUES == {
        "engine_mode": "no_engine",
        "engine": None,
        "engine_group": None,
    }


# ---------------------------------------------------------------------------
# connection.origin must be GROUPED (CHANGE B)
# ---------------------------------------------------------------------------


def test_connection_origin_is_grouped():
    payload = _build_instance_payload(
        _creation_view(),
        instance_name="x",
        capabilities=_capabilities(),
        profiles=[],
        instance_values={},
        connector_id="salesforce",
    )
    assert payload["connection"]["origin"] == "GROUPED"


# ---------------------------------------------------------------------------
# MULTI-PROFILE genericness — each profile digs its OWN leaves (no hardcoding)
# ---------------------------------------------------------------------------


def test_multi_profile_each_digs_its_own_leaves():
    """Two interpolated profiles, each with its OWN fields + mapping, both bound by
    the connection methods. Each profile payload must get its own correctly-dug
    leaf values — proving the resolution is generic, not connector-specific."""
    profile_a = ProfileSpec(
        id="passthrough.aws_acm",
        type="passthrough",
        interpolation_mapping={
            "username_role": "credentials.identifier",
            "password_role": "credentials.password",
        },
        auth_field_to_role={
            "credentials_username": "username_role",
            "credentials_password": "password_role",
        },
        field_ids=["credentials_username", "credentials_password"],
    )
    profile_b = ProfileSpec(
        id="oauth2.other",
        type="oauth2_client_credentials",
        interpolation_mapping={
            "tok_role": "auth.token",
            "host_role": "host",
        },
        auth_field_to_role={
            "oauth_token": "tok_role",
            "oauth_host": "host_role",
        },
        field_ids=["oauth_token", "oauth_host"],
    )
    payload = _build_instance_payload(
        _creation_view_with_profile("passthrough.aws_acm", "oauth2.other"),
        instance_name="x",
        capabilities=_capabilities(),
        profiles=[profile_a, profile_b],
        instance_values={
            "credentials": {"identifier": "AKIA_A", "password": "SECRET_A"},
            "auth": {"token": "TOK_B"},
            "host": "host-b.example.com",
        },
        connector_id="multi",
    )
    profs = {p["profile_id"]: p["values"] for p in payload["connection"]["profiles"]}
    assert set(profs) == {"passthrough.aws_acm", "oauth2.other"}
    # Profile A digs from credentials.*.
    assert profs["passthrough.aws_acm"]["credentials_username"] == "AKIA_A"
    assert profs["passthrough.aws_acm"]["credentials_password"] == "SECRET_A"
    # Profile B digs from its OWN paths (auth.token, host) — no cross-contamination.
    assert profs["oauth2.other"]["oauth_token"] == "TOK_B"
    assert profs["oauth2.other"]["oauth_host"] == "host-b.example.com"


# ---------------------------------------------------------------------------
# capture_ucp_params return-contract (hermetic, end-to-end stubbed)
# ---------------------------------------------------------------------------
def test_capture_ucp_params_returns_captured_and_payload_tuple(monkeypatch):
    """SUCCESS → capture_ucp_params returns (captured, payload).

    The whole heavy flow (port-forward, creation view, instance create/verify,
    mirror wait, magic-key arm, test-module, teardown) is monkeypatched so the
    test is fully hermetic. We assert the SECOND tuple element is exactly the
    payload object built by _build_instance_payload (the dict POSTed to create
    the UCP instance), surfaced for debugging in the results envelope.
    """
    import types

    import ucp_capture

    sentinel_payload = {"configuration": [], "connection": {"profiles": []}}
    captured_sentinel = {"captured": True}

    monkeypatch.setattr(ucp_capture, "get_instances_by_brand", lambda c, b: [])
    # The capture now ASSUMES a live session instead of starting a port-forward.
    monkeypatch.setattr(
        ucp_capture.session_env, "assert_session_live",
        lambda: types.SimpleNamespace(ucp_port=8080, tenant_id="tenant-1"),
    )
    monkeypatch.setattr(
        ucp_capture,
        "get_creation_view",
        lambda connector_id, tenant_id, port: {"instance_id": "view-1"},
    )
    monkeypatch.setattr(
        ucp_capture,
        "_build_instance_payload",
        lambda *a, **k: sentinel_payload,
    )
    monkeypatch.setattr(
        ucp_capture,
        "create_ucp_instance",
        lambda payload, tenant_id, port: {"id": "ucp-1", "name": "x", "status": "ok"},
    )
    monkeypatch.setattr(
        ucp_capture,
        "verify_ucp_instance_created",
        lambda **k: {"exists": True, "instance_id": "ucp-1", "status": "ok", "via": "get"},
    )
    monkeypatch.setattr(
        ucp_capture,
        "wait_for_xsoar_mirror",
        lambda *a, **k: {"id": "mirror-1"},
    )
    monkeypatch.setattr(
        ucp_capture,
        "inject_magic_key_and_persist",
        lambda client, mirror: {"id": "mirror-1", "armed": True},
    )
    monkeypatch.setattr(
        ucp_capture,
        "run_test_module_and_capture_params",
        lambda client, armed: captured_sentinel,
    )
    monkeypatch.setattr(ucp_capture, "delete_ucp_instance", lambda *a, **k: None)

    parity_inputs = types.SimpleNamespace(
        connector_id="aws-acm", capabilities=[], profiles=[]
    )

    result = ucp_capture.capture_ucp_params(
        xsoar_client=object(),
        xsoar_brand_name="AWS - ACM",
        parity_inputs=parity_inputs,
        instance_values={},
        connector_id="aws-acm",
        tenant_id="tenant-1",
    )

    assert isinstance(result, tuple)
    assert len(result) == 2
    captured, payload = result
    assert captured is captured_sentinel
    assert payload is sentinel_payload


def test_capture_ucp_params_failure_returns_none_and_payload(monkeypatch):
    """Mid-flow failure AFTER payload built (mirror never appears) → (None, payload)."""
    import types

    import ucp_capture

    sentinel_payload = {"configuration": [], "connection": {"profiles": []}}

    monkeypatch.setattr(ucp_capture, "get_instances_by_brand", lambda c, b: [])
    monkeypatch.setattr(
        ucp_capture.session_env, "assert_session_live",
        lambda: types.SimpleNamespace(ucp_port=8080, tenant_id="tenant-1"),
    )
    monkeypatch.setattr(
        ucp_capture,
        "get_creation_view",
        lambda connector_id, tenant_id, port: {"instance_id": "view-1"},
    )
    monkeypatch.setattr(
        ucp_capture, "_build_instance_payload", lambda *a, **k: sentinel_payload
    )
    monkeypatch.setattr(
        ucp_capture,
        "create_ucp_instance",
        lambda payload, tenant_id, port: {"id": "ucp-1", "name": "x", "status": "ok"},
    )
    monkeypatch.setattr(
        ucp_capture,
        "verify_ucp_instance_created",
        lambda **k: {"exists": True, "instance_id": "ucp-1", "status": "ok", "via": "get"},
    )
    # Mirror never appears → the function returns None for `captured`.
    monkeypatch.setattr(ucp_capture, "wait_for_xsoar_mirror", lambda *a, **k: None)
    monkeypatch.setattr(ucp_capture, "delete_ucp_instance", lambda *a, **k: None)

    parity_inputs = types.SimpleNamespace(
        connector_id="aws-acm", capabilities=[], profiles=[]
    )

    captured, payload = ucp_capture.capture_ucp_params(
        xsoar_client=object(),
        xsoar_brand_name="AWS - ACM",
        parity_inputs=parity_inputs,
        instance_values={},
        connector_id="aws-acm",
        tenant_id="tenant-1",
    )

    assert captured is None
    assert payload is sentinel_payload
