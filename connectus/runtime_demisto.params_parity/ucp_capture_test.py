"""Unit tests for ucp_capture._build_instance_payload (Phase 2).

These test the PURE payload-builder logic (no network/k8s): given a fake UCP
``creation_view`` and resolved ``CapabilitySpec``/``ProfileSpec``/``AuthMappingSpec``
objects, the builder must:

  * enable ALL parent capabilities + their subscribed sub-capabilities,
  * union the configuration scope over every enabled (sub-)capability,
  * push the SHARED instance_values into the configuration (never connector defaults),
  * skip config keys the connector doesn't declare (→ MISSING_IN_CONNECTOR later),
  * set interpolated-profile auth fields to the SAME instance values,
  * dummy-fill non-interpolated-profile auth fields.
"""
from __future__ import annotations

import pytest

from resolver import (
    AuthMappingSpec,
    CapabilitySpec,
    ProfileSpec,
    SubCapabilitySpec,
)
from ucp_capture import _build_instance_payload


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
# Tests
# ---------------------------------------------------------------------------

def test_enables_all_capabilities_and_subs():
    payload = _build_instance_payload(
        _creation_view(),
        instance_name="My Instance",
        capabilities=_capabilities(),
        profiles=[],
        auth_mappings=[],
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
            auth_mappings=[],
            instance_values={},
            connector_id="salesforce",
        )


def test_configuration_union_and_no_defaults():
    """Config scope spans BOTH enabled capabilities; connector defaults are NOT
    seeded (only pushed instance_values land)."""
    payload = _build_instance_payload(
        _creation_view(),
        instance_name="x",
        capabilities=_capabilities(),
        profiles=[],
        auth_mappings=[],
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
    payload = _build_instance_payload(
        _creation_view(),
        instance_name="x",
        capabilities=_capabilities(),
        profiles=[],
        auth_mappings=[],
        instance_values={"create_user_enabled": "v", "not_a_connector_field": "z"},
        connector_id="salesforce",
    )
    assert "create_user_enabled" in payload["configuration"]
    assert "not_a_connector_field" not in payload["configuration"]


def test_interpolated_profile_uses_instance_values():
    profile = ProfileSpec(
        id="oauth2.salesforce",
        type="oauth2_client_credentials",
        interpolated=True,
        auth_field_to_role={"sfdc_client_key": "client_key"},
        field_ids=["sfdc_client_key", "sfdc_client_secret"],
    )
    auth = AuthMappingSpec(
        name="credentials",
        type="APIKey",
        xsoar_to_connector_field={
            "client_key": "sfdc_client_key",
            "client_secret": "sfdc_client_secret",
        },
    )
    payload = _build_instance_payload(
        _creation_view(),
        instance_name="x",
        capabilities=_capabilities(),
        profiles=[profile],
        auth_mappings=[auth],
        instance_values={"client_key": "REAL_KEY", "client_secret": "REAL_SECRET"},
        connector_id="salesforce",
    )
    profs = payload["connection"]["profiles"]
    assert len(profs) == 1
    p = profs[0]
    assert p["profile_id"] == "oauth2.salesforce"
    # Interpolated → connector auth fields equal the integration instance values.
    assert p["values"]["sfdc_client_key"] == "REAL_KEY"
    assert p["values"]["sfdc_client_secret"] == "REAL_SECRET"
    # applied_for spans both enabled capabilities' methods, de-duped.
    assert set(p["applied_for"]) == {"m-auto", "m-fetch"}


def test_non_interpolated_profile_is_dummy_filled():
    profile = ProfileSpec(
        id="oauth2.salesforce",
        type="oauth2_client_credentials",
        interpolated=False,
        auth_field_to_role={"sfdc_client_key": "client_key"},
        field_ids=["sfdc_client_key", "sfdc_client_secret"],
    )
    payload = _build_instance_payload(
        _creation_view(),
        instance_name="x",
        capabilities=_capabilities(),
        profiles=[profile],
        auth_mappings=[],
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
        interpolated=False,
        field_ids=["f1"],
    )
    payload = _build_instance_payload(
        _creation_view(),
        instance_name="x",
        capabilities=_capabilities(),
        profiles=[profile],
        auth_mappings=[],
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
        auth_mappings=[],
        instance_values={"domain": "test.salesforce.com"},
        connector_id="salesforce",
    )
    assert payload["connection"]["general_configurations"]["domain"] == "test.salesforce.com"
