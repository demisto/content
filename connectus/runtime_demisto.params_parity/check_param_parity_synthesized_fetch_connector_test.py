"""Tests for the CONNECTOR creation-payload wiring of BE-synthesized fetch fields.

Regression target (third follow-up on the runtime ``demisto.params()`` parity
harness):

A BE-synthesized fetch field (e.g. ``incidentFetchInterval``) was correct on the
INTEGRATION side (``"111"``) but the CONNECTOR creation payload's serialized
``configuration`` block carried the field's TYPE DEFAULT (a ``duration`` → ``0``)
instead of the shared dummy ``111``. Root cause: the connector-keyed value map
(``connector_instance_values``) was built ONLY from ``param_to_connector_field``
(discovered from integration-YML params). BE-synthesized fetch fields are NOT in
the integration YML, so they never received the shared dummy under their CONNECTOR
field id — even though the handler ``serializer.yaml`` DOES map them
(``id: xsoar-<h>_incidentFetchInterval`` → ``field_name: incidentFetchInterval``).

The fix (``check_param_parity._build_connector_instance_values``) walks the
serializer ``by_connector`` map directly so a serializer-mapped synthesized field
receives the SAME dummy the integration got, coerced to the connector-side INT via
``be_config_params.connector_value_for`` (registry-driven int/string contract).

These tests prove:
  * a serializer-renamed synthesized interval field (isFetch / event / feed) lands
    in the connector value map as the INT ``111`` under its CONNECTOR field id;
  * the resulting connector CREATION PAYLOAD ``configuration`` block carries the
    serialized ``xsoar-<h>_incidentFetchInterval`` as the INT ``111`` (not the
    ``duration`` default ``0``);
  * a synthesized field for a DISABLED fetch flag (absent from ``shared_dummies``)
    is NOT forced onto the connector side.

Fully hermetic — no network / tenant / docker.
"""
from __future__ import annotations

import types

import check_param_parity
from be_config_params import apply_be_config_transform
from resolver import CapabilitySpec
from ucp_capture import _build_instance_payload


# A CiscoSMA-shaped serializer mapping (subset). The synthesized fetch interval
# fields ARE listed here (true runtime id == the bare xsoar name), which is what
# makes the serializer-driven re-key fire for them.
_BY_CONNECTOR = {
    "xsoar-ciscosma_filter_value": "filter_value",
    "xsoar-ciscosma_incidentFetchInterval": "incidentFetchInterval",
    "xsoar-ciscosma_eventFetchInterval": "eventFetchInterval",
    "xsoar-ciscosma_feedFetchInterval": "feedFetchInterval",
}


def _parity_inputs(*, by_connector=None, param_to_connector_field=None):
    return types.SimpleNamespace(
        serializer_by_connector=dict(by_connector or _BY_CONNECTOR),
        param_to_connector_field=dict(param_to_connector_field or {}),
    )


# ---------------------------------------------------------------------------
# _build_connector_instance_values — serializer-driven synthesized fetch wiring
# ---------------------------------------------------------------------------


def test_isfetch_synthesized_interval_lands_as_int_on_connector_field():
    """``incidentFetchInterval`` (isFetch) → the serializer-renamed connector field
    id carries the INT 111 (the connector side of the int/string contract)."""
    shared = {"incidentFetchInterval": "111", "filter_value": "<override_filter_value>"}
    out = check_param_parity._build_connector_instance_values(shared, _parity_inputs())
    # Connector field id carries the value, coerced to int per the contract.
    assert out["xsoar-ciscosma_incidentFetchInterval"] == 111
    assert isinstance(out["xsoar-ciscosma_incidentFetchInterval"], int)
    # ``out`` is the CONNECTOR-side value map; the int/string contract makes the
    # bare registry key int 111 here too. The INTEGRATION side keeps the STRING
    # because it reads the SEPARATE ``shared_dummies`` dict (asserted below), not
    # this connector copy.
    assert shared["incidentFetchInterval"] == "111"
    # A normal serializer-renamed field still flows (no regression).
    assert out["xsoar-ciscosma_filter_value"] == "<override_filter_value>"


def test_event_and_feed_intervals_land_as_int_on_connector_field():
    """Generalises beyond isFetch: event/feed synthesized intervals also get the
    INT 111 on their serializer-renamed connector field ids."""
    shared = {"eventFetchInterval": "111", "feedFetchInterval": "111"}
    out = check_param_parity._build_connector_instance_values(shared, _parity_inputs())
    assert out["xsoar-ciscosma_eventFetchInterval"] == 111
    assert out["xsoar-ciscosma_feedFetchInterval"] == 111


def test_disabled_flag_synthesized_field_not_forced_on_connector():
    """Off-flag guard: when a synthesized field is ABSENT from shared_dummies (its
    fetch flag is disabled), it is NEVER injected onto the connector side."""
    shared = {"incidentFetchInterval": "111"}  # only isFetch enabled
    out = check_param_parity._build_connector_instance_values(shared, _parity_inputs())
    assert "xsoar-ciscosma_incidentFetchInterval" in out
    # event/feed flags are OFF → their synthesized fields never entered shared_dummies
    # → must not be present under any connector field id.
    assert "xsoar-ciscosma_eventFetchInterval" not in out
    assert "xsoar-ciscosma_feedFetchInterval" not in out
    assert "eventFetchInterval" not in out
    assert "feedFetchInterval" not in out


def test_non_serializer_field_keeps_identity_and_value():
    """A field NOT in the serializer keeps its written id as its true id (no rename)
    and is not coerced (not in the int/string registry)."""
    shared = {"max_fetch": "<override_max_fetch>"}
    out = check_param_parity._build_connector_instance_values(
        shared, _parity_inputs(by_connector={})
    )
    assert out["max_fetch"] == "<override_max_fetch>"


# ---------------------------------------------------------------------------
# End-to-end: the CONNECTOR CREATION PAYLOAD configuration block carries 111
# ---------------------------------------------------------------------------


def _creation_view():
    return {
        "instance_id": "inst-1",
        "connector_id": "cisco-security",
        "steps": [
            {"capabilities": [{"id": "fetch-issues"}]},
            {"methods": [], "sections": []},
            {"sections": []},
        ],
    }


def test_connector_creation_payload_serialized_interval_is_111_int():
    """The full connector creation payload's serialized configuration block carries
    ``xsoar-ciscosma_incidentFetchInterval`` as the INT 111 (not the duration
    default 0), driven end-to-end by the serializer-aware value map + the BE
    transform for the isFetch variant."""
    # The isFetch variant's BE transform injects incidentFetchInterval = "111".
    shared = apply_be_config_transform(
        {}, {"isfetch": True}, fetch_flags={"isFetch": True}
    )
    assert shared["incidentFetchInterval"] == "111"

    connector_values = check_param_parity._build_connector_instance_values(
        shared, _parity_inputs()
    )

    cap = CapabilitySpec(id="fetch-issues")
    cap.config_field_ids = {"xsoar-ciscosma_incidentFetchInterval"}
    payload = _build_instance_payload(
        _creation_view(),
        instance_name="x",
        capabilities=[cap],
        profiles=[],
        instance_values=connector_values,
        connector_id="cisco-security",
        field_specs={"xsoar-ciscosma_incidentFetchInterval": {"field_type": "duration"}},
    )
    config = payload["configuration"]
    assert config["xsoar-ciscosma_incidentFetchInterval"] == 111
    assert isinstance(config["xsoar-ciscosma_incidentFetchInterval"], int)


def test_connector_creation_payload_disabled_interval_falls_to_default_not_forced():
    """When the variant does NOT enable a fetch flag, that synthesized interval is
    absent from shared_dummies, so the connector value map never carries it and the
    payload builder uses the field's type default (orphan duration → 0) — proving
    we never force a non-enabled flag's serialized field to 111."""
    # No fetch flags on → BE transform adds no synthesized fetch fields.
    shared = apply_be_config_transform({}, {}, fetch_flags={"isFetch": False})
    assert "eventFetchInterval" not in shared

    connector_values = check_param_parity._build_connector_instance_values(
        shared, _parity_inputs()
    )
    assert "xsoar-ciscosma_eventFetchInterval" not in connector_values

    cap = CapabilitySpec(id="fetch-issues")
    cap.config_field_ids = {"xsoar-ciscosma_eventFetchInterval"}
    payload = _build_instance_payload(
        _creation_view(),
        instance_name="x",
        capabilities=[cap],
        profiles=[],
        instance_values=connector_values,
        connector_id="cisco-security",
        field_specs={"xsoar-ciscosma_eventFetchInterval": {"field_type": "duration"}},
    )
    # Orphan duration → type default 0, NOT forced to 111.
    assert payload["configuration"]["xsoar-ciscosma_eventFetchInterval"] == 0
