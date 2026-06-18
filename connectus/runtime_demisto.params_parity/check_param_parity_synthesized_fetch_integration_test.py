"""Tests for the INTEGRATION creation-payload wiring of BE-synthesized fetch fields.

Regression target (fourth follow-up on the runtime ``demisto.params()`` parity
harness):

For an ``isFetchEvents`` / log-collection variant (e.g. CiscoAMPEventCollector,
which statically declares ``script.isfetchevents: true``), the INTEGRATION side
silently OMITTED the BE-synthesized event fields even though the CONNECTOR side
correctly enabled them:

  * Bug A — ``eventFetchInterval`` came back as the YML default ``"1"`` instead of
    the shared non-default ``"111"`` (connector had int ``111``) → VALUE_MISMATCH.
  * Bug B — ``isFetchEvents`` came back ``false`` instead of ``true`` (connector
    had ``true``) → VALUE_MISMATCH.

Two root causes, both fixed here:

  1. ``xsoar_capture.create_integration_instance`` injected the BE-synthesized
     ``extra_fields`` into ``module_instance["data"]`` ONLY when the field was NOT
     already present from the SERVER config schema. But for an integration whose
     YML statically sets a fetch flag (an event collector's ``isfetchevents``),
     the SERVER auto-exposes ``isFetchEvents``/``eventFetchInterval`` in its
     config schema; the schema loop then filled them from ``filled`` (which only
     carries YML-declared params) and so fell back to the schema DEFAULT, and the
     ``already_present`` guard SKIPPED the correct synthesized value. The fix
     makes ``extra_fields`` AUTHORITATIVE: a schema-declared synthesized field is
     OVERRIDDEN with the variant value, while a schema-absent one is still
     injected. ``capture_xsoar_params`` also folds ``extra_fields`` into
     ``filled`` so the surfaced creation payload reflects the toggle + interval.
  2. ``be_config_params.default_dummy_for`` returned a generic STRING for a fetch
     TOGGLE (``isFetchEvents``), so the integration carried a truthy string while
     the connector returned the boolean ``true`` → spurious VALUE_MISMATCH. The
     fix returns the boolean ``True`` for the fetch toggle fields.

Everything stays TABLE-DRIVEN off ``_FETCH_FLAG_FIELDS`` (no events special-case):
the same wiring fires for the active flag of EVERY variant (isFetch / isFetchEvents
/ isFetchAssets / feed).

Fully hermetic — no network / tenant / docker.
"""
from __future__ import annotations

import xsoar_capture
from xsoar_capture import (
    PARITY_DUMP_PARAM_KEY,
    capture_xsoar_params,
    create_integration_instance,
)
from be_config_params import (
    apply_be_config_transform,
    connector_value_for,
    default_dummy_for,
    values_match,
)


# ---------------------------------------------------------------------------
# default_dummy_for — toggle is a real boolean, interval is the "111" string
# ---------------------------------------------------------------------------


def test_default_dummy_for_fetch_toggle_is_boolean_true():
    """Every fetch TOGGLE is synthesized as the boolean ``True`` (matches the
    connector's runtime ``true``), NOT a generic string dummy."""
    for toggle in ("isFetch", "isFetchEvents", "isFetchAssets", "feed", "isFetchCredentials"):
        assert default_dummy_for(toggle) is True, toggle


def test_default_dummy_for_interval_is_minutes_string():
    """Interval/duration fields keep the non-default minutes STRING ``"111"``."""
    for interval in (
        "incidentFetchInterval",
        "eventFetchInterval",
        "assetsFetchInterval",
        "feedFetchInterval",
        "feedExpirationInterval",
    ):
        assert default_dummy_for(interval) == "111", interval


def test_default_dummy_for_other_field_is_generic_string():
    """A non-toggle, non-interval synthesized field keeps the generic string."""
    assert default_dummy_for("incidentType") == "dummy_config_incidentType"


# ---------------------------------------------------------------------------
# apply_be_config_transform — isFetchEvents-only variant (integration side)
# ---------------------------------------------------------------------------


def _flags(active: str) -> dict[str, bool]:
    names = ["isFetch", "isFetchEvents", "isFetchAssets", "feed", "isFetchCredentials"]
    return {n: (n == active) for n in names}


def test_isfetchevents_variant_integration_dummies_carry_toggle_and_interval():
    """An isFetchEvents-only variant's shared dummies carry the boolean toggle
    ``True`` AND the non-default interval string ``"111"`` (the int/string
    contract: connector coerces the same to int ``111``)."""
    out = apply_be_config_transform({}, {}, fetch_flags=_flags("isFetchEvents"))
    assert out["isFetchEvents"] is True                       # toggle: boolean
    assert out["eventFetchInterval"] == "111"                 # interval: string
    # connector side of the int/string contract.
    assert connector_value_for("eventFetchInterval", out["eventFetchInterval"]) == 111
    # off-flag toggles/intervals must NOT be set when only isFetchEvents is on.
    for fld in (
        "isFetch", "incidentFetchInterval",
        "isFetchAssets", "assetsFetchInterval",
        "feed", "feedFetchInterval", "feedExpirationInterval",
    ):
        assert fld not in out, fld


def test_isfetchevents_only_off_flag_toggles_not_set():
    """GUARD: an isFetchEvents-only variant must NOT enable isFetch / feed /
    assets toggles anywhere in the shared dummies."""
    out = apply_be_config_transform({}, {}, fetch_flags=_flags("isFetchEvents"))
    assert "isFetch" not in out
    assert "isFetchAssets" not in out
    assert "feed" not in out


# ---------------------------------------------------------------------------
# Parity: integration "111" string == connector 111 int; True == True
# ---------------------------------------------------------------------------


def test_isfetchevents_fields_are_at_parity_across_sides():
    """The isFetchEvents synthesized fields compare EQUAL across the two parity
    sides: interval ("111" string vs 111 int) and toggle (True vs True)."""
    out = apply_be_config_transform({}, {}, fetch_flags=_flags("isFetchEvents"))
    # interval: int/string equivalence is restored by values_match.
    assert values_match(
        "eventFetchInterval",
        out["eventFetchInterval"],                                  # integration "111"
        connector_value_for("eventFetchInterval", out["eventFetchInterval"]),  # connector 111
    )
    # toggle: both sides boolean True.
    assert values_match("isFetchEvents", out["isFetchEvents"], True)


# ---------------------------------------------------------------------------
# create_integration_instance — schema-declared synthesized fields are OVERRIDDEN
# (the core Bug A/B regression: an event collector's server schema declares them)
# ---------------------------------------------------------------------------


def _fake_client():
    return object()


def _server_config_with_event_fields():
    """A server config schema that ALREADY declares isFetchEvents/eventFetchInterval
    (as the backend does for an integration whose YML sets isfetchevents:true),
    each with its default value — exactly the case that masked the synthesized
    value before the fix."""
    return {
        "name": "CiscoAMPEventCollector",
        "category": "Analytics & SIEM",
        "configuration": [
            {"name": "url", "display": "Server URL", "type": 0},
            {"name": "isFetchEvents", "display": "Fetch Events", "type": 8,
             "defaultValue": False},
            {"name": "eventFetchInterval", "display": "Events Fetch Interval",
             "type": 0, "defaultValue": "1"},
        ],
    }


def _patch_put_capturing_data(monkeypatch, sink: dict):
    """Patch demisto_client.generic_request_func so the PUT body (the
    module_instance with its data list) is captured instead of sent."""
    def _fake_put(self, method, path, body, _request_timeout, response_type):
        sink["body"] = body
        return ({"id": "instance-xyz"}, 200, None)

    monkeypatch.setattr(
        xsoar_capture.demisto_client, "generic_request_func", _fake_put
    )


def _data_value(data: list, name: str):
    for entry in data:
        if entry.get("name") == name:
            return entry.get("value")
    raise AssertionError(f"{name!r} not present in module_instance.data")


def test_create_instance_overrides_schema_declared_synthesized_fields(monkeypatch):
    """Bug A + B core fix: when the server schema ALREADY declares isFetchEvents/
    eventFetchInterval, the synthesized variant values OVERRIDE the schema default
    in module_instance.data — toggle True, interval "111" — instead of being
    skipped by the old already_present guard."""
    sink: dict = {}
    _patch_put_capturing_data(monkeypatch, sink)

    # filled lacks the synthesized fields (they are NOT YML-declared); the schema
    # loop would otherwise fall back to the schema defaults.
    filled = {"url": "https://example.com", PARITY_DUMP_PARAM_KEY: "1"}
    extra_fields = {"isFetchEvents": True, "eventFetchInterval": "111"}

    module_instance, error = create_integration_instance(
        _fake_client(),
        "CiscoAMPEventCollector",
        _server_config_with_event_fields(),
        filled,
        extra_fields=extra_fields,
    )
    assert error == ""
    data = sink["body"]["data"]
    # The schema-declared fields are OVERRIDDEN with the synthesized values.
    assert _data_value(data, "isFetchEvents") is True
    assert _data_value(data, "eventFetchInterval") == "111"
    # No duplicate entries were appended for the overridden fields.
    assert sum(1 for e in data if e.get("name") == "isFetchEvents") == 1
    assert sum(1 for e in data if e.get("name") == "eventFetchInterval") == 1


def test_create_instance_injects_synthesized_fields_absent_from_schema(monkeypatch):
    """When a synthesized field is NOT in the server schema, it is still INJECTED
    into module_instance.data (the original behavior is preserved)."""
    sink: dict = {}
    _patch_put_capturing_data(monkeypatch, sink)

    server_config = {
        "name": "CiscoAMPEventCollector",
        "configuration": [{"name": "url", "display": "Server URL", "type": 0}],
    }
    filled = {"url": "https://example.com", PARITY_DUMP_PARAM_KEY: "1"}
    extra_fields = {"isFetchEvents": True, "eventFetchInterval": "111"}

    module_instance, error = create_integration_instance(
        _fake_client(), "CiscoAMPEventCollector", server_config, filled,
        extra_fields=extra_fields,
    )
    assert error == ""
    data = sink["body"]["data"]
    assert _data_value(data, "isFetchEvents") is True
    assert _data_value(data, "eventFetchInterval") == "111"


# ---------------------------------------------------------------------------
# capture_xsoar_params end-to-end (hermetic): the surfaced creation payload
# (``filled``) carries the toggle + interval for an isFetchEvents variant.
# ---------------------------------------------------------------------------


def _stub_capture(monkeypatch, *, yml_script, sink: dict):
    monkeypatch.setattr(
        xsoar_capture,
        "parse_integration_yml",
        lambda path: {
            "name": "CiscoAMPEventCollector",
            "configuration": [{"name": "url"}],
            "script": yml_script,
        },
    )
    monkeypatch.setattr(xsoar_capture, "create_client", lambda: object())
    monkeypatch.setattr(
        xsoar_capture, "get_integration_config", lambda client, name: {"some": "config"}
    )

    def _fake_create(client, name, server_config, filled, extra_fields=None):
        sink["filled"] = dict(filled)
        sink["extra_fields"] = dict(extra_fields or {})
        return {"id": "instance-123"}, None

    monkeypatch.setattr(xsoar_capture, "create_integration_instance", _fake_create)
    monkeypatch.setattr(
        xsoar_capture,
        "run_test_module_and_capture_params",
        lambda client, module_instance: {"captured": True},
    )
    monkeypatch.setattr(
        xsoar_capture, "delete_integration_instance", lambda client, instance_id: True
    )


def test_capture_isfetchevents_variant_payload_has_toggle_and_interval(monkeypatch):
    """End-to-end: an isFetchEvents variant's surfaced creation payload (filled)
    carries isFetchEvents=True AND eventFetchInterval="111" — mirroring the
    isFetch path that already works — even though the YML does not declare them in
    its ``configuration`` list."""
    sink: dict = {}
    # The shared dummies carry the variant-synthesized values (toggle True + "111").
    shared = apply_be_config_transform({}, {}, fetch_flags=_flags("isFetchEvents"))
    shared["url"] = "https://example.com"
    _stub_capture(monkeypatch, yml_script={"isfetchevents": True}, sink=sink)

    capture_xsoar_params(
        integration_yml_path="/tmp/fake.yml",
        overrides=shared,
        fetch_flags=_flags("isFetchEvents"),
    )

    filled = sink["filled"]
    extra = sink["extra_fields"]
    # Surfaced creation payload reflects both the toggle and the interval.
    assert filled["isFetchEvents"] is True
    assert filled["eventFetchInterval"] == "111"
    # extra_fields (authoritative for create_integration_instance) agree.
    assert extra["isFetchEvents"] is True
    assert extra["eventFetchInterval"] == "111"


def test_capture_isfetchevents_only_does_not_set_other_fetch_toggles(monkeypatch):
    """GUARD: an isFetchEvents-only variant must NOT inject isFetch / feed / assets
    toggles or their intervals into the integration payload."""
    sink: dict = {}
    shared = apply_be_config_transform({}, {}, fetch_flags=_flags("isFetchEvents"))
    shared["url"] = "https://example.com"
    _stub_capture(monkeypatch, yml_script={"isfetchevents": True}, sink=sink)

    capture_xsoar_params(
        integration_yml_path="/tmp/fake.yml",
        overrides=shared,
        fetch_flags=_flags("isFetchEvents"),
    )

    extra = sink["extra_fields"]
    for fld in (
        "isFetch", "incidentFetchInterval",
        "isFetchAssets", "assetsFetchInterval",
        "feed", "feedFetchInterval", "feedExpirationInterval",
    ):
        assert fld not in extra, fld
