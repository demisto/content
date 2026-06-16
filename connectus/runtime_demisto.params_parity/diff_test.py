"""Unit tests for diff.py — focused on the human-readable ignore-reason
rendering surfaced in OK_IGNORED per_param entries.

These tests are hermetic (no network / docker / tenant). They pin:
  * ``_describe_ignore_reason`` maps each known reason code to a clear sentence
    and passes unknown codes through unchanged.
  * ``diff_params`` composes the OK_IGNORED ``reason`` string with the new
    "Ignored — …" wording, threading the SPECIFIC per-side drop reason.
"""
from __future__ import annotations

import diff
from normalizers import normalize_for_diff


def test_describe_ignore_reason_known_codes():
    hidden_msg = diff._describe_ignore_reason("hidden")
    assert "hidden in the integration YML" in hidden_msg
    assert "not migrated to the connector" in hidden_msg
    assert "type-9 credentials param" in diff._describe_ignore_reason(
        "credentials_type9_interpolated"
    )
    assert "hard ignore-list" in diff._describe_ignore_reason("hard_ignore_list")
    assert "framework/mirroring/probe field" in diff._describe_ignore_reason(
        "name_ignored"
    )


def test_describe_ignore_reason_legacy_fallbacks():
    assert "hard ignore-list" in diff._describe_ignore_reason("hard_ignore")
    assert "non-interpolated profile" in diff._describe_ignore_reason(
        "profile_not_interpolated"
    )


def test_describe_ignore_reason_unknown_passthrough():
    assert diff._describe_ignore_reason("totally_unknown_code") == "totally_unknown_code"


def _ok_ignored(result: dict, name: str) -> dict:
    for p in result["per_param"]:
        if p["name"] == name and p["state"] == diff.STATE_OK_IGNORED:
            return p
    raise AssertionError(f"No OK_IGNORED per_param entry for {name!r}")


def test_ok_ignored_reason_both_sides_agree():
    """Both sides dropped with the same reason → single 'Ignored — <sentence>'."""
    integration_dropped = [{"name": "foo", "reason": "hidden", "side": "integration"}]
    connector_dropped = [{"name": "foo", "reason": "hidden", "side": "connector"}]
    result = diff.diff_params(
        {}, {},
        integration_dropped=integration_dropped,
        connector_dropped=connector_dropped,
    )
    entry = _ok_ignored(result, "foo")
    assert entry["reason"] == "Ignored — {}".format(
        diff._describe_ignore_reason("hidden")
    )
    assert entry["verdict"] == "ok"


def test_ok_ignored_reason_sides_differ():
    integration_dropped = [{"name": "foo", "reason": "hidden", "side": "integration"}]
    connector_dropped = [
        {"name": "foo", "reason": "name_ignored", "side": "connector"}
    ]
    result = diff.diff_params(
        {}, {},
        integration_dropped=integration_dropped,
        connector_dropped=connector_dropped,
    )
    entry = _ok_ignored(result, "foo")
    assert entry["reason"] == "Ignored — integration: {}; connector: {}".format(
        diff._describe_ignore_reason("hidden"),
        diff._describe_ignore_reason("name_ignored"),
    )


def test_ok_ignored_reason_integration_only():
    integration_dropped = [
        {"name": "foo", "reason": "hard_ignore_list", "side": "integration"}
    ]
    result = diff.diff_params(
        {}, {},
        integration_dropped=integration_dropped,
        connector_dropped=[],
    )
    entry = _ok_ignored(result, "foo")
    assert diff._describe_ignore_reason("hard_ignore_list") in entry["reason"]
    assert entry["reason"].startswith("Ignored — ")
    assert "integration side" in entry["reason"]


def test_ok_ignored_reason_connector_only():
    connector_dropped = [
        {"name": "foo", "reason": "name_ignored", "side": "connector"}
    ]
    result = diff.diff_params(
        {}, {},
        integration_dropped=[],
        connector_dropped=connector_dropped,
    )
    entry = _ok_ignored(result, "foo")
    assert diff._describe_ignore_reason("name_ignored") in entry["reason"]
    assert entry["reason"].startswith("Ignored — ")
    assert "connector side" in entry["reason"]


def _ok_entry(result: dict, name: str) -> dict:
    for p in result["per_param"]:
        if p["name"] == name and p["state"] == diff.STATE_OK:
            return p
    raise AssertionError(f"No OK per_param entry for {name!r}")


def test_credentials_ok_entry_annotated_with_ignored_subkeys():
    """When credentials is compared on identifier/password only, the OK entry is
    annotated so the envelope shows the rest of the credentials object was ignored."""
    integration_norm = {"credentials": {"identifier": "u", "password": "p"}}
    connector_norm = {"credentials": {"identifier": "u", "password": "p"}}
    integration_raw = {
        "credentials": {
            "identifier": "u", "password": "p",
            "credential": "", "passwordChanged": False,
            "credentials": {"id": "", "user": "", "password": ""},
        }
    }
    connector_raw = {"credentials": {"identifier": "u", "password": "p"}}
    result = diff.diff_params(
        integration_norm, connector_norm,
        yml_param_names={"credentials"},
        integration_raw=integration_raw, connector_raw=connector_raw,
    )
    entry = _ok_entry(result, "credentials")
    assert entry["state"] == diff.STATE_OK
    assert entry["verdict"] == "ok"
    # partial-ignore annotation present
    assert entry["partially_ignored"] is True
    assert entry["compared_keys"] == ["identifier", "password"]
    # the sub-keys dropped from the integration side, sorted, excluding identifier/password
    assert entry["ignored_keys"] == ["credential", "credentials", "passwordChanged"]
    assert isinstance(entry.get("partial_ignore_note"), str) and entry["partial_ignore_note"]


def test_credentials_ok_entry_no_annotation_when_nothing_extra():
    """If both sides only ever had identifier/password, there's nothing ignored —
    no partial-ignore annotation is added."""
    integration_norm = {"credentials": {"identifier": "u", "password": "p"}}
    connector_norm = {"credentials": {"identifier": "u", "password": "p"}}
    raw = {"credentials": {"identifier": "u", "password": "p"}}
    result = diff.diff_params(
        integration_norm, connector_norm,
        yml_param_names={"credentials"},
        integration_raw=raw, connector_raw=dict(raw),
    )
    entry = _ok_entry(result, "credentials")
    assert "partially_ignored" not in entry
    assert "ignored_keys" not in entry


def test_non_credentials_ok_entry_not_annotated():
    """The partial-ignore annotation is credentials-specific; other OK params are
    untouched even if their raw value is a dict with extra keys."""
    result = diff.diff_params(
        {"foo": {"a": 1}}, {"foo": {"a": 1}},
        yml_param_names={"foo"},
        integration_raw={"foo": {"a": 1, "b": 2}},
        connector_raw={"foo": {"a": 1}},
    )
    entry = _ok_entry(result, "foo")
    assert "partially_ignored" not in entry


def test_credentials_combined_ok_ignored_entry_emitted():
    """A dedicated COMBINED OK_IGNORED entry summarizes the ignored credentials sub-keys."""
    integration_norm = {"credentials": {"identifier": "u", "password": "p"}}
    connector_norm = {"credentials": {"identifier": "u", "password": "p"}}
    integration_raw = {
        "credentials": {
            "identifier": "u", "password": "p",
            "credential": "", "passwordChanged": False,
            "credentials": {"id": ""},
        }
    }
    connector_raw = {"credentials": {"identifier": "u", "password": "p"}}
    result = diff.diff_params(
        integration_norm, connector_norm,
        yml_param_names={"credentials"},
        integration_raw=integration_raw, connector_raw=connector_raw,
    )
    # The annotated OK entry still exists and is unchanged in spirit.
    ok = _ok_entry(result, "credentials")
    assert ok["partially_ignored"] is True
    # Dedicated combined OK_IGNORED entry exists.
    combined = _ok_ignored(result, "credentials (ignored sub-keys)")
    assert combined["state"] == diff.STATE_OK_IGNORED
    assert combined["verdict"] == "ok"
    assert combined["ignored_keys"] == ["credential", "credentials", "passwordChanged"]
    assert combined["reason"].startswith("Ignored — ")
    assert "identifier/password only" in combined["reason"]


def test_credentials_combined_ok_ignored_counts_in_summary():
    """The combined entry contributes to n_ok_ignored and n_total."""
    integration_norm = {"credentials": {"identifier": "u", "password": "p"}}
    connector_norm = {"credentials": {"identifier": "u", "password": "p"}}
    integration_raw = {"credentials": {"identifier": "u", "password": "p", "credential": ""}}
    connector_raw = {"credentials": {"identifier": "u", "password": "p"}}
    result = diff.diff_params(
        integration_norm, connector_norm,
        yml_param_names={"credentials"},
        integration_raw=integration_raw, connector_raw=connector_raw,
    )
    # credentials OK (1) + combined OK_IGNORED (1)
    assert result["summary"]["n_ok"] == 1
    assert result["summary"]["n_ok_ignored"] == 1
    # n_total = union_keys (1: credentials) + n_ok_ignored (1) = 2
    assert result["summary"]["n_total"] == 2
    assert result["summary"]["n_fail"] == 0


def test_no_combined_ok_ignored_when_nothing_ignored():
    """No combined entry when credentials only had identifier/password."""
    norm = {"credentials": {"identifier": "u", "password": "p"}}
    raw = {"credentials": {"identifier": "u", "password": "p"}}
    result = diff.diff_params(
        norm, dict(norm),
        yml_param_names={"credentials"},
        integration_raw=raw, connector_raw=dict(raw),
    )
    names = [p["name"] for p in result["per_param"]]
    assert "credentials (ignored sub-keys)" not in names
    assert result["summary"]["n_ok_ignored"] == 0


def test_prefixed_credentials_ok_entry_annotated():
    """The partial-ignore annotation is emitted for a PREFIXED type-9 field
    (e.g. Akamai's credentials_access_token), not just the literal "credentials".
    The OK entry is annotated and the dropped skeleton sub-keys are surfaced."""
    integration_norm = {"credentials_access_token": {"password": "s3cret"}}
    connector_norm = {"credentials_access_token": {"password": "s3cret"}}
    integration_raw = {
        "credentials_access_token": {
            "password": "s3cret",
            "credential": "",
            "passwordChanged": False,
            "credentials": {"id": "", "user": "", "password": ""},
        }
    }
    connector_raw = {"credentials_access_token": {"password": "s3cret"}}
    result = diff.diff_params(
        integration_norm, connector_norm,
        yml_param_names={"credentials_access_token"},
        integration_raw=integration_raw, connector_raw=connector_raw,
    )
    entry = _ok_entry(result, "credentials_access_token")
    assert entry["state"] == diff.STATE_OK
    assert entry["verdict"] == "ok"
    assert entry["partially_ignored"] is True
    assert entry["compared_keys"] == ["identifier", "password"]
    # The skeleton sub-keys dropped from the integration side, sorted,
    # excluding identifier/password.
    assert entry["ignored_keys"] == ["credential", "credentials", "passwordChanged"]
    assert isinstance(entry.get("partial_ignore_note"), str) and entry["partial_ignore_note"]


# ---------------------------------------------------------------------------
# Category 3 (alertType server bug) — end-to-end: integration-only → OK_IGNORED
# ---------------------------------------------------------------------------
def test_alerttype_integration_only_produces_ok_ignored_pass():
    """The server-injected `alertType` (integration-only) is normalized into a
    drop and surfaces as a passing OK_IGNORED entry — NOT dropped/MISSING/fail."""
    integration_raw = {"url": "x", "alertType": "Phishing"}
    connector_raw = {"url": "x"}
    integration_norm, integration_dropped = normalize_for_diff(
        integration_raw, [{"name": "url", "type": 0}], side="integration"
    )
    connector_norm, connector_dropped = normalize_for_diff(
        connector_raw, [{"name": "url", "type": 0}], side="connector"
    )
    result = diff.diff_params(
        integration_norm, connector_norm,
        yml_param_names={"url"},
        integration_raw=integration_raw, connector_raw=connector_raw,
        integration_dropped=integration_dropped, connector_dropped=connector_dropped,
    )
    # alertType is NOT a failure, NOT in dropped (it is an explicit named ignore).
    assert result["status"] == "pass"
    assert result["summary"]["n_fail"] == 0
    assert all(d["name"] != "alertType" for d in result["dropped"])
    entry = _ok_ignored(result, "alertType")
    assert entry["verdict"] == "ok"
    assert "server-injected `alertType`" in entry["reason"]
    assert "XSOAR BE bug" in entry["reason"]
    assert entry["integration_value"] == "Phishing"


# ---------------------------------------------------------------------------
# Category 2 — connector-only framework fields → OK_IGNORED, never EXTRA_IN_CONNECTOR
# ---------------------------------------------------------------------------
def _no_extra_in_connector(result: dict, name: str) -> None:
    for p in result["per_param"]:
        assert not (
            p["name"] == name and p["state"] == diff.STATE_EXTRA_IN_CONNECTOR
        ), f"{name} surfaced as EXTRA_IN_CONNECTOR"


def test_connector_only_framework_fields_ok_ignored_not_extra():
    """Each of the seven connector-only framework fields, present ONLY on the
    connector side, surfaces as a passing OK_IGNORED entry and never as
    EXTRA_IN_CONNECTOR."""
    fields = [
        "mappingId", "incomingMapperId", "outgoingMapperId", "engine",
        "engineGroup", "defaultIgnore", "integrationLogLevel",
    ]
    yml = [{"name": "url", "type": 0}]
    integration_raw = {"url": "x"}
    connector_raw = {"url": "x"}
    for name in fields:
        connector_raw[name] = "framework-value"
    integration_norm, integration_dropped = normalize_for_diff(
        integration_raw, yml, side="integration"
    )
    connector_norm, connector_dropped = normalize_for_diff(
        connector_raw, yml, side="connector"
    )
    result = diff.diff_params(
        integration_norm, connector_norm,
        yml_param_names={"url"},
        integration_raw=integration_raw, connector_raw=connector_raw,
        integration_dropped=integration_dropped, connector_dropped=connector_dropped,
    )
    assert result["status"] == "pass"
    assert result["summary"]["n_extra_in_connector"] == 0
    for name in fields:
        _no_extra_in_connector(result, name)
        entry = _ok_ignored(result, name)
        assert entry["verdict"] == "ok"
        assert entry["connector_value"] == "framework-value"


# ---------------------------------------------------------------------------
# BE-synthesized fetch params: integration-only → MISSING_IN_CONNECTOR (fail),
# NOT dropped as extra_in_integration. The XSOAR BE injects these at runtime;
# the connector platform never synthesizes anything, so an absent equivalent on
# the connector side is a genuine parity gap (the GuardiCore v2 case: the XSOAR
# integration reads `incidentFetchInterval`, the connector declared
# `alertFetchInterval` instead → no parity → fail).
# ---------------------------------------------------------------------------
def _per_param(result: dict, name: str) -> dict:
    for p in result["per_param"]:
        if p["name"] == name:
            return p
    raise AssertionError(f"No per_param entry for {name!r}")


def test_be_synth_integration_only_param_is_missing_in_connector_not_dropped():
    """`incidentFetchInterval` present on XSOAR, absent on connector, NOT in the
    integration YML → must be MISSING_IN_CONNECTOR (fail), not dropped."""
    result = diff.diff_params(
        {"incidentFetchInterval": "1"},
        {},
        yml_param_names=set(),  # NOT declared in the integration YML
    )
    # It must NOT be silently dropped as framework noise.
    assert all(d["name"] != "incidentFetchInterval" for d in result["dropped"])
    entry = _per_param(result, "incidentFetchInterval")
    assert entry["state"] == diff.STATE_MISSING_IN_CONNECTOR
    assert entry["verdict"] == "fail"
    assert result["status"] == "fail"
    assert result["summary"]["n_missing_in_connector"] == 1


def test_non_be_synth_integration_only_param_still_dropped_as_extra():
    """A genuinely-unknown integration-only key (not in YML, not BE-synthesized)
    is still dropped as extra_in_integration framework noise — the BE-synth fix
    must not over-broaden to ALL integration-only keys."""
    result = diff.diff_params(
        {"some_framework_noise_key": "x"},
        {},
        yml_param_names=set(),
    )
    assert any(
        d["name"] == "some_framework_noise_key"
        and d["reason"] == "extra_in_integration"
        for d in result["dropped"]
    )
    assert result["summary"]["n_missing_in_connector"] == 0


def test_be_synth_param_present_on_both_sides_compares_normally():
    """When the connector DOES declare the equivalent (so both sides carry it),
    the BE-synth name compares like any other param (OK on equal values)."""
    result = diff.diff_params(
        {"incidentFetchInterval": "1"},
        {"incidentFetchInterval": "1"},
        yml_param_names=set(),
    )
    entry = _per_param(result, "incidentFetchInterval")
    assert entry["state"] == diff.STATE_OK
    assert result["status"] == "pass"
