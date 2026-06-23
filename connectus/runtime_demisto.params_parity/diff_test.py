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
# `incidentFetchInterval` instead → no parity → fail).
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


# ---------------------------------------------------------------------------
# Fetch-toggle "absent == False" parity: a falsy toggle present on one side and
# absent on the other is at parity (the platform treats an absent toggle as
# False), so it must PASS as OK with an explanatory note — NOT
# MISSING_IN_CONNECTOR / EXTRA_IN_CONNECTOR.
# ---------------------------------------------------------------------------
def test_fetch_toggle_false_on_integration_absent_on_connector_is_ok():
    result = diff.diff_params(
        {"isFetch": False},
        {},
        yml_param_names=set(),
    )
    entry = _per_param(result, "isFetch")
    assert entry["state"] == diff.STATE_OK
    assert entry["verdict"] == "ok"
    assert "treated as False" in entry["reason"]
    assert result["status"] == "pass"
    assert result["summary"]["n_missing_in_connector"] == 0
    assert all(d["name"] != "isFetch" for d in result["dropped"])


def test_fetch_toggle_false_on_connector_absent_on_integration_is_ok():
    result = diff.diff_params(
        {},
        {"isFetchEvents": False},
        yml_param_names=set(),
    )
    entry = _per_param(result, "isFetchEvents")
    assert entry["state"] == diff.STATE_OK
    assert entry["verdict"] == "ok"
    assert "treated as False" in entry["reason"]
    assert result["status"] == "pass"
    assert result["summary"]["n_extra_in_connector"] == 0


def test_fetch_toggle_falsy_string_absent_other_side_is_ok():
    """The falsy form may be the string 'false' (XSOAR serializes booleans as
    strings in some captures)."""
    result = diff.diff_params(
        {"feed": "false"},
        {},
        yml_param_names=set(),
    )
    entry = _per_param(result, "feed")
    assert entry["state"] == diff.STATE_OK
    assert result["status"] == "pass"


def test_fetch_toggle_TRUE_on_integration_absent_on_connector_still_fails():
    """A TRUE toggle present on XSOAR but absent on the connector is a REAL gap
    (the connector should be emitting an active fetch flag) → MISSING_IN_CONNECTOR.
    The absent==False rule must NOT mask a truthy toggle."""
    result = diff.diff_params(
        {"isFetch": True},
        {},
        yml_param_names=set(),
    )
    entry = _per_param(result, "isFetch")
    assert entry["state"] == diff.STATE_MISSING_IN_CONNECTOR
    assert entry["verdict"] == "fail"
    assert result["status"] == "fail"


def test_fetch_toggle_present_both_sides_compares_normally():
    """Both sides carry the toggle → ordinary comparison (False==False → OK)."""
    result = diff.diff_params(
        {"isFetch": False},
        {"isFetch": False},
        yml_param_names=set(),
    )
    entry = _per_param(result, "isFetch")
    assert entry["state"] == diff.STATE_OK
    # The normal OK path has no "treated as False" note.
    assert "reason" not in entry or "treated as False" not in entry.get("reason", "")
    assert result["status"] == "pass"


def test_non_toggle_falsy_integration_only_is_not_excused():
    """The absent==False rule is scoped to fetch toggles ONLY. A non-toggle
    BE-synth param that is falsy and absent on the connector is still a real
    MISSING_IN_CONNECTOR (e.g. incidentType)."""
    result = diff.diff_params(
        {"incidentType": ""},
        {},
        yml_param_names=set(),
    )
    entry = _per_param(result, "incidentType")
    assert entry["state"] == diff.STATE_MISSING_IN_CONNECTOR
    assert result["status"] == "fail"


# ---------------------------------------------------------------------------
# Per-variant field SCOPING (Bucket C) — out_of_variant_scope reclassification.
# ---------------------------------------------------------------------------
def test_out_of_variant_scope_reclassifies_to_ok_ignored():
    """An integration-only field NOT in the variant's in_scope_fields AND owned
    by a sub-capability that is disabled in this variant → OK_IGNORED with the
    out_of_variant_scope reason; it is NOT MISSING_IN_CONNECTOR and does NOT
    fail the gate."""
    result = diff.diff_params(
        {"longRunning": True},  # integration sends it; connector (this variant) doesn't
        {},
        yml_param_names={"longRunning"},
        # This variant enables fetch-issues; longRunning belongs to the DISABLED
        # log-collection sub-capability, so it is out of scope here.
        in_scope_fields={"incidentType"},
        field_owning_subcapabilities={
            "longRunning": frozenset({"log-collection_x"}),
            "incidentType": frozenset({"fetch-issues_x"}),
        },
        enabled_ownership_units={"fetch-issues_x"},
    )
    entry = _per_param(result, "longRunning")
    assert entry["state"] == diff.STATE_OK_IGNORED
    assert entry["verdict"] == "ok"
    assert "out_of_variant_scope" not in entry["reason"]  # rendered human text
    assert "not enabled in this variant" in entry["reason"]
    assert entry["out_of_scope_owners"] == ["log-collection_x"]
    # No MISSING finding; gate passes.
    assert result["summary"]["n_missing_in_connector"] == 0
    assert result["summary"]["n_out_of_variant_scope"] == 1
    assert result["summary"]["n_fail"] == 0
    assert result["status"] == "pass"


def test_in_scope_but_absent_still_missing_in_connector():
    """A field that IS in the variant's in_scope_fields but is genuinely absent
    on the connector MUST still fail as MISSING_IN_CONNECTOR (no loss of
    coverage), even though it is owned by a (enabled) sub-capability."""
    result = diff.diff_params(
        {"incidentType": "Phishing"},
        {},
        yml_param_names={"incidentType"},
        in_scope_fields={"incidentType"},
        field_owning_subcapabilities={
            "incidentType": frozenset({"fetch-issues_x"}),
        },
        enabled_ownership_units={"fetch-issues_x"},
    )
    entry = _per_param(result, "incidentType")
    assert entry["state"] == diff.STATE_MISSING_IN_CONNECTOR
    assert result["summary"]["n_missing_in_connector"] == 1
    assert result["summary"]["n_out_of_variant_scope"] == 0
    assert result["status"] == "fail"


def test_out_of_scope_owned_only_by_enabled_unit_is_not_reclassified():
    """A field owned ONLY by ENABLED units is in-scope-equivalent: even if it were
    somehow absent from in_scope_fields, having no DISABLED owner means it is not
    out-of-variant-scope and stays MISSING_IN_CONNECTOR."""
    result = diff.diff_params(
        {"incidentType": "Phishing"},
        {},
        yml_param_names={"incidentType"},
        in_scope_fields=set(),  # deliberately empty
        field_owning_subcapabilities={
            "incidentType": frozenset({"fetch-issues_x"}),
        },
        enabled_ownership_units={"fetch-issues_x"},  # the sole owner IS enabled
    )
    entry = _per_param(result, "incidentType")
    assert entry["state"] == diff.STATE_MISSING_IN_CONNECTOR
    assert result["status"] == "fail"


def test_scoping_off_when_in_scope_fields_none_unchanged_behaviour():
    """When in_scope_fields is None (scoping OFF), an integration-only owned field
    still becomes MISSING_IN_CONNECTOR — backward-compatible behaviour."""
    result = diff.diff_params(
        {"longRunning": True},
        {},
        yml_param_names={"longRunning"},
        field_owning_subcapabilities={
            "longRunning": frozenset({"log-collection_x"}),
        },
        enabled_ownership_units={"fetch-issues_x"},
        # in_scope_fields omitted → scoping inactive.
    )
    entry = _per_param(result, "longRunning")
    assert entry["state"] == diff.STATE_MISSING_IN_CONNECTOR
    assert result["status"] == "fail"


def test_out_of_variant_scope_summary_counters_consistent():
    """n_total must NOT double-count out-of-scope keys (they are integration keys
    already in union_keys), while n_ok_ignored reflects them."""
    result = diff.diff_params(
        {"longRunning": True, "incidentType": "Phishing"},
        {"incidentType": "Phishing"},
        yml_param_names={"longRunning", "incidentType"},
        in_scope_fields={"incidentType"},
        field_owning_subcapabilities={
            "longRunning": frozenset({"log-collection_x"}),
            "incidentType": frozenset({"fetch-issues_x"}),
        },
        enabled_ownership_units={"fetch-issues_x"},
    )
    summary = result["summary"]
    # union_keys = {longRunning, incidentType} = 2; no normalizer drops here.
    assert summary["n_total"] == 2
    assert summary["n_out_of_variant_scope"] == 1
    assert summary["n_ok_ignored"] == 1
    assert summary["n_ok"] == 1            # incidentType matches on both sides
    assert summary["n_missing_in_connector"] == 0
    assert result["status"] == "pass"


# ---------------------------------------------------------------------------
# Bucket C DEFECT-2: the scope downgrade must apply to ALL THREE failing states
# (MISSING_IN_CONNECTOR — covered above — plus VALUE_MISMATCH and
# EXTRA_IN_CONNECTOR), via the single shared scope gate.
# ---------------------------------------------------------------------------
def test_out_of_variant_scope_value_mismatch_reclassified_to_ok_ignored():
    """A VALUE_MISMATCH on a field owned SOLELY by a DISABLED sub-capability (the
    platform injected a manifest default on the connector while the integration
    sent its override) must be downgraded to OK_IGNORED out_of_variant_scope —
    NOT counted as a value mismatch / failure."""
    result = diff.diff_params(
        {"page_size": "5"},          # integration override
        {"page_size": "20000"},      # connector manifest default → would mismatch
        yml_param_names={"page_size"},
        # fetch-issues variant: page_size belongs to the DISABLED log-collection.
        in_scope_fields={"incidentType"},
        field_owning_subcapabilities={
            "page_size": frozenset({"log-collection_x"}),
            "incidentType": frozenset({"fetch-issues_x"}),
        },
        enabled_ownership_units={"fetch-issues_x"},
    )
    entry = _per_param(result, "page_size")
    assert entry["state"] == diff.STATE_OK_IGNORED
    assert entry["verdict"] == "ok"
    assert "not enabled in this variant" in entry["reason"]
    assert entry["out_of_scope_owners"] == ["log-collection_x"]
    # Both value fields preserved for the operator.
    assert entry["integration_value"] == "5"
    assert entry["connector_value"] == "20000"
    summary = result["summary"]
    assert summary["n_value_mismatch"] == 0
    assert summary["n_out_of_variant_scope"] == 1
    assert summary["n_ok_ignored"] == 1
    assert summary["n_fail"] == 0
    assert result["status"] == "pass"


def test_out_of_variant_scope_extra_in_connector_reclassified_to_ok_ignored():
    """An EXTRA_IN_CONNECTOR field owned SOLELY by a DISABLED sub-capability (the
    platform injected a connector-only field belonging to a disabled
    sub-capability) must be downgraded to OK_IGNORED out_of_variant_scope —
    NOT counted as an extra / failure."""
    result = diff.diff_params(
        {},                                    # integration doesn't read it
        {"incidentFetchInterval": "1"},           # connector injects it
        yml_param_names=set(),
        # log-collection variant: incidentFetchInterval is gated on the DISABLED
        # fetch-issues sub-capability.
        in_scope_fields={"longRunning"},
        field_owning_subcapabilities={
            "incidentFetchInterval": frozenset({"fetch-issues_x"}),
            "longRunning": frozenset({"log-collection_x"}),
        },
        enabled_ownership_units={"log-collection_x"},
    )
    entry = _per_param(result, "incidentFetchInterval")
    assert entry["state"] == diff.STATE_OK_IGNORED
    assert entry["verdict"] == "ok"
    assert "not enabled in this variant" in entry["reason"]
    assert entry["out_of_scope_owners"] == ["fetch-issues_x"]
    assert entry["connector_value"] == "1"
    assert "integration_value" not in entry  # connector-only field
    summary = result["summary"]
    assert summary["n_extra_in_connector"] == 0
    assert summary["n_out_of_variant_scope"] == 1
    assert summary["n_ok_ignored"] == 1
    assert summary["n_fail"] == 0
    assert result["status"] == "pass"


def test_in_scope_value_mismatch_still_fails():
    """GUARD: an IN-SCOPE field with a value mismatch MUST still FAIL as
    VALUE_MISMATCH — the generalized scope gate must not swallow real drift for a
    field whose owning sub-capability is enabled."""
    result = diff.diff_params(
        {"incidentType": "Phishing"},
        {"incidentType": "Malware"},
        yml_param_names={"incidentType"},
        in_scope_fields={"incidentType"},
        field_owning_subcapabilities={
            "incidentType": frozenset({"fetch-issues_x"}),
        },
        enabled_ownership_units={"fetch-issues_x"},
    )
    entry = _per_param(result, "incidentType")
    assert entry["state"] == diff.STATE_VALUE_MISMATCH
    assert entry["verdict"] == "fail"
    summary = result["summary"]
    assert summary["n_value_mismatch"] == 1
    assert summary["n_out_of_variant_scope"] == 0
    assert result["status"] == "fail"


def test_in_scope_extra_in_connector_still_fails():
    """GUARD: an EXTRA_IN_CONNECTOR field owned by an ENABLED sub-capability MUST
    still FAIL as EXTRA_IN_CONNECTOR (no coverage loss for in-scope extras)."""
    result = diff.diff_params(
        {},
        {"incidentType": "Phishing"},
        yml_param_names=set(),
        in_scope_fields={"incidentType"},
        field_owning_subcapabilities={
            "incidentType": frozenset({"fetch-issues_x"}),
        },
        enabled_ownership_units={"fetch-issues_x"},
    )
    entry = _per_param(result, "incidentType")
    assert entry["state"] == diff.STATE_EXTRA_IN_CONNECTOR
    assert entry["verdict"] == "fail"
    assert result["summary"]["n_extra_in_connector"] == 1
    assert result["summary"]["n_out_of_variant_scope"] == 0
    assert result["status"] == "fail"


# ---------------------------------------------------------------------------
# Connector-int / Integration-string parity contract (incidentFetchInterval).
# ---------------------------------------------------------------------------
def test_incident_fetch_interval_int_vs_str_is_parity_ok():
    """connector int 111 == integration str "111" → OK, not VALUE_MISMATCH.

    ``incidentFetchInterval`` is a BE-synthesized param (so it is treated as a
    real param the integration reads) AND a registered connector-int /
    integration-string field, so the asymmetric int/str representation is at
    parity rather than a spurious mismatch.
    """
    result = diff.diff_params(
        {"incidentFetchInterval": "111"},   # integration side — string
        {"incidentFetchInterval": 111},     # connector side — integer
    )
    entry = _per_param(result, "incidentFetchInterval")
    assert entry["state"] == diff.STATE_OK
    assert entry["verdict"] == "ok"
    assert result["summary"]["n_value_mismatch"] == 0
    assert result["status"] == "pass"


def test_incident_fetch_interval_genuine_mismatch_still_fails():
    """connector int 111 vs integration str "222" → genuine VALUE_MISMATCH."""
    result = diff.diff_params(
        {"incidentFetchInterval": "222"},   # integration side — string
        {"incidentFetchInterval": 111},     # connector side — integer
    )
    entry = _per_param(result, "incidentFetchInterval")
    assert entry["state"] == diff.STATE_VALUE_MISMATCH
    assert entry["verdict"] == "fail"
    assert result["summary"]["n_value_mismatch"] == 1
    assert result["status"] == "fail"


def test_non_registry_number_int_vs_str_still_mismatches():
    """A NON-registry field keeps strict equality: int 111 != str "111" fails.

    Guards against the int/str equivalence leaking into a blanket rule. We use a
    YML param name so it is compared (not dropped as framework noise)."""
    result = diff.diff_params(
        {"somePort": "111"},
        {"somePort": 111},
        yml_param_names={"somePort"},
    )
    entry = _per_param(result, "somePort")
    assert entry["state"] == diff.STATE_VALUE_MISMATCH
    assert entry["verdict"] == "fail"


# ---------------------------------------------------------------------------
# serialized_from / serialized_to annotation SCOPING (grouped connectors)
#
# For a GROUPED connector (e.g. aws), diff._load_serializer_mappings rglobs
# EVERY handler's serializer.yaml and lets the LAST-parsed mapping for a shared
# xsoar param name win. That mis-attributes a param to a SIBLING handler's
# connector field id (observed: AWS-SNS-Listener's `incidentType` annotated
# `serialized_from: xsoar-aws-sqs_incidentType`, an AWS-SQS field; AWS-SQS's
# `first_fetch` annotated with the security-hub-event-collector field). The fix
# threads THIS handler's scoped serializer maps (from the resolver) into
# diff_params and uses them verbatim for the annotation.
# ---------------------------------------------------------------------------
def test_serialized_from_uses_scoped_handler_map_not_sibling():
    """Grouped connector: a shared param name is annotated from THIS handler's
    serializer map, never a sibling handler's connector field id.

    Models AWS-SNS-Listener: `incidentType` exists in the integration but the
    SNS-Listener handler serializer does NOT rename it, while a SIBLING handler
    (aws-sqs) maps `xsoar-aws-sqs_incidentType -> incidentType`. With the
    SNS-Listener-scoped maps (which have no incidentType entry), the param must
    carry NO serialized_from at all — not the SQS field id."""
    result = diff.diff_params(
        {"incidentType": "Phishing"},
        {},
        yml_param_names={"incidentType"},
        # SNS-Listener handler serializer has NO incidentType mapping.
        serializer_by_xsoar={},
        serializer_by_connector={},
    )
    entry = _per_param(result, "incidentType")
    assert entry["state"] == diff.STATE_MISSING_IN_CONNECTOR
    assert "serialized_from" not in entry


def test_serialized_from_prefers_scoped_map_over_rglob_fallback(tmp_path):
    """When scoped maps ARE provided, the connector-wide rglob is NOT consulted
    even though connector_dir points at a tree full of sibling serializers."""
    # A sibling handler tree that WOULD (via rglob) map incidentType to a SQS id.
    sib = tmp_path / "components" / "handlers" / "xsoar-aws-sqs"
    sib.mkdir(parents=True)
    (sib / "serializer.yaml").write_text(
        "field_mappings:\n"
        "- id: xsoar-aws-sqs_incidentType\n"
        "  field_name: incidentType\n"
    )
    result = diff.diff_params(
        {"first_fetch": "x"},
        {"first_fetch": "x"},
        yml_param_names={"first_fetch", "incidentType"},
        connector_dir=str(tmp_path),
        # THIS handler's scoped map: first_fetch is the only rename it declares.
        serializer_by_xsoar={"first_fetch": "xsoar-this-handler_first_fetch"},
        serializer_by_connector={"xsoar-this-handler_first_fetch": "first_fetch"},
    )
    ff = _per_param(result, "first_fetch")
    assert ff["serialized_from"] == "xsoar-this-handler_first_fetch"


def test_serialized_from_resolves_to_non_sub_prefixed_field_id():
    """The scoped map may declare a connector field id that does NOT follow the
    `xsoar-<this-sub>_<name>` shape (a cross-handler / shared serving field).
    The annotation must use exactly what the scoped map says."""
    result = diff.diff_params(
        {"first_fetch": "7 days"},
        {"first_fetch": "7 days"},
        yml_param_names={"first_fetch"},
        serializer_by_xsoar={"first_fetch": "shared_connector_first_fetch_field"},
        serializer_by_connector={"shared_connector_first_fetch_field": "first_fetch"},
    )
    entry = _per_param(result, "first_fetch")
    assert entry["serialized_from"] == "shared_connector_first_fetch_field"


def test_serialized_to_uses_scoped_handler_map():
    """A connector-only field is annotated serialized_to from THIS handler's
    by_connector map (so EXTRA_IN_CONNECTOR triage points at the right rename)."""
    result = diff.diff_params(
        {},
        {"xsoar-this-handler_domain": "v"},
        yml_param_names=set(),
        serializer_by_xsoar={"url": "xsoar-this-handler_domain"},
        serializer_by_connector={"xsoar-this-handler_domain": "url"},
    )
    entry = _per_param(result, "xsoar-this-handler_domain")
    assert entry["serialized_to"] == "url"


def test_serialized_from_falls_back_to_rglob_when_no_scoped_maps(tmp_path):
    """Back-compat: callers/tests that pass only connector_dir (no scoped maps)
    still get rglob-derived annotations — unchanged behaviour."""
    h = tmp_path / "components" / "handlers" / "xsoar-h"
    h.mkdir(parents=True)
    (h / "serializer.yaml").write_text(
        "field_mappings:\n- id: domain\n  field_name: url\n"
    )
    result = diff.diff_params(
        {"url": "v"},
        {"url": "v"},
        yml_param_names={"url"},
        connector_dir=str(tmp_path),
    )
    entry = _per_param(result, "url")
    assert entry["serialized_from"] == "domain"


# ---------------------------------------------------------------------------
# MULTI-PROFILE (XOR) auth — a non-active alternative profile's auth secret must
# be scoped out (OK_IGNORED / alternative_xor_auth_profile), NOT MISSING; and a
# single-profile genuine miss must STILL fail (over-suppression guard).
#
# These mirror what the resolver produces for a 2-profile (XOR) connector like
# FortiGate: each auth-bearing profile's auth params are attributed to a synthetic
# ``__profile__:<id>`` ownership unit; the variant ENABLES only its active
# profile's unit, so the OTHER profile's secret is owned solely by a DISABLED unit
# and flows through the existing out-of-variant-scope gate.
# ---------------------------------------------------------------------------
_PROF_API_KEY = diff._PROFILE_OWNERSHIP_PREFIX + "api_key.fortigate"
_PROF_PLAIN = diff._PROFILE_OWNERSHIP_PREFIX + "plain.fortigate"


def test_xor_auth_active_profile_secret_compared_other_scoped_out():
    """The ``plain`` profile is active: ``credentials`` is compared (OK), while the
    NON-active ``api_key`` profile's secret is OK_IGNORED with the dedicated
    alternative-XOR-auth reason — NOT MISSING_IN_CONNECTOR. No failure."""
    result = diff.diff_params(
        # integration declares BOTH secrets (FortiGate YML has api_key + credentials)
        {"api_key": {"password": "K"}, "credentials": {"identifier": "u", "password": "p"}},
        # connector instance (plain active) only delivers credentials
        {"credentials": {"identifier": "u", "password": "p"}},
        yml_param_names={"api_key", "credentials"},
        # ACTIVE profile = plain → credentials in scope; api_key NOT in scope.
        in_scope_fields={"credentials"},
        field_owning_subcapabilities={
            "api_key": frozenset({_PROF_API_KEY}),
            "credentials": frozenset({_PROF_PLAIN}),
        },
        # Only the plain profile's unit is enabled in this variant.
        enabled_ownership_units={_PROF_PLAIN},
    )
    cred = _per_param(result, "credentials")
    assert cred["state"] == diff.STATE_OK
    api = _per_param(result, "api_key")
    assert api["state"] == diff.STATE_OK_IGNORED
    assert api["out_of_scope_owners"] == [_PROF_API_KEY]
    assert "ALTERNATIVE" in api["reason"] or "alternative" in api["reason"]
    assert result["summary"]["n_missing_in_connector"] == 0
    assert result["summary"]["n_out_of_variant_scope"] == 1
    assert result["status"] == "pass"


def test_xor_auth_other_profile_active_symmetric():
    """Symmetric pass: when the ``api_key`` profile is active, ``api_key`` is
    compared and the ``credentials`` (plain) secret is scoped out — proving every
    profile's secret IS verified in its OWN variant (full coverage)."""
    result = diff.diff_params(
        {"api_key": {"password": "K"}, "credentials": {"identifier": "u", "password": "p"}},
        {"api_key": {"password": "K"}},  # api_key active
        yml_param_names={"api_key", "credentials"},
        in_scope_fields={"api_key"},
        field_owning_subcapabilities={
            "api_key": frozenset({_PROF_API_KEY}),
            "credentials": frozenset({_PROF_PLAIN}),
        },
        enabled_ownership_units={_PROF_API_KEY},
    )
    assert _per_param(result, "api_key")["state"] == diff.STATE_OK
    cred = _per_param(result, "credentials")
    assert cred["state"] == diff.STATE_OK_IGNORED
    assert cred["out_of_scope_owners"] == [_PROF_PLAIN]
    assert result["summary"]["n_missing_in_connector"] == 0
    assert result["status"] == "pass"


def test_single_profile_genuine_missing_secret_still_fails():
    """OVER-SUPPRESSION GUARD: a SINGLE-profile connector whose sole auth secret is
    genuinely absent on the connector side MUST still fail MISSING_IN_CONNECTOR.
    The sole profile is always active, so its secret is in_scope and owned by an
    ENABLED unit — the XOR exemption must NOT fire."""
    result = diff.diff_params(
        {"api_key": {"password": "K"}},  # integration has it
        {},                              # connector is genuinely missing it
        yml_param_names={"api_key"},
        # Single profile → its secret is in scope AND its (sole) profile unit is
        # the enabled/active one.
        in_scope_fields={"api_key"},
        field_owning_subcapabilities={"api_key": frozenset({_PROF_API_KEY})},
        enabled_ownership_units={_PROF_API_KEY},
    )
    entry = _per_param(result, "api_key")
    assert entry["state"] == diff.STATE_MISSING_IN_CONNECTOR
    assert result["summary"]["n_missing_in_connector"] == 1
    assert result["status"] == "fail"


def test_alternative_xor_auth_reason_describes_clearly():
    """The dedicated reason code renders an operator-clear XOR-auth explanation."""
    msg = diff._describe_ignore_reason("alternative_xor_auth_profile")
    assert "ALTERNATIVE" in msg
    assert "mutually-exclusive" in msg
    assert "active" in msg
