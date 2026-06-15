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
