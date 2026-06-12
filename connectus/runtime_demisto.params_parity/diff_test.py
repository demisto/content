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
