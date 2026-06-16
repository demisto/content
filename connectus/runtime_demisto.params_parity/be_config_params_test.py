"""Unit tests for be_config_params — focused on the VARIANT fetch-flag override.

The param-parity orchestrator drives the fetch decision from the capability
VARIANT under test (resolver.CapabilityVariant.fetch_flags), NOT the integration
YML's static script flags. These tests pin that override behavior and the
backward-compatible script-driven fallback.
"""
from __future__ import annotations

from be_config_params import (
    XSOAR_FETCH_TOGGLES,
    apply_be_config_transform,
    compute_be_synthesized_params,
    variant_toggle_overrides,
)


# Akamai WAF SIEM-like script: declares both fetch toggles AND longRunning. The
# VARIANT must decide which fetch is active, independent of these static flags.
_SIEM_SCRIPT = {
    "isfetch": True,
    "isfetchevents": True,
    "longRunning": True,
}


def _flags(active: str | None) -> dict[str, bool]:
    # Keys are the XSOAR toggle names (resolver.CAPABILITY_FETCH_FLAG values).
    names = ["isFetch", "isFetchEvents", "isFetchAssets", "feed", "isFetchCredentials"]
    return {n: (n == active) for n in names}


def test_variant_fetch_issues_overrides_script():
    """fetch-issues variant → isFetch params added, NO event params."""
    added, stripped = compute_be_synthesized_params(
        _SIEM_SCRIPT, fetch_flags=_flags("isFetch")
    )
    assert "alertFetchInterval" in added
    assert "incidentType" in added          # isfetchevents is OFF for this variant
    assert "eventFetchInterval" not in added
    assert stripped == []                    # a fetch IS on → nothing stripped
    # longRunning STILL comes from the script (not a variant axis).
    assert "longRunning" in added


def test_variant_log_collection_overrides_script():
    """log-collection variant → event params added, NO isFetch alert params."""
    added, stripped = compute_be_synthesized_params(
        _SIEM_SCRIPT, fetch_flags=_flags("isFetchEvents")
    )
    assert "eventFetchInterval" in added
    assert "alertFetchInterval" not in added
    assert "incidentType" not in added
    assert stripped == []
    assert "longRunning" in added            # script-driven, unaffected by variant


def test_variant_no_fetch_strips_fetch_params():
    """An always-on-only variant (no fetch) strips the fetch-only params."""
    added, stripped = compute_be_synthesized_params(
        _SIEM_SCRIPT, fetch_flags=_flags(None)
    )
    assert "alertFetchInterval" not in added
    assert "eventFetchInterval" not in added
    assert "isFetch" in stripped
    assert "isFetchEvents" in stripped
    # longRunning still added from script even with no fetch variant.
    assert "longRunning" in added


def test_variant_fetch_credentials_counts_as_fetch():
    """fetch-secrets variant: no synthesized add params, but NOT stripped."""
    added, stripped = compute_be_synthesized_params(
        {}, fetch_flags=_flags("isFetchCredentials")
    )
    # No BE-synthesized config params for credentials today...
    assert "alertFetchInterval" not in added
    assert "eventFetchInterval" not in added
    # ...but it counts as a fetch, so the no-fetch strip set must NOT apply.
    assert stripped == []


def test_script_fallback_when_no_variant_flags():
    """With no fetch_flags, the static script flags drive the decision (legacy)."""
    added, _ = compute_be_synthesized_params(
        {"isfetch": True}, fetch_flags=None
    )
    assert "alertFetchInterval" in added


def test_apply_transform_threads_variant_flags():
    out = apply_be_config_transform(
        {"existing": "v"},
        _SIEM_SCRIPT,
        fetch_flags=_flags("isFetchEvents"),
    )
    assert out["existing"] == "v"           # input preserved
    assert "eventFetchInterval" in out
    assert "alertFetchInterval" not in out


def test_variant_toggle_overrides_full_set_one_active():
    """log-collection variant → isFetchEvents True, ALL other toggles False."""
    out = variant_toggle_overrides(_flags("isFetchEvents"))
    # Covers EVERY XSOAR toggle (incl. isFetchSamples which has no capability).
    assert set(out) == set(XSOAR_FETCH_TOGGLES)
    assert out["isFetchEvents"] is True
    assert out["isFetch"] is False
    assert out["isFetchAssets"] is False
    assert out["isFetchSamples"] is False
    assert out["isFetchCredentials"] is False
    assert out["feed"] is False


def test_variant_toggle_overrides_no_fetch_all_false():
    out = variant_toggle_overrides(_flags(None))
    assert set(out) == set(XSOAR_FETCH_TOGGLES)
    assert all(v is False for v in out.values())


def test_variant_toggle_overrides_none_input():
    out = variant_toggle_overrides(None)
    assert set(out) == set(XSOAR_FETCH_TOGGLES)
    assert all(v is False for v in out.values())
