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
    assert "isFetch" in added
    assert "incidentFetchInterval" in added
    assert "incidentType" in added          # isfetchevents is OFF for this variant
    assert "eventFetchInterval" not in added
    assert "alertType" not in added         # alertType is NEVER auto-added
    assert stripped == []                    # a fetch IS on → nothing stripped
    # longRunning STILL comes from the script (not a variant axis).
    assert "longRunning" in added


def test_variant_log_collection_overrides_script():
    """log-collection variant → event params added, NO isFetch alert params."""
    added, stripped = compute_be_synthesized_params(
        _SIEM_SCRIPT, fetch_flags=_flags("isFetchEvents")
    )
    assert "isFetchEvents" in added
    assert "eventFetchInterval" in added
    assert "incidentFetchInterval" not in added
    assert "incidentType" not in added
    assert stripped == []
    assert "longRunning" in added            # script-driven, unaffected by variant


def test_variant_no_fetch_strips_fetch_params():
    """A truly-no-fetch script+variant (no fetch flag AND no longRunning) strips
    the fetch-only params."""
    added, stripped = compute_be_synthesized_params(
        {}, fetch_flags=_flags(None)
    )
    assert "incidentFetchInterval" not in added
    assert "eventFetchInterval" not in added
    assert "isFetch" in stripped
    assert "isFetchEvents" in stripped


def test_longrunning_script_counts_as_fetch_no_strip():
    """longRunning is a member of the BE's no-strip guard set: when the SIEM
    script declares longRunning but the variant has no fetch, the strip set must
    NOT apply (and longRunning is still added)."""
    added, stripped = compute_be_synthesized_params(
        _SIEM_SCRIPT, fetch_flags=_flags(None)
    )
    assert "longRunning" in added
    assert stripped == []


def test_variant_fetch_credentials_counts_as_fetch():
    """fetch-secrets variant: only the isFetchCredentials toggle is added, but it
    counts as a fetch so the no-fetch strip set must NOT apply."""
    added, stripped = compute_be_synthesized_params(
        {}, fetch_flags=_flags("isFetchCredentials")
    )
    # The BE adds the toggle itself...
    assert "isFetchCredentials" in added
    # ...but no other synthesized config params.
    assert "incidentFetchInterval" not in added
    assert "eventFetchInterval" not in added
    assert "incidentType" not in added
    # ...and it counts as a fetch, so the no-fetch strip set must NOT apply.
    assert stripped == []


def test_script_fallback_when_no_variant_flags():
    """With no fetch_flags, the static script flags drive the decision (legacy)."""
    added, _ = compute_be_synthesized_params(
        {"isfetch": True}, fetch_flags=None
    )
    assert "isFetch" in added
    assert "incidentFetchInterval" in added


def test_apply_transform_threads_variant_flags():
    out = apply_be_config_transform(
        {"existing": "v"},
        _SIEM_SCRIPT,
        fetch_flags=_flags("isFetchEvents"),
    )
    assert out["existing"] == "v"           # input preserved
    assert "isFetchEvents" in out
    assert "eventFetchInterval" in out
    assert "incidentFetchInterval" not in out


# ---------------------------------------------------------------------------
# Authoritative BE add/strip matrix (one block per script flag).
# ---------------------------------------------------------------------------
def test_isfetch_adds_isfetch_incidentfetchinterval_incidenttype():
    """IsFetch → isFetch, incidentFetchInterval, incidentType (not feed/events)."""
    added, stripped = compute_be_synthesized_params({}, fetch_flags=_flags("isFetch"))
    assert set(added) == {"isFetch", "incidentFetchInterval", "incidentType"}
    assert "alertType" not in added         # never auto-added
    assert stripped == []


def test_feed_adds_full_feed_field_set():
    """Feed → feed + the six feed* config params; incidentType is SKIPPED."""
    added, _ = compute_be_synthesized_params({}, fetch_flags=_flags("feed"))
    assert set(added) == {
        "feed",
        "feedReputation",
        "feedReliability",
        "feedExpirationPolicy",
        "feedExpirationInterval",
        "feedFetchInterval",
        "feedBypassExclusionList",
    }
    assert "incidentType" not in added


def test_isfetchevents_adds_isfetchevents_and_interval():
    """IsFetchEvents → isFetchEvents, eventFetchInterval; incidentType SKIPPED."""
    added, _ = compute_be_synthesized_params({}, fetch_flags=_flags("isFetchEvents"))
    assert set(added) == {"isFetchEvents", "eventFetchInterval"}
    assert "incidentType" not in added


def test_isfetchassets_adds_isfetchassets_and_interval():
    """IsFetchAssets → isFetchAssets, assetsFetchInterval."""
    added, stripped = compute_be_synthesized_params(
        {}, fetch_flags=_flags("isFetchAssets")
    )
    assert set(added) == {"isFetchAssets", "assetsFetchInterval"}
    assert stripped == []                    # assets counts as a fetch


def test_longrunning_adds_longrunning_and_incidenttype_not_alerttype():
    """LongRunning (no fetch variant) → longRunning + incidentType, but NEVER
    alertType, and (counting as a fetch) nothing is stripped."""
    added, stripped = compute_be_synthesized_params(
        {"longRunning": True}, fetch_flags=_flags(None)
    )
    assert "longRunning" in added
    assert "incidentType" in added          # not feed / not events
    assert "alertType" not in added         # XSIAM bug field — never on connector
    assert stripped == []                    # longRunning counts as a fetch


def test_longrunning_incidenttype_skipped_when_events_active():
    """LongRunning + IsFetchEvents → incidentType is SKIPPED (events active)."""
    added, _ = compute_be_synthesized_params(
        {"longRunning": True}, fetch_flags=_flags("isFetchEvents")
    )
    assert "longRunning" in added
    assert "incidentType" not in added
    assert "alertType" not in added


def test_longrunningport_adds_longrunningport():
    """LongRunningPort → longRunningPort."""
    added, _ = compute_be_synthesized_params(
        {"longRunningPort": True}, fetch_flags=_flags(None)
    )
    assert "longRunningPort" in added


def test_strip_when_no_fetch_full_set():
    """No fetch flag at all → the FULL strip set is removed, alertType included."""
    added, stripped = compute_be_synthesized_params({}, fetch_flags=_flags(None))
    assert added == []
    assert set(stripped) == {
        "isFetch",
        "isFetchEvents",
        "incidentFetchInterval",
        "alertFetchInterval",
        "eventFetchInterval",
        "incidentType",
        "alertType",
        "longRunning",
        "longRunningPort",
    }


def test_alerttype_never_auto_added_for_any_variant():
    """alertType must NEVER appear in `added` for ANY fetch variant."""
    for active in ("isFetch", "isFetchEvents", "isFetchAssets", "feed",
                   "isFetchCredentials", None):
        added, _ = compute_be_synthesized_params(
            {"longRunning": True, "longRunningPort": True},
            fetch_flags=_flags(active),
        )
        assert "alertType" not in added, active


def test_interval_fields_get_minutes_dummy():
    """The interval fields receive the valid-minutes dummy, not a generic string."""
    out = apply_be_config_transform({}, {}, fetch_flags=_flags("isFetch"))
    assert out["incidentFetchInterval"] == "1"
    out_feed = apply_be_config_transform({}, {}, fetch_flags=_flags("feed"))
    assert out_feed["feedFetchInterval"] == "1"
    assert out_feed["feedExpirationInterval"] == "1"


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
