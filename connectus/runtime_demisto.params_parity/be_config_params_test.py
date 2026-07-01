"""Unit tests for be_config_params — focused on the VARIANT fetch-flag override.

The param-parity orchestrator drives the fetch decision from the capability
VARIANT under test (resolver.CapabilityVariant.fetch_flags), NOT the integration
YML's static script flags. These tests pin that override behavior and the
backward-compatible script-driven fallback.
"""
from __future__ import annotations

from be_config_params import (
    CONNECTOR_INT_INTEGRATION_STRING_FIELDS,
    XSOAR_FETCH_TOGGLES,
    apply_be_config_transform,
    compute_be_synthesized_params,
    connector_value_for,
    is_connector_int_integration_string_field,
    values_match,
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


# Maps each variant fetch-flag (XSOAR toggle name) to the YML ``script.*`` key
# that DECLARES the corresponding fetch mechanism. The variant-branch gate in
# ``compute_be_synthesized_params`` synthesizes a flag's fields only when the YML
# script also declares it, so tests that exercise a flag must pass a script that
# declares it. ``isFetchCredentials`` has no YML script flag (capability-only).
_FLAG_TO_SCRIPT_KEY: dict[str, str] = {
    "isFetch": "isfetch",
    "isFetchEvents": "isfetchevents",
    "isFetchAssets": "isfetchassets",
    "feed": "feed",
}


def _script_for(*active: str) -> dict[str, bool]:
    """Build a YML ``script`` dict declaring the mechanism for each active flag,
    so the variant-branch gate opens for those flags."""
    return {
        _FLAG_TO_SCRIPT_KEY[a]: True
        for a in active
        if a in _FLAG_TO_SCRIPT_KEY
    }


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
# Per-flag generalization: EACH fetch flag injects its synthesized fields into
# BOTH payloads (apply_be_config_transform = integration side; the connector
# side coerces the same names via connector_value_for). Off-flags inject nothing.
# ---------------------------------------------------------------------------
def _multi_flags(*active: str) -> dict[str, bool]:
    """fetch_flags with MORE THAN ONE flag True (combined-variant simulation)."""
    names = ["isFetch", "isFetchEvents", "isFetchAssets", "feed", "isFetchCredentials"]
    return {n: (n in active) for n in names}


def test_isfetchevents_injects_interval_into_both_payloads_with_types():
    """isFetchEvents=True → eventFetchInterval present on BOTH sides, non-default
    "111" string on the integration side, int 111 on the connector side."""
    out = apply_be_config_transform(
        {}, _script_for("isFetchEvents"), fetch_flags=_flags("isFetchEvents")
    )
    assert out["eventFetchInterval"] == "111"          # integration side: string
    assert isinstance(out["eventFetchInterval"], str)
    # connector side: same field coerced to int via the registry.
    assert connector_value_for("eventFetchInterval", out["eventFetchInterval"]) == 111
    assert isinstance(connector_value_for("eventFetchInterval", out["eventFetchInterval"]), int)
    assert is_connector_int_integration_string_field("eventFetchInterval")
    # off-flag fields must NOT leak.
    assert "incidentFetchInterval" not in out
    assert "assetsFetchInterval" not in out
    assert "feedFetchInterval" not in out


def test_isfetchevents_absent_when_flag_off():
    """eventFetchInterval/isFetchEvents must NOT appear when the flag is off."""
    out = apply_be_config_transform({}, {}, fetch_flags=_flags("isFetch"))
    assert "isFetchEvents" not in out
    assert "eventFetchInterval" not in out


def test_isfetchassets_injects_interval_into_both_payloads_with_types():
    """isFetchAssets=True → assetsFetchInterval present on BOTH sides with the
    correct string/int contract; off-flag fields absent."""
    out = apply_be_config_transform(
        {}, _script_for("isFetchAssets"), fetch_flags=_flags("isFetchAssets")
    )
    assert out["assetsFetchInterval"] == "111"
    assert isinstance(out["assetsFetchInterval"], str)
    assert connector_value_for("assetsFetchInterval", out["assetsFetchInterval"]) == 111
    assert is_connector_int_integration_string_field("assetsFetchInterval")
    assert "incidentFetchInterval" not in out
    assert "eventFetchInterval" not in out
    assert "feedFetchInterval" not in out


def test_isfetchassets_absent_when_flag_off():
    out = apply_be_config_transform({}, {}, fetch_flags=_flags("isFetch"))
    assert "isFetchAssets" not in out
    assert "assetsFetchInterval" not in out


def test_feed_injects_full_field_set_into_both_payloads_with_types():
    """feed=True → the whole feed framework field set on BOTH sides; the two feed
    interval/duration fields carry the int/str contract; off-flag fields absent."""
    out = apply_be_config_transform(
        {}, _script_for("feed"), fetch_flags=_flags("feed")
    )
    for fld in (
        "feed",
        "feedReputation",
        "feedReliability",
        "feedExpirationPolicy",
        "feedExpirationInterval",
        "feedFetchInterval",
        "feedBypassExclusionList",
    ):
        assert fld in out, fld
    # the two interval/duration feed fields use the minutes dummy + int/str contract.
    for fld in ("feedFetchInterval", "feedExpirationInterval"):
        assert out[fld] == "111", fld
        assert isinstance(out[fld], str), fld
        assert connector_value_for(fld, out[fld]) == 111, fld
        assert is_connector_int_integration_string_field(fld), fld
    # off-flag fields must NOT leak.
    assert "incidentFetchInterval" not in out
    assert "eventFetchInterval" not in out
    assert "assetsFetchInterval" not in out


def test_feed_absent_when_flag_off():
    out = apply_be_config_transform({}, {}, fetch_flags=_flags("isFetch"))
    for fld in ("feed", "feedFetchInterval", "feedExpirationInterval"):
        assert fld not in out, fld


def test_combined_multi_flag_variant_injects_the_union():
    """A combined variant with isFetch + isFetchEvents + isFetchAssets + feed all
    True injects the UNION of every flag's fields (each interval at the non-default
    minutes value), proving the table-driven loop is additive across flags."""
    out = apply_be_config_transform(
        {},
        _script_for("isFetch", "isFetchEvents", "isFetchAssets", "feed"),
        fetch_flags=_multi_flags("isFetch", "isFetchEvents", "isFetchAssets", "feed"),
    )
    for fld in (
        "isFetch", "incidentFetchInterval",
        "isFetchEvents", "eventFetchInterval",
        "isFetchAssets", "assetsFetchInterval",
        "feed", "feedFetchInterval", "feedExpirationInterval",
    ):
        assert fld in out, fld
    for fld in (
        "incidentFetchInterval", "eventFetchInterval",
        "assetsFetchInterval", "feedFetchInterval", "feedExpirationInterval",
    ):
        assert out[fld] == "111", fld
        assert connector_value_for(fld, out[fld]) == 111, fld


def test_isfetch_only_variant_does_not_leak_event_assets_feed_fields():
    """GUARD (CiscoSMA/CiscoESA shape): a variant with ONLY isFetch True must get
    its own fetch fields but NONE of the event/assets/feed synthesized fields in
    EITHER payload — this is the exact mismatch the generalization must not cause."""
    out = apply_be_config_transform(
        {}, _script_for("isFetch"), fetch_flags=_flags("isFetch")
    )
    # isFetch fields ARE present.
    assert out["isFetch"]
    assert out["incidentFetchInterval"] == "111"
    assert "incidentType" in out
    # event / assets / feed fields are ALL absent.
    for fld in (
        "isFetchEvents", "eventFetchInterval",
        "isFetchAssets", "assetsFetchInterval",
        "feed", "feedReputation", "feedReliability", "feedExpirationPolicy",
        "feedExpirationInterval", "feedFetchInterval", "feedBypassExclusionList",
    ):
        assert fld not in out, fld


# ---------------------------------------------------------------------------
# Authoritative BE add/strip matrix (one block per script flag).
# ---------------------------------------------------------------------------
def test_isfetch_adds_isfetch_incidentfetchinterval_incidenttype():
    """IsFetch → isFetch, incidentFetchInterval, incidentType (not feed/events)."""
    added, stripped = compute_be_synthesized_params(
        _script_for("isFetch"), fetch_flags=_flags("isFetch")
    )
    assert set(added) == {"isFetch", "incidentFetchInterval", "incidentType"}
    assert "alertType" not in added         # never auto-added
    assert stripped == []


def test_feed_adds_full_feed_field_set():
    """Feed → feed + the six feed* config params; incidentType is SKIPPED."""
    added, _ = compute_be_synthesized_params(
        _script_for("feed"), fetch_flags=_flags("feed")
    )
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
    added, _ = compute_be_synthesized_params(
        _script_for("isFetchEvents"), fetch_flags=_flags("isFetchEvents")
    )
    assert set(added) == {"isFetchEvents", "eventFetchInterval"}
    assert "incidentType" not in added


def test_isfetchassets_adds_isfetchassets_and_interval():
    """IsFetchAssets → isFetchAssets, assetsFetchInterval."""
    added, stripped = compute_be_synthesized_params(
        _script_for("isFetchAssets"), fetch_flags=_flags("isFetchAssets")
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
        {"longRunning": True, "isfetchevents": True},
        fetch_flags=_flags("isFetchEvents"),
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
        "incidentFetchInterval",
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
    """Interval fields receive the NON-DEFAULT valid-minutes dummy ("111").

    "0"/"1" are at/near the YML default and cannot prove the connector actually
    delivered the value, so the harness pushes the recognizable non-default
    ``"111"`` to the INTEGRATION side (string). The CONNECTOR side coerces this
    to int 111 — see test_connector_value_for_coerces_registry_field_to_int.
    """
    out = apply_be_config_transform(
        {}, _script_for("isFetch"), fetch_flags=_flags("isFetch")
    )
    assert out["incidentFetchInterval"] == "111"
    out_feed = apply_be_config_transform(
        {}, _script_for("feed"), fetch_flags=_flags("feed")
    )
    assert out_feed["feedFetchInterval"] == "111"
    assert out_feed["feedExpirationInterval"] == "111"


# ---------------------------------------------------------------------------
# YML-script gate (Lookout): a variant fetch flag is synthesized ONLY when the
# integration YML `script` also declares the matching mechanism. A capability can
# be satisfied by an integration that does NOT use that XSOAR fetch mechanism
# (e.g. a long-running log collector with NO `script.isfetchevents`), and for
# such an integration the synthesized fields must NOT be injected.
# ---------------------------------------------------------------------------
def test_log_collection_variant_no_isfetchevents_yml_does_not_synthesize():
    """Lookout shape: log-collection capability → isFetchEvents variant flag, but
    the YML declares only `script.longRunning` (NO isfetchevents). The gate is
    CLOSED → neither isFetchEvents nor eventFetchInterval is synthesized."""
    added, _ = compute_be_synthesized_params(
        {"longRunning": True}, fetch_flags=_flags("isFetchEvents")
    )
    assert "isFetchEvents" not in added
    assert "eventFetchInterval" not in added


def test_log_collection_variant_with_isfetchevents_yml_still_synthesizes():
    """CiscoAMP shape: log-collection capability + the YML DECLARES
    `script.isfetchevents: true`. The gate is OPEN → both fields are synthesized
    (round-4 behavior preserved)."""
    added, _ = compute_be_synthesized_params(
        {"isfetchevents": True}, fetch_flags=_flags("isFetchEvents")
    )
    assert "isFetchEvents" in added
    assert "eventFetchInterval" in added


def test_isfetch_variant_gated_on_yml_isfetch():
    """isFetch variant: synthesized only when the YML declares `script.isfetch`."""
    # gate CLOSED (no YML isfetch) → not synthesized.
    added_closed, _ = compute_be_synthesized_params({}, fetch_flags=_flags("isFetch"))
    assert "isFetch" not in added_closed
    assert "incidentFetchInterval" not in added_closed
    # gate OPEN (YML declares isfetch) → synthesized.
    added_open, _ = compute_be_synthesized_params(
        {"isfetch": True}, fetch_flags=_flags("isFetch")
    )
    assert "isFetch" in added_open
    assert "incidentFetchInterval" in added_open


def test_feed_variant_gated_on_yml_feed():
    """feed variant: synthesized only when the YML declares `script.feed`."""
    added_closed, _ = compute_be_synthesized_params({}, fetch_flags=_flags("feed"))
    assert "feed" not in added_closed
    assert "feedFetchInterval" not in added_closed
    added_open, _ = compute_be_synthesized_params(
        {"feed": True}, fetch_flags=_flags("feed")
    )
    assert "feed" in added_open
    assert "feedFetchInterval" in added_open


def test_assets_variant_gated_on_yml_isfetchassets():
    """isFetchAssets variant: synthesized only when YML declares
    `script.isfetchassets`."""
    added_closed, _ = compute_be_synthesized_params(
        {}, fetch_flags=_flags("isFetchAssets")
    )
    assert "isFetchAssets" not in added_closed
    assert "assetsFetchInterval" not in added_closed
    added_open, _ = compute_be_synthesized_params(
        {"isfetchassets": True}, fetch_flags=_flags("isFetchAssets")
    )
    assert "isFetchAssets" in added_open
    assert "assetsFetchInterval" in added_open


def test_isfetchcredentials_variant_not_gated_on_yml():
    """isFetchCredentials has NO YML script flag — it is capability-only and is
    NOT gated on the YML. The toggle is added whenever the variant flag is on."""
    added, _ = compute_be_synthesized_params(
        {}, fetch_flags=_flags("isFetchCredentials")
    )
    assert "isFetchCredentials" in added


# ---------------------------------------------------------------------------
# Connector-int / Integration-string field registry (parity type contract).
# ---------------------------------------------------------------------------
def test_registry_contains_known_interval_fields():
    """incidentFetchInterval (the known case) is registered, plus the other
    minutes intervals that share the same int/str contract."""
    assert is_connector_int_integration_string_field("incidentFetchInterval")
    assert "incidentFetchInterval" in CONNECTOR_INT_INTEGRATION_STRING_FIELDS
    for fld in (
        "eventFetchInterval",
        "assetsFetchInterval",
        "feedFetchInterval",
        "feedExpirationInterval",
    ):
        assert is_connector_int_integration_string_field(fld), fld


def test_registry_excludes_non_contract_fields():
    """The contract is SCOPED — generic string fields are NOT in the registry."""
    assert not is_connector_int_integration_string_field("isFetch")
    assert not is_connector_int_integration_string_field("url")
    assert not is_connector_int_integration_string_field("apikey")


def test_connector_value_for_coerces_registry_field_to_int():
    """A registry field's shared STRING dummy is coerced to INT for the connector."""
    assert connector_value_for("incidentFetchInterval", "111") == 111
    assert isinstance(connector_value_for("incidentFetchInterval", "111"), int)
    # already-int passes through unchanged
    assert connector_value_for("incidentFetchInterval", 111) == 111


def test_connector_value_for_leaves_non_registry_fields_untouched():
    """Non-registry fields keep their value/type exactly (no blanket coercion)."""
    assert connector_value_for("url", "111") == "111"
    assert connector_value_for("isFetch", True) is True
    # uncoercible value on a registry field is left alone rather than mangled
    assert connector_value_for("incidentFetchInterval", "not-a-number") == "not-a-number"


def test_values_match_int_vs_str_for_registry_field():
    """connector int 111 == integration str "111" for a registry field."""
    assert values_match("incidentFetchInterval", "111", 111)
    assert values_match("incidentFetchInterval", "111", "111")


def test_values_match_genuine_mismatch_still_fails():
    """A genuinely different value still fails (no false parity)."""
    assert not values_match("incidentFetchInterval", "222", 111)
    assert not values_match("incidentFetchInterval", "111", 222)


def test_values_match_non_registry_field_is_plain_equality():
    """Non-registry fields use plain == — int 111 != str "111"."""
    assert values_match("someNumberField", 111, 111)
    assert not values_match("someNumberField", "111", 111)


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
