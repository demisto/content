"""Unit tests for the connector-profile-aware IGNORE policy in normalizers.py.

Focus:
  * HARD_IGNORE_PARAM_NAMES are always dropped (even over force_keep).
  * force_drop drops extra caller-supplied keys.
  * Type-4 (encrypted) / type-9 (credentials) params are COMPARED by default —
    the blanket type-based drop is gone. Removal is governed by the resolver's
    force_drop / name-ignore lists, NOT by a hardcoded YML type list.
  * Baseline behavior (name ignore, keep verbatim) is unchanged.
"""
from __future__ import annotations

from normalizers import (
    HARD_IGNORE_PARAM_NAMES,
    KNOWN_GAP_IGNORE_REASONS,
    SERVER_BUG_IGNORE_REASONS,
    normalize_for_diff,
)

_YML = [
    {"name": "url", "type": 0},
    {"name": "client_key", "type": 4},      # encrypted (auth)
    {"name": "client_secret", "type": 4},   # encrypted (auth)
    {"name": "credentials", "type": 9},     # credentials (auth)
    {"name": "max_fetch", "type": 0},
]


def test_baseline_keeps_all_non_ignored_including_auth():
    """NEW behavior: type-4/9 auth params are compared by default (no type drop)."""
    raw = {
        "url": "x",
        "client_key": "k",
        "credentials": {
            "identifier": "user1",
            "password": "pw1",
            "credential": "",
            "passwordChanged": False,
        },
        "max_fetch": 50,
    }
    kept, dropped = normalize_for_diff(raw, _YML, side="t")
    assert kept == {
        "url": "x",
        "client_key": "k",
        "credentials": {"identifier": "user1", "password": "pw1"},
        "max_fetch": 50,
    }
    assert dropped == []


def test_type4_9_compared_by_default():
    """type-4/9 params are compared by default; only force_drop/name-ignore removes them."""
    yml = [{"name": "client_key", "type": 4}, {"name": "credentials", "type": 9}]
    raw = {"client_key": "x", "credentials": {"identifier": "u"}}
    kept, dropped = normalize_for_diff(raw, yml, side="t")
    assert "client_key" in kept
    assert kept["credentials"] == {"identifier": "u"}
    assert dropped == []


def test_hard_ignore_always_dropped():
    raw = {"url": "x", "brand": "X", "integrationLogLevel": "Debug"}
    kept, dropped = normalize_for_diff(raw, _YML, side="t")
    assert "brand" not in kept
    assert "integrationLogLevel" not in kept
    reasons = {d["name"]: d["reason"] for d in dropped}
    assert reasons["brand"] == "hard_ignore_list"
    assert reasons["integrationLogLevel"] == "hard_ignore_list"


def test_ucp_credentials_dropped_never_extra_in_connector():
    """The platform/UCP-injected encrypted auth container ``ucp_credentials``
    (appears ONLY on the connector side, declared in no connector YAML) must be
    dropped as a hard-ignore artifact so it is never flagged EXTRA_IN_CONNECTOR."""
    raw = {"url": "x", "ucp_credentials": "{ENCRYPTED}abc123=="}
    kept, dropped = normalize_for_diff(raw, _YML, side="connector")
    assert "ucp_credentials" not in kept
    reasons = {d["name"]: d["reason"] for d in dropped}
    assert reasons["ucp_credentials"] == "hard_ignore_list"


def test_force_drop_drops_extra_keys():
    raw = {"url": "x", "some_extra": "y"}
    kept, dropped = normalize_for_diff(raw, _YML, side="t", force_drop={"some_extra"})
    assert "some_extra" not in kept
    assert kept == {"url": "x"}


def test_force_drop_drops_type4_param():
    """A type-4 param is dropped ONLY when explicitly in force_drop."""
    raw = {"url": "x", "client_key": "k"}
    kept, dropped = normalize_for_diff(raw, _YML, side="t", force_drop={"client_key"})
    assert "client_key" not in kept
    assert kept == {"url": "x"}
    assert {d["name"] for d in dropped} == {"client_key"}


def test_type4_kept_without_force_keep():
    """The blanket type drop is gone: a type-4 param survives with NO force_keep."""
    raw = {"url": "x", "client_key": "k", "client_secret": "s"}
    kept, dropped = normalize_for_diff(raw, _YML, side="t")
    assert kept == {"url": "x", "client_key": "k", "client_secret": "s"}
    assert dropped == []


def test_type4_kept_with_force_keep():
    """force_keep is now a no-op for type params (still kept, still no drop)."""
    raw = {"url": "x", "client_key": "k", "client_secret": "s"}
    kept, dropped = normalize_for_diff(
        raw, _YML, side="t", force_keep={"client_key", "client_secret"}
    )
    assert kept == {"url": "x", "client_key": "k", "client_secret": "s"}
    assert dropped == []


def test_hard_ignore_beats_force_keep():
    """Even if a caller force-keeps a hard-ignored name, it is still dropped."""
    raw = {"brand": "X", "url": "x"}
    kept, dropped = normalize_for_diff(raw, _YML, side="t", force_keep={"brand"})
    assert "brand" not in kept
    assert kept == {"url": "x"}


def test_force_drop_reasons_preserves_specific_hidden_reason():
    """A force_drop key with a 'hidden' reason in force_drop_reasons is dropped
    with that SPECIFIC reason, not the generic fallback."""
    raw = {"url": "x", "foo": "y"}
    kept, dropped = normalize_for_diff(
        raw, _YML, side="t",
        force_drop={"foo"}, force_drop_reasons={"foo": "hidden"},
    )
    assert "foo" not in kept
    reasons = {d["name"]: d["reason"] for d in dropped}
    assert reasons["foo"] == "hidden"


def test_force_drop_reasons_preserves_credentials_type9_reason():
    raw = {"url": "x", "credentials": {"identifier": "u"}}
    kept, dropped = normalize_for_diff(
        raw, _YML, side="t",
        force_drop={"credentials"},
        force_drop_reasons={"credentials": "credentials_type9_interpolated"},
    )
    assert "credentials" not in kept
    reasons = {d["name"]: d["reason"] for d in dropped}
    assert reasons["credentials"] == "credentials_type9_interpolated"


def test_force_drop_without_reason_entry_falls_back_to_hard_ignore_list():
    """A force_drop / HARD_IGNORE_PARAM_NAMES key with NO entry in
    force_drop_reasons falls back to 'hard_ignore_list'."""
    raw = {"url": "x", "engine": "E", "foo": "y"}
    kept, dropped = normalize_for_diff(
        raw, _YML, side="t",
        force_drop={"foo"}, force_drop_reasons={},  # no entry for foo / engine
    )
    reasons = {d["name"]: d["reason"] for d in dropped}
    # 'engine' is a built-in HARD_IGNORE_PARAM_NAMES key; 'foo' is force_drop
    # with no specific reason — both fall back.
    assert reasons["engine"] == "hard_ignore_list"
    assert reasons["foo"] == "hard_ignore_list"


def test_force_drop_reasons_backward_compatible_default():
    """Callers that don't pass force_drop_reasons still work (fallback reason)."""
    raw = {"url": "x", "foo": "y"}
    kept, dropped = normalize_for_diff(
        raw, _YML, side="t", force_drop={"foo"},
    )
    reasons = {d["name"]: d["reason"] for d in dropped}
    assert reasons["foo"] == "hard_ignore_list"


def test_hard_ignore_list_membership():
    # Sanity: the documented hard-ignore names are present.
    for name in [
        "brand", "packID", "engine", "engineGroup", "mappingId",
        "incomingMapperId", "outgoingMapperId", "defaultIgnore", "integrationLogLevel",
        # connector-injected field that legitimately appears in demisto.params()
        # on the platform — must be dropped, never flagged EXTRA_IN_CONNECTOR.
        "instance_name",
        # platform/UCP-injected encrypted auth container — same treatment.
        "ucp_credentials",
    ]:
        assert name in HARD_IGNORE_PARAM_NAMES


def test_credentials_reduced_to_identifier_and_password_only():
    """TEMPORARY workaround: the type-9 `credentials` param is compared on only
    its identifier/password leaves; the full nested XSOAR vault wrapper that the
    integration side carries (credential, passwordChanged, nested `credentials`
    object, etc.) is dropped before the diff so it does not spuriously mismatch
    the connector's flat {identifier, password}."""
    raw = {
        "credentials": {
            "credential": "",
            "credentials": {
                "cacheVersn": 0, "id": "", "locked": False, "name": "",
                "password": "", "user": "", "version": 0,
            },
            "identifier": "alice",
            "password": "s3cret",
            "passwordChanged": False,
        },
    }
    kept, dropped = normalize_for_diff(raw, _YML, side="integration")
    assert kept == {"credentials": {"identifier": "alice", "password": "s3cret"}}
    assert dropped == []


def test_credentials_connector_side_flat_form_unchanged():
    """The connector side already emits the flat form; reduction is a no-op for it,
    so both sides converge to the same {identifier, password} shape -> OK in diff."""
    raw = {"credentials": {"identifier": "alice", "password": "s3cret"}}
    kept, _ = normalize_for_diff(raw, _YML, side="connector")
    assert kept == {"credentials": {"identifier": "alice", "password": "s3cret"}}


def test_credentials_non_dict_value_left_untouched():
    """Defensive: a non-dict credentials value is not reduced (left verbatim)."""
    raw = {"credentials": "not-a-dict"}
    kept, _ = normalize_for_diff(raw, _YML, side="t")
    assert kept == {"credentials": "not-a-dict"}


def test_isfetch_is_compared_not_ignored():
    """RESOLVED GAP: the connector now emits `isFetch` at runtime, so it must be
    KEPT and compared (NOT dropped as a known-gap ignore). Regression guard
    against re-adding `isFetch` to KNOWN_GAP_IGNORE_REASONS."""
    raw = {"url": "x", "isFetch": True}
    kept, dropped = normalize_for_diff(raw, _YML, side="integration")
    assert kept.get("isFetch") is True
    assert all(d["name"] != "isFetch" for d in dropped)


def test_isfetch_compared_on_connector_side_too():
    raw = {"url": "x", "isFetch": True}
    kept, dropped = normalize_for_diff(raw, _YML, side="connector")
    assert kept.get("isFetch") is True
    assert all(d["name"] != "isFetch" for d in dropped)


# ---------------------------------------------------------------------------
# Prefixed type-9 credentials (Akamai credentials_* with hiddenusername:true)
# ---------------------------------------------------------------------------
def test_prefixed_type9_credentials_reduced_to_password():
    """A PREFIXED type-9 field (e.g. Akamai's credentials_access_token) is detected
    by SHAPE — not by the literal name "credentials" — and reduced to {password}
    on BOTH sides. The integration side carries the full XSOAR vault skeleton with
    NO identifier (hiddenusername:true, per Change 3); the connector side already
    delivers a flat {password}. Both canonicalize to {password} → password-only
    parity → would diff OK (no spurious VALUE_MISMATCH)."""
    yml = [{"name": "credentials_access_token", "type": 9}]
    integration_raw = {
        "credentials_access_token": {
            "credential": "",
            "credentials": {"id": "", "user": "", "password": ""},
            "password": "s3cret",
            "passwordChanged": False,
        }
    }
    connector_raw = {"credentials_access_token": {"password": "s3cret"}}

    integration_kept, _ = normalize_for_diff(integration_raw, yml, side="integration")
    connector_kept, _ = normalize_for_diff(connector_raw, yml, side="connector")

    assert integration_kept == {"credentials_access_token": {"password": "s3cret"}}
    assert connector_kept == {"credentials_access_token": {"password": "s3cret"}}
    # Both sides equal → parity holds with no identifier injected.
    assert integration_kept == connector_kept


def test_type9_credentials_with_real_identifier_still_compared():
    """A NON-hiddenusername type-9 field that carries a REAL non-empty identifier
    RETAINS the identifier in the reduction — guarding against a false-OK. Two
    DIFFERING identifiers must produce two DIFFERENT reduced dicts so a genuine
    username mismatch still surfaces."""
    yml = [{"name": "credentials", "type": 9}]
    side_a = {
        "credentials": {
            "identifier": "alice",
            "password": "pw",
            "credential": "",
            "passwordChanged": False,
        }
    }
    side_b = {
        "credentials": {
            "identifier": "bob",  # DIFFERENT username
            "password": "pw",
            "credential": "",
            "passwordChanged": False,
        }
    }
    kept_a, _ = normalize_for_diff(side_a, yml, side="integration")
    kept_b, _ = normalize_for_diff(side_b, yml, side="connector")

    # identifier is RETAINED (non-empty) on both sides.
    assert kept_a == {"credentials": {"identifier": "alice", "password": "pw"}}
    assert kept_b == {"credentials": {"identifier": "bob", "password": "pw"}}
    # Differing identifiers → differing reduced dicts → NOT a false-OK.
    assert kept_a != kept_b


# ---------------------------------------------------------------------------
# Category 3 — alertType is a SERVER BUG (explicit named ignore)
# ---------------------------------------------------------------------------
def test_alerttype_is_explicitly_ignored_as_server_bug():
    """The XSOAR server wrongly injects `alertType` into the integration
    demisto.params(); the connector never carries it. It must be dropped with a
    dedicated server-bug reason (surfaced as OK_IGNORED, never EXTRA_IN_INTEGRATION
    / MISSING / fail)."""
    raw = {"url": "x", "alertType": "Some Alert Type"}
    kept, dropped = normalize_for_diff(raw, _YML, side="integration")
    assert "alertType" not in kept
    reasons = {d["name"]: d["reason"] for d in dropped}
    assert reasons["alertType"] == "server_injected_alerttype_xsoar_bug"


def test_alerttype_ignored_on_connector_side_too():
    """alertType is dropped on the connector side as well (defensive — the
    connector should never carry it, but if it ever did it is still ignored)."""
    raw = {"url": "x", "alertType": "Some Alert Type"}
    kept, dropped = normalize_for_diff(raw, _YML, side="connector")
    assert "alertType" not in kept
    reasons = {d["name"]: d["reason"] for d in dropped}
    assert reasons["alertType"] == "server_injected_alerttype_xsoar_bug"


def test_server_bug_ignore_reasons_membership():
    assert SERVER_BUG_IGNORE_REASONS["alertType"] == "server_injected_alerttype_xsoar_bug"


# ---------------------------------------------------------------------------
# Category 2 — connector-only framework fields (never EXTRA_IN_CONNECTOR)
# ---------------------------------------------------------------------------
_CONNECTOR_ONLY_FRAMEWORK_FIELDS = [
    "mappingId",
    "incomingMapperId",
    "outgoingMapperId",
    "engine",
    "engineGroup",
    "defaultIgnore",
    "integrationLogLevel",
]


def test_connector_only_framework_fields_all_hard_ignored():
    """All seven connector-only framework fields are covered by the connector-side
    ignore policy (HARD_IGNORE_PARAM_NAMES), so they can never surface as
    EXTRA_IN_CONNECTOR."""
    for name in _CONNECTOR_ONLY_FRAMEWORK_FIELDS:
        assert name in HARD_IGNORE_PARAM_NAMES, name


def test_connector_only_framework_fields_dropped_on_connector_side():
    """When a connector-only framework field appears ONLY on the connector side it
    is dropped (kept out of the MUST-COMPARE bucket) so the diff never flags it
    EXTRA_IN_CONNECTOR."""
    raw = {"url": "x"}
    for name in _CONNECTOR_ONLY_FRAMEWORK_FIELDS:
        raw[name] = "framework-value"
    kept, dropped = normalize_for_diff(raw, _YML, side="connector")
    for name in _CONNECTOR_ONLY_FRAMEWORK_FIELDS:
        assert name not in kept, name
    dropped_names = {d["name"] for d in dropped}
    for name in _CONNECTOR_ONLY_FRAMEWORK_FIELDS:
        assert name in dropped_names, name
