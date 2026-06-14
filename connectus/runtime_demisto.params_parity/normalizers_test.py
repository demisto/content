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

from normalizers import HARD_IGNORE_PARAM_NAMES, normalize_for_diff

_YML = [
    {"name": "url", "type": 0},
    {"name": "client_key", "type": 4},      # encrypted (auth)
    {"name": "client_secret", "type": 4},   # encrypted (auth)
    {"name": "credentials", "type": 9},     # credentials (auth)
    {"name": "max_fetch", "type": 0},
]


def test_baseline_keeps_all_non_ignored_including_auth():
    """NEW behavior: type-4/9 auth params are compared by default (no type drop)."""
    raw = {"url": "x", "client_key": "k", "credentials": {"u": "a"}, "max_fetch": 50}
    kept, dropped = normalize_for_diff(raw, _YML, side="t")
    assert kept == {
        "url": "x",
        "client_key": "k",
        "credentials": {"u": "a"},
        "max_fetch": 50,
    }
    assert dropped == []


def test_type4_9_compared_by_default():
    """type-4/9 params are compared by default; only force_drop/name-ignore removes them."""
    yml = [{"name": "client_key", "type": 4}, {"name": "credentials", "type": 9}]
    raw = {"client_key": "x", "credentials": {"identifier": "u"}}
    kept, dropped = normalize_for_diff(raw, yml, side="t")
    assert "client_key" in kept
    assert "credentials" in kept
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
