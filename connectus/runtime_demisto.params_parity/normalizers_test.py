"""Unit tests for the connector-profile-aware IGNORE policy in normalizers.py.

Focus on the Phase 1 additions:
  * HARD_IGNORE_PARAM_NAMES are always dropped.
  * force_drop drops extra caller-supplied keys.
  * force_keep keeps an otherwise type-4/9-dropped auth param (interpolated profile).
  * Baseline behavior (name ignore, type 4/9 drop, keep verbatim) is unchanged.
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


def test_baseline_keeps_non_auth_drops_auth():
    raw = {"url": "x", "client_key": "k", "credentials": {"u": "a"}, "max_fetch": 50}
    kept, dropped = normalize_for_diff(raw, _YML, side="t")
    assert kept == {"url": "x", "max_fetch": 50}
    dropped_names = {d["name"] for d in dropped}
    assert dropped_names == {"client_key", "credentials"}


def test_hard_ignore_always_dropped():
    raw = {"url": "x", "brand": "X", "integrationLogLevel": "Debug"}
    kept, dropped = normalize_for_diff(raw, _YML, side="t")
    assert "brand" not in kept
    assert "integrationLogLevel" not in kept
    reasons = {d["name"]: d["reason"] for d in dropped}
    assert reasons["brand"] == "hard_ignore"
    assert reasons["integrationLogLevel"] == "hard_ignore"


def test_force_drop_drops_extra_keys():
    raw = {"url": "x", "some_extra": "y"}
    kept, dropped = normalize_for_diff(raw, _YML, side="t", force_drop={"some_extra"})
    assert "some_extra" not in kept
    assert kept == {"url": "x"}


def test_force_keep_overrides_type_drop():
    """An interpolated profile's auth params (force_keep) survive the type 4/9 drop."""
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


def test_hard_ignore_list_membership():
    # Sanity: the documented hard-ignore names are present.
    for name in [
        "brand", "packID", "engine", "engineGroup", "mappingId",
        "incomingMapperId", "outgoingMapperId", "defaultIgnore", "integrationLogLevel",
    ]:
        assert name in HARD_IGNORE_PARAM_NAMES
