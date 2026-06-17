"""Replicate the backend ValidateConfiguration auto-add/strip of fetch/feed/
long-running config params.

XSOAR's backend (ValidateConfiguration) injects extra CONFIG params into an
integration instance based on the integration's SCRIPT-level feature flags
(isfetch / feed / isfetchevents / isfetchassets / longRunning / longRunningPort),
and strips a set of fetch-only params when no fetch flag is enabled. These
params are NOT declared in the YML `configuration` list, so the param-parity
harness must replicate the same transform on the integration side to match what
the connector (and the live backend) actually expose.
"""
from __future__ import annotations

import logging

log = logging.getLogger(__name__)

# script.<flag> -> config param names the BE auto-adds.
# incidentType is special-cased (skipped when feed or isfetchevents is also on).
_ISFETCH_FIELDS = ["incidentFetchInterval", "incidentType"]
_FEED_FIELDS = [
    "feedReputation",
    "feedReliability",
    "feedExpirationPolicy",
    "feedExpirationInterval",
    "feedFetchInterval",
    "feedBypassExclusionList",
]
_ISFETCHEVENTS_FIELDS = ["eventFetchInterval"]
_ISFETCHASSETS_FIELDS = ["assetsFetchInterval"]
_LONGRUNNING_FIELDS = ["longRunning"]
_LONGRUNNINGPORT_FIELDS = ["longRunningPort"]

# Params the BE STRIPS when NO fetch flag is enabled.
_STRIP_WHEN_NO_FETCH = [
    "isFetch",
    "isFetchEvents",
    "incidentFetchInterval",
    "eventFetchInterval",
    "incidentType",
    "longRunning",
    "longRunningPort",
]

# Interval/duration BE-synthesized fields. The XSOAR backend coerces these to an
# integer number of minutes (an invalid string collapses to the default "1"),
# and the connector serializes a duration with output_format: minutes. A generic
# string dummy can therefore never match across both sides — push a valid minutes
# value to both instead.
_INTERVAL_FIELDS = frozenset(
    {
        "incidentFetchInterval",
        "eventFetchInterval",
        "assetsFetchInterval",
        "feedFetchInterval",
        "feedExpirationInterval",
    }
)
_INTERVAL_DUMMY = "1"  # valid minutes count; matches both sides' default_value


def default_dummy_for(name: str) -> str:
    """Return the dummy value the harness should push for a BE-synthesized field.

    Interval/duration fields require a valid minutes value (the backend coerces
    invalid strings to the default), so they get :data:`_INTERVAL_DUMMY`. All
    other synthesized fields take the generic ``dummy_config_<name>`` string.
    """
    if name in _INTERVAL_FIELDS:
        return _INTERVAL_DUMMY
    return f"dummy_config_{name}"


def _flag_is_true(script: dict, *keys: str) -> bool:
    """Return True if any of the given keys in `script` is truthy.

    Tolerant of casing and of boolean-vs-string 'true'.
    """
    for key in keys:
        if key in script:
            val = script[key]
            if val is True:
                return True
            if isinstance(val, str) and val.strip().lower() == "true":
                return True
    return False


def compute_be_synthesized_params(script: dict | None) -> tuple[list[str], list[str]]:
    """Compute the (added, stripped) config-param-name lists for a YML script block.

    Args:
        script: The integration YML's `script` dict (may be None/empty).

    Returns:
        (added, stripped) — `added` is the list of config param names the BE
        auto-injects; `stripped` is the list of param names the BE removes when
        no fetch flag is on. The two lists are disjoint.
    """
    script = script or {}

    is_fetch = _flag_is_true(script, "isfetch", "isFetch")
    is_feed = _flag_is_true(script, "feed", "Feed")
    is_fetch_events = _flag_is_true(script, "isfetchevents", "isFetchEvents", "isfetchEvents")
    is_fetch_assets = _flag_is_true(script, "isfetchassets", "isFetchAssets", "isfetchAssets")
    is_long_running = _flag_is_true(script, "longRunning", "longrunning", "islongrunning", "isLongRunning")
    is_long_running_port = _flag_is_true(
        script, "longRunningPort", "longrunningport", "longRunningport"
    )

    any_fetch = is_fetch or is_feed or is_fetch_events or is_fetch_assets

    added: list[str] = []
    if is_fetch:
        added.append("incidentFetchInterval")
        # incidentType is skipped when feed or isfetchevents is also on.
        if not (is_feed or is_fetch_events):
            added.append("incidentType")
    if is_feed:
        added.extend(_FEED_FIELDS)
    if is_fetch_events:
        added.extend(_ISFETCHEVENTS_FIELDS)
    if is_fetch_assets:
        added.extend(_ISFETCHASSETS_FIELDS)
    if is_long_running:
        added.extend(_LONGRUNNING_FIELDS)
    if is_long_running_port:
        added.extend(_LONGRUNNINGPORT_FIELDS)

    # De-dup while preserving order.
    seen: set[str] = set()
    added = [x for x in added if not (x in seen or seen.add(x))]

    stripped: list[str] = []
    if not any_fetch:
        stripped = list(_STRIP_WHEN_NO_FETCH)

    return added, stripped


def apply_be_config_transform(
    shared_dummies: dict,
    script: dict | None,
    dummy_value_factory=None,
) -> dict:
    """Return a copy of `shared_dummies` with BE auto-added params injected and
    BE-stripped params removed, based on the YML `script` flags.

    Args:
        shared_dummies: The pre-computed name->dummy-value dict (keyed by xsoar
            param id) that the harness pushes to BOTH parity sides.
        script: The integration YML's `script` dict.
        dummy_value_factory: Optional callable(name)->value used to produce a
            dummy value for a synthesized field. Defaults to
            ``f"dummy_config_{name}"`` to match the harness's existing
            generic-string dummy convention.

    Returns:
        A new dict (the input is not mutated).
    """
    if dummy_value_factory is None:
        dummy_value_factory = default_dummy_for

    result = dict(shared_dummies)
    added, stripped = compute_be_synthesized_params(script)

    for name in added:
        if name not in result:
            result[name] = dummy_value_factory(name)

    for name in stripped:
        result.pop(name, None)

    if added or stripped:
        log.info(
            "BE config transform: added %d synthesized params %s; stripped %d %s",
            len(added), added, len(stripped), stripped,
        )
    return result
