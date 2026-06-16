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
#
# These mirror the XSOAR backend (ValidateConfiguration) auto-add spec exactly:
#
#   IsFetch:        isFetch, incidentFetchInterval, incidentType*
#   Feed:           feed, feedReputation, feedReliability, feedExpirationPolicy,
#                   feedExpirationInterval, feedFetchInterval,
#                   feedBypassExclusionList
#   IsFetchEvents:  isFetchEvents, eventFetchInterval
#   IsFetchAssets:  isFetchAssets, assetsFetchInterval
#   LongRunning:    longRunning, incidentType* (XSIAM also injects alertType, but
#                   the connector does NOT carry it — see Category 3 — so we never
#                   auto-add alertType here)
#   LongRunningPort: longRunningPort
#   IsFetchCredentials: isFetchCredentials
#
# * incidentType is appended inline in compute_be_synthesized_params because it is
#   special-cased: added when EITHER IsFetch OR LongRunning is active, but ONLY
#   when neither Feed nor IsFetchEvents is active.
_ISFETCH_FIELDS = ["isFetch", "incidentFetchInterval"]
_FEED_FIELDS = [
    "feed",
    "feedReputation",
    "feedReliability",
    "feedExpirationPolicy",
    "feedExpirationInterval",
    "feedFetchInterval",
    "feedBypassExclusionList",
]
_ISFETCHEVENTS_FIELDS = ["isFetchEvents", "eventFetchInterval"]
_ISFETCHASSETS_FIELDS = ["isFetchAssets", "assetsFetchInterval"]
_LONGRUNNING_FIELDS = ["longRunning"]
_LONGRUNNINGPORT_FIELDS = ["longRunningPort"]
_ISFETCHCREDENTIALS_FIELDS = ["isFetchCredentials"]

# Params the BE STRIPS when NO fetch flag (IsFetch/LongRunning/Feed/IsFetchEvents/
# IsFetchAssets) is enabled.
_STRIP_WHEN_NO_FETCH = [
    "isFetch",
    "isFetchEvents",
    "incidentFetchInterval",
    "alertFetchInterval",
    "eventFetchInterval",
    "incidentType",
    "alertType",
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
        "alertFetchInterval",
        "eventFetchInterval",
        "assetsFetchInterval",
        "feedFetchInterval",
        "feedExpirationInterval",
    }
)
_INTERVAL_DUMMY = "1"  # valid minutes count; matches both sides' default_value

#: The COMPLETE set of XSOAR BE-synthesized CONFIG param NAMES — every param the
#: backend (ValidateConfiguration) can auto-add for a fetch/feed/long-running
#: integration. These are NOT declared in the integration YML ``configuration``
#: list, yet they DO appear in the integration's runtime ``demisto.params()``.
#:
#: The connector platform never synthesizes anything: a connector only emits the
#: params explicitly declared in its manifest. Therefore, when one of these
#: BE-synthesized params is present on the XSOAR side but ABSENT on the connector
#: side, that is a REAL parity failure (``MISSING_IN_CONNECTOR``) — the connector
#: author must declare an equivalent field. The diff engine consumes this set to
#: classify such an integration-only key as a real param (``in_yml``-equivalent)
#: rather than dropping it as ``extra_in_integration`` framework noise.
BE_SYNTHESIZED_PARAM_NAMES: frozenset[str] = frozenset(
    _ISFETCH_FIELDS
    + _FEED_FIELDS
    + _ISFETCHEVENTS_FIELDS
    + _ISFETCHASSETS_FIELDS
    + _LONGRUNNING_FIELDS
    + _LONGRUNNINGPORT_FIELDS
    + _ISFETCHCREDENTIALS_FIELDS
    + ["incidentType"]
)


def default_dummy_for(name: str) -> str:
    """Return the dummy value the harness should push for a BE-synthesized field.

    Interval/duration fields require a valid minutes value (the backend coerces
    invalid strings to the default), so they get :data:`_INTERVAL_DUMMY`. All
    other synthesized fields take the generic ``dummy_config_<name>`` string.
    """
    if name in _INTERVAL_FIELDS:
        return _INTERVAL_DUMMY
    return f"dummy_config_{name}"


#: The COMPLETE set of XSOAR instance-creation fetch toggle param NAMES. When the
#: param-parity test creates the INTEGRATION-side instance for a capability
#: VARIANT it sets ALL of these explicitly: the variant's active toggle ``True``,
#: every other toggle ``False`` — so the instance models exactly one legal fetch
#: type (the platform forbids enabling two). ``isFetchSamples`` has no connector
#: capability mapping, so it is always ``False`` in the variant matrix; the rest
#: ARE the values of ``resolver.CAPABILITY_FETCH_FLAG`` (same naming → no map).
XSOAR_FETCH_TOGGLES: tuple[str, ...] = (
    "isFetch",
    "isFetchEvents",
    "isFetchAssets",
    "isFetchSamples",
    "isFetchCredentials",
    "feed",
)


def variant_toggle_overrides(fetch_flags: dict[str, bool] | None) -> dict[str, bool]:
    """Build the FULL XSOAR toggle override set for a variant's ``fetch_flags``.

    Returns a ``{xsoar_param_name: bool}`` dict covering EVERY toggle in
    :data:`XSOAR_FETCH_TOGGLES`: each toggle defaults ``False`` and is set ``True``
    iff the variant's ``fetch_flags`` mark it active. Because a variant's
    ``fetch_flags`` keys ARE the XSOAR toggle names
    (``resolver.CAPABILITY_FETCH_FLAG`` values), no translation is needed.

    The orchestrator merges this into the INTEGRATION-side overrides so the type-8
    fetch toggles are set EXACTLY as the variant requires (never the
    guaranteed-different dummy the generator would otherwise produce), guaranteeing
    the legacy instance models the same single legal fetch type the connector
    enabled.
    """
    out: dict[str, bool] = {name: False for name in XSOAR_FETCH_TOGGLES}
    for flag, active in (fetch_flags or {}).items():
        if flag in out and active:
            out[flag] = True
    return out


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


def compute_be_synthesized_params(
    script: dict | None,
    fetch_flags: dict[str, bool] | None = None,
) -> tuple[list[str], list[str]]:
    """Compute the (added, stripped) config-param-name lists for a YML script block.

    Args:
        script: The integration YML's `script` dict (may be None/empty). Used for
            ``longRunning``/``longRunningPort`` always, and for the fetch flags
            ONLY when ``fetch_flags`` is not supplied.
        fetch_flags: Optional variant-driven override of the FETCH flags (keyed by
            the resolver flag names — ``isfetch``/``isfetchevents``/
            ``isfetchassets``/``feed``/``isFetchCredentials``). When provided, the
            BE add/strip decision uses THESE booleans instead of the YML script's
            fetch flags, so the integration side models the exact capability
            variant under test. ``longRunning``/``longRunningPort`` are unaffected.

    Returns:
        (added, stripped) — `added` is the list of config param names the BE
        auto-injects; `stripped` is the list of param names the BE removes when
        no fetch flag is on. The two lists are disjoint.
    """
    script = script or {}

    if fetch_flags is not None:
        # Variant-driven: the fetch decision comes ENTIRELY from the variant.
        # Keys are the XSOAR toggle names (resolver.CAPABILITY_FETCH_FLAG values).
        is_fetch = bool(fetch_flags.get("isFetch", False))
        is_feed = bool(fetch_flags.get("feed", False))
        is_fetch_events = bool(fetch_flags.get("isFetchEvents", False))
        is_fetch_assets = bool(fetch_flags.get("isFetchAssets", False))
    else:
        is_fetch = _flag_is_true(script, "isfetch", "isFetch")
        is_feed = _flag_is_true(script, "feed", "Feed")
        is_fetch_events = _flag_is_true(script, "isfetchevents", "isFetchEvents", "isfetchEvents")
        is_fetch_assets = _flag_is_true(script, "isfetchassets", "isFetchAssets", "isfetchAssets")
    # fetch-credentials (fetch-secrets capability). The BE auto-adds the
    # `isFetchCredentials` toggle itself (see _ISFETCHCREDENTIALS_FIELDS) but no
    # other config params; it DOES count as a fetch, so the no-fetch strip set
    # must not apply when it is the variant under test.
    if fetch_flags is not None:
        is_fetch_credentials = bool(fetch_flags.get("isFetchCredentials", False))
    else:
        is_fetch_credentials = _flag_is_true(
            script, "isFetchCredentials", "isfetchcredentials"
        )
    is_long_running = _flag_is_true(script, "longRunning", "longrunning", "islongrunning", "isLongRunning")
    is_long_running_port = _flag_is_true(
        script, "longRunningPort", "longrunningport", "longRunningport"
    )

    # The BE strips the fetch-only params ONLY when NONE of IsFetch / LongRunning /
    # Feed / IsFetchEvents / IsFetchAssets is true (per the authoritative spec).
    # isFetchCredentials additionally counts as a fetch here so the strip set never
    # applies when it is the variant under test.
    any_fetch = (
        is_fetch
        or is_feed
        or is_fetch_events
        or is_fetch_assets
        or is_fetch_credentials
        or is_long_running
    )

    added: list[str] = []
    if is_fetch:
        added.extend(_ISFETCH_FIELDS)
    if is_feed:
        added.extend(_FEED_FIELDS)
    if is_fetch_events:
        added.extend(_ISFETCHEVENTS_FIELDS)
    if is_fetch_assets:
        added.extend(_ISFETCHASSETS_FIELDS)
    if is_fetch_credentials:
        added.extend(_ISFETCHCREDENTIALS_FIELDS)
    if is_long_running:
        added.extend(_LONGRUNNING_FIELDS)
    if is_long_running_port:
        added.extend(_LONGRUNNINGPORT_FIELDS)
    # incidentType is auto-added by EITHER IsFetch OR LongRunning (XSIAM also
    # injects alertType under LongRunning, but the connector never carries it —
    # see Category 3 — so alertType is intentionally NOT auto-added here). It is
    # SKIPPED when Feed or IsFetchEvents is also active.
    if (is_fetch or is_long_running) and not (is_feed or is_fetch_events):
        added.append("incidentType")

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
    fetch_flags: dict[str, bool] | None = None,
) -> dict:
    """Return a copy of `shared_dummies` with BE auto-added params injected and
    BE-stripped params removed.

    The fetch decision is driven by ``fetch_flags`` (the capability VARIANT under
    test) when supplied, otherwise by the integration YML's static `script` flags.
    ``longRunning``/``longRunningPort`` always come from `script`.

    Args:
        shared_dummies: The pre-computed name->dummy-value dict (keyed by xsoar
            param id) that the harness pushes to BOTH parity sides.
        script: The integration YML's `script` dict.
        dummy_value_factory: Optional callable(name)->value used to produce a
            dummy value for a synthesized field. Defaults to
            ``f"dummy_config_{name}"`` to match the harness's existing
            generic-string dummy convention.
        fetch_flags: Optional variant-driven fetch-flag override (see
            :func:`compute_be_synthesized_params`).

    Returns:
        A new dict (the input is not mutated).
    """
    if dummy_value_factory is None:
        dummy_value_factory = default_dummy_for

    result = dict(shared_dummies)
    added, stripped = compute_be_synthesized_params(script, fetch_flags=fetch_flags)

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
