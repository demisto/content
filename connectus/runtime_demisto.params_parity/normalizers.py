"""normalizers — deterministic IGNORE policy.

Given a raw ``demisto.params()`` dict and the integration's YML, this module
classifies every encountered key into one of:

  * **IGNORE**  — silently dropped from comparison (mirroring params,
    framework noise, the probe protocol key, and the caller-supplied
    ``force_drop`` set / ``HARD_IGNORE_PARAM_NAMES``).
  * **MUST-COMPARE** — kept verbatim (values are NOT normalized; the diff
    engine sees exact values for exact-parity comparison).

Type-4 (encrypted text) and type-9 (credentials) params are **compared**, not
blanket-dropped: they DO arrive in runtime ``demisto.params()``. Whether a
given auth param is dropped is governed entirely by the resolver's
``force_drop`` decisions (hidden / hard-ignore / interpolated-type9-credentials,
derived from the connector connection profile's ``interpolation_mapping``) and
the name-ignore lists — NOT by a hardcoded YML type list.

**Strict exact-match policy:** no value normalization is applied. This means
any shape difference between the two sides surfaces as a real diff finding:

  * ``True`` (bool) vs ``"true"`` (string) → ``VALUE_MISMATCH``
  * ``50`` (int) vs ``"50"`` (str)         → ``VALUE_MISMATCH``
  * ``"  url"`` vs ``"url"``               → ``VALUE_MISMATCH``

This is intentional. The MVP wants maximum signal on UCP/connector bugs;
benign-looking shape drift may indicate a real serializer or default-value
bug worth investigating. A future iteration may add an opt-in
``--allow-shape-coerce`` flag if false positives become a problem.

Public entry point: :func:`normalize_for_diff`.
"""

from __future__ import annotations

import logging
from typing import Any

log = logging.getLogger("normalizers")


# ============================================================================
# IGNORE rules — kept as constants so the README + tests can reference them.
# ============================================================================

#: Param names that are IGNORE'd regardless of YML type. These cover:
#:
#:   * **Mirroring** — XSOAR-only concept, not supported on the Platform.
#:     Sources: ``mapper_out``, ``outgoingMapperId``, ``defaultMapperOut``
#:     (the three established names per the migration guide §3.2.1).
#:
#:   * **Probe protocol** — the magic key we inject to arm the probe must
#:     never leak into the diff.
#:
#:   * **Framework noise** — fields the XSOAR runtime appends to
#:     ``demisto.params()`` that aren't user-configurable in the YML
#:     (``apiproxy`` is the canonical example for SimpleAPIProxy-fronted
#:     integrations; others may be added as they're discovered in the wild).
IGNORED_PARAM_NAMES: set[str] = {
    # mirroring
    "mapper_out",
    "outgoingMapperId",
    "defaultMapperOut",
    # probe protocol
    "__params_parity_dump__",
    # framework noise
    "apiproxy",
}

#: HARD ignore-list — params that NEVER appear in a comparable way in runtime
#: ``demisto.params()``, even inside an interpolated profile. Mirrors
#: ``resolver.HARD_IGNORE_PARAMS`` (duplicated so the normalizer stays
#: import-light). USER-CONFIRMED 2026-06-07.
HARD_IGNORE_PARAM_NAMES: set[str] = {
    "brand",
    "packID",
    "engine",
    "engineGroup",
    "mappingId",
    "incomingMapperId",
    "outgoingMapperId",
    "defaultIgnore",
    "integrationLogLevel",
    # Connector-injected field (capabilities.yaml general_configurations) that
    # legitimately appears in demisto.params() on the platform; must be dropped,
    # never flagged EXTRA_IN_CONNECTOR.
    "instance_name",
    # Platform/UCP-injected ENCRYPTED auth container for an interpolated profile's
    # credentials (username/password packed into one blob at runtime). Not
    # declared in any connector YAML and not sent by the parity tool — it appears
    # ONLY on the connector side in demisto.params(); must be dropped, never
    # flagged EXTRA_IN_CONNECTOR. Mirrors resolver.HARD_IGNORE_PARAMS.
    "ucp_credentials",
}

#: KNOWN-GAP ignore (TEMPORARY): params that the connector does not yet emit at
#: runtime but that the integration side does. Until connector support lands,
#: these are dropped from BOTH sides and surfaced as OK_IGNORED (with the specific
#: reason below) rather than flagged MISSING_IN_CONNECTOR. Remove an entry here
#: once the connector emits it. See connectus_migration/connectus_connector_migration_guide.md
#: Section 6 "Open Items".
#:
#: ``isFetch`` was here while the connector did not emit it; that gap is now
#: RESOLVED — the connector emits ``isFetch`` at runtime, so it is compared
#: normally (no longer ignored). This dict is intentionally empty until a new
#: temporary gap appears.
KNOWN_GAP_IGNORE_REASONS: dict[str, str] = {}

#: SERVER-BUG ignore: params the XSOAR server wrongly injects into the integration
#: ``demisto.params()`` that the connector legitimately does NOT carry. These are
#: dropped (with the specific reason below) so the diff surfaces them as OK_IGNORED
#: (a documented server-bug pass) rather than EXTRA_IN_INTEGRATION/dropped noise or
#: a MISSING/fail. ``alertType`` is the canonical example: the XSOAR BE injects it
#: even when it shouldn't, and it is intentionally never auto-added to the
#: connector side (see be_config_params — Category 3).
SERVER_BUG_IGNORE_REASONS: dict[str, str] = {
    "alertType": "server_injected_alerttype_xsoar_bug",
}


# ============================================================================
# Type-9 credentials shape detection
# ============================================================================

#: The comparable leaves of an XSOAR type-9 credentials object. Everything else
#: in the vault skeleton (credential / passwordChanged / the nested `credentials`
#: object / id / version / …) is dropped before the diff — only the secret
#: material is value-compared. See ``_reduce_type9_credentials`` and diff.py.
_TYPE9_VAULT_MARKERS = frozenset(
    {"credential", "credentials", "passwordChanged", "identifier"}
)


def _is_type9_credentials(value: Any) -> bool:
    """Shape-based detector for an XSOAR type-9 credentials value.

    The OLD implementation only fired for a param literally named
    ``"credentials"``. Integrations with PREFIXED type-9 fields (Akamai's
    ``credentials_access_token`` / ``credentials_client_secret`` /
    ``credentials_client_token``, all ``type: 9`` with ``hiddenusername:
    true``) were therefore missed: the integration side kept the full XSOAR
    type-9 vault skeleton while the connector side delivered only
    ``{"password": ...}``, producing a spurious VALUE_MISMATCH on every
    credentials_* field.

    This predicate fires for ANY type-9 credentials value regardless of the
    param NAME, by recognizing its SHAPE: a dict that carries a ``password``
    leaf AND either (a) at least one vault-wrapper marker
    (``credential`` / nested ``credentials`` / ``passwordChanged`` /
    ``identifier``), or (b) is already the flat connector form whose keys are a
    subset of ``{"identifier", "password"}``. Case (b) ensures the connector's
    reduced ``{"password": ...}`` / ``{"identifier", "password"}`` is detected
    too, so BOTH sides canonicalize to the same shape.
    """
    if not isinstance(value, dict) or "password" not in value:
        return False
    if _TYPE9_VAULT_MARKERS & value.keys():
        return True
    return value.keys() <= {"identifier", "password"}


def _reduce_type9_credentials(value: dict) -> dict:
    """Reduce a type-9 credentials value to its comparable leaves.

    Always keeps ``password``. Keeps ``identifier`` ONLY when it is non-empty
    on this side — this is ``hiddenusername``-aware: for ``hiddenusername:
    true`` fields (e.g. Akamai) the connector legitimately has no username, and
    the harness (see xsoar_capture.generate_dummy_value_for_param) no longer
    injects a dummy identifier, so both sides reduce to ``{"password": ...}``.
    For NORMAL type-9 fields that DO carry a real username, the identifier is
    retained on both sides and a genuinely differing/missing username still
    surfaces as a mismatch (no false-OK).
    """
    reduced: dict[str, Any] = {"password": value.get("password", "")}
    ident = value.get("identifier")
    if ident:  # non-empty only; absent/"" for hiddenusername:true
        reduced["identifier"] = ident
    return reduced


# ============================================================================
# Public entry point
# ============================================================================


def normalize_for_diff(
    raw_params: dict | None,
    yml_configuration: list[dict] | None,
    *,
    side: str = "unknown",
    force_keep: set[str] | None = None,
    force_drop: set[str] | None = None,
    force_drop_reasons: dict[str, str] | None = None,
) -> tuple[dict[str, Any], list[dict[str, str]]]:
    """Apply the IGNORE policy and return the filtered dict (NO value normalization).

    Args:
        raw_params: The raw ``demisto.params()`` dict captured by either
            :mod:`xsoar_capture` or :mod:`ucp_capture`. May be ``None``
            (treated as empty).
        yml_configuration: The integration YML's ``configuration`` list.
            **Currently unused** — retained for API compatibility (callers pass
            it positionally). Type-based dropping was removed; type-4/9 params
            are now compared and removal is driven by ``force_drop`` /
            name-ignore lists instead.
        side: A label (``"xsoar"`` or ``"ucp"``) used purely in the dropped
            log entries so the orchestrator can attribute each drop.
        force_keep: Retained for API compatibility (see note below).
        force_drop: Caller-supplied set of param names to drop on this side
            (the resolver's hard-ignore decisions). See Rule 0.
        force_drop_reasons: Optional ``{name: reason}`` map carrying the
            SPECIFIC resolver reason for each ``force_drop`` key (one of
            ``"hidden"``, ``"credentials_type9_interpolated"``,
            ``"hard_ignore_list"``). When a force-dropped key has an entry
            here, that specific reason is recorded in the dropped log instead
            of the generic ``"hard_ignore_list"`` fallback. Optional →
            backward compatible: callers that omit it still work.

    Returns:
        ``(filtered_dict, dropped_log)`` tuple.

        * ``filtered_dict`` — the MUST-COMPARE bucket. Values are returned
          **verbatim** — no bool-coercion, no int-coercion, no whitespace
          stripping. The diff engine will see exactly what the integration
          container saw.

        * ``dropped_log`` — list of ``{"name": k, "reason": <str>, "side":
          side}`` dicts, one per dropped key. The reason is one of:
          ``"hidden"``, ``"credentials_type9_interpolated"``,
          ``"hard_ignore_list"`` (Rule 0, the specific resolver reason when
          carried in ``force_drop_reasons``; otherwise the
          ``"hard_ignore_list"`` fallback for built-in
          ``HARD_IGNORE_PARAM_NAMES``), or ``"name_ignored"`` (Rule 1).

    Notes:
        Connector-only keys (NOT in YML, e.g. the smoke-test surfaced
        ``instance_name`` leaking from the connector's
        ``capabilities.yaml`` general_configurations) are **retained** in
        the MUST-COMPARE bucket. The diff engine's key-union walk then
        flags them as ``EXTRA_IN_NEW`` since the YML-walk side won't have
        them.
    """
    raw_params = raw_params or {}
    # NOTE: force_keep is retained in the signature for API compatibility
    # (callers pass it), but the blanket type-4/9 drop it used to override is
    # gone, so it no longer affects classification here.
    force_drop = force_drop or set()

    filtered: dict[str, Any] = {}
    dropped: list[dict[str, str]] = []

    for key, value in raw_params.items():
        # Rule 0: HARD ignore-list (caller-supplied force_drop ∪ the built-in
        # HARD_IGNORE_PARAM_NAMES) — always wins. These never appear comparably
        # in runtime demisto.params().
        if key in force_drop or key in HARD_IGNORE_PARAM_NAMES:
            # Preserve the SPECIFIC resolver reason (hidden /
            # credentials_type9_interpolated / hard_ignore_list) so the report
            # can explain WHY, not just collapse to a generic code.
            reason = (force_drop_reasons or {}).get(key)
            if not reason:
                # Built-in HARD_IGNORE_PARAM_NAMES (engine, instance_name,
                # brand, …) that aren't carried in the resolver's
                # force_drop_reasons map fall back to the hard-ignore-list code.
                reason = "hard_ignore_list"
            dropped.append({"name": key, "reason": reason, "side": side})
            continue

        # Rule 1: name-based ignore — always wins.
        if key in IGNORED_PARAM_NAMES:
            dropped.append({"name": key, "reason": "name_ignored", "side": side})
            continue

        # Rule 1b: KNOWN-GAP ignore (TEMPORARY) — params the connector does not
        # yet emit (e.g. isFetch). Drop on both sides with a specific reason so
        # the diff engine surfaces them as OK_IGNORED ("ignored until supported")
        # instead of MISSING_IN_CONNECTOR. Remove once connector support lands.
        if key in KNOWN_GAP_IGNORE_REASONS:
            dropped.append(
                {"name": key, "reason": KNOWN_GAP_IGNORE_REASONS[key], "side": side}
            )
            continue

        # Rule 1c: SERVER-BUG ignore — params the XSOAR server wrongly injects
        # into the integration demisto.params() that the connector legitimately
        # does not carry (e.g. alertType). Drop with a specific reason so the diff
        # surfaces them as OK_IGNORED (a documented server-bug pass) rather than
        # EXTRA_IN_INTEGRATION noise or a MISSING/fail.
        if key in SERVER_BUG_IGNORE_REASONS:
            dropped.append(
                {"name": key, "reason": SERVER_BUG_IGNORE_REASONS[key], "side": side}
            )
            continue

        # Rule 2: keep this key verbatim (it's MUST-COMPARE). Type-4/9 auth
        # params land here too — they are compared, not blanket-dropped. The
        # resolver removes the ones that should not be compared via force_drop
        # (hidden / hard_ignore_list / credentials_type9_interpolated).
        #
        # TEMPORARY WORKAROUND (see connectus_migration/connectus_connector_migration_guide.md
        # Section 6 "Open Items"): a type-9 credentials param arrives on the
        # XSOAR side as a full nested vault wrapper (credential, passwordChanged,
        # a nested `credentials` object, …) but on the connector side as a flat
        # {password} (only the .password leaf is interpolated per the connector
        # profile). Until the credentials object is compared correctly
        # end-to-end, reduce BOTH sides to only the comparable secret leaves so
        # the wrapper shape drift does not produce a spurious VALUE_MISMATCH.
        #
        # NOTE: this is SHAPE-based, not name-based. The old guard keyed on the
        # literal name "credentials" and so MISSED prefixed type-9 fields such as
        # Akamai's credentials_access_token / credentials_client_secret /
        # credentials_client_token (all type 9, hiddenusername: true). The
        # shape detector subsumes the literal "credentials" case and also fires
        # for any credentials_* (or otherwise-named) type-9 value. The reduction
        # is hiddenusername-aware: identifier is kept only when non-empty, so a
        # hiddenusername:true field (no username on either side) compares on
        # password alone while a normal type-9 field still compares its username.
        if _is_type9_credentials(value):
            filtered[key] = _reduce_type9_credentials(value)
            continue

        filtered[key] = value

    log.debug(
        "[%s] normalize_for_diff: kept=%d dropped=%d (raw=%d)",
        side,
        len(filtered),
        len(dropped),
        len(raw_params),
    )
    return filtered, dropped


__all__ = [
    "IGNORED_PARAM_NAMES",
    "HARD_IGNORE_PARAM_NAMES",
    "KNOWN_GAP_IGNORE_REASONS",
    "SERVER_BUG_IGNORE_REASONS",
    "normalize_for_diff",
]
