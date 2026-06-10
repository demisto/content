"""normalizers — deterministic IGNORE policy.

Given a raw ``demisto.params()`` dict and the integration's YML, this module
classifies every encountered key into one of:

  * **IGNORE**  — silently dropped from comparison (credentials, encrypted
    fields, mirroring params, framework noise, the probe protocol key).
  * **MUST-COMPARE** — kept verbatim (values are NOT normalized; the diff
    engine sees exact values for exact-parity comparison).

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

#: YML param type ids that are IGNORE'd outright. Source of truth: the
#: ``XSOAR Parameter Type to Manifest Type`` table in
#: ``connectus/connectus_migration/connectus_connector_migration_guide.md``
#: (Appendix A), filtered down to the types UCP CANNOT deliver via
#: ``demisto.params()``: credentials and encrypted-text fields.
IGNORED_YML_TYPES: set[int] = {
    4,  # encrypted text (consumer_key, consumer_secret, …)
    9,  # credentials (user/pass, mostly auth-related)
}

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
}


# ============================================================================
# YML parsing helper
# ============================================================================


def _build_yml_index(yml_configuration: list[dict]) -> dict[str, dict]:
    """Index the integration's YML configuration list by param ``name``.

    Args:
        yml_configuration: The ``configuration`` list from the integration YML.

    Returns:
        Dict mapping param name → the raw YML entry.
    """
    index: dict[str, dict] = {}
    for entry in yml_configuration or []:
        name = entry.get("name")
        if not name:
            continue
        index[name] = entry
    return index


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
) -> tuple[dict[str, Any], list[dict[str, str]]]:
    """Apply the IGNORE policy and return the filtered dict (NO value normalization).

    Args:
        raw_params: The raw ``demisto.params()`` dict captured by either
            :mod:`xsoar_capture` or :mod:`ucp_capture`. May be ``None``
            (treated as empty).
        yml_configuration: The integration YML's ``configuration`` list.
            Used to classify keys by type. Pass ``None`` to skip type-directed
            dropping (only the name-based IGNORE list applies).
        side: A label (``"xsoar"`` or ``"ucp"``) used purely in the dropped
            log entries so the orchestrator can attribute each drop.

    Returns:
        ``(filtered_dict, dropped_log)`` tuple.

        * ``filtered_dict`` — the MUST-COMPARE bucket. Values are returned
          **verbatim** — no bool-coercion, no int-coercion, no whitespace
          stripping. The diff engine will see exactly what the integration
          container saw.

        * ``dropped_log`` — list of ``{"name": k, "reason": <str>, "side":
          side}`` dicts, one per dropped key. The reason is one of:
          ``"yml_type_ignored:<type>"`` or ``"name_ignored"``.

    Notes:
        Connector-only keys (NOT in YML, e.g. the smoke-test surfaced
        ``instance_name`` leaking from the connector's
        ``capabilities.yaml`` general_configurations) are **retained** in
        the MUST-COMPARE bucket. The diff engine's key-union walk then
        flags them as ``EXTRA_IN_NEW`` since the YML-walk side won't have
        them.
    """
    raw_params = raw_params or {}
    yml_index = _build_yml_index(yml_configuration or [])
    force_keep = force_keep or set()
    force_drop = force_drop or set()

    filtered: dict[str, Any] = {}
    dropped: list[dict[str, str]] = []

    for key, value in raw_params.items():
        # Rule 0: HARD ignore-list (caller-supplied force_drop ∪ the built-in
        # HARD_IGNORE_PARAM_NAMES) — always wins, even over force_keep. These
        # never appear comparably in runtime demisto.params().
        if key in force_drop or key in HARD_IGNORE_PARAM_NAMES:
            dropped.append({"name": key, "reason": "hard_ignore", "side": side})
            continue

        # Rule 1: name-based ignore — always wins.
        if key in IGNORED_PARAM_NAMES:
            dropped.append({"name": key, "reason": "name_ignored", "side": side})
            continue

        # Rule 2: type-based ignore — only applies when the YML knows about this
        # key AND the caller did NOT force-keep it. force_keep carries the params
        # of an INTERPOLATED connector profile: those auth fields (YML type 4/9)
        # DO arrive in runtime demisto.params(), so they must be compared rather
        # than dropped.
        if key not in force_keep:
            yml_entry = yml_index.get(key)
            if yml_entry is not None:
                yml_type = yml_entry.get("type")
                if yml_type in IGNORED_YML_TYPES:
                    dropped.append({
                        "name": key,
                        "reason": "yml_type_ignored:{}".format(yml_type),
                        "side": side,
                    })
                    continue

        # Rule 3: keep this key verbatim (it's MUST-COMPARE).
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
    "IGNORED_YML_TYPES",
    "HARD_IGNORE_PARAM_NAMES",
    "normalize_for_diff",
]
