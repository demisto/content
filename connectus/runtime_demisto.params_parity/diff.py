"""diff — symmetric 5-state diff engine for the param-parity test.

Compares two ``demisto.params()`` snapshots (already passed through
:func:`normalizers.normalize_for_diff`) and produces a JSON envelope shaped
after :file:`connectus/check_auth_parity.py`'s pattern. The envelope is the
final output the orchestrator emits and the operator reads.

Naming convention (used in the JSON envelope and throughout this module):

  * ``INTEGRATION`` — the legacy XSOAR-side capture (source-of-truth for
    what the integration's YML declares it needs at runtime).
  * ``CONNECTOR``   — the new UCP-side capture (what the connector actually
    delivers to the integration container).

Per-key states (symmetric — both MISSING and EXTRA fail the gate):

    OK                       — present in both, equal value
    MISSING_IN_CONNECTOR     — present in INTEGRATION only; the connector
                               forgot to declare a YML param the integration
                               needs at runtime
    EXTRA_IN_CONNECTOR       — present in CONNECTOR only; the connector
                               delivers a field the integration doesn't read
    VALUE_MISMATCH           — present in both but values differ (likely a
                               default-value drift or a serializer bug)
    EXTRA_IN_INTEGRATION     — present in INTEGRATION only AND not in YML
                               (e.g. XSOAR framework noise leaking through);
                               reported under ``dropped`` but NOT a failure

Each ``EXTRA_IN_CONNECTOR`` finding includes a ``reason_hint`` populated by
grepping the connector YAML directory for the field id. This makes the
report self-explanatory ("field X was delivered by the connector; X is
defined in <file>; fix by either adding X to the integration YML or adding
a serializer mapping or removing X from the connector").

Public entry point: :func:`diff_params`.
"""

from __future__ import annotations

import logging
import re
from pathlib import Path
from typing import Any

try:
    from ruamel.yaml import YAML
    _YAML = YAML(typ="safe")
except ImportError:  # pragma: no cover — ruamel.yaml is in requirements.txt
    _YAML = None

log = logging.getLogger("diff")


# ============================================================================
# Per-key states (string constants for stable JSON envelope keys).
# ============================================================================

STATE_OK = "OK"
STATE_OK_IGNORED = "OK_IGNORED"   # surfaces normalizer-dropped keys in per_param so the report is single-pane
STATE_MISSING_IN_CONNECTOR = "MISSING_IN_CONNECTOR"
STATE_EXTRA_IN_CONNECTOR = "EXTRA_IN_CONNECTOR"
STATE_VALUE_MISMATCH = "VALUE_MISMATCH"
STATE_EXTRA_IN_INTEGRATION = "EXTRA_IN_INTEGRATION"

#: States that fail the parity gate (status: "fail") unless explicitly allowed.
FAILING_STATES: set[str] = {
    STATE_MISSING_IN_CONNECTOR,
    STATE_EXTRA_IN_CONNECTOR,
    STATE_VALUE_MISMATCH,
}

#: Map state → orchestrator CLI flag that downgrades it from "fail" to "warn".
STATE_ALLOW_FLAG: dict[str, str] = {
    STATE_MISSING_IN_CONNECTOR: "allow_missing",
    STATE_EXTRA_IN_CONNECTOR: "allow_extra",
    STATE_VALUE_MISMATCH: "allow_mismatch",
}

#: Human-readable explanations for each ignore reason code, surfaced in the
#: OK_IGNORED per_param entries so triage is self-explanatory.
_IGNORE_REASON_DESCRIPTIONS: dict[str, str] = {
    "hidden": "hidden in the integration YML (hidden: true or hidden:<platform>), so it is not migrated to the connector and not compared",
    "credentials_type9_interpolated": "type-9 credentials param reconstructed by the integration at runtime from the connector's interpolated credentials.identifier/.password; the full vault object is not value-compared",
    "isfetch_not_emitted_by_connector": "KNOWN GAP (temporary): the connector does not currently emit the `isFetch` fetch flag at runtime, so it is dropped from both sides and ignored until connector support is added — tracked in the migration guide Open Items",
    "hard_ignore_list": "on the hard ignore-list (never appears comparably in runtime demisto.params(), e.g. brand/engine/instance_name/log-level)",
    "name_ignored": "a framework/mirroring/probe field that is not user-configurable (e.g. outgoingMapperId, apiproxy, the parity-probe key)",
    # legacy / safety fallbacks:
    "hard_ignore": "on the hard ignore-list (never appears comparably in runtime demisto.params())",
    "profile_not_interpolated": "an auth field of a non-interpolated profile (not delivered to runtime demisto.params())",
}


#: The only credentials sub-keys the param-parity check compares (the rest of the
#: XSOAR type-9 credentials vault wrapper is ignored — see normalizers.py and the
#: migration guide Open Items). Used to annotate the `credentials` OK entry so the
#: envelope shows the comparison was partial.
_CREDENTIALS_COMPARED_LEAVES = ("identifier", "password")


def _describe_ignore_reason(code: str) -> str:
    """Map a terse ignore reason code to a human-readable sentence (falls back to
    the raw code if unknown)."""
    return _IGNORE_REASON_DESCRIPTIONS.get(code, code)


def _annotate_credentials_partial_ignore(
    entry: dict[str, Any],
    integration_raw: dict[str, Any] | None,
    connector_raw: dict[str, Any] | None,
) -> list[str]:
    """Annotate the `credentials` OK entry to show the comparison was partial.

    The normalizer reduces a type-9 `credentials` param to identifier/password
    only before diffing, so the OK verdict covers ONLY those leaves. Surface the
    sub-keys that were dropped (present in the raw capture on either side but not
    among the compared leaves) so the envelope makes the partial comparison
    explicit. No-op when nothing beyond identifier/password was present.

    Returns the sorted list of ignored credentials sub-keys (empty list when
    nothing beyond identifier/password was present), while still mutating
    ``entry`` in place.
    """
    compared = set(_CREDENTIALS_COMPARED_LEAVES)
    ignored: set[str] = set()
    for raw in (integration_raw, connector_raw):
        val = (raw or {}).get("credentials")
        if isinstance(val, dict):
            ignored |= set(val.keys()) - compared
    if not ignored:
        return []
    entry["partially_ignored"] = True
    entry["compared_keys"] = list(_CREDENTIALS_COMPARED_LEAVES)
    entry["ignored_keys"] = sorted(ignored)
    entry["partial_ignore_note"] = (
        "credentials compared on identifier/password only; the rest of the "
        "XSOAR type-9 credentials object was ignored (see migration guide Open "
        "Items) — ignored sub-keys: " + ", ".join(sorted(ignored))
    )
    return sorted(ignored)


# ============================================================================
# Reason-hint resolver (grep the connector directory for EXTRA_IN_CONNECTOR fields)
# ============================================================================


def _scan_connector_for_field(
    connector_dir: Path,
    field_id: str,
) -> str | None:
    """Return a human-readable hint about where ``field_id`` is defined.

    Walks every ``.yaml`` / ``.yml`` file under ``connector_dir`` and reports
    the first file that declares the field. Heuristic — looks for both
    ``id: <field_id>`` and ``- <field_id>:`` patterns.

    Args:
        connector_dir: Path to the connector's YAML directory
            (e.g. ``connectus/runtime_demisto.params_parity/test_data/connectors/salesforce``).
        field_id: The field name to search for.

    Returns:
        A string like ``"from capabilities.yaml general_configurations"`` or
        ``"from configurations.yaml under capability automation-and-remediation"``,
        or ``None`` if the field isn't found anywhere in the connector dir.
    """
    if not connector_dir.exists() or not connector_dir.is_dir():
        return None

    # Be tolerant — match the field id in any of these YAML shapes:
    #   id: instance_name
    #   id: "instance_name"
    #   id: 'instance_name'
    #   - instance_name:
    #     instance_name:
    #     parameter: "instance_name"
    # The id-form uses an optional quote class around the value.
    escaped = re.escape(field_id)
    needles = [
        re.compile(r"\bid\s*:\s*[\"']?" + escaped + r"[\"']?\s*(?:#|$|\n)", re.MULTILINE),
        re.compile(r"^\s*-?\s*" + escaped + r"\s*:", re.MULTILINE),
        re.compile(r"\bparameter\s*:\s*[\"']?" + escaped + r"[\"']?", re.MULTILINE),
    ]

    for yaml_path in sorted(connector_dir.rglob("*.yaml")):
        try:
            text = yaml_path.read_text(encoding="utf-8", errors="replace")
        except Exception:
            continue
        if any(n.search(text) for n in needles):
            rel = yaml_path.name
            # Best-effort context attribution by filename.
            if rel == "connection.yaml":
                return "from connection.yaml (general_configurations or profile field)"
            if rel == "capabilities.yaml":
                return "from capabilities.yaml (general_configurations)"
            if rel == "configurations.yaml":
                # Try to identify which capability section the field is under.
                # Naive heuristic: find the nearest preceding `capability_id: ...` line.
                cap_match = None
                for m in re.finditer(r"capability_id\s*:\s*([\w\-]+)", text):
                    if m.start() < text.find(field_id):
                        cap_match = m.group(1)
                if cap_match:
                    return "from configurations.yaml under capability {}".format(cap_match)
                return "from configurations.yaml"
            if rel == "triggers.yaml":
                return "from triggers.yaml"
            if rel == "serializer.yaml":
                return "from serializer.yaml (field mapping)"
            return "from {}".format(rel)

    # Also scan .yml just in case.
    for yaml_path in sorted(connector_dir.rglob("*.yml")):
        try:
            text = yaml_path.read_text(encoding="utf-8", errors="replace")
        except Exception:
            continue
        if any(n.search(text) for n in needles):
            return "from {}".format(yaml_path.name)

    return None


def _load_serializer_mappings(connector_dir: Path) -> tuple[dict[str, str], dict[str, str]]:
    """Parse every ``serializer.yaml`` under ``connector_dir`` and return mapping indices.

    The connector serializer schema looks like::

        # components/handlers/<name>/serializer.yaml
        field_mappings:
          - id: "domain"           # connector field id (source — what UCP holds)
            field_name: "url"      # XSOAR param name (destination — what the integration sees)

    Returns:
        Tuple ``(by_xsoar_param, by_connector_field)`` where:

        * ``by_xsoar_param[<xsoar_name>] = <connector_field_id>``
          (used to annotate INTEGRATION-side entries with ``serialized_from``).

        * ``by_connector_field[<connector_field_id>] = <xsoar_name>``
          (used to annotate CONNECTOR-side entries with ``serialized_to``).

        Both maps are empty if no serializer.yaml files exist or YAML parsing fails.
    """
    by_xsoar: dict[str, str] = {}
    by_connector: dict[str, str] = {}

    if _YAML is None or not connector_dir.exists():
        return by_xsoar, by_connector

    for yaml_path in sorted(connector_dir.rglob("serializer.yaml")):
        try:
            with open(yaml_path) as f:
                doc = _YAML.load(f)
        except Exception as e:
            log.debug("Could not parse %s: %s", yaml_path, e)
            continue
        if not isinstance(doc, dict):
            continue
        for entry in (doc.get("field_mappings") or []):
            if not isinstance(entry, dict):
                continue
            connector_field = entry.get("id")
            xsoar_name = entry.get("field_name")
            if not connector_field or not xsoar_name:
                continue
            # If the same XSOAR param is fed by multiple connector fields across
            # different handlers, the LAST one wins. That's fine — the operator
            # will still see a serialized_from annotation either way.
            by_xsoar[xsoar_name] = connector_field
            by_connector[connector_field] = xsoar_name

    return by_xsoar, by_connector


# ============================================================================
# Public entry point
# ============================================================================


def diff_params(
    integration: dict[str, Any],
    connector: dict[str, Any],
    *,
    yml_param_names: set[str] | None = None,
    connector_dir: str | Path | None = None,
    integration_raw: dict[str, Any] | None = None,
    connector_raw: dict[str, Any] | None = None,
    integration_dropped: list[dict[str, str]] | None = None,
    connector_dropped: list[dict[str, str]] | None = None,
    allow_missing: bool = False,
    allow_extra: bool = False,
    allow_mismatch: bool = False,
) -> dict[str, Any]:
    """Diff two normalized ``demisto.params()`` dicts and return the JSON envelope.

    Args:
        integration: The INTEGRATION-side (XSOAR) normalized params (output
            of :func:`normalizers.normalize_for_diff`).
        connector: The CONNECTOR-side (UCP) normalized params (same).
        yml_param_names: Optional set of param names declared in the
            integration YML. Used to decide whether an INTEGRATION-only key
            is an ``EXTRA_IN_INTEGRATION`` (not in YML — XSOAR framework
            noise, dropped) or a ``MISSING_IN_CONNECTOR`` (in YML — real
            diff finding, the connector should be delivering it). When
            ``None``, every INTEGRATION-only key is treated as
            ``MISSING_IN_CONNECTOR``.
        connector_dir: Optional path to the connector's YAML directory.
            When provided, every ``EXTRA_IN_CONNECTOR`` finding is enriched
            with a ``reason_hint`` field naming the connector YAML file that
            declares the leaking field (see
            :func:`_scan_connector_for_field`).
        allow_missing: When ``True``, ``MISSING_IN_CONNECTOR`` findings stop
            contributing to the failure verdict (still reported as
            ``"warn"``).
        allow_extra: Same, for ``EXTRA_IN_CONNECTOR``.
        allow_mismatch: Same, for ``VALUE_MISMATCH``.

    Returns:
        A dict with the following shape (stable; suitable for ``json.dumps``)::

            {
                "status": "pass" | "fail",
                "summary": {
                    "n_total":                  int,  # union of (integration ∪ connector) keys
                    "n_ok":                     int,
                    "n_missing_in_connector":   int,
                    "n_extra_in_connector":     int,
                    "n_value_mismatch":         int,
                    "n_dropped":                int,  # EXTRA_IN_INTEGRATION count
                    "n_fail":                   int,  # total findings driving 'fail'
                    "n_warn":                   int,  # total findings downgraded by --allow-*
                },
                "per_param": [
                    {
                        "name":                str,
                        "state":               str,    # one of the STATE_* constants
                        "integration_value":   Any,    # absent for EXTRA_IN_CONNECTOR
                        "connector_value":     Any,    # absent for MISSING_IN_CONNECTOR / EXTRA_IN_INTEGRATION
                        "verdict":             "ok"|"fail"|"warn",
                        "reason_hint":         str,    # only for EXTRA_IN_CONNECTOR with connector_dir
                    },
                    ...
                ],
                "dropped": [
                    # EXTRA_IN_INTEGRATION entries (XSOAR framework noise — not failures)
                    {"name": str, "integration_value": Any, "reason": "extra_in_integration"},
                    ...
                ],
            }
    """
    yml_param_names = yml_param_names or set()
    connector_dir_path = Path(connector_dir) if connector_dir else None

    # Pre-load serializer mappings so we can annotate per-param entries with
    # `serialized_from` / `serialized_to`. Empty dicts if the connector has no
    # serializer.yaml files.
    by_xsoar_serialized, by_connector_serialized = (
        _load_serializer_mappings(connector_dir_path) if connector_dir_path else ({}, {})
    )

    union_keys = set(integration.keys()) | set(connector.keys())
    per_param: list[dict[str, Any]] = []
    credentials_ignored_keys: list[str] = []
    dropped: list[dict[str, Any]] = []

    # Per-state allowed map (mirrors STATE_ALLOW_FLAG resolved against the CLI flags).
    allow = {
        STATE_MISSING_IN_CONNECTOR: allow_missing,
        STATE_EXTRA_IN_CONNECTOR: allow_extra,
        STATE_VALUE_MISMATCH: allow_mismatch,
    }

    n_ok = n_missing = n_extra = n_mismatch = n_dropped = 0
    n_fail = n_warn = 0

    def _annotate_serializer(entry: dict[str, Any], key: str) -> None:
        """Attach serializer-mapping annotations to a per_param entry, if any.

        Three possible annotations (any combination):

          * ``serialized_from`` — present when ``key`` is the XSOAR-side
            destination of a serializer mapping (e.g. ``url`` is fed by
            connector field ``domain``). Tells the operator: "the integration
            sees this value AFTER the serializer remapped it from
            <connector_field>".

          * ``serialized_to`` — present when ``key`` is the connector-side
            source of a serializer mapping (e.g. ``domain`` is mapped to
            XSOAR param ``url``). Tells the operator: "this connector field
            is renamed to <xsoar_param> on the integration side, so
            EXTRA_IN_CONNECTOR / MISSING here is EXPECTED".

          * Neither — the key is not involved in any serializer mapping.
        """
        if key in by_xsoar_serialized:
            entry["serialized_from"] = by_xsoar_serialized[key]
        if key in by_connector_serialized:
            entry["serialized_to"] = by_connector_serialized[key]

    for key in sorted(union_keys):
        in_integration = key in integration
        in_connector = key in connector
        in_yml = key in yml_param_names

        if in_integration and in_connector:
            if integration[key] == connector[key]:
                state = STATE_OK
                n_ok += 1
                entry: dict[str, Any] = {
                    "name": key,
                    "state": state,
                    "integration_value": integration[key],
                    "connector_value": connector[key],
                    "verdict": "ok",
                }
                if key == "credentials":
                    credentials_ignored_keys = _annotate_credentials_partial_ignore(
                        entry, integration_raw, connector_raw
                    )
            else:
                state = STATE_VALUE_MISMATCH
                n_mismatch += 1
                verdict = "warn" if allow[state] else "fail"
                if verdict == "fail":
                    n_fail += 1
                else:
                    n_warn += 1
                entry = {
                    "name": key,
                    "state": state,
                    "integration_value": integration[key],
                    "connector_value": connector[key],
                    "verdict": verdict,
                }
            _annotate_serializer(entry, key)
            per_param.append(entry)

        elif in_integration and not in_connector:
            # INTEGRATION side has it; CONNECTOR side doesn't.
            # Decision: is it a real param the integration reads (in YML) →
            # MISSING_IN_CONNECTOR (failure); or just framework noise (NOT in
            # YML) → EXTRA_IN_INTEGRATION (dropped, no failure)?
            if in_yml:
                state = STATE_MISSING_IN_CONNECTOR
                n_missing += 1
                verdict = "warn" if allow[state] else "fail"
                if verdict == "fail":
                    n_fail += 1
                else:
                    n_warn += 1
                entry = {
                    "name": key,
                    "state": state,
                    "integration_value": integration[key],
                    "verdict": verdict,
                }
                _annotate_serializer(entry, key)
                per_param.append(entry)
            else:
                n_dropped += 1
                dropped.append({
                    "name": key,
                    "integration_value": integration[key],
                    "reason": "extra_in_integration",
                })

        else:  # in_connector and not in_integration
            state = STATE_EXTRA_IN_CONNECTOR
            n_extra += 1
            verdict = "warn" if allow[state] else "fail"
            if verdict == "fail":
                n_fail += 1
            else:
                n_warn += 1
            entry = {
                "name": key,
                "state": state,
                "connector_value": connector[key],
                "verdict": verdict,
            }
            if connector_dir_path is not None:
                hint = _scan_connector_for_field(connector_dir_path, key)
                if hint:
                    entry["reason_hint"] = hint
                else:
                    entry["reason_hint"] = "no_connector_file_reference_found"
            _annotate_serializer(entry, key)
            per_param.append(entry)

    # ── Surface IGNORED keys as OK_IGNORED entries in per_param ──
    # The normalizer drops some keys (credentials, encrypted, mirror_out, magic key,
    # framework noise) BEFORE the diff sees them. Users want those keys visible in
    # the single per_param view (not buried in a side log) so they can see the
    # full picture at a glance. Emit them as OK_IGNORED with a `reason` field
    # explaining WHY they were dropped. These never contribute to fail/warn counts.
    n_ok_ignored = 0
    integration_dropped = integration_dropped or []
    connector_dropped = connector_dropped or []

    # Index drops by name on each side so we can merge them. A key dropped on
    # BOTH sides (e.g. mapper_out is dropped on both because of name_ignored)
    # produces a single per_param entry. A key dropped on only one side has
    # half the integration/connector value fields filled in.
    drops_by_name: dict[str, dict[str, Any]] = {}
    for drop in integration_dropped:
        name = drop["name"]
        drops_by_name.setdefault(name, {})["integration_reason"] = drop["reason"]
        if integration_raw is not None and name in integration_raw:
            drops_by_name[name]["integration_value"] = integration_raw[name]
    for drop in connector_dropped:
        name = drop["name"]
        drops_by_name.setdefault(name, {})["connector_reason"] = drop["reason"]
        if connector_raw is not None and name in connector_raw:
            drops_by_name[name]["connector_value"] = connector_raw[name]

    for name in sorted(drops_by_name.keys()):
        info = drops_by_name[name]
        # Prefer the unified reason if both sides agree; otherwise show both.
        i_reason = info.get("integration_reason")
        c_reason = info.get("connector_reason")
        if i_reason and c_reason and i_reason == c_reason:
            reason = "Ignored — {}".format(_describe_ignore_reason(i_reason))
        elif i_reason and c_reason:
            reason = "Ignored — integration: {}; connector: {}".format(
                _describe_ignore_reason(i_reason), _describe_ignore_reason(c_reason)
            )
        elif i_reason:
            reason = "Ignored — {} (integration side)".format(
                _describe_ignore_reason(i_reason)
            )
        else:
            reason = "Ignored — {} (connector side)".format(
                _describe_ignore_reason(c_reason)
            )

        entry = {
            "name": name,
            "state": STATE_OK_IGNORED,
            "verdict": "ok",
            "reason": reason,
        }
        if "integration_value" in info:
            entry["integration_value"] = info["integration_value"]
        if "connector_value" in info:
            entry["connector_value"] = info["connector_value"]
        _annotate_serializer(entry, name)
        per_param.append(entry)
        n_ok_ignored += 1

    # Dedicated COMBINED OK_IGNORED entry summarizing the credentials sub-keys
    # that were dropped from the comparison (credentials is compared on
    # identifier/password only — see _annotate_credentials_partial_ignore and the
    # migration guide Open Items). Emitted only when something was actually
    # ignored; never contributes to fail/warn.
    if credentials_ignored_keys:
        per_param.append(
            {
                "name": "credentials (ignored sub-keys)",
                "state": STATE_OK_IGNORED,
                "verdict": "ok",
                "ignored_keys": credentials_ignored_keys,
                "reason": (
                    "Ignored — credentials sub-keys not compared (compared on "
                    "identifier/password only; the rest of the XSOAR type-9 "
                    "credentials object is ignored — see migration guide Open "
                    "Items): " + ", ".join(credentials_ignored_keys)
                ),
            }
        )
        n_ok_ignored += 1

    status = "pass" if n_fail == 0 else "fail"

    return {
        "status": status,
        "summary": {
            "n_total": len(union_keys) + n_ok_ignored,
            "n_ok": n_ok,
            "n_ok_ignored": n_ok_ignored,
            "n_missing_in_connector": n_missing,
            "n_extra_in_connector": n_extra,
            "n_value_mismatch": n_mismatch,
            "n_dropped": n_dropped,
            "n_fail": n_fail,
            "n_warn": n_warn,
        },
        "per_param": per_param,
        "dropped": dropped,
    }


__all__ = [
    "FAILING_STATES",
    "STATE_ALLOW_FLAG",
    "STATE_EXTRA_IN_CONNECTOR",
    "STATE_EXTRA_IN_INTEGRATION",
    "STATE_MISSING_IN_CONNECTOR",
    "STATE_OK_IGNORED",
    "STATE_OK",
    "STATE_VALUE_MISMATCH",
    "diff_params",
]
