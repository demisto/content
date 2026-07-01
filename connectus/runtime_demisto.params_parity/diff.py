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

from be_config_params import (
    BE_SYNTHESIZED_PARAM_NAMES,
    XSOAR_FETCH_TOGGLES,
    values_match,
)

try:
    from ruamel.yaml import YAML
    _YAML = YAML(typ="safe")
except ImportError:  # pragma: no cover — ruamel.yaml is in requirements.txt
    _YAML = None

log = logging.getLogger("diff")

#: Sentinel distinguishing "value field not supplied" from a real ``None`` value
#: when emitting an out-of-variant-scope OK_IGNORED entry (so we only attach the
#: integration/connector value field(s) that actually apply to the failing state).
_UNSET = object()


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

#: Prefix the resolver uses for a synthetic AUTH-PROFILE ownership unit
#: (``__profile__:<profile_id>``). When an out-of-variant-scope field's disabled
#: owners are ALL of this kind, the field is the auth secret of an alternative,
#: non-active XOR auth profile (see resolver._profile_ownership_unit). Kept in
#: sync with resolver._PROFILE_OWNERSHIP_PREFIX.
_PROFILE_OWNERSHIP_PREFIX = "__profile__:"

#: Human-readable explanations for each ignore reason code, surfaced in the
#: OK_IGNORED per_param entries so triage is self-explanatory.
_IGNORE_REASON_DESCRIPTIONS: dict[str, str] = {
    "hidden": "hidden in the integration YML (hidden: true or hidden:<platform>), so it is not migrated to the connector and not compared",
    "credentials_type9_interpolated": "type-9 credentials param reconstructed by the integration at runtime from the connector's interpolated credentials.identifier/.password; the full vault object is not value-compared",
    "isfetch_not_emitted_by_connector": "KNOWN GAP (temporary): the connector does not currently emit the `isFetch` fetch flag at runtime, so it is dropped from both sides and ignored until connector support is added — tracked in the migration guide Open Items",
    "server_injected_alerttype_xsoar_bug": "server-injected `alertType` (XSOAR BE bug) — not delivered by the connector, ignored",
    "hard_ignore_list": "on the hard ignore-list (never appears comparably in runtime demisto.params(), e.g. brand/engine/instance_name/log-level)",
    "name_ignored": "a framework/mirroring/probe field that is not user-configurable (e.g. outgoingMapperId, apiproxy, the parity-probe key)",
    "out_of_variant_scope": "field belongs to a sub-capability not enabled in this variant; not expected in the connector instance — not compared",
    "alternative_xor_auth_profile": "auth secret of an ALTERNATIVE (mutually-exclusive) auth profile that is NOT the one active in this connector instance; the runtime activates exactly one of the connector's XOR auth profiles, so this secret is absent BY DESIGN here and is verified in its own profile variant — not a MISSING_IN_CONNECTOR failure",
    # legacy / safety fallbacks:
    "hard_ignore": "on the hard ignore-list (never appears comparably in runtime demisto.params())",
    "profile_not_interpolated": "an auth field of a non-interpolated profile (not delivered to runtime demisto.params())",
}


#: The only credentials sub-keys the param-parity check compares (the rest of the
#: XSOAR type-9 credentials vault wrapper is ignored — see normalizers.py and the
#: migration guide Open Items). Used to annotate the `credentials` OK entry so the
#: envelope shows the comparison was partial.
_CREDENTIALS_COMPARED_LEAVES = ("identifier", "password")

#: Marker keys that identify an XSOAR type-9 credentials vault value by SHAPE
#: (mirrors normalizers._TYPE9_VAULT_MARKERS — kept as a local copy to avoid a
#: cross-module import, matching the codebase's preference for decoupled modules).
_TYPE9_VAULT_MARKERS = frozenset(
    {"credential", "credentials", "passwordChanged", "identifier"}
)


def _is_type9_credentials_param(name: str, value: Any) -> bool:
    """True if ``name``/``value`` is a type-9 credentials param.

    Recognized by NAME (the literal ``"credentials"`` or any ``credentials_*``
    prefixed field such as Akamai's ``credentials_access_token``) OR by SHAPE (a
    dict carrying ``password`` plus a vault marker, or the flat
    ``{identifier?, password}`` connector form). Name- and shape-based detection
    are OR'd so the partial-ignore annotation is emitted for ANY type-9
    credentials param, regardless of whether the connector reduced it to a flat
    ``{password}`` (which on its own would not carry a vault marker).
    """
    if name == "credentials" or name.startswith("credentials_"):
        return True
    if not isinstance(value, dict) or "password" not in value:
        return False
    if _TYPE9_VAULT_MARKERS & value.keys():
        return True
    return value.keys() <= {"identifier", "password"}


def _is_falsy_toggle_value(value: Any) -> bool:
    """True if ``value`` is the boolean-``False`` equivalent for a fetch toggle.

    A fetch toggle (``isFetch``/``isFetchEvents``/…) that is not present in
    ``demisto.params()`` is interpreted by the platform as ``False``. So an
    ABSENT toggle on one side is at parity with an explicit falsy toggle on the
    other side. This recognizes the falsy forms a toggle can take: real
    ``False``, the string ``"false"`` (any case), ``None``, or empty string.
    """
    if value is None:
        return True
    if isinstance(value, bool):
        return value is False
    if isinstance(value, str):
        return value.strip().lower() in ("", "false")
    return False


def _describe_ignore_reason(code: str) -> str:
    """Map a terse ignore reason code to a human-readable sentence (falls back to
    the raw code if unknown)."""
    return _IGNORE_REASON_DESCRIPTIONS.get(code, code)


def _annotate_credentials_partial_ignore(
    entry: dict[str, Any],
    integration_raw: dict[str, Any] | None,
    connector_raw: dict[str, Any] | None,
    name: str = "credentials",
) -> list[str]:
    """Annotate a type-9 credentials OK entry to show the comparison was partial.

    The normalizer reduces a type-9 credentials param to identifier/password
    only before diffing, so the OK verdict covers ONLY those leaves. Surface the
    sub-keys that were dropped (present in the raw capture on either side but not
    among the compared leaves) so the envelope makes the partial comparison
    explicit. No-op when nothing beyond identifier/password was present.

    ``name`` is the actual param key being annotated. It defaults to the literal
    ``"credentials"`` (so existing direct callers/tests are unaffected) but also
    supports PREFIXED type-9 fields such as Akamai's ``credentials_access_token``
    / ``credentials_client_secret`` / ``credentials_client_token`` — the raw
    skeleton is looked up under ``name`` rather than the hardcoded
    ``"credentials"``.

    Returns the sorted list of ignored credentials sub-keys (empty list when
    nothing beyond identifier/password was present), while still mutating
    ``entry`` in place.
    """
    compared = set(_CREDENTIALS_COMPARED_LEAVES)
    ignored: set[str] = set()
    for raw in (integration_raw, connector_raw):
        val = (raw or {}).get(name)
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
    in_scope_fields: set[str] | frozenset[str] | None = None,
    field_owning_subcapabilities: dict[str, frozenset[str]] | None = None,
    enabled_ownership_units: set[str] | frozenset[str] | None = None,
    serializer_by_xsoar: dict[str, str] | None = None,
    serializer_by_connector: dict[str, str] | None = None,
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
        in_scope_fields: Optional set of XSOAR-namespace field ids the CURRENT
            capability variant's enabled sub-capabilities legitimately expose.
            When provided (per-variant SCOPING is active), an integration-only
            field that is NOT in this set AND is owned by a sub-capability that
            exists but is disabled in this variant is reclassified from
            ``MISSING_IN_CONNECTOR`` to ``OK_IGNORED`` (``out_of_variant_scope``).
        field_owning_subcapabilities: Optional global map field id → set of
            owning ownership-unit ids (sub-capability id, or parent capability id
            when a capability declares no sub-capabilities), used together with
            ``enabled_ownership_units`` to detect out-of-variant-scope fields.
        enabled_ownership_units: Optional set of ownership-unit ids ENABLED in the
            current variant (the complement defines the disabled units).
        serializer_by_xsoar: Optional ``{xsoar_param_name: connector_field_id}``
            map scoped to THIS integration's handler (from the resolver). When
            provided, it is used for the ``serialized_from`` annotation INSTEAD of
            rglob-ing every handler's serializer.yaml under ``connector_dir`` —
            required for grouped connectors so a shared xsoar param name is not
            mis-attributed to a sibling handler's connector field id.
        serializer_by_connector: Optional ``{connector_field_id: xsoar_param_name}``
            map scoped to THIS integration's handler (from the resolver), used the
            same way for the ``serialized_to`` annotation. When EITHER scoped map
            is provided, the connector-wide rglob fallback is skipped entirely.
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

    # Per-variant field SCOPING (Bucket C). ``in_scope_fields`` is the set of
    # XSOAR-namespace param ids the CURRENT variant's enabled sub-capabilities
    # legitimately expose; ``field_owning_subcapabilities`` maps every owned field
    # id → the set of ownership units that own it (across ALL the connector's
    # sub-capabilities). An integration-only field that is NOT in scope AND is
    # owned by a unit that exists but is NOT enabled in this variant belongs to a
    # disabled sub-capability — so it is out-of-variant-scope (OK_IGNORED), NOT a
    # MISSING_IN_CONNECTOR failure. When these are absent (None), scoping is OFF
    # and behaviour is unchanged.
    scope_active = in_scope_fields is not None
    in_scope_fields = set(in_scope_fields or ())
    field_owning_subcapabilities = field_owning_subcapabilities or {}
    enabled_ownership_units = set(enabled_ownership_units or ())

    # Pre-load serializer mappings so we can annotate per-param entries with
    # `serialized_from` / `serialized_to`.
    #
    # SCOPING (grouped connectors): when the caller supplies the maps already
    # scoped to THIS integration's handler (``serializer_by_xsoar`` /
    # ``serializer_by_connector`` from the resolver, parsed from the single
    # handler dir), we use those verbatim. This is REQUIRED for grouped
    # connectors (e.g. ``aws``), where ``_load_serializer_mappings`` would
    # ``rglob`` EVERY handler's serializer.yaml and let the LAST-parsed mapping
    # for a shared xsoar param name win — falsely attributing, say,
    # ``incidentType`` on AWS-SNS-Listener to ``xsoar-aws-sqs_incidentType``
    # (a DIFFERENT handler's field). The annotation must reflect only the
    # handler under test. We fall back to the connector-wide rglob ONLY when no
    # scoped maps are provided (back-compat for callers/tests that pass just
    # ``connector_dir``).
    if serializer_by_xsoar is not None or serializer_by_connector is not None:
        by_xsoar_serialized = dict(serializer_by_xsoar or {})
        by_connector_serialized = dict(serializer_by_connector or {})
    elif connector_dir_path:
        by_xsoar_serialized, by_connector_serialized = _load_serializer_mappings(
            connector_dir_path
        )
    else:
        by_xsoar_serialized, by_connector_serialized = {}, {}

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
    n_out_of_scope = 0  # OK_IGNORED — out_of_variant_scope (folded into n_ok_ignored)

    def _out_of_variant_scope(key: str) -> frozenset[str] | None:
        """Return the DISABLED owning units of ``key`` when it is out-of-scope.

        ``key`` is out-of-variant-scope iff (1) per-variant scoping is active,
        (2) it is NOT in the variant's ``in_scope_fields``, and (3) it IS owned by
        at least one ownership unit that exists for this connector but is NOT
        enabled in the current variant. Returns the set of those DISABLED owning
        units (truthy) for annotation, or ``None`` when the key is in-scope, not
        owned by any sub-capability, or scoping is off. A field owned ONLY by
        ENABLED units (or by none) is never reclassified.
        """
        if not scope_active or key in in_scope_fields:
            return None
        owners = field_owning_subcapabilities.get(key)
        if not owners:
            return None
        disabled_owners = owners - enabled_ownership_units
        return disabled_owners or None

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

    def _try_scope_downgrade(
        key: str,
        *,
        integration_value: Any = _UNSET,
        connector_value: Any = _UNSET,
    ) -> bool:
        """Reclassify a TENTATIVELY-FAILING ``key`` to OK_IGNORED if out-of-scope.

        This is the SINGLE per-variant scoping gate shared by all three failing
        states (MISSING_IN_CONNECTOR / VALUE_MISMATCH / EXTRA_IN_CONNECTOR). It is
        invoked once the tentative failing verdict is known but BEFORE any fail/
        state counter is incremented. When ``key`` is owned SOLELY by
        sub-capabilities that are NOT enabled in this variant (see
        :func:`_out_of_variant_scope`), it emits an OK_IGNORED
        ``out_of_variant_scope`` entry (recording the value field(s) provided),
        bumps ``n_out_of_scope``, appends to ``per_param`` and returns ``True`` so
        the caller skips the failing path. A field that is in-scope, or owned by at
        least one ENABLED unit, returns ``False`` and keeps its real verdict — no
        coverage loss.
        """
        nonlocal n_out_of_scope
        disabled_owners = _out_of_variant_scope(key)
        if disabled_owners is None:
            return False
        # When EVERY disabled owner is a synthetic AUTH-PROFILE ownership unit
        # (prefixed ``__profile__:`` by the resolver), the key is the auth secret of
        # an alternative, non-active XOR profile — give it the clearer, dedicated
        # reason. Otherwise it is an ordinary sub-capability-scoped field.
        reason_code = (
            "alternative_xor_auth_profile"
            if disabled_owners
            and all(o.startswith(_PROFILE_OWNERSHIP_PREFIX) for o in disabled_owners)
            else "out_of_variant_scope"
        )
        entry: dict[str, Any] = {
            "name": key,
            "state": STATE_OK_IGNORED,
            "verdict": "ok",
            "reason": "Ignored — {}".format(_describe_ignore_reason(reason_code)),
            "out_of_scope_owners": sorted(disabled_owners),
        }
        if integration_value is not _UNSET:
            entry["integration_value"] = integration_value
        if connector_value is not _UNSET:
            entry["connector_value"] = connector_value
        _annotate_serializer(entry, key)
        per_param.append(entry)
        n_out_of_scope += 1
        return True

    for key in sorted(union_keys):
        in_integration = key in integration
        in_connector = key in connector
        # A key counts as a "real param the integration reads" when it is either
        # declared in the integration YML ``configuration`` OR is a known
        # XSOAR-BE-synthesized config param (isFetch/incidentFetchInterval/feed*/
        # eventFetchInterval/…). The BE auto-adds the latter at runtime — they are
        # NOT in the YML, but they ARE real params. The connector platform never
        # synthesizes anything, so a BE-synthesized param present on XSOAR but
        # absent on the connector is a genuine MISSING_IN_CONNECTOR failure (the
        # connector must declare an equivalent field), NOT framework noise.
        in_yml = key in yml_param_names or key in BE_SYNTHESIZED_PARAM_NAMES

        if in_integration and in_connector:
            # Equality is plain ``==`` EXCEPT for fields with the connector-int /
            # integration-string type contract (e.g. incidentFetchInterval), where
            # connector ``111`` and integration ``"111"`` are at parity. The
            # registry lives in be_config_params so the SAME contract that shapes
            # the creation payloads also governs the comparison.
            if values_match(key, integration[key], connector[key]):
                state = STATE_OK
                n_ok += 1
                entry: dict[str, Any] = {
                    "name": key,
                    "state": state,
                    "integration_value": integration[key],
                    "connector_value": connector[key],
                    "verdict": "ok",
                }
                # Annotate the OK entry for ANY type-9 credentials param —
                # the literal "credentials" OR a prefixed credentials_* field
                # (e.g. Akamai's credentials_access_token). Shape-based detection
                # also catches the connector's reduced {password}. Pass name=key
                # so the raw skeleton is looked up under the actual param key.
                if _is_type9_credentials_param(key, integration.get(key)):
                    credentials_ignored_keys = _annotate_credentials_partial_ignore(
                        entry, integration_raw, connector_raw, name=key
                    )
            else:
                # Per-variant SCOPING (Bucket C): a VALUE_MISMATCH on a field owned
                # SOLELY by sub-capabilities disabled in this variant is not a real
                # drift — the platform injected a manifest default for a field the
                # disabled sub-capability owns, while the integration sent its
                # override. Downgrade to OK_IGNORED out_of_variant_scope BEFORE
                # counting the mismatch as a failure (single shared scope gate).
                if _try_scope_downgrade(
                    key,
                    integration_value=integration[key],
                    connector_value=connector[key],
                ):
                    continue
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
            # A FETCH TOGGLE (isFetch/isFetchEvents/…) that is falsy on the
            # integration side and ABSENT on the connector side is at PARITY: an
            # absent toggle is interpreted as False by the platform, so
            # integration=False ↔ connector=<absent> means both are False. Emit
            # OK with a note rather than MISSING_IN_CONNECTOR.
            if key in XSOAR_FETCH_TOGGLES and _is_falsy_toggle_value(integration[key]):
                state = STATE_OK
                n_ok += 1
                entry = {
                    "name": key,
                    "state": state,
                    "integration_value": integration[key],
                    "verdict": "ok",
                    "reason": (
                        "fetch toggle absent on the connector side; an absent "
                        "toggle is treated as False, matching the integration's "
                        "falsy value — at parity"
                    ),
                }
                _annotate_serializer(entry, key)
                per_param.append(entry)
            # Otherwise: is it a real param the integration reads (in YML) →
            # MISSING_IN_CONNECTOR (failure); or just framework noise (NOT in
            # YML) → EXTRA_IN_INTEGRATION (dropped, no failure)?
            elif in_yml:
                # Per-variant SCOPING (Bucket C): before flagging a real YML param
                # as MISSING_IN_CONNECTOR, check whether it belongs to a
                # sub-capability that is NOT enabled in THIS variant. The connector
                # instance only exposes the fields of its enabled sub-capabilities,
                # so such a field is legitimately absent here — OK_IGNORED, not a
                # failure. A field that IS in scope but genuinely absent still falls
                # through to MISSING_IN_CONNECTOR (no loss of coverage).
                if _try_scope_downgrade(key, integration_value=integration[key]):
                    continue
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
            # Symmetric fetch-toggle parity: a falsy toggle on the CONNECTOR
            # side that is ABSENT on the integration side is also at parity (an
            # absent toggle is treated as False on both ends). Emit OK + note
            # instead of EXTRA_IN_CONNECTOR.
            if key in XSOAR_FETCH_TOGGLES and _is_falsy_toggle_value(connector[key]):
                state = STATE_OK
                n_ok += 1
                entry = {
                    "name": key,
                    "state": state,
                    "connector_value": connector[key],
                    "verdict": "ok",
                    "reason": (
                        "fetch toggle absent on the integration side; an absent "
                        "toggle is treated as False, matching the connector's "
                        "falsy value — at parity"
                    ),
                }
                _annotate_serializer(entry, key)
                per_param.append(entry)
                continue
            # Per-variant SCOPING (Bucket C): an EXTRA_IN_CONNECTOR field owned
            # SOLELY by sub-capabilities disabled in this variant means the
            # platform injected a connector-only field belonging to a disabled
            # sub-capability. Downgrade to OK_IGNORED out_of_variant_scope BEFORE
            # counting it as a failure (single shared scope gate).
            if _try_scope_downgrade(key, connector_value=connector[key]):
                continue
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

    # ``n_ok_ignored`` here counts the normalizer-DROPPED keys surfaced above; those
    # are NOT members of ``union_keys`` so they are added to ``n_total``. The
    # out-of-variant-scope OK_IGNORED entries (``n_out_of_scope``) ARE integration
    # keys already inside ``union_keys`` (reclassified away from MISSING), so they
    # are folded into the REPORTED ``n_ok_ignored`` but NOT re-added to ``n_total``.
    return {
        "status": status,
        "summary": {
            "n_total": len(union_keys) + n_ok_ignored,
            "n_ok": n_ok,
            "n_ok_ignored": n_ok_ignored + n_out_of_scope,
            "n_out_of_variant_scope": n_out_of_scope,
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
