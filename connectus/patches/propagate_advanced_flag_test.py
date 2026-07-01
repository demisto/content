"""TDD tests for the ``propagate_advanced_flag`` patch.

RED-FIRST SKELETON
==================
These tests are authored RED-FIRST: ``propagate_advanced_flag.py`` currently
exposes only a CLI skeleton + ``PatchResult`` dataclass, with NO business logic
(``patch_file``, ``find_yaml_files``, the resolver helpers, the
row-split/row-promote logic, etc.). Every test below either:

  * exercises a not-yet-existing helper on the ``patch`` module (which will
    raise AttributeError on first call), OR
  * calls ``pytest.fail("RED: <reason>")`` as a fallback when the relevant
    helper doesn't exist yet.

Once the implementation lands, each test must pin a SPECIFIC behaviour
described in the locked Phase 0 schema/placement matrix. The matrix lives in
``propagate_advanced_flag``'s module docstring; it is the source of truth.

Per-profile lookup parametrization
----------------------------------
Tests inject a ``advanced_lookup`` callable rather than wiring the real
pipeline-CSV / source-YML resolver. The shim mirrors
``flatten_non_type9_nesting_test._call_type_lookup`` and supports both the
1-arg ``lookup(yaml_path)`` AND the 2-arg ``lookup(yaml_path, context_dict)``
forms so the test can express PER-CONTEXT scoping (e.g. different advanced sets
per capability / per profile, which is the whole point of the qualys multi-
handler fixture).
"""

from __future__ import annotations

import inspect
import sys
import textwrap
from pathlib import Path

import pytest

# Make the sibling patch module importable regardless of invocation dir
# (mirrors flatten_non_type9_nesting_test.py).
_HERE = Path(__file__).resolve().parent
if str(_HERE) not in sys.path:
    sys.path.insert(0, str(_HERE))

import propagate_advanced_flag as patch  # noqa: E402


# --------------------------------------------------------------------------- #
# Lookup shim: 1-arg or 2-arg ``advanced_lookup`` (mirrors flatten test shim).
# --------------------------------------------------------------------------- #
def _call_advanced_lookup(lookup, path: Path, context: dict | None = None):
    """Invoke ``lookup`` supporting BOTH the 1-arg and 2-arg signatures.

    The 2-arg ``(yaml_path, context)`` form lets the test express per-capability
    / per-profile scoping (the production resolver scopes the advanced set to a
    single source integration). A 1-arg ``(yaml_path)`` form is also accepted
    for simpler single-context tests.
    """
    try:
        sig = inspect.signature(lookup)
        n_params = len(
            [
                p
                for p in sig.parameters.values()
                if p.kind
                in (
                    inspect.Parameter.POSITIONAL_ONLY,
                    inspect.Parameter.POSITIONAL_OR_KEYWORD,
                )
            ]
        )
    except (TypeError, ValueError):
        n_params = 1
    if n_params >= 2:
        return lookup(path, context or {}) or set()
    return lookup(path) or set()


# --------------------------------------------------------------------------- #
# Filesystem helpers (mirror flatten_non_type9_nesting_test helpers).
# --------------------------------------------------------------------------- #
def _write_config_yaml(tmp_path: Path, connector: str, body: str) -> Path:
    """Write a configurations.yaml under ``connectors/<connector>/``."""
    conn_dir = tmp_path / "connectors" / connector
    conn_dir.mkdir(parents=True, exist_ok=True)
    p = conn_dir / "configurations.yaml"
    p.write_text(textwrap.dedent(body).lstrip("\n"))
    return p


def _write_connection_yaml(tmp_path: Path, connector: str, body: str) -> Path:
    """Write a connection.yaml under ``connectors/<connector>/``."""
    conn_dir = tmp_path / "connectors" / connector
    conn_dir.mkdir(parents=True, exist_ok=True)
    p = conn_dir / "connection.yaml"
    p.write_text(textwrap.dedent(body).lstrip("\n"))
    return p


def _call_patch_file(*args, **kwargs):
    """Call ``patch.patch_file`` or RED-fail if it doesn't exist yet."""
    fn = getattr(patch, "patch_file", None)
    if fn is None:
        pytest.fail("RED: patch_file() not implemented yet")
    return fn(*args, **kwargs)


# --------------------------------------------------------------------------- #
# Synthetic YAML fixtures
# --------------------------------------------------------------------------- #
# Context 1 — configurations.yaml general_configurations row of 2 fields.
# Both fields belong to a single FieldGroup row; the patch may promote (if BOTH
# advanced) or split (if mixed) depending on the injected lookup.
CONFIG_GENERAL_ONE_ROW_TWO_FIELDS = """
    metadata:
      title: Configurations
    general_configurations:
      configurations:
      - fields:
        - id: insecure
          title: Trust any certificate
          field_type: checkbox
        - id: proxy
          title: Use system proxy
          field_type: checkbox
"""

# Context 1 — same shape, but with a view_group already on the row (grouped
# connector). Used by test_view_group_propagated_in_general_grouped.
CONFIG_GENERAL_GROUPED_ROW = """
    metadata:
      title: Configurations
    general_configurations:
      configurations:
      - view_group: connection
        required_for_capabilities:
        - Fetch Issues
        fields:
        - id: insecure
          title: Trust any certificate
          field_type: checkbox
        - id: first_fetch
          title: First fetch time
          field_type: input
"""

# Context 2 — configurations.yaml per-capability row. Per the schema, a row
# inside ``configurations[].configurations[]`` MUST NOT carry view_group /
# required_for_capabilities; it only carries fields (+ optional advanced).
CONFIG_PER_CAPABILITY_ROW = """
    metadata:
      title: Configurations
    configurations:
    - id: Fetch Issues
      view_group: collection
      configurations:
      - fields:
        - id: max_fetch
          title: Max fetch
          field_type: input
        - id: eventFetchInterval
          title: Event fetch interval
          field_type: input
"""

# Context 4 — connection.yaml profiles[].configurations[] per-profile row.
# Same legality as context 2: NO view_group, NO required_for_capabilities.
CONNECTION_WITH_PROFILE_ROW = """
    metadata:
      title: Connection
    profiles:
    - id: api_key.qualys
      type: api_key
      view_group: qualys
      title: API
      configurations:
      - fields:
        - id: url
          title: Server URL
          field_type: input
        - id: insecure
          title: Trust any certificate
          field_type: checkbox
"""

# Already-advanced single row — both fields advanced; idempotency target.
CONFIG_ALREADY_ADVANCED = """
    metadata:
      title: Configurations
    general_configurations:
      configurations:
      - advanced: true
        fields:
        - id: insecure
          title: Trust any certificate
          field_type: checkbox
        - id: proxy
          title: Use system proxy
          field_type: checkbox
"""

# Mixed row — one advanced, one not (split target).
CONFIG_MIXED_ROW = """
    metadata:
      title: Configurations
    general_configurations:
      configurations:
      - fields:
        - id: url
          title: Server URL
          field_type: input
        - id: insecure
          title: Trust any certificate
          field_type: checkbox
"""

# A connection.yaml general_configurations row (context 3) for the
# row-shape parity test (configurations.yaml vs. connection.yaml).
CONNECTION_GENERAL_ROW = """
    metadata:
      title: Connection
    general_configurations:
      configurations:
      - fields:
        - id: insecure
          title: Trust any certificate
          field_type: checkbox
        - id: proxy
          title: Use system proxy
          field_type: checkbox
"""

# Multi-capability mixed configurations.yaml — used by
# test_multi_handler_scoping_per_capability. Two per-capability blocks; the
# advanced set MUST be scoped per capability.
CONFIG_MULTI_CAPABILITY = """
    metadata:
      title: Configurations
    configurations:
    - id: QualysFIM Fetch
      view_group: fim
      configurations:
      - fields:
        - id: fetch_filter
          title: Fetch filter
          field_type: input
        - id: first_fetch
          title: First fetch
          field_type: input
    - id: QualysV2 Fetch
      view_group: v2
      configurations:
      - fields:
        - id: eventFetchInterval
          title: Event interval
          field_type: input
        - id: max_fetch
          title: Max fetch
          field_type: input
"""


# --------------------------------------------------------------------------- #
# Tests — all RED (skeleton). Each pins a single behaviour from the matrix.
# --------------------------------------------------------------------------- #
def test_whole_row_promotion(tmp_path: Path) -> None:
    """A row whose EVERY field is advanced is promoted to ``advanced: true``
    on the row itself (no split needed)."""
    cy = _write_config_yaml(tmp_path, "acme", CONFIG_GENERAL_ONE_ROW_TWO_FIELDS)

    def lookup(_path: Path) -> set[str]:
        # Both fields advanced -> whole-row promotion.
        return {"insecure", "proxy"}

    res = _call_patch_file(cy, advanced_lookup=lookup, dry_run=False)
    assert res.modified is True, "RED: row should have been promoted"
    assert res.promoted_rows, "RED: promoted_rows should be populated"
    assert not res.split_rows, "RED: a fully-advanced row must not split"

    doc = patch.load_yaml(cy)
    row = doc["general_configurations"]["configurations"][0]
    assert row.get("advanced") is True


def test_mixed_row_split_in_place_sibling_after(tmp_path: Path) -> None:
    """A mixed row splits in place: the original (non-advanced) row stays at
    its position and a NEW ``advanced: true`` sibling row is inserted IMMEDIATELY
    AFTER it carrying the advanced fields (relative order preserved)."""
    cy = _write_config_yaml(tmp_path, "acme", CONFIG_MIXED_ROW)

    def lookup(_path: Path) -> set[str]:
        # Only ``insecure`` is advanced -> split, ``url`` stays, ``insecure``
        # moves to a new sibling row marked advanced: true.
        return {"insecure"}

    res = _call_patch_file(cy, advanced_lookup=lookup, dry_run=False)
    assert res.modified is True
    assert res.split_rows, "RED: split_rows should be populated"

    doc = patch.load_yaml(cy)
    rows = doc["general_configurations"]["configurations"]
    assert len(rows) == 2, "RED: expected the row to split into two siblings"
    # Non-advanced row first, in place.
    assert not rows[0].get("advanced")
    assert [f["id"] for f in rows[0]["fields"]] == ["url"]
    # Advanced sibling immediately after.
    assert rows[1].get("advanced") is True
    assert [f["id"] for f in rows[1]["fields"]] == ["insecure"]


def test_idempotent_already_advanced(tmp_path: Path) -> None:
    """A row that's ALREADY ``advanced: true`` and whose every field is advanced
    is a no-op. Second run produces zero diff."""
    cy = _write_config_yaml(tmp_path, "acme", CONFIG_ALREADY_ADVANCED)
    before = cy.read_text()

    def lookup(_path: Path) -> set[str]:
        return {"insecure", "proxy"}

    res = _call_patch_file(cy, advanced_lookup=lookup, dry_run=False)
    assert res.modified is False, "RED: idempotent run must not report modified"
    assert not res.promoted_rows
    assert not res.split_rows
    assert cy.read_text() == before, "RED: file bytes must be identical"


def test_unmatched_param_reported_no_change(tmp_path: Path) -> None:
    """A param in the manifest whose owner the lookup COULDN'T resolve is
    reported via ``unmatched_params`` and the file is left untouched.

    Contract (post-Fix #2): the lookup signals "resolution failed — investigate"
    by returning ``None``. An empty ``set()`` now means "resolved successfully,
    the owner has no advanced params" and is a benign no-op. This test pins the
    resolution-failure branch; ``test_resolved_empty_set_does_NOT_report_unmatched``
    pins the empty-but-resolved branch.
    """
    cy = _write_config_yaml(tmp_path, "acme", CONFIG_GENERAL_ONE_ROW_TWO_FIELDS)
    before = cy.read_text()

    def lookup(_path: Path):
        # None = "resolution failed" (no handler / no source YML found):
        # this is the only condition that should populate unmatched_params.
        return None

    res = _call_patch_file(cy, advanced_lookup=lookup, dry_run=False)
    assert res.modified is False
    # Unmatched params must be reported (so an operator can fix the pipeline).
    assert "insecure" in res.unmatched_params or "proxy" in res.unmatched_params, (
        "unmatched_params should surface the manifest's params when the "
        "lookup signals resolution failure (returns None)"
    )
    assert cy.read_text() == before


def test_resolved_empty_set_does_NOT_report_unmatched(tmp_path: Path) -> None:
    """An EMPTY ``set()`` from the lookup means "owner resolved, advanced set
    is empty by design" — NOT a resolution failure. The patch must NOT report
    unmatched in that case, and must leave the file untouched.

    Pre-Fix #2 this leaked false positives on every per-capability / per-profile
    row whose owning integration simply had no advanced params (the operationally
    common "noop" case), drowning the genuine resolution-failure signal in noise.
    """
    cy = _write_config_yaml(tmp_path, "acme", CONFIG_GENERAL_ONE_ROW_TWO_FIELDS)
    before = cy.read_text()

    def lookup(_path: Path) -> set[str]:
        # set() = "resolved, owner has zero advanced params" -> noop, NOT
        # an unmatched-params event.
        return set()

    res = _call_patch_file(cy, advanced_lookup=lookup, dry_run=False)
    assert res.modified is False
    assert res.unmatched_params == [], (
        "an empty (but resolved) advanced set must NOT populate unmatched_params; "
        f"got {res.unmatched_params!r}"
    )
    assert cy.read_text() == before


def test_view_group_propagated_in_general_grouped(tmp_path: Path) -> None:
    """Context 1 split on a GROUPED connector: the new advanced sibling row
    inherits ``view_group`` AND ``required_for_capabilities`` from the source row
    (general_configurations is the only place these may live)."""
    cy = _write_config_yaml(tmp_path, "acme", CONFIG_GENERAL_GROUPED_ROW)

    def lookup(_path: Path) -> set[str]:
        # Only ``first_fetch`` advanced -> split. The new sibling must carry
        # view_group and required_for_capabilities forward (grouped connector).
        return {"first_fetch"}

    res = _call_patch_file(
        cy,
        advanced_lookup=lookup,
        dry_run=False,
        grouped=True,
    )
    assert res.modified is True
    doc = patch.load_yaml(cy)
    rows = doc["general_configurations"]["configurations"]
    assert len(rows) == 2
    assert rows[0]["view_group"] == "connection"
    assert rows[1]["view_group"] == "connection"
    assert rows[0].get("required_for_capabilities") == ["Fetch Issues"]
    assert rows[1].get("required_for_capabilities") == ["Fetch Issues"]
    assert rows[1].get("advanced") is True


def test_view_group_NOT_propagated_per_capability(tmp_path: Path) -> None:
    """Context 2 (configurations.yaml per-capability row) split must NEVER carry
    ``view_group`` on the new sibling — the schema forbids it there (the view is
    inherited from the enclosing configurations[] entry)."""
    cy = _write_config_yaml(tmp_path, "acme", CONFIG_PER_CAPABILITY_ROW)

    def lookup(_path: Path, _context: dict) -> set[str]:
        return {"eventFetchInterval"}

    res = _call_patch_file(
        cy,
        advanced_lookup=lookup,
        dry_run=False,
        grouped=True,
    )
    assert res.modified is True
    doc = patch.load_yaml(cy)
    rows = doc["configurations"][0]["configurations"]
    assert len(rows) == 2
    for row in rows:
        assert "view_group" not in row, (
            "RED: view_group must NOT appear on per-capability FieldGroup rows"
        )
        assert "required_for_capabilities" not in row, (
            "RED: required_for_capabilities is forbidden on per-capability rows"
        )
    assert rows[1].get("advanced") is True
    assert [f["id"] for f in rows[1]["fields"]] == ["eventFetchInterval"]


def test_view_group_NOT_propagated_per_profile(tmp_path: Path) -> None:
    """Context 4 (connection.yaml profiles[].configurations[]) split must NEVER
    carry ``view_group`` on the new sibling — derived from handler.yaml
    auth_options, not the row."""
    cy = _write_connection_yaml(tmp_path, "acme", CONNECTION_WITH_PROFILE_ROW)

    def lookup(_path: Path, _context: dict) -> set[str]:
        return {"insecure"}

    res = _call_patch_file(
        cy,
        advanced_lookup=lookup,
        dry_run=False,
        grouped=True,
    )
    assert res.modified is True
    doc = patch.load_yaml(cy)
    rows = doc["profiles"][0]["configurations"]
    assert len(rows) == 2
    for row in rows:
        assert "view_group" not in row, (
            "RED: view_group must NOT appear on per-profile FieldGroup rows"
        )
        assert "required_for_capabilities" not in row
    assert rows[1].get("advanced") is True


def test_required_for_capabilities_propagated_general_only(tmp_path: Path) -> None:
    """``required_for_capabilities`` propagates on general_configurations split
    (contexts 1/3) and is ABSENT everywhere else. Tested here on context 1 as
    the positive case; the negative-context tests above pin the absence."""
    cy = _write_config_yaml(tmp_path, "acme", CONFIG_GENERAL_GROUPED_ROW)

    def lookup(_path: Path) -> set[str]:
        return {"first_fetch"}

    res = _call_patch_file(
        cy,
        advanced_lookup=lookup,
        dry_run=False,
        grouped=False,  # not grouped -> view_group must NOT propagate, but RFC must
    )
    assert res.modified is True
    doc = patch.load_yaml(cy)
    rows = doc["general_configurations"]["configurations"]
    assert len(rows) == 2
    # required_for_capabilities propagates regardless of grouped-ness; view_group
    # only when grouped — so when grouped=False the source row's view_group must
    # NOT appear on the new sibling.
    assert rows[0].get("required_for_capabilities") == ["Fetch Issues"]
    assert rows[1].get("required_for_capabilities") == ["Fetch Issues"]
    assert "view_group" not in rows[1], (
        "RED: view_group must NOT propagate when the connector isn't grouped"
    )


def test_multi_handler_scoping_per_capability(tmp_path: Path) -> None:
    """Per-capability rows scope the advanced lookup to that capability's source
    integration. Mirrors the locked qualys fixture: a per-capability row keyed
    to QualysFIM must NOT inherit QualysV2's advanced params (and vice versa)."""
    cy = _write_config_yaml(tmp_path, "acme", CONFIG_MULTI_CAPABILITY)

    def lookup(_path: Path, context: dict) -> set[str]:
        # The patch is expected to pass the enclosing capability id into the
        # context; the lookup returns only the params advanced for THAT
        # integration.
        cap_id = (context or {}).get("capability_id", "")
        if cap_id == "QualysFIM Fetch":
            return {"fetch_filter"}  # NOT eventFetchInterval
        if cap_id == "QualysV2 Fetch":
            return {"eventFetchInterval"}  # NOT fetch_filter
        return set()

    res = _call_patch_file(cy, advanced_lookup=lookup, dry_run=False)
    assert res.modified is True

    doc = patch.load_yaml(cy)
    caps = doc["configurations"]
    # Capability 1: only fetch_filter advanced.
    fim_rows = caps[0]["configurations"]
    assert len(fim_rows) == 2
    assert [f["id"] for f in fim_rows[0]["fields"]] == ["first_fetch"]
    assert [f["id"] for f in fim_rows[1]["fields"]] == ["fetch_filter"]
    assert fim_rows[1].get("advanced") is True
    # Capability 2: only eventFetchInterval advanced.
    v2_rows = caps[1]["configurations"]
    assert len(v2_rows) == 2
    assert [f["id"] for f in v2_rows[0]["fields"]] == ["max_fetch"]
    assert [f["id"] for f in v2_rows[1]["fields"]] == ["eventFetchInterval"]
    assert v2_rows[1].get("advanced") is True


def test_works_on_configurations_yaml_row_shape(tmp_path: Path) -> None:
    """Sanity: the patch recognises configurations.yaml general_configurations
    row shape and edits IT (not some other section)."""
    cy = _write_config_yaml(tmp_path, "acme", CONFIG_GENERAL_ONE_ROW_TWO_FIELDS)

    def lookup(_path: Path) -> set[str]:
        return {"insecure", "proxy"}

    res = _call_patch_file(cy, advanced_lookup=lookup, dry_run=False)
    assert res.modified is True
    doc = patch.load_yaml(cy)
    # The general_configurations row was the one promoted.
    assert (
        doc["general_configurations"]["configurations"][0].get("advanced") is True
    )


def test_works_on_connection_yaml_row_shape(tmp_path: Path) -> None:
    """Sanity: the patch recognises connection.yaml general_configurations row
    shape and edits IT (parity with configurations.yaml)."""
    cy = _write_connection_yaml(tmp_path, "acme", CONNECTION_GENERAL_ROW)

    def lookup(_path: Path) -> set[str]:
        return {"insecure", "proxy"}

    res = _call_patch_file(cy, advanced_lookup=lookup, dry_run=False)
    assert res.modified is True
    doc = patch.load_yaml(cy)
    assert (
        doc["general_configurations"]["configurations"][0].get("advanced") is True
    )


# --------------------------------------------------------------------------- #
# Fix #1 (HIGH): _handler_entries defensive parsing.
#
# ``_handler_entries`` walks every handler.yaml under
# ``<connector>/components/handlers/`` and pulls the
# ``triggering.labels.xsoar-integration-id`` (with a ``metadata`` fallback).
# Real-world handler.yamls have been observed with ``triggering: null`` or
# ``triggering: [list]`` (and sibling-key shapes alike). The original chain
# ``hy.get("triggering", {}).get("labels", {})`` blows up with AttributeError
# the instant any intermediate node is non-mapping. The surrounding
# ``try/except`` wraps only ``yaml.safe_load``, so the exception escapes and
# aborts processing of the entire connector — turning ONE malformed handler
# into a whole-connector outage.
#
# Each test below writes ONE bad handler plus ONE good handler in the same
# connector dir; the good handler MUST still be reported. Pre-fix, the bad
# handler raises AttributeError before the good one is reached and the
# function never returns.
# --------------------------------------------------------------------------- #
def _make_handler(handlers_root: Path, name: str, body: str) -> Path:
    """Write a handler.yaml under ``<handlers_root>/<name>/handler.yaml``."""
    hdir = handlers_root / name
    hdir.mkdir(parents=True, exist_ok=True)
    p = hdir / "handler.yaml"
    p.write_text(textwrap.dedent(body).lstrip("\n"))
    return p


# A minimal well-formed handler.yaml whose entry MUST always be reported by
# ``_handler_entries`` — used as the "good neighbour" in every defensive test.
_GOOD_HANDLER = """
    id: xsoar-good
    triggering:
      labels:
        xsoar-integration-id: GoodInt
"""


def test_handler_entries_handles_null_triggering(tmp_path: Path) -> None:
    """A handler.yaml with ``triggering: null`` must not raise.

    The metadata fallback still provides the integration id, so the bad
    handler is also reported. Regardless, the sibling good handler MUST be
    reported.
    """
    connector_dir = tmp_path / "connectors" / "acme"
    handlers_root = connector_dir / "components" / "handlers"
    _make_handler(
        handlers_root,
        "xsoar-bad",
        """
        id: xsoar-bad
        triggering: null
        metadata:
          xsoar-integration-id: BadInt
        """,
    )
    _make_handler(handlers_root, "xsoar-good", _GOOD_HANDLER)

    entries = patch._handler_entries(connector_dir)
    iids = {iid for iid, _hdir, _hy in entries}
    assert "GoodInt" in iids, (
        "good handler must still be reported despite malformed sibling"
    )
    assert "BadInt" in iids, (
        "metadata fallback should yield the bad handler's integration id"
    )


def test_handler_entries_handles_non_mapping_triggering(tmp_path: Path) -> None:
    """A handler.yaml whose ``triggering`` is a list (not a mapping) must not
    raise. The good sibling handler MUST still be reported."""
    connector_dir = tmp_path / "connectors" / "acme"
    handlers_root = connector_dir / "components" / "handlers"
    _make_handler(
        handlers_root,
        "xsoar-bad",
        """
        id: xsoar-bad
        triggering:
        - some
        - list
        metadata:
          xsoar-integration-id: BadInt
        """,
    )
    _make_handler(handlers_root, "xsoar-good", _GOOD_HANDLER)

    entries = patch._handler_entries(connector_dir)
    iids = {iid for iid, _hdir, _hy in entries}
    assert "GoodInt" in iids
    assert "BadInt" in iids


def test_handler_entries_handles_null_labels(tmp_path: Path) -> None:
    """A handler.yaml with ``triggering: {labels: null}`` must not raise.

    Only the metadata fallback can supply the id here; the good sibling is
    still expected to be reported.
    """
    connector_dir = tmp_path / "connectors" / "acme"
    handlers_root = connector_dir / "components" / "handlers"
    _make_handler(
        handlers_root,
        "xsoar-bad",
        """
        id: xsoar-bad
        triggering:
          labels: null
        metadata:
          xsoar-integration-id: BadInt
        """,
    )
    _make_handler(handlers_root, "xsoar-good", _GOOD_HANDLER)

    entries = patch._handler_entries(connector_dir)
    iids = {iid for iid, _hdir, _hy in entries}
    assert "GoodInt" in iids
    assert "BadInt" in iids


def test_handler_entries_handles_null_metadata(tmp_path: Path) -> None:
    """A handler.yaml with NO ``triggering`` and ``metadata: null`` must not
    raise. The bad handler has no resolvable id (and so is silently dropped),
    but the good sibling MUST still be reported."""
    connector_dir = tmp_path / "connectors" / "acme"
    handlers_root = connector_dir / "components" / "handlers"
    _make_handler(
        handlers_root,
        "xsoar-bad",
        """
        id: xsoar-bad
        metadata: null
        """,
    )
    _make_handler(handlers_root, "xsoar-good", _GOOD_HANDLER)

    entries = patch._handler_entries(connector_dir)
    iids = {iid for iid, _hdir, _hy in entries}
    assert "GoodInt" in iids, (
        "good handler must still be reported even when sibling has null metadata"
    )
