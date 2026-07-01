"""Black-box E2E suite for the ``propagate_advanced_flag`` patch.

TDD-RED NOTICE
==============
Both the patch's BUSINESS LOGIC and its FIXTURES are authored in later phases.
This suite is the RED baseline: the test, harness and case-name contract land
before the implementation, and the whole suite is auto-activated only once
BOTH the patch script AND the fixtures ship. Specifically:

  * The 4 acceptance tests are xfailed (``strict=False``) whenever EITHER
        - ``propagate_advanced_flag.py`` is missing, OR
        - no cases are discovered under
          ``patches/e2e/fixtures/propagate_advanced_flag/``.
    Under that guard the parametrized tests xfail cleanly today (no cases
    discovered yet) and will auto-activate the moment Phase 2 (fixtures) and
    Phase 3 (implementation) both land.
  * ``test_cases_are_discovered`` is NEVER xfailed — it pins the exact 4 case
    names this suite expects and FAILS RED today (no fixtures).

This mirrors the convention used by ``add_vault_support_e2e_test.py`` and keeps
the patch invocation a true black-box subprocess (no in-process stubbing).

Run
---
    cd content/connectus && python3 -m pytest \
        patches/e2e/propagate_advanced_flag_e2e_test.py -v
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

# Self-bootstrapping sys.path shim (mirrors flatten_non_type9_nesting_test.py):
# make the sibling harness importable regardless of the invocation directory.
_HERE = Path(__file__).resolve().parent
if str(_HERE) not in sys.path:
    sys.path.insert(0, str(_HERE))

import propagate_advanced_flag_e2e_helpers as harness  # noqa: E402

# --------------------------------------------------------------------------- #
# TDD-RED guard: xfail the parametrized suite until BOTH the patch under test
# exists AND fixtures are discovered. The discovery sanity test below is NEVER
# xfailed so it stays loudly RED until cases land.
# --------------------------------------------------------------------------- #
_CASES = harness.discover_cases()
_CASE_IDS = [c.name for c in _CASES]

_PATCH_EXISTS = harness.PATCH_SCRIPT.is_file()
_FIXTURES_PRESENT = bool(_CASES)
_BOTH_READY = _PATCH_EXISTS and _FIXTURES_PRESENT

_TDD_RED = pytest.mark.xfail(
    not _BOTH_READY,
    reason=(
        "propagate_advanced_flag not ready yet (TDD red): "
        f"patch_exists={_PATCH_EXISTS}, fixtures_present={_FIXTURES_PRESENT}"
    ),
    strict=False,
    run=True,
)


def _expected_connection(case: harness.PatchE2ECase) -> Path:
    """First connection-or-configurations YAML golden under ``expected/``."""
    matches = sorted(
        list(case.expected_connectors.rglob("connection.yaml"))
        + list(case.expected_connectors.rglob("configurations.yaml"))
    )
    assert matches, (
        f"{case.name}: no expected/**/(connection|configurations).yaml golden found"
    )
    return matches[0]


def _sandbox_connection(
    connectors_root: Path,
    expected: Path,
    case: harness.PatchE2ECase,
) -> Path:
    """The YAML in the sandbox tree matching the golden's relative path."""
    rel = expected.relative_to(case.expected_connectors)
    return connectors_root / rel


# --------------------------------------------------------------------------- #
# (a) LIVE run -> patched tree semantically equals expected/ AFTER.
# --------------------------------------------------------------------------- #
@_TDD_RED
@pytest.mark.parametrize("case", _CASES, ids=_CASE_IDS)
def test_live_run_matches_expected(case: harness.PatchE2ECase, tmp_path: Path) -> None:
    connectors_root = harness.sandbox_inputs(case, tmp_path)

    result = harness.run_patch(case, connectors_root, dry_run=False)
    assert result.returncode == 0, (
        f"{case.name}: patch exited {result.returncode}\n"
        f"stdout:\n{result.stdout}\nstderr:\n{result.stderr}"
    )

    diff = harness.compare_trees(connectors_root, case.expected_connectors)
    assert diff.ok, f"{case.name}: live-patched tree != expected:\n{diff.as_message()}"


# --------------------------------------------------------------------------- #
# (b) DRY-RUN -> tree bytes unchanged, change reported, exit 0.
# --------------------------------------------------------------------------- #
@_TDD_RED
@pytest.mark.parametrize("case", _CASES, ids=_CASE_IDS)
def test_dry_run_writes_nothing_but_reports(
    case: harness.PatchE2ECase, tmp_path: Path
) -> None:
    connectors_root = harness.sandbox_inputs(case, tmp_path)
    before = harness.snapshot_tree(connectors_root)

    result = harness.run_patch(case, connectors_root, dry_run=True)
    assert result.returncode == 0, (
        f"{case.name}: dry-run exited {result.returncode}\n"
        f"stdout:\n{result.stdout}\nstderr:\n{result.stderr}"
    )

    after = harness.snapshot_tree(connectors_root)
    assert after == before, f"{case.name}: --dry-run mutated the tree on disk"

    if case.expect_modified:
        report = (result.stdout + result.stderr).lower()
        assert any(
            token in report
            for token in ("advanced", "would", "dry-run", "modif", case.connector or "")
        ), (
            f"{case.name}: dry-run did not report the intended change\n"
            f"stdout:\n{result.stdout}\nstderr:\n{result.stderr}"
        )


# --------------------------------------------------------------------------- #
# (c) IDEMPOTENCY -> second live run over patched tree is a no-op.
# --------------------------------------------------------------------------- #
@_TDD_RED
@pytest.mark.parametrize("case", _CASES, ids=_CASE_IDS)
def test_idempotent_second_run(case: harness.PatchE2ECase, tmp_path: Path) -> None:
    connectors_root = harness.sandbox_inputs(case, tmp_path)

    first = harness.run_patch(case, connectors_root, dry_run=False)
    assert first.returncode == 0, (
        f"{case.name}: first run exited {first.returncode}\n{first.stderr}"
    )
    after_first = harness.snapshot_tree(connectors_root)

    second = harness.run_patch(case, connectors_root, dry_run=False)
    assert second.returncode == 0, (
        f"{case.name}: second run exited {second.returncode}\n{second.stderr}"
    )
    after_second = harness.snapshot_tree(connectors_root)

    assert after_second == after_first, (
        f"{case.name}: second run changed the tree (not idempotent — likely "
        f"a duplicated split or re-promoted row)"
    )
    diff = harness.compare_trees(connectors_root, case.expected_connectors)
    assert diff.ok, (
        f"{case.name}: tree drifted from expected after second run:\n"
        f"{diff.as_message()}"
    )


# --------------------------------------------------------------------------- #
# (d) SCOPE GUARD -> negative case left untouched (after == before).
# --------------------------------------------------------------------------- #
_NEGATIVE_CASES = [c for c in _CASES if not c.expect_modified]
_NEGATIVE_IDS = [c.name for c in _NEGATIVE_CASES]


@_TDD_RED
@pytest.mark.parametrize("case", _NEGATIVE_CASES, ids=_NEGATIVE_IDS)
def test_scope_guard_leaves_non_passthrough_untouched(
    case: harness.PatchE2ECase, tmp_path: Path
) -> None:
    connectors_root = harness.sandbox_inputs(case, tmp_path)
    before = harness.snapshot_tree(connectors_root)

    result = harness.run_patch(case, connectors_root, dry_run=False)
    assert result.returncode == 0, (
        f"{case.name}: patch exited {result.returncode}\n{result.stderr}"
    )

    after = harness.snapshot_tree(connectors_root)
    assert after == before, (
        f"{case.name}: scope guard violated — the patch mutated a manifest with "
        f"no advanced params to propagate"
    )
    diff = harness.compare_trees(connectors_root, case.expected_connectors)
    assert diff.ok, f"{case.name}: negative tree != expected:\n{diff.as_message()}"


# --------------------------------------------------------------------------- #
# Suite sanity (always runs, never xfailed): fixtures discoverable + named.
# --------------------------------------------------------------------------- #
# The expected case names are PINNED here. They are the four scenarios the
# Phase 2 fixture work MUST author (drawn from the row-placement matrix in
# propagate_advanced_flag's module docstring):
#
#   1. configurations_general_advanced       (context 1 / row-split + propagate)
#   2. configurations_per_capability_advanced(context 2 / row-split + NO
#                                             view_group / no required_for_caps)
#   3. connection_profile_advanced           (context 4 / row-split on a
#                                             profiles[] row)
#   4. no_advanced_params_noop               (negative case: nothing to do)
_EXPECTED_CASE_NAMES = {
    "configurations_general_advanced",
    "configurations_per_capability_advanced",
    "connection_profile_advanced",
    "no_advanced_params_noop",
}


def test_cases_are_discovered() -> None:
    names = {c.name for c in _CASES}
    assert names == _EXPECTED_CASE_NAMES, (
        f"expected cases {_EXPECTED_CASE_NAMES!r}, found {names!r}"
    )


# --------------------------------------------------------------------------- #
# Fix #3 (HIGH): fixture-CSV portability guard.
#
# The pipeline-CSV column ``Integration File Path`` is the link between an
# XSOAR integration ID and the YML the patch reads to determine which params
# are ``advanced: true``. If a fixture hard-codes a developer-home absolute
# path (e.g. ``/Users/<name>/dev/.../NoOpConn.yml``), the fixture only works
# on that developer's machine — it breaks on CI, on every other contributor's
# checkout, and silently turns "patch correctly found no advanced params" into
# "patch couldn't find the YML at all". The harness's other three fixtures all
# use REPO-RELATIVE paths (e.g. ``Packs/SimpleConn/Integrations/...``), which
# the production resolver re-anchors against the CSV's parent dir so they
# resolve correctly under each fixture's own ``input/`` tree.
#
# This test walks every fixture's discovery CSV and asserts no
# ``Integration File Path`` value is absolute. It is intentionally cheap and
# runs in-process (no patch invocation) so a CSV-portability regression fails
# loudly without waiting for the full e2e suite.
# --------------------------------------------------------------------------- #
# --------------------------------------------------------------------------- #
# Fix #2 (HIGH): the noop fixture must not produce spurious "unmatched" noise.
#
# The ``no_advanced_params_noop`` fixture intentionally points at a source YML
# with ZERO ``advanced: true`` params. Post-Fix #2, "owner resolved with zero
# advanced params" is a benign no-op — the patch must report no unmatched
# params for this fixture. Pre-Fix #2 the patch wrongly listed every field id
# in the fixture's manifest (server_url, credentials_username,
# credentials_password) under "Unmatched params", drowning out genuine
# resolution-failure signals on other connectors.
#
# This is asserted at the BLACK-BOX level: invoke the patch via the harness and
# scan its combined stdout+stderr for "Unmatched" (case-insensitive). Doing it
# at the subprocess boundary catches both summary formatting regressions AND
# logic regressions in the lookup-vs-collect contract.
# --------------------------------------------------------------------------- #
@_TDD_RED
def test_no_advanced_noop_fixture_emits_no_unmatched_warnings(tmp_path: Path) -> None:
    """The noop fixture must run cleanly without "unmatched" output.

    Targets the ``no_advanced_params_noop`` case specifically. A live (non-dry)
    run is exercised because that is the operationally common path; the
    fixture is a true noop so no files are written either way.
    """
    noop_case = next(
        (c for c in _CASES if c.name == "no_advanced_params_noop"), None
    )
    assert noop_case is not None, "noop fixture missing — cannot run Fix #2 e2e"
    connectors_root = harness.sandbox_inputs(noop_case, tmp_path)
    result = harness.run_patch(noop_case, connectors_root, dry_run=False)
    assert result.returncode == 0, (
        f"noop run exited {result.returncode}\n"
        f"stdout:\n{result.stdout}\nstderr:\n{result.stderr}"
    )
    combined = (result.stdout + "\n" + result.stderr).lower()
    assert "unmatched" not in combined, (
        "noop fixture must not emit any 'unmatched' warnings (resolved-empty "
        "is not a resolution failure):\n"
        f"--- stdout ---\n{result.stdout}\n--- stderr ---\n{result.stderr}"
    )


def test_no_fixture_csv_uses_absolute_path() -> None:
    """No fixture CSV may carry an absolute ``Integration File Path``.

    A leading ``/`` (POSIX) or ``~`` (home expansion) or a Windows drive
    letter all make the fixture machine-specific. The portable form is a
    repo-relative path that the production resolver locates by trying both
    the CSV's parent dir AND the content root in turn.
    """
    import csv as _csv
    from pathlib import PurePath, PureWindowsPath

    offenders: list[str] = []
    for case in _CASES:
        if case.input_csv is None or not case.input_csv.is_file():
            continue
        with case.input_csv.open(newline="") as fh:
            for row in _csv.DictReader(fh):
                raw = (row.get("Integration File Path") or "").strip()
                if not raw:
                    continue
                # Detect: POSIX absolute, Windows absolute, or ~ home expansion.
                is_abs = (
                    PurePath(raw).is_absolute()
                    or PureWindowsPath(raw).is_absolute()
                    or raw.startswith("~")
                )
                if is_abs:
                    offenders.append(
                        f"{case.name}: {case.input_csv.name} row "
                        f"Integration ID={row.get('Integration ID')!r} "
                        f"-> {raw!r}"
                    )
    assert not offenders, (
        "Fixture CSV(s) contain non-portable absolute paths in the "
        "'Integration File Path' column. Replace with repo-relative paths so "
        "fixtures work on every machine and on CI:\n  - "
        + "\n  - ".join(offenders)
    )
