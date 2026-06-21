"""Black-box E2E suite for the ``add_vault_support`` patch.

TDD-RED NOTICE
==============
The patch under test — ``content/connectus/patches/add_vault_support.py`` — does
NOT exist yet. This suite is authored RED-FIRST (the test, harness and fixtures
land before the implementation). To keep the suite runnable today AND have it
auto-activate the moment the patch is implemented, the whole module is guarded by
a module-level check:

* if ``add_vault_support.py`` is MISSING, every test is marked
  ``pytest.mark.xfail(reason=..., strict=False)`` — the suite runs, the
  subprocess invocation fails (file not found) and pytest records an ``xfail``
  rather than a hard failure. Nothing here stubs or fakes the patch.
* once ``add_vault_support.py`` exists, the marker is NOT applied, so the real
  acceptance criteria are enforced. A passing patch flips the cases to green; a
  buggy patch fails loudly.

This mirrors the conventions of the sibling unit test
(``patches/flatten_non_type9_nesting_test.py``) and the generator black-box
harness (``connectus_migration/e2e/e2e_helpers.py``): the patch is invoked as a
real SUBPROCESS via ``sys.executable``; each case is SANDBOXED by copying its
``input/`` tree into a tmp dir (so the real repo is never mutated); and
``connection.yaml`` files are compared SEMANTICALLY (parsed YAML, canonicalized,
ignoring the leading ``# yaml-language-server`` directive line) rather than
byte-compared.

What is asserted (the FOUR acceptance criteria)
-----------------------------------------------
(a) LIVE run: the patched ``connection.yaml`` is semantically equal to the
    case's ``expected/`` AFTER (RemoteAccess: vault_mappings injected; negative
    case: unchanged).
(b) DRY-RUN: the sandbox tree is byte-for-byte unchanged, yet the CLI reports
    the intended change and exits 0.
(c) IDEMPOTENCY: a SECOND live run over the already-patched tree produces no
    further change (no duplicate vault_mappings).
(d) SCOPE GUARD: via ``negative_scope_untouched``, plain + api_key + the
    ``vault_support: true`` profiles are left untouched (after == before).

Run
---
    cd content/connectus && python3 -m pytest patches/e2e/add_vault_support_e2e_test.py -v
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

import patch_e2e_helpers as harness  # noqa: E402

# --------------------------------------------------------------------------- #
# TDD-RED guard: xfail the suite until the patch under test exists.
# --------------------------------------------------------------------------- #
_PATCH_EXISTS = harness.PATCH_SCRIPT.is_file()
_TDD_RED = pytest.mark.xfail(
    not _PATCH_EXISTS,
    reason="add_vault_support.py not implemented yet (TDD red)",
    strict=False,
    run=True,
)

_CASES = harness.discover_cases()
_CASE_IDS = [c.name for c in _CASES]


def _expected_connection(case: harness.PatchE2ECase) -> Path:
    """The single connection.yaml golden for ``case`` (under expected/)."""
    matches = sorted(case.expected_connectors.rglob("connection.yaml"))
    assert matches, f"{case.name}: no expected/**/connection.yaml golden found"
    return matches[0]


def _sandbox_connection(connectors_root: Path, expected: Path, case: harness.PatchE2ECase) -> Path:
    """The connection.yaml in the sandbox tree matching the golden's rel path."""
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
def test_dry_run_writes_nothing_but_reports(case: harness.PatchE2ECase, tmp_path: Path) -> None:
    connectors_root = harness.sandbox_inputs(case, tmp_path)
    before = harness.snapshot_tree(connectors_root)

    result = harness.run_patch(case, connectors_root, dry_run=True)
    assert result.returncode == 0, (
        f"{case.name}: dry-run exited {result.returncode}\n"
        f"stdout:\n{result.stdout}\nstderr:\n{result.stderr}"
    )

    after = harness.snapshot_tree(connectors_root)
    assert after == before, f"{case.name}: --dry-run mutated the tree on disk"

    # For a case that WOULD change, the dry-run must say so somewhere in its
    # report (mirrors flatten_non_type9_nesting's DRY-RUN summary). For a
    # no-change case we only require a clean exit (asserted above).
    if case.expect_modified:
        report = (result.stdout + result.stderr).lower()
        assert any(
            token in report
            for token in ("vault", "would", "dry-run", "modif", case.connector or "")
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
        f"{case.name}: second run changed the tree (not idempotent — likely a "
        f"duplicated vault_mappings block)"
    )
    # And the (idempotent) result still matches the golden.
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
        f"{case.name}: scope guard violated — the patch mutated non-passthrough "
        f"(plain / api_key / vault_support) profiles"
    )
    # Belt-and-braces: semantic equality with the (identical) golden.
    diff = harness.compare_trees(connectors_root, case.expected_connectors)
    assert diff.ok, f"{case.name}: negative tree != expected:\n{diff.as_message()}"


# --------------------------------------------------------------------------- #
# Suite sanity (always runs, never xfailed): fixtures discoverable + well-formed.
# --------------------------------------------------------------------------- #
def test_cases_are_discovered() -> None:
    names = {c.name for c in _CASES}
    assert "remote_access_v2_vault_backfill" in names
    assert "negative_scope_untouched" in names


@pytest.mark.parametrize("case", _CASES, ids=_CASE_IDS)
def test_fixture_is_well_formed(case: harness.PatchE2ECase) -> None:
    # Every case must have an input tree and a single connection.yaml golden.
    assert case.input_connectors.is_dir(), f"{case.name}: missing input/connectors"
    golden = _expected_connection(case)
    assert golden.is_file()
    if case.csv:
        assert case.input_csv is not None and case.input_csv.is_file(), (
            f"{case.name}: declared csv {case.csv!r} not found in input/"
        )
