"""Generic black-box E2E demo suite.

This suite proves the harness in ``patch_e2e_helpers.py`` is GENERIC: a case can
point at ANY python script (via the ``script`` key) with ANY flag contract (via
the ``args`` template) and be tested with the same sandbox + subprocess +
semantic-compare machinery used by the real patch suites.

Unlike ``add_vault_support_e2e_test.py`` (which defaults every case to
``add_vault_support.py``), each case here declares its own ``script``. The
example script under test — ``examples/set_metadata_owner.py`` — uses a
deliberately different flag contract (``--owner``) to demonstrate the ``args``
template fully shapes argv.

Cases live under ``fixtures/generic_example/`` and are discovered by scoping the
shared harness's ``discover_cases`` to that subdirectory, so this suite never
collides with the ``add_vault_support`` (direct-child) or
``propagate_advanced_flag`` (own-subdir) cases.

Run
---
    cd content/connectus && python3 -m pytest \
        patches/e2e/generic_example_e2e_test.py -v
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

# Self-bootstrapping sys.path shim so the sibling harness imports regardless of
# the invocation directory (mirrors the other e2e test modules).
_HERE = Path(__file__).resolve().parent
if str(_HERE) not in sys.path:
    sys.path.insert(0, str(_HERE))

import patch_e2e_helpers as harness  # noqa: E402

# Scope discovery to this demo's own fixtures subdir.
_GENERIC_FIXTURES = harness.FIXTURES_DIR / "generic_example"


def _discover_generic_cases() -> list[harness.PatchE2ECase]:
    if not _GENERIC_FIXTURES.is_dir():
        return []
    cases = [
        harness._load_case(p)
        for p in _GENERIC_FIXTURES.glob(f"*/{harness.CASE_FILE}")
    ]
    return sorted(cases, key=lambda c: c.name)


_CASES = _discover_generic_cases()
_CASE_IDS = [c.name for c in _CASES]


# --------------------------------------------------------------------------- #
# (a) LIVE run -> patched tree semantically equals expected/ AFTER.
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("case", _CASES, ids=_CASE_IDS)
def test_live_run_matches_expected(case: harness.PatchE2ECase, tmp_path: Path) -> None:
    connectors_root = harness.sandbox_inputs(case, tmp_path)

    result = harness.run_patch(case, connectors_root, dry_run=False)
    assert result.returncode == 0, (
        f"{case.name}: script exited {result.returncode}\n"
        f"stdout:\n{result.stdout}\nstderr:\n{result.stderr}"
    )

    diff = harness.compare_trees(connectors_root, case.expected_connectors)
    assert diff.ok, f"{case.name}: live-patched tree != expected:\n{diff.as_message()}"


# --------------------------------------------------------------------------- #
# (b) DRY-RUN -> tree bytes unchanged, change reported, exit 0.
# --------------------------------------------------------------------------- #
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
            token in report for token in ("would", "modif", case.connector or "")
        ), (
            f"{case.name}: dry-run did not report the intended change\n"
            f"stdout:\n{result.stdout}\nstderr:\n{result.stderr}"
        )


# --------------------------------------------------------------------------- #
# (c) IDEMPOTENCY -> second live run over patched tree is a no-op.
# --------------------------------------------------------------------------- #
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
        f"{case.name}: second run changed the tree (not idempotent)"
    )
    diff = harness.compare_trees(connectors_root, case.expected_connectors)
    assert diff.ok, (
        f"{case.name}: tree drifted from expected after second run:\n"
        f"{diff.as_message()}"
    )


# --------------------------------------------------------------------------- #
# Suite sanity: the demo case is discoverable and well-formed.
# --------------------------------------------------------------------------- #
def test_cases_are_discovered() -> None:
    names = {c.name for c in _CASES}
    assert "set_owner_demo" in names, (
        "expected the generic demo case under fixtures/generic_example/"
    )


@pytest.mark.parametrize("case", _CASES, ids=_CASE_IDS)
def test_fixture_is_well_formed(case: harness.PatchE2ECase) -> None:
    assert case.input_connectors.is_dir(), f"{case.name}: missing input/connectors"
    assert case.script, f"{case.name}: generic case must declare a `script`"
    assert case.resolved_script.is_file(), (
        f"{case.name}: resolved script {case.resolved_script} not found"
    )
    goldens = sorted(case.expected_connectors.rglob("connection.yaml"))
    assert goldens, f"{case.name}: no expected/**/connection.yaml golden found"
