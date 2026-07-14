"""Black-box E2E suite for the ``align_engines`` patch.

WIP / PLACEHOLDER
=================
``patches/align_engines.py`` is currently a scaffold that performs NO mutation
(it enumerates connections and confirms the CSV exists, then exits 0). So the
single baseline case here has ``expected/`` == ``input/``: the suite proves the
script is correctly wired into the harness (script path, CSV passthrough, dry-run
and idempotency) and pins the "no-op" contract until real engine-alignment logic
lands. When that logic is implemented, update ``expected/`` to the mutated golden
and flip the case's ``expect_modified`` to ``true``.

The script is driven via the GENERIC harness (``script`` + ``args`` in
``case.json``) — it uses a ``--csv`` flag contract rather than the legacy
``--pipeline-csv`` one, demonstrating the args template.

Cases live under ``fixtures/align_engines/`` and are discovered by scoping the
shared harness's loader to that subdirectory, so this suite never collides with
the other patch suites.

Run
---
    cd content/connectus && python3 -m pytest \
        patches/e2e/align_engines_e2e_test.py -v
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

# Scope discovery to this patch's own fixtures subdir.
_ALIGN_FIXTURES = harness.FIXTURES_DIR / "align_engines"


def _discover_align_cases() -> list[harness.PatchE2ECase]:
    if not _ALIGN_FIXTURES.is_dir():
        return []
    cases = [
        harness._load_case(p)
        for p in _ALIGN_FIXTURES.glob(f"*/{harness.CASE_FILE}")
    ]
    return sorted(cases, key=lambda c: c.name)


_CASES = _discover_align_cases()
_CASE_IDS = [c.name for c in _CASES]


# --------------------------------------------------------------------------- #
# (a) LIVE run -> patched tree semantically equals expected/ AFTER.
#     (For the WIP no-op, expected == input.)
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
# (b) DRY-RUN -> tree bytes unchanged, exit 0.
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("case", _CASES, ids=_CASE_IDS)
def test_dry_run_writes_nothing(case: harness.PatchE2ECase, tmp_path: Path) -> None:
    connectors_root = harness.sandbox_inputs(case, tmp_path)
    before = harness.snapshot_tree(connectors_root)

    result = harness.run_patch(case, connectors_root, dry_run=True)
    assert result.returncode == 0, (
        f"{case.name}: dry-run exited {result.returncode}\n"
        f"stdout:\n{result.stdout}\nstderr:\n{result.stderr}"
    )

    after = harness.snapshot_tree(connectors_root)
    assert after == before, f"{case.name}: --dry-run mutated the tree on disk"


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
# Suite sanity: the baseline case is discoverable and well-formed.
# --------------------------------------------------------------------------- #
def test_cases_are_discovered() -> None:
    names = {c.name for c in _CASES}
    expected = {
        "1_auth_profile_1_handler",
        "2_auth_profile_1_handler",
        "2_auth_profiles_2_handlers",
        "2_auth_profiles_different_handlers",
        "multiple_auth_profiles",
        "multiple_connectors",
    }
    assert expected <= names, (
        f"missing align_engines cases: {sorted(expected - names)}"
    )


@pytest.mark.parametrize("case", _CASES, ids=_CASE_IDS)
def test_fixture_is_well_formed(case: harness.PatchE2ECase) -> None:
    assert case.input_connectors.is_dir(), f"{case.name}: missing input/connectors"
    assert case.script, f"{case.name}: case must declare a `script`"
    assert case.resolved_script.is_file(), (
        f"{case.name}: resolved script {case.resolved_script} not found"
    )
    if case.csv:
        assert case.input_csv is not None and case.input_csv.is_file(), (
            f"{case.name}: declared csv {case.csv!r} not found in input/"
        )
    goldens = sorted(case.expected_connectors.rglob("connection.yaml"))
    assert goldens, f"{case.name}: no expected/**/connection.yaml golden found"
