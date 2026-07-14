"""End-to-end (golden-file) tests for the ConnectUs ``generate_manifest`` CLI.

This is a thin, data-driven driver: every case directory under
``e2e/fixtures/<feature>/<case>/`` becomes one parametrized test. The mechanics
(case discovery, subprocess invocation, semantic YAML comparison, golden
regeneration) live in ``e2e_helpers.py``.

Run normally::

    pytest connectus_migration/e2e/manifest_generator_e2e_test.py

(Re)generate goldens from actual output (then review the diff before commit)::

    UPDATE_GOLDEN=1 pytest connectus_migration/e2e/manifest_generator_e2e_test.py

See ``e2e/README.md`` for how to author a new case.
"""

from __future__ import annotations

from pathlib import Path

import pytest

import e2e_helpers as e2e

_CASES = e2e.discover_cases()


def _case_id(case: e2e.E2ECase) -> str:
    return case.name


# When no fixtures exist yet, ``parametrize`` with an empty list would error at
# collection time; guard with a skip so the suite stays green pre-authoring.
if _CASES:

    @pytest.mark.parametrize("case", _CASES, ids=_case_id)
    def test_generate_manifest_e2e(case: e2e.E2ECase, tmp_path: Path) -> None:
        result = e2e.run_generator(case, tmp_path)

        # Negative cases: assert the run failed (optionally with a stderr marker)
        # and never touch goldens.
        if case.expect_failure:
            assert result.returncode != 0, (
                f"{case.name}: expected the generator to fail but it exited 0.\n"
                f"stdout:\n{result.stdout}\nstderr:\n{result.stderr}"
            )
            if case.expect_stderr_contains:
                assert case.expect_stderr_contains in result.stderr, (
                    f"{case.name}: expected stderr to contain "
                    f"{case.expect_stderr_contains!r}.\nstderr:\n{result.stderr}"
                )
            return

        # Positive cases: the run must succeed.
        assert result.returncode == 0, (
            f"{case.name}: generator exited {result.returncode}.\n"
            f"stdout:\n{result.stdout}\nstderr:\n{result.stderr}"
        )

        if e2e.update_golden_enabled():
            e2e.regenerate_golden(case, result)
            pytest.skip(
                f"{case.name}: regenerated golden (UPDATE_GOLDEN). "
                f"Review the diff before committing."
            )

        assert case.expected_connectors.is_dir(), (
            f"{case.name}: no expected/connectors golden found. "
            f"Author it, or run once with UPDATE_GOLDEN=1 and review the result."
        )

        diff = e2e.compare_trees(result.connectors_root, case.expected_connectors)
        assert diff.ok, f"{case.name}: produced tree differs from golden:\n{diff.as_message()}"

else:

    @pytest.mark.skip(reason="No e2e fixture cases discovered under e2e/fixtures/")
    def test_generate_manifest_e2e() -> None:  # pragma: no cover
        pass
