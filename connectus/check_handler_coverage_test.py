"""Regression test for connectus/check_handler_coverage.py.

Runs the built-in ``standard_connectors_poc`` batch against the
``../unified-connectors-content/`` checkout and asserts that every handler
reports ``add == 0`` AND ``collision == 0`` AND ``status == 0`` — i.e. the
post-patch baseline established by the standard_connectors_poc PR review.

The test is **skipped** when the connectors-content checkout isn't
present (it's a sibling repo that contributors may not have locally) so
this file is safe to run as part of the regular content-repo test suite.
When the checkout IS present, the test acts as a gate against any future
content YML drift OR connectors-side edit that would re-introduce gaps in
the 7 standard_connectors_poc handlers.
"""

from __future__ import annotations

import io
from contextlib import redirect_stdout
from pathlib import Path

import pytest

from connectus.check_handler_coverage import (
    BATCH_STANDARD_CONNECTORS_POC,
    run_one,
)

CONNECTORS_REPO = Path(__file__).resolve().parents[1] / ".." / "unified-connectors-content"


def _all_triples_resolvable() -> bool:
    if not CONNECTORS_REPO.is_dir():
        return False
    for triple in BATCH_STANDARD_CONNECTORS_POC.values():
        connector = Path(triple["connector"])
        integration = Path(triple["integration"])
        if not connector.is_dir() or not integration.is_dir():
            return False
    return True


@pytest.mark.skipif(
    not _all_triples_resolvable(),
    reason=(
        "standard_connectors_poc parity test requires the ../unified-connectors-content "
        "sibling checkout. Clone the connectors repo at that path to enable this test."
    ),
)
@pytest.mark.parametrize("report_id,triple", sorted(BATCH_STANDARD_CONNECTORS_POC.items()))
def test_standard_connectors_poc_handler_is_covered(report_id: str, triple: dict[str, str]) -> None:
    """Every standard_connectors_poc handler must have 0 ADD-* gaps and 0 collisions."""
    integration_path = Path(triple["integration"])
    connector_dir = Path(triple["connector"])
    handler_id = triple["handler_id"]

    # Suppress the per-triple progress print so pytest output stays clean;
    # the actual gap details are still surfaced in the assertion message
    # if the test fails.
    with redirect_stdout(io.StringIO()):
        report, status = run_one(
            integration_path,
            connector_dir,
            handler_id,
            report_id,
            output_dir=None,
            emit_fragments=False,
        )

    # Two layers of assertion so the failure mode is obvious:
    # 1) the structured exit status (0 = clean)
    # 2) the textual report (which will be in the pytest assertion diff)
    assert status == 0, (
        f"{report_id}: parity check reports gaps. Re-run with --output-dir to inspect:\n"
        f"  python3 connectus/check_handler_coverage.py "
        f"--integration {integration_path} --connector {connector_dir} "
        f"--handler-id {handler_id} --output-dir /tmp/parity\n\n"
        f"Report excerpt:\n{report[-2000:]}"
    )
    assert "❌ ADD" not in report, f"{report_id}: report still contains ADD-* gaps"
    assert "⚠️ COLLISION" not in report, f"{report_id}: report still contains COLLISION verdicts"
