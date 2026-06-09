"""Edge-case tests for ``dry_run_auth`` / ``set-auth --dry-run`` (Part 2).

These tests are IN ADDITION to ``test_dry_run.py`` (the executable
specification). They cover edge cases that the spec leaves implicit:

1. :class:`TestProxyMitmFailure` — the parity gate surfacing a
   proxy/MITM-stage failure (crashed run → parity block → exit 1; or
   an unhandled analyzer crash → ``ERROR_PARITY_UNHANDLED`` → exit 3).
   See ``plans/auth-parity-proxy-mitm-refactor.md`` for the proxy
   failure semantics.
2. :class:`TestTimeoutBoundaries` — ``--timeout=`` boundary parsing.
3. :class:`TestFormatTextEnvelope` — ``--format=text`` for both the
   dry-run path and the real path (ASCII-safe, no JSON braces).
4. :class:`TestSetAuthExitCodeSymmetry` — ``set_auth_exit_code`` and
   ``dry_run_exit_code`` return the same code per logical branch,
   parametrized across all five branches.
5. :class:`TestIdempotencyConcurrent` — concurrent dry-runs return
   identical envelopes and never mutate the CSV.
"""
from __future__ import annotations

import json
import threading

import pytest

from workflow_state import api as ws_api
from workflow_state import cli as ws_cli


# ---------------------------------------------------------------------------
# Fixtures (mirroring test_dry_run.py)
# ---------------------------------------------------------------------------


class _FakeRow(dict):
    """Minimal CSV-row-shape stand-in for dry-run tests."""


@pytest.fixture
def fake_row() -> dict:
    return _FakeRow({
        "Integration ID": "MyIntegration",
        "Integration File Path": "Packs/Fake/Integrations/Fake/Fake.yml",
        "Connector ID": "fake",
        "Auth Details": "",
    })


@pytest.fixture
def mock_csv(monkeypatch: pytest.MonkeyPatch, fake_row: dict) -> list[dict]:
    """Mock load_csv() so dry_run_auth sees exactly one row; save_csv()
    raises if called (defence-in-depth for the CSV-untouched assertion).
    """
    rows = [fake_row]
    monkeypatch.setattr(ws_api, "load_csv", lambda: rows)

    def _exploding_save(_rows):  # pragma: no cover — guard
        raise AssertionError(
            "save_csv() must NOT be invoked from the dry-run path."
        )

    monkeypatch.setattr(ws_api, "save_csv", _exploding_save)
    return rows


_VALID_AUTH_JSON = (
    '{"auth_types":[{"type":"APIKey","name":"primary",'
    '"xsoar_param_map":{"api_key":"key"}}],"other_connection":[]}'
)


def _crashed_parity_block(stderr: str = "proxy CONNECT failed: connection refused") -> dict:
    """A check_auth_parity result whose only connection crashed at the
    proxy/MITM stage. Mirrors the analyzer's per-connection 'fail' shape
    with a crashed new_run carrying a proxy stderr excerpt.
    """
    return {
        "integration": "MyIntegration",
        "auth_parity": {
            "primary": {
                "status": "fail",
                "diffs": ["..."],
                "diagnostics": {
                    "commands": {
                        "test-module": {
                            "diffs": [{"failure_code": "RUN_FAILED_NEW"}],
                            "new_run": {
                                "status": "crashed",
                                "stderr_excerpt": stderr,
                            },
                        }
                    }
                },
            }
        },
        "diagnostics": {},
    }


def _infra_error(code: str = "ERROR_PARITY_UNHANDLED", msg: str = "proxy MITM stage raised") -> dict:
    return {"error": {"code": code, "message": msg, "exit_code": 3}}


# ---------------------------------------------------------------------------
# 1) Proxy / MITM failure branch
# ---------------------------------------------------------------------------


class TestAlwaysInterpolateGate:
    """ALWAYS-INTERPOLATE GATE (2026-06-09): the gate no longer runs the
    parity analyzer, so proxy/MITM-stage failures can no longer block a
    schema-valid payload. A schema-valid payload always commits.

    The legacy ``_crashed_parity_block`` / ``_infra_error`` helpers are
    retained at module level for the exit-code-mapping symmetry tests below,
    which exercise :func:`dry_run_exit_code` / :func:`set_auth_exit_code`
    directly on hand-built envelopes.
    """

    def test_schema_valid_payload_commits_regardless_of_proxy(
        self, monkeypatch: pytest.MonkeyPatch, mock_csv: list[dict]
    ) -> None:
        env = ws_api.dry_run_auth("MyIntegration", _VALID_AUTH_JSON)
        assert env["verdict"]["would_commit"] is True
        assert ws_api.dry_run_exit_code(env) == 0
        # The parity block is a structural-skip stub, never a parity result.
        assert "skipped" in env["parity"]
        assert env["parity"].get("forced_interpolated") is True


# ---------------------------------------------------------------------------
# 2) --timeout= boundary parsing
# ---------------------------------------------------------------------------


class TestTimeoutBoundaries:
    def test_timeout_one_is_minimum_positive_accepted(self) -> None:
        _r, _d, timeout, _f = ws_cli._parse_set_auth_flags(["X", "{}", "--timeout=1"])
        assert timeout == 1

    def test_timeout_large_value_accepted(self) -> None:
        _r, _d, timeout, _f = ws_cli._parse_set_auth_flags(["X", "{}", "--timeout=99999"])
        assert timeout == 99999

    def test_timeout_zero_rejected(self) -> None:
        with pytest.raises(SystemExit) as exc:
            ws_cli._parse_set_auth_flags(["X", "{}", "--timeout=0"])
        assert exc.value.code == 1

    def test_timeout_negative_rejected(self) -> None:
        with pytest.raises(SystemExit) as exc:
            ws_cli._parse_set_auth_flags(["X", "{}", "--timeout=-1"])
        assert exc.value.code == 1

    def test_timeout_empty_value_rejected(self) -> None:
        with pytest.raises(SystemExit) as exc:
            ws_cli._parse_set_auth_flags(["X", "{}", "--timeout="])
        assert exc.value.code == 1


# ---------------------------------------------------------------------------
# 3) --format=text envelope (both paths)
# ---------------------------------------------------------------------------


class TestFormatTextEnvelope:
    """``--format=text`` produces a human-readable, ASCII-safe report
    with NO JSON braces on either path.
    """

    def test_dry_run_text_output_has_no_json_braces(
        self,
        monkeypatch: pytest.MonkeyPatch,
        mock_csv: list[dict],
        capsys: pytest.CaptureFixture,
    ) -> None:
        # ALWAYS-INTERPOLATE GATE: a schema-valid payload always commits.
        with pytest.raises(SystemExit) as exc:
            ws_cli.cmd_set_auth([
                "MyIntegration", _VALID_AUTH_JSON, "--dry-run", "--format=text",
            ])
        assert exc.value.code == 0
        out = capsys.readouterr().out
        assert "{" not in out and "}" not in out
        assert "dry-run preview" in out.lower()
        assert "WOULD COMMIT" in out
        assert out.isascii()

    def test_dry_run_text_block_path_has_no_braces(
        self,
        monkeypatch: pytest.MonkeyPatch,
        mock_csv: list[dict],
        capsys: pytest.CaptureFixture,
    ) -> None:
        # ALWAYS-INTERPOLATE GATE: parity can no longer block, but a
        # schema-INvalid payload still blocks (validation runs first), which
        # exercises the WOULD NOT COMMIT text path. Use a brace-free invalid
        # payload (a JSON array) so the no-JSON-braces assertion is meaningful
        # — the validator rejects it because Auth Details must be an object.
        with pytest.raises(SystemExit) as exc:
            ws_cli.cmd_set_auth([
                "MyIntegration", "[]", "--dry-run", "--format=text",
            ])
        assert exc.value.code == 1
        out = capsys.readouterr().out
        assert "{" not in out and "}" not in out
        assert "WOULD NOT COMMIT" in out

    def test_real_path_text_success_returns_normally(
        self,
        monkeypatch: pytest.MonkeyPatch,
        capsys: pytest.CaptureFixture,
    ) -> None:
        def _capturing_set_auth(integration_id, raw, *, seed_overrides=None):  # noqa: ANN001
            return {
                "message": "Set 'Auth Details' for 'MyIntegration'.",
                "current_step": None,
                "parity": {"skipped": "test"},
            }

        monkeypatch.setattr(ws_cli, "set_integration_auth", _capturing_set_auth)
        # Real path + explicit text format → returns normally (exit 0).
        ws_cli.cmd_set_auth([
            "MyIntegration", _VALID_AUTH_JSON, "--format=text",
        ])
        out = capsys.readouterr().out
        assert "Set 'Auth Details'" in out
        assert out.isascii() or "🎉" in out  # emoji allowed only in all-done banner


# ---------------------------------------------------------------------------
# 4) Exit-code symmetry across all 5 branches
# ---------------------------------------------------------------------------


def _dry_envelope_for(branch: str) -> dict:
    base = {
        "dry_run": True,
        "integration_id": "X",
        "validator": {"passed": True, "errors": []},
        "seed_overlap": {"passed": True},
        "parity": {},
        "verdict": {"would_commit": False, "reason": branch},
    }
    if branch == "valid":
        base["parity"] = {"auth_parity": {"c": {"status": "pass"}}}
        base["verdict"] = {"would_commit": True, "reason": "ok"}
    elif branch == "invalid_json":
        base["validator"] = {"passed": False, "errors": ["bad json"]}
        base["seed_overlap"] = {"skipped": "..."}
        base["parity"] = {"skipped": "..."}
        base["verdict"] = {"would_commit": False, "reason": "validator failed"}
    elif branch == "seed_overlap":
        base["seed_overlap"] = {
            "passed": False,
            "error": {"code": "ERROR_SEED_AUTH_OVERLAP", "message": "...", "exit_code": 2},
        }
        base["parity"] = {"skipped": "..."}
        base["verdict"] = {"would_commit": False, "reason": "ERROR_SEED_AUTH_OVERLAP"}
    elif branch == "parity_fail":
        base["parity"] = {"auth_parity": {"c": {"status": "fail"}}}
        base["verdict"] = {"would_commit": False, "reason": "1 connection(s) did not pass"}
    elif branch == "infra":
        base["parity"] = {
            "error": {"code": "ERROR_PARITY_UNHANDLED", "message": "...", "exit_code": 3},
        }
        base["verdict"] = {"would_commit": False, "reason": "ERROR_PARITY_UNHANDLED"}
    return base


def _real_result_for(branch: str) -> dict:
    if branch == "valid":
        return {"message": "ok", "current_step": "x"}
    if branch == "invalid_json":
        return {"error": "Auth Details schema validation failed: bad json"}
    if branch == "seed_overlap":
        return {"error": {"code": "ERROR_SEED_AUTH_OVERLAP", "message": "...", "exit_code": 2}}
    if branch == "parity_fail":
        return {
            "error": "Auth Details rejected — parity gate failed for 'X': ...",
            "parity": {"auth_parity": {"c": {"status": "fail"}}},
        }
    if branch == "infra":
        return {
            "error": "Auth Details rejected — parity gate failed for 'X': ...",
            "parity": {"error": {"code": "ERROR_PARITY_UNHANDLED", "message": "...", "exit_code": 3}},
        }
    raise ValueError(branch)


class TestSetAuthExitCodeSymmetry:
    """For each logical branch, dry-run and real-path exit codes match."""

    @pytest.mark.parametrize(
        "branch,expected",
        [
            ("valid", 0),
            ("invalid_json", 1),
            ("seed_overlap", 2),
            ("parity_fail", 1),
            ("infra", 3),
        ],
    )
    def test_dry_and_real_exit_codes_are_symmetric(
        self, branch: str, expected: int
    ) -> None:
        dry_code = ws_api.dry_run_exit_code(_dry_envelope_for(branch))
        real_code = ws_api.set_auth_exit_code(_real_result_for(branch))
        assert dry_code == expected
        assert real_code == expected
        assert dry_code == real_code


# ---------------------------------------------------------------------------
# 5) Idempotency under concurrent dry-runs (+ CSV untouched)
# ---------------------------------------------------------------------------


class TestIdempotencyConcurrent:
    def test_concurrent_dry_runs_identical_and_csv_untouched(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path
    ) -> None:
        from workflow_state import csv_io

        csv_path = tmp_path / "pipeline.csv"
        header = [
            "Integration ID", "Integration File Path", "Connector ID",
            "assignee", "Auth Details", "Params to Commands",
            "Params for test with default in code", "Params to Capabilities",
            "generated manifest", "run manifest make validate", "Release Notes",
            "precommit/validate/unit tests passed", "param parity test passes",
            "code reviewed", "code merged",
        ]
        rows = [
            ",".join(header) + "\n",
            "MyIntegration,Packs/Fake/Integrations/Fake/Fake.yml,fake,,,,,,,,,,,,\n",
        ]
        csv_path.write_text("".join(rows), encoding="utf-8")

        monkeypatch.setattr(csv_io, "CSV_PATH", str(csv_path), raising=False)
        import workflow_state as _ws
        monkeypatch.setattr(_ws, "CSV_PATH", str(csv_path), raising=False)

        monkeypatch.setattr(
            ws_api,
            "_run_auth_parity_for_set_auth",
            lambda **_k: {
                "integration": "MyIntegration",
                "auth_parity": {"primary": {"status": "pass", "diffs": []}},
                "diagnostics": {},
            },
        )

        before_bytes = csv_path.read_bytes()

        results: list[dict] = []
        results_lock = threading.Lock()

        def _worker() -> None:
            env = ws_api.dry_run_auth("MyIntegration", _VALID_AUTH_JSON)
            with results_lock:
                results.append(env)

        threads = [threading.Thread(target=_worker) for _ in range(4)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        after_bytes = csv_path.read_bytes()

        # All four envelopes are identical (idempotent).
        assert len(results) == 4
        serialized = {json.dumps(r, sort_keys=True) for r in results}
        assert len(serialized) == 1, "concurrent dry-runs produced divergent envelopes"
        assert all(r["verdict"]["would_commit"] is True for r in results)

        # CSV byte-identical before/after — no mutation from any thread.
        assert before_bytes == after_bytes
