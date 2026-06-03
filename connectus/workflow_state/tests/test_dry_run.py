"""Tests for ``dry_run_auth`` and ``set-auth --dry-run`` (Part 1).

Covers:

1. :func:`dry_run_auth` returns the six-key envelope per the plan
   §"Dry-run output schema" in all branches (validator-fail,
   seed-overlap, parity-pass, parity-fail, structural-skip,
   integration-not-found).
2. :func:`dry_run_exit_code` maps each envelope to 0 / 1 / 2 / 3
   per the plan §"Exit code mapping".
3. :func:`set_auth_exit_code` shares the mapping with the real path.
4. :func:`cmd_set_auth` wires ``--dry-run`` / ``--timeout=N`` /
   ``--format=json|text`` through, defaults JSON for dry-run and
   TEXT for real, rejects ``--format X`` with a space.
5. **CSV-untouched assertion** — load CSV bytes, run dry-run, load
   CSV bytes after, assert bit-identical. This is the regression
   catch for "did we accidentally mutate?"
"""
from __future__ import annotations

import json
import os
from unittest import mock

import pytest

from workflow_state import api as ws_api
from workflow_state import cli as ws_cli


# ---------------------------------------------------------------------------
# Helpers
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
    """Mock load_csv() inside workflow_state.api so dry_run_auth sees
    exactly one row; save_csv() raises if called (defence-in-depth for
    the CSV-untouched assertion).
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


# ---------------------------------------------------------------------------
# 1) dry_run_auth — envelope shape per branch
# ---------------------------------------------------------------------------


class TestDryRunAuthEnvelopeShape:
    """Pin the 6-key envelope and the per-branch payload."""

    def test_envelope_always_has_six_keys(
        self,
        monkeypatch: pytest.MonkeyPatch,
        mock_csv: list[dict],
    ) -> None:
        monkeypatch.setattr(
            ws_api,
            "_run_auth_parity_for_set_auth",
            lambda **_k: {
                "integration": "MyIntegration",
                "auth_parity": {"primary": {"status": "pass", "diffs": []}},
                "diagnostics": {},
            },
        )
        env = ws_api.dry_run_auth("MyIntegration", _VALID_AUTH_JSON)
        assert set(env.keys()) == {
            "dry_run",
            "integration_id",
            "validator",
            "seed_overlap",
            "parity",
            "verdict",
        }
        assert env["dry_run"] is True
        assert env["integration_id"] == "MyIntegration"

    def test_validator_failure_short_circuits_with_skip_markers(
        self,
        monkeypatch: pytest.MonkeyPatch,
        mock_csv: list[dict],
    ) -> None:
        parity_called = {"value": False}

        def _exploding_parity(**_kwargs):  # noqa: ANN003
            parity_called["value"] = True
            raise AssertionError("parity must not run after validator fails")

        monkeypatch.setattr(
            ws_api, "_run_auth_parity_for_set_auth", _exploding_parity
        )
        env = ws_api.dry_run_auth("MyIntegration", "not valid json {")
        assert env["validator"]["passed"] is False
        assert env["validator"]["errors"]
        assert "skipped" in env["seed_overlap"]
        assert "skipped" in env["parity"]
        assert env["verdict"]["would_commit"] is False
        assert parity_called["value"] is False

    def test_seed_overlap_short_circuits_with_skip_marker(
        self,
        monkeypatch: pytest.MonkeyPatch,
        mock_csv: list[dict],
    ) -> None:
        parity_called = {"value": False}

        def _exploding_parity(**_kwargs):  # noqa: ANN003
            parity_called["value"] = True
            raise AssertionError("parity must not run after seed overlap")

        monkeypatch.setattr(
            ws_api, "_run_auth_parity_for_set_auth", _exploding_parity
        )
        env = ws_api.dry_run_auth(
            "MyIntegration",
            _VALID_AUTH_JSON,
            seed_overrides={"api_key": "real"},
        )
        assert env["validator"]["passed"] is True
        assert env["seed_overlap"]["passed"] is False
        err = env["seed_overlap"]["error"]
        assert err["code"] == "ERROR_SEED_AUTH_OVERLAP"
        assert err["exit_code"] == 2
        assert "skipped" in env["parity"]
        assert env["verdict"]["would_commit"] is False
        assert env["verdict"]["reason"] == "ERROR_SEED_AUTH_OVERLAP"
        assert parity_called["value"] is False

    def test_parity_pass_yields_would_commit_true(
        self,
        monkeypatch: pytest.MonkeyPatch,
        mock_csv: list[dict],
    ) -> None:
        monkeypatch.setattr(
            ws_api,
            "_run_auth_parity_for_set_auth",
            lambda **_k: {
                "integration": "MyIntegration",
                "auth_parity": {"primary": {"status": "pass", "diffs": []}},
                "diagnostics": {},
            },
        )
        env = ws_api.dry_run_auth("MyIntegration", _VALID_AUTH_JSON)
        assert env["verdict"]["would_commit"] is True
        assert "ok" in env["verdict"]["reason"].lower() or "pass" in env["verdict"]["reason"].lower()

    def test_parity_fail_yields_would_commit_false(
        self,
        monkeypatch: pytest.MonkeyPatch,
        mock_csv: list[dict],
    ) -> None:
        monkeypatch.setattr(
            ws_api,
            "_run_auth_parity_for_set_auth",
            lambda **_k: {
                "integration": "MyIntegration",
                "auth_parity": {"primary": {"status": "fail", "diffs": ["..."]}},
                "diagnostics": {},
            },
        )
        env = ws_api.dry_run_auth("MyIntegration", _VALID_AUTH_JSON)
        assert env["verdict"]["would_commit"] is False
        assert "fail" in env["verdict"]["reason"]

    def test_all_interpolated_structural_skip_yields_would_commit_true(
        self,
        monkeypatch: pytest.MonkeyPatch,
        mock_csv: list[dict],
    ) -> None:
        """ERROR_ALL_INTERPOLATED is the ONLY clean fallback: every auth is
        interpolated, so there is nothing to parity-test → would_commit=True.
        """
        monkeypatch.setattr(
            ws_api,
            "_run_auth_parity_for_set_auth",
            lambda **_k: {
                "error": {
                    "code": "ERROR_ALL_INTERPOLATED",
                    "message": "all auths are interpolated; nothing to test",
                    "exit_code": 12,
                },
            },
        )
        env = ws_api.dry_run_auth("MyIntegration", _VALID_AUTH_JSON)
        assert env["verdict"]["would_commit"] is True
        assert "structural skip" in env["verdict"]["reason"].lower()

    def test_no_baseclient_non_interpolated_yields_would_commit_false(
        self,
        monkeypatch: pytest.MonkeyPatch,
        mock_csv: list[dict],
    ) -> None:
        """AUTH-PARITY GATE STRICTNESS FIX: ERROR_NO_BASECLIENT means the
        analyzer could NOT parity-test a non-interpolated auth. It must now
        BLOCK (would_commit=False) instead of silently committing an
        untested secret-placement.
        """
        monkeypatch.setattr(
            ws_api,
            "_run_auth_parity_for_set_auth",
            lambda **_k: {
                "error": {
                    "code": "ERROR_NO_BASECLIENT",
                    "message": "integration does not subclass BaseClient",
                    "exit_code": 11,
                },
            },
        )
        env = ws_api.dry_run_auth("MyIntegration", _VALID_AUTH_JSON)
        assert env["verdict"]["would_commit"] is False
        assert "not parity-tested" in env["verdict"]["reason"].lower()
        # Surfaces the two valid resolutions for the operator.
        assert "interpolated: true" in env["verdict"]["reason"]
        assert "docker/env" in env["verdict"]["reason"]

    def test_apimodule_cannot_verify_non_interpolated_blocks(
        self,
        monkeypatch: pytest.MonkeyPatch,
        mock_csv: list[dict],
    ) -> None:
        """APIMODULE_INTEGRATION_CANNOT_VERIFY on a non-interpolated auth
        must BLOCK (would_commit=False) and map to a non-zero dry-run exit
        code.
        """
        monkeypatch.setattr(
            ws_api,
            "_run_auth_parity_for_set_auth",
            lambda **_k: {
                "error": {
                    "code": "APIMODULE_INTEGRATION_CANNOT_VERIFY",
                    "message": "Client subclasses MicrosoftApiModule",
                    "exit_code": 15,
                },
            },
        )
        env = ws_api.dry_run_auth("MyIntegration", _VALID_AUTH_JSON)
        assert env["verdict"]["would_commit"] is False
        assert ws_api.dry_run_exit_code(env) != 0

    def test_docker_unavailable_inconclusive_blocks(
        self,
        monkeypatch: pytest.MonkeyPatch,
        mock_csv: list[dict],
    ) -> None:
        """Docker/env unavailable surfaces as a per-connection
        ``inconclusive`` status. ``inconclusive`` is NOT in
        _PARITY_OK_STATUSES, so the gate must BLOCK (would_commit=False).
        """
        monkeypatch.setattr(
            ws_api,
            "_run_auth_parity_for_set_auth",
            lambda **_k: {
                "integration": "MyIntegration",
                "auth_parity": {
                    "primary": {"status": "inconclusive", "diffs": []},
                },
                "diagnostics": {},
            },
        )
        env = ws_api.dry_run_auth("MyIntegration", _VALID_AUTH_JSON)
        assert env["verdict"]["would_commit"] is False
        assert ws_api.dry_run_exit_code(env) != 0

    def test_integration_not_found_returns_would_commit_false(
        self,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        monkeypatch.setattr(ws_api, "load_csv", lambda: [])
        monkeypatch.setattr(
            ws_api,
            "save_csv",
            lambda _r: (_ for _ in ()).throw(AssertionError("must not write")),
        )
        parity_called = {"value": False}

        def _exploding_parity(**_kwargs):  # noqa: ANN003
            parity_called["value"] = True
            raise AssertionError("parity must not run after not-found")

        monkeypatch.setattr(
            ws_api, "_run_auth_parity_for_set_auth", _exploding_parity
        )
        env = ws_api.dry_run_auth("Nope", _VALID_AUTH_JSON)
        assert env["verdict"]["would_commit"] is False
        assert "not found" in env["verdict"]["reason"]
        assert parity_called["value"] is False


# ---------------------------------------------------------------------------
# 2) dry_run_exit_code — exit-code mapping (0/1/2/3)
# ---------------------------------------------------------------------------


class TestDryRunExitCodeMapping:
    def test_would_commit_returns_zero(self) -> None:
        env = {
            "dry_run": True,
            "integration_id": "X",
            "validator": {"passed": True},
            "seed_overlap": {"passed": True},
            "parity": {"auth_parity": {"c": {"status": "pass"}}},
            "verdict": {"would_commit": True, "reason": "ok"},
        }
        assert ws_api.dry_run_exit_code(env) == 0

    def test_seed_overlap_returns_two(self) -> None:
        env = {
            "dry_run": True,
            "integration_id": "X",
            "validator": {"passed": True},
            "seed_overlap": {
                "passed": False,
                "error": {
                    "code": "ERROR_SEED_AUTH_OVERLAP",
                    "message": "...",
                    "exit_code": 2,
                },
            },
            "parity": {"skipped": "..."},
            "verdict": {"would_commit": False, "reason": "ERROR_SEED_AUTH_OVERLAP"},
        }
        assert ws_api.dry_run_exit_code(env) == 2

    @pytest.mark.parametrize(
        "code",
        [
            "ERROR_FILES_LOOKUP",
            "ERROR_PARITY_IMPORT",
            "ERROR_PARITY_UNHANDLED",
            "ERROR_AUTH_NOT_JSON",
        ],
    )
    def test_infrastructure_failures_return_three(self, code: str) -> None:
        env = {
            "dry_run": True,
            "integration_id": "X",
            "validator": {"passed": True},
            "seed_overlap": {"passed": True},
            "parity": {"error": {"code": code, "message": "...", "exit_code": 3}},
            "verdict": {"would_commit": False, "reason": code},
        }
        assert ws_api.dry_run_exit_code(env) == 3

    def test_validator_fail_returns_one(self) -> None:
        env = {
            "dry_run": True,
            "integration_id": "X",
            "validator": {"passed": False, "errors": ["..."]},
            "seed_overlap": {"skipped": "..."},
            "parity": {"skipped": "..."},
            "verdict": {"would_commit": False, "reason": "validator failed"},
        }
        assert ws_api.dry_run_exit_code(env) == 1

    def test_parity_block_returns_one(self) -> None:
        env = {
            "dry_run": True,
            "integration_id": "X",
            "validator": {"passed": True},
            "seed_overlap": {"passed": True},
            "parity": {"auth_parity": {"c": {"status": "fail"}}},
            "verdict": {"would_commit": False, "reason": "1 connection(s) did not pass"},
        }
        assert ws_api.dry_run_exit_code(env) == 1


# ---------------------------------------------------------------------------
# 3) set_auth_exit_code — symmetric mapping for the real path
# ---------------------------------------------------------------------------


class TestSetAuthExitCodeMapping:
    def test_success_returns_zero(self) -> None:
        assert ws_api.set_auth_exit_code({"message": "ok", "current_step": "x"}) == 0

    def test_seed_overlap_returns_two(self) -> None:
        result = {
            "error": {
                "code": "ERROR_SEED_AUTH_OVERLAP",
                "message": "...",
                "exit_code": 2,
            },
        }
        assert ws_api.set_auth_exit_code(result) == 2

    @pytest.mark.parametrize(
        "code",
        [
            "ERROR_FILES_LOOKUP",
            "ERROR_PARITY_IMPORT",
            "ERROR_PARITY_UNHANDLED",
            "ERROR_AUTH_NOT_JSON",
        ],
    )
    def test_infra_failure_dict_error_returns_three(self, code: str) -> None:
        result = {
            "error": {"code": code, "message": "...", "exit_code": 3},
        }
        assert ws_api.set_auth_exit_code(result) == 3

    def test_infra_failure_via_parity_block_returns_three(self) -> None:
        """When the gate blocked with a string error but result['parity']
        carries an infra-code error, exit-3 still fires."""
        result = {
            "error": "Auth Details rejected — parity gate failed for 'X': ...",
            "parity": {
                "error": {
                    "code": "ERROR_PARITY_UNHANDLED",
                    "message": "...",
                    "exit_code": 3,
                },
            },
        }
        assert ws_api.set_auth_exit_code(result) == 3

    def test_generic_string_error_returns_one(self) -> None:
        result = {"error": "Integration 'X' not found."}
        assert ws_api.set_auth_exit_code(result) == 1

    def test_parity_block_string_error_returns_one(self) -> None:
        """Parity-block with no infra-code in result['parity'] → 1."""
        result = {
            "error": "Auth Details rejected — parity gate failed for 'X': ...",
            "parity": {"auth_parity": {"c": {"status": "fail"}}},
        }
        assert ws_api.set_auth_exit_code(result) == 1


# ---------------------------------------------------------------------------
# 4) cmd_set_auth — flag parsing, default formats, output dispatch
# ---------------------------------------------------------------------------


class TestParseSetAuthFlags:
    def test_no_flags_returns_defaults(self) -> None:
        remaining, dry, timeout, fmt = ws_cli._parse_set_auth_flags(["X", "{}"])
        assert remaining == ["X", "{}"]
        assert dry is False
        assert timeout is None
        assert fmt == ""

    def test_dry_run_flag(self) -> None:
        remaining, dry, _t, _f = ws_cli._parse_set_auth_flags(["X", "{}", "--dry-run"])
        assert remaining == ["X", "{}"]
        assert dry is True

    def test_timeout_equals(self) -> None:
        _r, _d, timeout, _f = ws_cli._parse_set_auth_flags(["X", "{}", "--timeout=120"])
        assert timeout == 120

    def test_timeout_space_form_rejected(self) -> None:
        with pytest.raises(SystemExit) as exc:
            ws_cli._parse_set_auth_flags(["X", "{}", "--timeout", "120"])
        assert exc.value.code == 1

    def test_format_equals_json(self) -> None:
        _r, _d, _t, fmt = ws_cli._parse_set_auth_flags(["X", "{}", "--format=json"])
        assert fmt == "json"

    def test_format_equals_text(self) -> None:
        _r, _d, _t, fmt = ws_cli._parse_set_auth_flags(["X", "{}", "--format=text"])
        assert fmt == "text"

    def test_format_space_form_rejected(self) -> None:
        with pytest.raises(SystemExit) as exc:
            ws_cli._parse_set_auth_flags(["X", "{}", "--format", "json"])
        assert exc.value.code == 1

    def test_unknown_format_value_rejected(self) -> None:
        with pytest.raises(SystemExit) as exc:
            ws_cli._parse_set_auth_flags(["X", "{}", "--format=xml"])
        assert exc.value.code == 1

    def test_invalid_timeout_value_rejected(self) -> None:
        with pytest.raises(SystemExit) as exc:
            ws_cli._parse_set_auth_flags(["X", "{}", "--timeout=abc"])
        assert exc.value.code == 1

    def test_non_positive_timeout_rejected(self) -> None:
        with pytest.raises(SystemExit) as exc:
            ws_cli._parse_set_auth_flags(["X", "{}", "--timeout=0"])
        assert exc.value.code == 1


# ---------------------------------------------------------------------------
# 5) CSV-untouched assertion — regression catch for accidental mutations
# ---------------------------------------------------------------------------


class TestCsvUntouchedByDryRun:
    """Load real CSV bytes before, run dry_run_auth, load after,
    assert byte-identical. This catches any accidental write/save
    that slipped through the test mocks.
    """

    def test_dry_run_does_not_mutate_real_csv(
        self,
        monkeypatch: pytest.MonkeyPatch,
        tmp_path,
    ) -> None:
        # Use a real CSV file (a tiny synthetic one) so we can compare
        # bytes before/after. Do NOT monkey-patch load_csv/save_csv;
        # let the real machinery touch the disk file (or not).
        from workflow_state import csv_io

        # Locate or create a synthetic minimal CSV in a temp dir.
        # The simplest path: monkey-patch BASE_DIR + the CSV path so
        # the real load_csv reads our tmp file.
        csv_path = tmp_path / "pipeline.csv"
        # Minimal header — we never actually parse step columns
        # because the parity gate is mocked out below.
        header = [
            "Integration ID",
            "Integration File Path",
            "Connector ID",
            "assignee",
            "Auth Details",
            "Params to Commands",
            "Params for test with default in code",
            "Shadowed Integration Commands",
            "Params to Capabilities",
            "generated manifest",
            "run manifest make validate",
            "write tests",
            "precommit/validate/unit tests passed",
            "param parity test passes",
            "code reviewed",
            "code merged",
        ]
        rows = [
            ",".join(header) + "\n",
            "MyIntegration,Packs/Fake/Integrations/Fake/Fake.yml,fake,,,,,,,,,,,,,\n",
        ]
        csv_path.write_text("".join(rows), encoding="utf-8")

        # Patch the module-level CSV path in csv_io to point at the tmp
        # file. The exact attribute name depends on csv_io internals;
        # we patch via monkeypatch.setattr on whatever the module
        # exposes.
        monkeypatch.setattr(csv_io, "CSV_PATH", str(csv_path), raising=False)
        # Also patch the package-level facade re-exports so load_csv()
        # inside api.py picks up the new path.
        import workflow_state as _ws
        monkeypatch.setattr(_ws, "CSV_PATH", str(csv_path), raising=False)

        # Mock the parity gate so we don't actually run docker/proxy.
        monkeypatch.setattr(
            ws_api,
            "_run_auth_parity_for_set_auth",
            lambda **_k: {
                "integration": "MyIntegration",
                "auth_parity": {"primary": {"status": "pass", "diffs": []}},
                "diagnostics": {},
            },
        )

        # Snapshot bytes BEFORE.
        before_bytes = csv_path.read_bytes()

        # Run dry-run.
        env = ws_api.dry_run_auth("MyIntegration", _VALID_AUTH_JSON)
        assert env["verdict"]["would_commit"] is True

        # Snapshot bytes AFTER.
        after_bytes = csv_path.read_bytes()

        # Bit-identical — no mutation allowed on the dry-run path.
        assert before_bytes == after_bytes, (
            "dry_run_auth() mutated the CSV file! This is a critical "
            "regression — dry-run MUST be read-only."
        )
