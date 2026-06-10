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
    """Pin the 6-key envelope and the per-branch payload.

    ALWAYS-INTERPOLATE GATE (2026-06-09): the dry-run no longer invokes
    ``_run_auth_parity_for_set_auth``; it forces ``interpolated: true`` onto
    every ``auth_types[]`` entry and short-circuits the parity test, so a
    schema-valid payload ALWAYS yields ``would_commit=True``. The only
    blocking branches that remain are schema-validation failure, seed-overlap,
    and integration-not-found — all of which run BEFORE the always-interpolate
    step.
    """

    def test_envelope_always_has_expected_keys(
        self,
        monkeypatch: pytest.MonkeyPatch,
        mock_csv: list[dict],
    ) -> None:
        env = ws_api.dry_run_auth("MyIntegration", _VALID_AUTH_JSON)
        assert set(env.keys()) == {
            "pass",
            "dry_run",
            "integration_id",
            "validator",
            "seed_overlap",
            "parity",
            "verdict",
        }
        assert env["dry_run"] is True
        assert env["integration_id"] == "MyIntegration"
        # Top-level `pass` mirrors verdict.would_commit.
        assert env["pass"] == env["verdict"]["would_commit"]

    def test_validator_failure_short_circuits_with_skip_markers(
        self,
        monkeypatch: pytest.MonkeyPatch,
        mock_csv: list[dict],
    ) -> None:
        env = ws_api.dry_run_auth("MyIntegration", "not valid json {")
        assert env["validator"]["passed"] is False
        assert env["validator"]["errors"]
        assert "skipped" in env["seed_overlap"]
        assert "skipped" in env["parity"]
        assert env["verdict"]["would_commit"] is False

    def test_seed_overlap_short_circuits_with_skip_marker(
        self,
        monkeypatch: pytest.MonkeyPatch,
        mock_csv: list[dict],
    ) -> None:
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

    def test_schema_valid_payload_always_commits(
        self,
        monkeypatch: pytest.MonkeyPatch,
        mock_csv: list[dict],
    ) -> None:
        """A schema-valid payload always clears the always-interpolate gate."""
        env = ws_api.dry_run_auth("MyIntegration", _VALID_AUTH_JSON)
        assert env["verdict"]["would_commit"] is True
        assert "interpolate" in env["verdict"]["reason"].lower()
        # The parity block is a structural-skip stub, not a parity result.
        assert "skipped" in env["parity"]

    def test_non_interpolated_payload_reports_forced_interpolation(
        self,
        monkeypatch: pytest.MonkeyPatch,
        mock_csv: list[dict],
    ) -> None:
        """A payload with no ``interpolated`` flag is forced to interpolated
        and the preview reports ``forced_interpolated: True``.
        """
        env = ws_api.dry_run_auth("MyIntegration", _VALID_AUTH_JSON)
        assert env["verdict"]["would_commit"] is True
        assert env["parity"].get("forced_interpolated") is True

    def test_already_interpolated_payload_reports_no_forcing(
        self,
        monkeypatch: pytest.MonkeyPatch,
        mock_csv: list[dict],
    ) -> None:
        """When every entry is already interpolated, nothing is rewritten and
        ``forced_interpolated`` is ``False`` (still committable).
        """
        already = (
            '{"auth_types":[{"type":"APIKey","name":"primary",'
            '"interpolated":true,"xsoar_param_map":{"api_key":"key"}}],'
            '"other_connection":[]}'
        )
        env = ws_api.dry_run_auth("MyIntegration", already)
        assert env["verdict"]["would_commit"] is True
        assert env["parity"].get("forced_interpolated") is False

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
        env = ws_api.dry_run_auth("Nope", _VALID_AUTH_JSON)
        assert env["verdict"]["would_commit"] is False
        assert "not found" in env["verdict"]["reason"]


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


# ---------------------------------------------------------------------------
# 6) _force_interpolated_auth_details — always-interpolate gate helper
# ---------------------------------------------------------------------------


class TestForceInterpolatedAuthDetails:
    """ALWAYS-INTERPOLATE GATE (2026-06-09): every auth_types[] entry must end
    up carrying ``interpolated: true`` before the cell is committed.
    """

    def test_sets_interpolated_true_on_every_entry(self) -> None:
        raw = (
            '{"auth_types":['
            '{"type":"APIKey","name":"a","xsoar_param_map":{"api_key":"key"}},'
            '{"type":"Plain","name":"b","xsoar_param_map":'
            '{"credentials.identifier":"username","credentials.password":"password"}}'
            '],"other_connection":[]}'
        )
        out, changed = ws_api._force_interpolated_auth_details(raw)
        payload = json.loads(out)
        assert changed is True
        assert all(e["interpolated"] is True for e in payload["auth_types"])

    def test_idempotent_when_already_interpolated(self) -> None:
        raw = (
            '{"auth_types":[{"type":"APIKey","name":"a","interpolated":true,'
            '"xsoar_param_map":{"api_key":"key"}}],"other_connection":[]}'
        )
        out, changed = ws_api._force_interpolated_auth_details(raw)
        assert changed is False
        assert out == raw  # unchanged string when nothing to force

    def test_overwrites_explicit_false(self) -> None:
        raw = (
            '{"auth_types":[{"type":"APIKey","name":"a","interpolated":false,'
            '"xsoar_param_map":{"api_key":"key"}}],"other_connection":[]}'
        )
        out, changed = ws_api._force_interpolated_auth_details(raw)
        payload = json.loads(out)
        assert changed is True
        assert payload["auth_types"][0]["interpolated"] is True

    def test_malformed_json_returns_unchanged(self) -> None:
        out, changed = ws_api._force_interpolated_auth_details("not json {")
        assert changed is False
        assert out == "not json {"

    def test_missing_auth_types_returns_unchanged(self) -> None:
        raw = '{"other_connection":[]}'
        out, changed = ws_api._force_interpolated_auth_details(raw)
        assert changed is False
        assert out == raw


class TestSetAuthForcesInterpolatedCommit:
    """The real ``set_integration_auth`` path persists the forced-interpolated
    payload (every entry carries ``interpolated: true``) without ever invoking
    the parity analyzer.
    """

    _AUTH_JSON = (
        '{"auth_types":[{"type":"APIKey","name":"primary",'
        '"xsoar_param_map":{"api_key":"key"}}],"other_connection":[]}'
    )

    def test_commit_persists_forced_interpolated_cell(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        committed: dict = {}

        row = {"Integration ID": "MyIntegration", "Auth Details": ""}
        monkeypatch.setattr(ws_api, "load_csv", lambda: [row])
        monkeypatch.setattr(ws_api, "save_csv", lambda _rows: None)

        # The parity analyzer must NEVER be called by the always-interpolate gate.
        def _exploding_parity(**_kwargs):  # noqa: ANN003
            raise AssertionError("parity analyzer must not be invoked")

        monkeypatch.setattr(
            ws_api, "_run_auth_parity_for_set_auth", _exploding_parity
        )

        # Capture what gets handed to the state machine for persistence.
        def _capture_apply(row, target, value, *, verb):  # noqa: ANN001
            committed["value"] = value
            return [], None

        monkeypatch.setattr(ws_api, "apply_step_action", _capture_apply)
        monkeypatch.setattr(ws_api, "current_step", lambda _row: None)

        result = ws_api.set_integration_auth("MyIntegration", self._AUTH_JSON)

        assert "error" not in result
        persisted = json.loads(committed["value"])
        assert all(e["interpolated"] is True for e in persisted["auth_types"])
        # The structural-skip stub is surfaced in the result.
        assert "skipped" in result["parity"]
        assert result["parity"].get("forced_interpolated") is True
