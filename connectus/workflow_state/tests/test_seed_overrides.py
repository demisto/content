"""Tests for the ``--seed-param`` plumbing added to ``set-auth``.

Covers three behaviors:

1. ``validate_seed_overrides_no_auth_overlap`` rejects keys that name
   a param already declared in the candidate ``Auth Details``.
2. :func:`set_integration_auth` returns the
   ``ERROR_SEED_AUTH_OVERLAP`` envelope **before** the parity gate
   runs when an overlap is detected.
3. :func:`cmd_set_auth` forwards repeatable ``--seed-param NAME=VALUE``
   arguments through to :func:`set_integration_auth` as a
   ``seed_overrides`` dict.

All tests use ``CONNECTUS_SKIP_AUTH_PARITY=1`` (or direct mocking) so
no actual parity run is invoked. The overlap rejection fires
**before** the parity gate, so the env-var bypass is irrelevant for
the overlap-positive cases.
"""
from __future__ import annotations

from unittest import mock

import pytest

from workflow_state import api as ws_api
from workflow_state import cli as ws_cli
from workflow_state.validators import validate_seed_overrides_no_auth_overlap


# ---------------------------------------------------------------------------
# 1) validate_seed_overrides_no_auth_overlap — pure-function tests
# ---------------------------------------------------------------------------


class TestValidateSeedOverridesNoAuthOverlap:
    """Pin overlap detection for the helper consumed by set_integration_auth."""

    def test_empty_overrides_returns_empty(self) -> None:
        assert validate_seed_overrides_no_auth_overlap({}, {}) == []
        assert validate_seed_overrides_no_auth_overlap(None, {}) == []  # type: ignore[arg-type]

    def test_empty_auth_details_returns_empty(self) -> None:
        # No auth-param projection set → no overlap possible.
        assert validate_seed_overrides_no_auth_overlap(
            {"foo": "x"}, {}
        ) == []

    def test_flat_key_overlapping_apikey_xsoar_param_map(self) -> None:
        """Flat ``api_key`` override overlaps with an ``APIKey``
        profile whose ``xsoar_param_map`` declares ``"api_key"``."""
        candidate = {
            "auth_types": [
                {
                    "type": "APIKey",
                    "name": "primary",
                    "xsoar_param_map": {"api_key": "key"},
                },
            ],
            "other_connection": [],
        }
        errors = validate_seed_overrides_no_auth_overlap(
            {"api_key": "real-key"}, candidate
        )
        assert len(errors) == 1
        err = errors[0]
        assert "'api_key'" in err
        assert "auth_types[].name='primary'" in err
        assert "xsoar_param_map" in err

    def test_flat_key_overlapping_other_connection(self) -> None:
        candidate = {
            "auth_types": [],
            "other_connection": ["url", "fetch_limit"],
        }
        errors = validate_seed_overrides_no_auth_overlap(
            {"url": "https://x"}, candidate
        )
        assert len(errors) == 1
        assert "'url'" in errors[0]
        assert "other_connection" in errors[0]

    def test_dotted_leaf_key_overlapping_plain_credentials(self) -> None:
        """``credentials.password`` collapses to ``credentials`` for
        the overlap check (mirroring the auth-param projection rule)."""
        candidate = {
            "auth_types": [
                {
                    "type": "Plain",
                    "name": "user_creds",
                    "xsoar_param_map": {
                        "credentials.identifier": "username",
                        "credentials.password": "password",
                    },
                },
            ],
            "other_connection": [],
        }
        errors = validate_seed_overrides_no_auth_overlap(
            {"credentials.password": "secret"}, candidate
        )
        assert len(errors) == 1
        err = errors[0]
        assert "'credentials.password'" in err
        # The parent param id ('credentials') is named in the message.
        assert "'credentials'" in err
        # The offending auth_types entry is cited verbatim.
        assert "user_creds" in err

    def test_non_overlapping_keys_are_silently_passed(self) -> None:
        """Keys that don't collide with any auth-param produce no errors."""
        candidate = {
            "auth_types": [
                {
                    "type": "APIKey",
                    "name": "primary",
                    "xsoar_param_map": {"api_key": "key"},
                },
            ],
            "other_connection": ["url"],
        }
        # ``certificate_thumbprint`` and ``jwt_secret`` are not in the
        # projection — both should be allowed through.
        assert validate_seed_overrides_no_auth_overlap(
            {
                "certificate_thumbprint": "A" * 40,
                "jwt_secret": "real-jwt-format-12345",
            },
            candidate,
        ) == []

    def test_multiple_overlap_keys_collected(self) -> None:
        """One error string per offending key — both surfaced."""
        candidate = {
            "auth_types": [
                {
                    "type": "APIKey",
                    "name": "primary",
                    "xsoar_param_map": {"api_key": "key"},
                },
            ],
            "other_connection": ["url"],
        }
        errors = validate_seed_overrides_no_auth_overlap(
            {"api_key": "x", "url": "https://x"}, candidate
        )
        assert len(errors) == 2
        joined = "\n".join(errors)
        assert "'api_key'" in joined
        assert "'url'" in joined


# ---------------------------------------------------------------------------
# 2) set_integration_auth — overlap rejection envelope (parity NEVER invoked)
# ---------------------------------------------------------------------------


class _FakeRow(dict):
    """Minimal CSV-row-shape stand-in for set_integration_auth tests."""


@pytest.fixture
def fake_row() -> dict:
    return _FakeRow({"Integration ID": "MyIntegration", "Auth Details": ""})


@pytest.fixture
def mock_csv(monkeypatch: pytest.MonkeyPatch, fake_row: dict) -> list[dict]:
    """Mock load_csv() inside workflow_state.api so set_integration_auth
    sees exactly one row, and save_csv() is a no-op.
    """
    rows = [fake_row]
    monkeypatch.setattr(ws_api, "load_csv", lambda: rows)
    monkeypatch.setattr(ws_api, "save_csv", lambda _rows: None)
    return rows


class TestSetIntegrationAuthSeedOverlap:
    """The overlap check fires BEFORE the parity gate. Asserted by
    monkey-patching :func:`_run_auth_parity_for_set_auth` to raise on
    call — when the overlap rejection fires first, the patched
    function is never reached.
    """

    _AUTH_JSON = (
        '{"auth_types":[{"type":"APIKey","name":"primary",'
        '"xsoar_param_map":{"api_key":"key"}}],"other_connection":[]}'
    )

    def test_flat_overlap_returns_error_envelope_without_invoking_parity(
        self, monkeypatch: pytest.MonkeyPatch, mock_csv: list[dict]
    ) -> None:
        parity_called = {"value": False}

        def _exploding_parity(**_kwargs):  # noqa: ANN003
            parity_called["value"] = True
            raise AssertionError("parity gate should NOT have been invoked")

        monkeypatch.setattr(
            ws_api, "_run_auth_parity_for_set_auth", _exploding_parity
        )

        result = ws_api.set_integration_auth(
            "MyIntegration",
            self._AUTH_JSON,
            seed_overrides={"api_key": "real-key"},
        )

        assert parity_called["value"] is False
        assert "error" in result
        err = result["error"]
        assert isinstance(err, dict)
        assert err.get("code") == "ERROR_SEED_AUTH_OVERLAP"
        assert err.get("exit_code") == 2
        msg = err.get("message") or ""
        assert "api_key" in msg
        assert "auth_types[].name='primary'" in msg

    def test_dotted_leaf_overlap_names_the_auth_types_entry(
        self, monkeypatch: pytest.MonkeyPatch, mock_csv: list[dict]
    ) -> None:
        parity_called = {"value": False}

        def _exploding_parity(**_kwargs):  # noqa: ANN003
            parity_called["value"] = True
            raise AssertionError("parity gate should NOT have been invoked")

        monkeypatch.setattr(
            ws_api, "_run_auth_parity_for_set_auth", _exploding_parity
        )

        plain_json = (
            '{"auth_types":[{"type":"Plain","name":"user_creds",'
            '"xsoar_param_map":{"credentials.identifier":"username",'
            '"credentials.password":"password"}}],"other_connection":[]}'
        )

        result = ws_api.set_integration_auth(
            "MyIntegration",
            plain_json,
            seed_overrides={"credentials.password": "secret"},
        )

        assert parity_called["value"] is False
        assert "error" in result
        err = result["error"]
        assert isinstance(err, dict)
        assert err.get("code") == "ERROR_SEED_AUTH_OVERLAP"
        msg = err.get("message") or ""
        assert "credentials.password" in msg
        # The auth_types[].name is cited verbatim.
        assert "user_creds" in msg

    def test_non_overlapping_seed_overrides_are_passed_to_parity(
        self, monkeypatch: pytest.MonkeyPatch, mock_csv: list[dict]
    ) -> None:
        """Overrides that don't overlap reach the parity gate function
        unchanged. We only assert the kwargs the parity gate sees —
        not the downstream CSV write, because the test fixture row
        intentionally has no upstream-step progress (assignee not set
        etc.) so the state-machine apply_step_action would reject. The
        parity-gate forwarding is the contract under test here; the
        downstream cascade is covered elsewhere.
        """
        captured: dict = {}

        def _capturing_parity(**kwargs):  # noqa: ANN003
            captured.update(kwargs)
            return {"integration": "MyIntegration", "auth_parity": {}, "diagnostics": {}}

        monkeypatch.setattr(
            ws_api, "_run_auth_parity_for_set_auth", _capturing_parity
        )

        ws_api.set_integration_auth(
            "MyIntegration",
            self._AUTH_JSON,
            seed_overrides={"certificate_thumbprint": "A" * 40},
        )

        # No overlap → parity was invoked with our overrides intact.
        assert captured.get("seed_overrides") == {"certificate_thumbprint": "A" * 40}


# ---------------------------------------------------------------------------
# 3) cmd_set_auth — CLI argument forwarding
# ---------------------------------------------------------------------------


class TestCmdSetAuthForwardsSeedParam:
    """Pin that ``cmd_set_auth`` parses repeatable ``--seed-param`` flags
    and forwards the parsed dict to :func:`set_integration_auth` as
    ``seed_overrides=``.
    """

    def test_forwards_single_seed_param(
        self, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture
    ) -> None:
        captured: dict = {}

        def _capturing_set_auth(integration_id, raw, *, seed_overrides=None):  # noqa: ANN001
            captured["integration_id"] = integration_id
            captured["raw"] = raw
            captured["seed_overrides"] = seed_overrides
            return {
                "message": "Set 'Auth Details' for 'MyIntegration'.",
                "current_step": None,
                "parity": {"skipped": "test"},
            }

        monkeypatch.setattr(ws_cli, "set_integration_auth", _capturing_set_auth)

        ws_cli.cmd_set_auth([
            "MyIntegration",
            '{"auth_types":[],"other_connection":[]}',
            "--seed-param", "certificate_thumbprint=" + ("A" * 40),
        ])

        assert captured["integration_id"] == "MyIntegration"
        assert captured["seed_overrides"] == {
            "certificate_thumbprint": "A" * 40,
        }

    def test_forwards_multiple_seed_params(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        captured: dict = {}

        def _capturing_set_auth(integration_id, raw, *, seed_overrides=None):  # noqa: ANN001
            captured["seed_overrides"] = seed_overrides
            return {"message": "ok", "current_step": None, "parity": {}}

        monkeypatch.setattr(ws_cli, "set_integration_auth", _capturing_set_auth)

        ws_cli.cmd_set_auth([
            "MyIntegration",
            '{"auth_types":[],"other_connection":[]}',
            "--seed-param", "jwt_secret=real-secret-1234",
            "--seed-param", "oidc_issuer=https://issuer.example.com",
            "--seed-param", "credentials.password=p@ssword-12",
        ])

        assert captured["seed_overrides"] == {
            "jwt_secret": "real-secret-1234",
            "oidc_issuer": "https://issuer.example.com",
            "credentials.password": "p@ssword-12",
        }

    def test_no_seed_param_forwards_none(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        captured: dict = {}

        def _capturing_set_auth(integration_id, raw, *, seed_overrides=None):  # noqa: ANN001
            captured["seed_overrides"] = seed_overrides
            return {"message": "ok", "current_step": None, "parity": {}}

        monkeypatch.setattr(ws_cli, "set_integration_auth", _capturing_set_auth)

        ws_cli.cmd_set_auth([
            "MyIntegration",
            '{"auth_types":[],"other_connection":[]}',
        ])

        assert captured["seed_overrides"] is None

    def test_duplicate_seed_param_name_rejected_exit_2(
        self, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture
    ) -> None:
        # set_integration_auth should NEVER be called when the CLI
        # itself rejects the args.
        called = {"value": False}

        def _explode(*_a, **_kw):  # noqa: ANN003
            called["value"] = True
            raise AssertionError("set_integration_auth should not be invoked")

        monkeypatch.setattr(ws_cli, "set_integration_auth", _explode)

        with pytest.raises(SystemExit) as exc_info:
            ws_cli.cmd_set_auth([
                "MyIntegration",
                '{"auth_types":[],"other_connection":[]}',
                "--seed-param", "foo=1",
                "--seed-param", "foo=2",
            ])
        assert exc_info.value.code == 2
        assert called["value"] is False
        captured_err = capsys.readouterr().err
        assert "more than once" in captured_err

    def test_malformed_seed_param_missing_equals_rejected_exit_2(
        self, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture
    ) -> None:
        called = {"value": False}

        def _explode(*_a, **_kw):  # noqa: ANN003
            called["value"] = True
            raise AssertionError("set_integration_auth should not be invoked")

        monkeypatch.setattr(ws_cli, "set_integration_auth", _explode)

        with pytest.raises(SystemExit) as exc_info:
            ws_cli.cmd_set_auth([
                "MyIntegration",
                '{"auth_types":[],"other_connection":[]}',
                "--seed-param", "foo_without_equals",
            ])
        assert exc_info.value.code == 2
        assert called["value"] is False
        captured_err = capsys.readouterr().err
        assert "missing '=' separator" in captured_err


# ---------------------------------------------------------------------------
# 4) _evaluate_parity_for_set_auth — parity gate strictness (FIXES-TODO #1)
# ---------------------------------------------------------------------------


class TestEvaluateParityForSetAuth:
    """Pin the parity gate's accept/reject decisions.

    Per FIXES-TODO #1 (LOCKED 2026-05-31): ``inconclusive`` per-connection
    statuses are NOT permissive anymore — they reject the candidate. The
    rejection diagnostic surfaces failure_codes + the last ~10 lines of
    stderr_excerpt per the cross-cutting Hints policy (no prescription
    text in the tool; that lives in the skill).
    """

    def test_inconclusive_now_rejects(self) -> None:
        result = {
            "auth_parity": {
                "api_key": {"status": "inconclusive", "commands": {}, "diagnostics": {}},
            },
        }
        gate = ws_api._evaluate_parity_for_set_auth(result)
        assert gate["allow"] is False
        assert "inconclusive" in gate["reason"]

    def test_pass_still_allows(self) -> None:
        result = {
            "auth_parity": {
                "api_key": {"status": "pass", "commands": {}, "diagnostics": {}},
            },
        }
        gate = ws_api._evaluate_parity_for_set_auth(result)
        assert gate["allow"] is True

    def test_skipped_passthrough_still_allows(self) -> None:
        result = {
            "auth_parity": {
                "secret_bag": {
                    "status": "skipped_passthrough", "commands": {}, "diagnostics": {},
                },
            },
        }
        gate = ws_api._evaluate_parity_for_set_auth(result)
        assert gate["allow"] is True

    def test_interpolated_structural_skip_codes_still_allow(self) -> None:
        # AUTH-PARITY GATE STRICTNESS FIX (2026-06-03): only the interpolated
        # codes remain in _PARITY_STRUCTURAL_SKIP_CODES; they are the ONLY
        # clean fallback (nothing to parity-test).
        for code in [
            "ERROR_ALL_INTERPOLATED",
            "ERROR_CONNECTION_INTERPOLATED",
        ]:
            result = {"error": {"code": code, "message": f"skip via {code}", "exit_code": 12}}
            gate = ws_api._evaluate_parity_for_set_auth(result)
            assert gate["allow"] is True, (
                f"interpolated structural skip {code} should allow but got: {gate}"
            )

    def test_cannot_verify_codes_now_block(self) -> None:
        # AUTH-PARITY GATE STRICTNESS FIX (2026-06-03): codes that mean "the
        # analyzer could not test this integration" no longer auto-pass; an
        # untested, non-interpolated auth must BLOCK.
        for code in [
            "ERROR_NON_PYTHON",
            "ERROR_NO_BASECLIENT",
            "APIMODULE_INTEGRATION_CANNOT_VERIFY",
            "ERROR_INTEGRATION_REJECTS_HTTP",
            "MULTI_SECRET_PASSTHROUGH",
        ]:
            result = {"error": {"code": code, "message": f"cannot verify {code}", "exit_code": 11}}
            gate = ws_api._evaluate_parity_for_set_auth(result)
            assert gate["allow"] is False, (
                f"cannot-verify code {code} must block but got: {gate}"
            )
            # Operator guidance is surfaced in the reason.
            assert "interpolated: true" in gate["reason"]
            assert "docker/env" in gate["reason"]

    def test_rejection_diagnostic_surfaces_failure_codes(self) -> None:
        """Per Hints policy: the diagnostic includes failure_codes from diffs."""
        result = {
            "auth_parity": {
                "api_key": {
                    "status": "inconclusive",
                    "commands": {"test-module": {"status": "inconclusive"}},
                    "diagnostics": {
                        "commands": {
                            "test-module": {
                                "diffs": [
                                    {"failure_code": "RUN_FAILED_NEW",
                                     "sentinel": "", "old_locations": [], "new_locations": []},
                                ],
                                "old_run": {"status": "crashed",
                                            "captured_request_count": 0,
                                            "locations": {},
                                            "stderr_excerpt": "old stderr line 1\nold stderr line 2"},
                                "new_run": {"status": "crashed",
                                            "captured_request_count": 0,
                                            "locations": {},
                                            "stderr_excerpt": (
                                                "Traceback (most recent call last):\n"
                                                "  File \"x.py\", line 1, in <module>\n"
                                                "KeyError: 'identifier'"
                                            )},
                            },
                        },
                    },
                },
            },
        }
        gate = ws_api._evaluate_parity_for_set_auth(result)
        assert gate["allow"] is False
        assert "RUN_FAILED_NEW" in gate["reason"]
        # The last lines of the stderr excerpt should be present
        assert "KeyError" in gate["reason"]

    def test_rejection_diagnostic_has_no_prescription_text(self) -> None:
        """The diagnostic describes; it does not prescribe (Hints policy
        cross-cutting #1). When multiple valid fixes exist, prescription
        lives in the skill, not the tool."""
        result = {
            "auth_parity": {
                "api_key": {
                    "status": "fail",
                    "commands": {"test-module": {"status": "fail"}},
                    "diagnostics": {
                        "commands": {
                            "test-module": {
                                "diffs": [
                                    {"failure_code": "WRONG_LOCATION",
                                     "sentinel": "k1",
                                     "old_locations": ["header:x-api-key"],
                                     "new_locations": ["header:authorization:bearer"]},
                                ],
                                "old_run": {"status": "ok"},
                                "new_run": {"status": "ok"},
                            },
                        },
                    },
                },
            },
        }
        gate = ws_api._evaluate_parity_for_set_auth(result)
        assert gate["allow"] is False
        # Sanity: no prescription verbs like "should", "must", "use", "add"
        # in the diagnostic. The tool reports facts; the skill prescribes.
        prescription_words = (
            "you should ", "you must ", "please ", "consider ",
        )
        lowered = gate["reason"].lower()
        for word in prescription_words:
            assert word not in lowered, (
                f"prescription word {word!r} leaked into diagnostic: {gate['reason']}"
            )


# ---------------------------------------------------------------------------
# 5) _evaluate_parity_for_set_auth — REAL diagnostics shape (sweep F3/F4)
# ---------------------------------------------------------------------------


class TestEvaluateParityRealDiagnosticsShape:
    """Regression for sweep finding F3 (2026-06-03).

    The real ``check_auth_parity`` result carries per-command diagnostics
    at the TOP LEVEL (``result["diagnostics"][conn]["commands"]``), NOT
    nested inside ``result["auth_parity"][conn]["diagnostics"]`` (which is
    the shape the older ``TestEvaluateParityForSetAuth`` fixtures used, and
    why the no-op went unnoticed). These tests use the production shape so a
    future regression to the wrong data path is caught.
    """

    def _real_shape_result(self, conn: str, failure_codes: list[str]) -> dict:
        return {
            "integration": "X",
            "auth_parity": {
                conn: {
                    "status": "inconclusive",
                    "commands": {"test-module": {"status": "inconclusive"}},
                },
            },
            "diagnostics": {
                conn: {
                    "sentinels": {},
                    "commands": {
                        "test-module": {
                            "status": "inconclusive",
                            "diffs": [
                                {"failure_code": fc, "sentinel": "",
                                 "old_locations": [], "new_locations": []}
                                for fc in failure_codes
                            ],
                            "old_run": {"status": "no_requests",
                                        "captured_request_count": 0,
                                        "locations": {}, "stderr_excerpt": ""},
                            "new_run": {"status": "no_requests",
                                        "captured_request_count": 0,
                                        "locations": {}, "stderr_excerpt": ""},
                        },
                    },
                },
            },
        }

    def test_failure_codes_surface_from_top_level_diagnostics(self) -> None:
        result = self._real_shape_result(
            "credentials", ["MISSING_IN_BOTH", "NO_REQUESTS_CAPTURED"]
        )
        gate = ws_api._evaluate_parity_for_set_auth(result)
        assert gate["allow"] is False
        # The whole point of F3: these MUST appear in the reason now.
        assert "MISSING_IN_BOTH" in gate["reason"]
        assert "NO_REQUESTS_CAPTURED" in gate["reason"]

    def test_no_requests_captured_emits_descriptive_note(self) -> None:
        """F4: a both-runs-zero-requests case gets a description-only note
        that points at the skill (no prescription)."""
        result = self._real_shape_result(
            "credentials", ["NO_REQUESTS_CAPTURED"]
        )
        gate = ws_api._evaluate_parity_for_set_auth(result)
        assert gate["allow"] is False
        reason = gate["reason"].lower()
        assert "no http requests" in reason or "observed no" in reason
        assert "inconclusive" in reason
        # Points to skill, does not prescribe.
        assert "§1.9" in gate["reason"] or "§1.12" in gate["reason"]
        for word in ("you should ", "you must ", "please ", "consider "):
            assert word not in reason

    def test_ucp_strip_note_still_fires_with_real_shape(self) -> None:
        result = self._real_shape_result(
            "credentials", ["UCP_STRIP_CRASHED_UNCONDITIONAL_READ"]
        )
        gate = ws_api._evaluate_parity_for_set_auth(result)
        assert gate["allow"] is False
        assert "UCP_STRIP_CRASHED_UNCONDITIONAL_READ" in gate["reason"]
        assert "§1.12" in gate["reason"]

    def test_crashed_run_stderr_surfaces_with_real_shape(self) -> None:
        result = {
            "integration": "X",
            "auth_parity": {
                "credentials": {
                    "status": "inconclusive",
                    "commands": {"test-module": {"status": "inconclusive"}},
                },
            },
            "diagnostics": {
                "credentials": {
                    "commands": {
                        "test-module": {
                            "diffs": [{"failure_code": "RUN_FAILED_NEW",
                                       "sentinel": "", "old_locations": [],
                                       "new_locations": []}],
                            "old_run": {"status": "ok"},
                            "new_run": {"status": "crashed",
                                        "stderr_excerpt": "Traceback...\nKeyError: 'identifier'"},
                        },
                    },
                },
            },
        }
        gate = ws_api._evaluate_parity_for_set_auth(result)
        assert gate["allow"] is False
        assert "RUN_FAILED_NEW" in gate["reason"]
        assert "KeyError" in gate["reason"]
