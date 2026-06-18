"""Tests for self-executing checkpoint gates (:mod:`workflow_state.gates`).

Covers:

1. The gate registry (``GATES``, ``known_gate_names``, ``is_known_gate``)
   and the ``run_gate`` runner with a mocked subprocess (pass / fail /
   timeout / unknown-gate / spawn-error).
2. The config loader parsing the per-step ``gate:`` key, including
   rejection of an unknown gate name and a ``gate`` on a non-checkpoint
   step.
3. ``markpass_integration_step`` running the gate and rejecting the
   markpass unless the gate passes — with NO bypass.
"""
from __future__ import annotations

import subprocess
from unittest import mock

import pytest

from workflow_state import api as ws_api
from workflow_state import gates
from workflow_state.config_loader import (
    _reset_config_for_testing,
    load_config,
)
from workflow_state.exceptions import ConfigLoadError


@pytest.fixture(autouse=True)
def _reset_singleton():
    _reset_config_for_testing()
    yield
    _reset_config_for_testing()


# ---------------------------------------------------------------------------
# 1) Registry + runner
# ---------------------------------------------------------------------------

class TestRegistry:
    def test_precommit_gate_registered(self) -> None:
        assert gates.is_known_gate("precommit")
        assert "precommit" in gates.known_gate_names()

    def test_make_validate_gate_registered(self) -> None:
        assert gates.is_known_gate("make_validate")
        assert "make_validate" in gates.known_gate_names()

    def test_handler_param_coverage_gate_registered(self) -> None:
        assert gates.is_known_gate("handler_param_coverage")
        assert "handler_param_coverage" in gates.known_gate_names()

    def test_param_parity_gate_registered(self) -> None:
        # param_parity is now ACTIVE — it runs deploy_and_test.py (live
        # deploy + param-parity) and is registered in the GATES registry.
        assert gates.is_known_gate("param_parity")
        assert "param_parity" in gates.known_gate_names()

    def test_no_bypass_helper_exists(self) -> None:
        # There must be no env-var bypass for checkpoint gates.
        assert not hasattr(gates, "gate_skipped_via_env")


class TestRunGate:
    def test_pass_on_exit_zero(self) -> None:
        completed = subprocess.CompletedProcess(
            args=["demisto-sdk"], returncode=0, stdout="ok", stderr=""
        )
        with mock.patch.object(gates.subprocess, "run", return_value=completed) as m:
            verdict = gates.run_gate("precommit", "/abs/dir", "MyInt")
        assert verdict["allow"] is True
        assert verdict["exit_code"] == 0
        assert verdict["gate"] == "precommit"
        # argv targets the integration dir.
        called_argv = m.call_args.args[0]
        assert called_argv == ["demisto-sdk", "pre-commit", "-i", "/abs/dir"]

    def test_make_validate_argv_and_cwd(self, monkeypatch) -> None:
        # The make_validate gate ignores the integration dir and runs
        # `make validate` from the ConnectUs repo root.
        monkeypatch.setenv(gates._CONNECTUS_REPO_ENV, "/some/connectus/repo")
        completed = subprocess.CompletedProcess(
            args=["make"], returncode=0, stdout="all good", stderr=""
        )
        with mock.patch.object(gates.subprocess, "run", return_value=completed) as m:
            verdict = gates.run_gate("make_validate", "/abs/integration/dir", "MyInt")
        assert verdict["allow"] is True
        assert verdict["gate"] == "make_validate"
        # argv is `make validate`, NOT keyed off the integration dir.
        assert m.call_args.args[0] == ["make", "validate"]
        # cwd is the ConnectUs repo (from the env override), not abs_dir.
        assert m.call_args.kwargs["cwd"] == "/some/connectus/repo"

    def test_make_validate_default_repo_is_content_sibling(self, monkeypatch) -> None:
        # With no override, the ConnectUs repo resolves to a sibling of the
        # content repo named `unified-connectors-content`.
        monkeypatch.delenv(gates._CONNECTUS_REPO_ENV, raising=False)
        resolved = gates._connectus_repo_root()
        import os
        parent = os.path.dirname(gates._repo_root())
        assert resolved == os.path.join(parent, "unified-connectors-content")
        assert os.path.basename(resolved) == "unified-connectors-content"

    def test_handler_param_coverage_argv(self, monkeypatch) -> None:
        # The handler_param_coverage gate runs the standalone coverage
        # script with --handler-path and --integration-yml resolved from
        # the pipeline CSV. Stub the resolvers so the argv is deterministic
        # without touching the real CSV / connector repo.
        monkeypatch.setattr(
            gates, "_handler_dir_abs", lambda iid: "/connectus/repo/connectors/c/components/handlers/xsoar-myint"
        )
        monkeypatch.setattr(
            gates, "_integration_yml_abs", lambda iid: "/content/Packs/P/Integrations/MyInt/MyInt.yml"
        )
        completed = subprocess.CompletedProcess(
            args=["python3"], returncode=0, stdout="PASS", stderr=""
        )
        with mock.patch.object(gates.subprocess, "run", return_value=completed) as m:
            verdict = gates.run_gate("handler_param_coverage", "/abs/integration/dir", "MyInt")
        assert verdict["allow"] is True
        assert verdict["gate"] == "handler_param_coverage"
        argv = m.call_args.args[0]
        # Script path + both resolved args are present, in order.
        assert argv[0] == gates.sys.executable
        assert argv[1] == gates._HANDLER_PARAM_COVERAGE_SCRIPT
        assert "--handler-path" in argv
        assert "--integration-yml" in argv
        assert argv[argv.index("--handler-path") + 1] == (
            "/connectus/repo/connectors/c/components/handlers/xsoar-myint"
        )
        assert argv[argv.index("--integration-yml") + 1] == (
            "/content/Packs/P/Integrations/MyInt/MyInt.yml"
        )

    def test_param_parity_argv_and_cwd(self, monkeypatch) -> None:
        # The param_parity gate runs deploy_and_test.py with the integration
        # id, from the content repo root. argv must be EXACTLY:
        #   [sys.executable, _DEPLOY_AND_TEST_SCRIPT, "--integration-id", iid]
        monkeypatch.setattr(gates, "_repo_root", lambda: "/content/repo")
        completed = subprocess.CompletedProcess(
            args=["python3"], returncode=0, stdout="PASS", stderr=""
        )
        with mock.patch.object(gates.subprocess, "run", return_value=completed) as m:
            verdict = gates.run_gate("param_parity", "/abs/integration/dir", "MyInt")
        assert verdict["allow"] is True
        assert verdict["gate"] == "param_parity"
        argv = m.call_args.args[0]
        assert argv == [
            gates.sys.executable,
            gates._DEPLOY_AND_TEST_SCRIPT,
            "--integration-id",
            "MyInt",
        ]
        # cwd is the content repo root, not abs_dir.
        assert m.call_args.kwargs["cwd"] == "/content/repo"

    def test_param_parity_pass_on_exit_zero(self) -> None:
        completed = subprocess.CompletedProcess(
            args=["python3"], returncode=0, stdout="parity ok", stderr=""
        )
        with mock.patch.object(gates.subprocess, "run", return_value=completed):
            verdict = gates.run_gate("param_parity", "/abs/dir", "MyInt")
        assert verdict["allow"] is True
        assert verdict["exit_code"] == 0
        assert verdict["gate"] == "param_parity"

    @pytest.mark.parametrize("exit_code", [10, 11, 20, 21, 30, 40, 7])
    def test_param_parity_fail_on_each_nonzero_exit(self, exit_code) -> None:
        # Every non-zero exit (parity fail 10, blocked 11, deploy 20/21, lock
        # busy 30, preflight 40, and any other e.g. 7) rejects the markpass.
        # The wrapper exit code propagates and the output tail is surfaced.
        completed = subprocess.CompletedProcess(
            args=["python3"],
            returncode=exit_code,
            stdout="some stdout tail",
            stderr=f"FAILED with code {exit_code}",
        )
        with mock.patch.object(gates.subprocess, "run", return_value=completed):
            verdict = gates.run_gate("param_parity", "/abs/dir", "MyInt")
        assert verdict["allow"] is False
        assert verdict["exit_code"] == exit_code
        assert f"exited {exit_code}" in verdict["reason"]
        assert verdict["stdout_tail"] == "some stdout tail"
        assert verdict["stderr_tail"] == f"FAILED with code {exit_code}"

    def test_param_parity_no_skip_envs_plain_argv(self, monkeypatch) -> None:
        # With BOTH deploy-scope env vars UNSET, the param_parity gate builds
        # the plain argv with NO skip flags appended.
        monkeypatch.delenv(gates._PARITY_SKIP_CONNECTOR_ENV, raising=False)
        monkeypatch.delenv(gates._PARITY_SKIP_BASE_PACK_ENV, raising=False)
        completed = subprocess.CompletedProcess(
            args=["python3"], returncode=0, stdout="PASS", stderr=""
        )
        with mock.patch.object(gates.subprocess, "run", return_value=completed) as m:
            verdict = gates.run_gate("param_parity", "/abs/dir", "MyInt")
        assert verdict["allow"] is True
        argv = m.call_args.args[0]
        assert argv == [
            gates.sys.executable,
            gates._DEPLOY_AND_TEST_SCRIPT,
            "--integration-id",
            "MyInt",
        ]
        assert "--skip-connector-deploy" not in argv
        assert "--skip-base-pack" not in argv

    def test_param_parity_skip_connector_env_appends_flag(self, monkeypatch) -> None:
        # CONNECTUS_PARITY_SKIP_CONNECTOR=1 appends --skip-connector-deploy
        # ONLY (NOT --skip-base-pack).
        monkeypatch.setenv(gates._PARITY_SKIP_CONNECTOR_ENV, "1")
        monkeypatch.delenv(gates._PARITY_SKIP_BASE_PACK_ENV, raising=False)
        completed = subprocess.CompletedProcess(
            args=["python3"], returncode=0, stdout="PASS", stderr=""
        )
        with mock.patch.object(gates.subprocess, "run", return_value=completed) as m:
            verdict = gates.run_gate("param_parity", "/abs/dir", "MyInt")
        assert verdict["allow"] is True
        argv = m.call_args.args[0]
        assert "--skip-connector-deploy" in argv
        assert "--skip-base-pack" not in argv
        # The integration id is still present.
        assert argv[argv.index("--integration-id") + 1] == "MyInt"

    def test_param_parity_skip_base_pack_env_appends_flag(self, monkeypatch) -> None:
        # CONNECTUS_PARITY_SKIP_BASE_PACK=1 appends --skip-base-pack ONLY
        # (NOT --skip-connector-deploy).
        monkeypatch.setenv(gates._PARITY_SKIP_BASE_PACK_ENV, "1")
        monkeypatch.delenv(gates._PARITY_SKIP_CONNECTOR_ENV, raising=False)
        completed = subprocess.CompletedProcess(
            args=["python3"], returncode=0, stdout="PASS", stderr=""
        )
        with mock.patch.object(gates.subprocess, "run", return_value=completed) as m:
            verdict = gates.run_gate("param_parity", "/abs/dir", "MyInt")
        assert verdict["allow"] is True
        argv = m.call_args.args[0]
        assert "--skip-base-pack" in argv
        assert "--skip-connector-deploy" not in argv
        assert argv[argv.index("--integration-id") + 1] == "MyInt"

    def test_param_parity_both_skip_envs_append_both_flags(self, monkeypatch) -> None:
        # Both env vars set → BOTH skip flags appended, still with the id.
        monkeypatch.setenv(gates._PARITY_SKIP_CONNECTOR_ENV, "1")
        monkeypatch.setenv(gates._PARITY_SKIP_BASE_PACK_ENV, "1")
        completed = subprocess.CompletedProcess(
            args=["python3"], returncode=0, stdout="PASS", stderr=""
        )
        with mock.patch.object(gates.subprocess, "run", return_value=completed) as m:
            verdict = gates.run_gate("param_parity", "/abs/dir", "MyInt")
        assert verdict["allow"] is True
        argv = m.call_args.args[0]
        assert "--skip-connector-deploy" in argv
        assert "--skip-base-pack" in argv
        assert argv[argv.index("--integration-id") + 1] == "MyInt"

    def test_param_parity_skip_envs_do_not_change_verdict(self, monkeypatch) -> None:
        # The deploy-scope env vars NEVER affect the pass/fail verdict. With a
        # skip env set AND a NON-zero subprocess exit (10 = parity fail), the
        # verdict is still allow=False; with exit 0 it is allow=True. The skip
        # env does not turn a failure into a pass.
        monkeypatch.setenv(gates._PARITY_SKIP_CONNECTOR_ENV, "1")
        fail = subprocess.CompletedProcess(
            args=["python3"], returncode=10, stdout="", stderr="parity mismatch"
        )
        with mock.patch.object(gates.subprocess, "run", return_value=fail):
            verdict = gates.run_gate("param_parity", "/abs/dir", "MyInt")
        assert verdict["allow"] is False
        assert verdict["exit_code"] == 10

        ok = subprocess.CompletedProcess(
            args=["python3"], returncode=0, stdout="parity ok", stderr=""
        )
        with mock.patch.object(gates.subprocess, "run", return_value=ok):
            verdict = gates.run_gate("param_parity", "/abs/dir", "MyInt")
        assert verdict["allow"] is True
        assert verdict["exit_code"] == 0

    def test_param_parity_falsey_skip_env_does_not_append_flag(self, monkeypatch) -> None:
        # A falsey value (e.g. "0") does NOT append the flag — matching the
        # coverage-force helper's truthiness semantics ({"1","true","yes"}).
        monkeypatch.setenv(gates._PARITY_SKIP_CONNECTOR_ENV, "0")
        monkeypatch.delenv(gates._PARITY_SKIP_BASE_PACK_ENV, raising=False)
        completed = subprocess.CompletedProcess(
            args=["python3"], returncode=0, stdout="PASS", stderr=""
        )
        with mock.patch.object(gates.subprocess, "run", return_value=completed) as m:
            gates.run_gate("param_parity", "/abs/dir", "MyInt")
        argv = m.call_args.args[0]
        assert "--skip-connector-deploy" not in argv
        assert "--skip-base-pack" not in argv

    def test_handler_param_coverage_fail_on_nonzero_exit(self, monkeypatch) -> None:
        # A non-zero exit from the coverage script (missing param / usage
        # error) becomes a failing verdict so the markpass is rejected.
        monkeypatch.setattr(gates, "_handler_dir_abs", lambda iid: "/h")
        monkeypatch.setattr(gates, "_integration_yml_abs", lambda iid: "/y.yml")
        completed = subprocess.CompletedProcess(
            args=["python3"], returncode=1, stdout="", stderr="FAIL: missing param x"
        )
        with mock.patch.object(gates.subprocess, "run", return_value=completed):
            verdict = gates.run_gate("handler_param_coverage", "/abs/dir", "MyInt")
        assert verdict["allow"] is False
        assert verdict["exit_code"] == 1

    def test_derive_handler_id_matches_guide(self) -> None:
        # Mirrors manifest_generator.derive_handler_id (guide §3.8).
        assert gates._derive_handler_id("Salesforce") == "xsoar-salesforce"
        assert gates._derive_handler_id("My Integration") == "xsoar-my-integration"
        assert gates._derive_handler_id("EWS v2") == "xsoar-ews-v2"

    def test_fail_on_nonzero_exit(self) -> None:
        completed = subprocess.CompletedProcess(
            args=["demisto-sdk"], returncode=1, stdout="", stderr="boom"
        )
        with mock.patch.object(gates.subprocess, "run", return_value=completed):
            verdict = gates.run_gate("precommit", "/abs/dir", "MyInt")
        assert verdict["allow"] is False
        assert verdict["exit_code"] == 1
        assert "exited 1" in verdict["reason"]
        assert verdict["stderr_tail"] == "boom"

    def test_timeout_is_failure(self) -> None:
        with mock.patch.object(
            gates.subprocess,
            "run",
            side_effect=subprocess.TimeoutExpired(cmd="demisto-sdk", timeout=5),
        ):
            verdict = gates.run_gate("precommit", "/abs/dir", "MyInt", timeout=5)
        assert verdict["allow"] is False
        assert verdict["exit_code"] is None
        assert "timed out" in verdict["reason"]

    def test_spawn_error_is_failure(self) -> None:
        with mock.patch.object(
            gates.subprocess, "run", side_effect=FileNotFoundError("no demisto-sdk")
        ):
            verdict = gates.run_gate("precommit", "/abs/dir", "MyInt")
        assert verdict["allow"] is False
        assert verdict["exit_code"] is None
        assert "could not be launched" in verdict["reason"]

    def test_unknown_gate_is_failure(self) -> None:
        verdict = gates.run_gate("nope", "/abs/dir", "MyInt")
        assert verdict["allow"] is False
        assert verdict["exit_code"] is None
        assert "unknown gate" in verdict["reason"]

    def test_timeout_override_passed_to_subprocess(self) -> None:
        completed = subprocess.CompletedProcess(
            args=["x"], returncode=0, stdout="", stderr=""
        )
        with mock.patch.object(gates.subprocess, "run", return_value=completed) as m:
            gates.run_gate("precommit", "/abs/dir", "MyInt", timeout=42)
        assert m.call_args.kwargs["timeout"] == 42


# ---------------------------------------------------------------------------
# 2) Config-loader gate parsing
# ---------------------------------------------------------------------------

_BASE_YAML = """\
schema_version: 1
identity_columns:
  - {{"name": "Integration ID", "description": "primary key"}}
markers:
  check: "✅"
  fail: "❌"
  na: "N/A"
  checkpoint_done_values: ["✅", "N/A"]
  flag_values: ["YES", "NO", "N/A"]
steps:
  - name: "assignee"
    kind: data
    optional: false
    setter: set-assignee
    description: "owner"
  - name: "gated cp"
    kind: {cp_kind}
    optional: false
    setter: {cp_setter}
    {gate_line}
    description: "a step"
"""


def _write(tmp_path, *, cp_kind="checkpoint", cp_setter="null", gate_line=""):
    body = _BASE_YAML.format(cp_kind=cp_kind, cp_setter=cp_setter, gate_line=gate_line)
    p = tmp_path / "wf.yml"
    p.write_text(body, encoding="utf-8")
    return str(p)


class TestLoaderGateParsing:
    def test_default_yaml_binds_precommit_gate(self) -> None:
        cfg = load_config()
        step = cfg.step_by_name["precommit/validate/unit tests passed"]
        assert step.gate == "precommit"

    def test_default_yaml_binds_make_validate_gate(self) -> None:
        cfg = load_config()
        step = cfg.step_by_name["run manifest make validate"]
        assert step.gate == "make_validate"

    def test_default_yaml_binds_param_parity_gate(self) -> None:
        cfg = load_config()
        step = cfg.step_by_name["param parity test passes"]
        assert step.gate == "param_parity"
        assert step.kind == "checkpoint"

    def test_default_yaml_binds_handler_param_coverage_gate(self) -> None:
        cfg = load_config()
        step = cfg.step_by_name["handler param coverage"]
        assert step.gate == "handler_param_coverage"
        assert step.kind == "checkpoint"

    def test_handler_param_coverage_runs_immediately_before_make_validate(
        self,
    ) -> None:
        # The new gate must sit exactly one step before make_validate so it
        # gates the workflow before connector-level schema validation.
        cfg = load_config()
        names = [s.name for s in cfg.steps]
        i_cov = names.index("handler param coverage")
        i_validate = names.index("run manifest make validate")
        assert i_validate == i_cov + 1
        # And the step right before the coverage check is the manifest gen.
        assert names[i_cov - 1] == "generated manifest"

    def test_checkpoint_without_gate_defaults_none(self) -> None:
        cfg = load_config()
        assert cfg.step_by_name["generated manifest"].gate is None

    def test_valid_gate_parsed(self, tmp_path) -> None:
        p = _write(tmp_path, gate_line="gate: precommit")
        cfg = load_config(p)
        assert cfg.step_by_name["gated cp"].gate == "precommit"

    def test_unknown_gate_rejected(self, tmp_path) -> None:
        p = _write(tmp_path, gate_line="gate: bogus_gate")
        with pytest.raises(ConfigLoadError) as exc:
            load_config(p)
        assert "unknown gate" in str(exc.value)

    def test_gate_on_data_step_rejected(self, tmp_path) -> None:
        p = _write(
            tmp_path, cp_kind="data", cp_setter="set-thing", gate_line="gate: precommit"
        )
        with pytest.raises(ConfigLoadError) as exc:
            load_config(p)
        assert "only valid for kind=checkpoint" in str(exc.value)


# ---------------------------------------------------------------------------
# 3) markpass gating (no bypass)
# ---------------------------------------------------------------------------

_GATED_STEP = "precommit/validate/unit tests passed"


def _row_at_gated_step() -> dict:
    """A CSV row with every step before the gated checkpoint already done."""
    cfg = load_config()
    row = {
        "Integration ID": "MyInt",
        "Integration File Path": "Packs/Fake/Integrations/Fake/Fake.yml",
        "Connector ID": "fake",
    }
    for s in cfg.steps:
        if s.name == _GATED_STEP:
            row[s.name] = ""  # the step under test — not yet done
            break
        # Fill prior steps: checkpoints get the check marker, data gets a value.
        row[s.name] = cfg.markers.check if s.kind == "checkpoint" else "x"
    # Ensure remaining columns exist (empty) so the row is well-formed.
    for s in cfg.steps:
        row.setdefault(s.name, "")
    return row


@pytest.fixture
def gated_csv(monkeypatch: pytest.MonkeyPatch) -> list[dict]:
    rows = [_row_at_gated_step()]
    monkeypatch.setattr(ws_api, "load_csv", lambda: rows)
    monkeypatch.setattr(ws_api, "save_csv", lambda _rows: None)
    return rows


class TestMarkpassGate:
    def test_gate_pass_allows_markpass(self, gated_csv, monkeypatch) -> None:
        monkeypatch.setattr(
            ws_api,
            "run_checkpoint_gate",
            lambda iid, gate, timeout: {"allow": True, "gate": gate, "reason": "passed"},
        )
        result = ws_api.markpass_integration_step("MyInt", _GATED_STEP)
        assert "error" not in result
        assert result["completed_step"] == _GATED_STEP
        assert gated_csv[0][_GATED_STEP] == load_config().markers.check

    def test_gate_fail_rejects_markpass(self, gated_csv, monkeypatch) -> None:
        monkeypatch.setattr(
            ws_api,
            "run_checkpoint_gate",
            lambda iid, gate, timeout: {
                "allow": False, "gate": gate, "reason": "exited 1",
                "stderr_tail": "boom",
            },
        )
        result = ws_api.markpass_integration_step("MyInt", _GATED_STEP)
        assert "error" in result
        assert "gate 'precommit' failed" in result["error"]
        # The cell must NOT have been marked passed.
        assert gated_csv[0][_GATED_STEP] == ""

    def test_gate_is_actually_invoked(self, gated_csv, monkeypatch) -> None:
        calls = []

        def _spy(iid, gate, timeout):
            calls.append((iid, gate, timeout))
            return {"allow": True, "gate": gate, "reason": "passed"}

        monkeypatch.setattr(ws_api, "run_checkpoint_gate", _spy)
        ws_api.markpass_integration_step("MyInt", _GATED_STEP, gate_timeout=99)
        assert calls == [("MyInt", "precommit", 99)]

    def test_no_bypass_kwarg(self) -> None:
        # markpass_integration_step must NOT accept a skip/bypass kwarg.
        import inspect
        sig = inspect.signature(ws_api.markpass_integration_step)
        assert "skip_gate" not in sig.parameters


_PARITY_STEP = "param parity test passes"


def _row_at_parity_step() -> dict:
    """A CSV row with every step before the param-parity checkpoint done."""
    cfg = load_config()
    row = {
        "Integration ID": "MyInt",
        "Integration File Path": "Packs/Fake/Integrations/Fake/Fake.yml",
        "Connector ID": "fake",
    }
    for s in cfg.steps:
        if s.name == _PARITY_STEP:
            row[s.name] = ""  # the step under test — not yet done
            break
        row[s.name] = cfg.markers.check if s.kind == "checkpoint" else "x"
    for s in cfg.steps:
        row.setdefault(s.name, "")
    return row


@pytest.fixture
def parity_csv(monkeypatch: pytest.MonkeyPatch) -> list[dict]:
    rows = [_row_at_parity_step()]
    monkeypatch.setattr(ws_api, "load_csv", lambda: rows)
    monkeypatch.setattr(ws_api, "save_csv", lambda _rows: None)
    return rows


def _patch_gate_via_real_run_gate(monkeypatch, completed) -> None:
    """Route ws_api.run_checkpoint_gate through the REAL gates.run_gate.

    This exercises the genuine exit-code -> verdict mapping (so the
    subprocess return code drives the markpass), while skipping the
    on-disk integration-directory resolution that get_integration_files
    performs (the fake CSV row points at a non-existent path). subprocess
    itself is mocked via ``completed`` so no live deploy runs.
    """

    def _run(iid, gate, timeout):
        with mock.patch.object(gates.subprocess, "run", return_value=completed):
            verdict = gates.run_gate(gate, "/abs/integration/dir", iid, timeout=timeout)
        verdict["integration_id"] = iid
        return verdict

    monkeypatch.setattr(ws_api, "run_checkpoint_gate", _run)


class TestParamParityMarkpassGate:
    def test_parity_gate_pass_marks_cell(self, parity_csv, monkeypatch) -> None:
        # Gate mocked to PASS (exit 0) via the real run_gate mapping. Cell ✅.
        completed = subprocess.CompletedProcess(
            args=["python3"], returncode=0, stdout="parity ok", stderr=""
        )
        _patch_gate_via_real_run_gate(monkeypatch, completed)
        result = ws_api.markpass_integration_step("MyInt", _PARITY_STEP)
        assert "error" not in result
        assert result["completed_step"] == _PARITY_STEP
        assert parity_csv[0][_PARITY_STEP] == load_config().markers.check

    def test_parity_gate_fail_rejects_markpass(self, parity_csv, monkeypatch) -> None:
        # Gate mocked to FAIL (exit 10, parity mismatch) via the real
        # run_gate mapping. The markpass is rejected; the cell stays empty.
        completed = subprocess.CompletedProcess(
            args=["python3"], returncode=10, stdout="", stderr="parity mismatch"
        )
        _patch_gate_via_real_run_gate(monkeypatch, completed)
        result = ws_api.markpass_integration_step("MyInt", _PARITY_STEP)
        assert "error" in result
        assert "gate 'param_parity' failed" in result["error"]
        assert parity_csv[0][_PARITY_STEP] == ""
