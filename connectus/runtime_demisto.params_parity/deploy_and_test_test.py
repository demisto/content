"""Unit tests for deploy_and_test.py (Phase 4 — atomic wrapper, design §4).

Hermetic: tenant_lock.acquire/release and the deploy/parity subprocess seams are mocked.
No real network/kubectl/gitlab/lockfile. Asserts EVERY wrapper exit-code branch
(0/10/11/20/21/30), that release() is called in `finally` even on an exception, and the
multi-id worst-case aggregation (setup-block > parity-fail > pass).
"""
from __future__ import annotations

import pytest

import deploy_and_test as dat
import tenant_lock


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
@pytest.fixture(autouse=True)
def _pass_preflight(monkeypatch):
    """These tests exercise the deploy/parity/lock logic, not preflight/session —
    make preflight always pass AND the session always live so they don't
    short-circuit (preflight is tested in preflight_check_test.py, the session in
    session_env_test.py)."""
    monkeypatch.setattr(dat, "_run_preflight", lambda integration_ids: True)
    monkeypatch.setattr(dat.session_env, "assert_session_live", lambda: None)


@pytest.fixture
def mock_lock(monkeypatch):
    """Mock acquire→shell_id and record release() calls."""
    calls = {"acquire": [], "release": []}

    def fake_acquire(tenant, *, integration_id=None, max_wait=0, force=False):
        calls["acquire"].append(
            {"tenant": tenant, "integration_id": integration_id,
             "max_wait": max_wait, "force": force}
        )
        return "shell-abc"

    def fake_release(tenant, shell_id):
        calls["release"].append({"tenant": tenant, "shell_id": shell_id})
        return True

    monkeypatch.setattr(tenant_lock, "acquire", fake_acquire)
    monkeypatch.setattr(tenant_lock, "release", fake_release)
    return calls


def _set_deploy(monkeypatch, code):
    monkeypatch.setattr(dat, "_run_deploy", lambda tenant, commit_path=None, *a, **k: code)


def _set_parity(monkeypatch, codes):
    """codes: dict id->rc or a single int applied to all."""
    if isinstance(codes, int):
        monkeypatch.setattr(dat, "_run_parity", lambda integration_id: codes)
    else:
        monkeypatch.setattr(dat, "_run_parity", lambda integration_id: codes[integration_id])


# ---------------------------------------------------------------------------
# Single-id exit-code branches
# ---------------------------------------------------------------------------
def test_all_pass_exit_0(monkeypatch, mock_lock):
    _set_deploy(monkeypatch, 0)
    _set_parity(monkeypatch, 0)
    rc = dat.run(["IntA"], "T1", max_wait=0, force=False)
    assert rc == dat.EXIT_ALL_PASS
    assert mock_lock["release"] == [{"tenant": "T1", "shell_id": "shell-abc"}]


def test_parity_fail_exit_10(monkeypatch, mock_lock):
    _set_deploy(monkeypatch, 0)
    _set_parity(monkeypatch, 1)
    rc = dat.run(["IntA"], "T1", max_wait=0, force=False)
    assert rc == dat.EXIT_PARITY_FAIL
    assert mock_lock["release"]  # released


def test_parity_block_exit_11(monkeypatch, mock_lock):
    _set_deploy(monkeypatch, 0)
    _set_parity(monkeypatch, 2)
    rc = dat.run(["IntA"], "T1", max_wait=0, force=False)
    assert rc == dat.EXIT_PARITY_BLOCK
    assert mock_lock["release"]


def test_deploy_fail_exit_20_skips_parity(monkeypatch, mock_lock):
    _set_deploy(monkeypatch, 1)
    parity_called = {"n": 0}

    def _parity(integration_id):
        parity_called["n"] += 1
        return 0

    monkeypatch.setattr(dat, "_run_parity", _parity)
    rc = dat.run(["IntA"], "T1", max_wait=0, force=False)
    assert rc == dat.EXIT_DEPLOY_FAIL
    assert parity_called["n"] == 0  # parity never runs on deploy fail
    assert mock_lock["release"]  # still released


def test_deploy_timeout_exit_21(monkeypatch, mock_lock):
    _set_deploy(monkeypatch, 2)
    _set_parity(monkeypatch, 0)
    rc = dat.run(["IntA"], "T1", max_wait=0, force=False)
    assert rc == dat.EXIT_DEPLOY_TIMEOUT
    assert mock_lock["release"]


# ---------------------------------------------------------------------------
# Lock busy (timeout) → 30, NO deploy, NO release (never acquired)
# ---------------------------------------------------------------------------
def test_lock_busy_exit_30(monkeypatch):
    holder = {"shell_id": "other", "integration_id": "IntZ", "acquired_at": 1.0}

    def fake_acquire(*a, **k):
        raise tenant_lock.TenantLockTimeout("busy", holder=holder)

    released = {"n": 0}
    monkeypatch.setattr(tenant_lock, "acquire", fake_acquire)
    monkeypatch.setattr(tenant_lock, "release", lambda *a, **k: released.__setitem__("n", released["n"] + 1))
    deployed = {"n": 0}
    monkeypatch.setattr(dat, "_run_deploy", lambda tenant, commit_path=None, *a, **k: deployed.__setitem__("n", deployed["n"] + 1) or 0)

    rc = dat.run(["IntA"], "T1", max_wait=0, force=False)
    assert rc == dat.EXIT_LOCK_BUSY
    assert deployed["n"] == 0  # never deployed
    assert released["n"] == 0  # nothing to release (never acquired)


# ---------------------------------------------------------------------------
# Preflight gate → exit 40, NO deploy, NO acquire
# ---------------------------------------------------------------------------
def test_preflight_fail_exit_40(monkeypatch):
    # Override the autouse pass-preflight: make preflight FAIL here.
    monkeypatch.setattr(dat, "_run_preflight", lambda integration_ids: False)
    acquired = {"n": 0}
    deployed = {"n": 0}
    monkeypatch.setattr(tenant_lock, "acquire",
                        lambda *a, **k: acquired.__setitem__("n", acquired["n"] + 1) or "s")
    monkeypatch.setattr(tenant_lock, "release", lambda *a, **k: True)
    monkeypatch.setattr(dat, "_run_deploy",
                        lambda tenant, commit_path=None, *a, **k: deployed.__setitem__("n", deployed["n"] + 1) or 0)
    rc = dat.run(["IntA"], "T1", max_wait=0, force=False)
    assert rc == dat.EXIT_PREFLIGHT_FAIL
    assert acquired["n"] == 0  # never acquired the lock
    assert deployed["n"] == 0  # never deployed


def test_session_not_ready_exit_11(monkeypatch):
    """A dead/missing session (SessionNotReady) → exit 11 BLOCKED, before lock/deploy."""
    def _boom():
        raise dat.session_env.SessionNotReady(
            dat.session_env.STATUS_NOT_INITIALIZED, "run session_setup.py"
        )
    monkeypatch.setattr(dat.session_env, "assert_session_live", _boom)
    # If it proceeded, these would be called — ensure they are NOT reached.
    monkeypatch.setattr(tenant_lock, "acquire",
                        lambda *a, **k: (_ for _ in ()).throw(AssertionError("should not acquire")))
    rc = dat.run(["IntA"], "T1", max_wait=0, force=False)
    assert rc == dat.EXIT_PARITY_BLOCK


def test_skip_preflight_bypasses_gate(monkeypatch, mock_lock):
    # Even with a failing preflight, skip_preflight=True proceeds.
    monkeypatch.setattr(dat, "_run_preflight", lambda integration_ids: False)
    _set_deploy(monkeypatch, 0)
    _set_parity(monkeypatch, 0)
    rc = dat.run(["IntA"], "T1", max_wait=0, force=False, skip_preflight=True)
    assert rc == dat.EXIT_ALL_PASS


# ---------------------------------------------------------------------------
# --skip-deploy bypasses deploy entirely and runs parity directly
# ---------------------------------------------------------------------------
def test_skip_deploy_bypasses_deploy(monkeypatch, mock_lock):
    deployed = {"n": 0}

    def boom(tenant, commit_path=None, *a, **k):
        deployed["n"] += 1
        raise AssertionError("_run_deploy must NOT be called when skip_deploy=True")

    monkeypatch.setattr(dat, "_run_deploy", boom)
    _set_parity(monkeypatch, 0)
    rc = dat.run(["IntA"], "T1", max_wait=0, force=False, skip_deploy=True)
    assert rc == dat.EXIT_ALL_PASS  # proceeded straight to parity → pass
    assert deployed["n"] == 0  # deploy never invoked
    assert mock_lock["release"]  # lock still released


# ---------------------------------------------------------------------------
# release() is called in finally even on an unexpected exception
# ---------------------------------------------------------------------------
def test_release_called_in_finally_on_exception(monkeypatch, mock_lock):
    def boom(tenant, commit_path=None, *a, **k):
        raise RuntimeError("deploy blew up")

    monkeypatch.setattr(dat, "_run_deploy", boom)
    with pytest.raises(RuntimeError):
        dat.run(["IntA"], "T1", max_wait=0, force=False)
    assert mock_lock["release"] == [{"tenant": "T1", "shell_id": "shell-abc"}]


# ---------------------------------------------------------------------------
# Multi-id worst-case aggregation (still report per-id)
# ---------------------------------------------------------------------------
def test_multi_id_worst_case_block_beats_fail_beats_pass(monkeypatch, mock_lock):
    _set_deploy(monkeypatch, 0)
    _set_parity(monkeypatch, {"A": 0, "B": 1, "C": 2})  # pass, fail, block
    rc = dat.run(["A", "B", "C"], "T1", max_wait=0, force=False)
    assert rc == dat.EXIT_PARITY_BLOCK  # 11 wins
    assert mock_lock["release"]


def test_multi_id_fail_beats_pass(monkeypatch, mock_lock):
    _set_deploy(monkeypatch, 0)
    _set_parity(monkeypatch, {"A": 0, "B": 1})  # pass, fail
    rc = dat.run(["A", "B"], "T1", max_wait=0, force=False)
    assert rc == dat.EXIT_PARITY_FAIL  # 10


def test_multi_id_all_pass(monkeypatch, mock_lock):
    _set_deploy(monkeypatch, 0)
    _set_parity(monkeypatch, {"A": 0, "B": 0})
    rc = dat.run(["A", "B"], "T1", max_wait=0, force=False)
    assert rc == dat.EXIT_ALL_PASS


def test_multi_id_deploy_runs_once(monkeypatch, mock_lock):
    deploys = {"n": 0}
    monkeypatch.setattr(dat, "_run_deploy", lambda tenant, commit_path=None, *a, **k: deploys.__setitem__("n", deploys["n"] + 1) or 0)
    _set_parity(monkeypatch, 0)
    dat.run(["A", "B", "C"], "T1", max_wait=0, force=False)
    assert deploys["n"] == 1  # ONE deploy under ONE lock


# ---------------------------------------------------------------------------
# acquire receives force from --force-unlock + per-id summary lines printed
# ---------------------------------------------------------------------------
def test_force_unlock_propagates_to_acquire(monkeypatch, mock_lock):
    _set_deploy(monkeypatch, 0)
    _set_parity(monkeypatch, 0)
    dat.run(["IntA"], "T1", max_wait=42, force=True)
    assert mock_lock["acquire"][0]["force"] is True
    assert mock_lock["acquire"][0]["max_wait"] == 42


def test_per_id_summary_lines_printed(monkeypatch, mock_lock, capsys):
    _set_deploy(monkeypatch, 0)
    _set_parity(monkeypatch, {"A": 0, "B": 1})
    dat.run(["A", "B"], "T1", max_wait=0, force=False)
    out = capsys.readouterr().out
    assert "DEPLOY_AND_TEST_RESULT integration=A result=PASS exit=0" in out
    assert "DEPLOY_AND_TEST_RESULT integration=B result=PARITY_FAIL exit=10" in out


# ---------------------------------------------------------------------------
# _run_deploy passes --commit-path through to deploy.py
# ---------------------------------------------------------------------------
class _FakeProc:
    def __init__(self, returncode=0):
        self.returncode = returncode


def test_run_deploy_appends_commit_path(monkeypatch):
    captured = {}

    def fake_run(cmd, **kwargs):
        captured["cmd"] = cmd
        return _FakeProc(0)

    monkeypatch.setattr(dat.subprocess, "run", fake_run)
    rc = dat._run_deploy("T1", "connectors/aws")
    assert rc == 0
    assert "--commit-path" in captured["cmd"]
    idx = captured["cmd"].index("--commit-path")
    assert captured["cmd"][idx + 1] == "connectors/aws"
    assert "--tenant" in captured["cmd"]


def test_run_deploy_omits_commit_path_when_none(monkeypatch):
    captured = {}

    def fake_run(cmd, **kwargs):
        captured["cmd"] = cmd
        return _FakeProc(0)

    monkeypatch.setattr(dat.subprocess, "run", fake_run)
    rc = dat._run_deploy("T1")
    assert rc == 0
    assert "--commit-path" not in captured["cmd"]


# ---------------------------------------------------------------------------
# _run_deploy passes --upload-pack (repeatable) + --upload-insecure through
# ---------------------------------------------------------------------------
def test_run_deploy_appends_upload_packs(monkeypatch):
    captured = {}

    def fake_run(cmd, **kwargs):
        captured["cmd"] = cmd
        return _FakeProc(0)

    monkeypatch.setattr(dat.subprocess, "run", fake_run)
    rc = dat._run_deploy(
        "T1", "connectors/aws", ["Packs/Base", "Packs/AMP"], upload_insecure=True
    )
    assert rc == 0
    cmd = captured["cmd"]
    # one --upload-pack per pack, in order
    pack_idxs = [i for i, t in enumerate(cmd) if t == "--upload-pack"]
    assert len(pack_idxs) == 2
    assert cmd[pack_idxs[0] + 1] == "Packs/Base"
    assert cmd[pack_idxs[1] + 1] == "Packs/AMP"
    assert "--upload-insecure" in cmd


def test_run_deploy_omits_upload_pack_when_none(monkeypatch):
    captured = {}

    def fake_run(cmd, **kwargs):
        captured["cmd"] = cmd
        return _FakeProc(0)

    monkeypatch.setattr(dat.subprocess, "run", fake_run)
    rc = dat._run_deploy("T1")
    assert rc == 0
    assert "--upload-pack" not in captured["cmd"]
    assert "--upload-insecure" not in captured["cmd"]


# ---------------------------------------------------------------------------
# Pack derivation from the integration YML path (Base + integration pack)
# ---------------------------------------------------------------------------
def test_integration_pack_dir_from_yml():
    assert (
        dat._integration_pack_dir("Packs/AMP/Integrations/AMPv2/AMPv2.yml")
        == "Packs/AMP"
    )


def test_integration_pack_dir_non_pack_path_is_none():
    assert dat._integration_pack_dir("some/other/path.yml") is None
    assert dat._integration_pack_dir("") is None


def test_packs_to_upload_base_first_then_integration():
    packs = dat._packs_to_upload("Packs/AMP/Integrations/AMPv2/AMPv2.yml")
    assert packs == ["Packs/Base", "Packs/AMP"]


def test_packs_to_upload_base_only_when_yml_not_under_packs():
    assert dat._packs_to_upload("nope.yml") == ["Packs/Base"]


def test_packs_to_upload_dedupes_base():
    # An integration YML living under Packs/Base must not double the Base pack.
    packs = dat._packs_to_upload("Packs/Base/Integrations/Foo/Foo.yml")
    assert packs == ["Packs/Base"]


# ---------------------------------------------------------------------------
# Tenant resolution (CLI > .env first-of-CSV; usage error if none)
# ---------------------------------------------------------------------------
def test_resolve_tenant_cli_wins(monkeypatch):
    monkeypatch.setenv("TENANT_ID", "111")
    assert dat._resolve_tenant("999") == "999"


def test_resolve_tenant_env(monkeypatch):
    monkeypatch.setenv("TENANT_ID", "111")
    assert dat._resolve_tenant(None) == "111"


def test_resolve_tenant_none_is_usage_error(monkeypatch):
    monkeypatch.delenv("TENANT_ID", raising=False)
    with pytest.raises(SystemExit):
        dat._resolve_tenant(None)
