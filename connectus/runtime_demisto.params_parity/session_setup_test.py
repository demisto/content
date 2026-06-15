"""Hermetic tests for session_setup / session_teardown — fully mocked."""

from __future__ import annotations

from unittest import mock

import pytest

import preflight_check as pf
import session_env as se
import session_setup
import session_teardown


def _ok(name):
    return pf.CheckResult(name, True, "ok")


def _all_ok():
    return [_ok("required .env vars"), _ok("gcloud authenticated")]


@pytest.fixture(autouse=True)
def _isolate(monkeypatch, tmp_path):
    # Never touch real env state; descriptor goes to tmp.
    monkeypatch.setattr(se, "SESSION_DIR", tmp_path / ".session")
    monkeypatch.setattr(se, "DESCRIPTOR_PATH", tmp_path / ".session" / "parity_session.json")
    monkeypatch.setenv("TENANT_ID", "9993253582446")
    monkeypatch.setattr(session_setup, "find_repo_root", lambda: tmp_path / "content")
    monkeypatch.setenv("CONNECTUS_REPO_DIR", str(tmp_path / "ucc"))


def test_setup_stops_on_verify_failure(monkeypatch):
    monkeypatch.setattr(session_setup.preflight_check, "run_preflight",
                        lambda iid, for_session_setup=False: [pf.CheckResult("vpn", False, "no")])
    rc = session_setup.main([])
    assert rc == 1


def test_setup_stops_on_get_credentials_failure(monkeypatch):
    monkeypatch.setattr(session_setup.preflight_check, "run_preflight",
                        lambda iid, for_session_setup=False: _all_ok())
    monkeypatch.setattr(session_setup.session_env, "load_descriptor", lambda: None)
    monkeypatch.setattr(session_setup, "_get_credentials", lambda t: (False, "boom auth"))
    rc = session_setup.main([])
    assert rc == 1


def test_setup_stops_on_gke_unreachable(monkeypatch):
    monkeypatch.setattr(session_setup.preflight_check, "run_preflight",
                        lambda iid, for_session_setup=False: _all_ok())
    monkeypatch.setattr(session_setup.session_env, "load_descriptor", lambda: None)
    monkeypatch.setattr(session_setup, "_get_credentials", lambda t: (True, "ok"))
    monkeypatch.setattr(session_setup.preflight_check, "_check_gke_reachable",
                        lambda: pf.CheckResult("gke", False, "timeout israel-gw"))
    rc = session_setup.main([])
    assert rc == 1


def test_setup_happy_path_writes_descriptor(monkeypatch):
    # NOTE: do NOT patch load_descriptor here — session_setup.session_env IS the
    # real session_env module, so patching it would also break the test's own
    # se.load_descriptor() read-back. The tmp descriptor simply doesn't exist yet
    # at the reuse-check, so the real load_descriptor returns None naturally.
    monkeypatch.setattr(session_setup.preflight_check, "run_preflight",
                        lambda iid, for_session_setup=False: _all_ok())
    monkeypatch.setattr(session_setup, "_get_credentials", lambda t: (True, "ok"))
    monkeypatch.setattr(session_setup.preflight_check, "_check_gke_reachable",
                        lambda: pf.CheckResult("gke", True, "ok"))
    monkeypatch.setattr(session_setup.session_env, "ensure_port_forward",
                        lambda t, port, existing_pid=None: (4242, "pod-z"))
    monkeypatch.setattr(session_setup.session_env, "port_is_live", lambda port, timeout=1.0: True)
    monkeypatch.setattr(session_setup.session_env, "gcloud_auth_ok", lambda: True)
    monkeypatch.setattr(session_setup.session_env, "current_gcloud_account", lambda: "joey@x")

    rc = session_setup.main(["--port", "8080"])
    assert rc == 0
    desc = se.load_descriptor()
    assert desc is not None
    assert desc.tenant_id == "9993253582446"
    assert desc.port_forward_pid == 4242
    assert desc.pod_name == "pod-z"
    assert desc.ucp_port == 8080
    assert desc.gcloud_account == "joey@x"


def test_setup_reuses_healthy_session(monkeypatch):
    existing = se.SessionDescriptor(
        tenant_id="9993253582446", ucp_port=8080, port_forward_pid=555,
        pod_name="pod-old", content_repo="/c", connectus_repo="/u",
        created_ts=1.0, gcloud_account="joey@x",
    )
    monkeypatch.setattr(session_setup.preflight_check, "run_preflight",
                        lambda iid, for_session_setup=False: _all_ok())
    monkeypatch.setattr(session_setup.session_env, "load_descriptor", lambda: existing)
    monkeypatch.setattr(session_setup.session_env, "gcloud_auth_ok", lambda: True)
    monkeypatch.setattr(session_setup.session_env, "_pid_alive", lambda pid: True)
    monkeypatch.setattr(session_setup.session_env, "port_is_live", lambda port, timeout=1.0: True)
    # If it tried to (re)establish, this would blow up:
    monkeypatch.setattr(session_setup, "_get_credentials",
                        lambda t: (_ for _ in ()).throw(AssertionError("should not re-establish")))

    rc = session_setup.main([])
    assert rc == 0


def test_setup_health_gate_fails_when_port_dead(monkeypatch):
    monkeypatch.setattr(session_setup.preflight_check, "run_preflight",
                        lambda iid, for_session_setup=False: _all_ok())
    monkeypatch.setattr(session_setup.session_env, "load_descriptor", lambda: None)
    monkeypatch.setattr(session_setup, "_get_credentials", lambda t: (True, "ok"))
    monkeypatch.setattr(session_setup.preflight_check, "_check_gke_reachable",
                        lambda: pf.CheckResult("gke", True, "ok"))
    monkeypatch.setattr(session_setup.session_env, "ensure_port_forward",
                        lambda t, port, existing_pid=None: (4242, "pod-z"))
    monkeypatch.setattr(session_setup.session_env, "port_is_live", lambda port, timeout=1.0: False)
    monkeypatch.setattr(session_setup.session_env, "gcloud_auth_ok", lambda: True)
    monkeypatch.setattr(session_setup.session_env, "current_gcloud_account", lambda: "joey@x")

    rc = session_setup.main([])
    assert rc == 1


# ---------------------------------------------------------------------------
# teardown
# ---------------------------------------------------------------------------


def test_check_exit_0_when_live(monkeypatch):
    desc = se.SessionDescriptor(
        tenant_id="t", ucp_port=8080, port_forward_pid=1, pod_name="p",
        content_repo="/c", connectus_repo="/u", created_ts=1.0, gcloud_account="a",
    )
    monkeypatch.setattr(session_setup.session_env, "assert_session_live", lambda: desc)
    assert session_setup.main(["--check"]) == 0


def test_check_exit_1_when_not_ready(monkeypatch):
    def _boom():
        raise se.SessionNotReady(se.STATUS_NOT_INITIALIZED, "run session_setup.py")
    monkeypatch.setattr(session_setup.session_env, "assert_session_live", _boom)
    assert session_setup.main(["--check"]) == 1


def test_teardown_no_session(monkeypatch):
    monkeypatch.setattr(session_teardown.session_env, "load_descriptor", lambda: None)
    assert session_teardown.main([]) == 0


def test_teardown_kills_and_clears(monkeypatch):
    desc = se.SessionDescriptor(
        tenant_id="t", ucp_port=8080, port_forward_pid=999, pod_name="p",
        content_repo="/c", connectus_repo="/u", created_ts=1.0, gcloud_account="a",
    )
    monkeypatch.setattr(session_teardown.session_env, "load_descriptor", lambda: desc)
    killed = mock.Mock()
    cleared = mock.Mock()
    monkeypatch.setattr(session_teardown.session_env, "kill_port_forward", killed)
    monkeypatch.setattr(session_teardown.session_env, "clear_descriptor", cleared)
    assert session_teardown.main([]) == 0
    killed.assert_called_once_with(999)
    cleared.assert_called_once()
