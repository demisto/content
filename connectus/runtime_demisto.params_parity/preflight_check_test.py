"""Unit tests for preflight_check.py — hermetic (monkeypatched env / paths / which)."""
from __future__ import annotations

from pathlib import Path

import pytest

import preflight_check as pf


# ---------------------------------------------------------------------------
# fixtures / helpers
# ---------------------------------------------------------------------------

_ALL_ENV = {
    "DEMISTO_BASE_URL": "https://t",
    "DEMISTO_API_KEY": "k",
    "XSIAM_AUTH_ID": "1",
    "CONNECTUS_REPO_DIR": "/tmp/repo",
    "CONNECTUS_BRANCH": "b",
    "TENANT_ID": "123",
    "GITLAB_TOKEN": "tok",
}


def _set_env(monkeypatch, **overrides):
    env = {**_ALL_ENV, **overrides}
    for k in pf._REQUIRED_ENV:
        v = env.get(k)
        if v is None:
            monkeypatch.delenv(k, raising=False)
        else:
            monkeypatch.setenv(k, v)


# ---------------------------------------------------------------------------
# required env
# ---------------------------------------------------------------------------

def test_required_env_all_set(monkeypatch):
    _set_env(monkeypatch)
    r = pf._check_required_env()
    assert r.ok


def test_required_env_missing(monkeypatch):
    _set_env(monkeypatch, GITLAB_TOKEN=None, TENANT_ID=None)
    r = pf._check_required_env()
    assert not r.ok
    assert "GITLAB_TOKEN" in r.detail and "TENANT_ID" in r.detail


# ---------------------------------------------------------------------------
# deploy branch name enforcement (xsoar-migration-<name>)
# ---------------------------------------------------------------------------

def test_branch_name_ok(monkeypatch):
    monkeypatch.setenv("CONNECTUS_BRANCH", "xsoar-migration-joey")
    assert pf._check_branch_name().ok


def test_branch_name_unset(monkeypatch):
    monkeypatch.delenv("CONNECTUS_BRANCH", raising=False)
    r = pf._check_branch_name()
    assert not r.ok and "unset" in r.detail


def test_branch_name_rejects_shared(monkeypatch):
    for shared in ("stable", "master", "main", "dev", "xsoar", "xsoar-playground"):
        monkeypatch.setenv("CONNECTUS_BRANCH", shared)
        r = pf._check_branch_name()
        assert not r.ok, f"{shared} should be rejected"
        assert "SHARED" in r.detail


def test_branch_name_rejects_wrong_shape(monkeypatch):
    for bad in ("xsoar-foo", "migration-joey", "xsoar-migration-", "xsoar-migration-Joey", "feature/x"):
        monkeypatch.setenv("CONNECTUS_BRANCH", bad)
        assert not pf._check_branch_name().ok, f"{bad} should be rejected"


# ---------------------------------------------------------------------------
# connectus repo
# ---------------------------------------------------------------------------

def test_connectus_repo_ok(monkeypatch, tmp_path):
    (tmp_path / "connectors").mkdir()
    monkeypatch.setenv("CONNECTUS_REPO_DIR", str(tmp_path))
    r = pf._check_connectus_repo()
    assert r.ok


def test_connectus_repo_unset(monkeypatch):
    monkeypatch.delenv("CONNECTUS_REPO_DIR", raising=False)
    r = pf._check_connectus_repo()
    assert not r.ok


def test_connectus_repo_not_a_dir(monkeypatch, tmp_path):
    monkeypatch.setenv("CONNECTUS_REPO_DIR", str(tmp_path / "missing"))
    r = pf._check_connectus_repo()
    assert not r.ok


def test_connectus_repo_no_connectors_subdir(monkeypatch, tmp_path):
    monkeypatch.setenv("CONNECTUS_REPO_DIR", str(tmp_path))
    r = pf._check_connectus_repo()
    assert not r.ok
    assert "connectors/" in r.detail


# ---------------------------------------------------------------------------
# probe
# ---------------------------------------------------------------------------

def test_probe_present(monkeypatch, tmp_path):
    csp = tmp_path / "CommonServerPython.py"
    csp.write_text("x __params_parity_dump__ y PARAMS_PARITY_DUMP:: z", encoding="utf-8")
    monkeypatch.setattr(pf, "_COMMON_SERVER_PYTHON", csp)
    r = pf._check_probe()
    assert r.ok


def test_probe_missing_markers(monkeypatch, tmp_path):
    csp = tmp_path / "CommonServerPython.py"
    csp.write_text("no probe here", encoding="utf-8")
    monkeypatch.setattr(pf, "_COMMON_SERVER_PYTHON", csp)
    r = pf._check_probe()
    assert not r.ok
    assert "__params_parity_dump__" in r.detail


def test_probe_file_absent(monkeypatch, tmp_path):
    monkeypatch.setattr(pf, "_COMMON_SERVER_PYTHON", tmp_path / "nope.py")
    r = pf._check_probe()
    assert not r.ok


# ---------------------------------------------------------------------------
# tooling on PATH
# ---------------------------------------------------------------------------

def test_tool_on_path_found(monkeypatch):
    monkeypatch.setattr(pf.shutil, "which", lambda t: "/usr/bin/" + t)
    r = pf._check_tool_on_path("gcloud")
    assert r.ok


def test_tool_on_path_missing(monkeypatch):
    monkeypatch.setattr(pf.shutil, "which", lambda t: None)
    r = pf._check_tool_on_path("kubectl")
    assert not r.ok


# ---------------------------------------------------------------------------
# resolver check
# ---------------------------------------------------------------------------

def test_resolver_ok(monkeypatch):
    class _Cap:
        id = "automation-and-remediation"

    class _PI:
        connector_id = "azuresentinel"
        capabilities = [_Cap()]
        compare_params = {"a", "b"}

    import resolver
    monkeypatch.setattr(resolver, "resolve", lambda iid: _PI())
    r = pf._check_resolver("Azure Sentinel")
    assert r.ok
    assert "azuresentinel" in r.detail


def test_resolver_failure(monkeypatch):
    import resolver
    def _boom(iid):
        raise resolver.ResolverError("no Connector Folder Path")
    monkeypatch.setattr(resolver, "resolve", _boom)
    r = pf._check_resolver("Whatever")
    assert not r.ok
    assert "failed" in r.detail


# ---------------------------------------------------------------------------
# orchestration
# ---------------------------------------------------------------------------

def test_run_preflight_skips_resolver_when_no_id(monkeypatch, tmp_path):
    _set_env(monkeypatch)
    monkeypatch.setattr(pf.shutil, "which", lambda t: "/usr/bin/" + t)
    names = [r.name for r in pf.run_preflight(None)]
    assert "resolver maps integration" not in names


def test_all_passed_true_and_false():
    assert pf.all_passed([pf.CheckResult("a", True, ""), pf.CheckResult("b", True, "")])
    assert not pf.all_passed([pf.CheckResult("a", True, ""), pf.CheckResult("b", False, "")])


# ---------------------------------------------------------------------------
# session-setup VERIFY checks (gcloud authed, auth plugin, gke reachable)
# ---------------------------------------------------------------------------

from unittest import mock  # noqa: E402


def test_check_gcloud_authed_ok(monkeypatch):
    res = mock.Mock(returncode=0, stdout="joey@example.com\n")
    monkeypatch.setattr("subprocess.run", lambda *a, **k: res)
    r = pf._check_gcloud_authed()
    assert r.ok and "joey@example.com" in r.detail


def test_check_gcloud_authed_unset(monkeypatch):
    res = mock.Mock(returncode=0, stdout="(unset)\n")
    monkeypatch.setattr("subprocess.run", lambda *a, **k: res)
    r = pf._check_gcloud_authed()
    assert not r.ok and "gcloud auth login" in r.detail


def test_check_auth_plugin_present(monkeypatch):
    monkeypatch.setattr(pf.shutil, "which",
                        lambda t: "/usr/bin/gke-gcloud-auth-plugin" if t == "gke-gcloud-auth-plugin" else None)
    r = pf._check_auth_plugin()
    assert r.ok


def test_check_auth_plugin_missing(monkeypatch):
    monkeypatch.setattr(pf.shutil, "which", lambda t: None)
    r = pf._check_auth_plugin()
    assert not r.ok and "gke-gcloud-auth-plugin" in r.detail


def test_check_auth_plugin_missing_but_found_in_sdk_bin(monkeypatch, tmp_path):
    # Build a fake SDK bin holding a stub gcloud + the bundled plugin.
    sdk_bin = tmp_path / "google-cloud-sdk" / "bin"
    sdk_bin.mkdir(parents=True)
    gcloud = sdk_bin / "gcloud"
    gcloud.write_text("#!/bin/sh\n", encoding="utf-8")
    (sdk_bin / "gke-gcloud-auth-plugin").write_text("#!/bin/sh\n", encoding="utf-8")

    # Plugin NOT on PATH, but `which("gcloud")` resolves into the SDK bin.
    def _which(tool):
        if tool == "gke-gcloud-auth-plugin":
            return None
        if tool == "gcloud":
            return str(gcloud)
        return None

    monkeypatch.setattr(pf.shutil, "which", _which)
    r = pf._check_auth_plugin()
    assert not r.ok
    assert str(sdk_bin) in r.detail
    assert "export PATH" in r.detail


def test_check_auth_plugin_missing_and_not_in_sdk_bin(monkeypatch, tmp_path):
    # Plugin not on PATH and gcloud's dir does NOT contain the plugin.
    sdk_bin = tmp_path / "bin"
    sdk_bin.mkdir(parents=True)
    gcloud = sdk_bin / "gcloud"
    gcloud.write_text("#!/bin/sh\n", encoding="utf-8")

    def _which(tool):
        if tool == "gcloud":
            return str(gcloud)
        return None

    monkeypatch.setattr(pf.shutil, "which", _which)
    monkeypatch.setattr(pf._sys, "platform", "darwin")
    r = pf._check_auth_plugin()
    assert not r.ok
    assert "brew reinstall --cask google-cloud-sdk" in r.detail


def test_check_gke_reachable_ok(monkeypatch):
    res = mock.Mock(returncode=0, stdout="{}", stderr="")
    monkeypatch.setattr("subprocess.run", lambda *a, **k: res)
    r = pf._check_gke_reachable()
    assert r.ok


def test_check_gke_reachable_timeout_hints_vpn(monkeypatch):
    res = mock.Mock(returncode=1, stdout="",
                    stderr="Unable to connect to the server: dial tcp 1.2.3.4:443: i/o timeout")
    monkeypatch.setattr("subprocess.run", lambda *a, **k: res)
    r = pf._check_gke_reachable()
    assert not r.ok and "israel-gw" in r.detail


def test_run_preflight_includes_session_setup_checks(monkeypatch):
    _set_env(monkeypatch)
    monkeypatch.setattr(pf.shutil, "which", lambda t: "/usr/bin/" + t)
    monkeypatch.setattr(pf, "_check_connectus_repo", lambda: pf.CheckResult("repo", True, ""))
    monkeypatch.setattr(pf, "_check_probe", lambda: pf.CheckResult("probe", True, ""))
    monkeypatch.setattr(pf, "_check_gcloud_authed", lambda: pf.CheckResult("gcloud authenticated", True, "x"))
    monkeypatch.setattr(pf, "_check_auth_plugin", lambda: pf.CheckResult("gke-gcloud-auth-plugin present", True, "x"))
    names = [r.name for r in pf.run_preflight(None, for_session_setup=True)]
    assert "gcloud authenticated" in names
    assert "gke-gcloud-auth-plugin present" in names


def test_run_preflight_omits_session_setup_checks_by_default(monkeypatch):
    _set_env(monkeypatch)
    monkeypatch.setattr(pf.shutil, "which", lambda t: "/usr/bin/" + t)
    monkeypatch.setattr(pf, "_check_connectus_repo", lambda: pf.CheckResult("repo", True, ""))
    monkeypatch.setattr(pf, "_check_probe", lambda: pf.CheckResult("probe", True, ""))
    names = [r.name for r in pf.run_preflight(None)]
    assert "gcloud authenticated" not in names
    assert "gke-gcloud-auth-plugin present" not in names
