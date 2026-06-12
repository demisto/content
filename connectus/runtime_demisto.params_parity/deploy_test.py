"""Unit tests for deploy.py — agent-independent git auth + connector commit step.

Hermetic: no real git, no network, no filesystem reads of real SSH keys. We
monkeypatch ``subprocess.run``, ``Path.is_file``, and (for git_operations) the
``run_git`` seam so we only assert the git argv sequence and env injection.
"""
from __future__ import annotations

from pathlib import Path

import pytest

import deploy


# ---------------------------------------------------------------------------
# _git_ssh_command
# ---------------------------------------------------------------------------
def test_git_ssh_command_uses_config_key_when_file_exists(monkeypatch):
    key = "/custom/key/id_ed25519"
    config = {"ssh_key": key}

    real_is_file = Path.is_file

    def fake_is_file(self):
        return str(self) == str(Path(key).expanduser())

    monkeypatch.setattr(Path, "is_file", fake_is_file)
    cmd = deploy._git_ssh_command(config)
    assert cmd == f"ssh -i {Path(key).expanduser()} -o IdentitiesOnly=yes"


def test_git_ssh_command_falls_back_to_default_ed25519(monkeypatch):
    config = {"ssh_key": ""}
    default = Path("~/.ssh/id_ed25519").expanduser()

    def fake_is_file(self):
        return str(self) == str(default)

    monkeypatch.setattr(Path, "is_file", fake_is_file)
    cmd = deploy._git_ssh_command(config)
    assert cmd == f"ssh -i {default} -o IdentitiesOnly=yes"


def test_git_ssh_command_returns_none_when_no_key_found(monkeypatch):
    config = {"ssh_key": ""}
    monkeypatch.setattr(Path, "is_file", lambda self: False)
    assert deploy._git_ssh_command(config) is None


# ---------------------------------------------------------------------------
# run_git env injection
# ---------------------------------------------------------------------------
class _FakeProc:
    def __init__(self, returncode=0, stdout="", stderr=""):
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = stderr


def test_run_git_injects_git_ssh_command(monkeypatch):
    key = "/custom/key/id_ed25519"
    config = {"repo_dir": "/tmp/repo", "ssh_key": key}
    captured = {}

    def fake_is_file(self):
        return str(self) == str(Path(key).expanduser())

    def fake_run(cmd, **kwargs):
        captured["env"] = kwargs.get("env")
        captured["cmd"] = cmd
        captured["cwd"] = kwargs.get("cwd")
        return _FakeProc(returncode=0, stdout="ok")

    # Ensure no inherited GIT_SSH_COMMAND so our injection path is exercised.
    monkeypatch.delenv("GIT_SSH_COMMAND", raising=False)
    monkeypatch.setattr(Path, "is_file", fake_is_file)
    monkeypatch.setattr(deploy.subprocess, "run", fake_run)

    ok, out = deploy.run_git(config, "status")
    assert ok is True
    assert captured["cmd"] == ["git", "status"]
    assert captured["cwd"] == "/tmp/repo"
    expected = f"ssh -i {Path(key).expanduser()} -o IdentitiesOnly=yes"
    assert captured["env"]["GIT_SSH_COMMAND"] == expected


def test_run_git_does_not_override_existing_git_ssh_command(monkeypatch):
    key = "/custom/key/id_ed25519"
    config = {"repo_dir": "/tmp/repo", "ssh_key": key}
    captured = {}

    monkeypatch.setattr(Path, "is_file",
                        lambda self: str(self) == str(Path(key).expanduser()))
    monkeypatch.setenv("GIT_SSH_COMMAND", "ssh -i /preset/key")

    def fake_run(cmd, **kwargs):
        captured["env"] = kwargs.get("env")
        return _FakeProc(returncode=0, stdout="ok")

    monkeypatch.setattr(deploy.subprocess, "run", fake_run)
    deploy.run_git(config, "status")
    assert captured["env"]["GIT_SSH_COMMAND"] == "ssh -i /preset/key"


def test_run_git_no_ssh_command_when_no_key(monkeypatch):
    config = {"repo_dir": "/tmp/repo", "ssh_key": ""}
    captured = {}

    monkeypatch.setattr(Path, "is_file", lambda self: False)
    monkeypatch.delenv("GIT_SSH_COMMAND", raising=False)

    def fake_run(cmd, **kwargs):
        captured["env"] = kwargs.get("env")
        return _FakeProc(returncode=0, stdout="ok")

    monkeypatch.setattr(deploy.subprocess, "run", fake_run)
    deploy.run_git(config, "status")
    assert "GIT_SSH_COMMAND" not in captured["env"]


# ---------------------------------------------------------------------------
# git_operations commit step
# ---------------------------------------------------------------------------
def _base_config(**overrides):
    cfg = {
        "repo_dir": "/tmp/repo",
        "branch_name": "xsoar",
        "ssh_key": "",
        "commit_path": "",
    }
    cfg.update(overrides)
    return cfg


class _FakeGit:
    """Records git argv sequences and returns scripted (ok, out) per command.

    ``scripts`` maps a matching prefix tuple of args to a (ok, out) result. If no
    script matches, returns (True, "") to keep the happy path flowing.
    """

    def __init__(self, scripts=None):
        self.calls = []
        self.scripts = scripts or {}

    def __call__(self, config, *args):
        self.calls.append(args)
        for prefix, result in self.scripts.items():
            if args[: len(prefix)] == prefix:
                return result
        return True, ""


def test_git_operations_commits_when_staged_changes(monkeypatch):
    config = _base_config(branch_name="xsoar-migration-joey", commit_path="connectors/aws")
    # show-ref returns ok (local branch exists) so we checkout it (no reset).
    # git diff --cached --quiet returns ok=False (rc!=0) => something IS staged.
    fake = _FakeGit(scripts={
        ("show-ref",): (True, ""),
        ("diff", "--cached", "--quiet"): (False, "staged"),
    })
    monkeypatch.setattr(deploy, "run_git", fake)

    deploy.git_operations(config)

    assert ("add", "--", "connectors/aws") in fake.calls
    commit_calls = [c for c in fake.calls if c[:1] == ("commit",)]
    assert len(commit_calls) == 1
    assert commit_calls[0] == ("commit", "-m", "param-parity: deploy connectors/aws")


def test_git_operations_skips_commit_when_nothing_staged(monkeypatch):
    config = _base_config(branch_name="xsoar-migration-joey", commit_path="connectors/aws")
    # diff --cached --quiet returns ok=True (rc==0) => NOTHING staged.
    fake = _FakeGit(scripts={
        ("show-ref",): (True, ""),
        ("diff", "--cached", "--quiet"): (True, ""),
    })
    monkeypatch.setattr(deploy, "run_git", fake)

    deploy.git_operations(config)

    assert ("add", "--", "connectors/aws") in fake.calls
    commit_calls = [c for c in fake.calls if c[:1] == ("commit",)]
    assert commit_calls == []  # skipped


def test_git_operations_no_commit_when_commit_path_empty(monkeypatch):
    config = _base_config(branch_name="xsoar-migration-joey", commit_path="")
    fake = _FakeGit(scripts={("show-ref",): (True, "")})
    monkeypatch.setattr(deploy, "run_git", fake)

    deploy.git_operations(config)

    add_calls = [c for c in fake.calls if c[:1] == ("add",)]
    commit_calls = [c for c in fake.calls if c[:1] == ("commit",)]
    assert add_calls == []
    assert commit_calls == []


# ---------------------------------------------------------------------------
# Safety invariants: NEVER reset --hard, NEVER force-push (new branch model)
# ---------------------------------------------------------------------------
def test_git_operations_never_resets_hard(monkeypatch):
    """The deploy must NOT `git reset --hard` — that destroyed local work and
    was the root cause of clobbering a shared branch. Branch is checked out as-is."""
    config = _base_config(branch_name="xsoar-migration-joey", commit_path="connectors/aws")
    fake = _FakeGit(scripts={
        ("show-ref",): (True, ""),  # local branch exists → checkout, no reset
        ("diff", "--cached", "--quiet"): (False, "staged"),
    })
    monkeypatch.setattr(deploy, "run_git", fake)

    deploy.git_operations(config)

    reset_calls = [c for c in fake.calls if c[:1] == ("reset",)]
    assert reset_calls == [], f"deploy must never reset --hard, got: {reset_calls}"


def test_git_operations_push_is_plain_no_force(monkeypatch):
    """The push must be a plain fast-forward push — never --force / --force-with-lease."""
    config = _base_config(branch_name="xsoar-migration-joey", commit_path="connectors/aws")
    fake = _FakeGit(scripts={
        ("show-ref",): (True, ""),
        ("diff", "--cached", "--quiet"): (False, "staged"),
    })
    monkeypatch.setattr(deploy, "run_git", fake)

    deploy.git_operations(config)

    push_calls = [c for c in fake.calls if c[:1] == ("push",)]
    assert push_calls == [("push", "origin", "xsoar-migration-joey")], push_calls
    for c in push_calls:
        assert "--force" not in c
        assert "--force-with-lease" not in c


def test_git_operations_creates_local_tracking_remote_when_no_local(monkeypatch):
    """If no local branch but remote exists, create local tracking origin/<branch>
    (still no reset)."""
    config = _base_config(branch_name="xsoar-migration-joey")

    def script(config, *args):
        script_fake.calls.append(args)
        if args[:1] == ("show-ref",):
            # local refs/heads missing, remote refs/remotes present
            if args[-1].startswith("refs/heads/"):
                return False, ""
            if args[-1].startswith("refs/remotes/"):
                return True, ""
        return True, ""

    script_fake = _FakeGit()
    script_fake.__call__ = None  # use the closure above instead
    monkeypatch.setattr(deploy, "run_git", script)
    script_fake.calls = []

    deploy.git_operations(config)

    checkout_calls = [c for c in script_fake.calls if c[:1] == ("checkout",)]
    assert ("checkout", "-b", "xsoar-migration-joey", "origin/xsoar-migration-joey") in checkout_calls
    assert [c for c in script_fake.calls if c[:1] == ("reset",)] == []


# ---------------------------------------------------------------------------
# Hard guardrail: refuse to operate on any non-personal branch (CHANGE 1)
# ---------------------------------------------------------------------------
@pytest.mark.parametrize(
    "bad_branch",
    [
        "stable",
        "dev",
        "master",
        "xsoar-playground",
        "XSOAR-migration-Joey",  # uppercase not allowed
        "xsoar-migration-",      # trailing dash only / empty name
        "",                      # empty
    ],
)
def test_git_operations_rejects_non_personal_branch(monkeypatch, bad_branch):
    """The deploy must HARD-REFUSE any branch that is not a personal
    `xsoar-migration-<name>` branch, BEFORE recording any git mutation, even if
    preflight was skipped. No commit/push (indeed NO git call at all) may occur."""
    config = _base_config(branch_name=bad_branch, commit_path="connectors/aws")
    fake = _FakeGit()
    monkeypatch.setattr(deploy, "run_git", fake)

    with pytest.raises(SystemExit):
        deploy.git_operations(config)

    # It must bail before ANY git mutation — no commits, no pushes, and in fact
    # no git calls at all (the guard runs before fetch/checkout).
    commit_calls = [c for c in fake.calls if c[:1] == ("commit",)]
    push_calls = [c for c in fake.calls if c[:1] == ("push",)]
    assert commit_calls == [], f"must not commit on bad branch {bad_branch!r}"
    assert push_calls == [], f"must not push on bad branch {bad_branch!r}"
    assert fake.calls == [], f"must not run any git on bad branch {bad_branch!r}"


def test_git_operations_accepts_personal_branch(monkeypatch):
    """A valid personal branch proceeds through the happy path (no SystemExit)."""
    config = _base_config(branch_name="xsoar-migration-joey", commit_path="connectors/aws")
    fake = _FakeGit(scripts={
        ("show-ref",): (True, ""),
        ("diff", "--cached", "--quiet"): (False, "staged"),
    })
    monkeypatch.setattr(deploy, "run_git", fake)

    deploy.git_operations(config)  # must not raise

    push_calls = [c for c in fake.calls if c[:1] == ("push",)]
    assert push_calls == [("push", "origin", "xsoar-migration-joey")]


def test_assert_personal_branch_accepts_valid_names():
    """Unit-level: the guard accepts well-formed personal branch names."""
    for good in ("xsoar-migration-joey", "xsoar-migration-a", "xsoar-migration-j0ey",
                 "xsoar-migration-team-1"):
        deploy._assert_personal_branch(good)  # must not raise


@pytest.mark.parametrize(
    "bad", ["stable", "dev", "master", "xsoar-playground",
            "XSOAR-migration-Joey", "xsoar-migration-", "xsoar-migration-A", ""],
)
def test_assert_personal_branch_rejects_bad_names(bad):
    """Unit-level: the guard rejects shared/protected/malformed branch names."""
    with pytest.raises(SystemExit):
        deploy._assert_personal_branch(bad)
