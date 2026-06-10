"""Unit tests for the unified :mod:`env_loader` module.

These tests use ``pytest`` fixtures (``monkeypatch``/``tmp_path``) and never
require real secrets or a real ``.env`` file.
"""

from __future__ import annotations

import importlib
from pathlib import Path

import env_loader


def test_find_repo_root_contains_pyproject() -> None:
    """Repo-root detection should return a dir containing ``pyproject.toml``."""
    root = env_loader.find_repo_root()
    assert (root / "pyproject.toml").exists()


def test_find_repo_root_walks_up_from_marker(tmp_path: Path) -> None:
    """A marker file in a parent dir should be discovered from a nested dir."""
    (tmp_path / "pyproject.toml").write_text("[tool.test]\n")
    nested = tmp_path / "a" / "b" / "c"
    nested.mkdir(parents=True)
    assert env_loader.find_repo_root(nested) == tmp_path


def test_load_env_returns_root_env_path() -> None:
    """``load_env`` should resolve ``<repo_root>/.env``."""
    importlib.reload(env_loader)
    env_path = env_loader.load_env()
    assert env_path.name == ".env"
    assert env_path.parent == env_loader.find_repo_root()


def test_load_env_is_idempotent(monkeypatch) -> None:
    """Repeated calls without ``override`` should only load once."""
    importlib.reload(env_loader)

    calls: list[bool] = []

    def fake_load_dotenv(*_args, **kwargs) -> bool:
        calls.append(kwargs.get("override", False))
        return True

    import dotenv

    monkeypatch.setattr(dotenv, "load_dotenv", fake_load_dotenv)

    env_loader.load_env()
    env_loader.load_env()
    env_loader.load_env()

    assert len(calls) == 1  # only the first call hits load_dotenv


def test_load_env_override_reloads(monkeypatch) -> None:
    """With ``override=True`` the file is reloaded even after a prior load."""
    importlib.reload(env_loader)

    calls: list[bool] = []

    def fake_load_dotenv(*_args, **kwargs) -> bool:
        calls.append(kwargs.get("override", False))
        return True

    import dotenv

    monkeypatch.setattr(dotenv, "load_dotenv", fake_load_dotenv)

    env_loader.load_env()
    env_loader.load_env(override=True)

    assert calls == [False, True]


def test_load_env_missing_file_is_graceful(monkeypatch, tmp_path: Path) -> None:
    """A missing ``.env`` should not crash; the path is still returned."""
    importlib.reload(env_loader)

    monkeypatch.setattr(env_loader, "find_repo_root", lambda *a, **k: tmp_path)

    loaded: list[str] = []

    def fake_load_dotenv(*_args, **kwargs) -> bool:
        loaded.append(str(kwargs.get("dotenv_path")))
        return False

    import dotenv

    monkeypatch.setattr(dotenv, "load_dotenv", fake_load_dotenv)

    env_path = env_loader.load_env()
    assert env_path == tmp_path / ".env"
    assert not env_path.exists()
    assert loaded == [str(tmp_path / ".env")]


def test_load_env_missing_dotenv_dependency(monkeypatch) -> None:
    """If python-dotenv is unimportable, load_env degrades gracefully."""
    importlib.reload(env_loader)

    import builtins

    real_import = builtins.__import__

    def fake_import(name: str, *args, **kwargs):
        if name == "dotenv":
            raise ImportError("simulated missing dotenv")
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", fake_import)

    env_path = env_loader.load_env()
    assert env_path.name == ".env"
