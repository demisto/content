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


# ---------------------------------------------------------------------------
# NO_PROXY augmentation (proxy-bypass for the XSOAR/tenant host)
# ---------------------------------------------------------------------------
#
# The idex CLI / VS Code injects HTTPS_PROXY into the subprocess env; a
# corporate proxy then 403s the CONNECT tunnel to the tenant host. load_env()
# must augment NO_PROXY/no_proxy so the tenant host (from DEMISTO_BASE_URL),
# the .paloaltonetworks.com suffix and localhost/127.0.0.1 always bypass it.

_TENANT_HOST = "connectus-yyy-july-migration-3.xdr-qa2-uat.us.paloaltonetworks.com"
_TENANT_API_HOST = f"api-{_TENANT_HOST}"
_TENANT_URL = f"https://{_TENANT_HOST}"


def _stub_dotenv_noop(monkeypatch) -> None:
    """Make ``load_dotenv`` a no-op so the real root .env never interferes."""
    import dotenv

    monkeypatch.setattr(dotenv, "load_dotenv", lambda *a, **k: True)


def _clear_proxy_env(monkeypatch) -> None:
    """Start each proxy test from a clean slate."""
    for var in ("NO_PROXY", "no_proxy", "HTTPS_PROXY", "HTTP_PROXY"):
        monkeypatch.delenv(var, raising=False)


def test_no_proxy_includes_tenant_host(monkeypatch) -> None:
    """After load_env, both NO_PROXY variants bypass the tenant host."""
    importlib.reload(env_loader)
    _clear_proxy_env(monkeypatch)
    _stub_dotenv_noop(monkeypatch)
    monkeypatch.setenv("DEMISTO_BASE_URL", _TENANT_URL)

    env_loader.load_env()

    for var in ("NO_PROXY", "no_proxy"):
        entries = [e.strip() for e in env_loader.os.environ[var].split(",")]
        assert _TENANT_HOST in entries
        # The SDK rewrites the tenant host to ``api-<host>`` for XSIAM/XSOAR-8
        # API calls, so the api-prefixed variant must be present too.
        assert _TENANT_API_HOST in entries
        assert ".paloaltonetworks.com" in entries
        assert "localhost" in entries
        assert "127.0.0.1" in entries


def test_no_proxy_preserves_existing_and_dedupes(monkeypatch) -> None:
    """Pre-existing NO_PROXY entries are preserved first and not duplicated."""
    importlib.reload(env_loader)
    _clear_proxy_env(monkeypatch)
    _stub_dotenv_noop(monkeypatch)
    monkeypatch.setenv("DEMISTO_BASE_URL", _TENANT_URL)
    # Pre-existing value, including one entry we will also add (localhost).
    monkeypatch.setenv("NO_PROXY", "example.com,localhost")

    env_loader.load_env()

    entries = [e.strip() for e in env_loader.os.environ["NO_PROXY"].split(",")]
    # Pre-existing custom entry survives.
    assert "example.com" in entries
    # Existing entries come first (order preserved).
    assert entries[0] == "example.com"
    # Newly-added host present.
    assert _TENANT_HOST in entries
    # No duplicates anywhere (e.g. localhost only once).
    assert len(entries) == len(set(entries))
    assert entries.count("localhost") == 1


def test_no_proxy_api_host_present_once_and_idempotent(monkeypatch) -> None:
    """The api-<host> variant is added exactly once and survives re-runs."""
    importlib.reload(env_loader)
    _clear_proxy_env(monkeypatch)
    _stub_dotenv_noop(monkeypatch)
    monkeypatch.setenv("DEMISTO_BASE_URL", _TENANT_URL)

    env_loader.load_env()
    env_loader.load_env(override=True)  # re-run augmentation

    for var in ("NO_PROXY", "no_proxy"):
        entries = [e.strip() for e in env_loader.os.environ[var].split(",")]
        # The api- variant is present and not duplicated.
        assert entries.count(_TENANT_API_HOST) == 1
        # Both the bare host and the api- host are present.
        assert _TENANT_HOST in entries
        assert _TENANT_API_HOST in entries
        assert len(entries) == len(set(entries))


def test_no_proxy_is_idempotent(monkeypatch) -> None:
    """Calling load_env twice does not duplicate bypass entries."""
    importlib.reload(env_loader)
    _clear_proxy_env(monkeypatch)
    _stub_dotenv_noop(monkeypatch)
    monkeypatch.setenv("DEMISTO_BASE_URL", _TENANT_URL)

    env_loader.load_env()
    first = env_loader.os.environ["NO_PROXY"]
    # override=True re-runs the augmentation path.
    env_loader.load_env(override=True)
    second = env_loader.os.environ["NO_PROXY"]

    assert first == second
    entries = [e.strip() for e in second.split(",")]
    assert len(entries) == len(set(entries))


def test_no_proxy_blank_base_url_is_safe(monkeypatch) -> None:
    """A blank/unset DEMISTO_BASE_URL never crashes; localhost still present."""
    importlib.reload(env_loader)
    _clear_proxy_env(monkeypatch)
    _stub_dotenv_noop(monkeypatch)
    # Blank value (and we also test the fully-unset case below).
    monkeypatch.setenv("DEMISTO_BASE_URL", "   ")

    env_loader.load_env()

    for var in ("NO_PROXY", "no_proxy"):
        entries = [e.strip() for e in env_loader.os.environ[var].split(",")]
        assert "localhost" in entries
        assert "127.0.0.1" in entries
        # No spurious host / suffix entries when there is no real host.
        assert ".paloaltonetworks.com" not in entries


def test_no_proxy_unset_base_url_is_safe(monkeypatch) -> None:
    """A fully-unset DEMISTO_BASE_URL still yields localhost/127.0.0.1."""
    importlib.reload(env_loader)
    _clear_proxy_env(monkeypatch)
    _stub_dotenv_noop(monkeypatch)
    monkeypatch.delenv("DEMISTO_BASE_URL", raising=False)

    env_loader.load_env()

    for var in ("NO_PROXY", "no_proxy"):
        entries = [e.strip() for e in env_loader.os.environ[var].split(",")]
        assert "localhost" in entries
        assert "127.0.0.1" in entries
