"""Tests for the ``CONNECTUS_PIPELINE_CSV`` override in
:mod:`workflow_state.csv_io`.

The pipeline CSV path is normally the bundled
``<repo_root>/connectus/connectus-migration-pipeline.csv``. Setting the
``CONNECTUS_PIPELINE_CSV`` env var to a full path (absolute, relative-to-repo,
or ``~``-prefixed) redirects all pipeline reads/writes to that file.

These tests exercise the path-resolution helper directly (no real CSV on disk
is needed) and confirm the existing ``monkeypatch.setattr(workflow_state,
"CSV_PATH", ...)`` indirection still wins, since :func:`csv_io._csv_path`
reads ``CSV_PATH`` from the package namespace at call time.
"""
from __future__ import annotations

import importlib
import os

import pytest

import env_loader
import workflow_state
from workflow_state import csv_io
from workflow_state.csv_io import (
    _DEFAULT_CSV_PATH,
    PIPELINE_CSV_ENV_VAR,
    _csv_path,
    _resolve_pipeline_csv,
)


def test_env_unset_falls_back_to_default(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv(PIPELINE_CSV_ENV_VAR, raising=False)
    assert _resolve_pipeline_csv() == _DEFAULT_CSV_PATH


def test_env_empty_falls_back_to_default(monkeypatch: pytest.MonkeyPatch) -> None:
    # Empty / whitespace-only values are treated as unset.
    monkeypatch.setenv(PIPELINE_CSV_ENV_VAR, "   ")
    assert _resolve_pipeline_csv() == _DEFAULT_CSV_PATH


def test_env_absolute_path_passes_through(
    tmp_path, monkeypatch: pytest.MonkeyPatch
) -> None:
    abs_path = tmp_path / "my-pipeline.csv"
    monkeypatch.setenv(PIPELINE_CSV_ENV_VAR, str(abs_path))
    assert _resolve_pipeline_csv() == str(abs_path)


def test_env_relative_path_resolved_against_repo_root(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv(PIPELINE_CSV_ENV_VAR, "custom/pipe.csv")
    expected = os.path.join(workflow_state.BASE_DIR, "custom/pipe.csv")
    assert _resolve_pipeline_csv() == expected


def test_env_tilde_is_expanded(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv(PIPELINE_CSV_ENV_VAR, "~/pipe.csv")
    resolved = _resolve_pipeline_csv()
    assert "~" not in resolved
    assert resolved == os.path.join(os.path.expanduser("~"), "pipe.csv")


def test_monkeypatched_csv_path_still_wins(
    tmp_path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Existing tests monkeypatch ``workflow_state.CSV_PATH`` directly; the
    call-time indirection in ``_csv_path()`` must keep honoring that, even when
    the env var is also set (the module-level CSV_PATH is computed once at import
    and the override is read via the namespace)."""
    override = str(tmp_path / "patched.csv")
    monkeypatch.setenv(PIPELINE_CSV_ENV_VAR, str(tmp_path / "from-env.csv"))
    monkeypatch.setattr(workflow_state, "CSV_PATH", override)
    assert _csv_path() == override


# ===========================================================================
# IMPORT-TIME wire-up (reload-based).
#
# The tests above exercise the ``_resolve_pipeline_csv()`` HELPER directly. They
# do NOT prove that the FROZEN module-level ``CSV_PATH`` attribute — the value
# production code actually consumes (``load_csv`` / ``save_csv`` read it via
# ``_csv_path()`` from the package namespace) — reflects the env var when it is
# set BEFORE import. ``CSV_PATH`` is computed exactly once, at import time
# (``CSV_PATH = _resolve_pipeline_csv()``), so a plain ``setenv`` never changes
# it. The only way to re-run that import-time resolution is to reload the module.
#
# These tests therefore set the env var, ``importlib.reload`` the module so the
# module-level resolution re-runs, and assert the frozen attribute reflects the
# override (and, with the var unset, the bundled default).
#
# STATE-LEAKAGE NOTE: reloading mutates the module objects PROCESS-WIDE. Both
# ``csv_io.CSV_PATH`` and the package re-export ``workflow_state.CSV_PATH`` are
# affected; many other suites in this process read ``workflow_state`` symbols.
# Critically, ``importlib.reload`` also REBINDS module-level objects (functions,
# classes) to new identities, which can break ``from workflow_state[.csv_io]
# import X`` references captured elsewhere. The ``reload_csv_modules_to_default``
# fixture therefore SNAPSHOTS the original ``__dict__`` of BOTH modules up front
# and, in its finalizer (run even on failure), restores those exact dicts onto
# the SAME module objects — bringing back the original objects so every imported
# reference stays identity-stable, with the frozen ``CSV_PATH`` back at its
# bundled default. ``env_loader._loaded`` is also restored in case the test
# touched it.
# ===========================================================================


def _reload_csv_io_and_package() -> None:
    """Re-run csv_io's import-time resolution, then refresh the package re-export.

    ``workflow_state.csv_io`` computes ``CSV_PATH`` at import. Reloading it
    re-runs that line against the CURRENT environment. The package
    ``workflow_state`` re-exports ``CSV_PATH`` (``from workflow_state.csv_io
    import CSV_PATH``), so it must be reloaded AFTER csv_io for the re-export to
    pick up the new value — that package attribute is what production callers and
    other tests read.
    """
    importlib.reload(csv_io)
    importlib.reload(workflow_state)


@pytest.fixture
def reload_csv_modules_to_default(monkeypatch: pytest.MonkeyPatch):
    """Provide a reloader and GUARANTEE identity-stable teardown.

    Yields a callable that reloads ``csv_io`` + the package against the current
    environment. The finalizer (run even if the test body raises) removes the
    override env var and restores SNAPSHOTS of both modules' original
    ``__dict__`` onto the same module objects — bringing back the original
    objects (so other tests' imported references stay identity-stable) and the
    frozen ``CSV_PATH`` to the bundled default, so the mutation never leaks into
    other tests. ``env_loader._loaded`` is also restored in case the test
    touched it.
    """
    saved_loaded = env_loader._loaded
    saved_csv_io = dict(csv_io.__dict__)
    saved_ws = dict(workflow_state.__dict__)
    try:
        yield _reload_csv_io_and_package
    finally:
        monkeypatch.delenv(PIPELINE_CSV_ENV_VAR, raising=False)
        env_loader._loaded = saved_loaded
        csv_io.__dict__.clear()
        csv_io.__dict__.update(saved_csv_io)
        workflow_state.__dict__.clear()
        workflow_state.__dict__.update(saved_ws)


def test_import_time_csv_path_reflects_env_override(
    tmp_path, monkeypatch: pytest.MonkeyPatch, reload_csv_modules_to_default
) -> None:
    """When ``CONNECTUS_PIPELINE_CSV`` is set BEFORE the module resolves its
    path, the FROZEN module-level ``CSV_PATH`` (the value production code
    consumes) reflects the override — proving the import-time wire-up, not just
    the helper. Asserts on both ``csv_io.CSV_PATH`` and the package re-export
    ``workflow_state.CSV_PATH``."""
    override = tmp_path / "override-pipeline.csv"
    monkeypatch.setenv(PIPELINE_CSV_ENV_VAR, str(override))

    reload_csv_modules_to_default()

    assert csv_io.CSV_PATH == str(override)
    assert workflow_state.CSV_PATH == str(override)


def test_import_time_csv_path_unset_yields_bundled_default(
    monkeypatch: pytest.MonkeyPatch, reload_csv_modules_to_default
) -> None:
    """Companion: with the env var UNSET, a fresh reload re-resolves the frozen
    ``CSV_PATH`` back to the bundled default (proving the import-time fallback,
    not just the helper's)."""
    monkeypatch.delenv(PIPELINE_CSV_ENV_VAR, raising=False)

    reload_csv_modules_to_default()

    assert csv_io.CSV_PATH == _DEFAULT_CSV_PATH
    assert workflow_state.CSV_PATH == _DEFAULT_CSV_PATH
