"""Path-resolution unit tests for the param-parity orchestrator.

Focused, hermetic tests (NO network / tenant / docker) that pin down the
ONE behavior the path-resolution bug-fix is about: a RELATIVE integration-yml
path must be resolved against the CONTENT-REPO WORKSPACE ROOT
(``resolver._WORKSPACE_ROOT``), NOT against the current working directory.

Background — the bug:
  ``check_param_parity.main()`` used ``os.path.abspath(integration_yml)`` to
  turn a relative CSV path (e.g. ``Packs/AWS-ACM/Integrations/AWS-ACM/AWS-ACM.yml``)
  into an absolute one. ``os.path.abspath`` resolves against the CWD, but the
  wrapper runs the script with ``cwd=runtime_demisto.params_parity/``, so the
  path resolved to ``runtime_demisto.params_parity/Packs/...`` which does not
  exist → ``return 2`` (setup-blocked). The correct base is the workspace root,
  exposed by ``resolver._abs_integration_yml`` / ``resolver._WORKSPACE_ROOT``.

These tests target the path helper directly (the actual fix point); driving the
full ``main()`` is intentionally avoided because it pulls in network deps.
"""
from __future__ import annotations

import os

import resolver


# ---------------------------------------------------------------------------
# Option 1 — test resolver._abs_integration_yml directly.
# ---------------------------------------------------------------------------


def test_relative_path_resolves_under_workspace_root():
    """A relative repo path resolves under _WORKSPACE_ROOT and keeps its tail."""
    rel = "Packs/Foo/Bar.yml"
    resolved = resolver._abs_integration_yml(rel)

    assert os.path.isabs(resolved)
    assert resolved.startswith(str(resolver._WORKSPACE_ROOT))
    assert resolved.endswith(os.path.join("Packs", "Foo", "Bar.yml"))


def test_relative_path_is_exactly_workspace_root_joined():
    """The resolved path equals _WORKSPACE_ROOT / <rel> (resolved)."""
    rel = "Packs/Foo/Bar.yml"
    expected = str((resolver._WORKSPACE_ROOT / rel).resolve())
    assert resolver._abs_integration_yml(rel) == expected


def test_absolute_path_returned_unchanged():
    """An already-absolute path is returned as-is (no re-rooting)."""
    abs_path = "/tmp/some/absolute/Integration.yml"
    assert resolver._abs_integration_yml(abs_path) == abs_path


# ---------------------------------------------------------------------------
# Option 2 — regression: workspace-rooted, NOT cwd-rooted.
# ---------------------------------------------------------------------------


def test_resolution_ignores_cwd(monkeypatch):
    """Even with a bogus CWD, resolution stays under the workspace root.

    This is the exact failure mode of the original bug: the script's CWD was
    ``runtime_demisto.params_parity/`` (not the repo root). A CWD-relative
    resolver (``os.path.abspath``) would re-root the path under the CWD; the
    workspace-rooted helper must not.
    """
    rel = "Packs/AWS-ACM/Integrations/AWS-ACM/AWS-ACM.yml"

    bogus_cwd = str(resolver._WORKSPACE_ROOT / "connectus" / "runtime_demisto.params_parity")
    monkeypatch.setattr(os, "getcwd", lambda: bogus_cwd)

    resolved = resolver._abs_integration_yml(rel)

    assert resolved.startswith(str(resolver._WORKSPACE_ROOT))
    # Must NOT have been re-rooted under the (bogus) CWD.
    assert "runtime_demisto.params_parity" not in resolved


# ---------------------------------------------------------------------------
# Fix-site guard — check_param_parity must delegate to the workspace-rooted
# helper (not re-introduce a CWD-relative os.path.abspath).
# ---------------------------------------------------------------------------


def test_check_param_parity_delegates_to_workspace_helper():
    """The orchestrator's source must call resolver_mod._abs_integration_yml.

    Guards against a regression to the CWD-relative ``os.path.abspath`` path
    resolution that caused the setup-block bug.
    """
    import inspect

    import check_param_parity

    src = inspect.getsource(check_param_parity.main)
    assert "_abs_integration_yml" in src, (
        "check_param_parity.main() must resolve a relative integration-yml via "
        "resolver_mod._abs_integration_yml (workspace-rooted), not os.path.abspath."
    )
