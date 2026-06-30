"""Sanity tests for the GoogleDriveStandardConnector shim integration.

Full behavioural coverage lives in the GoogleDriveApiModule tests; this file
exists only to confirm the shim wires through to the ApiModule correctly.
"""
from unittest.mock import patch  # noqa: F401

import GoogleDriveStandardConnector as integration_module


def test_shim_imports_run_entry_point():
    """The shim must re-export the ApiModule entry point under its expected name."""
    assert hasattr(integration_module, "run_google_drive_integration"), \
        "GoogleDriveApiModule.run_google_drive_integration must be importable via the shim"


def test_shim_imports_gsuite_client():
    """The shim must re-export the GSuiteClient class (originally from GSuiteApiModule, re-exported via the ApiModule)."""
    assert hasattr(integration_module, "GSuiteClient")


def test_shim_imports_constants():
    """Module-level constants used by playbooks/tests must remain accessible from the shim."""
    for name in ("HR_MESSAGES", "MESSAGES", "OUTPUT_PREFIX"):
        assert hasattr(integration_module, name), f"Constant {name!r} missing from shim"


def test_main_delegates_to_api_module(mocker):
    """`main()` must do nothing other than call the renamed ApiModule entry point."""
    mock_run = mocker.patch("GoogleDriveStandardConnector.run_google_drive_integration")
    integration_module.main()
    mock_run.assert_called_once_with()


def test_main_propagates_exceptions(mocker):
    """`main()` is a thin shim and must not swallow exceptions from the ApiModule."""
    mocker.patch("GoogleDriveStandardConnector.run_google_drive_integration", side_effect=RuntimeError("boom"))
    import pytest
    with pytest.raises(RuntimeError, match="boom"):
        integration_module.main()
