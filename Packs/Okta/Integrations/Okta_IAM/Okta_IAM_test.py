"""Sanity tests for the Okta IAM shim integration.

Full behavioural coverage lives in the OktaIAMApiModule tests; this file
exists only to confirm the shim wires through to the ApiModule correctly.
"""

from unittest.mock import patch  # noqa: F401

import pytest
import Okta_IAM as integration_module


def test_shim_imports_run_entry_point():
    """The shim must re-export the ApiModule entry point under its expected name."""
    assert hasattr(
        integration_module, "run_okta_iam_integration"
    ), "OktaIAMApiModule.run_okta_iam_integration must be importable via the shim"


def test_shim_imports_client():
    """The shim must re-export the Okta IAM Client class."""
    assert hasattr(integration_module, "Client")


def test_shim_imports_iam_api_module_symbols():
    """OktaIAMApiModule layers on IAMApiModule, so its primitives must reach the shim."""
    for name in ("IAMUserProfile", "IAMActions", "IAMErrors"):
        assert hasattr(integration_module, name), f"Symbol {name!r} missing from shim"


def test_shim_imports_commands_and_constants():
    """Commands and constants used by playbooks/tests must remain accessible from the shim."""
    for name in ("get_user_command", "create_user_command", "fetch_incidents", "DEPROVISIONED_STATUS"):
        assert hasattr(integration_module, name), f"Symbol {name!r} missing from shim"


def test_main_delegates_to_api_module(mocker):
    """`main()` must do nothing other than call the renamed ApiModule entry point."""
    mock_run = mocker.patch("Okta_IAM.run_okta_iam_integration")
    integration_module.main()
    mock_run.assert_called_once_with()


def test_main_propagates_exceptions(mocker):
    """`main()` is a thin shim and must not swallow exceptions from the ApiModule."""
    mocker.patch("Okta_IAM.run_okta_iam_integration", side_effect=RuntimeError("boom"))

    with pytest.raises(RuntimeError, match="boom"):
        integration_module.main()
