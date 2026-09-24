"""Sanity tests for the Okta v2 shim integration.

Full behavioural coverage lives in the OktaApiModule tests; this file
exists only to confirm the shim wires through to the ApiModule correctly.
"""

from unittest.mock import patch  # noqa: F401

import pytest
import Okta_v2 as integration_module


def test_shim_imports_run_entry_point():
    """The shim must re-export the ApiModule entry point under its expected name."""
    assert hasattr(integration_module, "run_okta_v2_integration"), (
        "OktaApiModule.run_okta_v2_integration must be importable via the shim"
    )


def test_shim_imports_client():
    """The shim must re-export the Okta v2 Client class and its OktaClient base."""
    assert hasattr(integration_module, "Client")
    assert hasattr(integration_module, "OktaClient")
    assert issubclass(integration_module.Client, integration_module.OktaClient)


def test_shim_imports_auth_symbols():
    """Auth helpers used by the UCP flow must remain accessible from the shim."""
    for name in ("AuthType", "JWTAlgorithm", "resolve_ucp_auth_type", "reset_integration_context"):
        assert hasattr(integration_module, name), f"Symbol {name!r} missing from shim"


def test_shim_imports_constants():
    """Module-level constants used by playbooks/tests must remain accessible from the shim."""
    for name in ("DATE_FORMAT", "OAUTH_TOKEN_SCOPES", "PROFILE_ARGS", "GROUP_PROFILE_ARGS"):
        assert hasattr(integration_module, name), f"Constant {name!r} missing from shim"


def test_main_delegates_to_api_module(mocker):
    """`main()` must do nothing other than call the renamed ApiModule entry point."""
    mock_run = mocker.patch("Okta_v2.run_okta_v2_integration")
    integration_module.main()
    mock_run.assert_called_once_with()


def test_main_propagates_exceptions(mocker):
    """`main()` is a thin shim and must not swallow exceptions from the ApiModule."""
    mocker.patch("Okta_v2.run_okta_v2_integration", side_effect=RuntimeError("boom"))

    with pytest.raises(RuntimeError, match="boom"):
        integration_module.main()
