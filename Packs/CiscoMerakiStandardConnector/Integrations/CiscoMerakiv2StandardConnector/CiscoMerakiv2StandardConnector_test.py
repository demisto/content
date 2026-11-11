"""Sanity tests for the CiscoMerakiv2StandardConnector shim integration.

Full behavioural coverage lives in the CiscoMerakiApiModule tests; this file
exists only to confirm the shim wires through to the ApiModule correctly.
"""

import CiscoMerakiv2StandardConnector as integration_module
import pytest


def test_shim_imports_run_entry_point():
    assert hasattr(integration_module, "run_cisco_meraki_v2_integration")


def test_shim_imports_auth_symbols():
    for name in ("MerakiBaseClient", "MerakiAuthMode", "resolve_meraki_base_url"):
        assert hasattr(integration_module, name), f"Symbol {name!r} missing from shim"


def test_main_delegates_to_api_module(mocker):
    mock_run = mocker.patch("CiscoMerakiv2StandardConnector.run_cisco_meraki_v2_integration")
    integration_module.main()
    mock_run.assert_called_once_with()


def test_main_propagates_exceptions(mocker):
    mocker.patch("CiscoMerakiv2StandardConnector.run_cisco_meraki_v2_integration", side_effect=RuntimeError("boom"))
    with pytest.raises(RuntimeError, match="boom"):
        integration_module.main()
