"""Sanity tests for the MicrosoftGraphTeamsStandardConnector shim integration.

Full behavioural coverage lives in the MicrosoftGraphTeamsApiModule tests; this file
exists only to confirm the shim wires through to the ApiModule correctly. Mirrors the
`MicrosoftGraphFilesStandardConnector` satellite pack's sanity-test shape.
"""

import pytest

import MicrosoftGraphTeamsStandardConnector as integration_module


def test_shim_imports_run_entry_point():
    assert hasattr(
        integration_module, "run_microsoft_graph_teams_integration"
    ), "MicrosoftGraphTeamsApiModule.run_microsoft_graph_teams_integration must be importable via the shim"


def test_shim_imports_client_class():
    assert hasattr(integration_module, "MsGraphClient")


def test_shim_imports_new_command_function():
    assert hasattr(
        integration_module, "update_teams_message_policy_violation_command"
    ), "The DLP policy-violation command must be importable via the shim"


def test_main_delegates_to_api_module(mocker):
    mock_run = mocker.patch("MicrosoftGraphTeamsStandardConnector.run_microsoft_graph_teams_integration")
    integration_module.main()
    mock_run.assert_called_once_with()


def test_main_propagates_exceptions(mocker):
    mocker.patch(
        "MicrosoftGraphTeamsStandardConnector.run_microsoft_graph_teams_integration",
        side_effect=RuntimeError("boom"),
    )
    with pytest.raises(RuntimeError, match="boom"):
        integration_module.main()
