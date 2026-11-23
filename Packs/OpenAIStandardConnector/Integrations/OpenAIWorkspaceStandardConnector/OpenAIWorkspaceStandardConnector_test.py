"""Sanity tests for the OpenAIWorkspaceStandardConnector shim integration.

Full behavioural coverage lives in the OpenAiChatGPTApiModule tests; this file only
confirms the shim runs the ApiModule entry point for its own service.
"""

import pytest

import OpenAIWorkspaceStandardConnector as integration_module


def test_main_runs_api_module_for_service(mocker):
    """`main()` must only call the ApiModule entry point with this integration's service."""
    mock_run = mocker.patch("OpenAIWorkspaceStandardConnector.run_openai_integration")
    integration_module.main()
    mock_run.assert_called_once_with(service=integration_module.Service.WORKSPACE)


def test_main_propagates_exceptions(mocker):
    """`main()` must not swallow exceptions raised by the ApiModule."""
    mocker.patch("OpenAIWorkspaceStandardConnector.run_openai_integration", side_effect=RuntimeError("boom"))
    with pytest.raises(RuntimeError, match="boom"):
        integration_module.main()
