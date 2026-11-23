"""Sanity tests for the OpenAI GPT shim integration.

Full behavioural coverage lives in the OpenAiChatGPTApiModule tests; this file only
confirms the shim wires through to the ApiModule correctly.
"""

import pytest

import OpenAiChatGPTV3 as integration_module


def test_shim_exposes_api_module_entry_point():
    """The shim must re-export the ApiModule entry point and client."""
    assert hasattr(integration_module, "run_openai_integration")
    assert hasattr(integration_module, "OpenAiClient")


def test_main_delegates_to_api_module(mocker):
    """`main()` must only call the ApiModule entry point."""
    mock_run = mocker.patch("OpenAiChatGPTV3.run_openai_integration")
    integration_module.main()
    mock_run.assert_called_once_with()


def test_main_propagates_exceptions(mocker):
    """`main()` must not swallow exceptions raised by the ApiModule."""
    mocker.patch("OpenAiChatGPTV3.run_openai_integration", side_effect=RuntimeError("boom"))
    with pytest.raises(RuntimeError, match="boom"):
        integration_module.main()
