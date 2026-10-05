"""Sanity tests for the AnthropicClaudeStandardConnector shim integration.

Full behavioural coverage lives in the AnthropicClaudeApiModule tests; this file
exists only to confirm the shim wires through to the ApiModule correctly. The
satellite integration exposes only the two delete commands in its YAML, but the
shared ``run_anthropic_claude_integration()`` function still holds the full
dispatcher — the YAML is the enforcement boundary.
"""

import pytest

import AnthropicClaudeStandardConnector as integration_module


def test_shim_imports_run_entry_point():
    assert hasattr(
        integration_module, "run_anthropic_claude_integration"
    ), "AnthropicClaudeApiModule.run_anthropic_claude_integration must be importable via the shim"


def test_shim_imports_delete_commands():
    """The satellite integration YAML surfaces exactly these two delete commands."""
    assert hasattr(integration_module, "chat_file_delete_command")
    assert hasattr(integration_module, "project_document_delete_command")


def test_shim_imports_compliance_client():
    """The delete commands require the ComplianceClient (Compliance Access Key auth)."""
    assert hasattr(integration_module, "ComplianceClient")


def test_main_delegates_to_api_module(mocker):
    mock_run = mocker.patch("AnthropicClaudeStandardConnector.run_anthropic_claude_integration")
    integration_module.main()
    mock_run.assert_called_once_with()


def test_main_propagates_exceptions(mocker):
    mocker.patch(
        "AnthropicClaudeStandardConnector.run_anthropic_claude_integration",
        side_effect=RuntimeError("boom"),
    )
    with pytest.raises(RuntimeError, match="boom"):
        integration_module.main()
