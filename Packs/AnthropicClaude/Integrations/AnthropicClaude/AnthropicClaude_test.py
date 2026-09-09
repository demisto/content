"""Sanity tests for the AnthropicClaude shim integration.

Full behavioural coverage lives in the AnthropicClaudeApiModule tests; this file
exists only to confirm the shim wires through to the ApiModule correctly.
"""

import pytest

import AnthropicClaude as integration_module


def test_shim_imports_run_entry_point():
    assert hasattr(
        integration_module, "run_anthropic_claude_integration"
    ), "AnthropicClaudeApiModule.run_anthropic_claude_integration must be importable via the shim"


def test_shim_imports_client_classes():
    assert hasattr(integration_module, "AnthropicClient")
    assert hasattr(integration_module, "ComplianceClient")


def test_shim_imports_command_functions():
    for name in (
        # LLM commands
        "send_message_command",
        "check_email_headers_command",
        "check_email_body_command",
        "create_soc_email_template_command",
        # Compliance read-only commands
        "list_organizations_command",
        "list_organization_users_command",
        "list_roles_command",
        "list_role_permissions_command",
        "list_groups_command",
        "list_group_members_command",
        "list_chats_command",
        "list_chat_messages_command",
        "list_projects_command",
        "list_project_attachments_command",
        "get_project_document_command",
        # Delete commands (also exposed on the satellite integration)
        "chat_file_delete_command",
        "project_document_delete_command",
        # Event collector
        "fetch_events_command",
        "get_events_command",
    ):
        assert hasattr(integration_module, name), f"Command {name!r} missing from shim"


def test_main_delegates_to_api_module(mocker):
    mock_run = mocker.patch("AnthropicClaude.run_anthropic_claude_integration")
    integration_module.main()
    mock_run.assert_called_once_with()


def test_main_propagates_exceptions(mocker):
    mocker.patch(
        "AnthropicClaude.run_anthropic_claude_integration",
        side_effect=RuntimeError("boom"),
    )
    with pytest.raises(RuntimeError, match="boom"):
        integration_module.main()
