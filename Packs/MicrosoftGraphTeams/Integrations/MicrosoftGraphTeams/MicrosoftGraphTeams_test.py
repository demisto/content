from unittest.mock import MagicMock

import pytest
from CommonServerPython import DemistoException
from MicrosoftGraphTeams import (
    build_policy_violation_body,
    build_teams_message_url_suffix,
    update_teams_message_policy_violation_command,
    validate_teams_message_target_args,
)


def test_build_teams_message_url_suffix_chat():
    """
    Given:
        - A chat_id and message_id.
    When:
        - Building the Teams message resource path.
    Then:
        - The chat message path is returned.
    """
    suffix = build_teams_message_url_suffix(
        chat_id="chat-1", team_id="", channel_id="", message_id="msg-1", parent_message_id="", payment_model=""
    )
    assert suffix == "chats/chat-1/messages/msg-1"


def test_build_teams_message_url_suffix_channel():
    """
    Given:
        - A team_id, channel_id, and message_id.
    When:
        - Building the Teams message resource path.
    Then:
        - The channel message path is returned.
    """
    suffix = build_teams_message_url_suffix(
        chat_id="", team_id="team-1", channel_id="chan-1", message_id="msg-1", parent_message_id="", payment_model=""
    )
    assert suffix == "teams/team-1/channels/chan-1/messages/msg-1"


def test_build_teams_message_url_suffix_channel_reply():
    """
    Given:
        - A team_id, channel_id, parent_message_id, and message_id.
    When:
        - Building the Teams message resource path.
    Then:
        - The channel reply path is returned.
    """
    suffix = build_teams_message_url_suffix(
        chat_id="", team_id="team-1", channel_id="chan-1", message_id="msg-1", parent_message_id="parent-1", payment_model=""
    )
    assert suffix == "teams/team-1/channels/chan-1/messages/parent-1/replies/msg-1"


def test_build_teams_message_url_suffix_with_payment_model():
    """
    Given:
        - A chat message target and a payment_model.
    When:
        - Building the Teams message resource path.
    Then:
        - The model query parameter is appended.
    """
    suffix = build_teams_message_url_suffix(
        chat_id="chat-1", team_id="", channel_id="", message_id="msg-1", parent_message_id="", payment_model="A"
    )
    assert suffix == "chats/chat-1/messages/msg-1?model=A"


def test_build_policy_violation_body_omits_verdict_when_empty():
    """
    Given:
        - A dlp_action and policy tip text, with no verdict_details.
    When:
        - Building the policy violation body.
    Then:
        - The verdictDetails field is omitted.
    """
    body = build_policy_violation_body(dlp_action="BlockAccess", policy_tip_general_text="Blocked.", verdict_details="")
    assert body == {"policyViolation": {"dlpAction": "BlockAccess", "policyTip": {"generalText": "Blocked."}}}


def test_build_policy_violation_body_includes_verdict_when_set():
    """
    Given:
        - A dlp_action, policy tip text, and verdict_details.
    When:
        - Building the policy violation body.
    Then:
        - The verdictDetails field is included.
    """
    body = build_policy_violation_body(
        dlp_action="BlockAccess", policy_tip_general_text="Blocked.", verdict_details="AllowFalsePositiveOverride"
    )
    assert body["policyViolation"]["verdictDetails"] == "AllowFalsePositiveOverride"


@pytest.mark.parametrize(
    "chat_id, team_id, channel_id, parent_message_id, error_message",
    [
        ("chat-1", "", "", "parent-1", "'parent_message_id' is only supported for channel messages"),
        ("chat-1", "team-1", "chan-1", "", "Provide either 'chat_id' or 'team_id' and 'channel_id', not both."),
        ("", "team-1", "", "parent-1", "A channel message requires both 'team_id' and 'channel_id'."),
        ("", "", "", "", "A message target is required"),
        ("", "team-1", "", "", "A channel message requires both 'team_id' and 'channel_id'."),
    ],
)
def test_validate_teams_message_target_args_invalid(chat_id, team_id, channel_id, parent_message_id, error_message):
    """
    Given:
        - An invalid combination of message-target arguments.
    When:
        - Validating the target arguments.
    Then:
        - A DemistoException with the specific message is raised.
    """
    with pytest.raises(DemistoException) as exc_info:
        validate_teams_message_target_args(chat_id, team_id, channel_id, parent_message_id)
    assert error_message in str(exc_info.value)


def test_update_teams_message_policy_violation_command_chat(mocker):
    """
    Given:
        - A chat message target with a dlp_action and policy tip.
    When:
        - Running the update_teams_message_policy_violation_command.
    Then:
        - A PATCH is issued to the chat message path with the policy violation body.
    """
    client = MagicMock()
    return_results = mocker.patch("MicrosoftGraphTeams.return_results")
    args = {
        "chat_id": "chat-1",
        "message_id": "msg-1",
        "dlp_action": "BlockAccess",
        "policy_tip_general_text": "This item has been blocked by the administrator.",
    }

    update_teams_message_policy_violation_command(client, args)

    client.update_message_policy_violation.assert_called_once_with(
        url_suffix="chats/chat-1/messages/msg-1",
        body={
            "policyViolation": {
                "dlpAction": "BlockAccess",
                "policyTip": {"generalText": "This item has been blocked by the administrator."},
            }
        },
    )
    result = return_results.call_args[0][0]
    assert result.outputs_prefix == "MSGraphTeams.TeamsMessagePolicyViolation"
    assert result.outputs["messageId"] == "msg-1"
    assert result.outputs["chatId"] == "chat-1"
    assert "verdictDetails" not in result.outputs


def test_update_teams_message_policy_violation_command_channel_reply(mocker):
    """
    Given:
        - A channel reply target with a verdict_details and payment_model.
    When:
        - Running the update_teams_message_policy_violation_command.
    Then:
        - A PATCH is issued to the channel reply path with the model query and verdictDetails.
    """
    client = MagicMock()
    return_results = mocker.patch("MicrosoftGraphTeams.return_results")
    args = {
        "team_id": "team-1",
        "channel_id": "chan-1",
        "parent_message_id": "parent-1",
        "message_id": "msg-1",
        "dlp_action": "BlockAccess",
        "policy_tip_general_text": "Blocked.",
        "verdict_details": "AllowFalsePositiveOverride",
        "payment_model": "A",
    }

    update_teams_message_policy_violation_command(client, args)

    client.update_message_policy_violation.assert_called_once_with(
        url_suffix="teams/team-1/channels/chan-1/messages/parent-1/replies/msg-1?model=A",
        body={
            "policyViolation": {
                "dlpAction": "BlockAccess",
                "policyTip": {"generalText": "Blocked."},
                "verdictDetails": "AllowFalsePositiveOverride",
            }
        },
    )
    result = return_results.call_args[0][0]
    assert result.outputs["parentMessageId"] == "parent-1"
    assert result.outputs["verdictDetails"] == "AllowFalsePositiveOverride"


def test_update_teams_message_policy_violation_command_invalid_target(mocker):
    """
    Given:
        - Both chat_id and channel arguments.
    When:
        - Running the update_teams_message_policy_violation_command.
    Then:
        - Validation fails before any HTTP request is made.
    """
    client = MagicMock()
    args = {
        "chat_id": "chat-1",
        "team_id": "team-1",
        "channel_id": "chan-1",
        "message_id": "msg-1",
    }
    with pytest.raises(DemistoException):
        update_teams_message_policy_violation_command(client, args)
    client.update_message_policy_violation.assert_not_called()
