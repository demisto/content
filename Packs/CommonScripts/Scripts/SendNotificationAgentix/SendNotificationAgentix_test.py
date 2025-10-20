from CommonServerPython import *
from SendNotificationAgentix import send_notification_by_brand, BRAND_MAPPING
import pytest
from CommonServerPython import DemistoException


@pytest.mark.parametrize("brand", ["Microsoft Teams", "Slack", "Mattermost", "Zoom"])
def test_send_notification_with_basic_args(mocker, brand):
    """
    Given:
        - valid brand and arguments
    When:
        - calling send_notification_by_brand
    Then:
        - demisto.executeCommand should be called with correct parameters
    """
    mock_execute_command = mocker.patch.object(demisto, "executeCommand")

    args = {
        "message": "Test notification",
        "to": "user@example.com",
    }

    send_notification_by_brand(brand, args)

    mock_execute_command.assert_called_once_with(
        "send-notification",
        args={
            "using-brand": BRAND_MAPPING.get(brand, {}).get("brand"),
            "message": "Test notification",
            "to": "user@example.com",
        },
    )


def test_send_notification_with_teams(mocker):
    """
    Given:
        - valid Microsoft Teams brand and arguments
    When:
        - calling send_notification_by_brand
    Then:
        - demisto.executeCommand should be called with correct parameters
    """
    mock_execute_command = mocker.patch.object(demisto, "executeCommand")

    args = {
        "message": "Test notification",
        "channel": "General",
        "team": "TestTeam",
    }

    send_notification_by_brand("Microsoft Teams", args)

    mock_execute_command.assert_called_once_with(
        "send-notification",
        args={
            "using-brand": "Microsoft Teams",
            "message": "Test notification",
            "channel": "General",
            "team": "TestTeam",
        },
    )


def test_send_notification_with_slack(mocker):
    """
    Given:
        - valid Slack brand and arguments
    When:
        - calling send_notification_by_brand
    Then:
        - demisto.executeCommand should be called with correct parameters
    """
    mock_execute_command = mocker.patch.object(demisto, "executeCommand")

    args = {
        "message": "Alert: System maintenance",
        "channel": "General",
    }

    send_notification_by_brand("Slack", args)

    mock_execute_command.assert_called_once_with(
        "send-notification", args={"using-brand": "SlackV3", "message": "Alert: System maintenance", "channel": "General"}
    )


def test_send_notification_with_mattermost(mocker):
    """
    Given:
        - valid Mattermost brand and arguments
    When:
        - calling send_notification_by_brand
    Then:
        - demisto.executeCommand should be called with correct parameters
    """
    mock_execute_command = mocker.patch.object(demisto, "executeCommand")

    args = {"message": "Simple notification", "channel": "General"}

    send_notification_by_brand("Mattermost", args)

    mock_execute_command.assert_called_once_with(
        "send-notification", args={"using-brand": "MattermostV2", "message": "Simple notification", "channel": "General"}
    )


def test_send_notification_with_zoom(mocker):
    """
    Given:
        - valid Zoom brand and arguments
    When:
        - calling send_notification_by_brand
    Then:
        - demisto.executeCommand should be called with correct parameters
    """
    mock_execute_command = mocker.patch.object(demisto, "executeCommand")

    args = {"message": "Simple notification", "channel_id": "C1234567890"}

    send_notification_by_brand("Zoom", args)

    mock_execute_command.assert_called_once_with(
        "send-notification", args={"using-brand": "Zoom", "message": "Simple notification", "channel_id": "C1234567890"}
    )


def test_send_notification_unsupported_brand():
    """
    Given:
        - an unsupported brand name
    When:
        - calling send_notification_by_brand
    Then:
        - DemistoException should be raised with appropriate error message
    """
    args = {"message": "Test message"}

    with pytest.raises(DemistoException) as exc_info:
        send_notification_by_brand("Discord", args)

    error_message = str(exc_info.value)
    assert "Discord is not supported" in error_message
    assert "Supported brands:" in error_message


@pytest.mark.parametrize("brand", ["Slack", "Mattermost", "Zoom"])
def test_send_notification_team_arg_invalid(brand):
    """
    Given:
        - Using the team argument with unsupported brand
    When:
        - calling send_notification_by_brand
    Then:
        - DemistoException should be raised about unsupported arguments
    """
    args = {"message": "Test message", "team": "invalid_for_slack"}

    with pytest.raises(DemistoException) as exc_info:
        send_notification_by_brand(brand, args)

    error_message = str(exc_info.value)
    assert f"Arguments ['team'] are not supported for brand - {brand}" in error_message


@pytest.mark.parametrize("brand", ["Mattermost", "Microsoft Teams"])
def test_send_notification_channel_id_invalid(brand):
    """
    Given:
        - Trying to use channel id with unsupported brand
    When:
        - calling send_notification_by_brand
    Then:
        - DemistoException should be raised about unsupported arguments
    """
    args = {"message": "Test message", "channel_id": "invalid_for_teams"}

    with pytest.raises(DemistoException) as exc_info:
        send_notification_by_brand(brand, args)

    error_message = str(exc_info.value)
    assert f"Arguments ['channel_id'] are not supported for brand - {brand}" in error_message


def test_send_notification_multiple_invalid_args():
    """
    Given:
        - Using multiple invalid arguments
    When:
        - calling send_notification_by_brand
    Then:
        - DemistoException should be raised listing the invalid arguments
    """
    args = {
        "message": "Test message",
        "team": "invalid_for_mattermost",
        "channel_id": "also_invalid",
        "invalid_arg": "completely_invalid",
    }

    with pytest.raises(DemistoException) as exc_info:
        send_notification_by_brand("Mattermost", args)

    error_message = str(exc_info.value)
    assert "are not supported for brand - Mattermost" in error_message
    assert all(arg in error_message for arg in ["team", "channel_id", "invalid_arg"])
