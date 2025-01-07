from unittest.mock import patch
import pytest
from MicrosoftTeamsWebhook import (Client, send_teams_message_command, create_teams_message)

WEBHOOK = "https://readywebookone"
MESSAGE = "Hello from XSOAR"
TITLE = "Cortex XSOAR URL"
SERVERURLS = {
    "investigation": "https://readyxsoarone:443/#/Details/8675309/"
}


fake_client = Client(base_url=WEBHOOK, verify=True, proxy=False, is_workflow=False)


def test_create_teams_message_adaptive_cards():
    message = create_teams_message(MESSAGE, TITLE, SERVERURLS["investigation"], True)
    assert message
    assert message["attachments"][0]["content"]["body"][1]["text"] == MESSAGE
    assert message["attachments"][0]["content"]["actions"][0]["title"] == TITLE
    assert message["attachments"][0]["content"]["actions"][0]["url"] == SERVERURLS["investigation"]


def test_create_teams_message():
    message = create_teams_message(MESSAGE, TITLE, SERVERURLS["investigation"], is_workflow=False)
    assert message
    assert message["sections"][0]["activitySubtitle"] == MESSAGE
    assert message["potentialAction"][0]["name"] == TITLE
    assert message["potentialAction"][0]["targets"][0]["uri"] == SERVERURLS["investigation"]


def test_send_teams_message_command(requests_mock):
    requests_mock.post(WEBHOOK, status_code=200, json={})
    res = send_teams_message_command(fake_client, MESSAGE, TITLE, SERVERURLS["investigation"])
    assert res.readable_output == 'message sent successfully'


def test_send_teams_message_command_with_adaptivecards(requests_mock):
    requests_mock.post(WEBHOOK, status_code=200, json={})
    res = send_teams_message_command(fake_client, MESSAGE, TITLE, SERVERURLS["investigation"], True)
    assert res.readable_output == 'message sent successfully'


def test_send_teams_message_command_with_adaptivecards_overwrite(requests_mock):
    requests_mock.post(WEBHOOK, status_code=200, json={})
    res = send_teams_message_command(fake_client, MESSAGE, TITLE, SERVERURLS["investigation"], True, {"Hello": "World"})
    assert res.readable_output == 'message sent successfully'


def test_test_module(requests_mock):
    from MicrosoftTeamsWebhook import test_module
    requests_mock.post(WEBHOOK, status_code=200, json={})

    res = test_module(fake_client, 'fake')
    assert res == 'ok'


workflow_client = Client(base_url=WEBHOOK, verify=True, proxy=False, is_workflow=True)


def test_create_teams_message_adaptive_cards_is_workflow():
    """
    Given:
      - The command arguments with is_workflow = true.
    When:
      - Executing the create_teams_message function.
    Then:
      - Verify request message- should use the full adaptive card template.
    """
    message = create_teams_message(MESSAGE, TITLE, SERVERURLS["investigation"], True, True)
    assert message
    assert message["attachments"][0]["content"]["body"][1]["text"] == MESSAGE
    assert message["attachments"][0]["content"]["actions"][0]["title"] == TITLE
    assert message["attachments"][0]["content"]["actions"][0]["url"] == SERVERURLS["investigation"]


def test_create_teams_message_is_workflow():
    """
    Given:
      - The command arguments with is_workflow = true.
    When:
      - Executing the create_teams_message function.
    Then:
      - Verify request message- should use the only text template.
    """
    message = create_teams_message(MESSAGE, TITLE, SERVERURLS["investigation"], is_workflow=True)
    assert message
    assert message["attachments"][0]["content"]["body"][0]["text"] == MESSAGE
    assert message["attachments"][0].get("content", {}).get("actions") is None


def test_send_teams_message_command_is_workflow(requests_mock):
    """
    Given:
      - The command arguments with is_workflow = true.
    When:
      - Executing the send_teams_message_command command.
    Then:
      - Verify when status is 202 we receive `message sent successfully`.
    """
    requests_mock.post(WEBHOOK, status_code=202, json={})
    res = send_teams_message_command(workflow_client, MESSAGE, TITLE, SERVERURLS["investigation"])
    assert res.readable_output == 'message sent successfully'


def test_send_teams_message_command_with_full_adaptivecards_is_workflow(requests_mock):
    """
    Given:
      - The command arguments with is_workflow = true.
    When:
      - Executing the send_teams_message_command command.
    Then:
      - Verify when status is 202 we receive `message sent successfully`.
    """
    requests_mock.post(WEBHOOK, status_code=202, json={})
    res = send_teams_message_command(workflow_client, MESSAGE, TITLE, SERVERURLS["investigation"], True)
    assert res.readable_output == 'message sent successfully'


@pytest.mark.parametrize(
    "client,messagecard, adaptive_cards_format, expected_full_url",
    [
        (fake_client, {"type": "MessageCard", "text": "Hello World"}, False, None),
        (fake_client, {"type": "AdaptiveCard", "text": "Hello Adaptive Card"}, True, "https://example.com/webhook"),
        (workflow_client, {"type": "AdaptiveCard", "text": "Hello Workflow Card"}, False, "https://example.com/webhook"),
    ]
)
@patch('MicrosoftTeamsWebhook.demisto.info')
def test_send_teams_message(mock_demisto_info, client, messagecard, adaptive_cards_format, expected_full_url, mocker):
    sender = client
    http_request = mocker.patch.object(client, '_http_request')
    http_request.return_value = "OK"
    sender.send_teams_message(messagecard, adaptive_cards_format)
    if expected_full_url:
        http_request.assert_called_once_with(
            method='POST',
            json_data=messagecard,
            raise_on_status=True,
            resp_type='text',
            full_url=sender.base_url
        )
    else:
        http_request.assert_called_once_with(
            method='POST',
            json_data=messagecard,
            raise_on_status=True,
            resp_type='text'
        )
    mock_demisto_info.assert_called_once_with('completed post of message. response text: OK')
