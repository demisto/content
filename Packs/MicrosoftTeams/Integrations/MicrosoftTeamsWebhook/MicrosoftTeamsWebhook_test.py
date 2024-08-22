from MicrosoftTeamsWebhook import (Client, send_teams_message_command, create_teams_message)

WEBHOOK = "https://readywebookone"
MESSAGE = "Hello from XSOAR"
TITLE = "Cortex XSOAR URL"
SERVERURLS = {
    "investigation": "https://readyxsoarone:443/#/Details/8675309/"
}


fake_client = Client(base_url=WEBHOOK, verify=True, proxy=False)

def test_create_teams_message_adaptive_cards():
    message = create_teams_message(MESSAGE, TITLE, SERVERURLS["investigation"], True)
    assert message
    assert message["attachments"][0]["content"]["body"][1]["text"] == MESSAGE
    assert message["attachments"][0]["content"]["actions"][0]["title"] == TITLE
    assert message["attachments"][0]["content"]["actions"][0]["url"] == SERVERURLS["investigation"]


def test_create_teams_message():
    message = create_teams_message(MESSAGE, TITLE, SERVERURLS["investigation"])
    assert message
    assert message["sections"][0]["activitySubtitle"] == MESSAGE
    assert message["potentialAction"][0]["name"] == TITLE
    assert message["potentialAction"][0]["targets"][0]["uri"] == SERVERURLS["investigation"]


def test_send_teams_message_command(requests_mock):
    requests_mock.post(WEBHOOK, status_code=200, json={})
    res = send_teams_message_command(fake_client, MESSAGE, TITLE, SERVERURLS["investigation"])
    assert res.readable_output == 'message sent successfully'


def test_send_teams_message_command(requests_mock):
    requests_mock.post(WEBHOOK, status_code=200, json={})
    res = send_teams_message_command(fake_client, MESSAGE, TITLE, SERVERURLS["investigation"], True)
    assert res.readable_output == 'message sent successfully'


def test_test_module(requests_mock):
    from MicrosoftTeamsWebhook import test_module
    requests_mock.post(WEBHOOK, status_code=200, json={})

    res = test_module(fake_client, 'fake')
    assert res == 'ok'
