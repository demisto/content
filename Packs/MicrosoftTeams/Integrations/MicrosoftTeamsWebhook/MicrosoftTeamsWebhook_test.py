from MicrosoftTeamsWebhook import (Client, send_teams_message_command)

WEBHOOK = "https://readywebookone"
MESSAGE = "Hello from XSOAR"
TITLE = "Cortex XSOAR URL"
SERVERURLS = {
    "investigation": "https://readyxsoarone:443/#/Details/8675309/"
}


def test_create_teams_message(Client):
    message = Client.create_teams_message(MESSAGE, TITLE, SERVERURLS["investigation"])
    assert message
    assert message["sections"][0]["activitySubtitle"] == MESSAGE
    assert message["potentialAction"][0]["name"] == TITLE
    assert message["potentialAction"][0]["targets"][0]["uri"] == SERVERURLS["investigation"]


def test_test_module(requests_mock, Client):
    from MicrosoftTeamsWebhook import test_module
    requests_mock.post(WEBHOOK, status_code=200)

    res = test_module(Client, SERVERURLS["investigation"])
    assert res == 'ok'


def test_send_teams_message_command(requests_mock, Client):
    requests_mock.post(WEBHOOK, status_code=200)

    res = send_teams_message_command(Client, MESSAGE, TITLE, SERVERURLS["investigation"])
    assert res == 'message sent successfully'
