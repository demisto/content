from MicrosoftTeamsWebhook import create_teams_message, send_teams_message_command, Client

WEBHOOK = "https://readywebookone"
MESSAGE = "Hello from XSOAR"
SERVERURLS = {
    "investigation": "https://readyxsoarone:443/#/Details/8675309/"
}

client = Client(WEBHOOK, False, True)


def test_create_teams_message():
    message = create_teams_message(MESSAGE, SERVERURLS)
    assert message
    assert message["sections"][0]["activitySubtitle"] == MESSAGE
    assert message["potentialAction"][0]["targets"][0]["uri"] == SERVERURLS["investigation"]


def test_test_module(requests_mock):
    from MicrosoftTeamsWebhook import test_module
    requests_mock.post(WEBHOOK, status_code=200)

    res = test_module(client)
    assert res == 'ok'


def test_send_teams_message_command(requests_mock):
    requests_mock.post(WEBHOOK, status_code=200)

    res = send_teams_message_command(client, MESSAGE, SERVERURLS)
    assert res == 'message sent successfully'
