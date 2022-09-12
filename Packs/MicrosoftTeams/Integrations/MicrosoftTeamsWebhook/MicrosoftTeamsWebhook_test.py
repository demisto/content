from MicrosoftTeamsWebhook import create_teams_message, send_teams_message_command

WEBHOOK = "https://readywebookone"
MESSAGE = "Hello from XSOAR"
SERVERURLS = {
    "investigation": "https://readyxsoarone:443/#/Details/8675309/"
}


def test_create_teams_message():
    message = create_teams_message(MESSAGE, SERVERURLS)
    assert message
    assert message["sections"][0]["activitySubtitle"] == MESSAGE
    assert message["potentialAction"][0]["targets"][0]["uri"] == SERVERURLS["investigation"]


def test_test_module(requests_mock):
    from MicrosoftTeamsWebhook import test_module
    requests_mock.post(WEBHOOK, status_code=200)

    res = test_module(WEBHOOK)
    assert res == 'ok'


def test_send_teams_message_command(requests_mock):
    requests_mock.post(WEBHOOK, status_code=200)

    res = send_teams_message_command(WEBHOOK, MESSAGE, SERVERURLS)
    assert res == 'message sent successfully'
