import demistomock as demisto  # noqa: F401
import requests
from CommonServerPython import *  # noqa: F401


def create_teams_message(message, serverurls):
    """
    Creates the Teams message using the messageCard format, and returns the card
    """
    messageCard = {
        "@type": "MessageCard",
        "@context": "http://schema.org/extensions",
        "themeColor": "0076D7",
        "summary": "Cortex XSOAR Notification",
        "sections": [{
            "activityTitle": "Cortex XSOAR Notification",
            "activitySubtitle": message,
            "markdown": True
        }],
        "potentialAction": [{
            "@type": "OpenUri",
            "name": "Cortex XSOAR URL",
            "targets": [{"os": "default", "uri": serverurls['investigation']}]
        }]
    }

    return messageCard


def test_module(webhook):
    """
    Test command, will send a notification with a static message, and check we got a 200 OK back
    """
    try:
        message = {
            "@type": "MessageCard",
            "@context": "http://schema.org/extensions",
            "themeColor": "0076D7",
            "summary": "Cortex XSOAR Notification",
            "sections": [{
                "activityTitle": "Cortex XSOAR Notification",
                "activitySubtitle": "Successful test message from Cortex XSOAR",
                "markdown": True
            }]
        }
        res = requests.post(webhook, json=message)
        res.raise_for_status()
        return 'ok'
    except Exception as e:
        return_error(e)


def send_teams_message_command(webhook, message, serverurls):
    """
    Sends the Teams Message to the provided webhook.
    """
    try:
        message = create_teams_message(message, serverurls)
        res = requests.post(webhook, json=message)
        res.raise_for_status()
        return 'message sent successfully'
    except Exception as e:
        return_error(e)


def main():
    """
    Grab the params and the server urls, and send the message, or test message.
    """
    webhook = demisto.params().get('webhookurl')
    serverurls = demisto.demistoUrls()

    if demisto.command() == 'test-module':
        return_results(test_module(webhook))
    elif demisto.command() == 'ms-teams-message':
        message = demisto.args().get("message", "")
        if demisto.args().get('team_webhook', False):
            return_results(send_teams_message_command(demisto.args().get('team_webhook'), message, serverurls))
        else:
            return_results(send_teams_message_command(webhook, message, serverurls))


if __name__ in ('__builtin__', 'builtins', '__main__'):
    main()
