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


def main():  # pragma: no cover
    """
    Grab the params and the server urls, and send the message, or test message.
    """
    webhook = demisto.params().get('webhookurl')
    serverurls = demisto.demistoUrls()
    args = demisto.args()
    command = demisto.command()
    try:
        if command == 'test-module':
            return_results(test_module(webhook))
        elif command == 'ms-teams-message':
            message = args.get("message", "")
            if args.get('team_webhook', False):
                return_results(send_teams_message_command(args.get('team_webhook'), message, serverurls))
            else:
                return_results(send_teams_message_command(webhook, message, serverurls))
        else:
            raise NotImplementedError(f"command {command} is not implemented.")

    except Exception as e:
        return_error(str(e), error=traceback.format_exc())


if __name__ in ('__builtin__', 'builtins', '__main__'):
    main()
