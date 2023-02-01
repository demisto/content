import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
import urllib3

# Disable insecure warnings
urllib3.disable_warnings()  # pylint: disable=no-member


class Client(BaseClient):
    def __init__(self, base_url: str, proxy: bool, verify: bool):
        """
        Client to use in the. Overrides BaseClient.

        Args:
            base_url (str): URL to access when doing a http request. Webhook url.

        """
        super().__init__(base_url=base_url, proxy=proxy, verify=verify)

    def post_message(self, msg: dict, webhook_url: str = ''):
        url = self._base_url
        if webhook_url:
            url = webhook_url
        res = self._http_request(method='POST', json_data=msg, full_url=url, resp_type='text')
        demisto.info(f'completed post of message. response text: {res}')


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


def test_module(client: Client):
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
        client.post_message(message)
        return 'ok'
    except Exception as e:
        return_error(e)


def send_teams_message_command(client: Client, message, serverurls, webhook_url=''):
    """
    Sends the Teams Message to the provided webhook.
    """
    try:
        message = create_teams_message(message, serverurls)
        client.post_message(message, webhook_url=webhook_url)
        return 'message sent successfully'
    except Exception as e:
        return_error(e)


def main():  # pragma: no cover
    """
    Grab the params and the server urls, and send the message, or test message.
    """
    webhook = demisto.params().get('webhookurl')
    verify_certificate = not demisto.params().get('insecure', False)
    proxy = demisto.params().get('proxy', False)
    client = Client(webhook, proxy, verify_certificate)
    serverurls = demisto.demistoUrls()
    args = demisto.args()
    command = demisto.command()
    try:
        if command == 'test-module':
            return_results(test_module(client))
        elif command == 'ms-teams-message':
            message = args.get("message", "")
            if args.get('team_webhook', False):
                return_results(send_teams_message_command(client, message, serverurls, args.get('team_webhook')))
            else:
                return_results(send_teams_message_command(client, message, serverurls))
        else:
            raise NotImplementedError(f"command {command} is not implemented.")

    except Exception as e:
        return_error(str(e), error=traceback.format_exc())


if __name__ in ('__builtin__', 'builtins', '__main__'):
    main()
