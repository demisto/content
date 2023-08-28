import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
import urllib3

# Disable insecure warnings
urllib3.disable_warnings()


class Client(BaseClient):

    def __init__(self, base_url: str, proxy: bool, verify: bool):
        """
        Client to use in the. Overrides BaseClient.

        Args:
            base_url (str): URL to access when doing a http request. Webhook url.

        """
        super().__init__(base_url=base_url, proxy=proxy, verify=verify)

    def send_teams_message(self, messagecard: dict):
        """
        Sends the Teams Message to the provided webhook.

        Args:
            messagecard (dict): dict the adaptive card to send to Teams.
        """

        res = self._http_request(
            method='POST',
            json_data=messagecard,
            raise_on_status=True,
            resp_type='text'
        )
        demisto.info(f'completed post of message. response text: {res}')


def create_teams_message(message: str, title: str, serverurls: str) -> dict:
    """
    Creates the Teams message using the messageCard format, and returns the card

    Args:
        message (str): The message to send in the message card to Teams.
        title (str): The title of the message card.
        serverurls (str): The URL to send in the message card.

        Returns:
        messagecard (dict): dict the adaptive card to send to Teams.
    """
    messagecard = {
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
            "name": title,
            "targets": [{"os": "default", "uri": serverurls}]
        }]
    }

    return messagecard


def test_module(client: Client, serverurls: str) -> str:
    """
    Test command, will send a notification with a static message.

    Args:
        client (Client): HelloWorld client to use.
        serverurls (str): The URL to send in the message card.

    Returns:
        str: 'ok' if test passed, anything else will raise an exception and will fail the test.
    """
    try:
        message = "Successful test message from Cortex XSOAR"
        title = "Cortex XSOAR Notification"
        test_message = create_teams_message(message, title, serverurls)
        client.send_teams_message(test_message)
        return 'ok'
    except DemistoException as e:
        return f'Error: {e}'


def send_teams_message_command(client: Client, message: str, title: str, serverurls: str) -> CommandResults:
    """
    send_teams_message command: Sends the Teams Message to the provided webhook.

    Args:
        client (Client): Teams client to use.
        message (str): The message to send in the message card to Teams.
        title (str): The title of the message card.
        serverurls (str): The URL to send in the message card.

    Returns:
        CommandResults/dict: A ``CommandResults`` compatible to return ``return_results()``,
        which contains the readable_output indicating the message was sent.
    """

    messagecard = create_teams_message(message, title, serverurls)
    client.send_teams_message(messagecard)
    return CommandResults(readable_output='message sent successfully')


def main() -> None:    # pragma: no cover
    """
    main function, parses params and runs command functions
    grab the params and the server urls, and send the message, or test message.
    """
    params = demisto.params()
    args = demisto.args()

    title = args.get('url_title', 'Cortex XSOAR URL')
    webhook = args.get('team_webhook', params.get('webhookurl'))
    verify_certificate = not params.get('insecure', False)
    proxy = params.get('proxy', False)

    serverurls = demisto.demistoUrls()

    if args.get('alternative_url'):
        serverurls = args.get('alternative_url')
    else:
        serverurls = serverurls.get("investigation", serverurls["server"])

    command = demisto.command()
    try:
        client = Client(
            base_url=webhook,
            verify=verify_certificate,
            proxy=proxy
        )

        if command == 'test-module':
            return_results(test_module(client, serverurls))
        elif command == 'ms-teams-message':
            message = args.get("message", "")
            return_results(send_teams_message_command(client, message, title, serverurls))
        else:
            raise NotImplementedError(f"command {command} is not implemented.")

    except Exception as e:
        return_error(str(e), error=traceback.format_exc())


if __name__ in ('__builtin__', 'builtins', '__main__'):
    main()
