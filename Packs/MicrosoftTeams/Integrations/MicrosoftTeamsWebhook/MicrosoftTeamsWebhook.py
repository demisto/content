import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
import urllib3

# Disable insecure warnings
urllib3.disable_warnings()


class Client(BaseClient):

    def __init__(self, base_url: str, proxy: bool, verify: bool, is_workflow: bool = True):
        """
        Client to use in the. Overrides BaseClient.

        Args:
            base_url (str): URL to access when doing a http request. Webhook url.

        """
        self.base_url = base_url
        self.is_workflow = is_workflow
        super().__init__(base_url=base_url, proxy=proxy, verify=verify)

    def send_teams_message(self, messagecard: dict, adaptive_cards_format: bool = False):
        """
        Sends the Teams Message to the provided webhook.

        Args:
            messagecard (dict): dict the adaptive card to send to Teams.
            adaptive_cards_format (bool): Should the adaptive card url format be used?
        """

        if adaptive_cards_format or self.is_workflow:
            res = self._http_request(
                method='POST',
                json_data=messagecard,
                raise_on_status=True,
                resp_type='text',
                full_url=self.base_url
            )
        else:
            res = self._http_request(
                method='POST',
                json_data=messagecard,
                raise_on_status=True,
                resp_type='text'
            )
        demisto.info(f'completed post of message. response text: {res}')


def create_teams_message(
    message: str,
    title: str,
    serverurls: str,
    adaptive_cards_format: bool = False,
    is_workflow: bool = True,
    overwrite_adaptive_card_json: dict | None = None
) -> dict:
    """
    Creates the Teams message using the messageCard format, and returns the card

    Args:
        message (str): The message to send in the message card to Teams.
        title (str): The title of the message card.
        serverurls (str): The URL to send in the message card.
        adaptive_cards_format (bool): Should the adaptive cards format be used?
        is_workflow (bool): Is the Microsoft Webhook URL is a workflow.
        overwrite_adaptive_card_json (dict | None): Value to overwrite the default adaptive card format.

        Returns:
        messagecard (dict): dict the adaptive card to send to Teams.
    """
    messagecard: dict = {}
    if adaptive_cards_format:
        if overwrite_adaptive_card_json is None:
            messagecard = {
                "type": "message",
                "attachments": [
                    {
                        "contentType": "application/vnd.microsoft.card.adaptive",
                        "content": {
                            "type": "AdaptiveCard",
                            "body": [
                                    {
                                        "type": "TextBlock",
                                        "text": "Cortex XSOAR Notification",
                                        "weight": "bolder",
                                        "size": "medium",
                                        "color": "accent"
                                    },
                                {
                                        "type": "TextBlock",
                                        "text": message,
                                        "wrap": True
                                        }
                            ],
                            "actions": [
                                {
                                    "type": "Action.OpenUrl",
                                    "title": title,
                                    "url": serverurls
                                }
                            ],
                            "$schema": "http://adaptivecards.io/schemas/adaptive-card.json",
                            "version": "1.0"
                        }
                    }
                ]
            }
        else:
            messagecard = overwrite_adaptive_card_json
    else:
        if is_workflow:
            messagecard = {
                "type": "message",
                "attachments": [
                    {
                        "contentType": "application/vnd.microsoft.card.adaptive",
                        "content": {
                            "type": "AdaptiveCard",
                            "body": [
                                {
                                    "type": "TextBlock",
                                    "text": message
                                }
                            ],
                            "$schema": "http://adaptivecards.io/schemas/adaptive-card.json",
                            "version": "1.0"
                        }
                    }
                ]
            }
        else:
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
        test_message = create_teams_message(message, title, serverurls, is_workflow=client.is_workflow)
        client.send_teams_message(test_message)
        return 'ok'
    except DemistoException as e:
        return f'Error: {e}'


def send_teams_message_command(
    client: Client,
    message: str,
    title: str,
    serverurls: str,
    adaptive_cards_format: bool = False,
    overwrite_adaptive_card_json: dict | None = None
) -> CommandResults:
    """
    send_teams_message command: Sends the Teams Message to the provided webhook.

    Args:
        client (Client): Teams client to use.
        message (str): The message to send in the message card to Teams.
        title (str): The title of the message card.
        serverurls (str): The URL to send in the message card.
        adaptive_cards_format (bool): Should the adaptive cards format be used?
        overwrite_adaptive_card_json (dict | None): Value to overwrite the default adaptive card format.

    Returns:
        CommandResults/dict: A ``CommandResults`` compatible to return ``return_results()``,
        which contains the readable_output indicating the message was sent.
    """

    messagecard = create_teams_message(message, title, serverurls, adaptive_cards_format,
                                       is_workflow=client.is_workflow,
                                       overwrite_adaptive_card_json=overwrite_adaptive_card_json)
    client.send_teams_message(messagecard, adaptive_cards_format)
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
    adaptive_cards_format: bool = argToBoolean(args.get("adaptive_cards_format", False))
    overwrite_adaptive_card_json_param: str = args.get('overwrite_adaptive_card_json', None)
    overwrite_adaptive_card_json: dict | None = json.loads(
        overwrite_adaptive_card_json_param) if overwrite_adaptive_card_json_param else None

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
            proxy=proxy,
            is_workflow='workflow' in webhook
        )

        if command == 'test-module':
            return_results(test_module(client, serverurls))
        elif command == 'ms-teams-message':
            message = args.get("message", "")
            return_results(send_teams_message_command(client, message, title, serverurls,
                           adaptive_cards_format, overwrite_adaptive_card_json))
        else:
            raise NotImplementedError(f"command {command} is not implemented.")

    except Exception as e:
        return_error(str(e), error=traceback.format_exc())


if __name__ in ('__builtin__', 'builtins', '__main__'):
    main()
