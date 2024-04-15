import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

import json
import urllib3

# Disable insecure warnings
urllib3.disable_warnings()


class Client(BaseClient):

    def __init__(self, base_url: str, proxy: bool, verify: bool, headers: dict,
                 key: str, token: str):
        """
        Client to use. Overrides BaseClient.

        Args:
            base_url (str): URL to access when doing a http request. Webhook url.

        """
        super().__init__(base_url=base_url, proxy=proxy, verify=verify, headers=headers)
        self.key = key
        self.token = token

    def send_google_chat_message(self, message: str, threadName: Optional[str]):
        """
        Sends the Google Chat Message to the provided webhook.

        Args:
            message (str): Message (text) to send to the Google Chat webhook.
            threadName (str): If provided, will reply to an existing thread (or create a new thread)
        """

        json_data: dict[str, Any] = {'text': message}

        params = {
            'key': self.key,
            'token': self.token
        }

        if threadName:
            json_data['thread'] = {'name': threadName}
            params.update({'messageReplyOption': 'REPLY_MESSAGE_FALLBACK_TO_NEW_THREAD'})

        res = self._http_request(
            method='POST',
            json_data=json_data,
            raise_on_status=True,
            url_suffix='/messages',
            params=params
        )
        demisto.info(f'Message sent. Response: {res}')
        return res

    def send_google_chat_custom_card(self, blocks: str, threadName: Optional[str]):
        """
        Sends the Google Chat custom card to the provided webhook.

        Args:
            blocks (str): Customized card to send to the Google Chat webhook.
            threadName (str): If provided, will reply to an existing thread (or create a new thread)
        """

        json_data: dict[str, Any] = {
            'cardsV2': [{
                'cardId': 'createCardMessage',
                'card': json.loads(blocks)
            }]
        }

        params = {
            'key': self.key,
            'token': self.token
        }

        if threadName:
            json_data['thread'] = {'name': threadName}
            params.update({'messageReplyOption': 'REPLY_MESSAGE_FALLBACK_TO_NEW_THREAD'})

        res = self._http_request(
            method='POST',
            json_data=json_data,
            raise_on_status=True,
            url_suffix='/messages',
            params=params
        )
        demisto.info(f'Message sent. Response: {res}')
        return res


def test_module(client):
    """
    Test command, will send a notification with a static message.

    Args:
        client (Client): Google Chat client to use.

    Returns:
        str: 'ok' if test passed, anything else will raise an exception and will fail the test.
    """
    try:
        message = 'Successful test message from Cortex XSOAR'
        client.send_google_chat_message(message=message, threadName=None)
        return 'ok'
    except DemistoException as e:
        return f'Error: {e}'


def send_google_chat_message_command(client: Client, message: str, threadName: Optional[str]) -> CommandResults:
    """
    send_google_chat_message command: Sends the Google Chat Message to the provided webhook.

    Args:
        client (Client): Google Chat client to use.
        message (str): The message to send to the Google Chat Space.

    Returns:
        CommandResults/dict: A ``CommandResults`` compatible to return ``return_results()``,
        which contains the readable_output indicating the message was sent.
    """
    res = client.send_google_chat_message(message=message, threadName=threadName)
    result = {
        'Message': res.get('text'),
        'SpaceName': res.get('space').get('name'),
        'SpaceDisplayName': res.get('space').get('displayName'),
        'SpaceType': res.get('space').get('type'),
        'CreatedTime': res.get('createTime'),
        'ThreadReply': res.get('threadReply', False),
        'ThreadName': res.get('thread').get('name'),
        'Name': res.get('name'),
        'SenderDisplayName': res.get('sender').get('displayName'),
        'SenderName': res.get('sender').get('name'),
        'SenderType': res.get('sender').get('type')
    }
    markdown = '### Google Chat\n'
    markdown += tableToMarkdown('Message Webhook', result)
    results = CommandResults(
        readable_output=markdown,
        outputs_prefix='GoogleChatWebhook.Message',
        outputs_key_field='name',
        outputs=result
    )
    return results


def send_google_chat_custom_card_command(client: Client, blocks: str, threadName: Optional[str]) -> CommandResults:
    """
    send_google_chat_custom_card command: Sends the Google Chat custom card to the provided webhook.

    Args:
        client (Client): Google Chat client to use.
        blocks (str): The custom card to send to the Google Chat Space (UI Kit Builder JSON blocks)
        threadName (str): If provided, will reply to an existing thread (or create a new thread)

    Returns:
        CommandResults/dict: A ``CommandResults`` compatible to return ``return_results()``,
        which contains the readable_output indicating the message was sent.
    """
    res = client.send_google_chat_custom_card(blocks=blocks, threadName=threadName)
    result = {
        'SpaceName': res.get('space').get('name'),
        'SpaceDisplayName': res.get('space').get('displayName'),
        'SpaceType': res.get('space').get('type'),
        'CreatedTime': res.get('createTime'),
        'ThreadReply': res.get('threadReply', False),
        'ThreadName': res.get('thread').get('name'),
        'Name': res.get('name'),
        'SenderDisplayName': res.get('sender').get('displayName'),
        'SenderName': res.get('sender').get('name'),
        'SenderType': res.get('sender').get('type')
    }
    markdown = '### Google Chat\n'
    markdown += tableToMarkdown('Custom Card Webhook', result)
    # Add the card details to context after formatting md
    result.update({'Cards': res.get('cardsV2')})
    results = CommandResults(
        readable_output=markdown,
        outputs_prefix='GoogleChatWebhook.CustomCard',
        outputs_key_field='name',
        outputs=result
    )
    return results


def main() -> None:    # pragma: no cover
    """
    Main function, parses params and runs command functions
    Sends a test message, a spaces message, or a customized card via the UI Kit Builder.
    """

    params = demisto.params()
    args = demisto.args()

    space_id = params.get('space_id')
    key = params.get('key').get('password')
    token = params.get('token').get('password')
    verify_certificate = not params.get('insecure', False)
    proxy = params.get('proxy', False)
    headers = {'Content-Type': 'application/json; charset=UTF-8'}
    base_url = f'https://chat.googleapis.com/v1/spaces/{space_id}'

    command = demisto.command()
    try:
        client = Client(
            base_url=base_url,
            verify=verify_certificate,
            proxy=proxy,
            headers=headers,
            key=key,
            token=token
        )

        # Runs the test module
        if command == 'test-module':
            return_results(test_module(client))
        # Runs the 'send-google-chat-message' integration command
        elif command == 'send-google-chat-message':
            message = args.get('message', '')
            threadName = args.get('threadName', '')
            return_results(send_google_chat_message_command(client, message, threadName))
        # Runs the 'send-google-chat-custom-card' integration command
        elif command == 'send-google-chat-custom-card':
            blocks = args.get('blocks', '')
            threadName = args.get('threadName', '')
            return_results(send_google_chat_custom_card_command(client, blocks, threadName))
        else:
            raise NotImplementedError(f'command {command} is not implemented.')

    except Exception as e:
        demisto.error(traceback.format_exc())
        return_error(f'Failed to execute {command} command.\nError:\n{e}')


if __name__ in ('__builtin__', 'builtins', '__main__'):
    main()
