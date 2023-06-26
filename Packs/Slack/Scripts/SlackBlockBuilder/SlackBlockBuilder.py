import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
from typing import Dict, Any, List
import traceback
import urllib.parse

DATE_FORMAT = '%Y-%m-%d %H:%M:%S'
''' STANDALONE FUNCTION '''


class Commands(object):
    SEND_NOTIFICATION = 'send-notification'
    ADD_ENTITLEMENT = 'addEntitlement'
    GET_LIST = 'getList'


class DefaultValues(object):
    RESPONSE = 'Thank you for your reply.'
    ONE_DAY = '1 day'


class ErrorMessages(object):
    MALFORMED_LIST = 'The list that was provided is not a dictionary. Please ensure the entire payload has been copied' \
                     ' from the Block Kit Builder'
    COMMAND_ERROR = 'An error has occurred while executing the send-notification command'
    MISSING_DESTINATION = 'Either a user or a channel must be provided.'
    NOT_FOUND = 'Item not found (8)'
    MISSING_URL_OR_LIST = 'blocks_url or a list was not specified'


class BlockCarrier:
    def __init__(self, url: str = '', list_name: Optional[str] = None, task: Optional[str] = None,
                 persistent: Optional[str] = None, reply_entries_tag: Optional[str] = None,
                 lifetime: str = DefaultValues.ONE_DAY,
                 reply: Optional[str] = None, default_response: str = DefaultValues.RESPONSE):
        """Used to format blocks for the send-notification command

        BlockCarrier will handle several formatting steps for the Slack blocks.
        - First, the investigation_id is retrieved. If none is found, the default is 00. This will give a failsafe for
        entitlements which enter the context and an incident cannot be found.
        - Second, the entitlement string is built. This requires a server call to generate the GUID. From there, we
        append information needed by SlackV3 in order to process any given reply.
        - Depending on the inputs, if a list name is given, then _retrieve_blocks_from_list is called and will make a
        server call to retrieve the stored blocks. If a URL is given, then _parse_url_blocks is called, and we will
        extract the blocks out of the URL given by the Slack Block Builder tool.

        Args:
            url (str): The Slack Builder URL. Not required if list_name is provided.
            list_name (str): The Name of the XSOAR list. Not required if url is provided.
            task (str): The ID for the task which will be closed when a response is received.
            persistent (str): Indicates if the entitlement should remain available after a reply is received.
            reply_entries_tag (str): The tag which should be added to entries containing the reply.
            lifetime (str): The TTL for the entitlement. This gets converted to an expiry time.
            reply (str): The message a user should receive when a response has been submitted.
            default_response (str): If the entitlement expires, this will be the response submitted to the incident.
        Raises:
            ValueError: If neither the url nor list_name arg is not provided, will raise an exception.
        """
        self.entitlement_string = str()
        self.default_response = default_response
        self.blocks_ready_for_args: Dict[str, Any] = dict()
        self.url = url
        self.list_name = list_name
        self.persistent = persistent
        self.reply_entries_tag = reply_entries_tag
        self.task = task
        self.blocks_dict: List[dict] = list(dict())
        self.investigation_id = demisto.investigation().get('id', '00')
        self.reply = reply
        self._build_entitlement()

        if self.list_name:
            self._retrieve_blocks_from_list()
        elif self.url:
            self._parse_url_blocks()
        else:
            raise ValueError(ErrorMessages.MISSING_URL_OR_LIST)

        parsed_date = dateparser.parse('in ' + lifetime, settings={'TIMEZONE': 'UTC'})
        assert parsed_date is not None, f'could not parse in {lifetime}'
        self.expiry = datetime.strftime(parsed_date, DATE_FORMAT)

    def _build_entitlement(self):
        """Builds the entitlement string

        Entitlement strings are essential in order to know which incident the response belongs to. This will get fed to
        the send-notification command and stored into the SlackV3 integration context.
        """
        res = demisto.executeCommand(command=Commands.ADD_ENTITLEMENT,
                                     args={
                                         'persistent': self.persistent,
                                         'replyEntriesTag': self.reply_entries_tag
                                     })
        if isError(res[0]):
            raise DemistoException(message=res)
        entitlement = demisto.get(obj=res[0], field='Contents')
        self.entitlement_string = entitlement + '@' + self.investigation_id
        if self.task:
            self.entitlement_string += '|' + self.task

    def _add_block_ids(self):
        """Populates block_ids into a given array of blocks

        Slack will give pre-populate the block_id fields if we do not specify them. This function will iterate over the
        elements of a block array and set the block_id field based on the label (in the case of input blocks) or
        action_ids in the case of everything else. We also increment an integer in order to keep each key as unique
        since this will inevitably be placed in the context of the incident.
        """
        action_id_int: int = 0
        for block in self.blocks_dict:
            if block.get('type') == 'input':
                action_id: str = block.get('element', {}).get('type', '')
                block['block_id'] = action_id + '_' + str(action_id_int)
                action_id_int += 1
            elif block.get('type') == 'actions':
                if 'elements' in block:
                    actions_block_id: str = block.get('elements', [{}])[0].get('type', '')
                    block['block_id'] = actions_block_id + '_' + str(action_id_int)
                    action_id_int += 1
            elif block.get('type') == 'section':
                if 'accessory' in block:
                    sec_action_id: str = block.get('accessory', {}).get('type', '')
                    block['block_id'] = sec_action_id + '_' + str(action_id_int)
                    block['accessory']['action_id'] = sec_action_id + str(action_id_int)
                    action_id_int += 1

    def _add_submit_button(self):
        """Adds a submit button with a known action_id

        We need to ensure that there will always be a button with a known action_id. SlackV3 will listen for blocks
        containing this action_id and then pull the state of the inputs.
        """
        value = json.dumps({
            'entitlement': self.entitlement_string,
            'reply': self.reply
        })
        self.blocks_dict.append({
            "type": "actions",
            "elements": [{
                'type': 'button',
                'text': {
                    'type': 'plain_text',
                    'text': 'Submit',
                    'emoji': True
                },
                'value': value,
                'action_id': 'xsoar-button-submit'
            }]
        })

    def _parse_url_blocks(self):
        """Parses the Slack Block Builder URL

        Slack provides a tool located at https://app.slack.com/block-kit-builder. When you are done, you can copy and
        paste the URL into the blocks_url argument for this automation. The URL is then decoded to provide the blocks.
        """
        url_encoded_blocks: str = self.url.split('#')[1]
        url_decoded_blocks: str = urllib.parse.unquote(url_encoded_blocks)
        parsed_blocks: Any = json.loads(url_decoded_blocks)
        self.blocks_dict = parsed_blocks.get('blocks', [{}])

    def _retrieve_blocks_from_list(self):
        """Retrieves the blocks when given an XSOAR list name.

        It may be useful to store the blocks which are used frequently as an item in the XSOAR lists. This function will
        retrieve the blocks from the list and set them in the BlockCarrier object.
        Raises:
            ValueError: If the list was not located, or the list contains an invalid JSON.
        """
        res = demisto.executeCommand(command=Commands.GET_LIST, args={'listName': self.list_name})
        if (
                not isinstance(res, list)
                or 'Contents' not in res[0]
                or not isinstance(res[0]['Contents'], str)
                or res[0]['Contents'] == ErrorMessages.NOT_FOUND
        ):
            raise ValueError(f'Cannot retrieve list {self.list_name}. Please verify the name is correct. If you have'
                             f' not created a list before, please refer to https://xsoar.pan.dev/docs/incidents/'
                             f'incident-lists for more information.')
        data: str = res[0]['Contents']
        if data and len(data) > 0:
            try:
                parsed_blocks: Any = json.loads(data)
                try:
                    assert isinstance(parsed_blocks, dict)
                except AssertionError:
                    raise DemistoException(ErrorMessages.MALFORMED_LIST)
                self.blocks_dict = parsed_blocks.get('blocks', [{}])

            except json.decoder.JSONDecodeError as e:
                raise ValueError(f'List does not contain valid JSON data: {e}')

    def _blocks_formatted_for_command(self):
        """Formats the Blocks for the send-notification command.

        Inevitably, the blocks will need to be converted to a json string and then fed into the send-notification command.
        This handles that process.
        """
        self.blocks_ready_for_args = {
            'blocks': json.dumps(self.blocks_dict),
            'entitlement': self.entitlement_string,
            'reply': self.reply,
            'expiry': self.expiry,
            'default_response': self.default_response
        }

    def format_blocks(self):
        """Finalizes the blocks for the send-notification command.

        Before calling the send-notification command, we finalize the blocks by adding the submit button and the
        block_ids. Lastly, we dump the results as a string in the blocks_as_json_str field.
        """
        self._add_submit_button()
        self._add_block_ids()
        self._blocks_formatted_for_command()


class SendNotification:
    def __init__(self, blocks_carrier: BlockCarrier, slack_instance: Optional[str] = None, to: Optional[str] = None,
                 channel_id: Optional[str] = None, channel: Optional[str] = None):
        self.blocks_carrier: BlockCarrier = blocks_carrier
        self.send_response: list = []
        self.command_args: dict = {
            'ignoreAddURL': 'true',
            'using-brand': 'SlackV3',
            'blocks': json.dumps(self.blocks_carrier.blocks_ready_for_args)
        }
        if slack_instance:
            self.command_args['using'] = slack_instance
        # Determine Destination, Raise error if not given
        if to:
            self.command_args['to'] = to
        elif channel_id:
            self.command_args['channel_id'] = channel_id
        elif channel:
            self.command_args['channel'] = channel
        else:
            raise DemistoException(message=ErrorMessages.MISSING_DESTINATION)

    def send(self):
        """Executes the send-notification command.

        Sends the blocks to the given destination. Will then store the response from the command.
        Raises:
            ValueError: If an error occurs while sending the notification.
        """
        try:
            self.send_response = demisto.executeCommand(Commands.SEND_NOTIFICATION, self.command_args)
        except ValueError as e:
            raise DemistoException(message=ErrorMessages.COMMAND_ERROR, exception=e)


''' COMMAND FUNCTION '''


def slack_block_builder_command(args: Dict[str, Any]):
    """Executes the block_builder command.

    Args:
        args (Dict[str, Any]): The demisto.args() object.

    Returns:
        CommandResults: Will contain the response from the send-notification command.
    """
    blocks_url: str = demisto.get(obj=args, field='blocks_url', defaultParam=None)
    list_name: str = demisto.get(obj=args, field='list_name', defaultParam=None)
    slack_instance = demisto.get(obj=args, field='slackInstance')
    lifetime = demisto.get(obj=args, field='lifetime', defaultParam='1 day')
    reply = demisto.get(obj=args, field='reply')
    task = demisto.get(obj=args, field='task')
    persistent = demisto.get(obj=args, field='persistent')
    reply_entries_tag = demisto.get(obj=args, field='reply_entries_tag')
    default_response = demisto.get(obj=args, field='defaultResponse')
    to = demisto.get(obj=args, field='user')
    channel = demisto.get(obj=args, field='channel')
    channel_id = demisto.get(obj=args, field='channel_id')

    block_carrier = BlockCarrier(url=blocks_url, list_name=list_name, task=task, persistent=persistent,
                                 reply_entries_tag=reply_entries_tag, lifetime=lifetime,
                                 reply=reply, default_response=default_response)
    block_carrier.format_blocks()
    notification = SendNotification(blocks_carrier=block_carrier, slack_instance=slack_instance, to=to,
                                    channel_id=channel_id, channel=channel)
    notification.send()
    human_readable = notification.send_response[0]['HumanReadable']
    return CommandResults(readable_output=human_readable)


''' MAIN FUNCTION '''


def main():
    try:
        return_results(slack_block_builder_command(demisto.args()))
    except Exception as excep:
        demisto.error(traceback.format_exc())  # print the traceback
        return_error(f'Failed to execute SlackBlockBuilder. Error: {str(excep)}')


''' ENTRY POINT '''

if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
