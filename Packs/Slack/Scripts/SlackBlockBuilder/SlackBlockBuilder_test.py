import json
import io
import demistomock as demisto  # noqa # pylint: disable=unused-wildcard-import
from CommonServerPython import entryTypes
from typing import List, Dict, Any


def util_load_json(path):
    with io.open(path, mode='r', encoding='utf-8') as f:
        return json.loads(f.read())


BLOCKS_URL = "https://app.slack.com/block-kit-builder/T0DAYMVCM#%7B%22blocks%22:%5B%7B%22type%22:%22section%22," \
             "%22text%22:%7B%22type%22:%22mrkdwn%22," \
             "%22text%22:%22You%20have%20a%20new%20request:%5Cn*%3CfakeLink.toEmployeeProfile.com%7CFred%20Enriquez" \
             "%20-%20New%20device%20request%3E*%22%7D%7D,%7B%22type%22:%22section%22," \
             "%22fields%22:%5B%7B%22type%22:%22mrkdwn%22,%22text%22:%22*Type:*%5CnComputer%20(laptop)%22%7D," \
             "%7B%22type%22:%22mrkdwn%22,%22text%22:%22*When:*%5CnSubmitted%20Aut%2010%22%7D," \
             "%7B%22type%22:%22mrkdwn%22,%22text%22:%22*Last%20Update:*%5CnMar%2010,%202015%20(3%20years," \
             "%205%20months)%22%7D,%7B%22type%22:%22mrkdwn%22," \
             "%22text%22:%22*Reason:*%5CnAll%20vowel%20keys%20aren't%20working.%22%7D,%7B%22type%22:%22mrkdwn%22," \
             "%22text%22:%22*Specs:*%5Cn%5C%22Cheetah%20Pro%2015%5C%22%20-%20Fast,%20really%20fast%5C%22%22%7D%5D%7D," \
             "%7B%22type%22:%22actions%22,%22elements%22:%5B%7B%22type%22:%22button%22," \
             "%22text%22:%7B%22type%22:%22plain_text%22,%22emoji%22:true,%22text%22:%22Approve%22%7D," \
             "%22style%22:%22primary%22,%22value%22:%22click_me_123%22%7D,%7B%22type%22:%22button%22," \
             "%22text%22:%7B%22type%22:%22plain_text%22,%22emoji%22:true,%22text%22:%22Deny%22%7D," \
             "%22style%22:%22danger%22,%22value%22:%22click_me_123%22%7D%5D%7D,%7B%22type%22:%22input%22," \
             "%22element%22:%7B%22type%22:%22plain_text_input%22,%22action_id%22:%22plain_text_input-action%22%7D," \
             "%22label%22:%7B%22type%22:%22plain_text%22,%22text%22:%22Label%22,%22emoji%22:true%7D%7D%5D%7D "


def test_block_carrier_with_url(mocker):
    """Tests the block carrier when given an url.

    Checks the output of the command function with the expected output.
    """
    from SlackBlockBuilder import BlockCarrier

    def executeCommand(command: str, args: Dict[str, Any]) -> List[Dict[str, Any]]:
        if command == 'addEntitlement':
            return [{'Type': entryTypes['note'], 'Contents': 'some-guid'}]

    mocker.patch.object(demisto, 'executeCommand', side_effect=executeCommand)
    block_carrier = BlockCarrier(url=BLOCKS_URL)
    mock_response = util_load_json('test_data/blocks.json')

    assert block_carrier.blocks_dict == mock_response


def test_block_carrier_with_list_name(mocker):
    """Tests the block carrier when given a list.

    Checks the output of the command function with the expected output.
    """
    from SlackBlockBuilder import BlockCarrier

    blocks_dict = util_load_json('test_data/blocks.json')
    mock_list = util_load_json('test_data/list.json')

    def executeCommand(command: str, args: Dict[str, Any]) -> List[Dict[str, Any]]:
        if command == 'getList':
            return [{"Contents": json.dumps(mock_list)}]
        elif command == 'addEntitlement':
            return [{'Type': entryTypes['note'], 'Contents': 'some-guid'}]

    mocker.patch.object(demisto, 'executeCommand', side_effect=executeCommand)

    list_name = "SomeList"
    block_carrier = BlockCarrier(list_name=list_name)

    assert block_carrier.blocks_dict == blocks_dict


COMMAND_ARGS = {
    "channel": "random",
    "task": "4",
    "replyEntriesTag": "slackResponse",
    "persistent": "yes"
}


def test_block_builder_command_list(mocker):
    """
    Given: An XSOAR list containing a valid Slack Block JSON.
    When: Executing the block builder command using the list argument.
    Then: Assert that the readable output from the command indicates that the message was successfully sent.
    """
    from SlackBlockBuilder import slack_block_builder_command

    mock_list = util_load_json('test_data/list.json')

    def executeCommand(command: str, args: Dict[str, Any]) -> List[Dict[str, Any]]:
        if command == 'getList':
            return [{"Contents": json.dumps(mock_list)}]
        elif command == 'addEntitlement':
            return [{'Type': entryTypes['note'], 'Contents': 'some-guid'}]
        elif command == 'send-notification':
            return [{'Type': entryTypes['note'], 'HumanReadable': 'Message sent to Slack successfully.\nThread ID is: '
                                                                  '1660645689.649679'}]

    mocker.patch.object(demisto, 'executeCommand', side_effect=executeCommand)
    COMMAND_ARGS["list_name"] = "SomeList"
    mocker.patch.object(demisto, 'args', return_value=COMMAND_ARGS)

    response = slack_block_builder_command(COMMAND_ARGS)
    assert response.readable_output == 'Message sent to Slack successfully.\nThread ID is: 1660645689.649679'


def test_block_builder_command_url(mocker):
    """
    Given: A URL which contains a valid URI encoded Slack Block JSON.
    When: Executing the block builder command using the url argument.
    Then: Assert that the readable output from the command indicates that the message was successfully sent.
    """
    from SlackBlockBuilder import slack_block_builder_command

    mock_list = util_load_json('test_data/list.json')

    def executeCommand(command: str, args: Dict[str, Any]) -> List[Dict[str, Any]]:
        if command == 'getList':
            return [{"Contents": json.dumps(mock_list)}]
        elif command == 'addEntitlement':
            return [{'Type': entryTypes['note'], 'Contents': 'some-guid'}]
        elif command == 'send-notification':
            return [{'Type': entryTypes['note'], 'HumanReadable': 'Message sent to Slack successfully.\nThread ID is: '
                                                                  '1660645689.649679'}]

    mocker.patch.object(demisto, 'executeCommand', side_effect=executeCommand)
    COMMAND_ARGS["blocks_url"] = BLOCKS_URL
    mocker.patch.object(demisto, 'args', return_value=COMMAND_ARGS)

    response = slack_block_builder_command(COMMAND_ARGS)
    assert response.readable_output == 'Message sent to Slack successfully.\nThread ID is: 1660645689.649679'
