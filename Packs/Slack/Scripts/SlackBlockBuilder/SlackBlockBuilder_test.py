import json
import demistomock as demisto  # noqa # pylint: disable=unused-wildcard-import
from CommonServerPython import entryTypes
from typing import Any
import pytest
from CommonServerPython import DemistoException


def util_load_json(path):
    with open(path, encoding='utf-8') as f:
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
             "%22style%22:%22danger%22,%22value%22:%22click_me_123%22,%22url%22:%22https://google.com/#/Details/incident.id%22%" \
             "7D%5D%7D,%7B%22type%22:%22input%22,%22element%22:%7B%22type%22:%22plain_text_input%22,%22action_id%22:%" \
             "22plain_text_input-action%22%7D,%22label%22:%7B%22type%22:%22plain_text%22,%22text%22:%22Label%22," \
             "%22emoji%22:true%7D%7D%5D%7D "


def test_block_carrier_with_url(mocker):
    """Tests the block carrier when given an url.

    Checks the output of the command function with the expected output.
    """
    from SlackBlockBuilder import BlockCarrier

    def executeCommand(command: str, args: dict[str, Any]) -> list[dict[str, Any]]:
        if command == 'addEntitlement':
            return [{'Type': entryTypes['note'], 'Contents': 'some-guid'}]
        return None

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

    def executeCommand(command: str, args: dict[str, Any]) -> list[dict[str, Any]]:
        if command == 'getList':
            return [{"Contents": json.dumps(mock_list)}]
        elif command == 'addEntitlement':
            return [{'Type': entryTypes['note'], 'Contents': 'some-guid'}]
        return None

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

    def executeCommand(command: str, args: dict[str, Any]) -> list[dict[str, Any]]:
        if command == 'getList':
            return [{"Contents": json.dumps(mock_list)}]
        elif command == 'addEntitlement':
            return [{'Type': entryTypes['note'], 'Contents': 'some-guid'}]
        elif command == 'send-notification':
            return [{'Type': entryTypes['note'], 'HumanReadable': 'Message sent to Slack successfully.\nThread ID is: '
                                                                  '1660645689.649679',
                     'Contents': {'ts': 'ts', 'channel': 'channel',
                                  'message': {'text': 'text', 'bot_id': 'bot_id', 'username': 'username', 'app_id': 'app_id'}}}]
        return None

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

    def executeCommand(command: str, args: dict[str, Any]) -> list[dict[str, Any]]:
        if command == 'getList':
            return [{"Contents": json.dumps(mock_list)}]
        elif command == 'addEntitlement':
            return [{'Type': entryTypes['note'], 'Contents': 'some-guid'}]
        elif command == 'send-notification':
            return [{'Type': entryTypes['note'], 'HumanReadable': 'Message sent to Slack successfully.\nThread ID is: '
                                                                  '1660645689.649679',
                     'Contents': {'ts': 'ts', 'channel': 'channel',
                                  'message': {'text': 'text', 'bot_id': 'bot_id', 'username': 'username', 'app_id': 'app_id'}}}]
        return None

    mocker.patch.object(demisto, 'executeCommand', side_effect=executeCommand)
    COMMAND_ARGS["blocks_url"] = BLOCKS_URL
    mocker.patch.object(demisto, 'args', return_value=COMMAND_ARGS)

    response = slack_block_builder_command(COMMAND_ARGS)
    assert response.readable_output == 'Message sent to Slack successfully.\nThread ID is: 1660645689.649679'


def test_block_builder_command_url_return_fail(mocker):
    """
    Given: A URL which contains a valid URI encoded Slack Block JSON.
    When: Executing the block builder command using the url argument.
    Then: Assert that the readable output from the command indicates that the message was successfully sent.
    """
    from SlackBlockBuilder import slack_block_builder_command

    mock_list = util_load_json('test_data/list.json')

    def executeCommand(command: str, args: dict[str, Any]) -> list[dict[str, Any]]:
        if command == 'getList':
            return [{"Contents": json.dumps(mock_list)}]
        elif command == 'addEntitlement':
            return [{'Type': entryTypes['note'], 'Contents': 'some-guid'}]
        elif command == 'send-notification':
            return [{'Type': 4, 'HumanReadable': None,
                     'Contents': "Could not find any destination to send to."}]
        return []

    mocker.patch.object(demisto, 'executeCommand', side_effect=executeCommand)
    COMMAND_ARGS["blocks_url"] = BLOCKS_URL
    mocker.patch.object(demisto, 'args', return_value=COMMAND_ARGS)

    with pytest.raises(DemistoException, match="Could not find any destination to send to."):
        slack_block_builder_command(COMMAND_ARGS)


def test_image_id_bug_XSUP_31982(mocker):
    """Tests the block carrier when given an url containing an image.

    Checks the output of the command function with the expected output.
    """
    from SlackBlockBuilder import BlockCarrier

    provided_url = ("https://app.slack.com/block-kit-builder/TAT0NDT9A#%7B%22blocks%22:%5B%7B%22type%22:%22section%22,"
                    "%22text%22:%7B%22type%22:%22mrkdwn%22,"
                    "%22text%22:%22The%20risk%20threshold%20exceeded%20for%20*user*:%22%7D%7D,"
                    "%7B%22type%22:%22header%22,%22text%22:%7B%22type%22:%22plain_text%22,"
                    "%22text%22:%22:splunk:%20Splunk%20Notable%22,%22emoji%22:true%7D%7D,"
                    "%7B%22type%22:%22divider%22%7D,%7B%22type%22:%22section%22,"
                    "%22text%22:%7B%22type%22:%22mrkdwn%22,"
                    "%22text%22:%22*Risk%20Object:%20*%20*%3CfakeLink.toUserProfiles.com%7Cryan.ng%3E*%5Cn*Severity"
                    ":%20*%20:xsoar_critical:%20Critical%5Cn*Risk%20Score:%20*%20100.0%22%7D,"
                    "%22accessory%22:%7B%22type%22:%22image%22,%22image_url%22:%22https://i.imgur.com/xCvzudW.png%22,"
                    "%22alt_text%22:%22user%22%7D%7D%5D%7D")

    def executeCommand(command: str, args: dict[str, Any]) -> list[dict[str, Any]]:
        if command == 'addEntitlement':
            return [{'Type': entryTypes['note'], 'Contents': 'some-guid'}]
        return None

    def contains_action_id_image0(data):
        for item in data:
            if item.get('type') == 'actions':
                for element in item.get('elements', []):
                    if element.get('action_id') == 'image0':
                        return True
        return False

    mocker.patch.object(demisto, 'executeCommand', side_effect=executeCommand)
    block_carrier = BlockCarrier(url=provided_url)
    block_carrier.format_blocks()
    mock_response = util_load_json('test_data/blocks_xsup_31982.json')

    assert block_carrier.blocks_dict == mock_response
    assert not contains_action_id_image0(block_carrier.blocks_dict), "action_id 'image0' is present in the data"
