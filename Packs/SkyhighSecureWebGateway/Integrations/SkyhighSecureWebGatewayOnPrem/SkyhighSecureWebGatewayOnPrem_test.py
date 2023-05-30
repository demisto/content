"""Base Integration for Cortex XSOAR - Unit Tests file

Pytest Unit Tests: all funcion names must start with "test_"

More details: https://xsoar.pan.dev/docs/integrations/unit-testing

MAKE SURE YOU REVIEW/REPLACE ALL THE COMMENTS MARKED AS "TODO"

You must add at least a Unit Test function for every XSOAR command
you are implementing with your integration
"""

import json
import io
from SkyhighSecureWebGatewayOnPrem import Client

client = Client(username="user",
                password="password",
                base_url="base_url",
                verify=False,
                headers={"Content-Type": "application/mwg+xml"},
                proxy=False)


def util_load_file(path):
    with io.open(path, mode="r", encoding="utf-8") as f:
        return f.read()


def test_get_lists(mocker):
    """Tests get available lists command function.

    Checks the output of the command function with the expected output.
    """
    from SkyhighSecureWebGatewayOnPrem import get_lists_command

    args = {"filter": "blocklist"}
    raw_response = util_load_file("test_data/get_lists/raw_response.xml")
    expected_results = json.loads(util_load_file("test_data/get_lists/parsed_result.json"))

    mocker.patch.object(client, 'get_lists', return_value=raw_response)
    command_result = get_lists_command(client, args)

    assert expected_results["EntryContext"] == command_result.to_context()['EntryContext']
    assert expected_results['HumanReadable'] == command_result.to_context()['HumanReadable']


def test_get_list(mocker):
    """Tests get list command function.

    Checks the output of the command function with the expected output.
    """
    from SkyhighSecureWebGatewayOnPrem import get_list_command

    args = {"list_id": "com.scur.type.regex.386"}
    raw_response = util_load_file("test_data/get_list/raw_response.xml")
    expected_results = json.loads(util_load_file("test_data/get_list/parsed_result.json"))

    mocker.patch.object(client, 'get_list', return_value=raw_response)
    command_result = get_list_command(client, args)

    assert expected_results["EntryContext"] == command_result.to_context()['EntryContext']
    assert expected_results['HumanReadable'] == command_result.to_context()['HumanReadable']


def test_get_list_entry(mocker):
    """Tests get list entry command function.

    Checks the output of the command function with the expected output.
    """
    from SkyhighSecureWebGatewayOnPrem import get_list_entry_command

    args = {"list_id": "com.scur.type.regex.386", "entry_pos": "0"}
    raw_response = util_load_file("test_data/get_list_entry/raw_response.xml")
    expected_results = json.loads(util_load_file("test_data/get_list_entry/parsed_result.json"))

    mocker.patch.object(client, 'get_list_entry', return_value=raw_response)
    command_result = get_list_entry_command(client, args)

    assert expected_results["EntryContext"] == command_result.to_context()['EntryContext']
    assert expected_results['HumanReadable'] == command_result.to_context()['HumanReadable']


def test_insert_entry(mocker):
    """Tests insert list entry command function.

    Checks the output of the command function with the expected output.
    """
    from SkyhighSecureWebGatewayOnPrem import insert_entry_command

    args = {
        "list_id": "com.scur.type.regex.386",
        "entry_pos": "0",
        "name": "http*://evil.corp/*",
        "description": "ticket #1: This is an evil domain"
    }
    raw_response = util_load_file("test_data/insert_entry/raw_response.xml")
    expected_results = json.loads(util_load_file("test_data/insert_entry/parsed_result.json"))

    mocker.patch.object(client, 'insert_entry', return_value=raw_response)
    mocker.patch.object(client, 'commit', return_value=True)
    command_result = insert_entry_command(client, args)

    assert expected_results["EntryContext"] == command_result.to_context()['EntryContext']
    assert expected_results['HumanReadable'] == command_result.to_context()['HumanReadable']


def test_delete_entry(mocker):
    """Tests delete list entry command function.

    Checks the output of the command function with the expected output.
    """
    from SkyhighSecureWebGatewayOnPrem import delete_entry_command

    args = {"list_id": "com.scur.type.regex.386", "entry_pos": "0"}
    raw_response = util_load_file("test_data/delete_entry/raw_response.xml")
    expected_results = json.loads(util_load_file("test_data/delete_entry/parsed_result.json"))

    mocker.patch.object(client, 'delete_entry', return_value=raw_response)
    mocker.patch.object(client, 'commit', return_value=True)
    command_result = delete_entry_command(client, args)

    assert expected_results['HumanReadable'] == command_result.to_context()['HumanReadable']


def test_modify_list(mocker):
    """Tests modify list command function.

    Checks the output of the command function with the expected output.
    """
    from SkyhighSecureWebGatewayOnPrem import modify_list_command

    args = {
        "list_id": "com.scur.type.regex.386",
        "config": '<list version="1.0.3.46" mwg-version="11.2.9-44482" name="blocklist" id="com.scur.type.regex.386" typeId='
                  + '"com.scur.type.regex" classifier="Other" systemList="false" structuralList="false" defaultRights="2">'
                  + '<description>blocklist</description><content><listEntry><entry>http*://evil.corp/*</entry>'
                  + '<description>ticket #1: This is an evil domain</description></listEntry></content></list>'
    }
    raw_response = util_load_file("test_data/modify_list/raw_response.xml")
    expected_results = json.loads(util_load_file("test_data/modify_list/parsed_result.json"))

    mocker.patch.object(client, 'put_list', return_value=raw_response)
    mocker.patch.object(client, 'commit', return_value=True)
    command_result = modify_list_command(client, args)

    assert expected_results["EntryContext"] == command_result.to_context()['EntryContext']
    assert expected_results['HumanReadable'] == command_result.to_context()['HumanReadable']
