
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


def test_get_lists_command(mocker):
    """
    Given
    - valid arguments for get lists command

    When
    - running get_lists_command in XSOAR

    Then
    - the expected human readable and entry context are returned
    """
    from SkyhighSecureWebGatewayOnPrem import get_lists_command

    args = {"name": "blocklist"}
    raw_response = util_load_file("test_data/get_lists/raw_response.xml")
    expected_results = json.loads(util_load_file("test_data/get_lists/parsed_result.json"))

    mocker.patch.object(client, 'get_lists', return_value=raw_response)
    command_result = get_lists_command(client, args)

    assert expected_results["EntryContext"] == command_result.to_context().get('EntryContext')
    assert expected_results['HumanReadable'] == command_result.to_context().get('HumanReadable')


def test_get_list(mocker):
    """
    Given
    - valid arguments for get list command

    When
    - running get_list_command in XSOAR

    Then
    - the expected human readable and entry context are returned
    """
    from SkyhighSecureWebGatewayOnPrem import get_list_command

    args = {"list_id": "com.scur.type.regex.386"}
    raw_response = util_load_file("test_data/get_list/raw_response.xml")
    expected_results = json.loads(util_load_file("test_data/get_list/parsed_result.json"))

    mocker.patch.object(client, 'get_list', return_value=raw_response)
    command_result = get_list_command(client, args)

    assert expected_results["EntryContext"] == command_result.to_context().get('EntryContext')
    assert expected_results['HumanReadable'] == command_result.to_context().get('HumanReadable')


def test_get_list_entry(mocker):
    """
    Given
    - valid arguments for get list entry command

    When
    - running get_list_entry_command in XSOAR

    Then
    - the expected human readable and entry context are returned
    """
    from SkyhighSecureWebGatewayOnPrem import get_list_entry_command

    args = {"list_id": "com.scur.type.regex.386", "entry_pos": "0"}
    raw_response = util_load_file("test_data/get_list_entry/raw_response.xml")
    expected_results = json.loads(util_load_file("test_data/get_list_entry/parsed_result.json"))

    mocker.patch.object(client, 'get_list_entry', return_value=raw_response)
    command_result = get_list_entry_command(client, args)

    assert expected_results["EntryContext"] == command_result.to_context().get('EntryContext')
    assert expected_results['HumanReadable'] == command_result.to_context().get('HumanReadable')


def test_insert_entry(mocker):
    """
    Given
    - valid arguments for insert entry command

    When
    - running insert_entry_command in XSOAR

    Then
    - the expected human readable and entry context are returned
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

    assert expected_results["EntryContext"] == command_result.to_context().get('EntryContext')
    assert expected_results['HumanReadable'] == command_result.to_context().get('HumanReadable')


def test_delete_entry(mocker):
    """
    Given
    - valid arguments for delete entry command

    When
    - running delete_entry_command in XSOAR

    Then
    - the expected human readable is returned
    """
    from SkyhighSecureWebGatewayOnPrem import delete_entry_command

    args = {"list_id": "com.scur.type.regex.386", "entry_pos": "0"}
    raw_response = util_load_file("test_data/delete_entry/raw_response.xml")
    expected_results = json.loads(util_load_file("test_data/delete_entry/parsed_result.json"))

    mocker.patch.object(client, 'delete_entry', return_value=raw_response)
    mocker.patch.object(client, 'commit', return_value=True)
    command_result = delete_entry_command(client, args)

    assert expected_results['HumanReadable'] == command_result.to_context().get('HumanReadable')


def test_modify_list(mocker):
    """
    Given
    - valid arguments for modify list command

    When
    - running modify_list_command in XSOAR

    Then
    - the expected human readable and entry context are returned
    """
    from SkyhighSecureWebGatewayOnPrem import modify_list_command

    args = {
        "list_id": "com.scur.type.regex.386",
        "config": '<list><description>blocklist</description><content><listEntry><entry>http*://evil.corp/*</entry>'
                  + '<description>ticket #1: This is an evil domain</description></listEntry></content></list>'
    }
    raw_response = util_load_file("test_data/modify_list/raw_response.xml")
    expected_results = json.loads(util_load_file("test_data/modify_list/parsed_result.json"))

    mocker.patch.object(client, 'put_list', return_value=raw_response)
    mocker.patch.object(client, 'commit', return_value=True)
    command_result = modify_list_command(client, args)

    assert expected_results["EntryContext"] == command_result.to_context().get('EntryContext')
    assert expected_results['HumanReadable'] == command_result.to_context().get('HumanReadable')


def test_create_list(mocker):
    """
    Given
    - valid arguments for create list command

    When
    - running create_list_command in XSOAR

    Then
    - the expected human readable and entry context are returned
    """
    from SkyhighSecureWebGatewayOnPrem import create_list_command

    args = {"name": "blocklist", "type": "regex"}
    raw_response = util_load_file("test_data/create_list/raw_response.xml")
    expected_results = json.loads(util_load_file("test_data/create_list/parsed_result.json"))

    mocker.patch.object(client, 'create_list', return_value=raw_response)
    mocker.patch.object(client, 'commit', return_value=True)
    command_result = create_list_command(client, args)

    assert expected_results["EntryContext"] == command_result.to_context().get('EntryContext')
    assert expected_results['HumanReadable'] == command_result.to_context().get('HumanReadable')


def test_delete_list(mocker):
    """
    Given
    - valid arguments for delete list command

    When
    - running delete_list_command in XSOAR

    Then
    - the expected human readable and entry context are returned
    """
    from SkyhighSecureWebGatewayOnPrem import delete_list_command

    args = {"list_id": "com.scur.type.regex.460"}
    raw_response = util_load_file("test_data/delete_list/raw_response.xml")
    expected_results = json.loads(util_load_file("test_data/delete_list/parsed_result.json"))

    mocker.patch.object(client, 'delete_list', return_value=raw_response)
    mocker.patch.object(client, 'commit', return_value=True)
    command_result = delete_list_command(client, args)

    assert expected_results['HumanReadable'] == command_result.to_context().get('HumanReadable')
