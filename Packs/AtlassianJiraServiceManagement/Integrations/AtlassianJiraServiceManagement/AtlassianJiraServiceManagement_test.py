import pytest
from unittest.mock import Mock
from pytest_mock import MockerFixture
from typing import Any
import AtlassianJiraServiceManagement as JSM
import json
from CommonServerPython import CommandResults
import demistomock as demisto
import os


def util_load_json(path):
    with open(path, encoding='utf-8') as f:
        return json.loads(f.read())


command_test_data = util_load_json('./test_data/command_test_data.json')

client = JSM.Client(base_url='https://url.com', verify=False, proxy=False, api_key='key123')


def test_convert_keys_to_pascal_empty_list():
    """
    Given:
        - An empty list of objects to convert to pascal case.
    When:
        - Calling the convert_keys_to_pascal function.
    Then:
        - The function should return an empty list.
    """
    objects = []
    key_mapping = None
    expected_result = []
    result = JSM.convert_keys_to_pascal(objects, key_mapping)
    assert result == expected_result


def test_convert_keys_to_pascal_list_with_keys():
    """
    Given:
        - A list of objects with keys to convert to pascal case.
    When:
        - Calling the convert_keys_to_pascal function.
    Then:
        - The function should return the list with keys converted to pascal case.
    """
    objects = [
        {"key1": "value1", "key2": "value2"},
        {"key3": "value3", "key4": "value4"},
    ]
    key_mapping = None
    expected_result = [
        {"Key1": "value1", "Key2": "value2"},
        {"Key3": "value3", "Key4": "value4"},
    ]
    result = JSM.convert_keys_to_pascal(objects, key_mapping)
    assert result == expected_result


def test_convert_keys_to_pascal_list_with_keys_and_mapping():
    """
    Given:
        - A list of objects with keys to convert to pascal case.
        - A key mapping to apply to the keys.
    When:
        - Calling the convert_keys_to_pascal function.
    Then:
        - The function should return the list with keys converted to pascal case
          and mapping applied where specified.
    """
    objects = [
        {"key1": "value1", "key2": "value2"},
        {"key3": "value3", "key4": "value4"},
    ]
    key_mapping = {"key1": "MappedKey1", "key4": "MappedKey4"}
    expected_result = [
        {"MappedKey1": "value1", "Key2": "value2"},
        {"Key3": "value3", "MappedKey4": "value4"},
    ]
    result = JSM.convert_keys_to_pascal(objects, key_mapping)
    assert result == expected_result


def test_get_object_readable_outputs():
    objects = [
        {'objectType': {'name': 'typeA'}, 'avatar': 'avatarA', 'id': 123, 'key': 'value'},
        {'objectType': {'name': 'typeB'}, 'avatar': 'avatarB', 'id': 456, 'key': 'value'}
    ]

    expected_output = [{'ID': 123, 'Key': 'value', 'Type': 'typeA'}, {'ID': 456, 'Key': 'value', 'Type': 'typeB'}]
    assert JSM.get_object_readable_outputs(objects) == expected_output


def test_clean_object_attributes_with_type_and_default_type():
    """
    Given:
        - An object with 'id', 'name', 'type', and 'defaultType' fields.
    When:
        - Cleaning the object attributes to match a certain format.
    Then:
        - The cleaned attributes should match the expected format with 'type' replaced by its string representation and
        keys in PascalCase.
    """
    attributes = [{'id': 1, 'name': 'Test', 'type': 0, 'defaultType': {'name': 'Text'}, 'objectType': {'id': 1}}]
    expected = [{'id': 1, 'name': 'Test', 'type': 'Text', 'defaultType': {'name': 'Text'}}]
    result = JSM.clean_object_attributes(attributes)
    assert result == expected


def test_clean_object_attributes_with_type():
    """
    Given:
        - An object with 'id', 'value', and 'type' fields.
    When:
        - Cleaning the object attributes to match a certain format.
    Then:
        - The cleaned attributes should match the expected format with 'type' replaced by its string representation and
        keys in PascalCase.
    """
    attributes = [{'id': 2, 'value': 'Hello', 'type': 1}]
    expected = [{'id': 2, 'value': 'Hello', 'type': 'Object Reference'}]
    result = JSM.clean_object_attributes(attributes)
    assert result == expected


def test_clean_object_attributes_empty():
    """
    Given:
        - An empty list of object attributes.
    When:
        - Cleaning the object attributes to match a certain format.
    Then:
        - The function should return an empty list as no attributes are present to clean.
    """
    attributes = []
    expected = []
    result = JSM.clean_object_attributes(attributes)
    assert result == expected


def test_convert_attributes_multiple_values():
    """
    Given:
        - A dictionary with one attribute having multiple values.
    When:
        - The convert_attributes function is called with the dictionary.
    Then:
        - The function should return a list with a dictionary containing 'objectTypeAttributeId' set to the attribute ID
         and 'objectAttributeValues' as a list of dictionaries with 'value' keys.
    """
    attributes = {"attr1": ["value1", "value2"]}
    expected = [
        {"objectTypeAttributeId": "attr1", "objectAttributeValues": [{"value": "value1"}, {"value": "value2"}]}
    ]
    result = JSM.convert_attributes(attributes)
    assert result == expected


def test_convert_attributes_single_value():
    """
    Given:
        - A dictionary with one attribute having a single value.
    When:
        - The convert_attributes function is called with the dictionary.
    Then:
        - The function should return a list with a dictionary containing 'objectTypeAttributeId' set to the attribute ID
         and 'objectAttributeValues' as a list with a single dictionary with the 'value' key.
    """
    attributes = {"attr2": ["hello"]}
    expected = [
        {"objectTypeAttributeId": "attr2", "objectAttributeValues": [{"value": "hello"}]}
    ]
    result = JSM.convert_attributes(attributes)
    assert result == expected


def test_convert_attributes_empty():
    """
    Given:
        - An empty dictionary of attributes.
    When:
        - The convert_attributes function is called with the dictionary.
    Then:
        - The function should return an empty list as there are no attributes to convert.
    """
    attributes = {}
    expected = []
    result = JSM.convert_attributes(attributes)
    assert result == expected


def test_convert_attributes_empty_values():
    """
    Given: A dictionary with an attribute ID and an empty list of values
    When: The convert_attributes function is called with the dictionary
    Then: The function should return a list with a dictionary containing an empty list for objectAttributeValues
    """
    attributes = {"attr4": []}
    expected = [{"objectTypeAttributeId": "attr4", "objectAttributeValues": []}]
    result = JSM.convert_attributes(attributes)
    assert result == expected


def test_get_attributes_json_data_with_attributes():
    """
    Given: An object type ID and a string representation of attributes
    When: The get_attributes_json_data function is called with the object type ID and attributes
    Then: The function should return a dictionary with the object type ID and converted attributes
    """
    object_type_id = "test_object_type"
    attributes = {"attr1": ["value1", "value2"], "attr2": ["hello"]}
    expected = {
        'objectTypeId': object_type_id,
        'attributes': [
            {'objectTypeAttributeId': 'attr1', 'objectAttributeValues': [{'value': 'value1'}, {'value': 'value2'}]},
            {'objectTypeAttributeId': 'attr2', 'objectAttributeValues': [{'value': 'hello'}]}
        ]
    }
    result = JSM.get_attributes_json_data(object_type_id, attributes=attributes)
    assert result == expected


def test_get_attributes_json_data_with_attributes_json():
    """
    Given: An object type ID and a JSON string representation of attributes
    When: The get_attributes_json_data function is called with the object type ID and attributes_json
    Then: The function should return a dictionary with the object type ID and converted attributes
    """
    object_type_id = "test_object_type"
    attributes_json = (
        '{'
        '"attributes": ['
        '{"objectTypeAttributeId": "attr1", "objectAttributeValues": [{"value": "value1"},{"value": "value2"}]},'
        '{"objectTypeAttributeId": "attr2", "objectAttributeValues": [{"value": "hello"}]}]}'
    )
    expected = {
        'objectTypeId': object_type_id,
        'attributes': [
            {'objectTypeAttributeId': 'attr1', 'objectAttributeValues': [{'value': 'value1'}, {'value': 'value2'}]},
            {'objectTypeAttributeId': 'attr2', 'objectAttributeValues': [{'value': 'hello'}]}
        ]
    }
    result = JSM.get_attributes_json_data(object_type_id, attributes_json=attributes_json)
    assert result == expected


def test_get_attributes_json_data_no_input():
    """
    Given: An object type ID, but no attributes or attributes_json
    When: The get_attributes_json_data function is called without providing attributes or attributes_json
    Then: The function should raise a ValueError
    """
    object_type_id = "test_object_type"
    with pytest.raises(ValueError):
        JSM.get_attributes_json_data(object_type_id)


def test_get_attributes_json_data_both_inputs():
    """
    Given: An object type ID, and both attributes and attributes_json
    When: The get_attributes_json_data function is called with both attributes and attributes_json
    Then: The function should raise a ValueError
    """
    object_type_id = "test_object_type"
    attributes = '{"attr1": ["value1", "value2"]}'
    attributes_json = '{"attributes": [{"attr2": ["hello"]}]}'
    with pytest.raises(ValueError):
        JSM.get_attributes_json_data(object_type_id, attributes=attributes, attributes_json=attributes_json)


def test_parse_object_results_basic():
    """
    Given: An object with multiple fields, but no object type.
    When: The parse_object_results function is called with the object.
    Then: The function should return a dictionary with the object ID and the object name.
    """
    res = {'id': 123, 'name': 'TestObject'}
    expected_output = {
        'outputs': [{'id': 123, 'name': 'TestObject'}],
        'objectId': 123
    }
    assert JSM.parse_object_results(res) == expected_output


def test_parse_object_results_with_object_type():
    """
        Given: An object with multiple fields and an object type.
        When: The parse_object_results function is called with the object.
        Then: The function should return a dict with the object ID and name converted to PascalCase but delete the object type.
    """
    res = {'id': 123, 'name': 'TestObject', 'objectType': 'TestType'}
    expected_output = {
        'outputs': [{'id': 123, 'name': 'TestObject'}],
        'objectId': 123
    }
    assert JSM.parse_object_results(res) == expected_output


def test_parse_object_results_empty():
    """
    Given: An empty object.
    When: The parse_object_results function is called with the object.
    Then: The function should return a dictionary with an empty dictionary for outputs and no ID.
    """
    res = {}
    expected_output = {
        'outputs': [{}],
        'objectId': None
    }
    assert JSM.parse_object_results(res) == expected_output


def test_jira_asset_object_schema_list_command_with_limit(mocker: MockerFixture):
    """
    Given:
        - An args dict with a 'limit' argument.
    When:
        - Calling the jira_asset_object_schema_list_command with the args dict.
    Then:
        - The command returns a limited number of results as specified by the 'limit' argument.
    """
    args = {'limit': '2'}
    expected_len = 2
    mocked_return_value = command_test_data['object_schema_list']['response']
    mocked_client = mocker.patch.object(client, 'get_schema_list', return_value=mocked_return_value)
    command_results = JSM.jira_asset_object_schema_list_command(client, args)
    mocked_client.assert_called()
    assert len(command_results.outputs) == expected_len


def test_jira_asset_object_schema_list_command_all_results(mocker: MockerFixture):
    """
    Given:
        - An args dict with 'all_results' set to 'true'.
    When:
        - Calling the jira_asset_object_schema_list_command with the args dict.
    Then:
        - The command returns all results, ignoring any 'limit' argument.
    """
    args = {'all_results': 'true'}
    expected_len = 3
    mocked_return_value = command_test_data['object_schema_list']['response']
    mocked_client = mocker.patch.object(client, 'get_schema_list', return_value=mocked_return_value)
    command_results = JSM.jira_asset_object_schema_list_command(client, args)
    mocked_client.assert_called()
    assert len(command_results.outputs) == expected_len


def test_jira_asset_object_schema_list_command_all_results_with_limit(mocker: MockerFixture):
    """
    Given:
        - An args dict with 'all_results' set to 'true' and a 'limit' argument.
    When:
        - Calling the jira_asset_object_schema_list_command with the args dict.
    Then:
        - The command returns all results, taking into account the 'limit' only if 'all_results' is false.
    """
    args = {'all_results': 'true', 'limit': 2}
    expected_len = 3
    mocked_return_value = command_test_data['object_schema_list']['response']
    mocked_client = mocker.patch.object(client, 'get_schema_list', return_value=mocked_return_value)
    command_results = JSM.jira_asset_object_schema_list_command(client, args)
    mocked_client.assert_called()
    assert len(command_results.outputs) == expected_len


def test_jira_asset_object_type_list_command_with_limit_2(mocker: MockerFixture):
    """
    Given:
        - An arguments dictionary with 'limit' set to '2' and 'schema_id' set to '1'.
    When:
        - Calling the jira_asset_object_type_list_command with the given arguments.
    Then:
        - The command should return exactly 2 results as specified by the 'limit' argument.
    """
    args = {'limit': '2', 'schema_id': '1'}
    expected_len = 2
    mocked_return_value = command_test_data['object_type_list']['response']
    mocked_client = mocker.patch.object(client, 'get_object_type_list', return_value=mocked_return_value)
    command_results = JSM.jira_asset_object_type_list_command(client, args)
    mocked_client.assert_called_with('1', None)
    assert len(command_results.outputs) == expected_len


def test_jira_asset_object_type_list_command_with_limit_4(mocker: MockerFixture):
    """
    Given:
        - An arguments dictionary with 'limit' set to '4' and 'schema_id' set to '1'.
    When:
        - Calling the jira_asset_object_type_list_command with the given arguments.
    Then:
        - The command should return exactly 4 results as specified by the 'limit' argument.
    """
    args = {'limit': '4', 'schema_id': '1'}
    expected_len = 4
    mocked_return_value = command_test_data['object_type_list']['response']
    mocked_client = mocker.patch.object(client, 'get_object_type_list', return_value=mocked_return_value)
    command_results = JSM.jira_asset_object_type_list_command(client, args)
    mocked_client.assert_called_with('1', None)
    assert len(command_results.outputs) == expected_len


def test_jira_asset_object_type_list_command_all_results(mocker: MockerFixture):
    """
    Given:
        - An arguments dictionary with 'all_results' set to 'true' and 'schema_id' set to '1'.
    When:
        - Calling the jira_asset_object_type_list_command with the given arguments.
    Then:
        - The command should return all available results, ignoring the 'limit' argument.
    """
    args = {'all_results': 'true', 'schema_id': '1'}
    expected_len = 5
    mocked_return_value = command_test_data['object_type_list']['response']
    mocked_client = mocker.patch.object(client, 'get_object_type_list', return_value=mocked_return_value)
    command_results = JSM.jira_asset_object_type_list_command(client, args)
    mocked_client.assert_called_with('1', None)
    assert len(command_results.outputs) == expected_len


def test_jira_asset_object_type_list_command_all_results_with_limit(mocker: MockerFixture):
    """
    Given:
        - An arguments dictionary with 'all_results' set to 'true', a 'limit' of 2, and 'schema_id' set to '1'.
    When:
        - Calling the jira_asset_object_type_list_command with the given arguments.
    Then:
        - The command should return all available results, as 'all_results' takes precedence over the 'limit'.
    """
    args = {'all_results': 'true', 'limit': 2, 'schema_id': '1'}
    expected_len = 5
    mocked_return_value = command_test_data['object_type_list']['response']
    mocked_client = mocker.patch.object(client, 'get_object_type_list', return_value=mocked_return_value)
    command_results = JSM.jira_asset_object_type_list_command(client, args)
    mocked_client.assert_called_with('1', None)
    assert len(command_results.outputs) == expected_len


@pytest.mark.parametrize("args, expected_len", [
    ({'limit': '2', 'object_type_id': '1'}, 2),
    ({'limit': '4', 'object_type_id': '1'}, 4),
    ({'all_results': 'true', 'object_type_id': '1'}, 6),
    ({'all_results': 'true', 'limit': 2, 'object_type_id': '1'}, 6),
])
def test_jira_asset_object_type_attribute_list_command(mocker: MockerFixture, args: dict[str, Any], expected_len: int):
    """
    Given: An args dict with limit and/or all_results
    When: Calling the jira_asset_object_type_list_command with the args dict
    Then: The command returns results, taking into account the limit, only if all_results is false
    """
    mocked_return_value = command_test_data['object_type_attributes']['response']
    mocked_client = mocker.patch.object(client, 'get_object_type_attributes', return_value=mocked_return_value)
    command_results = JSM.jira_asset_object_type_attribute_list_command(client, args)
    assert len(command_results.outputs) == expected_len
    mocked_client.assert_called_with(
        object_type_id=args['object_type_id'],
        order_by_name=False,
        query=None,
        include_value_exist=False,
        exclude_parent_attributes=False,
        include_children=False,
        order_by_required=False
    )


def test_jira_asset_object_create_command(mocker: MockerFixture):
    """
    Given: An object_type_id and a string of attributes
    When: The object_create command is called with said arguments
    Then: The client's create_object function is called with said arguments in the format that the
            get_attributes_json_data function returns
    """
    object_type_id = "1"
    attributes = {"1": ["value1"], "2": ["value1", "value2"]}
    attributes_json_data = JSM.get_attributes_json_data(object_type_id, attributes)
    mocked_client = mocker.patch.object(
        client,
        'create_object',
        return_value=command_test_data['object_create']['response']
    )
    JSM.jira_asset_object_create_command(client, {"object_type_id": object_type_id, "attributes": attributes})
    mocked_client.assert_called_with(attributes_json_data)


def test_jira_asset_object_update_command(mocker: MockerFixture):
    """
    Given: An object_id and a string of attributes
    When: The object_update command is called with said arguments
    Then: The client's update_object function is called with said arguments in the format that the
            get_attributes_json_data function returns
    """
    object_id = "1"
    object_type_id = "3"
    attributes = {"1": ["value1"], "2": ["value1", "value2"]}
    attributes_json_data = JSM.get_attributes_json_data(object_type_id, attributes)
    mocker.patch.object(client, 'get_object', return_value=command_test_data['get_object']['response'])
    mocked_update_object = mocker.patch.object(
        client,
        'update_object',
        return_value=command_test_data['object_update']['response']
    )
    JSM.jira_asset_object_update_command(client, {"object_id": object_id, "attributes": attributes})
    mocked_update_object.assert_called_with(object_id, attributes_json_data)


def test_jira_asset_object_delete_command(mocker: MockerFixture):
    """
    Given: An object id
    When: The jira_asset_object_delete_command function is called
    Then: The client's delete_object function is called with said object id
    """
    object_id = "1"
    mocked_client = mocker.patch.object(client, 'delete_object', return_value={})
    JSM.jira_asset_object_delete_command(client, {"object_id": object_id})
    mocked_client.assert_called_with(object_id)


def test_jira_asset_object_delete_non_exising_object(mocker: MockerFixture):
    """
    Given: A non-existing object id
    When: The client's delete_object function returns None
    Then: The jira_asset_object_delete_command function returns a specific hr response
    """
    object_id = "-1"
    mock_delete = mocker.patch.object(client, 'delete_object', return_value=None)
    command_result = JSM.jira_asset_object_delete_command(client, {"object_id": object_id})
    mock_delete.assert_called_with(object_id)
    assert command_result.readable_output == f'Object with id: {object_id} does not exist'


def test_jira_object_get_command(mocker: MockerFixture):
    """
    Given: An object id
    When: The jira_asset_object_get_command function is called
    Then: The client's get_object function is called with said object id
    """
    object_id = "1"
    mocked_client = mocker.patch.object(client, 'get_object', return_value=command_test_data['get_object']['response'])
    JSM.jira_asset_object_get_command(client, {"object_id": object_id})
    mocked_client.assert_called_with(object_id)


def test_jira_asset_object_get_non_exising_object(mocker: MockerFixture):
    """
    Given: A non-existing object id
    When: The client's get_object function returns None
    Then: The jira_asset_object_get_command function returns a specific hr response
    """
    object_id = "-1"
    mock_delete = mocker.patch.object(client, 'get_object', return_value=None)
    command_result = JSM.jira_asset_object_get_command(client, {"object_id": object_id})
    mock_delete.assert_called_with(object_id)
    assert command_result.readable_output == f'Object with id: {object_id} does not exist'


def test_jira_asset_object_search_command(mocker: MockerFixture):
    """
    Given: A ql_query
    When: The jira_asset_object_search_command function is called
    Then: The client's search_objects function is called with said ql_query, with the default values for the rest of the arguments
    """
    ql_query = 'objectType = SW_engineer'
    mocked_client = mocker.patch.object(
        client,
        'search_objects',
        return_value=command_test_data['search_objects']['response']
    )
    JSM.jira_asset_object_search_command(client, {'ql_query': ql_query})
    mocked_client.assert_called_with(ql_query, False, 1, 50, None)


@pytest.mark.parametrize("args, expected_len", [
    ({'object_type_id': '1'}, 6),
    ({'object_type_id': '1', 'is_required': 'true'}, 4)
])
def test_jira_asset_attribute_json_create_command(mocker: MockerFixture, args, expected_len):
    """
    Given: An args dictionary with the object_type_id and an optional is_required argument
    When: The jira_asset_attribute_json_create_command function is called
    Then: The client's get_object_type_attributes function is called with the right parameters and returns only required objects
            if the is_required argument is set to true
    """
    object_type_id = '1'
    mocked_attributes_response = command_test_data['object_type_attributes']['response']
    mock_attributes_call = mocker.patch.object(client, 'get_object_type_attributes', return_value=mocked_attributes_response)
    command_results = JSM.jira_asset_attribute_json_create_command(client, args)
    mock_attributes_call.assert_called_with(object_type_id=object_type_id, is_editable=False)
    _, command_results = command_results
    os.remove(f"1_{_.get('FileID')}")
    attributes = json.loads(command_results.readable_output).get('attributes')
    assert len(attributes) == expected_len


def test_jira_asset_comment_create_command(mocker: MockerFixture):
    """
    Given: An object id and a comment
    When: The jira_asset_comment_create_command function is called
    Then: The client's create_comment function is called with the object_id and the comment
    """
    object_id = '1'
    comment = 'comment body'
    mocked_client = mocker.patch.object(client, 'create_comment', return_value={'id': 1})
    JSM.jira_asset_comment_create_command(client, {'object_id': object_id, 'comment': comment})
    mocked_client.assert_called_with(object_id, comment)


def test_jira_asset_comment_list_command(mocker: MockerFixture):
    """
    Given: An object id
    When: The jira_asset_comment_list_command function is called
    Then: The client's get_comment_list function is called with the object_id
    """
    object_id = '1'
    mocked_client = mocker.patch.object(client, 'get_comment_list', return_value=[{'id': 1}])
    JSM.jira_asset_comment_list_command(client, {'object_id': object_id})
    mocked_client.assert_called_with(object_id)


def test_jira_asset_connected_ticket_list_command(mocker: MockerFixture):
    """
    Given: An object id
    When: The jira_asset_connected_ticket_list_command function is called
    Then: The client's get_object_connected_tickets function is called with the object_id
    """
    object_id = '1'
    mocked_client = mocker.patch.object(client, 'get_object_connected_tickets', return_value={'tickets': [{'id': 1}]})
    JSM.jira_asset_connected_ticket_list_command(client, {'object_id': object_id})
    mocked_client.assert_called_with(object_id)


def test_jira_asset_attachment_add_command(mocker: MockerFixture):
    object_id = '1'
    entry_id = None
    mocker.patch.object(demisto, 'getFilePath', return_value={'path': 'test_data/test_file.txt'})
    mocked_client = mocker.patch.object(client, 'send_file', return_value=[{'id': 1}])
    JSM.jira_asset_attachment_add_command(client, {'object_id': object_id, 'entry_id': entry_id})
    mocked_client.assert_called_with(object_id=object_id, file_path='test_data/test_file.txt')


def test_jira_asset_attachment_list_command_no_download(mocker: MockerFixture):
    object_id = '1'
    path = f'/attachments/object/{object_id}'
    mocked_client = mocker.patch.object(client, 'get_object_attachment_list', return_value=[{'id': 1}])
    JSM.jira_asset_attachment_list_command(client, {'object_id': object_id, 'download_file': 'false'})
    mocked_client.assert_called_with(path)


def test_jira_asset_attachment_list_command_with_download(mocker: MockerFixture):
    object_id = '1'
    file_list = command_test_data['attachment_list']['response']
    path = f'/attachments/object/{object_id}'
    mocked_client = mocker.patch.object(client, 'get_object_attachment_list', return_value=file_list)
    mocker.patch.object(client, 'get_file', return_value=Mock(content=b'file content'))
    mocker.patch('os.remove')
    mocker.patch('builtins.open', mocker.mock_open())
    mocker.patch('zipfile.ZipFile')
    result = JSM.jira_asset_attachment_list_command(client, {'object_id': object_id, 'download_file': 'true'})

    mocked_client.assert_called_with(path)
    assert isinstance(result, list)
    assert isinstance(result[0], dict)  # fileResult returns a dict
    assert result[0]['File'] == 'ObjectAttachments.zip'
    assert isinstance(result[1], CommandResults)


def test_jira_asset_attachment_remove_command(mocker: MockerFixture):
    file_id = '1'
    mocked_client = mocker.patch.object(client, 'remove_file', return_value={'id': 1})
    JSM.jira_asset_attachment_remove_command(client, {'id': file_id})
    mocked_client.assert_called_with(file_id)
