import pytest
from pytest_mock import MockerFixture
from typing import Any
import AtlassianJiraServiceManagement as JSM
import json


def util_load_json(path):
    with open(path, encoding='utf-8') as f:
        return json.loads(f.read())

command_test_data = util_load_json('./test_data/command_test_data.json')

client = JSM.Client(base_url='https://url.com', verify=False, proxy=False, api_key='key123')

@pytest.mark.parametrize(
    "objects, key_mapping, expected_result",
    [
        ([], None, []),
        (
            [
                {"key1": "value1", "key2": "value2"},
                {"key3": "value3", "key4": "value4"},
            ],
            None,
            [
                {"Key1": "value1", "Key2": "value2"},
                {"Key3": "value3", "Key4": "value4"},
            ],
        ),
        (
            [
                {"key1": "value1", "key2": "value2"},
                {"key3": "value3", "key4": "value4"},
            ],
            {"key1": "MappedKey1", "key4": "MappedKey4"},
            [
                {"MappedKey1": "value1", "Key2": "value2"},
                {"Key3": "value3", "MappedKey4": "value4"},
            ],
        ),
    ],
)
def test_convert_keys_to_pascal(objects, key_mapping, expected_result):
    result = JSM.convert_keys_to_pascal(objects, key_mapping)
    assert result == expected_result


@pytest.mark.parametrize(
    "input_str, expected_output",
    [
        ("snake_case", "SnakeCase"),
        ("camelCase", "CamelCase"),
        ("PascalCase", "PascalCase"),
        ("UPPERCASE", "UPPERCASE"),
        ("mixed_Case", "MixedCase"),
    ],
)
def test_pascal_case(input_str, expected_output):
    assert JSM.pascal_case(input_str) == expected_output


def test_get_object_outputs():
    objects = [
                {'ObjectType': {'name': 'typeA'}, 'Avatar': 'avatarA', 'ID': 123, 'key': 'value'},
                {'ObjectType': {'name': 'typeB'}, 'Avatar': 'avatarB', 'ID': 456, 'key': 'value'}
            ]

    expected_output = (
                [{'ID': 123, 'key': 'value'},{'ID': 456, 'key': 'value'}],
                [{'Type': 'typeA', 'ID': 123, 'key': 'value'}, {'Type': 'typeB', 'ID': 456, 'key': 'value'}],
            )
    assert JSM.get_object_outputs(objects) == expected_output


@pytest.mark.parametrize("attributes, expected", [
    ([{'id': 1, 'name': 'Test', 'type': 0, 'defaultType': {'name': 'Text'}}], [{'ID': 1, 'Name': 'Test', 'Type': 'Text'}]),
    ([{'id': 2, 'value': 'Hello', 'type': 1}], [{'ID': 2, 'Value': 'Hello', 'Type': 'Object Reference'}]),
    ([], []),
])
def test_clean_object_attributes(attributes, expected):
    result = JSM.clean_object_attributes(attributes)
    assert result == expected


@pytest.mark.parametrize("attributes, expected", [
    ({"attr1": ["value1", "value2"]}, [{"objectTypeAttributeId": "attr1", "objectAttributeValues": [{"value": "value1"}, {"value": "value2"}]}]),
    ({"attr2": ["hello"]}, [{"objectTypeAttributeId": "attr2", "objectAttributeValues": [{"value": "hello"}]}]),
    ({}, []),
])
def test_convert_attributes(attributes, expected):
    """
    Given: A dictionary of attribute IDs and their corresponding values
    When: The convert_attributes function is called with the dictionary
    Then: The function should return a list of dictionaries with the correct structure
    """
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
    attributes = '{"attr1": ["value1", "value2"], "attr2": ["hello"]}'
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
    Then: The function should return a dictionary with the object ID and the object name converted to PascalCase.
    """
    res = {'id': 123, 'name': 'TestObject'}
    expected_output = {
        'outputs': [{'ID': 123, 'Name': 'TestObject'}],
        'objectId': 123
    }
    assert JSM.parse_object_results(res) == expected_output


def test_parse_object_results_with_object_type():
    """
        Given: An object with multiple fields and an object type.
        When: The parse_object_results function is called with the object.
        Then: The function should return a dict with the object ID and name converted to PascalCase but delete the object type.
    """
    res = {'id': 123, 'name': 'TestObject', 'ObjectType': 'TestType'}
    expected_output = {
        'outputs': [{'ID': 123, 'Name': 'TestObject'}],
        'objectId': 123
    }
    assert JSM.parse_object_results(res) == expected_output


def test_parse_object_results_no_id():
    """
    Given: An object with no ID field.
    When: The parse_object_results function is called with the object.
    Then: The function should return a dictionary with the object name converted to PascalCase and no ID.
    """
    res = {'name': 'TestObject'}
    expected_output = {
        'outputs': [{'Name': 'TestObject'}],
        'objectId': None
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


@pytest.mark.parametrize("args, expected_len", [
    ({'limit': '2'}, 2),
    ({'all_results': 'true'}, 3),
    ({'all_results': 'true', 'limit': 2}, 3),
])
def test_jira_asset_object_schema_list_command(mocker: MockerFixture, args: dict[str, Any], expected_len: int):
    """
    Given: An args dict with limit and/or all_results
    When: Calling the jira_asset_object_schema_list_command with the args dict
    Then: The command returns results, taking into account the limit, only if all_results is fault
    """
    mocked_return_value = command_test_data['object_schema_list']['response']
    mocked_client = mocker.patch.object(client, 'get_schema_list', return_value=mocked_return_value)
    command_results = JSM.jira_asset_object_schema_list_command(client, args)
    mocked_client.assert_called()
    assert len(command_results.outputs) == expected_len


@pytest.mark.parametrize("args, expected_len", [
    ({'limit': '2', 'schema_id': '1'}, 2),
    ({'limit': '4', 'schema_id': '1'}, 4),
    ({'all_results': 'true', 'schema_id': '1'}, 5),
    ({'all_results': 'true', 'limit': 2, 'schema_id': '1'}, 5),
])
def test_jira_asset_object_type_list_command(mocker: MockerFixture, args: dict[str,Any], expected_len: int):
    """
    Given: An args dict with limit and/or all_results
    When: Calling the jira_asset_object_type_list_command with the args dict
    Then: The command returns results, taking into account the limit, only if all_results is fault
    """
    mocked_return_value = command_test_data['object_type_list']['response']
    mocked_client = mocker.patch.object(client, 'get_object_type_list', return_value=mocked_return_value)
    command_results = JSM.jira_asset_object_type_list_command(client, args)
    mocked_client.assert_called_with(args['schema_id'], None, None)
    assert len(command_results.outputs) == expected_len


@pytest.mark.parametrize("args, expected_len", [
    ({'limit': '2', 'object_type_id': '1'}, 2),
    ({'limit': '4', 'object_type_id': '1'}, 4),
    ({'all_results': 'true', 'object_type_id': '1'}, 6),
    ({'all_results': 'true', 'limit': 2, 'object_type_id': '1'}, 6),
])
def test_jira_asset_object_type_attribute_list_command(mocker: MockerFixture, args: dict[str,Any], expected_len: int):
    """
    Given: An args dict with limit and/or all_results
    When: Calling the jira_asset_object_type_list_command with the args dict
    Then: The command returns results, taking into account the limit, only if all_results is fault
    """
    mocked_return_value = command_test_data['object_type_attributes']['response']
    mocked_client = mocker.patch.object(client, 'get_object_type_attributes', return_value=mocked_return_value)
    command_results = JSM.jira_asset_object_type_attribute_list_command(client, args)
    mocked_client.assert_called_with(object_type_id=args['object_type_id'], order_by_name=False, query=None, include_value_exist=False, exclude_parent_attributes=False, include_children=False, order_by_required=False)
    assert len(command_results.outputs) == expected_len

