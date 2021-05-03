import json
import io
import HPEArubaClearpass
from HPEArubaClearpass import *
from freezegun import freeze_time
import pytest

CLIENT_ID = "id123"
CLIENT_SECRET = "secret123"
CLIENT_AUTH = \
    {
        "access_token": "auth123",
        "expires_in": 28800,
        "token_type": "Bearer",
        "scope": None
    }
NEW_ACCESS_TOKEN = "new123"

TEST_LOGIN_LIST = \
    [
        ({}, "auth123"),  # no integration context, should generate new access token
        ({"access_token": "old123", "expires_in": "2021-05-03T12:00:00Z"},  # access token valid
         "old123"),
        ({"access_token": "old123", "expires_in": "2021-05-03T10:00:00Z"},  # access token expired
         "auth123"),
    ]


def util_load_json(path):
    with io.open(path, mode='r', encoding='utf-8') as f:
        return json.loads(f.read())


def create_client(proxy: bool = False, verify: bool = False, base_url: str = "https://example.com/api/"
                  , client_id: str = CLIENT_ID, client_secret: str = CLIENT_SECRET):
    return HPEArubaClearpass.Client(proxy=proxy, verify=verify, base_url=base_url, client_id=client_id,
                                    client_secret=client_secret)


@pytest.mark.parametrize('integration_context, expected_token', TEST_LOGIN_LIST)
@freeze_time("2021-05-03T11:00:00Z")
def test_login(mocker, integration_context, expected_token):
    """
    Given:
    - Integration context which includes access token and it's expiration time.

    When:
    - Calling any command.

    Then:
    - Ensures that access token exists and is not expired.
    - Ensures that if access token is expired, a new one is generated.
    """
    client = create_client()
    mocker.patch.object(HPEArubaClearpass, "get_integration_context", return_value=integration_context)
    mocker.patch.object(client, "generate_new_access_token", return_value=CLIENT_AUTH)
    client.login()
    assert client.access_token == expected_token


def test_get_endpoints_list_command(mocker):
    """
    Given:
    - This command has no mandatory args.

    When:
    - Calling that command in order to get list of endpoints.

    Then:
    - Ensures that command outputs are valid.
    """
    client = create_client()
    mock_endpoints_response = util_load_json("test_data/endpoints_list_response.json")
    mocker.patch.object(client, "prepare_request", return_value=mock_endpoints_response)
    results = get_endpoints_list_command(client, {})
    assert results.outputs_prefix == "HPEArubaClearpass.endpoints.list"
    assert results.outputs_key_field == "id"
    assert results.outputs[0]['id'] == 1
    assert results.outputs[1]['id'] == 2
    assert results.outputs[0]['mac_address'] == '001234567891'
    assert results.outputs[1]['mac_address'] == '001234567892'


def test_update_endpoint_command(mocker):
    """
    Given:
    - Arguments to set the new endpoint with.

    When:
    - Calling that command in order to create a new endpoint.

    Then:
    - Ensures that new endpoint has the required fields.
    """
    client = create_client()
    mock_endpoint_response = util_load_json("test_data/update_endpoint_response.json")
    mocker.patch.object(client, "prepare_request", return_value=mock_endpoint_response)
    args = {"id": '1', "mac_address": "123456789", "description": "test1", "status": "Unknown"}
    results = update_endpoint_command(client, args)
    assert results.outputs_prefix == "HPEArubaClearpass.endpoints.update"
    assert results.outputs_key_field == "id"
    assert results.outputs['ID'] == 1
    assert results.outputs['MAC Address'] == '123456789'
    assert results.outputs['Description'] == 'test1'
    assert results.outputs['Status'] == 'Unknown'


def test_get_attributes_list_command(mocker):
    """
    Given:
    - This command has no mandatory args.

    When:
    - Calling that command in order to get list of attributes.

    Then:
    - Ensures that command outputs are valid.
    """
    client = create_client()
    mock_attributes_response = util_load_json("test_data/attributes_list_response.json")
    mocker.patch.object(client, "prepare_request", return_value=mock_attributes_response)
    results = get_attributes_list_command(client, {})
    assert results.outputs_prefix == "HPEArubaClearpass.attributes.list"
    assert results.outputs_key_field == "id"
    assert results.outputs[0]['id'] == 1
    assert results.outputs[0]['name'] == 'Controller Id'
    assert results.outputs[0]['entity_name'] == 'Device'
    assert results.outputs[0]['data_type'] == 'String'
    assert results.outputs[0]['mandatory'] is False
    assert results.outputs[0]['allow_multiple'] is True


def test_create_attribute_command(mocker):
    """
    Given:
    - Arguments to set the new attribute with.

    When:
    - Calling that command in order to create a new attribute.

    Then:
    - Ensures that new attribute has the required fields.
    """
    client = create_client()
    mock_endpoint_response = util_load_json("test_data/create_attribute_response.json")
    mocker.patch.object(client, "prepare_request", return_value=mock_endpoint_response)
    args = {"data_type": "Boolean", "name": "new123", "entity_name": "Device"}
    results = create_attribute_command(client, args)
    assert results.outputs_prefix == "HPEArubaClearpass.attributes.create"
    assert results.outputs_key_field == "id"
    assert results.outputs['ID'] == 1
    assert results.outputs['Name'] == args.get('name')
    assert results.outputs['Entity name'] == args.get('entity_name')
    assert results.outputs['Data type'] == args.get('data_type')
    assert results.outputs['Mandatory'] is False
    assert results.outputs['Allow multiple'] is False


def test_update_attribute_command(mocker):
    """
    Given:
    - Arguments to update an attribute with.

    When:
    - Calling that command in order to update fields of an attribute.

    Then:
    - Ensures that the attribute fields were updated as required.
    """
    client = create_client()
    mock_endpoint_response = util_load_json("test_data/create_attribute_response.json")
    mocker.patch.object(client, "prepare_request", return_value=mock_endpoint_response)
    args = {"attribute_id": "1", "data_type": "Boolean", "name": "new123", "entity_name": "Device"}
    results = update_attribute_command(client, args)
    assert results.outputs_prefix == "HPEArubaClearpass.attributes.update"
    assert results.outputs_key_field == "id"
    assert results.outputs['ID'] == 1
    assert results.outputs['Name'] == args.get('name')
    assert results.outputs['Entity name'] == args.get('entity_name')
    assert results.outputs['Data type'] == args.get('data_type')
    assert results.outputs['Mandatory'] is False
    assert results.outputs['Allow multiple'] is False


def test_delete_attribute_command(mocker):
    """
    Given:
    - Attribute id to be deleted

    When:
    - Calling that command in order to delete an attribute.

    Then:
    - Ensures that the attribute was deleted successfully.
    """
    client = create_client()
    args = {"attribute_id": "1"}
    mocker.patch.object(client, "prepare_request")
    results = delete_attribute_command(client, args)
    human_readable = f"HPE Aruba Clearpass attribute with ID: {args.get('attribute_id')} deleted successfully."
    assert results.readable_output == human_readable
