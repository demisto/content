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


def create_client(mocker, proxy: bool = False, verify: bool = False, base_url: str = "https://example.com/api/",
                  client_id: str = CLIENT_ID, client_secret: str = CLIENT_SECRET):
    mocker.patch.object(HPEArubaClearpass.Client, 'login')
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
    mocker.patch.object(HPEArubaClearpass, "get_integration_context", return_value=integration_context)
    mocker.patch.object(HPEArubaClearpass.Client, "generate_new_access_token", return_value=CLIENT_AUTH)
    client = HPEArubaClearpass.Client(proxy=False, verify=False, base_url="https://example.com/api/",
                                      client_id=CLIENT_ID, client_secret=CLIENT_SECRET)
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
    client = create_client(mocker)
    mock_endpoints_response = util_load_json("test_data/endpoints_list_response.json")
    mocker.patch.object(client, "prepare_request", return_value=mock_endpoints_response)
    results = get_endpoints_list_command(client, {})
    assert results.outputs_prefix == "HPEArubaClearpass.endpoints"
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
    client = create_client(mocker)
    mock_endpoint_response = util_load_json("test_data/update_endpoint_response.json")
    mocker.patch.object(client, "prepare_request", return_value=mock_endpoint_response)
    args = {"endpoint_id": '1', "mac_address": "123456789", "description": "test1", "status": "Unknown"}
    results = update_endpoint_command(client, args)
    assert results.outputs_prefix == "HPEArubaClearpass.endpoints"
    assert results.outputs_key_field == "id"
    assert results.outputs['id'] == 1
    assert results.outputs['mac_address'] == '123456789'
    assert results.outputs['description'] == 'test1'
    assert results.outputs['status'] == 'Unknown'


def test_get_attributes_list_command(mocker):
    """
    Given:
    - This command has no mandatory args.

    When:
    - Calling that command in order to get list of attributes.

    Then:
    - Ensures that command outputs are valid.
    """
    client = create_client(mocker)
    mock_attributes_response = util_load_json("test_data/attributes_list_response.json")
    mocker.patch.object(client, "prepare_request", return_value=mock_attributes_response)
    results = get_attributes_list_command(client, {})
    assert results.outputs_prefix == "HPEArubaClearpass.attributes"
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
    client = create_client(mocker)
    mock_endpoint_response = util_load_json("test_data/create_attribute_response.json")
    mocker.patch.object(client, "prepare_request", return_value=mock_endpoint_response)
    args = {"data_type": "Boolean", "name": "new123", "entity_name": "Device"}
    results = create_attribute_command(client, args)
    assert results.outputs_prefix == "HPEArubaClearpass.attributes"
    assert results.outputs_key_field == "id"
    assert results.outputs['id'] == 1
    assert results.outputs['name'] == args.get('name')
    assert results.outputs['entity_name'] == args.get('entity_name')
    assert results.outputs['data_type'] == args.get('data_type')
    assert results.outputs['mandatory'] is False
    assert results.outputs['allow_multiple'] is False


def test_update_attribute_command(mocker):
    """
    Given:
    - Arguments to update an attribute with.

    When:
    - Calling that command in order to update fields of an attribute.

    Then:
    - Ensures that the attribute fields were updated as required.
    """
    client = create_client(mocker)
    mock_endpoint_response = util_load_json("test_data/create_attribute_response.json")
    mocker.patch.object(client, "prepare_request", return_value=mock_endpoint_response)
    args = {"attribute_id": "1", "data_type": "Boolean", "name": "new123", "entity_name": "Device"}
    results = update_attribute_command(client, args)
    assert results.outputs_prefix == "HPEArubaClearpass.attributes"
    assert results.outputs_key_field == "id"
    assert results.outputs['id'] == 1
    assert results.outputs['name'] == args.get('name')
    assert results.outputs['entity_name'] == args.get('entity_name')
    assert results.outputs['data_type'] == args.get('data_type')
    assert results.outputs['mandatory'] is False
    assert results.outputs['allow_multiple'] is False


def test_delete_attribute_command(mocker):
    """
    Given:
    - Attribute id to be deleted

    When:
    - Calling that command in order to delete an attribute.

    Then:
    - Ensures that the attribute was deleted successfully.
    """
    client = create_client(mocker)
    args = {"attribute_id": "1"}
    mocker.patch.object(client, "prepare_request")
    results = delete_attribute_command(client, args)
    human_readable = f"HPE Aruba Clearpass attribute with ID: {args.get('attribute_id')} deleted successfully."
    assert results.readable_output == human_readable


def test_get_active_sessions_list_command(mocker):
    """
    Given:
    - This command has no mandatory args.

    When:
    - Calling that command in order to get list of active sessions.

    Then:
    - Ensures that command outputs are valid.
    """
    client = create_client(mocker)
    mock_sessions_response = util_load_json("test_data/active_sessions_list_response.json")
    mocker.patch.object(client, "prepare_request", return_value=mock_sessions_response)
    results = get_active_sessions_list_command(client, {})
    assert results.outputs_prefix == "HPEArubaClearpass.sessions"
    assert results.outputs_key_field == "id"
    assert results.outputs[0]['ID'] == 1
    assert results.outputs[0]['Device_IP'] == "1.2.3.4"
    assert results.outputs[0]['Device_mac_address'] == "001234567891"
    assert results.outputs[0]['State'] == "active"
    assert results.outputs[0]['Visitor_phone'] == "+972512345678"


def test_disconnect_active_session_command(mocker):
    """
    Given:
    - Active session id to be disconnected.

    When:
    - Calling that command in order to disconnect an active session.

    Then:
    - Ensures that the attribute session disconnected successfully.
    """
    client = create_client(mocker)
    mock_sessions_response = util_load_json("test_data/disconnect_active_session_response.json")
    mocker.patch.object(client, "prepare_request", return_value=mock_sessions_response)
    results = disconnect_active_session_command(client, {'session_id': 1})
    assert results.outputs_prefix == "HPEArubaClearpass.sessions"
    assert results.outputs_key_field == "id"
    assert results.outputs['Error_code'] == 0
    assert results.outputs['Response_message'] == "Success"
