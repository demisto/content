import json
import os

import CiscoUmbrellaCloudSecurityv2
import CommonServerPython
import pytest

TEST_DATA = 'test_data'
DESTINATION_ENDPOINT = CommonServerPython.urljoin(
    CiscoUmbrellaCloudSecurityv2.BASE_URL,
    CiscoUmbrellaCloudSecurityv2.Client.DESTINATION_LIST_ENDPOINT,
)


def load_mock_response(file_name: str) -> str:
    """
    Load mock file that simulates an API response.
    Args:
        file_name (str): Name of the mock response JSON file to return.
    Returns:
        str: Mock file content.
    """
    file_path = os.path.join(TEST_DATA, file_name)

    with open(file_path, encoding='utf-8') as mock_file:
        return json.loads(mock_file.read())


@pytest.fixture()
def mock_client(requests_mock) -> CiscoUmbrellaCloudSecurityv2.Client:
    """
    Establish a mock connection to the client with a username and password.

    Returns:
        Client: Mock connection to client.
    """
    requests_mock.post(
        url=f'{CiscoUmbrellaCloudSecurityv2.BASE_URL}/auth/v2/token',
        json={
            'access_token': 'Pichu',
        },
    )

    return CiscoUmbrellaCloudSecurityv2.Client(
        base_url=CiscoUmbrellaCloudSecurityv2.BASE_URL,
        api_key='Pikachu',
        api_secret='Riachu',
    )


def test_list_destinations_command(requests_mock, mock_client):
    """
    Scenario:
    - Test listing destinations of a destination list

    Given:
    - A destination list ID

    When:
    - list_destinations_command

    Then:
    - Ensure that the CommandResults outputs_prefix is correct.
    - Ensure that the CommandResults outputs_key_field is correct.
    - Ensure that the CommandResults outputs is correct.
    - Ensure that the CommandResults raw_response is correct.
    """
    args = {
        'destination_list_id': '123',
    }
    response = load_mock_response('destinations.json')
    url = CommonServerPython.urljoin(DESTINATION_ENDPOINT, f'{args["destination_list_id"]}/destinations')

    requests_mock.get(url=url, json=response)

    command_results: CommonServerPython.CommandResults = CiscoUmbrellaCloudSecurityv2.list_destinations_command(
        mock_client, args
    )

    assert command_results.outputs_prefix == (
        f'{CiscoUmbrellaCloudSecurityv2.INTEGRATION_OUTPUT_PREFIX}.'
        f'{CiscoUmbrellaCloudSecurityv2.DESTINATION_OUTPUT_PREFIX}'
    )
    assert command_results.outputs_key_field == CiscoUmbrellaCloudSecurityv2.ID_OUTPUTS_KEY_FIELD
    assert command_results.outputs == response['data']
    assert command_results.raw_response == response


def test_list_destinations_command_fetch_destinations(requests_mock, mock_client):
    """
    Scenario:
    - Test fetching destinations of a destination list

    Given:
    - A destination list ID

    When:
    - list_destinations_command

    Then:
    - Ensure that the CommandResults outputs_prefix is correct.
    - Ensure that the CommandResults outputs_key_field is correct.
    - Ensure that the CommandResults outputs is correct.
    - Ensure that the CommandResults raw_response is correct.
    """
    args = {
        'destination_list_id': '123',
        'destinations': ['www.LiorSB.com', '1.1.1.1'],
        'destination_ids': ['111', '333'],
    }
    response = load_mock_response('destinations.json')
    url = CommonServerPython.urljoin(DESTINATION_ENDPOINT, f'{args["destination_list_id"]}/destinations')

    requests_mock.get(url=url, json=response)

    command_results: CommonServerPython.CommandResults = CiscoUmbrellaCloudSecurityv2.list_destinations_command(
        mock_client, args
    )

    data = response['data']
    expected_outputs = [data[0], data[2], data[3]]

    assert command_results.outputs_prefix == (
        f'{CiscoUmbrellaCloudSecurityv2.INTEGRATION_OUTPUT_PREFIX}.'
        f'{CiscoUmbrellaCloudSecurityv2.DESTINATION_OUTPUT_PREFIX}'
    )
    assert command_results.outputs_key_field == CiscoUmbrellaCloudSecurityv2.ID_OUTPUTS_KEY_FIELD
    assert command_results.outputs == expected_outputs
    assert command_results.raw_response == response


def test_add_destinations_command(requests_mock, mock_client):
    """
    Scenario:
    - Test adding destinations to a destination list

    Given:
    - A destination list ID and destinations

    When:
    - add_destinations_command

    Then:
    - Ensure that the CommandResults raw_response is correct.
    - Ensure that the CommandResults readable_output is correct.
    """
    args = {
        'destination_list_id': '123',
        'destinations': ['1.1.1.1', '0.0.0.0'],
        'comment': 'Lior is watching',
    }
    response = load_mock_response('destination_list.json')
    url = CommonServerPython.urljoin(DESTINATION_ENDPOINT, f'{args["destination_list_id"]}/destinations')

    requests_mock.post(url=url, json=response)

    command_results: CommonServerPython.CommandResults = CiscoUmbrellaCloudSecurityv2.add_destination_command(
        mock_client, args
    )

    expected_readable_output = (
        f'The destination(s) "{args["destinations"]}" '
        f'were successfully added to the destination list "{args["destination_list_id"]}"'
    )

    assert command_results.readable_output == expected_readable_output
    assert command_results.raw_response == response


def test_delete_destination_command(requests_mock, mock_client):
    """
    Scenario:
    - Test deleting destinations from a destination list

    Given:
    - A destination list ID and destination IDs

    When:
    - delete_destination_command

    Then:
    - Ensure that the CommandResults readable_output is correct.
    - Ensure that the CommandResults raw_response is correct.
    """
    args = {
        'destination_list_id': '123',
        'destination_ids': [111, 222, 333],
    }
    response = load_mock_response('destination_list.json')
    url = CommonServerPython.urljoin(DESTINATION_ENDPOINT, f'{args["destination_list_id"]}/destinations')

    requests_mock.delete(url=f'{url}/remove', json=response)

    command_results: CommonServerPython.CommandResults = CiscoUmbrellaCloudSecurityv2.delete_destination_command(
        mock_client, args
    )

    expected_readable_output = (
        f'The destination(s) "{args["destination_ids"]}" '
        f'were successfully removed from the destination list "{args["destination_list_id"]}"'
    )

    assert command_results.readable_output == expected_readable_output
    assert command_results.raw_response == response


def test_list_destination_lists_command(requests_mock, mock_client):
    """
    Scenario:
    - Test listing a specific destination list

    Given:
    - A destination list ID

    When:
    - list_destination_lists_command

    Then:
    - Ensure that the CommandResults outputs_prefix is correct.
    - Ensure that the CommandResults outputs_key_field is correct.
    - Ensure that the CommandResults outputs is correct.
    - Ensure that the CommandResults raw_response is correct.
    """
    args = {
        'destination_list_id': '12345',
    }
    response = load_mock_response('destination_list.json')
    url = CommonServerPython.urljoin(DESTINATION_ENDPOINT, args['destination_list_id'])
    requests_mock.get(url=url, json=response)

    command_results: CommonServerPython.CommandResults = CiscoUmbrellaCloudSecurityv2.list_destination_lists_command(
        mock_client, args
    )

    assert command_results.outputs_prefix == (
        f'{CiscoUmbrellaCloudSecurityv2.INTEGRATION_OUTPUT_PREFIX}.'
        f'{CiscoUmbrellaCloudSecurityv2.DESTINATION_LIST_OUTPUT_PREFIX}'
    )
    assert command_results.outputs_key_field == CiscoUmbrellaCloudSecurityv2.ID_OUTPUTS_KEY_FIELD
    assert command_results.outputs == response['data']
    assert command_results.raw_response == response


def test_list_destination_lists_command_list_request(requests_mock, mock_client):
    """
    Scenario:
    - Test listing destination lists

    Given:
    - Nothing

    When:
    - list_destination_lists_command

    Then:
    - Ensure that the CommandResults outputs_prefix is correct.
    - Ensure that the CommandResults outputs_key_field is correct.
    - Ensure that the CommandResults outputs is correct.
    - Ensure that the CommandResults raw_response is correct.
    """
    response = load_mock_response('destination_lists.json')
    requests_mock.get(url=DESTINATION_ENDPOINT, json=response)

    command_results: CommonServerPython.CommandResults = CiscoUmbrellaCloudSecurityv2.list_destination_lists_command(
        mock_client, {}
    )

    assert command_results.outputs_prefix == (
        f'{CiscoUmbrellaCloudSecurityv2.INTEGRATION_OUTPUT_PREFIX}.'
        f'{CiscoUmbrellaCloudSecurityv2.DESTINATION_LIST_OUTPUT_PREFIX}'
    )
    assert command_results.outputs_key_field == CiscoUmbrellaCloudSecurityv2.ID_OUTPUTS_KEY_FIELD
    assert command_results.outputs == response['data']
    assert command_results.raw_response == response


def test_create_destination_list_command(requests_mock, mock_client):
    """
    Scenario:
    - Test creating a destination list

    Given:
    - Name, access, is_global, bundle_type, destinations, destinations_comment
        for a new destination list

    When:
    - create_destination_list_command

    Then:
    - Ensure that the CommandResults outputs_prefix is correct.
    - Ensure that the CommandResults outputs_key_field is correct.
    - Ensure that the CommandResults outputs is correct.
    - Ensure that the CommandResults raw_response is correct.
    """
    args = {
        'name': 'Lior chose Pikachu',
        'access': CiscoUmbrellaCloudSecurityv2.Access.ALLOW.value,
        'is_global': 'false',
        'bundle_type': 'DNS',
        'destinations': ['1.1.1.1', '0.0.0.0'],
        'destinations_comment': 'Comment',
    }
    response = load_mock_response('destination_list.json')['data']

    requests_mock.post(url=DESTINATION_ENDPOINT, json=response)

    command_results: CommonServerPython.CommandResults = CiscoUmbrellaCloudSecurityv2.create_destination_list_command(
        mock_client, args
    )

    assert command_results.outputs_prefix == (
        f'{CiscoUmbrellaCloudSecurityv2.INTEGRATION_OUTPUT_PREFIX}.'
        f'{CiscoUmbrellaCloudSecurityv2.DESTINATION_LIST_OUTPUT_PREFIX}'
    )
    assert command_results.outputs_key_field == CiscoUmbrellaCloudSecurityv2.ID_OUTPUTS_KEY_FIELD
    assert command_results.outputs == response
    assert command_results.raw_response == response


def test_update_destination_list_command(requests_mock, mock_client):
    """
    Scenario:
    - Test updating a destination list

    Given:
    - A destination list ID and a new name

    When:
    - update_destination_list_command

    Then:
    - Ensure that the CommandResults outputs_prefix is correct.
    - Ensure that the CommandResults outputs_key_field is correct.
    - Ensure that the CommandResults outputs is correct.
    - Ensure that the CommandResults raw_response is correct.
    """
    args = {
        'destination_list_id': '123',
        'name': 'Lior Sabri',
    }
    response = load_mock_response('destination_list.json')
    url = CommonServerPython.urljoin(DESTINATION_ENDPOINT, args['destination_list_id'])

    requests_mock.patch(url=url, json=response)

    command_results: CommonServerPython.CommandResults = CiscoUmbrellaCloudSecurityv2.update_destination_list_command(
        mock_client, args
    )

    assert command_results.outputs_prefix == (
        f'{CiscoUmbrellaCloudSecurityv2.INTEGRATION_OUTPUT_PREFIX}.'
        f'{CiscoUmbrellaCloudSecurityv2.DESTINATION_LIST_OUTPUT_PREFIX}'
    )
    assert command_results.outputs_key_field == CiscoUmbrellaCloudSecurityv2.ID_OUTPUTS_KEY_FIELD
    assert command_results.outputs == response['data']
    assert command_results.raw_response == response


def test_delete_destination_list_command(requests_mock, mock_client):
    """
    Scenario:
    - Test deleting a destination list

    Given:
    - A destination list ID

    When:
    - delete_destination_list_command

    Then:
    - Ensure that the CommandResults readable_output is correct.
    - Ensure that the CommandResults raw_response is correct.
    """
    args = {
        'destination_list_id': '123',
    }
    response = load_mock_response('delete.json')

    url = CommonServerPython.urljoin(DESTINATION_ENDPOINT, args['destination_list_id'])

    requests_mock.delete(url=url, json=response)

    command_results: CommonServerPython.CommandResults = CiscoUmbrellaCloudSecurityv2.delete_destination_list_command(
        mock_client, args
    )

    expected_readable_output = f'The destination list "{args["destination_list_id"]}" was successfully deleted'

    assert command_results.readable_output == expected_readable_output
    assert command_results.raw_response == response
