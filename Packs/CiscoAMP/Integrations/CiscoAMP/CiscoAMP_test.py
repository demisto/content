"""
Unit testing for CiscoAMP (Advanced Malware Protection)
"""
import json
import io
import os
from typing import Dict, List, Any
import pytest
from CiscoAMP import Client

API_KEY = 'API_Key'
CLIENT_ID = 'Client_ID'
SERVER_URL = 'https://api.eu.amp.cisco.com'
BASE_URL = f'{SERVER_URL}/{Client.API_VERSION}'


def assert_output_has_no_links(outputs: List[Dict]):
    """
    Check that there are no 'links' keys in the outputs.

    Args:
        outputs (List[Dict, str]): output to loop through.
    """
    for output in outputs:
        assert 'links' not in output


def load_mock_response(file_name: str) -> str | io.TextIOWrapper:
    """
    Load mock file that simulates an API response.
    Args:
        file_name (str): Name of the mock response JSON file to return.
    Returns:
        str: Mock file content.
    """
    path = os.path.join('test_data', file_name)

    with io.open(path, mode='r', encoding='utf-8') as mock_file:
        if os.path.splitext(file_name)[1] == '.json':
            return json.loads(mock_file.read())

        return mock_file


@pytest.fixture(autouse=True)
def mock_client() -> Client:
    """
    Establish a connection to the client with a URL and API key.

    Returns:
        Client: Connection to client.
    """
    from CommonServerPython import DBotScoreReliability

    return Client(
        server_url=SERVER_URL,
        api_key=API_KEY,
        client_id=CLIENT_ID,
        reliability=DBotScoreReliability.C
    )


@pytest.mark.parametrize(
    'args, suffix, file',
    [({'limit': '34'}, '', 'computer_list_response.json'),
     ({'connector_guid': '1'}, '/1', 'computer_get_response.json')]
)
def test_computer_list_command(requests_mock, mock_client, args, suffix, file):
    """
    Scenario:
    -   Get a list of 34 computers.
    -   Get a single computer.
    Given:
    -   The user has entered a limit.
    -   The user has entered a connector_guid.
    When:
    -    cisco-amp-computer-list is called.
    Then:
    -   Ensure outputs_prefix is correct.
    -   Ensure links don't exist.
    """
    mock_response = load_mock_response(file)
    requests_mock.get(
        f'{BASE_URL}/computers{suffix}',
        json=mock_response
    )

    from CiscoAMP import computer_list_command
    responses = computer_list_command(mock_client, args)

    counter = 0

    # Last CommandResults has only a readableOutput, therefore it won't be checked.
    for response in responses[:-1]:
        assert response.outputs_prefix == 'CiscoAMP.Computer'
        assert 'links' not in response.outputs
        assert response.indicator.id == response.outputs['connector_guid']
        assert response.indicator.mac_address == response.outputs['network_addresses'][0]['mac']
        assert response.indicator.status == 'Online' if response.outputs['active'] else 'Offline'
        assert response.indicator.vendor == 'CiscoAMP Response'

        counter += 1


def test_computer_list_error_command(requests_mock, mock_client):
    """
    Scenario:
    -   Search for a specific computer and get a list of computers in a group.
    Given:
    -   The user has entered a connector_guid and a group_guid.
    When:
    -    cisco-amp-computer-list is called.
    Then:
    -   Ensure an exception has been raised.
    """
    args = {
        'connector_guid': '1',
        'group_guid': '2'
    }

    requests_mock.get(
        f'{BASE_URL}/computers/{args["connector_guid"]}'
    )

    with pytest.raises(ValueError) as ve:
        from CiscoAMP import computer_list_command
        computer_list_command(mock_client, args)

        assert str(ve) == 'connector_guid must be the only input, when fetching a specific computer.'


def test_computer_trajectory_list_command(requests_mock, mock_client):
    """
    Scenario:
    -   Get a computer's trajectory with pagination.
    Given:
    -   The user has entered a connector_guid, page and page_size.
    When:
    -    cisco-amp-computer-trajectory-get is called.
    Then:
    -   Ensure outputs_prefix is correct.
    -   Ensure length of the events in context output is correct.
    -   Ensure connector_guid is in the events.
    -   Ensure pagination worked.
    """
    args = {
        'connector_guid': '1',
        'page': 2,
        'page_size': 2
    }

    mock_response = load_mock_response('computer_trajectory_response.json')
    requests_mock.get(
        f'{BASE_URL}/computers/{args["connector_guid"]}/trajectory',
        json=mock_response
    )

    from CiscoAMP import computer_trajectory_list_command
    response = computer_trajectory_list_command(mock_client, args)

    assert response.outputs_prefix == 'CiscoAMP.ComputerTrajectory'
    assert len(response.outputs) == args['page_size']
    assert response.outputs[0]['timestamp'] == 'data_events[2]_timestamp'
    assert_output_has_no_links(response.outputs)


def test_computer_trajectory_list_error_command(requests_mock, mock_client):
    """
    Scenario:
    -   Get a computer's trajectory and filter it by a false query.
    Given:
    -   The user has entered a connector_guid and a query_string.
    When:
    -    cisco-amp-computer-trajectory-get is called.
    Then:
    -   Ensure an exception has been raised.
    """
    args = {
        'connector_guid': '1',
        'query_string': '\"'
    }

    with pytest.raises(ValueError) as ve:
        from CiscoAMP import computer_trajectory_list_command
        computer_trajectory_list_command(mock_client, args)

        assert str(ve) == 'query_string must be: SHA-256/IPv4/URL'


def test_computer_user_activity_list_command(requests_mock, mock_client):
    """
    Scenario:
    -   Get user activity on computers.
    Given:
    -   The user has entered a username.
    When:
    -    cisco-amp-computer-user-activity-get is called.
    Then:
    -   Ensure outputs_prefix is correct.
    -   Ensure isn't in the outputs.
    """
    mock_response = load_mock_response('computer_user_activity_response.json')
    requests_mock.get(
        f'{BASE_URL}/computers/user_activity',
        json=mock_response
    )

    args = {
        'username': 'johndoe'
    }

    from CiscoAMP import computer_user_activity_list_command
    response = computer_user_activity_list_command(mock_client, args)

    assert response.outputs_prefix == 'CiscoAMP.ComputerUserActivity'
    assert_output_has_no_links(response.outputs)

    for output, mock_output in zip(response.outputs, mock_response['data']):
        assert output['connector_guid'] == mock_output['connector_guid']
        assert output['hostname'] == mock_output['hostname']
        assert output['active'] == mock_output['active']


@pytest.mark.parametrize(
    'args',
    [({'connector_guid': '1', 'page': '1', 'page_size': '1'})]
)
def test_computer_user_trajectory_list_command(requests_mock, mock_client, args):
    """
    Scenario:
    -   Get a computer's trajectory with pagination.
    Given:
    -   The user has entered a connector_guid, page and page_size.
    When:
    -    cisco-amp-computer-user-trajectory-get is called.
    Then:
    -   Ensure outputs_prefix is correct.
    -   Ensure length of the outputs is correct.
    -   Ensure connector_guid is in the outputs.
    """
    mock_response = load_mock_response('computer_user_trajectory_response.json')
    requests_mock.get(
        f'{BASE_URL}/computers/{args["connector_guid"]}/user_trajectory',
        json=mock_response
    )

    from CiscoAMP import computer_user_trajectory_list_command
    response = computer_user_trajectory_list_command(mock_client, args)

    assert response.outputs_prefix == 'CiscoAMP.ComputerUserTrajectory'
    assert len(response.outputs) == 1

    for output, mock_output in zip(response.outputs, mock_response['data']['events']):
        assert output['id'] == mock_output['id']
        assert output['date'] == mock_output['date']
        assert output['event_type'] == mock_output['event_type']


def test_computer_vulnerabilities_list_command(requests_mock, mock_client):
    """
    Scenario:
    -   Get vulnerabilities of a computer.
    Given:
    -   The user has entered a connector_guid.
    When:
    -    cisco-amp-computer-vulnerabilities-get is called.
    Then:
    -   Ensure outputs_prefix is correct.
    -   Ensure length of the outputs is correct.
    -   Ensure connector_guid is in the outputs.
    """
    args = {
        'connector_guid': '12345'
    }

    mock_response = load_mock_response('computer_vulnerabilities_response.json')
    requests_mock.get(
        f'{BASE_URL}/computers/{args["connector_guid"]}/vulnerabilities',
        json=mock_response
    )

    from CiscoAMP import computer_vulnerabilities_list_command
    response = computer_vulnerabilities_list_command(mock_client, args)

    assert response.outputs_prefix == 'CiscoAMP.ComputerVulnerability'
    assert len(response.outputs) == 1
    assert_output_has_no_links(response.outputs)

    for output, mock_output in zip(response.outputs, mock_response['data']['vulnerabilities']):
        assert output['connector_guid'] == mock_response['data']['connector_guid']
        assert output['file']['identity']['sha256'] == mock_output['file']['identity']['sha256']


def test_computer_move_command(requests_mock, mock_client):
    """
    Scenario:
    -   Move a computer to another group.
    Given:
    -   The user has entered a connector_guid and a group_guid.
    When:
    -    cisco-amp-computer-move is called.
    Then:
    -   Ensure outputs_prefix is correct.
    -   Ensure a links doesn't exist in outputs.
    """
    args: Dict[str, Any] = {
        'connector_guid': 1,
        'group_guid': 2
    }

    mock_response = load_mock_response('computer_move_response.json')
    requests_mock.patch(
        f'{BASE_URL}/computers/{args["connector_guid"]}',
        json=mock_response
    )

    from CiscoAMP import computer_move_command
    response = computer_move_command(mock_client, args)

    assert response.outputs_prefix == 'CiscoAMP.Computer'
    assert 'links' not in response.outputs
    assert response.outputs[0]['connector_guid'] == mock_response['data']['connector_guid']


def test_computer_delete_command(requests_mock, mock_client):
    """
    Scenario:
    -   Delete a computer.
    Given:
    -   The user has entered a connector_guid.
    When:
    -   cisco-amp-computer-delete is called.
    Then:
    -   Ensure the computer has been deleted.
    """
    args: Dict[str, Any] = {
        'connector_guid': 1
    }

    mock_response = load_mock_response('computer_delete_response.json')
    requests_mock.delete(
        f'{BASE_URL}/computers/{args["connector_guid"]}',
        json=mock_response
    )

    from CiscoAMP import computer_delete_command
    response = computer_delete_command(mock_client, args)

    assert response.raw_response['data']['deleted'] is True


def test_computer_delete_error_command(requests_mock, mock_client):
    """
    Scenario:
    -   Delete a computer.
    Given:
    -   The user has entered a connector_guid.
    When:
    -   cisco-amp-computer-delete is called.
    Then:
    -   Ensure a value error has been raised.
    """
    args: Dict[str, Any] = {
        'connector_guid': 1
    }

    mock_response = load_mock_response('computer_delete_fail_response.json')
    requests_mock.delete(
        f'{BASE_URL}/computers/{args["connector_guid"]}',
        json=mock_response
    )

    from CommonServerPython import DemistoException
    with pytest.raises(DemistoException) as de:
        from CiscoAMP import computer_delete_command
        computer_delete_command(mock_client, args)

        assert de.message.startswith('Failed to delete Connector GUID:')


def test_computer_activity_list_command(requests_mock, mock_client):
    """
    Scenario:
    -   Get activity on computers by query.
    Given:
    -   The user has entered a url to query.
    When:
    -    cisco-amp-computer-activity-list is called.
    Then:
    -   Ensure outputs_prefix is correct.
    -   Ensure a links doesn't exist in outputs.
    """
    args = {
        'query_string': '8.8.8.8'
    }

    mock_response = load_mock_response('computer_activity_response.json')
    requests_mock.get(
        f'{BASE_URL}/computers/activity',
        json=mock_response
    )

    from CiscoAMP import computer_activity_list_command
    response = computer_activity_list_command(mock_client, args)

    assert response.outputs_prefix == 'CiscoAMP.ComputerActivity'
    assert_output_has_no_links(response.outputs)

    for output, mock_output in zip(response.outputs, mock_response['data']):
        assert output['connector_guid'] == mock_output['connector_guid']
        assert output['hostname'] == mock_output['hostname']
        assert output['active'] == mock_output['active']


def test_computer_activity_list_error_command(requests_mock, mock_client):
    """
    Scenario:
    -   Get activity on computers by query.
    Given:
    -   The user has entered a false query.
    When:
    -    cisco-amp-computer-activity-list is called.
    Then:
    -   Ensure a value has been raised.
    """
    args = {
        'query_string': '"'
    }

    requests_mock.get(
        f'{BASE_URL}/computers/activity'
    )

    with pytest.raises(ValueError) as ve:
        from CiscoAMP import computer_activity_list_command
        computer_activity_list_command(mock_client, args)

        assert str(ve) == 'query_string must be: SHA-256/IPv4/URL/Filename'


def test_computer_isolation_feature_availability_get_command(requests_mock, mock_client):
    """
    Scenario:
    -   Get available features on a computer.
    When:
    -    cisco-amp-computer_isolation_feature_availability_get is called.
    Then:
    -   Ensure readable_output is correct.
    """
    args: Dict[str, Any] = {
        'connector_guid': 1
    }

    requests_mock.options(
        f'{BASE_URL}/computers/{args["connector_guid"]}/isolation',
        headers={
            'Allow': 'GET, PUT, DELETE'
        }
    )

    from CiscoAMP import computers_isolation_feature_availability_get_command
    response = computers_isolation_feature_availability_get_command(mock_client, args)

    assert response.readable_output == 'Can get information about an isolation with computer-isolation-get\nCan request to create a new isolation with computer-isolation-create\nCan request to stop the isolation with computer-isolation-delete\n'


def test_computer_isolation_get_command(requests_mock, mock_client):
    """
    Scenario:
    -   Get isolation status on a computer.
    Given:
    -   The user has entered a connector_guid.
    When:
    -    cisco-amp-computer-isolation-get is called.
    Then:
    -   Ensure outputs_prefix is correct.
    -   Ensure comment is set in readable_output.
    """
    args: Dict[str, Any] = {
        'connector_guid': 1
    }
    mock_response = load_mock_response('isolation_response.json')

    requests_mock.get(
        f'{BASE_URL}/computers/{args["connector_guid"]}/isolation',
        json=mock_response
    )

    from CiscoAMP import computer_isolation_get_command
    response = computer_isolation_get_command(mock_client, args)

    assert response.outputs_prefix == 'CiscoAMP.ComputerIsolation'
    assert response.outputs['connector_guid'] == args['connector_guid']


def test_computer_isolation_create_command(requests_mock, mock_client):
    """
    Scenario:
    -   Put a computer in isolation.
    Given:
    -   The user has entered a connector_guid, comment adn unlock_code.
    When:
    -    cisco-amp-computer-isolation-create is called.
    Then:
    -   Ensure outputs_prefix is correct.
    """
    args: Dict[str, Any] = {
        'connector_guid': '1',
        'comment': 'Hello',
        'unlock_code': 'Goodbye',
    }

    mock_response = load_mock_response('isolation_response.json')
    requests_mock.put(
        f'{BASE_URL}/computers/{args["connector_guid"]}/isolation',
        json=mock_response
    )

    from CiscoAMP import computer_isolation_create_command
    response = computer_isolation_create_command(mock_client, args)

    assert response.outputs_prefix == 'CiscoAMP.ComputerIsolation'
    assert response.outputs['connector_guid'] == args['connector_guid']
    assert response.outputs['available'] == mock_response['data']['available']
    assert response.outputs['status'] == mock_response['data']['status']
    assert response.outputs['unlock_code'] == mock_response['data']['unlock_code']


def test_computer_isolation_delete_command(requests_mock, mock_client):
    """
    Scenario:
    -   Delete a computer in isolation.
    Given:
    -   The user has entered a connector_guid.
    When:
    -    cisco-amp-computer-isolation-delete is called.
    Then:
    -   Ensure outputs_prefix is correct.
    """
    args: Dict[str, Any] = {
        'connector_guid': '1',
    }

    mock_response = load_mock_response('isolation_response.json')
    requests_mock.delete(
        f'{BASE_URL}/computers/{args["connector_guid"]}/isolation',
        json=mock_response
    )

    from CiscoAMP import computer_isolation_delete_command
    response = computer_isolation_delete_command(mock_client, args)

    assert response.outputs_prefix == 'CiscoAMP.ComputerIsolation'
    assert response.outputs[0]['available'] == mock_response['data']['available']
    assert response.outputs[0]['status'] == mock_response['data']['status']
    assert response.outputs[0]['unlock_code'] == mock_response['data']['unlock_code']


def test_event_list_command(requests_mock, mock_client):
    """
    Scenario:
    -   Get list of events.
    Given:
    -   The user has entered no arguments.
    When:
    -    cisco-amp-event-list is called.
    Then:
    -   Ensure outputs_prefix is correct.
    -   Ensure there are no links in the outputs.
    """
    mock_response = load_mock_response('event_list_response.json')
    requests_mock.get(
        f'{BASE_URL}/events',
        json=mock_response
    )

    args: Dict[str, Any] = {}

    from CiscoAMP import event_list_command
    responses = event_list_command(mock_client, args)

    # Not including last element as it is only a readable output.
    for response in responses[:-1]:
        assert response.outputs_prefix == 'CiscoAMP.Event'

        if 'file' in response.outputs:
            assert response.indicator.sha256 == response.outputs['file']['identity']['sha256']
            assert response.indicator.path == response.outputs['file']['file_path']
            assert response.indicator.name == response.outputs['file']['file_name']

        if computer := response.outputs.get('computer'):
            assert 'links' not in computer

    assert responses[-1].readable_output == \
        '### Results\n' + \
        '|Current Item Count|Index|Items Per Page|Total|\n' + \
        '|---|---|---|---|\n' + \
        '| metadata_results_current_item_count | metadata_results_index | ' + \
        'metadata_results_items_per_page | metadata_results_total |\n' + \
        '### Event Information\n' + \
        '|ID|Date|Event Type|Detection|Connector GUID|Severity|\n' + \
        '|---|---|---|---|---|---|\n' + \
        '| data[0]_id | data[0]_date | data[0]_event_type |  | data[0]_connector_guid |  |\n' + \
        '| data[1]_id | data[1]_date | data[1]_event_type |  | data[1]_connector_guid |  |\n' + \
        '| data[2]_id | data[2]_date | data[2]_event_type |  | data[2]_connector_guid |  |\n' + \
        '| data[3]_id | data[3]_date | data[3]_event_type |  | data[3]_connector_guid |  |\n' + \
        '| data[4]_id | data[4]_date | data[4]_event_type |  | data[4]_connector_guid |  |\n' + \
        '| data[5]_id | data[5]_date | data[5]_event_type |  | data[5]_connector_guid |  |\n' + \
        '| data[6]_id | data[6]_date | data[6]_event_type |  | data[6]_connector_guid |  |\n' + \
        '| data[7]_id | data[7]_date | data[7]_event_type |  | data[7]_connector_guid |  |\n' + \
        '| data[8]_id | data[8]_date | data[8]_event_type |  | data[8]_connector_guid |  |\n' + \
        '| data[9]_id | data[9]_date | data[9]_event_type |  | data[9]_connector_guid |  |\n' + \
        '| data[10]_id | data[10]_date | data[10]_event_type |  | data[10]_connector_guid |  |\n' + \
        '| data[11]_id | data[11]_date | data[11]_event_type |  | data[11]_connector_guid |  |\n' + \
        '| data[12]_id | data[12]_date | data[12]_event_type |  | data[12]_connector_guid |  |\n' + \
        '| data[13]_id | data[13]_date | data[13]_event_type |  |  |  |\n' + \
        '| data[14]_id | data[14]_date | data[14]_event_type | ' + \
        'data[14]_detection | data[14]_connector_guid | data[14]_severity |\n'


@pytest.mark.parametrize(
    'args, expected_number_of_results, expected_value',
    [({}, 100, 'data[0]_id'),
     ({'limit': '50'}, 50, 'data[0]_id'),
     ({'page': '7', 'page_size': '5'}, 5, 'data[30]_id')]
)
def test_event_types_list_command(requests_mock, mock_client, args, expected_number_of_results, expected_value):
    """
    Scenario:
    -   Get list of event types.
    Given:
    -   The user has entered no arguments.
    -   The user has entered automatic pagination.
    -   The user has entered manual pagination.
    When:
    -    cisco-amp-event-type-list is called.
    Then:
    -   Ensure outputs_prefix is correct.
    -   Ensure pagination has worked.
    """
    mock_response = load_mock_response('event_type_list_response.json')
    requests_mock.get(
        f'{BASE_URL}/event_types',
        json=mock_response
    )

    from CiscoAMP import event_type_list_command
    response = event_type_list_command(mock_client, args)

    assert response.outputs_prefix == 'CiscoAMP.EventType'
    assert len(response.outputs) == expected_number_of_results
    assert response.outputs[0]['id'] == expected_value


@pytest.mark.parametrize(
    'file, suffix, args, expected_file_list_type',
    [(
        'file_list_list_response.json',
        'file_lists/1',
        {'file_list_guid': '1'},
        'application_blocking'
    ), (
        'file_list_application_blocking_response.json',
        'file_lists/application_blocking',
        {},
        'application_blocking'
    ), (
        'file_list_simple_custom_detections_response.json',
        'file_lists/simple_custom_detections',
        {'file_list_type': 'Simple Custom Detection'},
        'simple_custom_detections'
    )]
)
def test_file_list_list_command(requests_mock, mock_client, file, suffix, args, expected_file_list_type):
    """
    Scenario:
    -   Get a specific file list.
    -   Get an application_blocking list.
    -   Get a simple_custom_detections list.
    Given:
    -   The user has entered a file_list_guid.
    -   The user has entered no arguments.
    -   The user has entered a file_list_type.
    When:
    -    cisco-amp-file-list-list is called.
    Then:
    -   Ensure outputs_prefix is correct.
    -   Ensure there are no links in the outputs.
    -   Ensure the correct file list type has been returned.
    """
    mock_response = load_mock_response(file)
    requests_mock.get(
        f'{BASE_URL}/{suffix}',
        json=mock_response
    )

    from CiscoAMP import file_list_list_command
    response = file_list_list_command(mock_client, args)

    assert response.outputs_prefix == 'CiscoAMP.FileList'

    if not isinstance(response.outputs, List):
        response.outputs = [response.outputs]

    if isinstance(mock_response['data'], dict):
        mock_response['data'] = [mock_response['data']]

    for output in response.outputs:
        assert 'links' not in output
        assert output['type'] == expected_file_list_type

    for output, mock_output in zip(response.outputs, mock_response['data']):
        assert output['guid'] == mock_output['guid']
        assert output['name'] == mock_output['name']
        assert output['type'] == mock_output['type']


@pytest.mark.parametrize(
    'file, suffix, args',
    [(
        'file_list_item_list_response.json',
        'file_lists/1/files',
        {'file_list_guid': '1'},
    ), (
        'file_list_item_get_response.json',
        'file_lists/1/files/1',
        {'file_list_guid': '1', 'sha256': '1'},
    )]
)
def test_file_list_item_list_command(requests_mock, mock_client, file, suffix, args):
    """
    Scenario:
    -   Get a file item list.
    -   Get a specific file item list item.
    Given:
    -   The user has entered a file_list_guid.
    -   The user has entered a file_list_guid and a sha256.
    When:
    -    cisco-amp-file-list-item-list is called.
    Then:
    -   Ensure outputs_prefix is correct.
    -   Ensure there are no links in the outputs.
    """
    mock_response = load_mock_response(file)
    requests_mock.get(
        f'{BASE_URL}/{suffix}',
        json=mock_response
    )

    from CiscoAMP import file_list_item_list_command
    response = file_list_item_list_command(mock_client, args)

    assert response.outputs_prefix == 'CiscoAMP.FileListItem'
    assert 'links' not in response.outputs

    if policies := response.outputs[0].get('policies'):
        assert_output_has_no_links(policies)

        for policy, mock_policy in zip(policies, mock_response['data']['policies']):
            assert policy['guid'] == mock_policy['guid']
            assert policy['name'] == mock_policy['name']

    if items := response.outputs[0].get('items'):
        assert_output_has_no_links(items)

        for item, mock_item in zip(items, mock_response['data']['items']):
            assert item['sha256'] == mock_item['sha256']
            assert item['source'] == mock_item['source']


def test_file_list_item_create_command(requests_mock, mock_client):
    """
    Scenario:
    -   Create an item for a file item list
    Given:
    -   The user has entered a file_list_guid and a sha256.
    When:
    -    cisco-amp-file-list-item-create is called.
    Then:
    -   Ensure outputs_prefix is correct.
    -   Ensure there are no links in the outputs.
    """
    args: Dict[str, Any] = {
        'file_list_guid': '1',
        'sha256': '1'
    }

    mock_response = load_mock_response('file_list_item_create_response.json')
    requests_mock.post(
        f'{BASE_URL}/file_lists/{args["file_list_guid"]}/files/{args["sha256"]}',
        json=mock_response
    )

    from CiscoAMP import file_list_item_create_command
    response = file_list_item_create_command(mock_client, args)

    assert response.outputs_prefix == 'CiscoAMP.FileListItem'
    assert 'links' not in response.outputs
    assert response.outputs[0]['sha256'] == mock_response['data']['sha256']
    assert response.outputs[0]['description'] == mock_response['data']['description']


def test_file_list_item_delete_command(requests_mock, mock_client):
    """
    Scenario:
    -   Delete a file item from a file item list.
    Given:
    -   The user has entered a file_list_guid and a sha256.
    When:
    -    cisco-amp-file-list-item-delete is called.
    Then:
    -   Ensure the deletion succeeded.
    """
    args = {
        'file_list_guid': '1',
        'sha256': '1'
    }

    mock_response = load_mock_response('file_list_item_delete_response.json')
    requests_mock.delete(
        f'{BASE_URL}/file_lists/{args["file_list_guid"]}/files/{args["sha256"]}',
        json=mock_response
    )

    from CiscoAMP import file_list_item_delete_command
    response = file_list_item_delete_command(mock_client, args)

    assert response.readable_output == \
        f'SHA-256: "{args["sha256"]}" Successfully deleted from File List GUID: "{args["file_list_guid"]}".'


def test_file_list_item_delete_error_command(requests_mock, mock_client):
    """
    Scenario:
    -   Delete a file item from a file item list.
    Given:
    -   The user has entered a file_list_guid and a sha256.
    When:
    -    cisco-amp-file-list-item-delete is called.
    Then:
    -   Ensure the deletion failed.
    """
    args = {
        'file_list_guid': '1',
        'sha256': '1'
    }

    mock_response = load_mock_response('file_list_item_delete_fail_response.json')
    requests_mock.delete(
        f'{BASE_URL}/file_lists/{args["file_list_guid"]}/files/{args["sha256"]}',
        json=mock_response
    )

    with pytest.raises(ValueError) as ve:
        from CiscoAMP import file_list_item_delete_command
        file_list_item_delete_command(mock_client, args)

        assert str(ve) == \
            f'Failed to delete-\nFile List GUID: "{args["file_list_guid"]}"\nSHA-256: "{args["sha256"]}" not found.'


@pytest.mark.parametrize(
    'file, args, suffix',
    [('group_list_response.json', {}, ''),
     ('group_response.json', {'group_guid': '1'}, '/1')]
)
def test_group_list_command(requests_mock, mock_client, file, args, suffix):
    """
    Scenario:
    -   Get a group list.
    -   Get a specific group.
    Given:
    -   The user hasn't entered any arguments.
    -   The user has entered a group_guid.
    When:
    -    cisco-amp-group-list is called.
    Then:
    -   Ensure outputs_prefix is correct.
    -   Ensure there are no links in the outputs.
    """
    mock_response = load_mock_response(file)
    requests_mock.get(
        f'{BASE_URL}/groups{suffix}',
        json=mock_response
    )

    from CiscoAMP import group_list_command
    response = group_list_command(mock_client, args)

    assert response.outputs_prefix == 'CiscoAMP.Group'

    assert_output_has_no_links(response.outputs)

    if policies := response.outputs[0].get('policies'):
        assert_output_has_no_links(policies)

    if isinstance(mock_response['data'], dict):
        mock_response['data'] = [mock_response['data']]

    for output, mock_output in zip(response.outputs, mock_response['data']):
        assert output['name'] == mock_output['name']
        assert output['description'] == mock_output['description']


def test_group_policy_update_command(requests_mock, mock_client):
    """
    Scenario:
    -   Update a group policy.
    Given:
    -   The user hasn't entered any policy arguments.
    -   The user has entered a group_guid and a policy argument.
    When:
    -    cisco-amp-group-policy-update is called.
    Then:
    -   Ensure outputs_prefix is correct.
    -   Ensure there are no links in the outputs.
    """
    args = {
        'group_guid': '1',
        'windows_policy_guid': '1'
    }

    mock_response = load_mock_response('group_response.json')
    requests_mock.patch(
        f'{BASE_URL}/groups/{args["group_guid"]}',
        json=mock_response
    )

    from CiscoAMP import group_policy_update_command
    response = group_policy_update_command(mock_client, args)

    assert response.outputs_prefix == 'CiscoAMP.Group'

    if policies := response.outputs[0].get('policies'):
        assert_output_has_no_links(policies)

    if isinstance(mock_response['data'], dict):
        mock_response['data'] = [mock_response['data']]

    for output, mock_output in zip(response.outputs, mock_response['data']):
        assert output['name'] == mock_output['name']
        assert output['description'] == mock_output['description']


def test_group_policy_update_error_command(requests_mock, mock_client):
    """
    Scenario:
    -   Update a group policy.
    Given:
    -   The user hasn't entered any policy arguments.
    When:
    -    cisco-amp-group-policy-update is called.
    Then:
    -   Ensure an error has been raised
    """
    args = {
        'group_guid': '1'
    }

    requests_mock.patch(
        f'{BASE_URL}/groups/{args["group_guid"]}'
    )

    with pytest.raises(ValueError) as ve:
        from CiscoAMP import group_policy_update_command
        group_policy_update_command(mock_client, args)

        assert str(ve) == 'At least one Policy GUID must be entered.'


@pytest.mark.parametrize(
    'file',
    [('group_response.json'),
     ('group_response.json')]
)
def test_group_parent_update_command(requests_mock, mock_client, file):
    """
    Scenario:
    -   Update a group policy.
    Given:
    -   The user has entered a child_guid.
    When:
    -    cisco-amp-group-parent-update is called.
    Then:
    -   Ensure outputs_prefix is correct.
    -   Ensure there are no links in the outputs.
    """
    args: Dict[str, Any] = {
        'child_guid': '1'
    }

    mock_response = load_mock_response(file)
    requests_mock.patch(
        f'{BASE_URL}/groups/{args["child_guid"]}/parent',
        json=mock_response
    )

    from CiscoAMP import group_parent_update_command
    response = group_parent_update_command(mock_client, args)

    assert response.outputs_prefix == 'CiscoAMP.Group'

    if policies := response.outputs[0].get('policies'):
        assert_output_has_no_links(policies)

    if isinstance(mock_response['data'], dict):
        mock_response['data'] = [mock_response['data']]

    for output, mock_output in zip(response.outputs, mock_response['data']):
        assert output['name'] == mock_output['name']
        assert output['description'] == mock_output['description']


def test_group_create_command(requests_mock, mock_client):
    """
    Scenario:
    -   Create a new group.
    Given:
    -   The user has entered a name and description.
    When:
    -    cisco-amp-group-create is called.
    Then:
    -   Ensure outputs_prefix is correct.
    -   Ensure there are no links in the outputs.
    """
    args: Dict[str, Any] = {
        'name': 'Til',
        'description': 'Tamar',
    }

    mock_response = load_mock_response('group_response.json')
    requests_mock.post(
        f'{BASE_URL}/groups',
        json=mock_response
    )

    from CiscoAMP import group_create_command
    response = group_create_command(mock_client, args)

    assert response.outputs_prefix == 'CiscoAMP.Group'

    if policies := response.outputs[0].get('policies'):
        assert_output_has_no_links(policies)

    if isinstance(mock_response['data'], dict):
        mock_response['data'] = [mock_response['data']]

    for output, mock_output in zip(response.outputs, mock_response['data']):
        assert output['name'] == mock_output['name']
        assert output['description'] == mock_output['description']


def test_group_delete_command(requests_mock, mock_client):
    """
    Scenario:
    -   Delete a group.
    Given:
    -   The user has entered a group_guid.
    When:
    -    cisco-amp-groups-delete is called.
    Then:
    -   Ensure the deletion succeeded.
    """
    args: Dict[str, Any] = {
        'group_guid': '1',
    }

    mock_response = load_mock_response('group_delete_response.json')
    requests_mock.delete(
        f'{BASE_URL}/groups/{args["group_guid"]}',
        json=mock_response
    )

    from CiscoAMP import groups_delete_command
    response = groups_delete_command(mock_client, args)

    assert response.readable_output == f'Group GUID: "{args["group_guid"]}"\nSuccessfully deleted.'


def test_group_delete_error_command(requests_mock, mock_client):
    """
    Scenario:
    -   Delete a group.
    Given:
    -   The user has entered a group_guid.
    When:
    -    cisco-amp-groups-delete is called.
    Then:
    -   Ensure the deletion failed.
    """
    args: Dict[str, Any] = {
        'group_guid': '1',
    }

    mock_response = load_mock_response('group_delete_fail_response.json')
    requests_mock.delete(
        f'{BASE_URL}/groups/{args["group_guid"]}',
        json=mock_response
    )

    with pytest.raises(ValueError) as ve:
        from CiscoAMP import groups_delete_command
        groups_delete_command(mock_client, args)

        assert str(ve) == f'Failed to delete Group GUID: "{args["group_guid"]}".'


@pytest.mark.parametrize(
    'file, args, suffix',
    [('indicator_list_response.json', {}, ''),
     ('indicator_get_response.json', {'indicator_guid': '1'}, '/1')]
)
def test_indicator_list_command(requests_mock, mock_client, file, args, suffix):
    """
    Scenario:
    -   Get an indicator list.
    -   Get a specific indicator.
    Given:
    -   The user hasn't entered any arguments.
    -   The user has entered an indicator_guid.
    When:
    -    cisco-amp-indicator-list is called.
    Then:
    -   Ensure outputs_prefix is correct.
    -   Ensure there are no links in the outputs.
    """
    mock_response = load_mock_response(file)
    requests_mock.get(
        f'{BASE_URL}/indicators{suffix}',
        json=mock_response
    )

    from CiscoAMP import indicator_list_command
    from CommonServerPython import dict_safe_get
    response = indicator_list_command(mock_client, args)

    assert response.outputs_prefix == 'CiscoAMP.Indicator'
    assert_output_has_no_links(response.outputs)

    if isinstance(mock_response['data'], dict):
        mock_response['data'] = [mock_response['data']]

    for output, mock_output in zip(response.outputs, mock_response['data']):
        assert output['guid'] == mock_output['guid']
        assert output['name'] == mock_output['name']
        assert output['description'] == mock_output['description']
        assert dict_safe_get(output, ['mitre', 'tactics']) == dict_safe_get(mock_output, ['mitre', 'tactics'])
        assert dict_safe_get(output, ['mitre', 'techniques']) == dict_safe_get(mock_output, ['mitre', 'techniques'])


@pytest.mark.parametrize(
    'file, args, suffix',
    [('policy_list_response.json', {}, ''),
     ('policy_get_response.json', {'policy_guid': '1'}, '/1')]
)
def test_policy_list_command(requests_mock, mock_client, file, args, suffix):
    """
    Scenario:
    -   Get a policy list.
    -   Get a specific policy.
    Given:
    -   The user hasn't entered any arguments.
    -   The user has entered an policy_guid.
    When:
    -    cisco-amp-policy-list is called.
    Then:
    -   Ensure outputs_prefix is correct.
    -   Ensure there are no links in the outputs.
    """
    mock_response = load_mock_response(file)
    requests_mock.get(
        f'{BASE_URL}/policies{suffix}',
        json=mock_response
    )

    from CiscoAMP import policy_list_command
    response = policy_list_command(mock_client, args)

    assert response.outputs_prefix == 'CiscoAMP.Policy'
    assert_output_has_no_links(response.outputs)

    if isinstance(mock_response['data'], dict):
        mock_response['data'] = [mock_response['data']]

    for output, mock_output in zip(response.outputs, mock_response['data']):
        assert output['guid'] == mock_output['guid']
        assert output['name'] == mock_output['name']
        assert output['description'] == mock_output['description']


@pytest.mark.parametrize(
    'args, expected_number_of_results, expected_value',
    [({'ios_bid': 'Gotta'}, 100, 'data[0]_connector_guid'),
     ({'ios_bid': 'Catch-em', 'limit': '50'}, 50, 'data[0]_connector_guid'),
     ({'ios_bid': 'All', 'page': '7', 'page_size': '5'}, 5, 'data[30]_connector_guid')]
)
def test_app_trajectory_query_list_command(
    requests_mock,
    mock_client,
    args,
    expected_number_of_results,
    expected_value
):
    """
    Scenario:
    -   Get an app trajectory.
    Given:
    -   The user has entered an ios_bid.
    -   The user has entered an ios_bid and automatic pagination.
    -   The user has entered an ios_bid and manual pagination.
    When:
    -    cisco-amp-app-trajectory-query-list is called.
    Then:
    -   Ensure outputs_prefix is correct.
    -   Ensure pagination has worked.
    """
    mock_response = load_mock_response('app_trajectory_query_response.json')
    requests_mock.get(
        f'{BASE_URL}/app_trajectory/queries',
        json=mock_response
    )

    from CiscoAMP import app_trajectory_query_list_command
    response = app_trajectory_query_list_command(mock_client, args)

    assert response.outputs_prefix == 'CiscoAMP.AppTrajectoryQuery'
    assert len(response.outputs) == expected_number_of_results
    assert response.outputs[0]['connector_guid'] == expected_value


def test_version_get_command(requests_mock, mock_client):
    """
    Scenario:
    -   Get current version of API.
    When:
    -    cisco-amp-version-get is called.
    Then:
    -   Ensure outputs_prefix is correct.
    """
    arg: Dict[str, Any] = {}

    mock_response = load_mock_response('version_get_response.json')
    requests_mock.get(
        f'{BASE_URL}/version',
        json=mock_response
    )

    from CiscoAMP import version_get_command
    response = version_get_command(mock_client, arg)

    assert response.outputs_prefix == 'CiscoAMP.Version'


@pytest.mark.parametrize(
    'file, args, suffix, is_list',
    [('vulnerability_list_response.json', {}, '', True),
     ('vulnerability_get_response.json', {'sha256': '1'}, '/1/computers', False)]
)
def test_vulnerability_list_command(requests_mock, mock_client, file, args, suffix, is_list):
    """
    Scenario:
    -   Get a vulnerability list.
    -   Get a vulnerable item trajectory.
    Given:
    -   The user hasn't entered any arguments.
    -   The user has entered a sha256.
    When:
    -    cisco-amp-vulnerability-list is called.
    Then:
    -   Ensure outputs_prefix is correct.
    -   Ensure there are no links in the outputs.
    """
    mock_response = load_mock_response(file)
    requests_mock.get(
        f'{BASE_URL}/vulnerabilities{suffix}',
        json=mock_response
    )

    from CiscoAMP import vulnerability_list_command
    response = vulnerability_list_command(mock_client, args)

    assert response.outputs_prefix == 'CiscoAMP.Vulnerability'
    assert_output_has_no_links(response.outputs)

    for output, mock_output in zip(response.outputs, mock_response['data']):
        if is_list:
            assert output['application'] == mock_output['application']
            assert output['version'] == mock_output['version']

        else:
            assert output['connector_guid'] == mock_output['connector_guid']
            assert output['hostname'] == mock_output['hostname']
