import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
import pytest

'''MOCK PARAMETERS '''
SERVER_URL = "https://help.kusto.windows.net"
BASE_URL = f'{SERVER_URL}/phoenix/rest'
USERNAME = 'TEST_USERNAME'
PASSWORD = 'XXXX'
QUERY = "eventId=123"
IP_ADDRESS_1 = '1.1.1.1'
IP_ADDRESS_2 = '2.2.2.2'


def load_json_mock_response(file_name: str) -> str:
    """
    Load mock file that simulates an API response.
    Args:
        file_name (str): Name of the mock response JSON file to return.
    Returns:
        str: Mock file content.
    """
    with open(f'test_data/{file_name}', mode='r', encoding='utf-8') as mock_file:
        return json.loads(mock_file.read())


def load_xml_mock_response(file_name: str) -> str:
    """
    Load mock file in XML format that simulates an API response.
    Args:
        file_name (str): Name of the mock response XML file to return.
    Returns:
        str: Mock file content.
    """
    file_path = f'test_data/{file_name}'

    top = ET.parse(file_path)
    return ET.tostring(top.getroot(), encoding='utf8').decode("utf-8")


def mock_client():
    from FortiSIEMV2 import FortiSIEMClient
    return FortiSIEMClient(SERVER_URL, True, False, {}, (USERNAME, PASSWORD))


@pytest.mark.parametrize("mock_response_file,command_arguments,expected_devices_number,expected_device_name", [
    ('list_devices_1.xml', {
        'include_ip_list': f'{IP_ADDRESS_1},{IP_ADDRESS_2}'
    }, 2, 'DEVICE_1'),
    ('list_devices_1.xml', {}, 2, 'DEVICE_1'),
    ('list_devices_2.xml', {
        'include_ip_list': f'{IP_ADDRESS_1}-{IP_ADDRESS_2}',
        'exclude_ip_list': f'{IP_ADDRESS_1}'
    }, 1, 'DEVICE_2')
])
def test_cmdb_devices_list(mock_response_file, command_arguments, expected_devices_number, expected_device_name,
                           requests_mock):
    """
    Scenario: List CMDB devices.
    Given:
     - User has provided valid credentials.
     - User may provided list/range of include/exclude IP addresses.
    When:
     - fortisiem-cmdb-device-list command called.
    Then:
     - Ensure number of items is correct.
     - Ensure outputs prefix is correct.
    - Validate outputs' fields.
    """
    from FortiSIEMV2 import cmdb_devices_list_command
    client = mock_client()
    mock_response = load_xml_mock_response(mock_response_file)
    requests_mock.get(f'{client._base_url}cmdbDeviceInfo/devices', text=mock_response)
    result = cmdb_devices_list_command(client, command_arguments)
    outputs = result.outputs
    assert len(outputs) == expected_devices_number
    assert outputs[0]['name'] == expected_device_name


def test_cmdb_device_get(requests_mock):
    """
    Scenario: Get CMDB device.
    Given:
     - User has provided valid credentials.
     - User has provided valid IP address.
    When:
     - fortisiem-cmdb-device-get command called.
    Then:
     - Ensure outputs prefix is correct.
    - Validate outputs' fields.
    """
    from FortiSIEMV2 import FortiSIEMClient, cmdb_device_get_command
    client: FortiSIEMClient = mock_client()
    mock_response = load_xml_mock_response("get_device.xml")
    requests_mock.get(f'{client._base_url}cmdbDeviceInfo/device', text=mock_response)
    results = cmdb_device_get_command(client, {
        'ip_address': IP_ADDRESS_1
    })
    outputs = results[0].outputs
    assert outputs[0]['name'] == 'DEVICE_1'
    assert outputs[0]['accessIp'] == IP_ADDRESS_1


def test_monitored_organizations_list(requests_mock):
    """
    Scenario: List Organizations.
    Given:
        - User has provided valid credentials.
    When:
        - fortisiem-monitored-organizations-list command called.
    Then:
        - Ensure number of items is correct.
        - Ensure outputs prefix is correct.
        - Validate outputs' fields.
    """
    from FortiSIEMV2 import FortiSIEMClient, monitored_organizations_list_command
    client: FortiSIEMClient = mock_client()
    mock_response = load_xml_mock_response('list_organizations.xml')
    requests_mock.get(f'{client._base_url}config/Domain', text=mock_response)
    result = monitored_organizations_list_command(client, {'limit': 2})
    outputs = result.outputs
    assert len(outputs) == 1
    assert outputs[0]['custId'] == '0'
    assert outputs[0]['id'] == '500003'
    assert outputs[0]['creationTime'] == '2021-11-23T08:58:49'


@pytest.mark.parametrize("command_arguments,expected_response,expected_msg", [
    ({
         "incident_id": "123", "comment": "test-success"
     }, "OK", "successfully updated")
])
def test_update_incident(command_arguments, expected_response, expected_msg, requests_mock):
    """
    Scenario: Update incident.
    Given:
        - User has provided valid credentials.
        - User provided incident ID.
        - User provided comment.
    When:
        - fortisiem-incident-update command called.
    Then:
        - Validate outputs' fields.
    """
    from FortiSIEMV2 import FortiSIEMClient, incident_update_command
    client: FortiSIEMClient = mock_client()
    requests_mock.post(f'{client._base_url}incident/external', json=expected_response)
    result = incident_update_command(client, command_arguments)
    outputs = result.readable_output
    assert expected_msg in outputs


def test_list_events_by_incident(requests_mock):
    """
    Scenario: List triggered events.
    Given:
        - User has provided valid credentials.
        - User has provided incident ID.
    When:
        - fortisiem-event-list-by-incident command called.
    Then:
        - Ensure number of items is correct.
        - Ensure outputs prefix is correct.
        - Validate outputs' fields.
    """
    from FortiSIEMV2 import FortiSIEMClient, events_list_command
    client: FortiSIEMClient = mock_client()
    mock_response = load_json_mock_response('list_events_by_incident.json')
    requests_mock.get(f'{client._base_url}pub/incident/triggeringEvents', json=mock_response)
    result = events_list_command(client, {
        "limit": 2,
        "incident_id": 123
    })
    outputs = result.outputs
    assert len(outputs) == 2
    assert outputs[0]['id'] == 1111
    assert outputs[0]['attributes']['Reporting IP'] == '192.168.1.1'
    assert outputs[1]['id'] == 9071234812007542512
    assert outputs[1]['attributes']['Reporting IP'] == '192.168.1.2'


@pytest.mark.parametrize(
    "command_arguments,response_file,suffix_url,watchlist_number,watchlist_id,watchlist_display_name", [
        ({
             "limit": "2",
         }, 'list_watchlist.json', 'watchlist/all', 2, 111, "Accounts Locked"),
        ({
             "entry_value": "192.168.1.1"
         }, 'list_watchlist2.json', 'watchlist/value', 1, 112, "Port Scanners")
    ])
def test_list_watchlist(command_arguments, response_file, suffix_url, watchlist_number, watchlist_id,
                        watchlist_display_name, requests_mock):
    """
        Scenario: List Watchlist groups.
        Given:
            - User has provided valid credentials.
        When:
            - fortisiem-watchlist-list command called.
        Then:
            - Ensure number of items is correct.
            - Ensure outputs prefix is correct.
            - Validate outputs' fields.
    """
    from FortiSIEMV2 import FortiSIEMClient, watchlist_list_command
    client: FortiSIEMClient = mock_client()
    mock_response = load_json_mock_response(response_file)
    requests_mock.get(f'{client._base_url}{suffix_url}', json=mock_response)
    result = watchlist_list_command(client, command_arguments)
    outputs = result.outputs
    assert len(outputs) == watchlist_number
    assert result.outputs_prefix == 'FortiSIEM.Watchlist'
    assert outputs[0]['id'] == watchlist_id
    assert outputs[0]['displayName'] == watchlist_display_name


@pytest.mark.parametrize(
    "command_arguments,response_file,suffix_url,watchlist_id,watchlist_display_name", [
        ({
             "watchlist_id": "111",
         }, 'get_watchlist.json', 'watchlist/111', 111, "Accounts Locked"),
        ({
             "entry_id": "55555"
         }, 'list_watchlist2.json', 'watchlist/byEntry/55555', 112, "Port Scanners")
    ])
def test_get_watchlist(command_arguments, response_file, suffix_url, watchlist_id,
                       watchlist_display_name, requests_mock):
    """
        Scenario: Get Watchlist group.
        Given:
            - User has provided valid credentials.
        When:
            - fortisiem-watchlist-get command called.
        Then:
            - Ensure number of items is correct.
            - Ensure outputs prefix is correct.
            - Validate outputs' fields.
    """
    from FortiSIEMV2 import FortiSIEMClient, watchlist_get_command
    client: FortiSIEMClient = mock_client()
    mock_response = load_json_mock_response(response_file)
    requests_mock.get(f'{client._base_url}{suffix_url}', json=mock_response)
    results = watchlist_get_command(client, command_arguments)
    outputs = results[0].outputs
    assert results[0].outputs_prefix == 'FortiSIEM.Watchlist'
    assert outputs[0]['id'] == watchlist_id
    assert outputs[0]['displayName'] == watchlist_display_name


def test_add_watchlist(requests_mock):
    """
        Scenario: Add Watchlist group.
        Given:
            - User has provided valid credentials.
        When:
            - fortisiem-watchlist-add command called.
        Then:
            - Ensure outputs prefix is correct.
            - Validate outputs' fields.
    """
    from FortiSIEMV2 import FortiSIEMClient, watchlist_add_command
    client: FortiSIEMClient = mock_client()
    mock_response = load_json_mock_response('add_watchlist.json')
    requests_mock.post(f'{client._base_url}watchlist/save', json=mock_response)
    result = watchlist_add_command(client, {
        "description": "Servers, network or storage devices",
        "display_name": "Resource Issues Test4",
        "is_case_sensitive": False,
        "data_creation_type": "USER",
        "value_type": "STRING",
        "entry_inclusive": "true"
    })
    outputs = result.outputs
    assert result.outputs_prefix == 'FortiSIEM.Watchlist'
    assert outputs[0]['id'] == 111
    assert outputs[0]['displayName'] == "Resource Issues Test4"
    assert outputs[0]['description'] == "Servers, network or storage devices"
    assert outputs[0]['valueType'] == 'STRING'


def test_add_entry(requests_mock):
    """
        Scenario: Add Entry.
        Given:
            - User has provided valid credentials.
        When:
            - fortisiem-watchlist-entry-add command called.
        Then:
            - Ensure outputs prefix is correct.
            - Validate outputs' fields.
    """
    from FortiSIEMV2 import FortiSIEMClient, watchlist_entry_add_command
    client: FortiSIEMClient = mock_client()
    mock_response = load_json_mock_response('add_entry.json')
    requests_mock.post(f'{client._base_url}watchlist/addTo', json=mock_response)
    result = watchlist_entry_add_command(client, {
        "watchlist_id": 500496,
        "value": "192.168.1.1",
        "inclusive": True,
        "count": 2,
    })
    readable_output = result.readable_output
    assert readable_output.startswith("Successfully added Entry")


def test_update_entry(requests_mock):
    """
        Scenario: Update Entry.
        Given:
            - User has provided valid credentials.
        When:
            - fortisiem-watchlist-entry-update command called.
        Then:
            - Ensure outputs prefix is correct.
            - Validate outputs' fields.
    """
    from FortiSIEMV2 import FortiSIEMClient, watchlist_entry_update_command
    client: FortiSIEMClient = mock_client()
    mock_response = load_json_mock_response('update_entry.json')
    requests_mock.post(f'{client._base_url}watchlist/entry/save', json=mock_response)
    result = watchlist_entry_update_command(client, {
        "data_creation_type": "USER",
        "count": 100,
        "triggering_rules": "Datastore Space Warning",
        "description": "Testing again",
        "entry_id": 889400,
        "inclusive": True,
        "value": "PVVol_A001_A000356_POWER23"
    })
    outputs = result.outputs
    assert result.outputs_prefix == 'FortiSIEM.WatchlistEntry'
    assert outputs[0]['id'] == 889400
    assert outputs[0]['state'] == 'Enabled'
    assert outputs[0]['triggeringRules'] == "Datastore Space Warning"
    assert outputs[0]['dataCreationType'] == 'USER'
    assert outputs[0]['description'] == "Testing again"


def test_delete_watchlist(requests_mock):
    """
        Scenario: Delete Watchlist.
        Given:
            - User has provided valid credentials.
        When:
            - fortisiem-watchlist-delete command called.
        Then:
            - Validate outputs' fields.
    """
    from FortiSIEMV2 import FortiSIEMClient, watchlist_delete_command
    client: FortiSIEMClient = mock_client()
    mock_response = load_json_mock_response('delete_watchlist.json')
    requests_mock.post(f'{client._base_url}watchlist/delete', json=mock_response)
    results = watchlist_delete_command(client, {
        "watchlist_id": 111
    })
    readable_output = results[0].readable_output
    assert readable_output == 'The watchlist 111 was deleted successfully.'


def test_delete_entry(requests_mock):
    """
        Scenario: Delete entry.
        Given:
            - User has provided valid credentials.
        When:
            - fortisiem-watchlist-entry-delete command called.
        Then:
            - Validate outputs' fields.
    """
    from FortiSIEMV2 import FortiSIEMClient, watchlist_entry_delete_command
    client: FortiSIEMClient = mock_client()
    mock_response = load_json_mock_response('delete_entry.json')
    requests_mock.post(f'{client._base_url}watchlist/entry/delete', json=mock_response)
    results = watchlist_entry_delete_command(client, {
        "entry_id": 11111
    })
    readable_output = results[0].readable_output
    assert readable_output == 'The entry 11111 were deleted successfully.'


def test_get_entry(requests_mock):
    """
    Scenario: Get entry.
    Given:
        - User has provided valid credentials.
        - User has provided entry ID.
    When:
        - fortisiem-watchlist-entry-get command called.
    Then:
        - Ensure number of items is correct.
        - Ensure outputs prefix is correct.
        - Validate outputs' fields.
    """
    from FortiSIEMV2 import FortiSIEMClient, watchlist_entry_get_command
    client: FortiSIEMClient = mock_client()
    mock_response = load_json_mock_response('get_entry.json')
    entry_id = 55555
    requests_mock.get(f'{client._base_url}watchlist/entry/{entry_id}', json=mock_response)
    results = watchlist_entry_get_command(client, {
        "entry_id": entry_id
    })
    outputs = results[0].outputs
    assert results[0].outputs_prefix == 'FortiSIEM.WatchlistEntry'
    assert len(outputs) == 1
    assert outputs[0]['id'] == entry_id
