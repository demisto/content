import json
from unittest.mock import patch
from freezegun import freeze_time
import defusedxml.ElementTree as defused_ET

import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
import pytest

'''MOCK PARAMETERS '''
SERVER_URL = "https://192.168.30.124"
BASE_URL = f'{SERVER_URL}/phoenix/rest'
USERNAME = 'TEST_USERNAME'
PASSWORD = 'XXXX'
QUERY = "eventId=123"
IP_ADDRESS_1 = '1.1.1.1'
IP_ADDRESS_2 = '2.2.2.2'


def load_json_mock_response(file_name: str) -> dict:
    """
    Load mock file that simulates an API response.
    Args:
        file_name (str): Name of the mock response JSON file to return.
    Returns:
        str: Mock file content.
    """
    with open(f'test_data/{file_name}', encoding='utf-8') as mock_file:
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

    top = defused_ET.parse(file_path)
    return ET.tostring(top.getroot(), encoding='utf8').decode("utf-8")


def mock_client():
    from FortiSIEMV2 import FortiSIEMClient
    return FortiSIEMClient(SERVER_URL, True, False, {}, (USERNAME, PASSWORD))


@pytest.mark.parametrize("mock_response_file,command_arguments,expected_devices_number,expected_device_name",
                         [
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
        'ips': IP_ADDRESS_1
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


@pytest.mark.parametrize("command_arguments,expected_response,expected_msg",
                         [({"incident_id": "123", "comment": "test-success"},
                           "OK", "successfully updated")
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
    assert outputs[0]['id'] == "1111"
    assert outputs[0]['attributes']['Reporting IP'] == '192.168.1.1'
    assert outputs[1]['id'] == "9071234812007542512"
    assert outputs[1]['attributes']['Reporting IP'] == '192.168.1.2'


@pytest.mark.parametrize(
    "command_arguments,response_file,suffix_url,watchlist_number,watchlist_id,watchlist_display_name",
    [({"limit": "2"},
      'list_watchlist.json', 'watchlist/all', 2, 111, "Accounts Locked"),
     ({"entry_value": "192.168.1.1"},
      'list_watchlist2.json', 'watchlist/value', 1, 112, "Port Scanners")
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


@pytest.mark.parametrize("command_arguments,response_file,suffix_url,watchlist_id,watchlist_display_name",
                         [({"watchlist_ids": "111"},
                           'get_watchlist.json', 'watchlist/111', 111, "Accounts Locked"),
                          ({"entry_id": "55555"},
                           'list_watchlist2.json', 'watchlist/byEntry/55555', 112, "Port Scanners")])
def test_get_watchlist(command_arguments, response_file, suffix_url, watchlist_id, watchlist_display_name,
                       requests_mock):
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
        "entry_ids": 11111
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
        "entry_ids": entry_id
    })
    outputs = results[0].outputs
    assert results[0].outputs_prefix == 'FortiSIEM.WatchlistEntry'
    assert len(outputs) == 1
    assert outputs[0]['id'] == entry_id


def test_events_search_init(requests_mock):
    """
    Scenario: Initiate events search query..
    Given:
        - User has provided valid credentials.
        - User has provided valid query.
    When:
        - fortisiem-event-search command called.
    Then:
        - Ensure number of items is correct.
        - Ensure outputs prefix is correct.
        - Validate outputs' fields.
    """
    from FortiSIEMV2 import FortiSIEMClient, events_search_init_command
    client: FortiSIEMClient = mock_client()
    query_id = '10931,1638796483313'
    query = "eventId='9071234812007542512'"
    from_time = "2021-10-12"
    to_time = "2022=-02-10"
    requests_mock.post(f'{client._base_url}query/eventQuery', text=query_id)
    results = events_search_init_command(client, {
        "query": query,
        "from_time": from_time,
        "to_time": to_time,
    })
    outputs = results.outputs
    assert results.outputs_prefix == 'FortiSIEM.EventsSearchInit'
    assert len(outputs) == 1
    assert outputs['search_id'] == query_id


def test_events_search_status(requests_mock):
    """
    Scenario: Get events search query status.
    Given:
        - User has provided valid credentials.
        - User has provided valid search ID.
    When:
        - fortisiem-event-search-status command called.
    Then:
        - Ensure number of items is correct.
        - Ensure outputs prefix is correct.
        - Validate outputs' fields.
    """
    from FortiSIEMV2 import FortiSIEMClient, events_search_status_command
    client: FortiSIEMClient = mock_client()
    search_id = '10931,1638796483313'
    mock_response = '100'
    requests_mock.get(f'{client._base_url}query/progress/{search_id}', text=mock_response)
    results = events_search_status_command(client, {
        "search_id": search_id
    })
    outputs = results.outputs
    assert results.outputs_prefix == 'FortiSIEM.EventsSearchStatus'
    assert len(outputs) == 2
    assert outputs['percentage_status'] == mock_response


def test_events_search_results(requests_mock):
    """
    Scenario: Retrieve the events that returned from the specified search query ID.
    Given:
        - User has provided valid credentials.
        - User has provided search ID.
    When:
        -  'fortisiem-event-search-results' command called.
    Then:
        - Ensure number of items is correct.
        - Ensure outputs prefix is correct.
        - Validate outputs' fields.
    """
    from FortiSIEMV2 import FortiSIEMClient, events_search_results_command
    client: FortiSIEMClient = mock_client()
    mock_response = load_xml_mock_response('list_events_via_search_query.xml')
    start_index = 0
    limit = 1
    search_id = '47189,1638796483313'
    requests_mock.get(f'{client._base_url}query/events/{search_id}/{start_index}/{limit}', text=mock_response)
    result = events_search_results_command(client, {
        "search_id": search_id,
        "limit": limit,
        "page": 1
    })
    outputs = result.outputs
    assert len(outputs) == 1
    assert result.outputs_prefix == 'FortiSIEM.Event'
    assert outputs[0]['id'] == "9071234812100595667"
    assert outputs[0]['attributes']['reptDevIpAddr'] == '192.168.1.1'


@pytest.mark.parametrize("incident_attrib,original_key,formatted_key",
                         [("incidentTarget", "hostName", "target_hostName"),
                          ("incidentSrc", "hostIpAddr", "source_ipAddr")])
def test_build_readable_attribute_key(incident_attrib, original_key, formatted_key):
    """
    Scenario: Formatting nested attribute name to be more readable, and convenient to display in fetch incident command.
    For the input of "srcIpAddr", "incidentSrc" the formatted key will be: "source_ipAddr".
    Given:
        - Incident attribute name.
        - The nested key of the value the resides in the incident attribute.
    When:
        -  During fetch incidents command is invoked.
    Then:
        - Validate method's output.
    """
    from FortiSIEMV2 import build_readable_attribute_key
    result = build_readable_attribute_key(original_key, incident_attrib)
    assert result == formatted_key


@pytest.mark.parametrize("args,expected_output",
                         [({"extended_data": True,
                            "eventId": "111",
                            "eventType": "ASA-Built-Conn"},
                           'eventId = "111" AND eventType = "ASA-Built-Conn"'),
                          ({"query": "eventId!=111", "extended_data": False}, '')])
def test_build_constraint_from_args(args, expected_output):
    """
    Building a constraint for the search query.
    Given:
        - 'fortisiem-event-search' arguments.
    When:
        -  'fortisiem-event-search' command called.
    Then:
        - Validate method's output.
    """
    from FortiSIEMV2 import build_constraint_from_args
    result = build_constraint_from_args(args)
    assert result == expected_output


@pytest.mark.commands
@freeze_time(time.ctime(1646205070))
@pytest.mark.parametrize("last_run,incidents_file,fetch_with_events,expected_output",
                         [({}, "fetch_incidents.json", False, {
                             'incidents_number': 10,
                             'events_number': 0,
                             'last_run': {
                                 'create_time': 1646105070000,
                                 'last_incidents': [1, 2, 3, 4, 5, 6, 7, 8, 9, 10],
                                 'start_index': 0
                             }
                         }), ({'create_time': 1646094600000, 'last_incidents': [1, 2, 3, 4, 5],
                               'start_index': 0},
                              "fetch_incidents.json", False, {
                                  'incidents_number': 5,
                                  'events_number': 0,
                                  'last_run': {
                                      'create_time': 1646105070000,
                                      'last_incidents': [6, 7, 8, 9, 10],
                                      'start_index': 0
                                  }}
                              ), ({'create_time': 1646105070000, 'last_incidents': [1, 2, 3, 4, 5, 6, 7, 8, 9, 10],
                                   'start_index': 0}, 'fetch_incidents_empty.json', False,
                                  {'incidents_number': 0,
                                   'events_number': 0,
                                   'last_run': {
                                       'create_time': 1646105070000,
                                       'last_incidents': [1, 2, 3, 4, 5, 6, 7, 8, 9, 10],
                                       'start_index': 0
                                   }
                                   }), (
                                  {}, "fetch_incidents.json", True, {
                                      'incidents_number': 10,
                                      'events_number': 5,
                                      'last_run': {
                                          'create_time': 1646105070000,
                                          'last_incidents': [1, 2, 3, 4, 5, 6, 7, 8, 9, 10],
                                          'start_index': 0
                                      }
                                  }), (
                                  {
                                      'last_incidents': [1, 2, 3, 4, 5, 6, 7, 8, 9, 10],
                                      'start_index': 0,
                                      'create_time': 1646092830000},
                                  "fetch_incidents_same_time.json", False, {
                                      'incidents_number': 5,
                                      'events_number': 0,
                                      'last_run': {
                                          'last_incidents': [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
                                          'start_index': 5,
                                          'create_time': 1646092830000
                                      }})])
def test_fetch_incidents(last_run, incidents_file, fetch_with_events, expected_output, requests_mock):
    """
    Fetching incidents.
    Given:
        - 'fetch-incidents' arguments.
    Scenarios:
        - Last run do not exist.
        - Last run exists
        - No incidents to fetch.
        - Incidents to fetch with events.
        - New incidents came in the same time like prev last incidents.
    Then:
        - Validate incidents & updated last run obj.
    """
    from FortiSIEMV2 import FortiSIEMClient, fetch_incidents
    client: FortiSIEMClient = mock_client()
    status_list = ['Active']
    max_fetch = 10
    max_events_fetch = 5
    first_fetch = "1 week"

    mock_response = load_json_mock_response(incidents_file)
    requests_mock.post(f'{client._base_url}pub/incident', json=mock_response)
    if fetch_with_events:
        events_mock_response = load_json_mock_response("triggered_events.json")
        requests_mock.get(f'{client._base_url}pub/incident/triggeringEvents', json=events_mock_response)

    incidents, updated_last_run = fetch_incidents(client, max_fetch, first_fetch, status_list, fetch_with_events,
                                                  max_events_fetch, last_run)

    expected_incidents_number = expected_output.get('incidents_number')
    expected_events_number = expected_output.get('events_number')
    expected_last_run = expected_output.get('last_run')
    incident_raw_json = json.loads(incidents[0]['rawJSON']) if incidents else {}
    events = incident_raw_json.get('events')
    events_number = len(events) if events else 0
    assert len(incidents) == expected_incidents_number
    assert updated_last_run == expected_last_run
    assert events_number == expected_events_number


@pytest.mark.commands
@freeze_time(time.ctime(1646240070))
@patch('FortiSIEMV2.FortiSIEMClient.fetch_incidents_request')
def test_fetch_incidents_with_pagination(post_mock):
    """
    Fetching incidents in pagination use case.
    Given:
        - 'fetch-incidents' arguments.
    Scenarios:
        - Fetch incidents which retrieved from different pages.
    Then:
        - Validate incidents & updated last run obj.
    """
    from FortiSIEMV2 import FortiSIEMClient, fetch_incidents
    client: FortiSIEMClient = mock_client()
    status_list = ['Active']
    max_fetch = 5
    max_events_fetch = 5
    first_fetch = "3 hours"

    mocked_responses = [
        load_json_mock_response('fetch_incidents_paging_1.json'),
        load_json_mock_response('fetch_incidents_paging_2.json')
    ]

    post_mock.side_effect = mocked_responses
    incidents, updated_last_run = fetch_incidents(client, max_fetch, first_fetch, status_list, False, max_events_fetch,
                                                  {})
    assert len(incidents) == 5
    assert updated_last_run['create_time'] == 1646237070000
    assert updated_last_run['last_incidents'] == [9, 10, 11, 12, 13]


@pytest.mark.parametrize('nested_attr, expected_result', [
    ('key:value', ('key', 'value')),
    ('key:value:extra', ('key', 'value')),
    ('', (None, None)),
    ('key', (None, None)),
])
def test_format_nested_incident_attribute(nested_attr, expected_result):
    """
    Formatting incident attributes.
    Given:
        - Some incident attributes.
    When:
        - format_nested_incident_attribute is running.
    Then:
        - Check that the formatted incident attribute is as expected.
    """
    from FortiSIEMV2 import format_nested_incident_attribute

    assert format_nested_incident_attribute(nested_attr) == expected_result


@pytest.mark.parametrize('events_mock_response, expected_result', [
    ({'result': {'description': 'The incident detail was not found for incident 123465'}}, 0),
    (load_json_mock_response("triggered_events.json"), 5),
    (load_json_mock_response("triggered_events_dict.json"), 5),
])
def test_get_related_events_for_fetch_command(events_mock_response, expected_result, requests_mock):
    """
    Fetching events per incident.
    Given:
        - Incident ID with/without events.
    When:
        - get_related_events_for_fetch_command is running.
    Then:
        - Check that the sum of the events is as expected.
    """
    from FortiSIEMV2 import FortiSIEMClient, get_related_events_for_fetch_command
    client: FortiSIEMClient = mock_client()
    requests_mock.get(f'{client._base_url}pub/incident/triggeringEvents', json=events_mock_response)

    assert len(get_related_events_for_fetch_command('123456', 20, client)) == expected_result
