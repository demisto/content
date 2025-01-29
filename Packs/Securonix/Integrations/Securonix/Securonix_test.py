import json
from tempfile import mkdtemp

import demistomock as demisto
import pytest
from CommonServerPython import *

from Securonix import reformat_resource_groups_outputs, reformat_outputs, parse_data_arr, Client, list_workflows, \
    get_default_assignee_for_workflow, list_possible_threat_actions, list_resource_groups, list_users, \
    list_incidents, get_incident, create_incident, perform_action_on_incident, list_watchlists, get_watchlist, \
    create_watchlist, check_entity_in_watchlist, add_entity_to_watchlist, get_incident_name, fetch_securonix_incident, \
    fetch_securonix_threat, list_threats, get_incident_activity_history, list_whitelists, get_whitelist_entry, \
    create_whitelist, delete_lookup_table_config_and_data, add_whitelist_entry, list_lookup_tables, \
    delete_whitelist_entry, add_entry_to_lookup_table, list_lookup_table_entries, create_lookup_table, \
    get_incident_attachments, list_violation_data, get_incident_workflow, get_incident_status, \
    get_incident_available_actions, add_comment_to_incident, get_modified_remote_data_command, \
    get_remote_data_command, update_remote_system, create_xsoar_to_securonix_state_mapping, delete_lookup_table_entries, \
    main, validate_mirroring_parameters, filter_attachment_activity_entries, list_activity_data

from test_data.response_constants import RESPONSE_LIST_WORKFLOWS, RESPONSE_DEFAULT_ASSIGNEE, \
    RESPONSE_POSSIBLE_THREAT_ACTIONS, RESPONSE_LIST_RESOURCE_GROUPS, RESPONSE_LIST_USERS, RESPONSE_LIST_INCIDENT, \
    RESPONSE_GET_INCIDENT, RESPONSE_CREATE_INCIDENT, RESPONSE_PERFORM_ACTION_ON_INCIDENT, RESPONSE_LIST_WATCHLISTS, \
    RESPONSE_GET_WATCHLIST, RESPONSE_CREATE_WATCHLIST, RESPONSE_ENTITY_IN_WATCHLIST, RESPONSE_ADD_ENTITY_TO_WATCHLIST, \
    RESPONSE_FETCH_INCIDENT_ITEM, RESPONSE_FETCH_INCIDENT_ITEM_MULTIPLE_REASONS, RESPONSE_FETCH_INCIDENTS, \
    RESPONSE_FETCH_INCIDENT_ITEM_NO_THREAT_MODEL, RESPONSE_FETCH_INCIDENT_ITEM_VERSION_6_4, RESPONSE_LIST_THREATS, \
    RESPONSE_FETCH_THREATS, RESPONSE_GET_INCIDENT_ACTIVITY_HISTORY_6_4, RESPONSE_LIST_WHITELISTS_ENTRY, \
    RESPONSE_GET_WHITELIST_ENTRY, RESPONSE_CREATE_WHITELIST, RESPONSE_DELETE_LOOKUP_TABLE_CONFIG_AND_DATA, \
    get_mock_create_lookup_table_response, \
    RESPONSE_ADD_WHITELIST_ENTRY_6_4, RESPONSE_LOOKUP_TABLE_LIST, RESPONSE_DELETE_WHITELIST_ENTRY, \
    RESPONSE_LOOKUP_TABLE_ENTRY_ADD, RESPONSE_LOOKUP_TABLE_ENTRIES_LIST, get_mock_attachment_response, \
    RESPONSE_LIST_VIOLATION_6_4, RESPONSE_GET_INCIDENT_WORKFLOW, RESPONSE_GET_INCIDENT_STATUS, \
    RESPONSE_GET_INCIDENT_AVAILABLE_ACTIONS, RESPONSE_ADD_COMMENT_TO_INCIDENT, RESPONSE_LIST_ACTIVITY, \
    MIRROR_RESPONSE_GET_INCIDENT_ACTIVITY_HISTORY, MIRROR_ENTRIES, RESPONSE_DELETE_LOOKUP_ENTRIES_DELETE, \
    DELETE_LOOKUP_TABLE_ENTRIES_INVALID_LOOKUP_NAME, DELETE_LOOKUP_TABLE_ENTRIES_INVALID_LOOKUP_KEYS, \
    MIRROR_RESPONSE_GET_INCIDENT_ACTIVITY_HISTORY_ATTACHMENT, RESPONSE_LIST_ACTIVITY_NO_DATA

from test_data.result_constants import EXPECTED_FETCH_INCIDENT, EXPECTED_LIST_WORKFLOWS, EXPECTED_DEFAULT_ASSIGNEE, \
    EXPECTED_POSSIBLE_THREAT_ACTIONS, EXPECTED_LIST_RESOURCE_GROUPS, EXPECTED_LIST_USERS, EXPECTED_LIST_INCIDENT, \
    EXPECTED_GET_INCIDENT, EXPECTED_CREATE_INCIDENT, EXPECTED_PERFORM_ACTION_ON_INCIDENT, \
    EXPECTED_LIST_WATCHLISTS, EXPECTED_GET_WATCHLIST, EXPECTED_CREATE_WATCHLIST, EXPECTED_ENTITY_IN_WATCHLIST, \
    EXPECTED_ADD_ENTITY_TO_WATCHLIST, EXPECTED_LIST_THREATS, EXPECTED_GET_INCIDENT_ACTIVITY_HISTORY_6_4, \
    EXPECTED_LIST_WHITELISTS_ENTRY, EXPECTED_GET_WHITELIST_ENTRY, EXPECTED_CREATE_WHITELIST, \
    EXPECTED_DELETE_LOOKUP_TABLE_CONFIG_AND_DATA, EXPECTED_ADD_WHITELIST_ENTRY_6_4, EXPECTED_LOOKUP_TABLE_LIST, \
    EXPECTED_DELETE_WHITELIST_ENTRY, EXPECTED_LOOKUP_TABLE_ENTRY_ADD, EXPECTED_LOOKUP_TABLE_ENTRIES_LIST, \
    EXPECTED_CREATE_LOOKUP_TABLE, EXPECTED_LIST_ACTIVITY_NO_DATA, \
    EXPECTED_GET_INCIDENT_ATTACHMENT_HISTORY_6_4, EXPECTED_LIST_VIOLATION_DATA_6_4, EXPECTED_GET_INCIDENT_WORKFLOW, \
    EXPECTED_GET_INCIDENT_STATUS, EXPECTED_GET_INCIDENT_AVAILABLE_ACTIONS, EXPECTED_ADD_COMMENT_TO_INCIDENT, \
    EXPECTED_XSOAR_STATE_MAPPING, EXPECTED_DELETE_LOOKUP_ENTRIES_DELETE, EXPECTED_LIST_ACTIVITY


@pytest.fixture()
def mock_client(mocker):
    """Mock a client object with required data to mock."""
    mocker.patch.object(Client, '_generate_token', return_value='test_token')
    client = Client('tenant', 'https://127.0.0.1/Snypr/ws', 'username', 'password', 'verify', 'proxies', 0, 0, 'Fixed')

    return client


def perform_action_on_incident_request_side_effect(*args, **kwargs):
    """Side effect function to replicate perform_action_on_incident_request function."""
    assert kwargs['incident_id'] == '1234'
    assert kwargs['action_parameters'] == ''
    assert kwargs['action'] == 'Close Incident'
    return 'Action performed successfully.'


def add_comment_to_incident_request_side_effect(*args, **kwargs):
    """Side effect function to replicate add_comment_request function."""
    assert kwargs['comment'] == '[Mirrored From XSOAR] XSOAR Incident ID: 345\nClosed By: admin\nClose Reason: ' \
                                'Resolved\nClose Notes: Closing XSOAR incident'
    return 'Comment was added to the incident successfully.'


def test_reformat_resource_groups_outputs():
    assert reformat_resource_groups_outputs('rg_category') == 'ResourceGroupCategory'
    assert reformat_resource_groups_outputs('rg_id') == 'ResourceGroupID'
    assert reformat_resource_groups_outputs('rg_name') == 'ResourceGroupName'
    assert reformat_resource_groups_outputs('rg_vendor') == 'ResourceGroupVendor'
    assert reformat_resource_groups_outputs('rg_functionality') == 'ResourceGroupFunctionality'
    assert reformat_resource_groups_outputs('rg_resourcetypeid') == 'ResourceGroupTypeID'


def test_reformat_outputs():
    assert reformat_outputs('id') == 'ID'
    assert reformat_outputs('eventId') == 'EventID'
    assert reformat_outputs('entityId') == 'EntityID'
    assert reformat_outputs('jobId') == 'JobID'
    assert reformat_outputs('U_name') == 'Name'
    assert reformat_outputs('u_hostname') == 'Hostname'
    assert reformat_outputs('invalidEventAction') == 'Invalid Event Action'


def test_parse_data_arr():
    outputs = {
        'employeeid': '123',
        'employeetype': 'user'
    }

    parsed_readable, parsed_outputs = parse_data_arr(outputs)

    expected_readable = {
        'EmployeeID': '123',
        'Employeetype': 'user'
    }
    expected_outputs = {
        'EmployeeID': '123',
        'Employeetype': 'user'
    }
    assert parsed_readable == expected_readable
    assert parsed_outputs == expected_outputs


def test_get_incident_name():
    expected_incident_name = 'Uploads to personal websites: 10134'
    assert expected_incident_name == get_incident_name(RESPONSE_FETCH_INCIDENT_ITEM, '10134', '12')

    expected_multiple_reasons_incident_name = 'Uploads to personal websites, Emails Sent to Personal Email: 10135'
    assert expected_multiple_reasons_incident_name == get_incident_name(RESPONSE_FETCH_INCIDENT_ITEM_MULTIPLE_REASONS,
                                                                        '10135', '12')

    expected_multiple_reasons_incident_name = 'Securonix Incident 10135, Violator ID: 12'
    assert expected_multiple_reasons_incident_name == get_incident_name(RESPONSE_FETCH_INCIDENT_ITEM_NO_THREAT_MODEL,
                                                                        '10135', '12')

    expected_multiple_reasons_incident_name = 'Data egress via network uploads: 10135'
    assert expected_multiple_reasons_incident_name == get_incident_name(RESPONSE_FETCH_INCIDENT_ITEM_VERSION_6_4,
                                                                        '10135', '12')


def test_fetch_securonix_incidents(mocker):
    """Unit test
    Given
    - fetch incidents command
    - command args
    - command raw response
    When
    - mock the Client's send_request.
    Then
    - run the fetch incidents command using the Client
    Validate the length of the results.
    Validate the incident name
    Validate that the severity is low (1)
    """
    mocker.patch.object(Client, '_generate_token')
    client = Client('tenant', 'server_url', 'username', 'password', 'verify', 'proxies', 0, 0, 'Fixed')
    mocker.patch.object(client, 'list_incidents_request', return_value=RESPONSE_FETCH_INCIDENTS)
    incidents = fetch_securonix_incident(client, fetch_time='1 hour', incident_status='open', default_severity='',
                                         max_fetch='200', last_run={}, close_incident=False)
    assert len(incidents) == 1
    assert incidents[0].get('name') == 'Emails with large File attachments: 100107'
    assert incidents[0].get('severity') == 1
    assert json.loads(incidents[0].get('rawJSON')) == EXPECTED_FETCH_INCIDENT


def test_fetch_securonix_incidents_with_default_severity(mocker):
    """Unit test
    Given
    - fetch incidents command
    - command args
    - command raw response
    When
    - mock the Client's send_request.
    Then
    - run the fetch incidents command using the Client
    Validate that the severity is high (3)
    """
    mocker.patch.object(Client, '_generate_token')
    client = Client('tenant', 'server_url', 'username', 'password', 'verify', 'proxies', 0, 0, 'Fixed')
    mocker.patch.object(client, 'list_incidents_request', return_value=RESPONSE_FETCH_INCIDENTS)
    incidents = fetch_securonix_incident(client, fetch_time='1 hour', incident_status='open', default_severity='High',
                                         max_fetch='200', last_run={}, close_incident=False)
    assert len(incidents) == 1
    assert incidents[0].get('severity') == 3


def test_fetch_securonix_incidents_is_already_fetched(mocker):
    """Unit test
    Given
    - fetch incidents command
    - command args
    - command raw response
    When
    - mock the already_fetched and time.
    - mock the Client's send_request.
    Then
    - run the fetch incidents command using the Client
    Validate The length of the results.
    """
    mocker.patch.object(Client, '_generate_token')
    client = Client('tenant', 'server_url', 'username', 'password', 'verify', 'proxies', 0, 0, 'Fixed')
    mocker.patch.object(client, 'list_incidents_request', return_value=RESPONSE_FETCH_INCIDENTS)
    incidents = fetch_securonix_incident(client, fetch_time='1 hour', incident_status='open', default_severity='',
                                         max_fetch='200',
                                         last_run={'already_fetched': ['100107'],
                                                   'from': '1675900800000',
                                                   'to': '1676367548000',
                                                   'offset': 1}, close_incident=False)
    assert len(incidents) == 0


def test_fetch_securonix_threats(mocker):
    """Unit test
    Given
    - fetch threats command
    - command args
    - command raw response
    When
    - mock the Client's send_request.
    Then
    - run the fetch threats command using the Client
    Validate the length of the results.
    Validate the incident name
    """
    mocker.patch.object(Client, '_generate_token')
    client = Client('tenant', 'server_url', 'username', 'password', False, False, 0, 0, 'Fixed')
    mocker.patch.object(client, 'list_threats_request', return_value=RESPONSE_FETCH_THREATS)
    incidents = fetch_securonix_threat(client, fetch_time='1 hour', tenant_name='Response-Automation',
                                       max_fetch='200', last_run={})
    assert len(incidents) == 1
    assert incidents[0].get('name') == 'TM_Response-PB-ActivityAccount-Manual, Entity ID: VIOLATOR5-1673852881421'


def test_fetch_securonix_threat_is_already_fetched(mocker):
    """Unit test
    Given
    - fetch threats command
    - command args
    - command raw response
    When
    - mock the already_fetched and time.
    - mock the Client's send_request.
    Then
    - run the fetch incidents command using the Client
    Validate The length of the results.
    """
    mocker.patch.object(Client, '_generate_token')
    client = Client('tenant', 'server_url', 'username', 'password', 'verify', 'proxies', 0, 0, 'Fixed')
    mocker.patch.object(client, 'list_threats_request', return_value=RESPONSE_FETCH_THREATS)
    incidents = fetch_securonix_threat(client, fetch_time='1 hour', tenant_name='Response-Automation',
                                       max_fetch='200',
                                       last_run={'already_fetched': [(
                                           "VIOLATOR5-1673852881421", "RES10-RESOURCE-302184",
                                           "Res-Playbook", "RES-PLAYBOOK-DS-AUTOMATION",
                                           "Response-PB-ActivityAccount-Manual")],
                                           'time': "2020-06-07T08:32:41.679579Z"})
    assert len(incidents) == 0


def test_module(mocker):
    """
    Given
    - Securonix test module
    When
    - mock the demisto params.
    - mock the Client's generate_token
    - mock the Client's list_workflows_request
    - mock the Client's list_incidents_request
    Then
    - run the test_module command using the Client
    Validate The response is ok.
    """
    from Securonix import test_module as module
    mocker.patch.object(demisto, 'params', return_value={'isFetch': True, 'fetch_time': '1 hour', 'max_fetch': '200'})
    mocker.patch.object(Client, '_generate_token')
    client = Client('tenant', 'server_url', 'username', 'password', 'verify', 'proxies', 0, 0, 'Fixed')
    mocker.patch.object(client, 'list_workflows_request', return_value=RESPONSE_LIST_WORKFLOWS)
    mocker.patch.object(client, 'list_incidents_request', return_value=RESPONSE_LIST_INCIDENT)
    result = module(client)
    assert result == 'ok'


@pytest.mark.parametrize('command, args, response, expected_result', [
    (list_workflows, {}, RESPONSE_LIST_WORKFLOWS, EXPECTED_LIST_WORKFLOWS),
    (get_default_assignee_for_workflow, {'workflow': 'SOCTeamReview'}, RESPONSE_DEFAULT_ASSIGNEE,
     EXPECTED_DEFAULT_ASSIGNEE),
    (list_possible_threat_actions, {}, RESPONSE_POSSIBLE_THREAT_ACTIONS, EXPECTED_POSSIBLE_THREAT_ACTIONS),
    (list_resource_groups, {}, RESPONSE_LIST_RESOURCE_GROUPS, EXPECTED_LIST_RESOURCE_GROUPS),
    (list_users, {}, RESPONSE_LIST_USERS, EXPECTED_LIST_USERS),
    (list_incidents, {"from": "1 year"}, RESPONSE_LIST_INCIDENT, EXPECTED_LIST_INCIDENT),
    (get_incident, {'incident_id': '1234'}, RESPONSE_GET_INCIDENT, EXPECTED_GET_INCIDENT),
    (create_incident, {'action_name': "Mark as concern and create incident", 'entity_name': 'name',
                       'entity_type': 'Users', 'resource_group': "BLUECOAT", 'resource_name': "BLUECOAT",
                       'violation_name': "Uploads to personal Websites", 'workflow': "SOCTeamReview"},
     RESPONSE_CREATE_INCIDENT, EXPECTED_CREATE_INCIDENT),
    (perform_action_on_incident, {'action': "ASSIGN TO ANALYST", 'incident_id': '1234',
                                  'action_parameters': "assigntouserid={user_id},assignedTo=USER"},
     RESPONSE_PERFORM_ACTION_ON_INCIDENT, EXPECTED_PERFORM_ACTION_ON_INCIDENT),
    (list_watchlists, {}, RESPONSE_LIST_WATCHLISTS, EXPECTED_LIST_WATCHLISTS),
    (get_watchlist, {'watchlist_name': "Flight RiskUsers"}, RESPONSE_GET_WATCHLIST, EXPECTED_GET_WATCHLIST),
    (create_watchlist, {'watchlist_name': 'test234'}, RESPONSE_CREATE_WATCHLIST, EXPECTED_CREATE_WATCHLIST),
    (check_entity_in_watchlist, {'watchlist_name': 'test234', 'entity_name': '1002'}, RESPONSE_ENTITY_IN_WATCHLIST,
     EXPECTED_ENTITY_IN_WATCHLIST),
    (add_entity_to_watchlist, {'watchlist_name': 'test234', 'entity_name': '1004', 'entity_type': 'Users'},
     RESPONSE_ADD_ENTITY_TO_WATCHLIST, EXPECTED_ADD_ENTITY_TO_WATCHLIST),
    (list_threats, {'date_from': '1 day', 'tenant_name': 'Response-Automation'}, RESPONSE_LIST_THREATS,
     EXPECTED_LIST_THREATS),
    (get_incident_activity_history, {'incident_id': 'test_id'}, RESPONSE_GET_INCIDENT_ACTIVITY_HISTORY_6_4,
     EXPECTED_GET_INCIDENT_ACTIVITY_HISTORY_6_4),
    (list_whitelists, {}, RESPONSE_LIST_WHITELISTS_ENTRY, EXPECTED_LIST_WHITELISTS_ENTRY),
    (get_whitelist_entry, {'whitelist_name': 'test_whitelist'}, RESPONSE_GET_WHITELIST_ENTRY,
     EXPECTED_GET_WHITELIST_ENTRY),
    (create_whitelist, {'whitelist_name': 'test_whitelist', 'entity_type': 'Users'}, RESPONSE_CREATE_WHITELIST,
     EXPECTED_CREATE_WHITELIST),
    (add_whitelist_entry,
     {'whitelistname': 'whitelistdemo1', 'tenantname': 'test_tenant', 'whitelist_type': 'Global',
      'entity_type': 'Users',
      'entity_id': 'f??abc', 'exipry_date': '10/02/2023'}, RESPONSE_ADD_WHITELIST_ENTRY_6_4,
     EXPECTED_ADD_WHITELIST_ENTRY_6_4),
    (delete_lookup_table_config_and_data, {'name': 'test'}, RESPONSE_DELETE_LOOKUP_TABLE_CONFIG_AND_DATA,
     EXPECTED_DELETE_LOOKUP_TABLE_CONFIG_AND_DATA),
    (list_lookup_tables, {'max': '2', 'offset': '0'}, RESPONSE_LOOKUP_TABLE_LIST, EXPECTED_LOOKUP_TABLE_LIST),
    (delete_whitelist_entry, {'whitelist_name': 'test_whitelist', 'entity_id': 'test_id', 'tenant_name': 'test_tenant'},
     RESPONSE_DELETE_WHITELIST_ENTRY, EXPECTED_DELETE_WHITELIST_ENTRY),
    (add_entry_to_lookup_table, {'name': 'XSOAR_TEST', 'json_data': json.dumps([{"key1": "value1"}])},
     RESPONSE_LOOKUP_TABLE_ENTRY_ADD, EXPECTED_LOOKUP_TABLE_ENTRY_ADD),
    (list_lookup_table_entries, {'name': 'TEST_XSOAR', 'max': '2'}, RESPONSE_LOOKUP_TABLE_ENTRIES_LIST,
     EXPECTED_LOOKUP_TABLE_ENTRIES_LIST),
    (create_lookup_table,
     {'name': 'test_table', 'field_names': 'accname,id', 'key': 'accname,id', 'tenant_name': 'test_tenant',
      'scope': 'Global'}, get_mock_create_lookup_table_response().text, EXPECTED_CREATE_LOOKUP_TABLE),
    (list_violation_data, {'from': "01/17/2022 00:00:00", 'query': 'policy="Response-Account-\\?*AutoPlay"',
                           'to': "01/17/2023 00:00:20"}, RESPONSE_LIST_VIOLATION_6_4,
     EXPECTED_LIST_VIOLATION_DATA_6_4),
    (list_violation_data, {'query': ' index  = violation and policy="Response-Account-AutoPlay"',
                           'from': "01/17/2022 00:00:00", 'to': "01/17/2023 00:00:20"}, RESPONSE_LIST_VIOLATION_6_4,
     EXPECTED_LIST_VIOLATION_DATA_6_4),
    (list_activity_data, {'from': "01/12/2024 10:00:00", 'query': 'hostname = "HOST\\?*.com"',
                          'to': "01/15/2024 12:01:00"}, RESPONSE_LIST_ACTIVITY, EXPECTED_LIST_ACTIVITY),
    (list_activity_data, {'query': ' index  = activity and hostname = "HOST.com"', 'from': "01/12/2024 10:00:00",
                          'to': "01/15/2024 12:01:00"}, RESPONSE_LIST_ACTIVITY, EXPECTED_LIST_ACTIVITY),
    (list_activity_data, {'query': ' index  = activity and hostname = "HOST.com"', 'from': "01/12/2024 10:00:00",
                          'to': "01/15/2024 12:01:00"}, RESPONSE_LIST_ACTIVITY_NO_DATA, EXPECTED_LIST_ACTIVITY_NO_DATA),
    (get_incident_attachments, {'incident_id': 'test_id'}, get_mock_attachment_response(),
     EXPECTED_GET_INCIDENT_ATTACHMENT_HISTORY_6_4),
    (get_incident_workflow, {'incident_id': '123456'}, RESPONSE_GET_INCIDENT_WORKFLOW, EXPECTED_GET_INCIDENT_WORKFLOW),
    (get_incident_status, {'incident_id': '123456'}, RESPONSE_GET_INCIDENT_STATUS, EXPECTED_GET_INCIDENT_STATUS),
    (get_incident_available_actions, {'incident_id': '123456'}, RESPONSE_GET_INCIDENT_AVAILABLE_ACTIONS,
     EXPECTED_GET_INCIDENT_AVAILABLE_ACTIONS),
    (add_comment_to_incident, {'incident_id': '123456', 'comment': 'testcomment'},
     RESPONSE_ADD_COMMENT_TO_INCIDENT, EXPECTED_ADD_COMMENT_TO_INCIDENT)
])  # noqa: E124
def test_commands(command, args, response, expected_result, mocker):
    """Unit test for integration commands.
    Integration was build and tested with: SNYPR Version 6.3
    Args:
        command: func name in .py
        args: func args
        response: response as mocked from 'SNYPR 6.3 CU4 Administration Guide'
        expected_result: expected result in demisto
        mocker: mocker object
    """
    mocker.patch.object(Client, '_generate_token')
    client = Client('tenant', 'server_url', 'username', 'password', 'verify', 'proxies', 0, 0, 'Fixed')
    mocker.patch.object(client, 'http_request', return_value=response)
    result = command(client, args)
    if command == get_incident_attachments:
        assert expected_result[0].get('File') == result[1].get('File')
    elif command == list_violation_data:
        assert expected_result == result[0].outputs  # list_violation_data returns CommandResult object
    elif command == add_whitelist_entry or command == create_lookup_table or command == get_incident_workflow or \
            command == get_incident_status or command == get_incident_available_actions \
            or command == add_comment_to_incident:
        assert expected_result == result[0]
    else:
        assert expected_result == result[1]  # entry context is found in the 2nd place in the result of the command


def test_get_modified_remote_data(mocker):
    """Valid incident IDs should be returned by get_modified_remote_data_command."""
    mocker.patch.object(demisto, 'debug')
    mocker.patch.object(Client, '_generate_token')
    client = Client('tenant', 'server_url', 'username', 'password', 'verify', 'proxies', 0, 0, 'Fixed')

    mocker.patch.object(client, 'http_request', return_value=RESPONSE_LIST_INCIDENT)
    result = get_modified_remote_data_command(client, {'lastUpdate': "2022-02-01T00:00:00Z"})

    assert result.modified_incident_ids == [
        record.get('incidentId')
        for record in RESPONSE_LIST_INCIDENT.get('result', {}).get('data', {}).get('incidentItems', [])
    ]


def test_get_remote_data(mocker):
    """The incident should be updated when get_remote_data command is called."""
    mocker.patch.object(demisto, 'debug')
    mocker.patch.object(Client, '_generate_token')
    client = Client('tenant', 'server_url', 'username', 'password', 'verify', 'proxies', 0, 0, 'Fixed')

    args = {'id': '2849604490', 'lastUpdate': "2022-02-01T00:00:00Z"}
    mocker.patch.object(client, 'get_incident_request',
                        return_value=RESPONSE_GET_INCIDENT['result']['data'])
    mocker.patch.object(client, 'get_incident_activity_history_request',
                        return_value=MIRROR_RESPONSE_GET_INCIDENT_ACTIVITY_HISTORY['result']['activityStreamData'])

    res = get_remote_data_command(client, args, ['closed', 'completed'])

    assert res.mirrored_object == RESPONSE_GET_INCIDENT['result']['data']['incidentItems'][0]
    assert res.entries == [
        {
            'Type': 1,
            'Contents': {
                'dbotIncidentClose': True,
                'closeNotes': 'Closing the XSOAR incident as Securonix incident is closed.',
                'closeReason': 'Resolved'
            },
            'ContentsFormat': 'json',
            'Note': True
        },
        {
            'Type': 1,
            'Contents': '[Mirrored From Securonix]\nAdded By: Admin Admin\nAdded At'
                        ': Jan 12, 2023 7:25:38 AM UTC\nComment Content: Incident created'
                        ' while executing playbook - Create Security Incident',
            'ContentsFormat': 'text',
            'Note': True
        }
    ]


def add_comment_to_incident_request(*args):
    """Side effect function to replicate add_comment_request function."""
    assert '[Mirrored From XSOAR] XSOAR Incident ID: 345\nAdded By: Admin\nComment: This is a comment' == args[1]
    return 'Comment was added to the incident successfully.'


def test_upload_entries_update_remote_system_command(mocker):
    """Update remote system command should reflact the entries added to XSOAR incident."""
    mocker.patch.object(demisto, 'debug')
    mocker.patch.object(Client, '_generate_token')
    client = Client('tenant', 'server_url', 'username', 'password', 'verify', 'proxies', 0, 0, 'Fixed')

    args = {'remoteId': '1234', 'data': {'id': '345'}, 'entries': MIRROR_ENTRIES, 'incidentChanged': False, 'delta': {}}
    mocker.patch.object(client, 'add_comment_to_incident_request', side_effect=add_comment_to_incident_request)

    update_remote_system(client, args)


def test_create_xsoar_to_securonix_state_mapping():
    """Test case scenario for successful execution of create_xsoar_to_securonix_state_mapping."""
    args = {
        'active_state_action_mapping': 'Start Investigation',
        'active_state_status_mapping': 'in progress',
        'closed_state_action_mapping': 'Close Incident',
        'closed_state_status_mapping': 'completed'
    }
    result = create_xsoar_to_securonix_state_mapping(args)

    assert result.outputs == EXPECTED_XSOAR_STATE_MAPPING
    assert result.outputs_prefix == "Securonix.StateMapping"


@pytest.mark.parametrize('name,order,err_msg', [
    ('', 'asc', 'Lookup table name is a required argument.'),
    (' ', 'asc', 'Lookup table name is a required argument.'),
    ('test', 'asr', 'Order argument must be "asc" or "desc".')
])
def test_list_lookup_table_entries_for_invalid_arguments(mock_client, name, order, err_msg):
    """Test case to validate that ValueError should be raised for invalid arguments."""
    with pytest.raises(ValueError) as error:
        args = {'name': name, 'order': order}
        list_lookup_table_entries(mock_client, args)

    assert str(error.value) == err_msg


def test_list_lookup_table_entries_verify_default_values(mock_client, mocker):
    """Test case to verify the default values of attribute, max, offset & page_num when no values provided in args."""
    list_lookup_table_mock = mocker.patch.object(Client, 'list_lookup_table_entries_request',
                                                 return_value=RESPONSE_LOOKUP_TABLE_ENTRIES_LIST)
    list_lookup_table_entries(mock_client, {'name': 'test_table'})

    assert list_lookup_table_mock.call_args[1]['attribute'] == 'key'
    assert list_lookup_table_mock.call_args[1]['max_records'] == 15
    assert list_lookup_table_mock.call_args[1]['offset'] == 0
    assert list_lookup_table_mock.call_args[1]['page_num'] == 1
    assert list_lookup_table_mock.call_args[1]['order'] == 'asc'


@pytest.mark.parametrize('name,keys,err_msg', [
    ('', 'key1', 'Lookup table name is a required parameter.'),
    (' ', 'key1', 'Lookup table name is a required parameter.'),
    ('name', '', 'At least one lookup table key is required to execute the command.'),
    ('name', ' ', 'At least one lookup table key is required to execute the command.')
])
def test_delete_lookup_table_entries_for_invalid_arguments(mock_client, name, keys, err_msg):
    """Test case to validate that ValueError should be raised for invalid arguments."""
    with pytest.raises(ValueError) as error:
        args = {'name': name, 'lookup_unique_keys': keys}
        delete_lookup_table_entries(mock_client, args)

    assert str(error.value) == err_msg


@pytest.mark.parametrize('name,keys', [('test_table', 'key1'), ('test_table', 'key1,key2')])
def test_delete_lookup_table_entries_for_valid_arguments(mock_client, mocker, name, keys):
    """Test case to validate that valid human-readable and raw response should be returned for valid arguments."""
    expected_human_readable = f'Successfully deleted following entries from {name}: {", ".join(argToList(keys))}.'

    mocker.patch.object(mock_client, 'http_request', return_value=RESPONSE_DELETE_LOOKUP_ENTRIES_DELETE)
    args = {'name': name, 'lookup_unique_keys': keys}
    resp = delete_lookup_table_entries(mock_client, args)

    assert resp[0] == expected_human_readable
    assert resp[1] == EXPECTED_DELETE_LOOKUP_ENTRIES_DELETE  # As this command doesn't return any context data.
    assert resp[2] == RESPONSE_DELETE_LOOKUP_ENTRIES_DELETE


@pytest.mark.parametrize('name,keys,mock_response', [
    ('test_table', 'key1', DELETE_LOOKUP_TABLE_ENTRIES_INVALID_LOOKUP_NAME),
    ('test_table', 'key1', DELETE_LOOKUP_TABLE_ENTRIES_INVALID_LOOKUP_KEYS)
])
def test_delete_lookup_table_entries_for_bad_request(requests_mock, mock_client, mocker, name, keys, mock_response):
    """Test case to verify that an exception should be raised if invalid name and key value."""
    requests_mock.delete(re.compile("/lookupTable/deleteLookupKeys"), json=mock_response, status_code=500)
    expected_error_msg = f'Error in API call to Securonix 500. Reason: {json.dumps(mock_response)}'

    with pytest.raises(Exception) as error:
        args = {'name': name, 'lookup_unique_keys': keys}
        delete_lookup_table_entries(mock_client, args)

    assert str(error.value) == expected_error_msg


@pytest.mark.parametrize('name,json_data,file_entry_id,err_msg', [
    ('', '{}', '234@2973', 'Lookup table name is a required parameter.'),
    (' ', '{}', '234@2973', 'Lookup table name is a required parameter.'),
    ('test_table', '', '', 'Either JSON data or file entry ID is required to add data to lookup table.'),
    ('test_table', ' ', ' ', 'Either JSON data or file entry ID is required to add data to lookup table.'),
])
def test_add_entry_to_lookup_table_invalid_arguments(mock_client, name, json_data, file_entry_id, err_msg):
    """Test case to verify that ValueError should be raised for invalid arguments."""
    with pytest.raises(ValueError) as error:
        add_entry_to_lookup_table(mock_client, {'name': name, 'json_data': json_data, 'file_entry_id': file_entry_id})

    assert str(error.value) == err_msg


def test_add_entry_to_lookup_table_when_invalid_json_data_provided(mock_client):
    """Test case to verify that Exception should be raised when invalid JSON data is provided."""
    expected_error_message = 'Could not able to parse the provided JSON data. ' \
                             'Error: Expecting value: line 1 column 9 (char 8)'

    with pytest.raises(Exception) as error:
        add_entry_to_lookup_table(mock_client, {'name': 'test_table', 'json_data': '{"key1":}'})

    assert str(error.value) == expected_error_message


def test_add_entry_to_look_table_when_invalid_json_data_provided_via_file_entry_id(mock_client, mocker):
    """Test case to verify that Exception should be raised when invalid JSON data is provided via file entry ID."""
    tmp_dir = mkdtemp()
    file_name = 'test_file.json'
    file_obj = {
        'name': file_name,
        'path': os.path.join(tmp_dir, file_name)
    }
    with open(file_obj['path'], 'w') as f:
        f.write('{"key1":}')

    expected_error_message = 'Could not able to parse the provided JSON data. ' \
                             'Error: Expecting value: line 1 column 9 (char 8)'
    mocker.patch.object(demisto, 'getFilePath', return_value=file_obj)

    with pytest.raises(Exception) as error:
        add_entry_to_lookup_table(mock_client, {'name': 'test_table', 'file_entry_id': '27@1344'})

    assert str(error.value) == expected_error_message


@pytest.mark.parametrize('name,json_data', [
    ('XSOAR_TEST', '{"key1": "value1", "expiryDate": "02/13/2023"}'),
    ('XSOAR_TEST', '[{"key1": "value1", "key2": "value2", "expiryDate": "02/13/2023"}]')
])
def test_add_entry_to_lookup_table_when_valid_json_data_provided(mock_client, name, json_data, mocker):
    """Test case to verify that the command should be successful when valid JSON data is provided."""
    mocker.patch.object(mock_client, 'http_request', return_value=RESPONSE_LOOKUP_TABLE_ENTRY_ADD)
    args = {'name': name, 'json_data': json_data}
    resp = add_entry_to_lookup_table(mock_client, args)

    assert resp[0] == RESPONSE_LOOKUP_TABLE_ENTRY_ADD
    assert resp[1] == EXPECTED_LOOKUP_TABLE_ENTRY_ADD  # As this command doesn't return any context data.
    assert resp[2] == RESPONSE_LOOKUP_TABLE_ENTRY_ADD


@pytest.mark.parametrize('name,json_data', [
    ('XSOAR_TEST', '{"key1": "value1", "expiryDate": "Something"}'),
    ('XSOAR_TEST', '{"key1": "value1", "expiryDate": "15th Dec 2023"}'),
    ('XSOAR_TEST', '{"key1": "value1", "expiryDate": "15/03/2023"}'),
    ('XSOAR_TEST', '{"key1": "value1", "expiryDate": "2023/02/01T00:00:00Z"}'),
    ('XSOAR_TEST', '{"key1": "value1", "expiryDate": "Jan 23, 2023"}'),
])
def test_add_entry_to_lookup_table_when_invalid_expiry_date_provided(mock_client, name, json_data):
    """Test case to verify that ValueError should be raised when invalid expiry date is provided."""
    expected_error_message = "The value of expiryDate field is not in MM/DD/YYYY format."

    with pytest.raises(ValueError) as error:
        add_entry_to_lookup_table(mock_client, {'name': name, 'json_data': json_data})

    assert str(error.value) == expected_error_message


def test_update_remote_system_with_close_incidents(mock_client, mocker):
    """Test case scenario to verify that remote Securonix incident is closed once the XSOAR incident is closed."""
    mocker.patch.object(demisto, 'params', return_value={'host': 'https://127.0.0.1/Snypr',
                                                         'closed_state_action_mapping': 'Close Incident',
                                                         'closed_state_status_mapping': 'Completed'})
    mocker.patch.object(demisto, 'command', return_value='update-remote-system')

    mock_args = {
        'remoteId': '1234',
        'data': {
            'id': '345',
            'securonixcloseincident': False
        },
        'incidentChanged': True,
        'status': 2,
        'delta': {
            "closeNotes": "Closing XSOAR incident",
            "closeReason": "Resolved",
            "closingUserId": "admin"
        }
    }
    mocker.patch.object(demisto, 'args', return_value=mock_args)

    mocker.patch.object(Client, 'perform_action_on_incident_request',
                        side_effect=perform_action_on_incident_request_side_effect)
    mocker.patch.object(Client, 'add_comment_to_incident_request',
                        side_effect=add_comment_to_incident_request_side_effect)

    main()


def test_get_remote_data_command_with_attachment(mock_client, mocker):
    """Test case scenario to verify that the get_remote_data command when attachment is added to Securonix incident."""
    mocker.patch.object(mock_client, 'get_incident_request', return_value=RESPONSE_GET_INCIDENT['result']['data'])
    mocker.patch.object(mock_client, 'get_incident_activity_history_request',
                        return_value=MIRROR_RESPONSE_GET_INCIDENT_ACTIVITY_HISTORY_ATTACHMENT['result'][
                            'activityStreamData'])
    mocker.patch.object(mock_client, 'get_incident_attachments_request', return_value=get_mock_attachment_response())
    mock_args = {'id': '2849604490', 'lastUpdate': 1424683062000}

    entries = get_remote_data_command(mock_client, mock_args, ['closed', 'completed'])
    new_entries = entries.entries

    assert len(new_entries) == 1
    assert new_entries[0]['File'] == 'test.txt'
    assert new_entries[0]['ContentsFormat'] == 'text'


def test_filter_attachment_activity_entries():
    """Test case to verify that the filter_attachment_activity_entries function works as expected."""
    mock_activity_history = [
        {'actiontaken': 'COMMENTS_ADDED'},
        {'actiontaken': 'ATTACHED_FILE'},
        {'actiontaken': 'COMMENTS_ADDED'},
        {'actiontaken': 'ATTACHED_FILE'},
        {'actiontaken': 'ATTACHED_FILE'}
    ]

    resp = filter_attachment_activity_entries(mock_activity_history)

    assert len(resp) == 3


@pytest.mark.parametrize('close_states_of_securonix', ['', ' '])
def test_validate_mirroring_parameters_for_incoming_mirroring_direction(close_states_of_securonix):
    """Test case to verify that ValueError should be raised when value is not provided for close_states_of_securonix."""
    expected_error_message = 'Following field is required for Incoming Mirroring: "Securonix workflow state(s) ' \
                             'that can be considered as Close state in XSOAR for Incoming mirroring".'

    with pytest.raises(ValueError) as error:
        validate_mirroring_parameters(
            {'close_states_of_securonix': close_states_of_securonix, 'mirror_direction': 'Incoming'})

    assert str(error.value) == expected_error_message


@pytest.mark.parametrize('active_state_action,active_state_status,close_state_action,close_state_status,'
                         'comment_entry_tag', [
                             ('', 'In Progress', 'Close Investigation', 'Completed', 'Comment'),
                             ('  ', 'In Progress', 'Close Investigation', 'Completed', 'Comment'),
                             ('Start Investigation', '', 'Close Investigation', 'Completed', 'Comment'),
                             ('Start Investigation', '  ', 'Close Investigation', 'Completed', 'Comment'),
                             ('Start Investigation', 'In Progress', '', 'Completed', 'Comment'),
                             ('Start Investigation', 'In Progress', '  ', 'Completed', 'Comment'),
                             ('Start Investigation', 'In Progress', 'Close Investigation', '', 'Comment'),
                             ('Start Investigation', 'In Progress', 'Close Investigation', '  ', 'Comment'),
                             ('Start Investigation', 'In Progress', 'Close Investigation', 'Completed', ''),
                             ('Start Investigation', 'In Progress', 'Close Investigation', 'Completed', '  '),
                         ])
def test_validate_mirroring_parameters_for_outgoing_mirroring_direction(active_state_action, active_state_status,
                                                                        close_state_action, close_state_status,
                                                                        comment_entry_tag):
    """Test case to verify that ValueError should be raised, when required parameters are not provided for outgoing
    mirroring."""
    expected_error_message = 'Following fields are required for Outgoing Mirroring: "Securonix action name to map ' \
                             'with XSOAR\'s active state for Outgoing mirroring", "Securonix status to map with ' \
                             'XSOAR\'s active state for Outgoing mirroring", "Securonix action name to map with ' \
                             'XSOAR\'s closed state for Outgoing mirroring", "Securonix status to map with XSOAR\'s ' \
                             'closed state for Outgoing mirroring", "Comment Entry Tag".'

    with pytest.raises(ValueError) as error:
        validate_mirroring_parameters({
            'mirror_direction': 'Outgoing',
            'active_state_action': active_state_action,
            'active_state_status': active_state_status,
            'close_state_action': close_state_action,
            'close_state_status': close_state_status,
            'comment_entry_tag': comment_entry_tag
        })

    assert str(error.value) == expected_error_message


@pytest.mark.parametrize('active_state_action,active_state_status,close_state_action,close_state_status,'
                         'comment_entry_tag,close_states_of_securonix', [
                             ('', 'In Progress', 'Close Investigation', 'Completed', 'Comment', 'Closed'),
                             ('  ', 'In Progress', 'Close Investigation', 'Completed', 'Comment', 'Closed'),
                             ('Start Investigation', '', 'Close Investigation', 'Completed', 'Comment', 'Closed'),
                             ('Start Investigation', '  ', 'Close Investigation', 'Completed', 'Comment', 'Closed'),
                             ('Start Investigation', 'In Progress', '', 'Completed', 'Comment', 'Closed'),
                             ('Start Investigation', 'In Progress', '  ', 'Completed', 'Comment', 'Closed'),
                             ('Start Investigation', 'In Progress', 'Close Investigation', '', 'Comment', 'Closed'),
                             ('Start Investigation', 'In Progress', 'Close Investigation', '  ', 'Comment', 'Closed'),
                             ('Start Investigation', 'In Progress', 'Close Investigation', 'Completed', '', 'Closed'),
                             ('Start Investigation', 'In Progress', 'Close Investigation', 'Completed', '  ', 'Closed'),
                             ('Start Investigation', 'In Progress', 'Close Investigation', 'Completed', 'Comment', ''),
                             ('Start Investigation', 'In Progress', 'Close Investigation', 'Completed', 'Comment', ' '),
                         ])
def test_validate_mirroring_parameters_for_incoming_and_outgoing_mirroring_direction(active_state_action,
                                                                                     active_state_status,
                                                                                     close_state_action,
                                                                                     close_state_status,
                                                                                     comment_entry_tag,
                                                                                     close_states_of_securonix):
    """Test case to verify that ValueError should be raised, when required parameters are not provided for outgoing
    mirroring."""
    expected_error_message = 'Following fields are required for Incoming And Outgoing Mirroring: "Securonix workflow ' \
                             'state(s) that can be considered as Close state in XSOAR for Incoming mirroring", ' \
                             '"Securonix action name to map with XSOAR\'s active state for Outgoing mirroring", ' \
                             '"Securonix status to map with XSOAR\'s active state for Outgoing mirroring", ' \
                             '"Securonix action name to map with XSOAR\'s closed state for Outgoing mirroring", ' \
                             '"Securonix status to map with XSOAR\'s closed state for Outgoing mirroring", ' \
                             '"Comment Entry Tag".'

    with pytest.raises(ValueError) as error:
        validate_mirroring_parameters({
            'mirror_direction': 'Incoming And Outgoing',
            'active_state_action': active_state_action,
            'active_state_status': active_state_status,
            'close_state_action': close_state_action,
            'close_state_status': close_state_status,
            'comment_entry_tag': comment_entry_tag,
            'close_states_of_securonix': close_states_of_securonix
        })

    assert str(error.value) == expected_error_message


@pytest.mark.parametrize('active_state_action,active_state_status,close_state_action,close_state_status', [
    ('', 'In Progress', 'Close Investigation', 'Completed'),
    ('  ', 'In Progress', 'Close Investigation', 'Completed'),
    ('Start Investigation', '', 'Close Investigation', 'Completed'),
    ('Start Investigation', '  ', 'Close Investigation', 'Completed'),
    ('Start Investigation', 'In Progress', '', 'Completed'),
    ('Start Investigation', 'In Progress', '  ', 'Completed'),
    ('Start Investigation', 'In Progress', 'Close Investigation', ''),
    ('Start Investigation', 'In Progress', 'Close Investigation', '  ')
])
def test_validate_mirroring_parameters_for_close_incident_checkbox(active_state_action, active_state_status,
                                                                   close_state_action, close_state_status):
    """Test case to verify that ValueError should be raised, when required parameters are not provided for close
    Securonix incident checkbox."""
    expected_error_message = 'Following fields are required for closing incident on Securonix: "Securonix action name' \
                             ' to map with XSOAR\'s active state for Outgoing mirroring", "Securonix status to map ' \
                             'with XSOAR\'s active state for Outgoing mirroring", "Securonix action name to map with ' \
                             'XSOAR\'s closed state for Outgoing mirroring", "Securonix status to map with XSOAR\'s ' \
                             'closed state for Outgoing mirroring".'

    with pytest.raises(ValueError) as error:
        validate_mirroring_parameters({
            'close_incident': True,
            'mirror_direction': 'test',
            'active_state_action': active_state_action,
            'active_state_status': active_state_status,
            'close_state_action': close_state_action,
            'close_state_status': close_state_status,
        })

    assert str(error.value) == expected_error_message


def test_fetch_securonix_incident_when_no_new_incident_found(mock_client, mocker):
    """Test case to verify that when 0 incident returned from API, offset value should be updated."""
    mocker.patch.object(demisto, 'params', return_value={'host': 'https://127.0.0.1/Snypr'})
    mocker.patch.object(demisto, 'command', return_value='fetch-incidents')
    mocker.patch.object(demisto, 'args', return_value={'close_incident': True, 'entity_type_to_fetch': 'Incident'})
    mocker.patch.object(demisto, 'getLastRun', return_value={"value": json.dumps({'already_fetched': ['100107'],
                                                                                  'from': '1675900800000',
                                                                                  'to': '1676367548000',
                                                                                  'offset': 1})})
    mocker.patch.object(Client, 'list_incidents_request', return_value={'totalIncidents': 0.0,
                                                                        'incidentItems': []})
    mock_set_last_run = mocker.patch.object(demisto, 'setLastRun')

    main()
    call_args = json.loads(mock_set_last_run.call_args[0][0]['value'])

    assert call_args['offset'] == 0
    assert call_args['from'] == '1676367548000'
    assert call_args['already_fetched'] == ['100107']


def test_fetch_securonix_incident_when_time_key_found_in_last_run_object(mock_client, mocker):
    """Test case to verify that when time key is found in last run object, its value should be set in from key."""
    mocker.patch.object(demisto, 'params', return_value={'host': 'https://127.0.0.1/Snypr', 'close_incident': True,
                                                         'entity_type_to_fetch': 'Incident', 'incident_status': 'All'})
    mocker.patch.object(demisto, 'command', return_value='fetch-incidents')
    mocker.patch.object(demisto, 'getLastRun', return_value={"value": json.dumps({'already_fetched': ['100108'],
                                                                                  'time': '2020-06-07T08:32:41.679579Z'}
                                                                                 )})
    mocker.patch.object(Client, 'list_incidents_request', return_value=RESPONSE_FETCH_INCIDENTS)
    mock_set_last_run = mocker.patch.object(demisto, 'setLastRun')

    main()
    call_args = json.loads(mock_set_last_run.call_args[0][0]['value'])

    assert call_args['offset'] == 1
    assert call_args['from'] == date_to_timestamp('2020-06-07T08:32:41.679579Z', '%Y-%m-%dT%H:%M:%S.%fZ')
    assert call_args['already_fetched'] == ['100108', '100107']


@pytest.mark.parametrize('args,err_msg', [
    ({'whitelist_name': 'test_whitelist', 'whitelist_type': 'invalid'}, 'Provide valid whitelist_type'),
    ({'whitelist_name': 'test_whitelist', 'whitelist_type': 'Global', 'entity_type': 'test_entity'},
     'Provide valid entity_type'),
    ({'whitelist_name': 'test_whitelist', 'whitelist_type': 'Attribute', 'attribute_name': 'test_attribute',
      'violation_type': 'Policy'}, 'Provide valid attribute_name'),
    ({'whitelist_name': 'test_whitelist', 'whitelist_type': 'Attribute', 'attribute_name': 'resourcetype',
      'violation_type': 'test_violation'}, 'Provide valid violation_type'),
    ({'whitelist_name': 'test_whitelist', 'whitelist_type': 'Attribute', 'attribute_name': 'resourcetype',
      'violation_type': 'Policy', 'expiry_date': '13-03-2023'}, 'exipry_date is not in MM/DD/YYYY format')
])
def test_whitelist_entry_add_for_invalid_arguments(mock_client, args, err_msg):
    """Test case to validate that Exception should be raised for invalid arguments."""
    with pytest.raises(Exception) as error:
        add_whitelist_entry(mock_client, args)

    assert str(error.value) == err_msg


@pytest.mark.parametrize('command_name,args,response,err_msg', [
    (create_lookup_table, {}, 'Error in command.',
     'Failed to create lookup table.\nResponse from Securonix is:Error in command.'),
    (add_entry_to_lookup_table, {'name': 'test_lookup_table', 'json_data': '{"id": "1"}'}, 'Error in command.',
     'Failed adding entries to the lookup table. Error from Securonix: Error in command.'),
    (delete_whitelist_entry, {'tenant_name': 'test', 'whitelist_name': 'test_whitelist', 'entity_id': 'test_entity'},
     {'result': 'Error in command.'},
     'Failed to remove entry from whitelist.\nResponse from Securonix is:Error in command.'),
    (delete_lookup_table_config_and_data, {'name': 'test_lookup_table'}, 'Error in command.',
     'Failed to delete lookup table and its data.\nResponse from Securonix is: Error in command.'),
    (create_whitelist, {'whitelist_name': 'test_whitelist', 'entity_type': 'Activityaccount'},
     {'messages': 'Error in command.'},
     'Failed to create whitelist.\nResponse from Securonix is:{\'messages\': \'Error in command.\'}'),
    (get_whitelist_entry, {'whitelist_name': 'test_whitelist'}, {'result': {}},
     'Whitelist does not contain items.\nMake sure the whitelist_name is not empty and it is correct.'),
    (add_entity_to_watchlist, {'watchlist_name': 'test_watchlist', 'entity_name': {'test_entity'}}, 'Error in command',
     'Failed to add entity {\'test_entity\'} to the watchlist test_watchlist.\nError from Securonix is: Error in '
     'command.'),
    (create_watchlist, {'watchlist_name': 'test_watchlist'}, 'Error in command.',
     'Failed to list watchlists.\nResponse from Securonix is:Error in command.'),
    (list_activity_data, {}, {"error": True, 'errorMessage': 'Invalid Query'},
     'Failed to get activity data in the given time frame.\nError from Securonix is: Invalid Query'),
])
def test_exceptions_in_command(command_name, args, response, err_msg, mocker):
    """Test case scenario to validate Exceptions for the commands."""
    mocker.patch.object(Client, '_generate_token')
    client = Client('tenant', 'server_url', 'username', 'password', 'verify', 'proxies', 0, 0, 'Fixed')
    mocker.patch.object(client, 'http_request', return_value=response)
    with pytest.raises(Exception) as error:
        command_name(client, args)

    assert str(error.value) == err_msg
