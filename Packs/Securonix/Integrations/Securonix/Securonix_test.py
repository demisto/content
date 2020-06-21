import pytest
from Securonix import reformat_resource_groups_outputs, reformat_outputs, parse_data_arr, Client, list_workflows,\
    get_default_assignee_for_workflow, list_possible_threat_actions, list_resource_groups, list_users,\
    list_incidents, get_incident, create_incident, perform_action_on_incident, list_watchlists, get_watchlist, \
    create_watchlist, check_entity_in_watchlist, add_entity_to_watchlist, get_incident_name, fetch_incidents
from test_data.response_constants import RESPONSE_LIST_WORKFLOWS, RESPONSE_DEFAULT_ASSIGNEE,\
    RESPONSE_POSSIBLE_THREAT_ACTIONS, RESPONSE_LIST_RESOURCE_GROUPS, RESPONSE_LIST_USERS, RESPONSE_LIST_INCIDENT,\
    RESPONSE_GET_INCIDENT, RESPONSE_CREATE_INCIDENT, RESPONSE_PERFORM_ACTION_ON_INCIDENT, RESPONSE_LIST_WATCHLISTS, \
    RESPONSE_GET_WATCHLIST, RESPONSE_CREATE_WATCHLIST, RESPONSE_ENTITY_IN_WATCHLIST, RESPONSE_ADD_ENTITY_TO_WATCHLIST, \
    RESPONSE_FETCH_INCIDENT_ITEM, RESPONSE_FETCH_INCIDENT_ITEM_MULTIPLE_REASONS, RESPONSE_FETCH_INCIDENTS
from test_data.result_constants import EXPECTED_LIST_WORKFLOWS, EXPECTED_DEFAULT_ASSIGNEE,\
    EXPECTED_POSSIBLE_THREAT_ACTIONS, EXPECTED_LIST_RESOURCE_GROUPS, EXPECTED_LIST_USERS, EXPECTED_LIST_INCIDENT,\
    EXPECTED_GET_INCIDENT, EXPECTED_CREATE_INCIDENT, EXPECTED_PERFORM_ACTION_ON_INCIDENT, \
    EXPECTED_LIST_WATCHLISTS, EXPECTED_GET_WATCHLIST, EXPECTED_CREATE_WATCHLIST, EXPECTED_ENTITY_IN_WATCHLIST, \
    EXPECTED_ADD_ENTITY_TO_WATCHLIST


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
    assert expected_incident_name == get_incident_name(RESPONSE_FETCH_INCIDENT_ITEM, '10134')

    expected_multiple_reasons_incident_name = 'Uploads to personal websites, Emails Sent to Personal Email: 10135'
    assert expected_multiple_reasons_incident_name == get_incident_name(RESPONSE_FETCH_INCIDENT_ITEM_MULTIPLE_REASONS,
                                                                        '10135')


def test_fetch_incidents(mocker):
    """Unit test
    Given
    - fetch incidents command
    - command args
    - command raw response
    When
    - mock the Client's send_request.
    Then
    - run the fetch incidents command using the Client
    Validate The length of the results.
    """
    mocker.patch.object(Client, '_generate_token')
    client = Client('tenant', 'server_url', 'username', 'password', 'verify', 'proxies')
    mocker.patch.object(client, 'list_incidents_request', return_value=RESPONSE_FETCH_INCIDENTS)
    incidents = fetch_incidents(client, fetch_time='1 hour', incident_status='open', max_fetch='50', last_run={})
    assert len(incidents) == 1
    assert incidents[0].get('name') == 'Emails with large File attachments: 100107'


def test_fetch_incidents_is_already_fetched(mocker):
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
    client = Client('tenant', 'server_url', 'username', 'password', 'verify', 'proxies')
    mocker.patch.object(client, 'list_incidents_request', return_value=RESPONSE_FETCH_INCIDENTS)
    incidents = fetch_incidents(client, fetch_time='1 hour', incident_status='open', max_fetch='50',
                                last_run={'already_fetched': ['100107'], 'time': "2020-06-07T08:32:41.679579Z"})
    assert len(incidents) == 0


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
    (get_watchlist, {'watchlist_name': 'test'}, RESPONSE_GET_WATCHLIST, EXPECTED_GET_WATCHLIST),
    (create_watchlist, {'watchlist_name': 'test234'}, RESPONSE_CREATE_WATCHLIST, EXPECTED_CREATE_WATCHLIST),
    (check_entity_in_watchlist, {'watchlist_name': 'test234', 'entity_name': '1002'}, RESPONSE_ENTITY_IN_WATCHLIST,
     EXPECTED_ENTITY_IN_WATCHLIST),
    (add_entity_to_watchlist, {'watchlist_name': 'test234', 'entity_name': '1004', 'entity_type': 'Users'},
     RESPONSE_ADD_ENTITY_TO_WATCHLIST, EXPECTED_ADD_ENTITY_TO_WATCHLIST)
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
    client = Client('tenant', 'server_url', 'username', 'password', 'verify', 'proxies')
    mocker.patch.object(client, 'http_request', return_value=response)
    result = command(client, args)
    assert expected_result == result[1]  # entry context is found in the 2nd place in the result of the command
