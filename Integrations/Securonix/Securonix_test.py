import pytest
from Securonix import reformat_resource_groups_outputs, reformat_outputs, parse_data_arr, Client, list_workflows,\
    get_default_assignee_for_workflow, list_possible_threat_actions, list_resource_groups, list_users,\
    list_incidents, get_incident, list_watchlists, get_watchlist
from test_data.response_constants import RESPONSE_LIST_WORKFLOWS, RESPONSE_DEFAULT_ASSIGNEE,\
    RESPONSE_POSSIBLE_THREAT_ACTIONS, RESPONSE_LIST_RESOURCE_GROUPS, RESPONSE_LIST_USERS, RESPONSE_LIST_INCIDENT,\
    RESPONSE_GET_INCIDENT, RESPONSE_LIST_WATCHLISTS, RESPONSE_GET_WATCHLIST
from test_data.result_constants import EXPECTED_LIST_WORKFLOWS, EXPECTED_DEFAULT_ASSIGNEE,\
    EXPECTED_POSSIBLE_THREAT_ACTIONS, EXPECTED_LIST_RESOURCE_GROUPS, EXPECTED_LIST_USERS, EXPECTED_LIST_INCIDENT,\
    EXPECTED_GET_INCIDENT, EXPECTED_LIST_WATCHLISTS, EXPECTED_GET_WATCHLIST


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


@pytest.mark.parametrize('command, args, response, expected_result', [
    (list_workflows, {}, RESPONSE_LIST_WORKFLOWS, EXPECTED_LIST_WORKFLOWS),
    (get_default_assignee_for_workflow, {'workflow': 'SOCTeamReview'}, RESPONSE_DEFAULT_ASSIGNEE,
     EXPECTED_DEFAULT_ASSIGNEE),
    (list_possible_threat_actions, {}, RESPONSE_POSSIBLE_THREAT_ACTIONS, EXPECTED_POSSIBLE_THREAT_ACTIONS),
    (list_resource_groups, {}, RESPONSE_LIST_RESOURCE_GROUPS, EXPECTED_LIST_RESOURCE_GROUPS),
    (list_users, {}, RESPONSE_LIST_USERS, EXPECTED_LIST_USERS),
    (list_incidents, {"from": "1 year"}, RESPONSE_LIST_INCIDENT, EXPECTED_LIST_INCIDENT),
    (get_incident, {'incident_id': '1234'}, RESPONSE_GET_INCIDENT, EXPECTED_GET_INCIDENT),
    (list_watchlists, {}, RESPONSE_LIST_WATCHLISTS, EXPECTED_LIST_WATCHLISTS),
    (get_watchlist, {'watchlist_name': 'test'}, RESPONSE_GET_WATCHLIST, EXPECTED_GET_WATCHLIST)
])  # noqa: E124
def test_commands(command, args, response, expected_result, mocker):
    """Unit test for integration commands

    Args:
        command: func name in .py
        args: func args
        response: response as mocked from 'SNYPR 6.2 CU4 Administration Guide'
        expected_result: expected result in demisto
        mocker: mocker object
    """
    mocker.patch.object(Client, '_generate_token')
    client = Client('tenant', 'server_url', 'username', 'password', 'verify', 'proxies')
    mocker.patch.object(client, 'http_request', return_value=response)
    result = command(client, args)
    assert expected_result == result[1]  # entry context is found in the 2nd place in the result of the command
