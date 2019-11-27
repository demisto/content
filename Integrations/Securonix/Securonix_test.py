import pytest
from Securonix import camel_case_to_readable, parse_data_arr, Client, list_workflows, get_default_assignee_for_workflow,\
    list_possible_threat_actions
from test_data.response_constants import RESPONSE_LIST_WORKFLOWS, RESPONSE_DEFAULT_ASSIGNEE,\
    RESPONSE_POSSIBLE_THREAT_ACTIONS
from test_data.result_constants import EXPECTED_LIST_WORKFLOWS, EXPECTED_DEFAULT_ASSIGNEE,\
    EXPECTED_POSSIBLE_THREAT_ACTIONS


def test_camel_case_to_readable():
    assert camel_case_to_readable('id') == 'ID'
    assert camel_case_to_readable('invalidEventAction') == 'Invalid Event Action'


def test_parse_data_arr():
    outputs = {
        'employeeid': '123',
        'employeetype': 'user'
    }

    parsed_readable, parsed_outputs = parse_data_arr(outputs)

    expected_readable = {
        'Employeeid': '123',
        'Employeetype': 'user'
    }
    expected_outputs = {
        'Employeeid': '123',
        'Employeetype': 'user'
    }
    assert parsed_readable == expected_readable
    assert parsed_outputs == expected_outputs


@pytest.mark.parametrize('command, args, response, expected_result', [
    (list_workflows, {}, RESPONSE_LIST_WORKFLOWS, EXPECTED_LIST_WORKFLOWS),
    (get_default_assignee_for_workflow, {'workflow': 'SOCTeamReview'}, RESPONSE_DEFAULT_ASSIGNEE,
     EXPECTED_DEFAULT_ASSIGNEE),
    (list_possible_threat_actions, {}, RESPONSE_POSSIBLE_THREAT_ACTIONS, EXPECTED_POSSIBLE_THREAT_ACTIONS)
])  # noqa: E124
def test_commands(command, args, response, expected_result, mocker):
    mocker.patch.object(Client, '_generate_token')
    client = Client('tenant', 'server_url', 'username', 'password', 'verify', 'proxies')
    mocker.patch.object(client, 'http_request', return_value=response)
    result = command(client, args)
    # print(result[1])
    assert expected_result == result[1]  # entry context is found in the 2nd place in the result of the command
