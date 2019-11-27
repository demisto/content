import pytest
from Securonix import camel_case_to_readable, parse_data_arr, Client, list_workflows
from test_data.response_constants import RESPONSE_LIST_WORKFLOWS
from test_data.result_constants import EXPECTED_LIST_WORKFLOWS


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
    (list_workflows, {}, RESPONSE_LIST_WORKFLOWS, EXPECTED_LIST_WORKFLOWS)
])  # noqa: E124
def test_commands(command, args, response, expected_result, mocker):
    mocker.patch.object(Client, '_generate_token')
    client = Client('tenant', 'server_url', 'username', 'password', 'verify', 'proxies')
    mocker.patch.object(client, 'http_request', return_value=response)
    result = command(client, args)
    assert expected_result == result[1]  # entry context is found in the 2nd place in the result of the command
