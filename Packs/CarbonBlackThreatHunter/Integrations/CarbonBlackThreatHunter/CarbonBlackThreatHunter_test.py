import pytest
from CarbonBlackThreatHunter import Client, cb_query
from test_data.response_constants import QUERY_RESPONSE
from test_data.result_constants import QUERY_RESULT


@pytest.mark.parametrize('command, args, response, expected_result', [
    (cb_query, {'query': 'test_query', 'query_type': 'processes'}, QUERY_RESPONSE, QUERY_RESULT),
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
    client = Client(server_url='demo.com', org_key='org_key', auth_token='auth_token', verify=True, proxy=False)
    mocker.patch.object(client, 'http_request', return_value=response)
    result = command(client, args)
    assert expected_result == result[1]  # entry context is found in the 2nd place in the result of the command
