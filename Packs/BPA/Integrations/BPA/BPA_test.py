import pytest

from test_data.response_constants import GET_RESULTS_RESPONSE, GET_DOCUMENTATION_RESPONSE
from test_data.result_constants import GET_RESULTS_NO_FILTER, GET_RESULTS_ID_FILTER, GET_RESULTS_NAME_FILTER, \
    GET_DOCUMENTATION_NO_FILTER, GET_DOCUMENTATION_ID_FILTER

from BPA import Client, get_results_command, get_documentation_command


@pytest.mark.parametrize('args, expected_result', [
    ({'task_id': '1234'}, GET_RESULTS_NO_FILTER),
    ({'task_id': '1234', 'check_id': '82,83,84'}, GET_RESULTS_ID_FILTER),
    ({'task_id': '1234', 'check_name': 'Log Forwarding,Disabled Rules'}, GET_RESULTS_NAME_FILTER)
])
def test_get_results(args, expected_result, mocker):
    """
    Given:
        - The get_results_request command.
    When:
        - Mocking the response of the server for get_results_request and:
        - (a) Not applying any filter on the results.
        - (b) Filtering the results according to specific check_ids.
        - (c) Filtering the results according to specific check_name.
    Then:
        - (a) Verify that all the results are returned.
        - (b) Only the results matching the given check_ids are returned.
        - (c) Only the results matching the given check_names are returned
    """
    client = Client('bpa_token', 'verify', 'proxy')
    mocker.patch.object(client, 'get_results_request', return_value=GET_RESULTS_RESPONSE)
    assert get_results_command(client, args)[1] == expected_result


@pytest.mark.parametrize('args, expected_result', [
    ({'task_id': '1234'}, GET_DOCUMENTATION_NO_FILTER),
    ({'task_id': '1234', 'ids': '3,4,5,6'}, GET_DOCUMENTATION_ID_FILTER)
])
def test_get_documentation(args, expected_result, mocker):
    """
    Given:
        - The get_documentation command.
    When:
        - Mocking the response of the server for get_documentation_request and:
        - (a) Not applying any filter on the results.
        - (b) Filtering the results according to specific doc_ids.
    Then:
        - (a) Verify that all the documents from the response are returned.
        - (b) Only the results matching the given doc_ids are returned.
    """
    client = Client('bpa_token', 'verify', 'proxy')
    mocker.patch.object(client, 'get_documentation_request', return_value=GET_DOCUMENTATION_RESPONSE)
    assert get_documentation_command(client, args)[1] == expected_result
