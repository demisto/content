import io
import os

import pytest
import json

from CommonServerPython import DemistoException
from test_data import input_data
from unittest import mock

BASE_URL = 'https://mocked_url/v1/'

URL_SUFFIX = {
    "REPORTS": "reports",
    "PROGRAMS": "me/programs"
}


def util_load_json(path):
    with io.open(path, mode='r', encoding='utf-8') as f:
        return json.loads(f.read())


@pytest.fixture()
def client():
    from HackerOne import Client
    return Client("https://mocked_url/v1", False, False, auth=("user", "user123"), max_fetch=1,
                  first_fetch="2020-09-07T04:59:51Z",
                  program_handle=["checker_program_h1b"], severity="", state="", filters="")


def test_test_module_when_valid_response_is_returned(client, requests_mock):
    """
    Test test_module function for success cases.
    Given
        - A valid response
    When
        - The status code returned is 200
    Then
        - Ensure test module should return success
    """
    from HackerOne import test_module

    requests_mock.get(BASE_URL + URL_SUFFIX["PROGRAMS"], status_code=200, json="{}")

    assert test_module(client) == 'ok'


def test_test_module_when_isfetch_is_true(requests_mock, client):
    """
    Test test_module function when isFetch is True.
    Given
        - A valid response
    When
        - The status code returned is 200 and is_fetch is true
    Then
        - Ensure test module should return success
    """
    from HackerOne import test_module

    requests_mock.get(BASE_URL + URL_SUFFIX["PROGRAMS"], json={"page_size": 1}, status_code=200)
    requests_mock.get(BASE_URL + URL_SUFFIX["REPORTS"], json={"filter[program][]": ["abc"]}, status_code=200)

    assert test_module(client) == 'ok'


def test_test_module_when_authentication_error_is_returned(requests_mock, client):
    """
     Test test_module function for failure cases.
     Given
        - an error status code
     When
        - the user can't be authenticated
     Then
        - raise DemistoException
    """
    from HackerOne import test_module
    requests_mock.get(BASE_URL + URL_SUFFIX["PROGRAMS"], status_code=400, json={})
    with pytest.raises(DemistoException):
        test_module(client)


@pytest.mark.parametrize("status_code, error_msg, expected_error_message", input_data.exception_handler_params)
def test_exception_handler_json(status_code, error_msg, expected_error_message, client):
    """
    To test exception handler in various http error code.
     Given
        - a dictionary containing http error code.
    When
        - initializing client.
    Then
        - raise DemistoException

    """
    mocked_response = mock.Mock()
    mocked_response.status_code = status_code
    mocked_response.json.return_value = error_msg
    mocked_response.headers = {'Content-Type': "application/json"}
    with pytest.raises(DemistoException) as err:
        client.exception_handler(mocked_response)
    assert str(err.value) == expected_error_message


def test_exception_handler_not_json(client):
    """
    To test exception handler in various http error code.
    Given
        - 423 error code
    When
        - initializing client.
    Then
        - raise DemistoException
    """

    status_code = 423
    error_msg = "<html>\n<head><title>423 Invalid</title></head>\n<body>\n<center><h1>423 Invalid</h1></center>" \
                "\n<hr><center>nginx</center>\n</body>\n</html>"

    expected_error_message = "Unable to retrieve the data based on arguments."
    mocked_response = mock.Mock()
    mocked_response.status_code = status_code
    mocked_response.json.return_value = error_msg
    mocked_response.headers = {'Content-Type': "text/html"}
    with pytest.raises(DemistoException) as err:
        client.exception_handler(mocked_response)
    assert str(err.value) == expected_error_message


def test_hackerone_program_list_command_when_valid_response_is_returned(client, requests_mock):
    """
    Test case scenario for successful execution of hackerone-program-list command.
    Given:
        - command arguments for list program command
    When:
        - Calling `hackerone-program-list` command
    Then:
        -  Returns the response data
    """
    from HackerOne import hackerone_program_list_command

    response = util_load_json(
        os.path.join("test_data", "program/program_command_response.json"))

    requests_mock.get(BASE_URL + URL_SUFFIX["PROGRAMS"], json=response, status_code=200)

    context_output = util_load_json(
        os.path.join("test_data", "program/program_command_context.json"))

    with open(os.path.join("test_data", "program/program_command_readable_output.md"), 'r') as f:
        readable_output = f.read()

    # Execute
    command_response = hackerone_program_list_command(client, {})

    # Assert
    assert command_response.outputs_prefix == 'HackerOne.Program'
    assert command_response.outputs_key_field == "id"
    assert command_response.outputs == context_output
    assert command_response.readable_output == readable_output


def test_hackerone_program_list_command_when_empty_response_is_returned(client, requests_mock):
    """
    Test case scenario for successful execution of hackerone-program-list command with an empty response.
    Given:
        - command arguments for list program command
    When:
        - Calling `hackerone-program-list` command
    Then:
        - Returns no records for the given input arguments
    """
    from HackerOne import hackerone_program_list_command
    expected_response = {"data": [], "links": []}
    requests_mock.get(BASE_URL + URL_SUFFIX["PROGRAMS"], status_code=200, json=expected_response)
    readable_output = "No programs were found for the given argument(s)."

    # Execute
    command_response = hackerone_program_list_command(client, {})

    # Assert
    assert command_response.readable_output == readable_output


@pytest.mark.parametrize("args, expected_error", input_data.invalid_args_for_program_list)
def test_hackerone_program_list_command_when_invalid_args_provided(client, args, expected_error):
    """
    Test case scenario when invalid arguments are provided.
    Given:
        - invalid command arguments for list program command
    When
        - Calling `hackerone-program-list`
    Then:
        - Returns the response message of invalid input arguments
    """
    from HackerOne import hackerone_program_list_command

    with pytest.raises(ValueError) as err:
        hackerone_program_list_command(client, args)

    assert str(err.value) == expected_error


@pytest.mark.parametrize("args, expected_params", input_data.report_list_args)
def test_validate_report_list_args_when_valid_args_are_provided(args, expected_params):
    """
    Test case scenario when report list valid arguments are provided.
    Given:
        - valid command arguments for list report command
    When
        - Calling `prepare_report_list_args`
    Then:
        - Returns the expected params.
    """
    from HackerOne import prepare_report_list_args

    assert prepare_report_list_args(args) == expected_params


def test_hackerone_report_list_command_when_empty_response_is_returned(client, requests_mock):
    """
    Test case scenario for successful execution of hackerone-report-list command with an empty response.
    Given:
        - command arguments for list report command
    When:
        - Calling `hackerone-report-list` command
    Then:
        - Returns no records for the given input arguments
    """
    from HackerOne import hackerone_report_list_command
    expected_response = {"data": [], "links": []}
    requests_mock.get(BASE_URL + URL_SUFFIX["REPORTS"], json=expected_response, status_code=200)
    readable_output = "No reports were found for the given argument(s)."

    # Execute
    command_response = hackerone_report_list_command(client, {"program_handle": "abc"})

    # Assert
    assert command_response.readable_output == readable_output


def test_hackerone_report_list_command_when_valid_response_is_returned(client, requests_mock):
    """
    Test case scenario for successful execution of hackerone-report-list command.
    Given:
        - command arguments for list report command
    When:
        - Calling `hackerone-report-list` command
    Then:
        -  Returns the response data
    """
    from HackerOne import hackerone_report_list_command

    response = util_load_json(
        os.path.join("test_data", "report/report_command_response.json"))

    requests_mock.get(BASE_URL + URL_SUFFIX["REPORTS"], json=response, status_code=200)

    context_output = util_load_json(
        os.path.join("test_data", "report/report_command_context.json"))

    with open(os.path.join("test_data", "report/report_command_readable_output.md"), 'r') as f:
        readable_output = f.read()

    # Execute
    command_response = hackerone_report_list_command(client, {"program_handle": "abc"})

    # Assert
    assert command_response.outputs_prefix == 'HackerOne.Report'
    assert command_response.outputs_key_field == "id"
    assert command_response.outputs == context_output
    assert command_response.readable_output == readable_output


@pytest.mark.parametrize("args, expected_error", input_data.invalid_args_for_report_list)
def test_hackerone_report_list_command_when_invalid_args_provided(client, args, expected_error):
    """
    Test case scenario when invalid arguments for report list command are provided.
    Given:
        - invalid command arguments for list report command
    When
        - Calling `hackerone-report-list`
    Then:
        - Returns the response message of invalid input arguments
    """
    from HackerOne import hackerone_report_list_command

    with pytest.raises(ValueError) as err:
        hackerone_report_list_command(client, args)

    assert str(err.value) == expected_error


def test_fetch_incident_when_empty_result_is_returned(client, requests_mock):
    """
    test case scenario when the results are empty.
    Given:
        - Fetch incident parameters
    When:
        - Fetching incidents.
    Then:
        -  Returns empty response for first time
    """
    from HackerOne import fetch_incidents
    last_run = {'current_created_at': '2020-09-07T04:59:51', 'next_page': 2}
    expected_response = {"data": [], "links": []}
    requests_mock.get(BASE_URL + URL_SUFFIX["REPORTS"], json=expected_response, status_code=200)
    fetched_incidents = fetch_incidents(client, last_run)

    expected_next_run = {'current_created_at': '2020-09-07T04:59:51', 'next_page': 2}

    assert fetched_incidents == (expected_next_run, [])


def test_fetch_incident_when_valid_result_is_returned(client, requests_mock):
    """
    test case scenario when the results are valid on fetching for the first time.
    Given:
        - Fetch incident parameters
    When:
        - Fetching incidents.
    Then:
        - Ensure that the incidents returned are as expected.
    """

    from HackerOne import fetch_incidents

    last_run = {}
    incident_data = util_load_json(
        os.path.join("test_data", "incident/raw_response.json"))

    requests_mock.get(BASE_URL + URL_SUFFIX["REPORTS"], json=incident_data, status_code=200)
    fetched_incidents = fetch_incidents(client, last_run)

    next_run = {'next_page': 1,
                'next_created_at': '2021-08-09T13:41:38.039Z',
                'report_ids': ['1295856']}

    incidents = [
        {
            "name": incident_data.get("data")[0].get("attributes").get("title"),
            "occurred": incident_data.get("data")[0].get("attributes").get("created_at"),
            "rawJSON": json.dumps(incident_data.get("data")[0])
        }
    ]

    assert fetched_incidents == (next_run, incidents)


def test_fetch_incident_when_getting_already_fetched_report(client, requests_mock):
    """
    test case scenario when the results are valid on fetching for the first time.
    Given:
        - Fetch incident parameters
    When:
        - Fetching incidents.
    Then:
        - Ensure that these reports are already fetched previously.
    """

    from HackerOne import fetch_incidents

    incident_data = util_load_json(
        os.path.join("test_data", "incident/raw_response.json"))

    last_run = {'next_page': 1, 'next_created_at': '2021-08-09T13:41:38.039Z',
                'report_ids': ['1295856']}

    requests_mock.get(BASE_URL + URL_SUFFIX["REPORTS"], json=incident_data, status_code=200)

    fetched_incidents = fetch_incidents(client, last_run)
    next_run = {'next_page': 2, 'next_created_at': '2021-08-09T13:41:38.039Z',
                'report_ids': ['1295856']}
    assert fetched_incidents == (next_run, [])


def test_fetch_incident_when_report_ids_should_be_replaced(client, requests_mock):
    """
    Test case scenario when report ids are replaced
    Given:
        - Fetch incident parameters
    When:
        - Fetching incidents.
    Then:
        - Ensure that the report ids are replaced.
    """

    from HackerOne import fetch_incidents

    incident_data = util_load_json(
        os.path.join("test_data", "incident/raw_response.json"))

    last_run = {'next_page': 2,
                'next_created_at': '2020-09-07T04:59:51Z',
                'report_ids': ['1295852']}

    requests_mock.get(BASE_URL + URL_SUFFIX["REPORTS"], json=incident_data, status_code=200)

    fetched_incidents = fetch_incidents(client, last_run)

    next_run = {'next_page': 1,
                'next_created_at': '2021-08-09T13:41:38.039Z',
                'report_ids': ['1295856']}

    incidents = [
        {
            "name": incident_data.get("data")[0].get("attributes").get("title"),
            "occurred": incident_data.get("data")[0].get("attributes").get("created_at"),
            "rawJSON": json.dumps(incident_data.get("data")[0])
        }
    ]

    assert fetched_incidents == (next_run, incidents)


@pytest.mark.parametrize("max_fetch, first_fetch, program_handle, severity, state, filters, page, expected_params",
                         input_data.valid_params_for_fetch_incidents)
def test_fetch_incident_when_valid_params_are_provided(max_fetch, first_fetch, program_handle, severity, state, filters,
                                                       page,
                                                       expected_params):
    """
    test case scenario when valid parameters are provided for fetching the incidents.
    Given:
        - Valid fetch incident parameters
    When:
        - Fetching incidents.
    Then:
        - Prepare params to fetch incidents
    """
    from HackerOne import prepare_fetch_incidents_parameters

    assert prepare_fetch_incidents_parameters(max_fetch, first_fetch, program_handle, severity, state,
                                              filters, page) == expected_params


@pytest.mark.parametrize("max_fetch, program_handle,filters, expected_error_msg",
                         input_data.invalid_params_for_fetch_incidents)
def test_fetch_incident_when_invalid_params_are_provided(max_fetch, program_handle, filters,
                                                         expected_error_msg):
    """
    test case scenario when invalid parameters are provided for fetching the incidents.
    Given:
        - Invalid fetch incident parameters
    When:
        - Fetching incidents.
    Then:
        - Returns error for invalid arguments
    """

    from HackerOne import validate_fetch_incidents_parameters

    with pytest.raises(ValueError) as err:
        validate_fetch_incidents_parameters(max_fetch, program_handle, filters)

    assert str(err.value) == expected_error_msg
