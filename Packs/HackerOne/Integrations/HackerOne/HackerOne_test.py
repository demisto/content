import io
import os

import pytest
import json

from CommonServerPython import DemistoException
from test_data import input_data
from unittest import mock

BASE_URL = 'https://mocked_url/'

URL_SUFFIX = {
    "REPORTS": "reports",
    "PROGRAMS": "me/programs"
}


def util_load_json(path):
    with io.open(path, mode='r', encoding='utf-8') as f:
        return json.loads(f.read())


@pytest.fixture
def mocked_client():
    mocked_client = mock.Mock()
    return mocked_client


@pytest.fixture()
def client():
    from HackerOne import Client
    return Client("https://mocked_url", False, False, auth=("user", "user123"))


def test_test_module_when_valid_response_is_returned(mocked_client):
    """Test test_module function for success cases."""
    from HackerOne import test_module
    mocked_response = mock.Mock()
    mocked_response.status_code = 200

    mocked_client.http_request.return_value = mocked_response

    assert test_module(mocked_client, {}) == 'ok'


def test_test_module_when_isfetch_is_true(requests_mock, client):
    """Test test_module function when isFetch is True."""
    from HackerOne import test_module

    requests_mock.get(BASE_URL + URL_SUFFIX["PROGRAMS"], json={"page_size": 1}, status_code=200)
    requests_mock.get(BASE_URL + URL_SUFFIX["REPORTS"], json={"filter[program][]": ["abc"]}, status_code=200)

    assert test_module(client, {"isFetch": True, "program_handle": "abc"}) == 'ok'


def test_test_module_when_authentication_error_is_there(mocked_client):
    """Test test_module function for failure cases."""
    from HackerOne import test_module
    mocked_client.http_request.side_effect = DemistoException("Authentication Error")
    with pytest.raises(DemistoException):
        test_module(mocked_client, {})


def test_test_module_when_400_status_code_is_returned(mocked_client):
    """Test test_module function for success cases."""
    from HackerOne import test_module, HTTP_ERROR

    mocked_response = mock.Mock()
    mocked_response.status_code = 400

    mocked_client.http_request.return_value = mocked_response

    with pytest.raises(DemistoException) as err:
        test_module(mocked_client, {})

    assert str(err.value) == HTTP_ERROR[401]


@pytest.mark.parametrize("status_code, error_msg, expected_error_message", input_data.exception_handler_params)
def test_exception_handler_json(status_code, error_msg, expected_error_message, client):
    """
    To test exception handler in various http error code.
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


def test_retrieve_fields():
    from HackerOne import retrieve_fields
    dummy_args = " ,abc, xyz, "
    assert retrieve_fields(dummy_args) == ["abc", "xyz"]


@pytest.mark.parametrize("args, expected_params", input_data.common_args)
def test_validate_common_args(args, expected_params):
    """Test case scenario when valid arguments are provided."""
    from HackerOne import validate_common_args

    assert validate_common_args(args) == expected_params


def test_hackerone_program_list_command_when_valid_response_is_returned(mocked_client):
    """Test case scenario for successful execution of hackerone-program-list command."""
    from HackerOne import hackerone_program_list_command

    response = util_load_json(
        os.path.join("test_data", "program/program_command_response.json"))

    mocked_client.http_request.return_value = response

    context_output = util_load_json(
        os.path.join("test_data", "program/program_command_context.json"))

    with open(os.path.join("test_data", "program/program_command_readable_output.md"), 'r') as f:
        readable_output = f.read()

    # Execute
    command_response = hackerone_program_list_command(mocked_client, {})

    # Assert
    assert command_response.outputs_prefix == 'HackerOne.Program'
    assert command_response.outputs_key_field == "id"
    assert command_response.outputs == context_output
    assert command_response.readable_output == readable_output
    assert command_response.raw_response == response


def test_hackerone_program_list_command_when_empty_response_is_returned(mocked_client):
    """Test case scenario for successful execution of hackerone-program-list command with an empty response."""
    from HackerOne import hackerone_program_list_command

    mocked_client.http_request.return_value = {"data": [], "links": []}
    readable_output = "No programs were found for the given argument(s)."

    # Execute
    command_response = hackerone_program_list_command(mocked_client, {})

    # Assert
    assert command_response.readable_output == readable_output


@pytest.mark.parametrize("args, expected_error", input_data.invalid_args_for_program_list)
def test_hackerone_program_list_command_when_invalid_args_provided(mocked_client, args, expected_error):
    """Test case scenario when invalid arguments are provided."""
    from HackerOne import hackerone_program_list_command

    with pytest.raises(ValueError) as err:
        hackerone_program_list_command(mocked_client, args)

    assert str(err.value) == expected_error


@pytest.mark.parametrize("args, expected_params", input_data.report_list_args)
def test_validate_report_list_args_when_valid_args_are_provided(args, expected_params):
    """Test case scenario when report list valid arguments are provided."""
    from HackerOne import validate_report_list_args

    assert validate_report_list_args(args) == expected_params


def test_hackerone_report_list_command_when_empty_response_is_returned(mocked_client):
    """Test case scenario for successful execution of hackerone-report-list command with an empty response."""
    from HackerOne import hackerone_report_list_command

    mocked_client.http_request.return_value = {"data": [], "links": []}
    readable_output = "No reports were found for the given argument(s)."

    # Execute
    command_response = hackerone_report_list_command(mocked_client, {"program_handle": "abc"})

    # Assert
    assert command_response.readable_output == readable_output


def test_hackerone_report_list_command_when_valid_response_is_returned(mocked_client):
    """Test case scenario for successful execution of hackerone-report-list command."""
    from HackerOne import hackerone_report_list_command

    response = util_load_json(
        os.path.join("test_data", "report/report_command_response.json"))

    mocked_client.http_request.return_value = response

    context_output = util_load_json(
        os.path.join("test_data", "report/report_command_context.json"))

    with open(os.path.join("test_data", "report/report_command_readable_output.md"), 'r') as f:
        readable_output = f.read()

    # Execute
    command_response = hackerone_report_list_command(mocked_client, {"program_handle": "abc"})

    # Assert
    assert command_response.outputs_prefix == 'HackerOne.Report'
    assert command_response.outputs_key_field == "id"
    assert command_response.outputs == context_output
    assert command_response.readable_output == readable_output
    assert command_response.raw_response == response


@pytest.mark.parametrize("args, expected_error", input_data.invalid_args_for_report_list)
def test_hackerone_report_list_command_when_invalid_args_provided(mocked_client, args, expected_error):
    """Test case scenario when invalid arguments for report list command are provided."""
    from HackerOne import hackerone_report_list_command

    with pytest.raises(ValueError) as err:
        hackerone_report_list_command(mocked_client, args)

    assert str(err.value) == expected_error


def test_fetch_incident_when_empty_result_is_returned_on_first_fetch(mocked_client):
    """test case scenario when the results are empty on fetching for the first time."""
    from HackerOne import fetch_incidents
    last_run = {}

    mocked_client.http_request.return_value = {"data": [], "links": []}
    fetched_incidents = fetch_incidents(mocked_client, last_run,
                                        {"max_fetch": "15", "first_fetch": "2020-09-07T05:04:25Z",
                                         "program_handle": "something_h1b"})

    expected_next_run = {'current_created_at': '2020-09-07T05:04:25Z', 'next_page': 1}

    assert fetched_incidents == (expected_next_run, [])


def test_fetch_incident_when_valid_result_is_returned(mocked_client):
    """test case scenario when the results are valid on fetching for the first time."""

    from HackerOne import fetch_incidents

    last_run = {}
    incident_data = util_load_json(
        os.path.join("test_data", "incident/raw_response.json"))

    mocked_client.http_request.return_value = incident_data
    fetched_incidents = fetch_incidents(mocked_client, last_run,
                                        {"max_fetch": "1", "first_fetch": "2020-09-07T04:59:51Z",
                                         "program_handle": "checker_program_h1b"})

    next_run = {'next_page': 2, 'current_created_at': '2020-09-07T04:59:51Z',
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


def test_fetch_incident_when_empty_result_is_returned_on_second_fetch(mocked_client):
    """test case scenario when the result is empty on fetching for the second time."""

    from HackerOne import fetch_incidents
    mocked_client.http_request.return_value = {"data": [], "links": []}

    last_run = {'next_page': 2, 'current_created_at': '2020-09-07T04:59:51Z',
                'next_created_at': '2021-08-09T13:41:38.039Z',
                'report_ids': ['1295856']}

    second_fetched_incidents = fetch_incidents(mocked_client, last_run,
                                               {"max_fetch": "1", "first_fetch": "2020-09-07T04:59:51Z",
                                                "program_handle": "checker_program_h1b"})

    expected_next_run = {'next_page': 1, 'current_created_at': '2021-08-09T13:41:38.039Z',
                         'next_created_at': '2021-08-09T13:41:38.039Z',
                         'report_ids': ['1295856']}
    assert second_fetched_incidents == (expected_next_run, [])


def test_fetch_incident_when_getting_already_fetched_report(mocked_client):
    """test case scenario when the results are valid on fetching for the first time."""

    from HackerOne import fetch_incidents

    incident_data = util_load_json(
        os.path.join("test_data", "incident/raw_response.json"))

    last_run = {'next_page': 2, 'current_created_at': '2020-09-07T04:59:51Z',
                'next_created_at': '2021-08-09T13:41:38.039Z',
                'report_ids': ['1295856']}

    mocked_client.http_request.return_value = incident_data

    fetched_incidents = fetch_incidents(mocked_client, last_run,
                                        {"max_fetch": "1", "first_fetch": "2020-09-07T04:59:51Z",
                                         "program_handle": "checker_program_h1b"})
    next_run = {'next_page': 3, 'current_created_at': '2020-09-07T04:59:51Z',
                'next_created_at': '2021-08-09T13:41:38.039Z',
                'report_ids': ['1295856']}
    assert fetched_incidents == (next_run, [])


def test_fetch_incident_when_report_ids_should_be_replaced(mocked_client):
    """Test case scenario when report ids are replaced"""

    from HackerOne import fetch_incidents

    incident_data = util_load_json(
        os.path.join("test_data", "incident/raw_response.json"))

    last_run = {'next_page': 2, 'current_created_at': '2020-09-07T04:59:51Z',
                'next_created_at': '2020-09-07T04:59:51Z',
                'report_ids': ['1295852']}

    mocked_client.http_request.return_value = incident_data

    fetched_incidents = fetch_incidents(mocked_client, last_run,
                                        {"max_fetch": "1", "first_fetch": "2020-09-07T04:59:51Z",
                                         "program_handle": "checker_program_h1b"})

    next_run = {'next_page': 3, 'current_created_at': '2020-09-07T04:59:51Z',
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


@pytest.mark.parametrize("params, expected_params", input_data.valid_params_for_fetch_incidents)
def test_fetch_incident_when_valid_params_are_provided(params, expected_params):
    """test case scenario when valid parameters are provided for fetching the incidents."""
    from HackerOne import validate_fetch_incidents_parameters

    assert validate_fetch_incidents_parameters(params) == expected_params


@pytest.mark.parametrize("params, expected_error_msg", input_data.invalid_params_for_fetch_incidents)
def test_fetch_incident_when_invalid_params_are_provided(params, expected_error_msg):
    """test case scenario when invalid parameters are provided for fetching the incidents."""

    from HackerOne import validate_fetch_incidents_parameters

    with pytest.raises(ValueError) as err:
        validate_fetch_incidents_parameters(params)

    assert str(err.value) == expected_error_msg
