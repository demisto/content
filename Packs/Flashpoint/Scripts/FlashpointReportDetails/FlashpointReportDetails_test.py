"""FlashpointReportDetails Test File."""

import json
from unittest.mock import patch

import demistomock as demisto
import pytest
from FlashpointReportDetails import (
    ALERT_TEXT_FIELD,
    EMPTY_DATA,
    ERROR_MESSAGES,
    REPORT_GET_COMMAND,
    SET_INCIDENT_COMMAND,
    get_report_details,
    main,
)

""" CONSTANTS """

REPORT_ID = "00000000000000000001"

""" UTILITY FUNCTIONS """


def util_load_json(path: str):
    """Load a json to python dict."""
    with open(path, encoding="utf-8") as f:
        return json.loads(f.read())


def get_execute_command_mock(mocker, report_response):
    """
    Mock demisto.executeCommand to return the given response for the report-get command.

    :type mocker: pytest_mock.MockerFixture
    :param mocker: Mocker fixture.

    :type report_response: Any
    :param report_response: Response to return for the report-get command.

    :return: The mocked executeCommand object.
    """

    def side_effect(command, args):
        if command == REPORT_GET_COMMAND:
            return report_response
        return [{"Type": 1, "Contents": "", "ContentsFormat": "text"}]

    return mocker.patch.object(demisto, "executeCommand", side_effect=side_effect)


def assert_set_incident_call(execute_command_mock, expected_body):
    """
    Assert that setIncident was called with the expected report body.

    :type execute_command_mock: unittest.mock.MagicMock
    :param execute_command_mock: The mocked executeCommand object.

    :type expected_body: str
    :param expected_body: Expected value of the report body field.
    """
    set_incident_calls = [call for call in execute_command_mock.call_args_list if call.args[0] == SET_INCIDENT_COMMAND]

    assert len(set_incident_calls) == 1
    assert set_incident_calls[0].args[1] == {ALERT_TEXT_FIELD: expected_body}


""" TEST CASES """


@pytest.mark.parametrize(
    "args, incident",
    [
        ({"report_id": REPORT_ID}, {}),
        ({}, {"CustomFields": {"flashpointsourceid": REPORT_ID}}),
    ],
)
def test_get_report_details_success(mocker, args, incident):
    """
    Test case scenario for successful execution of get_report_details.

    Given:
       - report_id argument, or an incident with the 'flashpointsourceid' custom field
    When:
       - Calling `get_report_details` function
    Then:
       - Returns the raw report entry and sets the report body on the incident.
    """
    report_response = util_load_json("test_data/report_get_success.json")

    mocker.patch.object(demisto, "incident", return_value=incident)
    execute_command_mock = get_execute_command_mock(mocker, [report_response])

    result = get_report_details(args)

    assert result == report_response
    assert execute_command_mock.call_args_list[0].args == (REPORT_GET_COMMAND, {"report_id": REPORT_ID})
    assert_set_incident_call(execute_command_mock, report_response["Contents"]["body"])


def test_get_report_details_when_no_report_body(mocker):
    """
    Test case scenario for execution of get_report_details when the command succeeds without a report body.

    Given:
       - report_id argument and a successful response without a body
    When:
       - Calling `get_report_details` function
    Then:
       - Returns the raw report entry and sets the placeholder message on the incident.
    """
    report_response = util_load_json("test_data/report_get_success_without_body.json")

    mocker.patch.object(demisto, "incident", return_value={})
    execute_command_mock = get_execute_command_mock(mocker, [report_response])

    result = get_report_details({"report_id": REPORT_ID})

    assert result == report_response
    assert_set_incident_call(execute_command_mock, EMPTY_DATA)


def test_get_report_details_when_command_fails(mocker):
    """
    Test case scenario for execution of get_report_details when the report-get command fails.

    Given:
       - report_id argument and a non-list error response from the report-get command
    When:
       - Calling `get_report_details` function
    Then:
       - Returns an empty dict, logs the error and sets the placeholder message on the incident.
    """
    error = "Error in API call [404] - Not Found"

    mocker.patch.object(demisto, "incident", return_value={})
    error_mock = mocker.patch.object(demisto, "error")
    execute_command_mock = get_execute_command_mock(mocker, {"Type": 4, "Contents": error, "ContentsFormat": "text"})

    result = get_report_details({"report_id": REPORT_ID})

    assert result == {}
    assert error_mock.call_args.args[0] == ERROR_MESSAGES["FAILED_COMMAND"].format(REPORT_GET_COMMAND, error)
    assert_set_incident_call(execute_command_mock, EMPTY_DATA)


@pytest.mark.parametrize(
    "args, incident",
    [
        ({}, {}),
        ({"report_id": None}, {}),
        ({"report_id": ""}, {"CustomFields": {}}),
        ({"report_id": ""}, {"CustomFields": {"flashpointsourceid": ""}}),
    ],
)
def test_get_report_details_when_invalid_arguments(mocker, args, incident):
    """
    Test case scenario for execution of get_report_details when report_id can not be resolved.

    Given:
       - no report_id argument and an incident without the 'flashpointsourceid' custom field
    When:
       - Calling `get_report_details` function
    Then:
       - Raises a valid error message.
    """
    mocker.patch.object(demisto, "incident", return_value=incident)
    execute_command_mock = mocker.patch.object(demisto, "executeCommand")

    with pytest.raises(ValueError) as error:
        get_report_details(args)

    assert str(error.value) == ERROR_MESSAGES["MISSING_ARGUMENT"].format("report_id")
    assert execute_command_mock.call_count == 0


@patch("FlashpointReportDetails.return_results")
def test_main_success(mock_return_results, mocker):
    """
    Test case scenario for successful execution of the script through the main function.

    Given:
       - report_id argument with surrounding whitespaces
    When:
       - Calling `main` function
    Then:
       - Returns the raw report entry and sets the report body on the incident.
    """
    report_response = util_load_json("test_data/report_get_success.json")

    mocker.patch.object(demisto, "args", return_value={"report_id": f" {REPORT_ID} "})
    mocker.patch.object(demisto, "incident", return_value={})
    execute_command_mock = get_execute_command_mock(mocker, [report_response])

    main()

    assert mock_return_results.call_args.args[0] == report_response
    assert execute_command_mock.call_args_list[0].args == (REPORT_GET_COMMAND, {"report_id": REPORT_ID})
    assert_set_incident_call(execute_command_mock, report_response["Contents"]["body"])


@patch("FlashpointReportDetails.return_error")
def test_main_calls_return_error_on_exception(mock_return_error, mocker):
    """
    Test case scenario for execution of the script through the main function when an exception is raised.

    Given:
       - no report_id argument and an incident without the 'flashpointsourceid' custom field
    When:
       - Calling `main` function
    Then:
       - Returns a valid error message.
    """
    mocker.patch.object(demisto, "args", return_value={})
    mocker.patch.object(demisto, "incident", return_value={})
    mocker.patch.object(demisto, "error")

    main()

    assert mock_return_error.call_args.args[0] == (
        f"Failed to execute FlashpointReportDetails. Error: {ERROR_MESSAGES['MISSING_ARGUMENT'].format('report_id')}"
    )
