"""FlashpointCreateThreatIntelReport Test File."""

import json
from unittest.mock import patch

import demistomock as demisto
import pytest
from FlashpointCreateThreatIntelReport import (
    CREATE_XSOAR_THREAT_INTEL_REPORT_COMMAND,
    DRAFT_STATUS,
    EMPTY_REPORT_BODY,
    ERROR_MESSAGES,
    REPORT_GET_COMMAND,
    REPORT_TYPE,
    create_threat_intel_report,
    main,
)

""" CONSTANTS """

REPORT_ID = "00000000000000000001"
TEST_DATA_PATH = "test_data/ignite_report_get.json"
EXPECTED_PAYLOAD_PATH = "test_data/create_report_payload.json"
EXPECTED_READABLE_OUTPUT_PATH = "test_data/create_report_readable_output.md"

""" UTILITY FUNCTIONS """


def util_load_json(path: str):
    """Load a json to python dict."""
    with open(path, encoding="utf-8") as f:
        return json.loads(f.read())


def util_load_text(path: str):
    """Load a file to a string."""
    with open(path, encoding="utf-8") as f:
        return f.read()


def get_execute_command_mock(mocker, report_response, create_response=None):
    """
    Mock demisto.executeCommand to return the given responses for the report-get and create commands.

    :type mocker: pytest_mock.MockerFixture
    :param mocker: Mocker fixture.

    :type report_response: Any
    :param report_response: Response to return for the report-get command.

    :type create_response: Any
    :param create_response: Response to return for the createThreatIntelReport command. Defaults to the sample
        response of the command.

    :return: The mocked executeCommand object.
    """
    created = create_response or [util_load_json(TEST_DATA_PATH)["create_report_success"]]

    def side_effect(command, args):
        if command == REPORT_GET_COMMAND:
            return report_response
        if command == CREATE_XSOAR_THREAT_INTEL_REPORT_COMMAND:
            return created
        return [{"Type": 1, "Contents": "", "ContentsFormat": "text"}]

    return mocker.patch.object(demisto, "executeCommand", side_effect=side_effect)


def get_create_call_args(execute_command_mock):
    """
    Return the arguments passed to the createThreatIntelReport command.

    :type execute_command_mock: unittest.mock.MagicMock
    :param execute_command_mock: The mocked executeCommand object.

    :return: Arguments of the createThreatIntelReport call.
    :rtype: dict
    """
    create_calls = [
        call for call in execute_command_mock.call_args_list if call.args[0] == CREATE_XSOAR_THREAT_INTEL_REPORT_COMMAND
    ]

    assert len(create_calls) == 1
    return create_calls[0].args[1]


""" TEST CASES """


def test_create_threat_intel_report_success(mocker):
    """
    Test case scenario for successful execution of create_threat_intel_report.

    Given:
       - report_id argument
    When:
       - Calling `create_threat_intel_report` function
    Then:
       - Maps every Ignite field onto the Threat Intel Report, converts the HTML body to markdown, prefixes it
         with the metadata header, and returns the created entry.
    """
    test_data = util_load_json(TEST_DATA_PATH)
    report_response = test_data["report_get_success"]

    execute_command_mock = get_execute_command_mock(mocker, [report_response])

    created_entry, command_results = create_threat_intel_report({"report_id": REPORT_ID})

    assert created_entry == test_data["create_report_success"]
    assert command_results.readable_output == util_load_text(EXPECTED_READABLE_OUTPUT_PATH)

    assert execute_command_mock.call_args_list[0].args == (REPORT_GET_COMMAND, {"report_id": REPORT_ID})
    assert get_create_call_args(execute_command_mock) == util_load_json(EXPECTED_PAYLOAD_PATH)


@pytest.mark.parametrize(
    "report, expected_body, expected_status, absent_fields",
    [
        (
            {"id": REPORT_ID, "published_status": "draft", "body": "<h1>Head</h1><p>Text.</p>"},
            f"**Report ID:** {REPORT_ID}\n\n**Report Body**\n\n---\n\n# Head\n\nText.",
            DRAFT_STATUS,
            ["name", "description", "published", "modified", "tags"],
        ),
        (
            {"id": REPORT_ID, "actors": ["", None], "platform_url": "", "body": "<p>Text.</p>"},
            f"**Report ID:** {REPORT_ID}\n\n**Report Body**\n\n---\n\nText.",
            DRAFT_STATUS,
            ["name", "description", "published", "modified", "tags"],
        ),
        (
            {"id": REPORT_ID},
            f"**Report ID:** {REPORT_ID}\n\n**Report Body**\n\n---\n\n{EMPTY_REPORT_BODY}",
            DRAFT_STATUS,
            ["name", "description", "published", "modified", "tags"],
        ),
    ],
)
def test_create_threat_intel_report_when_fields_are_absent(mocker, report, expected_body, expected_status, absent_fields):
    """
    Test case scenario for execution of create_threat_intel_report when the report is missing fields.

    Given:
       - report_id argument and a report without some of the mapped fields
    When:
       - Calling `create_threat_intel_report` function
    Then:
       - Sends only the fields that are present, so the absent ones do not overwrite the defaults of the object,
         and keeps the absent metadata fields out of the body header.
    """
    execute_command_mock = get_execute_command_mock(mocker, [{"Type": 1, "Contents": report, "ContentsFormat": "json"}])

    create_threat_intel_report({"report_id": REPORT_ID})

    args = get_create_call_args(execute_command_mock)
    assert args["value"] == REPORT_ID
    assert args["type"] == REPORT_TYPE
    assert args["reportstatus"] == expected_status
    assert args["bodyexecutivebrief"] == expected_body
    for field in absent_fields:
        assert field not in args


@pytest.mark.parametrize(
    "report_response, create_response, expected_error",
    [
        (
            [{"Type": 4, "Contents": "Error in API call [404] - Not Found", "ContentsFormat": "text"}],
            None,
            ERROR_MESSAGES["FAILED_COMMAND"].format(REPORT_GET_COMMAND, "Error in API call [404] - Not Found"),
        ),
        (
            [{"Type": 1, "Contents": {"title": "No ID"}, "ContentsFormat": "json"}],
            None,
            ERROR_MESSAGES["NO_REPORT"].format(REPORT_ID),
        ),
        (
            [{"Type": 1, "Contents": {}, "ContentsFormat": "json"}],
            None,
            ERROR_MESSAGES["NO_REPORT"].format(REPORT_ID),
        ),
        (
            [{"Type": 1, "Contents": "", "ContentsFormat": "text"}],
            None,
            ERROR_MESSAGES["NO_REPORT"].format(REPORT_ID),
        ),
        (
            None,
            [{"Type": 4, "Contents": "Object creation failed", "ContentsFormat": "text"}],
            ERROR_MESSAGES["FAILED_COMMAND"].format(CREATE_XSOAR_THREAT_INTEL_REPORT_COMMAND, "Object creation failed"),
        ),
    ],
)
def test_create_threat_intel_report_when_command_fails(mocker, report_response, create_response, expected_error):
    """
    Test case scenario for execution of create_threat_intel_report when one of the executed commands fails.

    Given:
       - report_id argument and an error or unusable response from the report-get or create command
    When:
       - Calling `create_threat_intel_report` function
    Then:
       - Raises a valid error message.
    """
    report_response = report_response or [util_load_json(TEST_DATA_PATH)["report_get_success"]]
    get_execute_command_mock(mocker, report_response, create_response)

    with pytest.raises(ValueError) as error:
        create_threat_intel_report({"report_id": REPORT_ID})

    assert str(error.value) == expected_error


@pytest.mark.parametrize("args", [{}, {"report_id": None}, {"report_id": ""}])
def test_create_threat_intel_report_when_invalid_arguments(mocker, args):
    """
    Test case scenario for execution of create_threat_intel_report when report_id is not provided.

    Given:
       - no report_id argument
    When:
       - Calling `create_threat_intel_report` function
    Then:
       - Raises a valid error message and does not execute any command.
    """
    execute_command_mock = mocker.patch.object(demisto, "executeCommand")

    with pytest.raises(ValueError) as error:
        create_threat_intel_report(args)

    assert str(error.value) == ERROR_MESSAGES["MISSING_ARGUMENT"].format("report_id")
    assert execute_command_mock.call_count == 0


@patch("FlashpointCreateThreatIntelReport.return_results")
def test_main_success(mock_return_results, mocker):
    """
    Test case scenario for successful execution of the script through the main function.

    Given:
       - report_id argument with surrounding whitespaces
    When:
       - Calling `main` function
    Then:
       - Creates the Threat Intel Report from the trimmed report ID and returns the created entry.
    """
    test_data = util_load_json(TEST_DATA_PATH)

    mocker.patch.object(demisto, "args", return_value={"report_id": f" {REPORT_ID} "})
    execute_command_mock = get_execute_command_mock(mocker, test_data["report_get_success"])

    main()

    assert mock_return_results.call_args.args[0][0] == test_data["create_report_success"]
    assert execute_command_mock.call_args_list[0].args == (REPORT_GET_COMMAND, {"report_id": REPORT_ID})


@patch("FlashpointCreateThreatIntelReport.return_error")
def test_main_calls_return_error_on_exception(mock_return_error, mocker):
    """
    Test case scenario for execution of the script through the main function when an exception is raised.

    Given:
       - no report_id argument
    When:
       - Calling `main` function
    Then:
       - Returns a valid error message.
    """
    mocker.patch.object(demisto, "args", return_value={})
    mocker.patch.object(demisto, "error")

    main()

    assert mock_return_error.call_args.args[0] == (
        f"Failed to execute FlashpointCreateThreatIntelReport. Error: {ERROR_MESSAGES['MISSING_ARGUMENT'].format('report_id')}"
    )
