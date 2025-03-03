import json
import os
from typing import Any
import pytest
from unittest.mock import patch
from freezegun import freeze_time

"""MOCK PARAMETERS"""
CREDENTIALS = "credentials"


"""CONSTANTS"""
BASE_URL = "https://example.com/esa/api/v2.0"
USERNAME = "MOCK_USER"
PASSWORD = "XXX"
TOKEN = "XXX-XXXX"


def load_mock_response(file_name: str) -> str:
    """
    Load mock file that simulates an API response.
    Args:
        file_name (str): Name of the mock response JSON file to return.
    Returns:
        str: Mock file content.
    """
    with open(
        os.path.join("test_data/outputs", file_name), encoding="utf-8"
    ) as mock_file:
        return json.loads(mock_file.read())


def mock_access_token(client):
    return TOKEN


@pytest.fixture(autouse=True)
@patch(
    "CiscoEmailSecurityApplianceIronPortV2.Client.handle_request_headers",
    mock_access_token,
)
def mock_client():
    """
    Mock client
    """
    from CiscoEmailSecurityApplianceIronPortV2 import Client

    return Client(BASE_URL, USERNAME, PASSWORD, verify=False, proxy=False)


""" TESTING INTEGRATION COMMANDS"""


@pytest.mark.parametrize(
    "response_file_name,command_arguments,expected_outputs_len,expected_message_id",
    [
        (
            "spam_quarantine_message_search.json",
            {
                "start_date": "1 day",
                "end_date": "now",
                "limit": "3",
            },
            3,
            783,
        ),
        (
            "spam_quarantine_message_search.json",
            {
                "start_date": "2 weeks",
                "end_date": "1 day",
                "page": "2",
                "page_size": "3",
                "filter_by": "subject",
                "filter_operator": "contains",
                "filter_value": "test",
            },
            3,
            783,
        ),
    ],
)
def test_spam_quarantine_message_search_command(
    response_file_name: str,
    command_arguments: dict[str, Any],
    expected_outputs_len: int,
    expected_message_id: int,
    requests_mock,
    mock_client,
):
    """
    Scenario: Spam quarantine message search.
    Given:
     - User has provided valid credentials.
     - User may provided pagination args.
     - User may Provided filtering arguments.
    When:
     - cisco-esa-spam-quarantine-message-search command called.
    Then:
     - Ensure outputs prefix is correct.
     - Ensure number of items is correct.
     - Validate outputs' fields.
    """
    from CiscoEmailSecurityApplianceIronPortV2 import (
        spam_quarantine_message_search_command,
    )

    mock_response = load_mock_response(response_file_name)
    url = f"{BASE_URL}/quarantine/messages"
    requests_mock.get(url=url, json=mock_response)

    result = spam_quarantine_message_search_command(mock_client, command_arguments)
    outputs = result.outputs

    assert result.outputs_prefix == "CiscoESA.SpamQuarantineMessage"
    assert len(outputs) == expected_outputs_len
    assert outputs[0]["mid"] == expected_message_id


@pytest.mark.parametrize(
    "response_file_name,command_arguments,expected_message_id",
    [
        (
            "spam_quarantine_message_get.json",
            {"message_id": 620},
            620,
        )
    ],
)
def test_spam_quarantine_message_get_command(
    response_file_name: str,
    command_arguments: dict[str, Any],
    expected_message_id: int,
    requests_mock,
    mock_client,
):
    """
    Scenario: Spam quarantine message get.
    Given:
     - User has provided valid credentials.
     - User may provided pagination args.
     - User may Provided filtering arguments.
    When:
     - cisco-esa-spam-quarantine-message-get command called.
    Then:
     - Ensure outputs prefix is correct.
     - Validate outputs' fields.
    """
    from CiscoEmailSecurityApplianceIronPortV2 import (
        spam_quarantine_message_get_command,
    )

    mock_response = load_mock_response(response_file_name)
    url = f"{BASE_URL}/quarantine/messages/details"
    requests_mock.get(url=url, json=mock_response)

    result = spam_quarantine_message_get_command(mock_client, command_arguments)
    outputs = result.outputs

    assert result.outputs_prefix == "CiscoESA.SpamQuarantineMessage"
    assert outputs["mid"] == expected_message_id


@pytest.mark.parametrize(
    "response_file_name,command_arguments,expected_message",
    [
        (
            "spam_quarantine_message_release.json",
            {"message_ids": [50]},
            "Quarantined message 50 successfully released.",
        )
    ],
)
def test_spam_quarantine_message_release_command(
    response_file_name: str,
    command_arguments: dict[str, Any],
    expected_message: str,
    requests_mock,
    mock_client,
):
    """
    Scenario: Spam quarantine message release.
    Given:
     - User has provided valid credentials.
     - User may provided pagination args.
     - User may Provided filtering arguments.
    When:
     - cisco-esa-spam-quarantine-message-release command called.
    Then:
     - Ensure the human readable message is correct.
    """
    from CiscoEmailSecurityApplianceIronPortV2 import (
        spam_quarantine_message_release_command,
    )

    mock_response = load_mock_response(response_file_name)
    url = f"{BASE_URL}/quarantine/messages"
    requests_mock.post(url=url, json=mock_response)

    result = spam_quarantine_message_release_command(mock_client, command_arguments)

    assert result[0].readable_output == expected_message


@pytest.mark.parametrize(
    "response_file_name,command_arguments,expected_message_first_id,expected_message_second_id",
    [
        (
            "spam_quarantine_message_delete.json",
            {"message_ids": [100, 101]},
            "Quarantined message 100 successfully deleted.",
            "Quarantined message 101 successfully deleted.",
        ),
        (
            "spam_quarantine_message_delete_failed.json",
            {"message_ids": [120, 121]},
            "Quarantined message 120 not found.",
            "Quarantined message 121 not found.",
        ),
    ],
)
def test_spam_quarantine_message_delete_command(
    response_file_name: str,
    command_arguments: dict[str, Any],
    expected_message_first_id: str,
    expected_message_second_id: str,
    requests_mock,
    mock_client,
):
    """
    Scenario: Spam quarantine message delete.
    Given:
     - User has provided valid credentials.
     - User may provided pagination args.
     - User may Provided filtering arguments.
    When:
     - cisco-esa-spam-quarantine-message-delete command called.
    Then:
     - Ensure the human readable message is correct.
    """
    from CiscoEmailSecurityApplianceIronPortV2 import (
        spam_quarantine_message_delete_command,
    )

    mock_response = load_mock_response(response_file_name)
    url = f"{BASE_URL}/quarantine/messages"
    requests_mock.delete(url=url, json=mock_response)

    result = spam_quarantine_message_delete_command(mock_client, command_arguments)

    assert result[0].readable_output == expected_message_first_id
    assert result[1].readable_output == expected_message_second_id


@pytest.mark.parametrize(
    "response_file_name,command_arguments,expected_outputs_len,expected_recipient_address",
    [
        (
            "list_entry_get_blocklist.json",
            {
                "entry_type": "blocklist",
                "limit": "2",
            },
            2,
            "test@test.com",
        ),
        (
            "list_entry_get_safelist.json",
            {
                "entry_type": "safelist",
                "page": "2",
                "page_size": "1",
            },
            1,
            "test@test.com",
        ),
    ],
)
def test_list_entry_get_command(
    response_file_name: str,
    command_arguments: dict[str, Any],
    expected_outputs_len: int,
    expected_recipient_address: str,
    requests_mock,
    mock_client,
):
    """
    Scenario: List entry get.
    Given:
     - User has provided valid credentials.
     - User may provided pagination args.
     - User may Provided filtering arguments.
    When:
     - cisco-esa-list-entry-get command called.
    Then:
     - Ensure outputs prefix is correct.
     - Ensure number of items is correct.
     - Validate outputs' fields.
    """
    from CiscoEmailSecurityApplianceIronPortV2 import list_entry_get_command

    mock_response = load_mock_response(response_file_name)
    entry_type = command_arguments.get("entry_type")
    url = f"{BASE_URL}/quarantine/{entry_type}"
    requests_mock.get(url=url, json=mock_response)

    result = list_entry_get_command(mock_client, command_arguments)
    outputs = result.outputs

    assert result.outputs_prefix == f"CiscoESA.ListEntry.{entry_type.title()}"
    assert len(outputs) == expected_outputs_len
    assert outputs[0]["recipientAddress"] == expected_recipient_address


@pytest.mark.parametrize(
    "command_arguments,expected_message",
    [
        (
            {
                "entry_type": "blocklist",
                "view_by": "recipient",
                "recipient_addresses": ["test@test.com"],
                "sender_list": ["t1@test.com", "t2@test.com"],
            },
            "Successfully added t1@test.com, t2@test.com senders to test@test.com recipients in blocklist.",
        )
    ],
)
def test_list_entry_add_command(
    command_arguments: dict[str, Any], expected_message: str, requests_mock, mock_client
):
    """
    Scenario: List entry add.
    Given:
     - User has provided valid credentials.
     - User may provided pagination args.
     - User may Provided filtering arguments.
    When:
     - cisco-esa-list-entry-add command called.
    Then:
     - Ensure the human readable message is correct.
    """
    from CiscoEmailSecurityApplianceIronPortV2 import list_entry_add_command

    entry_type = command_arguments.get("entry_type")
    url = f"{BASE_URL}/quarantine/{entry_type}"
    requests_mock.post(url=url, json={})

    result = list_entry_add_command(mock_client, command_arguments)

    assert result.readable_output == expected_message


@pytest.mark.parametrize(
    "command_arguments,expected_message",
    [
        (
            {
                "entry_type": "safelist",
                "view_by": "sender",
                "sender_addresses": ["test@test.com", "test2@test.com"],
                "recipient_list": ["t3@test.com", "t4@test.com"],
            },
            "Successfully appended t3@test.com, t4@test.com recipients to test@test.com, test2@test.com senders in safelist.",
        )
    ],
)
def test_list_entry_append_command(
    command_arguments: dict[str, Any], expected_message: str, requests_mock, mock_client
):
    """
    Scenario: List entry append.
    Given:
     - User has provided valid credentials.
     - User may provided pagination args.
     - User may Provided filtering arguments.
    When:
     - cisco-esa-list-entry-append command called.
    Then:
     - Ensure the human readable message is correct.
    """
    from CiscoEmailSecurityApplianceIronPortV2 import list_entry_append_command

    entry_type = command_arguments.get("entry_type")
    url = f"{BASE_URL}/quarantine/{entry_type}"
    requests_mock.post(url=url, json={})

    result = list_entry_append_command(mock_client, command_arguments)

    assert result.readable_output == expected_message


@pytest.mark.parametrize(
    "command_arguments,expected_message",
    [
        (
            {
                "entry_type": "safelist",
                "view_by": "sender",
                "sender_addresses": ["test@test.com", "test2@test.com"],
                "recipient_list": ["t3@test.com", "t4@test.com"],
            },
            "Successfully edited test@test.com, test2@test.com senders' recipients to t3@test.com, t4@test.com in safelist.",
        )
    ],
)
def test_list_entry_edit_command(
    command_arguments: dict[str, Any], expected_message: str, requests_mock, mock_client
):
    """
    Scenario: List entry edit.
    Given:
     - User has provided valid credentials.
     - User may provided pagination args.
     - User may Provided filtering arguments.
    When:
     - cisco-esa-list-entry-edit command called.
    Then:
     - Ensure the human readable message is correct.
    """
    from CiscoEmailSecurityApplianceIronPortV2 import list_entry_edit_command

    entry_type = command_arguments.get("entry_type")
    url = f"{BASE_URL}/quarantine/{entry_type}"
    requests_mock.post(url=url, json={})

    result = list_entry_edit_command(mock_client, command_arguments)

    assert result.readable_output == expected_message


@pytest.mark.parametrize(
    "command_arguments,expected_message",
    [
        (
            {
                "entry_type": "blocklist",
                "view_by": "recipient",
                "recipient_list": ["test@test.com"],
            },
            "Successfully deleted test@test.com recipients from blocklist.",
        )
    ],
)
def test_list_entry_delete_command(
    command_arguments: dict[str, Any], expected_message: str, requests_mock, mock_client
):
    """
    Scenario: List entry delete.
    Given:
     - User has provided valid credentials.
     - User may provided pagination args.
     - User may Provided filtering arguments.
    When:
     - cisco-esa-list-entry-delete command called.
    Then:
     - Ensure the human readable message is correct.
    """
    from CiscoEmailSecurityApplianceIronPortV2 import list_entry_delete_command

    entry_type = command_arguments.get("entry_type")
    url = f"{BASE_URL}/quarantine/{entry_type}"
    requests_mock.delete(url=url, json={})

    result = list_entry_delete_command(mock_client, command_arguments)

    assert result.readable_output == expected_message


@pytest.mark.parametrize(
    "response_file_name,command_arguments,expected_outputs_len,expected_message_id,expected_recipients",
    [
        (
            "message_search.json",
            {
                "start_date": "1 week",
                "end_date": "now",
                "limit": "4",
            },
            4,
            [780],
            ["test@test.com"],
        ),
        (
            "message_search.json",
            {
                "start_date": "2 weeks",
                "end_date": "1 day",
                "page": "2",
                "page_size": "4",
                "recipient_filter_operator": "is",
                "recipient_filter_value": "test@test.com",
            },
            4,
            [780],
            ["test@test.com"],
        ),
    ],
)
def test_message_search_command(
    response_file_name: str,
    command_arguments: dict[str, Any],
    expected_outputs_len: int,
    expected_message_id: list[int],
    expected_recipients: list[str],
    requests_mock,
    mock_client,
):
    """
    Scenario: Tracking message search.
    Given:
     - User has provided valid credentials.
     - User may provided pagination args.
     - User may Provided filtering arguments.
    When:
     - cisco-esa-message-search command called.
    Then:
     - Ensure outputs prefix is correct.
     - Ensure number of items is correct.
     - Validate outputs' fields.
    """
    from CiscoEmailSecurityApplianceIronPortV2 import message_search_command

    mock_response = load_mock_response(response_file_name)
    url = f"{BASE_URL}/message-tracking/messages"
    requests_mock.get(url=url, json=mock_response)

    result = message_search_command(mock_client, command_arguments)
    outputs = result.outputs

    assert result.outputs_prefix == "CiscoESA.Message"
    assert len(outputs) == expected_outputs_len
    assert outputs[0]["mid"] == expected_message_id
    assert outputs[1]["recipient"] == expected_recipients


@pytest.mark.parametrize(
    "response_file_name,command_arguments,expected_message_id,expected_recipients,expected_summary_len",
    [
        (
            "message_details_get.json",
            {
                "serial_number": "TESTAAA",
                "message_ids": [765, 766, 767],
                "injection_connection_id": 23092,
            },
            [765, 766, 767],
            ["test@test.com"],
            5,
        )
    ],
)
def test_message_details_get_command(
    response_file_name: str,
    command_arguments: dict[str, Any],
    expected_message_id: list[int],
    expected_recipients: list[str],
    expected_summary_len: int,
    requests_mock,
    mock_client,
):
    """
    Scenario: Message detail get.
    Given:
     - User has provided valid credentials.
     - User may provided pagination args.
     - User may Provided filtering arguments.
    When:
     - cisco-esa-message-details-get command called.
    Then:
     - Ensure outputs prefix is correct.
     - Validate outputs' fields.
    """
    from CiscoEmailSecurityApplianceIronPortV2 import message_details_get_command

    mock_response = load_mock_response(response_file_name)
    url = f"{BASE_URL}/message-tracking/details"
    requests_mock.get(url=url, json=mock_response)

    result = message_details_get_command(mock_client, command_arguments)
    outputs = result.outputs

    assert result.outputs_prefix == "CiscoESA.Message"
    assert outputs["mid"] == expected_message_id
    assert outputs["recipient"] == expected_recipients
    assert len(outputs["summary"]) == expected_summary_len


@pytest.mark.parametrize(
    "response_file_name,command_arguments,expected_message_id,expected_recipients,expected_amp_summary_len",
    [
        (
            "message_amp_details_get.json",
            {
                "serial_number": "TESTAAA",
                "message_ids": [765, 766, 767],
            },
            [765, 766, 767],
            ["test@test.com"],
            3,
        )
    ],
)
def test_message_amp_details_get_command(
    response_file_name: str,
    command_arguments: dict[str, Any],
    expected_message_id: list[int],
    expected_recipients: list[str],
    expected_amp_summary_len: int,
    requests_mock,
    mock_client,
):
    """
    Scenario: Message AMP details summary get.
    Given:
     - User has provided valid credentials.
     - User may provided pagination args.
     - User may Provided filtering arguments.
    When:
     - cisco-esa-message-amp-details-get command called.
    Then:
     - Ensure outputs prefix is correct.
     - Validate outputs' fields.
    """
    from CiscoEmailSecurityApplianceIronPortV2 import message_amp_details_get_command

    mock_response = load_mock_response(response_file_name)
    url = f"{BASE_URL}/message-tracking/amp-details"
    requests_mock.get(url=url, json=mock_response)

    result = message_amp_details_get_command(mock_client, command_arguments)
    outputs = result.outputs

    assert result.outputs_prefix == "CiscoESA.AMPDetail"
    assert outputs["mid"] == expected_message_id
    assert outputs["recipient"] == expected_recipients
    assert len(outputs["ampDetails"]) == expected_amp_summary_len


@pytest.mark.parametrize(
    "response_file_name,command_arguments,expected_message_id,expected_recipients,expected_dlp_policy",
    [
        (
            "message_dlp_details_get.json",
            {
                "serial_number": "TESTAAA",
                "message_ids": [1131],
            },
            [1131],
            ["test@test.com"],
            "US HIPAA and HITECH (Low Threshold)",
        )
    ],
)
def test_message_dlp_details_get_command(
    response_file_name: str,
    command_arguments: dict[str, Any],
    expected_message_id: list[int],
    expected_recipients: list[str],
    expected_dlp_policy: str,
    requests_mock,
    mock_client,
):
    """
    Scenario: Message dlp details summary get.
    Given:
     - User has provided valid credentials.
     - User may provided pagination args.
     - User may Provided filtering arguments.
    When:
     - cisco-esa-message-dlp-details-get command called.
    Then:
     - Ensure outputs prefix is correct.
     - Validate outputs' fields.
    """
    from CiscoEmailSecurityApplianceIronPortV2 import message_dlp_details_get_command

    mock_response = load_mock_response(response_file_name)
    url = f"{BASE_URL}/message-tracking/dlp-details"
    requests_mock.get(url=url, json=mock_response)

    result = message_dlp_details_get_command(mock_client, command_arguments)
    outputs = result.outputs

    assert result.outputs_prefix == "CiscoESA.DLPDetail"
    assert outputs["mid"] == expected_message_id
    assert outputs["recipient"] == expected_recipients
    assert outputs["dlpDetails"]["dlpPolicy"] == expected_dlp_policy


@pytest.mark.parametrize(
    "response_file_name,command_arguments,expected_message_id,expected_recipients,expected_url_summary_len",
    [
        (
            "message_url_details_get.json",
            {
                "serial_number": "TESTAAA",
                "message_ids": [222, 223, 224],
            },
            [222, 223, 224],
            ["test@test.com"],
            7,
        )
    ],
)
def test_message_url_details_get_command(
    response_file_name: str,
    command_arguments: dict[str, Any],
    expected_message_id: list[int],
    expected_recipients: list[str],
    expected_url_summary_len: int,
    requests_mock,
    mock_client,
):
    """
    Scenario: Message url details summary get.
    Given:
     - User has provided valid credentials.
     - User may provided pagination args.
     - User may Provided filtering arguments.
    When:
     - cisco-esa-message-url-details-get command called.
    Then:
     - Ensure outputs prefix is correct.
     - Validate outputs' fields.
    """
    from CiscoEmailSecurityApplianceIronPortV2 import message_url_details_get_command

    mock_response = load_mock_response(response_file_name)
    url = f"{BASE_URL}/message-tracking/url-details"
    requests_mock.get(url=url, json=mock_response)

    result = message_url_details_get_command(mock_client, command_arguments)
    outputs = result.outputs

    assert result.outputs_prefix == "CiscoESA.URLDetail"
    assert outputs["mid"] == expected_message_id
    assert outputs["recipient"] == expected_recipients
    assert len(outputs["urlDetails"]) == expected_url_summary_len


@pytest.mark.parametrize(
    "response_file_name,command_arguments,expected_type,expected_results_len",
    [
        (
            "report_get.json",
            {
                "report_type": "mail_incoming_traffic_summary",
                "start_date": "1 week",
                "end_date": "now",
            },
            "mail_incoming_traffic_summary",
            26,
        )
    ],
)
def test_message_report_get_command(
    response_file_name: str,
    command_arguments: dict[str, Any],
    expected_type: str,
    expected_results_len: int,
    requests_mock,
    mock_client,
):
    """
    Scenario: Report get.
    Given:
     - User has provided valid credentials.
     - User may provided pagination args.
     - User may Provided filtering arguments.
    When:
     - cisco-esa-report-get command called.
    Then:
     - Ensure outputs prefix is correct.
     - Validate outputs' fields.
    """
    from CiscoEmailSecurityApplianceIronPortV2 import report_get_command

    mock_response = load_mock_response(response_file_name)
    url = f'{BASE_URL}/reporting/{command_arguments.get("report_type")}'
    requests_mock.get(url=url, json=mock_response)

    result = report_get_command(mock_client, command_arguments)
    outputs = result.outputs

    assert result.outputs_prefix == "CiscoESA.Report"
    assert outputs["type"] == expected_type
    assert len(outputs["resultSet"]) == expected_results_len


""" TESTING HELPER FUNCTIONS"""


@pytest.mark.parametrize(
    "number_list_argument,expected_result",
    [
        (
            "10,20,30",
            [10, 20, 30],
        )
    ],
)
def test_format_number_list_argument(
    number_list_argument: str, expected_result: list[int]
):
    """
    Scenario: Format number list argument.
    Given:
     - User has provided number list argument.
    When:
     - format_number_list_argument function called.
    Then:
     - Ensure result is correct.
    """
    from CiscoEmailSecurityApplianceIronPortV2 import format_number_list_argument

    result = format_number_list_argument(number_list_argument)

    assert result == expected_result


@pytest.mark.parametrize(
    "custom_query_argument,expected_result",
    [
        (
            "test_key1=test_value1;test_key2=test_value2",
            {"test_key1": "test_value1", "test_key2": "test_value2"},
        )
    ],
)
def test_format_custom_query_args(
    custom_query_argument: str, expected_result: dict[str, Any]
):
    """
    Scenario: Format custom query arguments for tracking message advanced filters.
    Given:
     - User has provided custom query argument.
    When:
     - format_custom_query_args function called.
    Then:
     - Ensure result is correct.
    """
    from CiscoEmailSecurityApplianceIronPortV2 import format_custom_query_args

    result = format_custom_query_args(custom_query_argument)

    assert result == expected_result


@pytest.mark.parametrize(
    "timestamp,output_format,expected_result",
    [
        ("07 Sep 2022 09:08:03 (GMT)", "%Y-%m-%dT%H:%M:%SZ", "2022-09-07T09:08:03Z"),
        (
            "24 Apr 2023 10:14:50 (GMT -05:00)",
            "%Y-%m-%dT%H:%M:00.000Z",
            "2023-04-24T15:14:00.000Z",
        ),
        (
            "24 Apr 2023 10:14:50 (GMT-06:00)",
            "%Y-%m-%dT%H:%M:%SZ",
            "2023-04-24T16:14:50Z",
        ),
        (
            "24 Apr 2023 10:14:50 (GMT +01:00)",
            "%Y-%m-%dT%H:%M:%SZ",
            "2023-04-24T09:14:50Z",
        ),
        (None, "%Y-%m-%dT%H:%M:%SZ", None),
    ],
)
def test_format_timestamp(timestamp, output_format, expected_result):
    """
    Given:
     - timestamps strings.
    When:
     - format_timestamp function called.
    Then:
     - Ensure result is correct.
    """
    from CiscoEmailSecurityApplianceIronPortV2 import format_timestamp

    result = format_timestamp(timestamp, output_format)

    assert result == expected_result


data_test_fetch_incidents = [
    ({}, 0, {}),
    ({}, 1, {"last_minute_incident_ids": [1], "start_time": "2023-06-29T00:00:00Z"}),
    ({}, 2, {"last_minute_incident_ids": [1, 2], "start_time": "2023-06-29T00:00:00Z"}),
    (
        {"last_minute_incident_ids": [1, 2]},
        2,
        {"offset": 2, "last_minute_incident_ids": [1, 2]},
    ),
    (
        {"last_minute_incident_ids": [1, 2], "offset": 2},
        2,
        {"last_minute_incident_ids": [1, 2], "offset": 4},
    ),
    (
        {"last_minute_incident_ids": [3, 2], "offset": 2},
        1,
        {"last_minute_incident_ids": [3, 2, 1], "start_time": "2023-06-29T00:00:00Z"},
    ),
]


@pytest.mark.parametrize(
    "previous_run, fetch_size, expected_last_run", data_test_fetch_incidents
)
@freeze_time("2023-06-29T00:00:00Z")
def test_fetch_incidents(
    mock_client, mocker, previous_run, fetch_size, expected_last_run
):
    from CiscoEmailSecurityApplianceIronPortV2 import fetch_incidents

    mocker.patch.object(
        mock_client,
        "spam_quarantine_message_search_request",
        return_value={
            "data": [
                {"attributes": {"date": "now"}, "mid": i + 1} for i in range(fetch_size)
            ]
        },
    )
    incidents = [{"mid": i + 1} for i in range(fetch_size)]
    mocker.patch.object(
        mock_client,
        "spam_quarantine_message_get_request",
        new=lambda *_a, **_b: {"data": incidents.pop(0)},
    )

    _, last_run = fetch_incidents(
        mock_client,
        max_fetch=2,
        first_fetch="1 day",
        last_run=previous_run,
    )
    assert last_run == expected_last_run


def test_check_dictionary_mode_args():
    """
    Given:
     - A mode type ("group" or "machine") and respective arguments (`host_name` and `group_name`).
    When:
     - The check_dictionary_mode_args function is called with these arguments.
    Then:
     - Ensure the function correctly returns a tuple with the appropriate host name and group name based on the mode.
    """
    from CiscoEmailSecurityApplianceIronPortV2 import (
        check_dictionary_mode_args,
    )

    assert check_dictionary_mode_args("group", host_name="", group_name="group1") == (None, "group1")
    assert check_dictionary_mode_args("machine", host_name="host1", group_name="") == ("host1", None)


def test_convert_words_to_list():
    """
    Given:
     - A string representing a list of lists containing words, numbers, or both.
    When:
     - The convert_words_to_list function is called with the input string.
    Then:
     - Ensure the function correctly converts the input string to a list of lists, preserving the order and data types.
    """
    from CiscoEmailSecurityApplianceIronPortV2 import (
        convert_words_to_list,
    )
    assert convert_words_to_list("['test']") == [['test']]
    assert convert_words_to_list("['test1'],['test2']") == [['test1'], ['test2']]
    assert convert_words_to_list("['test1',5],['test2',7]") == [['test1', 5], ['test2', 7]]
    assert convert_words_to_list("['test1',5,'prefix'],['test2',7]") == [['test1', 5, 'prefix'], ['test2', 7]]


def test_dictionary_list_command(mocker, mock_client):
    """
    Given:
     - A dictionary name as input.
    When:
     - The dictionary_list_command is called.
    Then:
     - Ensure the command returns the correct information about the dictionary.
    """
    from CiscoEmailSecurityApplianceIronPortV2 import (
        dictionary_list_command,
    )
    mock_response = {
        "data": [
            {
                "name": "example_dictionary",
                "encoding": "UTF-8",
                "ignorecase": 1,
                "words": ["example", "test", "demo"],
                "words_count": {
                    "term_count": 3,
                    "smart_identifier_count": 1,
                },
                "wholewords": 0,
            }
        ]
    }
    mocker.patch(
        "CiscoEmailSecurityApplianceIronPortV2.Client.dictionary_list_request",
        return_value=mock_response
    )

    args = {"dictionary_name": "example_dictionary"}
    result = dictionary_list_command(mock_client, args)

    assert "Information for Dictionary: example_dictionary" in result.readable_output

    outputs = result.outputs
    assert outputs == mock_response["data"]

    dictionary_output = outputs[0]
    assert dictionary_output["name"] == "example_dictionary"
    assert dictionary_output["encoding"] == "UTF-8"
    assert dictionary_output["ignorecase"] == 1
    assert dictionary_output["words"] == ["example", "test", "demo"]
    assert dictionary_output["words_count"]["term_count"] == 3
    assert dictionary_output["words_count"]["smart_identifier_count"] == 1
    assert dictionary_output["wholewords"] == 0


def test_dictionary_add_command(mocker, mock_client):
    """
    Given:
     - A dictionary name and words to add.
    When:
     - The dictionary_add_command is called.
    Then:
     - Ensure the dictionary is added successfully with the correct output message.
    """
    from CiscoEmailSecurityApplianceIronPortV2 import (
        dictionary_add_command,
    )

    mocker.patch(
        "CiscoEmailSecurityApplianceIronPortV2.Client.dictionary_add_request",
        return_value={"status": "success"}
    )

    args = {"dictionary_name": "TestDict", "words": "[['word1'],['word2']]"}
    result = dictionary_add_command(mock_client, args)

    assert "TestDict was added successfully." in result.readable_output


def test_dictionary_edit_command(mocker, mock_client):
    """
    Given:
     - A dictionary name, updated name, and new words.
    When:
     - The dictionary_edit_command is called.
    Then:
     - Ensure the dictionary is updated successfully with the correct output message.
    """
    from CiscoEmailSecurityApplianceIronPortV2 import (
        dictionary_edit_command,
    )

    mocker.patch(
        "CiscoEmailSecurityApplianceIronPortV2.Client.dictionary_edit_request",
        return_value={"status": "success"}
    )

    args = {"dictionary_name": "TestDict", "updated_name": "NewTestDict", "words": "[['word1'],['word2']]"}
    result = dictionary_edit_command(mock_client, args)

    assert "TestDict has been successfully updated." in result.readable_output


def test_dictionary_delete_command(mocker, mock_client):
    """
    Given:
     - A dictionary name to delete.
    When:
     - The dictionary_delete_command is called.
    Then:
     - Ensure the dictionary is deleted successfully with the correct output message.
    """
    from CiscoEmailSecurityApplianceIronPortV2 import (
        dictionary_delete_command,
    )

    mocker.patch(
        "CiscoEmailSecurityApplianceIronPortV2.Client.dictionary_delete_request",
        return_value={"status": "success"}
    )

    args = {"dictionary_name": "TestDict"}
    result = dictionary_delete_command(mock_client, args)
    assert "TestDict deleted successfully." in result.readable_output


def test_dictionary_words_add_command(mocker, mock_client):
    """
    Given:
     - A dictionary name and words to add to it.
    When:
     - The dictionary_words_add_command is called.
    Then:
     - Ensure the words are added successfully with the correct output message.
    """
    from CiscoEmailSecurityApplianceIronPortV2 import (
        dictionary_words_add_command,
    )

    mocker.patch(
        "CiscoEmailSecurityApplianceIronPortV2.Client.dictionary_words_add_request",
        return_value={"status": "success"}
    )

    args = {"dictionary_name": "TestDict", "words": "['word1', 'word2']"}
    result = dictionary_words_add_command(mock_client, args)

    assert "Added successfully to TestDict." in result.readable_output


def test_dictionary_words_delete_command(mocker, mock_client):
    """
    Given:
     - A dictionary name and words to delete from it.
    When:
     - The dictionary_words_delete_command is called.
    Then:
     - Ensure the words are deleted successfully with the correct output message and result type.
    """
    from CiscoEmailSecurityApplianceIronPortV2 import (
        dictionary_words_delete_command,
    )

    mocker.patch(
        "CiscoEmailSecurityApplianceIronPortV2.Client.dictionary_words_delete_request",
        return_value={"status": "success"}
    )

    args = {"dictionary_name": "TestDict", "words": "['word1', 'word2']"}
    result = dictionary_words_delete_command(mock_client, args)

    assert "Words deleted successfully from TestDict." in result.readable_output
