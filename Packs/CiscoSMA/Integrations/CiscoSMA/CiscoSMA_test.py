import json
import os
import pytest
from unittest.mock import patch


"""MOCK PARAMETERS"""
CREDENTIALS = "credentials"


"""CONSTANTS"""
BASE_URL = "https://example.com/sma/api/v2.0"
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
@patch("CiscoSMA.Client.handle_request_headers", mock_access_token)
def mock_client():
    """
    Mock client
    """
    from CiscoSMA import Client

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
            45,
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
            45,
        ),
    ],
)
def test_spam_quarantine_message_search_command(
    response_file_name,
    command_arguments,
    expected_outputs_len,
    expected_message_id,
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
     - cisco-sma-spam-quarantine-message-search command called.
    Then:
     - Ensure outputs prefix is correct.
     - Ensure number of items is correct.
     - Validate outputs' fields.
    """
    from CiscoSMA import spam_quarantine_message_search_command

    mock_response = load_mock_response(response_file_name)
    url = f"{BASE_URL}/quarantine/messages"
    requests_mock.get(url=url, json=mock_response)

    result = spam_quarantine_message_search_command(mock_client, command_arguments)
    outputs = result.outputs

    assert result.outputs_prefix == "CiscoSMA.SpamQuarantineMessage"
    assert len(outputs) == expected_outputs_len
    assert outputs[0]["mid"] == expected_message_id


@pytest.mark.parametrize(
    "response_file_name,command_arguments,expected_message_id",
    [
        (
            "spam_quarantine_message_get.json",
            {"message_id": 50},
            50,
        )
    ],
)
def test_spam_quarantine_message_get_command(
    response_file_name,
    command_arguments,
    expected_message_id,
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
     - cisco-sma-spam-quarantine-message-get command called.
    Then:
     - Ensure outputs prefix is correct.
     - Validate outputs' fields.
    """
    from CiscoSMA import spam_quarantine_message_get_command

    mock_response = load_mock_response(response_file_name)
    url = f"{BASE_URL}/quarantine/messages/details"
    requests_mock.get(url=url, json=mock_response)

    result = spam_quarantine_message_get_command(mock_client, command_arguments)
    outputs = result.outputs

    assert result.outputs_prefix == "CiscoSMA.SpamQuarantineMessage"
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
    response_file_name, command_arguments, expected_message, requests_mock, mock_client
):
    """
    Scenario: Spam quarantine message release.
    Given:
     - User has provided valid credentials.
     - User may provided pagination args.
     - User may Provided filtering arguments.
    When:
     - cisco-sma-spam-quarantine-message-release command called.
    Then:
     - Ensure the human readable message is correct.
    """
    from CiscoSMA import spam_quarantine_message_release_command

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
    response_file_name,
    command_arguments,
    expected_message_first_id,
    expected_message_second_id,
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
     - cisco-sma-spam-quarantine-message-delete command called.
    Then:
     - Ensure the human readable message is correct.
    """
    from CiscoSMA import spam_quarantine_message_delete_command

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
    response_file_name,
    command_arguments,
    expected_outputs_len,
    expected_recipient_address,
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
     - cisco-sma-list-entry-get command called.
    Then:
     - Ensure outputs prefix is correct.
     - Ensure number of items is correct.
     - Validate outputs' fields.
    """
    from CiscoSMA import list_entry_get_command

    mock_response = load_mock_response(response_file_name)
    entry_type = command_arguments.get("entry_type")
    url = f"{BASE_URL}/quarantine/{entry_type}"
    requests_mock.get(url=url, json=mock_response)

    result = list_entry_get_command(mock_client, command_arguments)
    outputs = result.outputs

    assert result.outputs_prefix == f"CiscoSMA.ListEntry.{entry_type.title()}"
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
    command_arguments, expected_message, requests_mock, mock_client
):
    """
    Scenario: List entry add.
    Given:
     - User has provided valid credentials.
     - User may provided pagination args.
     - User may Provided filtering arguments.
    When:
     - cisco-sma-list-entry-get command called.
    Then:
     - Ensure the human readable message is correct.
    """
    from CiscoSMA import list_entry_add_command

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
    command_arguments, expected_message, requests_mock, mock_client
):
    """
    Scenario: List entry append.
    Given:
     - User has provided valid credentials.
     - User may provided pagination args.
     - User may Provided filtering arguments.
    When:
     - cisco-sma-list-entry-append command called.
    Then:
     - Ensure the human readable message is correct.
    """
    from CiscoSMA import list_entry_append_command

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
    command_arguments, expected_message, requests_mock, mock_client
):
    """
    Scenario: List entry edit.
    Given:
     - User has provided valid credentials.
     - User may provided pagination args.
     - User may Provided filtering arguments.
    When:
     - cisco-sma-list-entry-edit command called.
    Then:
     - Ensure the human readable message is correct.
    """
    from CiscoSMA import list_entry_edit_command

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
    command_arguments, expected_message, requests_mock, mock_client
):
    """
    Scenario: List entry delete.
    Given:
     - User has provided valid credentials.
     - User may provided pagination args.
     - User may Provided filtering arguments.
    When:
     - cisco-sma-list-entry-delete command called.
    Then:
     - Ensure the human readable message is correct.
    """
    from CiscoSMA import list_entry_delete_command

    entry_type = command_arguments.get("entry_type")
    url = f"{BASE_URL}/quarantine/{entry_type}"
    requests_mock.delete(url=url, json={})

    result = list_entry_delete_command(mock_client, command_arguments)

    assert result.readable_output == expected_message


@pytest.mark.parametrize(
    "response_file_name,command_arguments,expected_outputs_len,expected_message_id,expected_recipients,requested_params",
    [
        (
            "message_search.json",
            {
                "start_date": "1 week",
                "end_date": "now",
                "limit": "4",
                "subject_filter_operator": "contains",
                "subject_filter_value": "bla bla",
            },
            4,
            [315],
            ["test@test.com"],
            "bla%20bla",
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
            [315],
            ["test@test.com"],
            "test%40test.com",
        ),
    ],
)
def test_message_search_command(
    response_file_name,
    command_arguments,
    expected_outputs_len,
    expected_message_id,
    expected_recipients,
    requested_params,
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
     - cisco-sma-message-search command called.
    Then:
     - Ensure outputs prefix is correct.
     - Ensure number of items is correct.
     - Validate outputs' fields.
    """
    from CiscoSMA import message_search_command

    mock_response = load_mock_response(response_file_name)
    url = f"{BASE_URL}/message-tracking/messages"
    mock_request = requests_mock.get(url=url, json=mock_response)

    result = message_search_command(mock_client, command_arguments)
    outputs = result.outputs

    assert requested_params in mock_request.last_request.query
    assert result.outputs_prefix == "CiscoSMA.Message"
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
                "message_ids": [349],
                "injection_connection_id": 13646,
            },
            [349],
            ["test@test.com"],
            3,
        )
    ],
)
def test_message_details_get_command(
    response_file_name,
    command_arguments,
    expected_message_id,
    expected_recipients,
    expected_summary_len,
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
     - cisco-sma-message-details-get command called.
    Then:
     - Ensure outputs prefix is correct.
     - Validate outputs' fields.
    """
    from CiscoSMA import message_details_get_command

    mock_response = load_mock_response(response_file_name)
    url = f"{BASE_URL}/message-tracking/details"
    requests_mock.get(url=url, json=mock_response)

    result = message_details_get_command(mock_client, command_arguments)
    outputs = result.outputs

    assert result.outputs_prefix == "CiscoSMA.Message"
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
                "message_ids": [21],
            },
            [21],
            ["test@test.com"],
            3,
        )
    ],
)
def test_message_amp_details_get_command(
    response_file_name,
    command_arguments,
    expected_message_id,
    expected_recipients,
    expected_amp_summary_len,
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
     - cisco-sma-message-amp-details-get command called.
    Then:
     - Ensure outputs prefix is correct.
     - Validate outputs' fields.
    """
    from CiscoSMA import message_amp_details_get_command

    mock_response = load_mock_response(response_file_name)
    url = f"{BASE_URL}/message-tracking/amp-details"
    requests_mock.get(url=url, json=mock_response)

    result = message_amp_details_get_command(mock_client, command_arguments)
    outputs = result.outputs

    assert result.outputs_prefix == "CiscoSMA.AMPDetail"
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
                "message_ids": [84],
            },
            [84],
            ["test@test.com"],
            "PCI-DSS (Payment Card Industry Data Security Standard)",
        )
    ],
)
def test_message_dlp_details_get_command(
    response_file_name,
    command_arguments,
    expected_message_id,
    expected_recipients,
    expected_dlp_policy,
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
     - cisco-sma-message-dlp-details-get command called.
    Then:
     - Ensure outputs prefix is correct.
     - Validate outputs' fields.
    """
    from CiscoSMA import message_dlp_details_get_command

    mock_response = load_mock_response(response_file_name)
    url = f"{BASE_URL}/message-tracking/dlp-details"
    requests_mock.get(url=url, json=mock_response)

    result = message_dlp_details_get_command(mock_client, command_arguments)
    outputs = result.outputs

    assert result.outputs_prefix == "CiscoSMA.DLPDetail"
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
                "message_ids": [21],
            },
            [21],
            ["test@test.com"],
            3,
        )
    ],
)
def test_message_url_details_get_command(
    response_file_name,
    command_arguments,
    expected_message_id,
    expected_recipients,
    expected_url_summary_len,
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
     - cisco-sma-message-url-details-get command called.
    Then:
     - Ensure outputs prefix is correct.
     - Validate outputs' fields.
    """
    from CiscoSMA import message_url_details_get_command

    mock_response = load_mock_response(response_file_name)
    url = f"{BASE_URL}/message-tracking/url-details"
    requests_mock.get(url=url, json=mock_response)

    result = message_url_details_get_command(mock_client, command_arguments)
    outputs = result.outputs

    assert result.outputs_prefix == "CiscoSMA.URLDetail"
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
    response_file_name,
    command_arguments,
    expected_type,
    expected_results_len,
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
     - cisco-sma-report-get command called.
    Then:
     - Ensure outputs prefix is correct.
     - Validate outputs' fields.
    """
    from CiscoSMA import report_get_command

    mock_response = load_mock_response(response_file_name)
    url = f'{BASE_URL}/reporting/{command_arguments.get("report_type")}'
    requests_mock.get(url=url, json=mock_response)

    result = report_get_command(mock_client, command_arguments)
    outputs = result.outputs

    assert result.outputs_prefix == "CiscoSMA.Report"
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
def test_format_number_list_argument(number_list_argument, expected_result):
    """
    Scenario: Format number list argument.
    Given:
     - User has provided number list argument.
    When:
     - format_number_list_argument function called.
    Then:
     - Ensure result is correct.
    """
    from CiscoSMA import format_number_list_argument

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
def test_format_custom_query_args(custom_query_argument, expected_result):
    """
    Scenario: Format custom query arguments for tracking message advanced filters.
    Given:
     - User has provided custom query argument.
    When:
     - format_custom_query_args function called.
    Then:
     - Ensure result is correct.
    """
    from CiscoSMA import format_custom_query_args

    result = format_custom_query_args(custom_query_argument)

    assert result == expected_result


@pytest.mark.parametrize(
    "timestamp,output_format,expected_result",
    [
        (
            "07 Sep 2022 09:08:03 (GMT)",
            "%Y-%m-%dT%H:%M:%SZ",
            "2022-09-07T09:08:03Z"
        ),
        (
            "24 Apr 2023 10:14:50 (GMT -05:00)",
            "%Y-%m-%dT%H:%M:00.000Z",
            "2023-04-24T15:14:00.000Z"
        ),
        (
            "24 Apr 2023 10:14:50 (GMT-06:00)",
            "%Y-%m-%dT%H:%M:%SZ",
            "2023-04-24T16:14:50Z"
        ),
        (
            "24 Apr 2023 10:14:50 (GMT +01:00)",
            "%Y-%m-%dT%H:%M:%SZ",
            "2023-04-24T09:14:50Z"
        )
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
    from CiscoSMA import format_timestamp

    result = format_timestamp(timestamp, output_format)

    assert result == expected_result
