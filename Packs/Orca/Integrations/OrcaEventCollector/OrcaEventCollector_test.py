import json

import demistomock as demisto
import pytest
from freezegun import freeze_time

from OrcaEventCollector import Client, get_alerts, add_time_key_to_alerts, orca_test_module, main
from CommonServerPython import DemistoException


# --- MOCK DATA ---


def util_load_json(path):
    with open(path, encoding="utf-8") as f:
        return json.loads(f.read())


MOCK_API_RESPONSES = util_load_json("test_data/get_alerts_test.json")


# --- CLIENT CLASS TESTS ---


@pytest.mark.parametrize(
    "next_page_token, expected_start_index",
    [
        (None, 0),
        ("100", 100),
        ("abc", 0),  # Invalid token defaults to 0
    ],
)
def test_client_get_alerts_request_payload(mocker, next_page_token, expected_start_index):
    """
    Given:
        - A last_fetch time and various next_page_tokens.
    When:
        - Calling get_alerts_request.
    Then:
        - Ensure the _http_request method is called with the correct POST payload.
        - Ensure pagination (start_at_index) is handled correctly.
    """
    mocker.patch.object(demisto, "info")  # Mock demisto.info for the invalid token case
    mock_http_request = mocker.patch.object(Client, "_http_request")

    client = Client(server_url="https://test.com/api", headers={})
    last_fetch = "2023-01-01T00:00:00Z"
    max_fetch = 150

    client.get_alerts_request(max_fetch, last_fetch, next_page_token)

    # Verify the invalid token case logs an info message
    if next_page_token == "abc":
        demisto.info.assert_called_with("Invalid next_page_token (expected integer for start_at_index): abc. Defaulting to 0.")

    # Verify the payload sent to _http_request
    expected_payload = {
        "query": {
            "models": ["Alert"],
            "type": "object_set",
            "with": {
                "type": "operation",
                "operator": "and",
                "values": [
                    {"key": "CreatedAt", "values": [last_fetch], "type": "datetime", "operator": "date_gte", "value_type": "days"}
                ],
            },
        },
        "limit": max_fetch,
        "start_at_index": expected_start_index,
        "order_by[]": ["CreatedAt"],
        "select": [
            "AlertId",
            "AlertType",
            "OrcaScore",
            "RiskLevel",
            "RuleSource",
            "ScoreVector",
            "Category",
            "Inventory.Name",
            "CloudAccount.Name",
            "CloudAccount.CloudProvider",
            "Source",
            "Status",
            "CreatedAt",
            "LastSeen",
            "Labels",
        ],
    }

    mock_http_request.assert_called_once_with(method="POST", url_suffix="/serving-layer/query", json_data=expected_payload)


# --- HELPER FUNCTION TESTS ---


@freeze_time("2023-01-04T00:00:00")
def test_add_time_key_to_alerts_corrected(mocker):
    """
    Given:
        - A list of alerts in the actual API response format.
    When:
        - Calling add_time_key_to_alerts (the corrected version).
    Then:
        - Ensure _time key is added and correctly formatted from 'data.CreatedAt.value'.
        - Ensure _time key is None for alerts with missing timestamps.
    """
    mocker.patch.object(demisto, "debug")  # Mock debug calls
    alerts = [
        {"data": {"CreatedAt": {"value": "2023-01-01T12:00:00Z"}}},
        {"data": {"CreatedAt": {"value": "2023-01-02T13:00:00+00:00"}}},  # Test timezone
        {"data": {"CreatedAt": {"value": None}}},
        {"data": {"CreatedAt": {}}},  # Missing 'value'
        {"data": {}},  # Missing 'CreatedAt'
        {},  # Empty alert
    ]

    expected = [
        {"data": {"CreatedAt": {"value": "2023-01-01T12:00:00Z"}}, "_time": "2023-01-01T12:00:00Z"},
        {"data": {"CreatedAt": {"value": "2023-01-02T13:00:00+00:00"}}, "_time": "2023-01-02T13:00:00Z"},
        {"data": {"CreatedAt": {"value": None}}, "_time": "2023-01-04T00:00:00Z"},
        {"data": {"CreatedAt": {}}, "_time": "2023-01-04T00:00:00Z"},
        {"data": {}, "_time": "2023-01-04T00:00:00Z"},
        {"_time": "2023-01-04T00:00:00Z"},
    ]

    result = add_time_key_to_alerts(alerts)
    assert result == expected

    # Test empty list
    assert add_time_key_to_alerts([]) == []


# --- COMMAND FUNCTION TESTS ---


def test_get_alerts(mocker):
    """
    Given:
        - A mock client and a mock response from the file.
    When:
        - Calling get_alerts command.
    Then:
        - The list of alerts and the next page token is returned.
    """
    # Load data from our mock file
    MOCK_API_RESPONSES = util_load_json("test_data/get_alerts_test.json")
    mock_response = MOCK_API_RESPONSES["page_1_with_more"]

    # Mock the client's get_alerts_request method
    client = Client(server_url="https://test.com/api", headers={})
    mocker.patch.object(client, "get_alerts_request", return_value=mock_response)

    expected_alerts = mock_response.get("data", [])
    expected_next_page_token = mock_response.get("next_page_token")

    alerts, next_page_token = get_alerts(client, 1, "2023-01-01T00:00:00Z", None)

    assert alerts == expected_alerts
    assert next_page_token == expected_next_page_token


def test_orca_test_module(mocker):
    """
    Given:
        - A mock client.
    When:
        - Calling test-module.
    Then:
        - Return 'ok' on success.
        - Raise the correct exception on failure (404).
        - Raise a generic exception on other failures.
    """
    client = Client(server_url="https://test.com/api", headers={})

    # Test success
    mocker.patch.object(client, "get_alerts_request", return_value={})
    assert orca_test_module(client, "2023-01-01T00:00:00Z", 1) == "ok"

    # Test 404 failure
    mocker.patch.object(client, "get_alerts_request", side_effect=DemistoException("Error in API call [404] - Not Found"))
    with pytest.raises(Exception) as e:
        orca_test_module(client, "2023-01-01T00:00:00Z", 1)
    assert "Error in API call [404] - Not Found" in str(e.value)
    assert "URL is invalid" in str(e.value)

    # Test other failure
    mocker.patch.object(client, "get_alerts_request", side_effect=DemistoException("Some other error"))
    with pytest.raises(Exception) as e:
        orca_test_module(client, "2023-01-01T00:00:00Z", 1)
    assert "Some other error" in str(e.value)


# --- MAIN FUNCTION TESTS ---

# Base parameters for all main function tests
BASE_PARAMS = {
    "credentials": {"password": "api_token"},
    "insecure": True,
    "proxy": False,
    "server_url": "server_url",
    "first_fetch": "3 days",
    "max_fetch": "1000",
}


@freeze_time("2023-01-04T00:00:00")  # Set a consistent 'now' for '3 days'
@pytest.mark.parametrize(
    "test_name, last_run_in, mock_data_key, expected_last_fetch_arg, "
    "expected_token_arg, expected_set_last_run, expected_events_sent_count",
    [
        (
            "1. First Run (fetches events, last page)",
            {},  # No last run
            "page_2_last",  # Mocks 2 alerts, no more pages
            "2023-01-01T00:00:00Z",  # '3 days' before freeze_time
            None,
            {"lastRun": "2023-01-01T13:00:00Z", "next_page_token": None},  # Sets lastRun to last event
            2,
        ),
        (
            "2. First Run (no events)",
            {},  # No last run
            "empty",  # Mocks 0 alerts
            "2023-01-01T00:00:00Z",  # '3 days' before freeze_time
            None,
            {"lastRun": "2023-01-01T00:00:00Z", "next_page_token": None},  # Sets lastRun back to first_fetch time
            0,
        ),
        (
            "3. Second Run (fetches new events)",
            {"lastRun": "2023-01-01T09:00:00Z", "next_page_token": None},  # Last run was T1
            "single_alert_no_more",  # Mocks 1 alert, no more pages
            "2023-01-01T09:00:00Z",  # Uses lastRun time
            None,
            {"lastRun": "2023-01-02T10:00:00Z", "next_page_token": None},  # Sets lastRun to last event
            1,
        ),
        (
            "4. Second Run (no new events)",
            {"lastRun": "2023-01-01T09:00:00Z", "next_page_token": None},
            "empty",  # Mocks 0 alerts
            "2023-01-01T09:00:00Z",
            None,
            {"lastRun": "2023-01-01T09:00:00Z", "next_page_token": None},  # lastRun time is unchanged
            0,
        ),
        (
            "5. Pagination (Page 1)",
            {"lastRun": "2023-01-01T09:00:00Z", "next_page_token": None},
            "page_1_with_more",  # Mocks 2 alerts, has next_page_token
            "2023-01-01T09:00:00Z",
            None,
            {"lastRun": "2023-01-01T09:00:00Z", "next_page_token": "100"},  # lastRun time unchanged, token added
            2,
        ),
        (
            "6. Pagination (Page 2 - last page)",
            {"lastRun": "2023-01-01T09:00:00Z", "next_page_token": "100"},  # Has page token
            "page_2_last",  # Mocks 2 alerts, no more pages
            "2023-01-01T09:00:00Z",  # Uses lastRun time
            "100",  # Uses lastRun token
            {"lastRun": "2023-01-01T13:00:00Z", "next_page_token": None},  # Sets lastRun to last event, token cleared
            2,
        ),
    ],
)
def test_main_fetch_events_scenarios(
    mocker,
    test_name,
    last_run_in,
    mock_data_key,
    expected_last_fetch_arg,
    expected_token_arg,
    expected_set_last_run,
    expected_events_sent_count,
):
    """
    Given:
        - Various 'fetch-events' scenarios (first run, second run, pagination, no events).
    When:
        - Calling main() with the 'fetch-events' command.
    Then:
        - Ensure get_alerts is called with the correct time and token.
        - Ensure send_events_to_xsiam is called with the correct number of events.
        - Ensure setLastRun is called with the correct new lastRun object.
    """
    # Load mock data from file and select the scenario
    api_response = MOCK_API_RESPONSES[mock_data_key]

    mocker.patch.object(demisto, "command", return_value="fetch-events")
    mocker.patch.object(demisto, "params", return_value=BASE_PARAMS)
    mocker.patch.object(demisto, "getLastRun", return_value=last_run_in)
    mock_set_last_run = mocker.patch.object(demisto, "setLastRun")
    mock_send_events = mocker.patch("OrcaEventCollector.send_events_to_xsiam")

    # Mock get_alerts to return the specific data and token for this scenario
    mock_get_alerts = mocker.patch(
        "OrcaEventCollector.get_alerts", return_value=(api_response.get("data"), api_response.get("next_page_token"))
    )

    mocker.patch.object(demisto, "debug")  # Mock debug calls
    mocker.patch.object(demisto, "info")  # Mock info calls

    main()

    # 1. Verify get_alerts call
    mock_get_alerts.assert_called_once_with(
        mocker.ANY,  # the client instance
        1000,  # max_fetch from BASE_PARAMS
        expected_last_fetch_arg,
        expected_token_arg,
    )

    # 2. Verify send_events call
    if expected_events_sent_count > 0:
        mock_send_events.assert_called_once()
        sent_alerts = mock_send_events.call_args[0][0]
        assert len(sent_alerts) == expected_events_sent_count
        # Check that _time was added correctly
        assert "_time" in sent_alerts[0]
        assert sent_alerts[0]["_time"] is not None
    else:
        mock_send_events.assert_not_called()

    # 3. Verify last_run was set
    mock_set_last_run.assert_called_once_with(expected_set_last_run)


@freeze_time("2023-01-04T00:00:00")
def test_main_get_events_command(mocker):
    """
    Given:
        - command="orca-security-get-events"
    When:
        - Calling main.
    Then:
        - Fetches events.
        - Does *not* send events to XSIAM.
        - Returns results via return_results.
        - Still sets last_run correctly (using new logic).
    """
    # Load mock data
    api_response = MOCK_API_RESPONSES["single_alert_no_more"]

    mocker.patch.object(demisto, "command", return_value="orca-security-get-events")
    mocker.patch.object(demisto, "params", return_value=BASE_PARAMS)
    mocker.patch.object(demisto, "args", return_value={"should_push_events": "false"})
    mocker.patch.object(demisto, "getLastRun", return_value={})  # First run
    mock_set_last_run = mocker.patch.object(demisto, "setLastRun")
    mock_send_events = mocker.patch("OrcaEventCollector.send_events_to_xsiam")
    mock_return_results = mocker.patch("OrcaEventCollector.return_results")
    mocker.patch.object(demisto, "debug")
    mocker.patch.object(demisto, "info")

    # Mock get_alerts to return the specific data and token
    mocker.patch("OrcaEventCollector.get_alerts", return_value=(api_response.get("data"), api_response.get("next_page_token")))

    main()

    # 1. Verify results were returned
    mock_return_results.assert_called_once()
    # Check that the raw_response in CommandResults is the list of alerts
    assert mock_return_results.call_args[0][0].raw_response == api_response.get("data")

    # 2. Verify events were *not* sent
    mock_send_events.assert_not_called()

    # 3. Verify last_run was still set correctly
    expected_last_run = {"lastRun": "2023-01-02T10:00:00Z", "next_page_token": None}  # From last event
    mock_set_last_run.assert_called_once_with(expected_last_run)
