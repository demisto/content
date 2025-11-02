import json
from copy import deepcopy

import demistomock as demisto
import pytest
from freezegun import freeze_time

# Import the methods from your integration file
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
        demisto.info.assert_called_with(
            "Invalid next_page_token (expected integer for start_at_index): abc. Defaulting to 0."
        )

    # Verify the payload sent to _http_request
    expected_payload = {
        "query": {
            "models": ["Alert"],
            "type": "object_set",
            "with": {
                "type": "operation",
                "operator": "and",
                "values": [
                    {
                        "key": "CreatedAt",
                        "values": [last_fetch],
                        "type": "datetime",
                        "operator": "date_gte",
                        "value_type": "days"
                    }
                ]
            }
        },
        "limit": max_fetch,
        "start_at_index": expected_start_index,
        "order_by[]": ["CreatedAt"],
        "select": [
            "AlertId", "AlertType", "OrcaScore", "RiskLevel",
            "RuleSource", "ScoreVector", "Category", "Inventory.Name",
            "CloudAccount.Name", "CloudAccount.CloudProvider", "Source",
            "Status", "CreatedAt", "LastSeen", "Labels"
        ]
    }

    mock_http_request.assert_called_once_with(
        method="POST",
        url_suffix="/serving-layer/query",
        json_data=expected_payload
    )


# --- HELPER FUNCTION TESTS ---

def test_add_time_key_to_alerts():
    """
    Given:
        - A list of alerts with and without 'created_at' timestamps.
    When:
        - Calling add_time_key_to_alerts.
    Then:
        - Ensure _time key is added and correctly formatted for alerts with a timestamp.
        - Ensure _time key is None for alerts without a timestamp.
        - Ensure an empty list is handled.
    """
    alerts = [
        {"state": {"alert_id": "1", "created_at": "2023-01-01T12:00:00Z"}},
        {"state": {"alert_id": "2", "created_at": None}},
        {"state": {"alert_id": "3"}},
        {},
    ]

    expected = [
        {"state": {"alert_id": "1", "created_at": "2023-01-01T12:00:00Z"}, "_time": "2023-01-01T12:00:00Z"},
        {"state": {"alert_id": "2", "created_at": None}, "_time": None},
        {"state": {"alert_id": "3"}, "_time": None},
        {"_time": None},
    ]

    result = add_time_key_to_alerts(alerts)
    assert result == expected

    # Test empty list
    assert add_time_key_to_alerts([]) == []


# --- COMMAND FUNCTION TESTS ---

def test_get_alerts(mocker):
    """
    Given:
        - A mock client.
    When:
        - Calling get_alerts command.
    Then:
        - The list of alerts and the next page token is returned.
    """
    mock_response = MOCK_API_RESPONSES.get("test_1")

    # Mock the client's get_alerts_request method
    client = Client(server_url="https://test.com/api", headers={})
    mocker.patch.object(client, "get_alerts_request", return_value=mock_response)

    expected_alerts = mock_response.get("data", [])
    expected_next_page_token = mock_response.get("next_page_token")

    alerts, next_page_token = get_alerts(client, 1, "2023-03-08T00:00:00Z", None)

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
    assert 'Error in API call [404] - Not Found' in str(e.value)
    assert 'URL is invalid' in str(e.value)

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
    "max_fetch": "1",
}


# Freeze time for consistent 'first_fetch' calculation
@freeze_time("2023-03-14T00:00:00")
def test_main_fetch_events(mocker):
    """
    Given:
        - command="fetch-events", no last run (first fetch).
    When:
        - Calling main.
    Then:
        - Fetches events using the 'first_fetch' time.
        - Sends events to XSIAM.
        - Sets the correct last_run.
    """
    mocker.patch.object(demisto, "command", return_value="fetch-events")
    mocker.patch.object(demisto, "params", return_value=BASE_PARAMS)
    mocker.patch.object(demisto, "getLastRun", return_value={})  # No last run
    mock_set_last_run = mocker.patch.object(demisto, "setLastRun")
    mock_send_events = mocker.patch("OrcaEventCollector.send_events_to_xsiam")

    # Mock the API response
    api_response = MOCK_API_RESPONSES.get("test_1")
    mock_get_alerts = mocker.patch("OrcaEventCollector.get_alerts", return_value=(
        api_response.get("data"),
        api_response.get("next_page_token")
    ))

    main()

    # 1. Verify get_alerts was called with 'first_fetch' time
    expected_first_fetch_time = "2023-03-11T00:00:00Z"
    mock_get_alerts.assert_called_once_with(
        mocker.ANY,  # the client instance
        1,  # max_fetch
        expected_first_fetch_time,
        None  # next_page_token
    )

    # 2. Verify events were sent
    mock_send_events.assert_called_once()
    sent_alerts = mock_send_events.call_args[0][0]
    assert sent_alerts[0]["_time"] == "2023-03-11T00:00:00Z"  # Check add_time_key

    # 3. Verify last_run was set
    expected_last_run = {"lastRun": "2023-03-11T00:00:00Z", "next_page_token": "next_page_token"}
    mock_set_last_run.assert_called_once_with(expected_last_run)


@freeze_time("2023-03-14T00:00:00")
def test_main_fetch_events_pagination(mocker):
    """
    Given:
        - command="fetch-events", with a last run that includes a next_page_token.
    When:
        - Calling main.
    Then:
        - Fetches events using the 'lastRun' time and 'next_page_token'.
        - Sets the correct new last_run (without pagination token).
    """
    mocker.patch.object(demisto, "command", return_value="fetch-events")
    mocker.patch.object(demisto, "params", return_value=BASE_PARAMS)

    # Mock last run with pagination
    last_run = {"lastRun": "2023-03-10T00:00:00Z", "next_page_token": "100"}
    mocker.patch.object(demisto, "getLastRun", return_value=last_run)
    mock_set_last_run = mocker.patch.object(demisto, "setLastRun")
    mocker.patch("OrcaEventCollector.send_events_to_xsiam")

    # Mock the API response (last page)
    api_response = MOCK_API_RESPONSES.get("test_2")
    mock_get_alerts = mocker.patch("OrcaEventCollector.get_alerts", return_value=(
        api_response.get("data"),
        api_response.get("next_page_token")  # None
    ))

    main()

    # 1. Verify get_alerts was called with 'lastRun' time and token
    mock_get_alerts.assert_called_once_with(
        mocker.ANY,
        1,
        "2023-03-10T00:00:00Z",
        "100"
    )

    # 2. Verify last_run was set correctly (new time, no token)
    expected_last_run = {"lastRun": "2023-03-13T00:00:00Z", "next_page_token": None}
    mock_set_last_run.assert_called_once_with(expected_last_run)


@freeze_time("2023-03-14T00:00:00")
def test_main_fetch_no_new_alerts(mocker):
    """
    Given:
        - command="fetch-events", with a last run.
    When:
        - Calling main, and the API returns no alerts.
    Then:
        - No events are sent.
        - setLastRun is called with the *previous* last_fetch time.
    """
    mocker.patch.object(demisto, "command", return_value="fetch-events")
    mocker.patch.object(demisto, "params", return_value=BASE_PARAMS)

    last_run = {"lastRun": "2023-03-13T00:00:00Z", "next_page_token": None}
    mocker.patch.object(demisto, "getLastRun", return_value=last_run)
    mock_set_last_run = mocker.patch.object(demisto, "setLastRun")
    mock_send_events = mocker.patch("OrcaEventCollector.send_events_to_xsiam")

    # Mock empty API response
    api_response = MOCK_API_RESPONSES.get("empty")
    mocker.patch("OrcaEventCollector.get_alerts", return_value=(
        api_response.get("data"),
        api_response.get("next_page_token")
    ))

    main()

    # 1. Verify no events were sent
    mock_send_events.assert_not_called()

    # 2. Verify last_run was set with the *old* time
    expected_last_run = {"lastRun": "2023-03-13T00:00:00Z", "next_page_token": None}
    mock_set_last_run.assert_called_once_with(expected_last_run)


@freeze_time("2023-03-14T00:00:00")
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
        - Still sets last_run.
    """
    mocker.patch.object(demisto, "command", return_value="orca-security-get-events")
    mocker.patch.object(demisto, "params", return_value=BASE_PARAMS)
    mocker.patch.object(demisto, "args", return_value={"should_push_events": "false"})
    mocker.patch.object(demisto, "getLastRun", return_value={})
    mock_set_last_run = mocker.patch.object(demisto, "setLastRun")
    mock_send_events = mocker.patch("OrcaEventCollector.send_events_to_xsiam")
    mock_return_results = mocker.patch("OrcaEventCollector.return_results")

    api_response = MOCK_API_RESPONSES.get("test_1")
    mocker.patch("OrcaEventCollector.get_alerts", return_value=(
        api_response.get("data"),
        api_response.get("next_page_token")
    ))

    main()

    # 1. Verify results were returned
    mock_return_results.assert_called_once()

    # 2. Verify events were *not* sent
    mock_send_events.assert_not_called()

    # 3. Verify last_run was still set
    expected_last_run = {"lastRun": "2023-03-11T00:00:00Z", "next_page_token": "next_page_token"}
    mock_set_last_run.assert_called_once_with(expected_last_run)