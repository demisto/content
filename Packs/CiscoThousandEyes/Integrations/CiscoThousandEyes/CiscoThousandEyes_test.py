import json

import pytest
import demistomock as demisto


def util_load_json(path):
    with open(path, encoding="utf-8") as f:
        return json.loads(f.read())


def mock_client():
    """
    Create a mock client for testing.
    """
    from CiscoThousandEyes import Client

    return Client(
        base_url="example.com",
        verify=False,
        proxy=False,
        headers={},
    )


def mock_http_request(method, full_url, params=None):
    if "alerts" in full_url:
        return util_load_json("test_data/alerts_list.json")
    elif "audit" in full_url:
        return util_load_json("test_data/events_list.json")
    return {}


@pytest.mark.parametrize(
    "fetch_type, next_page_url, request_url, previous_page_url, expected_result, case_id",
    [
        pytest.param(
            "alerts",
            "https://api.example.com/v1/alerts?page=2",
            "https://api.example.com/v1/alerts?page=1",
            "https://api.example.com/v1/alerts?page=1",
            True,
            "Case 1: alerts, next_page_url != request_url",
            id="alerts_next_page_different",
        ),
        pytest.param(
            "alerts",
            "https://api.example.com/v1/alerts?page=1",
            "https://api.example.com/v1/alerts?page=1",
            "https://api.example.com/v1/alerts?page=1",
            False,
            "Case 2: alerts, next_page_url == request_url",
            id="alerts_next_page_same",
        ),
        pytest.param(
            "audit",
            "https://api.example.com/v1/events?page=2",
            "https://api.example.com/v1/events?page=2",
            "https://api.example.com/v1/events?page=1",
            True,
            "Case 3: events, request_url != previous_page_url",
            id="events_request_diff_previous",
        ),
        pytest.param(
            "audit",
            "https://api.example.com/v1/events?page=1",
            "https://api.example.com/v1/events?page=1",
            "https://api.example.com/v1/events?page=1",
            False,
            "Case 4: events, request_url == previous_page_url",
            id="events_request_same_previous",
        ),
    ],
)
def test_is_fetch_paginated(fetch_type, next_page_url, request_url, previous_page_url, expected_result, case_id):
    """
    Given:
    - Different scenarios for pagination during data fetch:
      1. Fetch type is 'alerts' or 'events'.
      2. Various combinations of next_page_url, request_url, and previous_page_url.

    When:
    - Determining if the fetch operation should proceed to the next page.

    Then:
    - Return True if pagination should continue (e.g., next_page_url differs from request_url or previous_page_url).
    - Return False if pagination should stop (e.g., next_page_url matches request_url or previous_page_url).
    """
    from CiscoThousandEyes import is_fetch_paginated
    result = is_fetch_paginated(fetch_type, next_page_url, request_url, previous_page_url)
    assert result is expected_result, f"Failed {case_id}"


def test_full_fetch_events(mocker):
    """
    Given:
    - A client configured to fetch events and alerts.
    - A previous last run state containing the last fetched timestamps for alerts and events.
    - A mock HTTP request function simulating API responses for alerts and events.

    When:
    - Fetching events and alerts using the `fetch_events` function with specified fetch limits.

    Then:
    - Ensure the correct number of events are returned.
    - Verify the next run state includes the correct offset for alerts and contains a "nextTrigger".
    - Confirm the first event has the expected start date.
    """
    from CiscoThousandEyes import fetch_events

    client = mock_client()
    last_run = {
        "alerts": {"last_fetch": "2024-11-19T14:20:00Z"},
        "audit": {"last_fetch": "2024-11-28T08:59:17Z"},
    }
    mocker.patch.object(demisto, "getLastRun", return_value=last_run)
    mocker.patch.object(demisto, "debug")
    mocker.patch.object(client, "_http_request", side_effect=mock_http_request)
    next_run, events = fetch_events(
        client=client,
        max_fetch_alerts=2,
        max_fetch_audits=10,
    )

    assert len(events) == 12
    assert next_run.get("alerts").get("offset") == 2
    assert "nextTrigger" in next_run
    assert events[0].get('startDate') == "2024-12-22T07:29:00Z"


def test_test_module_command(mocker):
    """
    Given:
    - A client configured to interact with the Cisco ThousandEyes API.
    - Mocked HTTP requests to simulate API responses.

    When:
    - Running the `test_module` command to validate the connection to the API.

    Then:
    - Ensure the function returns 'ok' indicating a successful connection.
    - Verify that the mocked HTTP request is called as expected.
    """
    from CiscoThousandEyes import test_module

    client = mock_client()
    mocker.patch.object(client, "_http_request", side_effect=mock_http_request)
    assert test_module(client=client) == 'ok'


def test_get_events_command(mocker):
    """
    Given:
    - A client configured to fetch alerts and events.
    - Arguments specifying a high limit (1000), a start date, and a flag indicating not to push events.
    - A previous last run state containing the last fetched timestamps for alerts and events.

    When:
    - Running the `get_events_command` function to fetch both alerts and events.

    Then:
    - Ensure the correct number of events and alerts are fetched.
    - Verify that the human-readable output contains references to both "Test Events" and "Test Alerts".
    - Confirm that the function handles pagination correctly for events.
    """
    from CiscoThousandEyes import get_events_command

    client = mock_client()

    args = {
        "limit": "1000",
        "should_push_events": "false",
        "start_date": "2024-11-19T08:57:17Z",
    }
    call_count = 0

    def mock_http_request(method, full_url, params=None):
        nonlocal call_count

        if "alerts" in full_url:
            return util_load_json("test_data/alerts_list.json")
        elif "audit" in full_url:
            call_count += 1

            if call_count == 1:
                return util_load_json("test_data/events_list.json")
            else:
                return {
                    "auditEvents": [],
                    "startDate": "2024-11-28T08:59:17Z",
                    "endDate": "2024-12-30T08:56:46Z",
                    "_links": {
                        "self": {
                            "href": "https://example.com"
                        }
                    },
                }
        return {}

    last_run = {
        "alerts": {"last_fetch": "2024-11-18T14:20:00Z"},
        "audit": {"last_fetch": "2024-11-28T08:59:17Z"},
    }
    mocker.patch.object(demisto, "getLastRun", return_value=last_run)
    mocker.patch.object(demisto, "debug")
    mocker.patch.object(client, "_http_request", side_effect=mock_http_request)
    events, hr = get_events_command(client, args)

    assert len(events) == 22
    assert "Test Events" in hr.readable_output
    assert "Test Alerts" in hr.readable_output


def test_get_events_command_with_limit(mocker):
    """
    Given:
    - A client configured to fetch events.
    - Arguments specifying a limit of 3 events, a start date, and a flag indicating not to push events.
    - A previous last run state containing the last fetched timestamps for alerts and events.

    When:
    - Running the `get_events_command` function to fetch events.

    Then:
    - Ensure the correct number of events are fetched, considering the specified limit.
    - Verify the function handles the limit argument appropriately and returns the expected events.
    """
    from CiscoThousandEyes import get_events_command

    client = mock_client()

    args = {
        "limit": "3",
        "should_push_events": "false",
        "start_date": "2023-11-19T08:57:17Z",
    }

    last_run = {
        "alerts": {"last_fetch": "2024-11-19T14:20:00Z"},
        "audit": {"last_fetch": "2024-11-28T08:59:17Z"},
    }
    mocker.patch.object(demisto, "getLastRun", return_value=last_run)
    mocker.patch.object(demisto, "debug")
    mocker.patch.object(client, "_http_request", side_effect=mock_http_request)
    events, _ = get_events_command(client, args)

    assert len(events) == 6


def test_fetch_events_by_nextTrigger(mocker):
    """
    Given:
    - A client configured to fetch alerts and events with a specified next page URL and offsets.
    - A previous last run state containing the last fetched timestamps, next page URLs, and offsets for alerts and events.
    - Mock HTTP responses for alerts and events, with events returning an empty list on subsequent calls.

    When:
    - Fetching alerts and events using the `fetch_events` function.

    Then:
    - Ensure the correct number of events are returned.
    - Verify that the next run state resets the alerts offset to 0.
    - Confirm that the "nextTrigger" key is removed from the next run state.
    - Validate that the first event has the expected start date.
    """
    from CiscoThousandEyes import fetch_events

    client = mock_client()
    last_run = {
        "alerts": {
            "last_fetch": "2024-12-22T07:29:00Z",
            "next_page": "example.com/v7/alerts?startDate=2024-11-19T14:20:00Z&endDate=2024-12-30T11:24:09Z&max=500",
            "offset": 3,
        },
        "audit": {
            "last_fetch": "2024-12-22T07:40:10Z",
            "next_page": "example.com/v7/audit-user-events?startDate=2024-11-28T08:59:17Z&endDate=2024-12-30T11:24:11Z&max=500",
            "offset": 10,
        },
        "nextTrigger": "0",
    }
    call_count = 0

    def mock_http_request(method, full_url, params=None):
        nonlocal call_count

        if "alerts" in full_url:
            return util_load_json("test_data/alerts_list.json")
        elif "audit" in full_url:
            call_count += 1

            if call_count == 1:
                return util_load_json("test_data/events_list.json")
            else:
                return {
                    "auditEvents": [],
                    "startDate": "2024-11-28T08:59:17Z",
                    "endDate": "2024-12-30T08:56:46Z",
                    "_links": {
                        "self": {
                            "href": "https://example.com"
                        }
                    },
                }
        return {}
    mocker.patch.object(demisto, "getLastRun", return_value=last_run)
    mocker.patch.object(demisto, "debug")
    mocker.patch.object(client, "_http_request", side_effect=mock_http_request)
    next_run, events = fetch_events(
        client=client,
        max_fetch_alerts=2,
        max_fetch_audits=10,
    )

    assert len(events) == 9
    assert "offset" not in next_run.get("alerts")
    assert "nextTrigger" not in next_run
    assert events[0].get('startDate') == "2024-11-20T14:20:00Z"


def test_fetch_events_in_multiple_cycles(mocker):
    """
    Given:
    - A configured client to interact with the Cisco ThousandEyes API.
    - Mocked HTTP requests to simulate fetching events data in two separate fetches.
    - A last_run object with the last fetch dates for alerts and events.

    When:
    - Running the `fetch_events` function twice to retrieve all events in two fetch cycles.

    Then:
    - Ensure the total number of events fetched across the two fetch cycles is correct.
    - Verify that the offsets and last fetch times are updated correctly in the next_run object.
    - Confirm that no "nextTrigger" remains after the second fetch completes.
    """
    from CiscoThousandEyes import fetch_events

    client = mock_client()
    last_run = {
        "alerts": {"last_fetch": "2024-11-19T14:20:00Z"},
        "audit": {"last_fetch": "2024-11-28T08:59:17Z"},
    }
    call_count = 0

    def mock_http_request(method, full_url, params=None):
        nonlocal call_count

        if "alerts" in full_url:
            return util_load_json("test_data/alerts_list.json")
        elif "audit" in full_url:
            call_count += 1

            if call_count == 1:
                return util_load_json("test_data/events_list.json")
            else:
                return {
                    "auditEvents": [],
                    "startDate": "2024-11-28T08:59:17Z",
                    "endDate": "2024-12-30T08:56:46Z",
                    "_links": {
                        "self": {
                            "href": "https://example.com"
                        }
                    },
                }
        return {}
    mocker.patch.object(demisto, "getLastRun", return_value=last_run)
    mocker.patch.object(demisto, "debug")
    mocker.patch.object(client, "_http_request", side_effect=mock_http_request)
    next_run, first_fetch_events = fetch_events(
        client=client,
        max_fetch_alerts=3,
        max_fetch_audits=10,
    )

    assert len(first_fetch_events) == 13
    assert next_run.get("alerts").get("offset") == 3
    assert "nextTrigger" in next_run
    assert first_fetch_events[0].get('startDate') == "2024-12-22T07:29:00Z"

    call_count = 0
    mocker.patch.object(demisto, "getLastRun", return_value=next_run)
    next_run, second_fetch_events = fetch_events(
        client=client,
        max_fetch_alerts=3,
        max_fetch_audits=10,
    )
    full_events = first_fetch_events + second_fetch_events

    assert len(full_events) == 22
    assert "offset" not in next_run.get("alerts")
    assert "offset" not in next_run.get("audit")
    assert "nextTrigger" not in next_run
    assert next_run.get("audit").get("last_fetch") == "2024-12-22T07:40:10Z"
    assert next_run.get("alerts").get("last_fetch") == "2024-12-22T07:29:00Z"


@pytest.mark.parametrize(
    "events, start_date, date_key, expected_events",
    [
        pytest.param(
            [
                {"date": "2024-12-22T07:40:10Z", "event": "Event1"},
                {"date": "2024-12-21T07:40:10Z", "event": "Event2"},
                {"date": "2024-12-23T07:40:10Z", "event": "Event3"},
            ],
            "2024-12-22T00:00:00Z",
            "date",
            [
                {"date": "2024-12-22T07:40:10Z", "event": "Event1"},
                {"date": "2024-12-23T07:40:10Z", "event": "Event3"},
            ],
            id="normal-filtering",
        ),
        pytest.param(
            [],
            "2024-12-22T00:00:00Z",
            "date",
            [],
            id="empty-list",
        ),
        pytest.param(
            [
                {"date": "2024-12-22T00:00:00Z", "event": "Event1"},
                {"date": "2024-12-22T00:00:00Z", "event": "Event2"},
            ],
            "2024-12-22T00:00:00Z",
            "date",
            [],
            id="no-events-meet-criteria",
        ),
        pytest.param(
            [
                {"date": "2024-12-23T07:40:10Z", "event": "Event1"},
                {"date": "2024-12-24T07:40:10Z", "event": "Event2"},
            ],
            "2024-12-22T00:00:00Z",
            "date",
            [
                {"date": "2024-12-23T07:40:10Z", "event": "Event1"},
                {"date": "2024-12-24T07:40:10Z", "event": "Event2"},
            ],
            id="all-events-meet-criteria",
        ),
    ],
)
def test_deduplicate_events(events, start_date, date_key, expected_events):
    """
    Test deduplicate_events with various scenarios.
    """
    from CiscoThousandEyes import deduplicate_events

    deduplicate_events(events, start_date, date_key)
    assert events == expected_events
