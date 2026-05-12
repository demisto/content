from freezegun import freeze_time
import demistomock as demisto
from unittest.mock import Mock
import json


def load_test_events():
    with open("test_data/event_list.json") as file:
        return json.load(file)


def create_mock_client(test_events):
    client = Mock()

    def mock_search_events(limit, from_date, until_date, offset):
        return test_events[offset: offset + limit]

    client.search_events.side_effect = mock_search_events
    return client


def test_client_request(mocker):
    """
    Given:
        - The `query_params` dictionary includes:
            - `limit`: 50
            - `sort_by`: "created_at"
            - `after`: "2024-11-18T11:16:09.076711Z"
            - `before`: "2024-11-18T14:00:20.303699Z"
        - The `_http_request` method is patched to avoid actual HTTP requests.
        - The `demisto.debug` method is patched to capture debug log outputs.
    When:
        - The `client._request` method is called with the provided `query_params`.
    Then:
        - Ensure that the debug log contains the expected query string with `sort_by=created_at` and `after` parameters.
        - Validate that the expected parameters are found in the log call arguments.
    """
    from BloodHoundEnterprise import Client, Credentials

    query_params = {
        "limit": 50,
        "sort_by": "created_at",
        "after": "2024-11-18T11:16:09.076711",
        "before": "2024-11-18T14:00:20.303699",
    }
    client = Client(
        base_url="example.com",
        verify=False,
        proxy=False,
        credentials=Credentials(token_id="token_id", token_key="token_key"),
    )

    mocker.patch.object(client, "_http_request")
    log = mocker.patch.object(demisto, "debug")
    client._request("GET", "/api/v2/audit", query_params=query_params)
    found = any(
        "/api/v2/audit?limit=50&sort_by=created_at&after=2024-11-18T11%3A16%3A09.076711&before=2024-11-18T14%3A00%3A20.303699,"
        in call.args[0]
        for call in log.call_args_list
    )
    assert found, "'sort_by=created_at&after' was not found in any demisto.debug calls."


@freeze_time("2024-11-22T13:28:27.698038Z")
def test_fetch_events_first_time(mocker):
    """
    Given:
        - A mock client with a predefined set of test events loaded from a JSON file.
        - The current date and time are frozen at "2024-11-22T13:28:27.698038Z".
        - No previous fetch history from `demisto.getLastRun` (indicating the first time fetching events).
        - The parameter for `max_events_per_fetch` is set to "7".

    When:
        - The `fetch_events` function is called with empty 'getLastRun' like the first fetch time.

    Then:
        - Ensure that exactly 7 events are fetched.
        - Validate that the next run metadata (`next_run`) is correctly updated with:
            - `last_event_date` timestamp.
            - `last_event_id` of the last fetched event.
            - `fetch_id` set to 1.
            - `skip` indicating the number of events fetched.
        - Verify that the first event in the fetched list has the correct ID (2051).
    """
    from BloodHoundEnterprise import fetch_events

    test_events = load_test_events()
    client = create_mock_client(test_events)
    mocker.patch.object(demisto, "getLastRun", return_value={})
    mocker.patch.object(demisto, "debug")

    next_run, events = fetch_events(
        client=client,
        params={"max_events_per_fetch": "7"},
    )

    assert len(events) == 7
    assert next_run.get("last_event_date", "").startswith("2024-11-22T13:27:27.698038+")
    assert all(
        (
            next_run.get("last_event_id") == 2057,
            next_run.get("fetch_id") == 1,
            next_run.get("offset") == 7,
        )
    )
    assert events[0].get("id") == 2051


@freeze_time("2024-11-20T13:17:24.074375+02:00")
def test_fetch_events_second_time(mocker):
    """
    Given:
        - A mock client with a predefined set of test events loaded from a JSON file.
        - The current date and time are frozen at "2024-11-20T13:17:24.074375+02:00".
        - The previous fetch history is simulated using `demisto.getLastRun`, with the following values:
            - `last_event_date` set to "2024-11-24T12:43:57.27948Z".
            - `last_event_id` set to 2072.
            - `fetch_id` set to 1.

    When:
        - The `fetch_events` function is called to retrieve events with the mock client,
            with a parameter for `max_events_per_fetch` set to "2".

    Then:
        - Ensure that exactly 2 events are fetched.
        - Validate that the first event in the fetched list has the correct ID (2073).
        - Verify that the next run metadata (`next_run`) is correctly updated with:
            - `last_event_date` timestamp.
            - `last_event_id` of the last fetched event (2074).
            - `fetch_id` incremented to 2.
            - `skip` indicating the number of events fetched (2).
    """
    from BloodHoundEnterprise import fetch_events

    mocker.patch.object(
        demisto,
        "getLastRun",
        return_value={
            "last_event_date": "2024-11-24T12:43:57.27948Z",
            "last_event_id": 2072,
            "fetch_id": 1,
        },
    )
    mocker.patch.object(demisto, "debug")
    test_events = load_test_events()
    client = create_mock_client(test_events)
    next_run, events = fetch_events(
        client=client,
        params={"max_events_per_fetch": "2"},
    )

    assert len(events) == 2
    assert events[0].get("id") == 2073
    assert next_run.get("last_event_date", "").startswith("2024-11-24T12:43:57.27948")
    assert all(
        (
            next_run.get("last_event_id") == 2074,
            next_run.get("fetch_id") == 2,
            next_run.get("offset") == 2,
        )
    )


def test_get_events_command(mocker):
    """
    Given:
        - A mock client with a predefined set of test events loaded from a JSON file.
        - The `args` dictionary contains the following parameters:
            - `start`: "2024-11-23T18:39:35.546751Z"
            - `end`: "2024-11-23T18:39:58.113381Z"
            - `limit`: "3"

    When:
        - The `get_events_command` function is called with the mock client and the provided arguments.

    Then:
        - Ensure that exactly 3 events are returned.
        - Validate that the first event in the list has the correct ID (2051).
        - Ensure that the human-readable output (`hr.readable_output`) contains the string "2052".
    """
    from BloodHoundEnterprise import get_events_command

    args = {
        "start": "2024-11-23T18:39:35.546751Z",
        "end": "2024-11-23T18:39:58.113381Z",
        "limit": "3",
    }
    test_events = load_test_events()
    client = create_mock_client(test_events)

    events, hr = get_events_command(
        client=client,
        args=args,
    )

    assert len(events) == 3
    assert events[0].get("id") == 2051
    assert "2052" in hr.readable_output


def test_fetch_all_events_in_second_fetch():
    """
    Given:
        - A mock client with a predefined set of test events loaded from a JSON file.
        - The `max_events` is set to the total number of events available in the `test_events` list.
        - The `last_event_id` is set to 2051, indicating the starting point for the second fetch.

    When:
        - The `get_events_with_pagination` function is called to fetch events within the specified
        date range from "2024-11-22T00:00:00Z" to "2024-11-24T23:59:59Z", with the `last_event_id` set to 2051.

    Then:
        - Ensure that the number of events returned is equal to the total number of events in `test_events`
            excluding the first event (i.e., starting from event ID 2052).
        - Validate that the `next_skip` value is 0, indicating that there are no more events to fetch.
    """
    from BloodHoundEnterprise import get_events_with_pagination

    test_events = load_test_events()
    client = create_mock_client(test_events)

    max_events = len(test_events)
    last_event_id = 2051

    events, next_skip = get_events_with_pagination(
        client=client,
        start_date="2024-11-22T00:00:00Z",
        end_date="2024-11-24T23:59:59Z",
        max_events=max_events,
        last_event_id=last_event_id,
    )

    assert len(events) == len(test_events[1:])
    assert next_skip == 0


def test_fetch_limited_events():
    """
    Given:
        - A mock client with a predefined set of test events loaded from a JSON file.
        - The `max_events` parameter is set to 10, limiting the number of events to fetch.
        - The date range for fetching events is from "2024-11-22T00:00:00Z" to "2024-11-24T23:59:59Z".

    When:
        - The `get_events_with_pagination` function is called to fetch a limited number of events within the specified date range.

    Then:
        - Ensure that the number of events returned matches the `max_events` limit, which should be 10.
        - Validate that the `next_skip` value is equal to `max_events` (10), indicating the number of events fetched.
    """
    from BloodHoundEnterprise import get_events_with_pagination

    test_events = load_test_events()
    client = create_mock_client(test_events)

    max_events = 10
    events, next_skip = get_events_with_pagination(
        client=client,
        start_date="2024-11-22T00:00:00Z",
        end_date="2024-11-24T23:59:59Z",
        max_events=max_events,
    )

    assert len(events) == max_events
    assert next_skip == max_events


def test_pagination_with_initial_skip():
    """
    Given:
        - A mock client with a predefined set of test events loaded from a JSON file.
        - The `initial_skip` parameter is set to 5, meaning the first 5 events should be skipped.
        - The `max_events` parameter is set to 10, limiting the number of events to fetch.
        - The date range for fetching events is from "2024-11-22T00:00:00Z" to "2024-11-24T23:59:59Z".

    When:
        - The `get_events_with_pagination` function is called to fetch a limited number
        of events (10) starting after the initial skip of 5.

    Then:
        - Verify that the first event returned matches the event after the initial skip
        (i.e., `events[0]['id']` should equal the ID of the event at `initial_skip` index).
        - Ensure that the number of events returned matches the `max_events` limit, which should be 10.
        - Confirm that the `next_skip` value equals `initial_skip + max_events`, indicating the total number of events processed.
    """
    from BloodHoundEnterprise import get_events_with_pagination

    test_events = load_test_events()
    client = create_mock_client(test_events)

    initial_skip = 5
    max_events = 10
    events, next_skip = get_events_with_pagination(
        client=client,
        start_date="2024-11-22T00:00:00Z",
        end_date="2024-11-24T23:59:59Z",
        max_events=max_events,
        offset=initial_skip,
    )

    assert events[0]["id"] == test_events[initial_skip]["id"]
    assert len(events) == max_events
    assert next_skip == initial_skip + max_events


def test_fetch_with_last_event_id():
    """
    Given:
        - A mock client with a predefined set of test events loaded from a JSON file.
        - The `last_event_id` parameter is set to 2060, meaning events with an ID less than or equal to 2060 should be excluded.
        - The `max_events` parameter is set to 5, limiting the number of events to fetch.
        - The date range for fetching events is from "2024-11-22T00:00:00Z" to "2024-11-24T23:59:59Z".

    When:
        - The `get_events_with_pagination` function is called with the
        specified `last_event_id` to fetch events that have a higher ID than 2060.

    Then:
        - Verify that all returned events have an `id` greater than 2060.
        - Ensure that the number of events fetched matches the `max_events` limit, which is 5.
        - Confirm that the first event in the returned list has an `id` greater than `last_event_id` (2060).
    """
    from BloodHoundEnterprise import get_events_with_pagination

    test_events = load_test_events()
    client = create_mock_client(test_events)

    last_event_id = 2060
    max_events = 5
    events, next_skip = get_events_with_pagination(
        client=client,
        start_date="2024-11-22T00:00:00Z",
        end_date="2024-11-24T23:59:59Z",
        max_events=max_events,
        last_event_id=last_event_id,
    )

    assert all(event["id"] > last_event_id for event in events)
    assert len(events) == max_events
    assert events[0]["id"] > last_event_id
