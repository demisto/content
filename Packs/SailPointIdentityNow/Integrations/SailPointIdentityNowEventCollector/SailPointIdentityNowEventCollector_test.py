import demistomock as demisto
from SailPointIdentityNowEventCollector import (
    Client,
    add_time_and_status_to_events,
    dedup_events,
    fetch_events,
)
import pytest

# Test data constants
EVENTS_SEQUENTIAL = [
    {"id": "1", "created": "2022-01-01T00:01:00Z"},
    {"id": "2", "created": "2022-01-01T00:02:00Z"},
    {"id": "3", "created": "2022-01-01T00:03:00Z"},
    {"id": "4", "created": "2022-01-01T00:04:00Z"},
]

SINGLE_EVENT = {"id": "2", "created": "2022-01-01T00:57:00Z"}

EVENTS_WITH_DIFFERENT_DATE = [
    {"created": "2022-01-01T00:00:00Z", "id": "1"},
    {"created": "2022-01-01T00:00:00Z", "id": "2"},
    {"created": "2022-01-02T00:00:00Z", "id": "3"},
    {"created": "2022-01-02T00:00:00Z", "id": "4"},
]

EVENTS_WITH_THE_SAME_DATE = [
    {"created": "2022-01-01T00:00:00Z", "id": "1"},
    {"created": "2022-01-01T00:00:00Z", "id": "2"},
    {"created": "2022-01-01T00:00:00Z", "id": "3"},
    {"created": "2022-01-01T00:00:00Z", "id": "4"},
]


@pytest.mark.parametrize("expiration_time, expected", [(9999999999, "valid_token"), (0, "new_token")])
def test_get_token(mocker, expiration_time, expected):
    """
    Test token management with different expiration scenarios:

    Case 1: Token not expired (returns existing valid token)
    Case 2: Token expired (generates and returns new token)

    Given:
        - A SailPointIdentityNow client
        - A context with a token and expiration time
    When:
        - Calling get_token
    Then:
        - Ensure existing token is used if not expired, or new token is generated if expired
    """
    mocker.patch.object(Client, "_http_request").return_value = {"access_token": "dummy token", "expires_in": 1}
    client = Client(base_url="https://example.com", client_id="test_id", client_secret="test_secret", verify=False, proxy=False)
    mocker.patch(
        "SailPointIdentityNowEventCollector.get_integration_context",
        return_value={"token": "valid_token", "expires": expiration_time},
    )
    mocker.patch.object(Client, "generate_token", return_value="new_token")
    token = client.get_token()
    assert token == expected


# =============================================================================
# FETCH EVENTS TESTS
# =============================================================================


@pytest.mark.parametrize(
    "scenario,api_responses,max_events_per_fetch,look_back,last_run,expected_events_count,expected_prev_date,expected_cache_contains",
    [
        (
            "sequential_calls_with_dedup",
            [EVENTS_SEQUENTIAL[:3], EVENTS_SEQUENTIAL[2:4], []],
            5,
            0,
            {"prev_date": "2022-01-01T00:00:00Z"},
            4,
            "2022-01-01T00:04:00Z",
            ["4"],
        ),
        (
            "single_batch",
            [EVENTS_SEQUENTIAL[:2], []],
            5,
            0,
            {"prev_date": "2022-01-01T00:00:00Z"},
            2,
            "2022-01-01T00:02:00Z",
            ["2"],
        ),
        (
            "exact_limit_multiple_batches",
            [EVENTS_SEQUENTIAL[:3], EVENTS_SEQUENTIAL[3:4], []],
            4,
            0,
            {"prev_date": "2022-01-01T00:00:00Z"},
            4,
            "2022-01-01T00:04:00Z",
            ["4"],
        ),
        (
            "all_duplicates",
            [EVENTS_SEQUENTIAL[:3], []],
            5,
            0,
            {
                "prev_date": "2022-01-01T00:01:00Z",
                "last_fetched_id_timestamps": {
                    "1": "2022-01-01T00:01:00Z",
                    "2": "2022-01-01T00:02:00Z",
                    "3": "2022-01-01T00:03:00Z",
                },
            },
            0,
            "2022-01-01T00:03:00Z",
            ["1", "2", "3"],
        ),
        (
            "with_lookback",
            [[SINGLE_EVENT], []],
            5,
            5,
            {"prev_date": "2022-01-01T01:00:00Z", "last_fetched_id_timestamps": {"1": "2022-01-01T01:00:00Z"}},
            1,
            "2022-01-01T01:00:00Z",
            ["2"],
        ),
        (
            "no_events_available",
            [[]],
            5,
            0,
            {"prev_date": "2022-01-01T00:00:00Z", "last_fetched_id_timestamps": {"0": "2022-01-01T00:00:00Z"}},
            0,
            "2022-01-01T00:00:00Z",
            ["0"],
        ),
        (
            "partial_final_batch",
            [EVENTS_SEQUENTIAL[:3], EVENTS_SEQUENTIAL[3:4], []],
            10,
            0,
            {"prev_date": "2022-01-01T00:00:00Z"},
            4,
            "2022-01-01T00:04:00Z",
            ["4"],
        ),
    ],
)
def test_fetch_events__end_to_end(
    mocker,
    scenario,
    api_responses,
    max_events_per_fetch,
    look_back,
    last_run,
    expected_events_count,
    expected_prev_date,
    expected_cache_contains,
):
    """
    Test end-to-end fetch_events functionality with various scenarios:

    Case 1 (sequential_calls_with_dedup): Sequential API calls with deduplication across batches
    Case 2 (single_batch): Single batch where all events fit within limit
    Case 3 (exact_limit_multiple_batches): Multiple batches that exactly hit the fetch limit
    Case 4 (all_duplicates): All events are duplicates and should be filtered out
    Case 5 (with_lookback): Lookback functionality to retrieve older events
    Case 6 (no_events_available): Empty API response when no events are available
    Case 7 (partial_final_batch): API returns fewer events than the limit in final batch

    Given:
        - A SailPointIdentityNow client with mocked search_events responses
        - MAX_EVENTS_PER_API_CALL limited to 3 events per call (to test batching)
        - Various scenarios with different max_events_per_fetch limits, lookback settings, and last_run states
    When:
        - Calling fetch_events with different configurations
    Then:
        - Ensure correct number of events are returned after deduplication
        - Ensure next_run structure contains proper prev_date and last_fetched_id_timestamps cache
        - Ensure scenario-specific behaviors work correctly (lookback dates, duplicate handling, etc.)
    """
    # Mock the API limit to 3 events per call to test sequential batch behavior
    mocker.patch("SailPointIdentityNowEventCollector.MAX_EVENTS_PER_API_CALL", 3)
    mocker.patch.object(demisto, "debug")

    client = mocker.patch("SailPointIdentityNowEventCollector.Client")
    client.search_events.side_effect = api_responses

    next_run, events = fetch_events(client, max_events_per_fetch, look_back, last_run)

    # Verify event count
    assert (
        len(events) == expected_events_count
    ), f"Scenario '{scenario}': Expected {expected_events_count} events, got {len(events)}"

    # Verify next_run structure
    assert next_run.get("prev_date") == expected_prev_date, f"Scenario '{scenario}': Wrong prev_date"
    assert next_run.get("last_fetched_id_timestamps") is not None, f"Scenario '{scenario}': Missing cache structure"

    # Verify cache contains expected items
    cache = next_run.get("last_fetched_id_timestamps", {})
    for expected_id in expected_cache_contains:
        assert expected_id in cache, f"Scenario '{scenario}': Cache missing expected ID '{expected_id}'. Cache: {cache}"

    # Verify events have proper structure if any were returned
    if expected_events_count > 0:
        for event in events:
            assert "id" in event, f"Scenario '{scenario}': Event missing 'id' field"
            assert "created" in event, f"Scenario '{scenario}': Event missing 'created' field"

    # Scenario-specific additional validations
    if scenario == "all_duplicates":
        # Should preserve original cache when all events are duplicates
        assert len(cache) >= 3, f"Scenario '{scenario}': Should preserve original cache entries"

    elif scenario == "with_lookback":
        # Should have made API call with lookback date
        call_args = client.search_events.call_args_list[0]
        from_date_used = call_args.kwargs.get("from_date") or call_args.args[0] if call_args.args else None
        assert from_date_used != last_run["prev_date"], f"Scenario '{scenario}': Should use lookback date, not original prev_date"


@pytest.mark.parametrize(
    "api_responses,limit,expected_events_count,expected_most_recent_timestamp",
    [
        # Single batch with all new events
        (
            [EVENTS_SEQUENTIAL[:2], []],
            5,
            2,
            "2022-01-01T00:02:00Z",
        ),
        # Multiple full batches - test true batching behavior
        (
            [EVENTS_SEQUENTIAL[:2], EVENTS_SEQUENTIAL[2:4], []],
            5,
            4,
            "2022-01-01T00:04:00Z",
        ),
        # Partial final batch
        (
            [EVENTS_SEQUENTIAL[:2], EVENTS_SEQUENTIAL[2:3], []],
            5,
            3,
            "2022-01-01T00:03:00Z",
        ),
        # Single batch hitting exact limit
        (
            [EVENTS_SEQUENTIAL[:3], []],
            3,
            3,
            "2022-01-01T00:03:00Z",
        ),
        # Empty result from API
        (
            [[]],
            5,
            0,
            None,
        ),
    ],
)
def test_fetch_events_batch(mocker, api_responses, limit, expected_events_count, expected_most_recent_timestamp):
    """
    Test _fetch_events_batch with different API response patterns:

    Case 1: Single batch with all new events (2 events fit within limit)
    Case 2: Multiple full batches (2+2 events across multiple API calls)
    Case 3: Partial final batch (2+1 events, stops after partial response)
    Case 4: Single batch hitting exact limit (3 events with limit=3)
    Case 5: Empty result from API (no events returned)

    Given:
        - A SailPoint client that returns different API response patterns
        - Various limits and API response sequences
    When:
        - Calling _fetch_events_batch with different configurations
    Then:
        - Ensure correct number of events are fetched and deduplication cache is built properly
    """
    from SailPointIdentityNowEventCollector import _fetch_events_batch

    # Mock the API limit to 2 events per call to test true batching behavior
    mocker.patch("SailPointIdentityNowEventCollector.MAX_EVENTS_PER_API_CALL", 2)

    client = mocker.Mock()
    client.search_events.side_effect = api_responses

    mocker.patch("SailPointIdentityNowEventCollector.dedup_events", side_effect=lambda events, *args, **kwargs: events)

    all_events, dedup_cache = _fetch_events_batch(client, limit, "2022-01-01T00:00:00")

    assert len(all_events) == expected_events_count
    assert len(dedup_cache) == expected_events_count

    # Verify most recent timestamp if events were returned
    if expected_events_count > 0 and expected_most_recent_timestamp:
        timestamps = list(dedup_cache.values())
        assert max(timestamps) == expected_most_recent_timestamp


@pytest.mark.parametrize(
    "all_events,dedup_cache,look_back,expected_prev_date,expected_cache_size",
    [
        # Events with lookback=0 (only keep most recent timestamp)
        (
            EVENTS_SEQUENTIAL[:2],
            {"1": "2022-01-01T00:01:00", "2": "2022-01-01T00:02:00"},
            0,
            "2022-01-01T00:02:00",
            1,
        ),
        # Events with lookback>0 (keep all within window)
        (
            [EVENTS_SEQUENTIAL[0], {"id": "2", "created": "2022-01-01T00:05:00"}],
            {"1": "2022-01-01T00:01:00", "2": "2022-01-01T00:05:00"},
            10,
            "2022-01-01T00:05:00",
            2,
        ),
        # No events (use fallback date)
        (
            [],
            {},
            0,
            "2022-01-01T00:00:00Z",
            0,
        ),
        # Events with matching cache
        (
            [EVENTS_SEQUENTIAL[2]],
            {"3": "2022-01-01T00:03:00Z"},
            0,
            "2022-01-01T00:03:00Z",
            1,
        ),
    ],
)
def test_build_next_run(all_events, dedup_cache, look_back, expected_prev_date, expected_cache_size):
    """
    Test _build_next_run function with various event and cache combinations:

    Case 1: Events with lookback=0 (only keep most recent timestamp)
    Case 2: Events with lookback>0 (keep all within window)
    Case 3: No events (use fallback date)
    Case 4: Events with matching cache

    Given:
        - Various combinations of events, dedup cache, and lookback settings
    When:
        - Calling the _build_next_run function
    Then:
        - Ensure it returns correct next_run structure with proper prev_date and cache
    """
    from SailPointIdentityNowEventCollector import _build_next_run

    fallback_date = "2022-01-01T00:00:00Z"  # Default fallback, should only be used when no events
    next_run = _build_next_run(all_events, dedup_cache, fallback_date, look_back)

    assert next_run["prev_date"] == expected_prev_date
    assert len(next_run["last_fetched_id_timestamps"]) == expected_cache_size


@pytest.mark.parametrize(
    "id_timestamps,most_recent_timestamp,look_back,has_events,expected_result",
    [
        # lookback = 0, has events - keep only most recent timestamp
        (
            {"1": "2022-01-01T00:01:00", "2": "2022-01-01T00:02:00", "3": "2022-01-01T00:02:00"},
            "2022-01-01T00:02:00",
            0,
            True,
            {"2": "2022-01-01T00:02:00", "3": "2022-01-01T00:02:00"},
        ),
        # lookback = 0, no events - return all
        (
            {"1": "2022-01-01T00:01:00", "2": "2022-01-01T00:02:00"},
            "2022-01-01T00:02:00",
            0,
            False,
            {"1": "2022-01-01T00:01:00", "2": "2022-01-01T00:02:00"},
        ),
        # lookback > 0 - use lookback filtering
        (
            {"1": "2022-01-01T00:01:00", "2": "2022-01-01T00:02:00"},
            "2022-01-01T00:02:00",
            5,
            True,
            {"1": "2022-01-01T00:01:00", "2": "2022-01-01T00:02:00"},  # Mock will return all
        ),
        # Empty cache
        ({}, "2022-01-01T00:02:00", 0, True, {}),
    ],
)
def test_filter_dedup_cache(mocker, id_timestamps, most_recent_timestamp, look_back, has_events, expected_result):
    """
    Test filtering deduplication cache based on lookback settings:

    Case 1: lookback=0 with events (keep only most recent)
    Case 2: lookback=0 without events (return all)
    Case 3: lookback>0 (use lookback filtering)
    Case 4: Empty cache (return empty)

    Given:
        - Various dedup cache states, timestamps, and lookback configurations
    When:
        - calling _filter_dedup_cache
    Then:
        - Ensure cache is filtered correctly based on lookback settings
    """
    from SailPointIdentityNowEventCollector import _filter_dedup_cache

    mock_filter = mocker.patch("SailPointIdentityNowEventCollector.filter_id_timestamps_by_lookback_window")
    mock_filter.return_value = expected_result

    result = _filter_dedup_cache(id_timestamps, most_recent_timestamp, look_back, has_events)

    assert result == expected_result


@pytest.mark.parametrize(
    "id_timestamps,current_date,look_back,expected_result",
    [
        # Events older than current_date, filtered out when lookback=0
        (
            {event["id"]: event["created"] for event in EVENTS_SEQUENTIAL[:2]},
            "2022-01-01T00:10:00Z",
            0,
            {},
        ),
        # Events within lookback window
        (
            {event["id"]: event["created"] for event in EVENTS_SEQUENTIAL[:2]},
            "2022-01-01T00:03:00Z",
            5,
            {event["id"]: event["created"] for event in EVENTS_SEQUENTIAL[:2]},
        ),
        # Empty cache
        (
            {},
            "2022-01-01T00:10:00Z",
            5,
            {},
        ),
    ],
)
def test_filter_id_timestamps_by_lookback_window(id_timestamps, current_date, look_back, expected_result):
    """
    Test filtering ID timestamps based on lookback window:

    Case 1: Events older than current_date, filtered out when lookback=0
    Case 2: Events within lookback window (keeps events from 23:58 to 00:03)
    Case 3: Empty cache (returns empty result)

    Given:
        - ID timestamp mappings and lookback configuration
    When:
        - Calling the filter_id_timestamps_by_lookback_window function
    Then:
        - Ensure it correctly filters timestamps based on lookback window
    """
    from SailPointIdentityNowEventCollector import filter_id_timestamps_by_lookback_window

    result = filter_id_timestamps_by_lookback_window(id_timestamps, current_date, look_back)

    # Assert exact expected result
    assert result == expected_result


def test_add_time_and_status_to_events(mocker):
    """
    Test adding _ENTRY_STATUS and _time fields to events based on created/modified timestamps:

    Case 1: Modified > created (status = "modified", time = modified)
    Case 2: Modified < created (status = "new", time = created)
    Case 3: No modified field (status = "new", time = created)

    Given:
        - A list of events with different created and modified timestamp combinations
    When:
        - Calling add_time_and_status_to_events
    Then:
        - Ensure the _ENTRY_STATUS field is added correctly based on the created and modified fields
        - Ensure the _time field is added with the appropriate timestamp
    """
    mocker.patch.object(demisto, "debug")

    events = [
        {"created": "2022-01-01T00:00:00", "modified": "2022-01-01T00:01:00"},
        {"created": "2022-01-01T00:02:00", "modified": "2022-01-01T00:01:00"},
        {"created": "2022-01-01T00:03:00"},
    ]

    add_time_and_status_to_events(events)

    assert events[0] == {
        "created": "2022-01-01T00:00:00",
        "modified": "2022-01-01T00:01:00",
        "_ENTRY_STATUS": "modified",
        "_time": "2022-01-01T00:01:00Z",
    }
    assert events[1] == {
        "created": "2022-01-01T00:02:00",
        "modified": "2022-01-01T00:01:00",
        "_ENTRY_STATUS": "new",
        "_time": "2022-01-01T00:02:00Z",
    }
    assert events[2] == {"created": "2022-01-01T00:03:00", "_time": "2022-01-01T00:03:00Z", "_ENTRY_STATUS": "new"}


@pytest.mark.parametrize(
    "prev_id, expected",
    [
        (
            "123",
            '{"indices": ["events"], "queryType": "SAILPOINT", "queryVersion": "5.2", "sort": ["+id"], "query": {"query": "type:* "}, "searchAfter": ["123"]}',  # noqa: E501
        ),
        (
            None,
            '{"indices": ["events"], "queryType": "SAILPOINT", "queryVersion": "5.2", "sort": ["+created"], "query": {"query": "type:* AND created: [2022-01-01T00:00:00 TO now]"}, "timeZone": "GMT"}',  # noqa: E501
        ),
    ],
)
def test_search_events(mocker, prev_id, expected):
    """
    Test search_events API request formatting with different parameters:

    Case 1: With prev_id (uses searchAfter with +id sorting)
    Case 2: Without prev_id (uses time-based query with +created sorting)

    Given:
        - A SailPointIdentityNow client
        - Different prev_id values (with ID or None)
    When:
        - Calling search_events with different configurations
    Then:
        - Ensure the correct API request format is sent based on prev_id presence
    """
    mocker_request = mocker.patch.object(Client, "_http_request")
    mocker.patch.object(Client, "get_token").return_value = {}
    client = Client(
        base_url="https://example.com",
        client_id="test_id",
        client_secret="test_secret",
        verify=False,
        proxy=False,
        token="dummy_token",
    )
    client.search_events(from_date="2022-01-01T00:00:00", limit=1, prev_id=prev_id)
    assert mocker_request.call_args.kwargs["data"] == expected


@pytest.mark.parametrize(
    "events, last_fetched_ids, expected, debug_msgs",
    [
        (
            EVENTS_WITH_DIFFERENT_DATE,
            ["1", "2"],
            [{"created": "2022-01-02T00:00:00Z", "id": "3"}, {"created": "2022-01-02T00:00:00Z", "id": "4"}],
            [
                "Starting deduping. Events before: 4, cached ids: 2",
                "Filtered out 2 duplicate event IDs: ['1', '2']",
                "Kept 2 new event IDs: ['3', '4']",
            ],
        ),
        (EVENTS_WITH_THE_SAME_DATE, ["1", "2", "3", "4"], [], []),
        (EVENTS_WITH_THE_SAME_DATE, ["6", "5"], EVENTS_WITH_THE_SAME_DATE, []),
    ],
)
def test_dedup_events(mocker, events, last_fetched_ids, expected, debug_msgs):
    """
    Test deduplication of events based on last fetched IDs:

    Case 1: Some events are duplicates (filters out events 1,2, keeps 3,4)
    Case 2: All events are duplicates (returns empty list)
    Case 3: No events are duplicates (returns all events)

    Given:
        - A list of events with duplicate and unique entries
        - A list of last fetched IDs
    When:
        - Calling dedup_events
    Then:
        - Ensure duplicate events are removed based on last fetched IDs
        - Ensure appropriate debug messages are logged
    """
    debug_msg = mocker.patch.object(demisto, "debug")
    deduped_events = dedup_events(events, last_fetched_ids=last_fetched_ids, prev_date=None)

    assert deduped_events == expected
    for i, msg in enumerate(debug_msgs):
        assert msg in debug_msg.call_args_list[i][0][0]
