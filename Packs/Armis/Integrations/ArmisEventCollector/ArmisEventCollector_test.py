import re
import threading
from collections.abc import Iterator
from concurrent.futures import ThreadPoolExecutor
from unittest.mock import MagicMock, patch

import pytest
from ArmisEventCollector import (
    ALERT_ENRICHMENT_CHUNK_SIZE,
    BULK_ENRICHMENT_BATCH_SIZE,
    EVENT_TYPE,
    EVENT_TYPES,
    MAX_PAGINATION_DURATION_SECONDS,
    MIN_PAGINATION_DURATION_SECONDS,
    Any,
    Client,
    DemistoException,
    IntegrationContextManager,
    _attach_enrichment,
    _bulk_fetch_entities_by_id,
    _collect_unique_enrichment_ids,
    _enrich_and_ship_in_chunks,
    _next_fetch_window,
    _stream_page_to_xsiam,
    _wait_for_enrichment,
    apply_activities_aql_filter,
    arg_to_datetime,
    bulk_enrich_alerts,
    compute_pagination_budget,
    compute_resume_state,
    datetime,
    fetch_by_event_type,
    fetch_events,
    handle_fetched_events,
    timedelta,
    timezone,
)
from freezegun import freeze_time


@pytest.fixture
def dummy_client(mocker):
    """
    A dummy client fixture for testing.
    """
    mocker.patch.object(Client, "_is_token_still_fresh", return_value=True)
    # context_manager is required by Client.__init__ (no fallback path remains in production).
    # Tests that exercise context-aware behaviour build their own client with a real
    # IntegrationContextManager; this fixture wires a minimal one to satisfy the signature.
    return Client(
        base_url="test_base_url",
        api_key="test_api_key",
        access_token="test_access_token",
        context_manager=IntegrationContextManager(),
        verify=False,
        proxy=False,
    )


class TestClientFunctions:
    @freeze_time("2023-01-01T01:00:00")
    def test_initial_fetch_by_aql_query(self, mocker, dummy_client):
        """
        Test fetch_by_aql_query function behavior on initial fetch.

        Given:
            - Valid HTTP request parameters.
            - First fetch of the instance is running.
            - from argument is None.

        When:
            - Fetching events.
        Then:
            - Make sure the request is sent with right parameters.
            - Make sure the 'from' aql parameter request is sent with the "current" time 2023-01-01T01:00:00.
            - Make sure the pagination logic performs as expected.
        """
        first_response = {
            "data": {"next": 1, "results": [{"unique_id": "1", "time": "2023-01-01T01:00:10.123456+00:00"}], "total": "Many"}
        }

        second_response = {"data": {"next": 2, "results": [{"unique_id": "2", "time": "2023-01-01T01:00:20.123456+00:00"}]}}

        expected_result = [
            {"unique_id": "1", "time": "2023-01-01T01:00:10.123456+00:00"},
            {"unique_id": "2", "time": "2023-01-01T01:00:20.123456+00:00"},
        ]

        expected_args = {
            "url_suffix": "/search/",
            "method": "GET",
            "params": {
                "aql": "example_query after:2023-01-01T00:59:00",
                "includeTotal": "false",
                "length": 1,
                "orderBy": "time",
                "from": 1,
            },
            "headers": {"Authorization": "test_access_token", "Accept": "application/json"},
            "timeout": 180,
            "retries": 1,
            "status_list_to_retry": {500, 502},
        }

        mocked_http_request = mocker.patch.object(Client, "_http_request", side_effect=[first_response, second_response])
        assert dummy_client.fetch_by_aql_query("example_query", 2, (datetime.now() - timedelta(minutes=1))) == (
            expected_result,
            2,
        )

        mocked_http_request.assert_called_with(**expected_args)

    @freeze_time("2022-12-31T01:00:00")
    def test_continues_fetch_by_aql_query(self, mocker, dummy_client):
        """
        Test fetch_by_aql_query function behavior on continues fetch.

        Given:
            - Valid HTTP request parameters.
            - An ongoing fetch of the instance is running (not initial fetch).
            - from argument is set to a datetime value from last fetch.

        When:
            - Fetching events.
        Then:
            - Make sure the request is sent with right parameters.
            - Make sure the 'from' aql parameter request is sent with the given from argument.
            - Make sure the pagination logic performs as expected.
        """
        first_response = {
            "data": {"next": 1, "results": [{"unique_id": "1", "time": "2023-01-01T01:00:10.123456+00:00"}], "total": "Many"}
        }

        second_response = {"data": {"next": None, "results": [{"unique_id": "2", "time": "2023-01-01T01:00:20.123456+00:00"}]}}

        expected_result = [
            {"unique_id": "1", "time": "2023-01-01T01:00:10.123456+00:00"},
            {"unique_id": "2", "time": "2023-01-01T01:00:20.123456+00:00"},
        ]

        expected_args = {
            "url_suffix": "/search/",
            "method": "GET",
            "params": {
                "aql": "example_query after:2023-01-01T01:00:01",
                "includeTotal": "false",
                "length": 2,
                "orderBy": "time",
                "from": 1,
            },
            "headers": {"Authorization": "test_access_token", "Accept": "application/json"},
            "timeout": 180,
            "retries": 1,
            "status_list_to_retry": {500, 502},
        }

        from_arg = arg_to_datetime("2023-01-01T01:00:01")
        mocked_http_request = mocker.patch.object(Client, "_http_request", side_effect=[first_response, second_response])
        assert dummy_client.fetch_by_aql_query("example_query", 3, from_arg) == (expected_result, 0)

        mocked_http_request.assert_called_with(**expected_args)

    def test_fetch_by_aql_query_pagination_timeout(self, mocker, dummy_client):
        """
        Test fetch_by_aql_query function behavior when pagination duration exceeds the limit.

        Given:
            - A fetch operation with multiple pages of results.
            - The time taken to fetch pages exceeds MAX_PAGINATION_DURATION_SECONDS.
        When:
            - Fetching events using fetch_by_aql_query.
        Then:
            - The fetch operation should break early.
            - It should return the results fetched so far.
            - It should return the 'next' pointer for the subsequent fetch.
        """
        with freeze_time("2023-01-01T01:00:00") as frozen_time:
            first_response = {
                "data": {"next": 1, "results": [{"unique_id": "1", "time": "2023-01-01T01:00:10.123456+00:00"}], "total": "Many"}
            }

            second_response = {
                "data": {"next": 2, "results": [{"unique_id": "2", "time": "2023-01-01T01:00:20.123456+00:00"}], "total": "Many"}
            }

            third_response = {
                "data": {"next": 3, "results": [{"unique_id": "3", "time": "2023-01-01T01:00:30.123456+00:00"}], "total": "Many"}
            }

            call_count = 0
            responses = [first_response, second_response, third_response]

            def advance_time_and_return_response(*args, **kwargs):
                nonlocal call_count
                response = responses[call_count]
                call_count += 1
                frozen_time.tick(delta=timedelta(seconds=200))
                return response

            mocked_http_request = mocker.patch.object(Client, "_http_request", side_effect=advance_time_and_return_response)

            results, next_page = dummy_client.fetch_by_aql_query(
                aql_query="example_query", max_fetch=10, after=(datetime.now() - timedelta(minutes=1))
            )

            assert mocked_http_request.call_count == 2
            assert len(results) == 2
            assert next_page == 2


class TestHelperFunction:
    date_1 = "2023-01-01T01:00:00"
    date_2 = "2023-01-01T02:00:00"
    date_3 = "2023-01-01T00:00:00"
    date_4 = "2023-01-01T00:00:01"
    datetime_1 = arg_to_datetime(date_1)
    datetime_2 = arg_to_datetime(date_2)
    datetime_3 = arg_to_datetime(date_3)
    datetime_4 = arg_to_datetime(date_4)

    # test_calculate_fetch_start_time parametrize arguments
    case_last_run_exist_after_higher_than_before = (date_1, datetime_2, (datetime(2023, 1, 1, 0, 59), datetime(2023, 1, 1, 1, 0)))
    case_last_run_exist_after_lower_than_before = (date_3, datetime_4, (datetime_3, datetime(2023, 1, 1, 1, 0)))
    case_from_date_parameter_after_higher_than_before = (
        None,
        datetime_1,
        (datetime(2023, 1, 1, 0, 59), datetime(2023, 1, 1, 1, 0)),
    )  # type: ignore
    case_from_date_parameter_after_lower_than_before = (
        None,
        datetime_3,
        (datetime(2023, 1, 1, 0, 0), datetime(2023, 1, 1, 1, 0)),
    )  # type: ignore
    case_first_fetch_no_from_date_parameter = (None, None, (datetime(2023, 1, 1, 0, 59), datetime(2023, 1, 1, 1, 0)))

    @pytest.mark.parametrize(
        "last_fetch_time, fetch_start_time_param, expected_result",
        [
            case_last_run_exist_after_higher_than_before,
            case_last_run_exist_after_lower_than_before,
            case_from_date_parameter_after_higher_than_before,
            case_from_date_parameter_after_lower_than_before,
            case_first_fetch_no_from_date_parameter,
        ],
    )
    @freeze_time("2023-01-01 01:00:00")
    def test_calculate_fetch_start_time(self, last_fetch_time, fetch_start_time_param, expected_result):
        """
        Given:
            - Case 1: last_fetch_time exist in last_run, thus being prioritized (fetch-events / armis-get-events commands)
                      but time is larger/equal than now time.
            - Case 2: last_fetch_time exist in last_run, thus being prioritized (fetch-events / armis-get-events commands)
                      but time is less than now time.
            - Case 3: last_run is empty & from_date parameter exist (armis-get-events command with from_date argument)
                      but time is larger/equal than now time.
            - Case 4: last_run is empty & from_date parameter exist (armis-get-events command with from_date argument)
                      but time is less than now time.
            - Case 5: first fetch in the instance (no last_run),
                      this will set the current date time (fetch-events / armis-get-events commands).
        When:
            - Calculating fetch start time and end time from current fetch cycle.
        Then:
            - Case 1: Use the before time - 1 minute delta.
            - Case 2: Prefer last_fetch_time from last run and convert it to a valid datetime object.
            - Case 3: Use the before time - 1 minute delta.
            - Case 4: Use provided fetch_start_time_param (usually current time) datetime object.
            - Case 5: Should return the now time (freezed as 2023-01-01) + 1 minute.
        """
        from ArmisEventCollector import calculate_fetch_start_time

        assert calculate_fetch_start_time(last_fetch_time, fetch_start_time_param, fetch_delay=0) == expected_result

    @pytest.mark.parametrize("x, y, expected_result", [(datetime_1, datetime_1, True), (datetime_1, datetime_2, False)])
    def test_are_two_event_time_equal(self, x, y, expected_result):
        """
        Given:
            - Case 1: First and last datetime objected from the API response are equal up to seconds attribute.
            - Case 2: First and last datetime objected from the API response are not equal.
        When:
            - Verifying if all events in the API response have the same time up to seconds.
        Then:
            - Case 1: Return True.
            - Case 2: Return False.
        """
        from ArmisEventCollector import are_two_datetime_equal_by_second

        assert are_two_datetime_equal_by_second(x, y) == expected_result

    def test_resume_advances_and_resets_offset_when_response_spans_multiple_seconds(self):
        """
        Given: a response spanning two or more distinct seconds, resumed from offset 30000.
        When:  computing the next-cycle resume state.
        Then:  'after' advances to the latest event's second and the offset resets to 0.
        """
        from ArmisEventCollector import compute_resume_state

        response = [
            {"id": "a", "time": "2026-10-06T08:33:16.100000+00:00"},
            {"id": "b", "time": "2026-10-06T08:33:16.900000+00:00"},
            {"id": "c", "time": "2026-10-06T08:33:17.050000+00:00"},
        ]
        after, offset = compute_resume_state(response, "2026-10-06T08:33:16", 30000, "time")
        assert after == "2026-10-06T08:33:17"
        assert offset == 0

    def test_resume_steps_within_single_second_page(self):
        """
        Given: a full page whose events all share one second, resumed from offset 20000.
        When:  computing the next-cycle resume state.
        Then:  'after' stays on the same second and the offset steps forward by the page
               length so the next cycle reads the following slice of that second.
        """
        from ArmisEventCollector import compute_resume_state

        response = [
            {"id": "d", "time": "2026-10-06T08:33:16.100000+00:00"},
            {"id": "e", "time": "2026-10-06T08:33:16.200000+00:00"},
            {"id": "f", "time": "2026-10-06T08:33:16.300000+00:00"},
        ]
        after, offset = compute_resume_state(response, "2026-10-06T08:33:16", 20000, "time")
        assert after == "2026-10-06T08:33:16"
        assert offset == 20003

    def test_resume_does_not_advance_when_boundary_timestamp_missing(self):
        """
        Given: a multi-element response where an event is missing the order-by field.
        When:  computing the next-cycle resume state.
        Then:  the watermark is NOT advanced (a missing timestamp must not be mistaken
               for a second boundary); the offset steps conservatively instead.
        """
        from ArmisEventCollector import compute_resume_state

        response = [
            {"id": "a"},  # missing 'time'
            {"id": "b", "time": "2026-10-06T08:33:17.050000+00:00"},
        ]
        after, offset = compute_resume_state(response, "2026-10-06T08:33:16", 10, "time")
        assert after == "2026-10-06T08:33:16"
        assert offset == 12  # 10 + len(response)

    @pytest.mark.parametrize(
        "response",
        [
            pytest.param(
                [{"id": "a", "time": None}, {"id": "b", "time": "2026-10-06T08:33:17.050000+00:00"}],
                id="first_event_time_is_None",
            ),
            pytest.param(
                [{"id": "a", "time": "2026-10-06T08:33:16.010000+00:00"}, {"id": "b", "time": None}],
                id="last_event_time_is_None",
            ),
        ],
    )
    def test_resume_treats_explicit_none_timestamp_as_missing(self, response):
        """
        Given: a response where the boundary event has an explicit None order-by value.
        When:  computing the next-cycle resume state.
        Then:  None is treated as a missing timestamp (not the string "None"), so the
               watermark is NOT advanced and the offset steps conservatively instead.
        """
        from ArmisEventCollector import compute_resume_state

        after, offset = compute_resume_state(response, "2026-10-06T08:33:16", 10, "time")
        assert after == "2026-10-06T08:33:16"
        assert offset == 12  # 10 + len(response)

    def test_resume_keeps_state_unchanged_when_no_events(self):
        """
        Given: an empty response.
        When:  computing the next-cycle resume state.
        Then:  both 'after' and the offset are kept unchanged, so already-consumed
               events are not re-fetched on the next cycle.
        """
        from ArmisEventCollector import compute_resume_state

        after, offset = compute_resume_state([], "2026-10-06T08:33:16", 50000, "time")
        assert after == "2026-10-06T08:33:16"
        assert offset == 50000

    def test_resume_offset_never_grows_across_a_second_boundary(self):
        """
        Given: a single second holding more events than one page, followed by a later second.
        When:  draining it across multiple cycles.
        Then:  the offset only ever counts within that one second and snaps back to 0 once
               the later second appears, never accumulating into a deep offset.
        """
        from ArmisEventCollector import compute_resume_state

        page_size = 3
        after = "2026-10-06T08:33:16"
        offset = 0
        observed_offsets = []

        hot_second = [{"id": c, "time": "2026-10-06T08:33:16.000000+00:00"} for c in "ABCDEFG"]
        next_second = [{"id": "H", "time": "2026-10-06T08:33:17.000000+00:00"}]
        all_events = hot_second + next_second

        for _ in range(5):
            page = all_events[offset : offset + page_size]
            after, offset = compute_resume_state(page, after, offset, "time")
            observed_offsets.append(offset)
            if after == "2026-10-06T08:33:17":
                break

        assert max(observed_offsets) <= len(hot_second)
        assert after == "2026-10-06T08:33:17"
        assert offset == 0

    # test_dedup_events parametrize arguments
    case_all_events_with_same_time = (
        [
            {"unique_id": "1", "time": "2023-01-01T01:00:00.123456+00:00"},
            {"unique_id": "2", "time": "2023-01-01T01:00:00.123456+00:00"},
            {"unique_id": "3", "time": "2023-01-01T01:00:00.123456+00:00"},
        ],
        ["0", "1", "2"],
        "unique_id",
        ([{"unique_id": "3", "time": "2023-01-01T01:00:00.123456+00:00"}], ["0", "1", "2", "3"]),
    )
    case_events_with_different_time = (
        [
            {"unique_id": "1", "time": "2023-01-01T01:00:10.123456+00:00"},
            {"unique_id": "2", "time": "2023-01-01T01:00:20.123456+00:00"},
            {"unique_id": "3", "time": "2023-01-01T01:00:30.123456+00:00"},
        ],
        ["2"],
        "unique_id",
        (
            [
                {"unique_id": "1", "time": "2023-01-01T01:00:10.123456+00:00"},
                {"unique_id": "3", "time": "2023-01-01T01:00:30.123456+00:00"},
            ],
            ["3"],
        ),
    )
    case_empty_event_list: tuple = ([], ["1", "2", "3"], "unique_id", ([], ["1", "2", "3"]))

    @pytest.mark.parametrize(
        "events, events_last_fetch_ids, unique_id_key, expected_result",
        [case_all_events_with_same_time, case_events_with_different_time, case_empty_event_list],
    )
    def test_dedup_events(self, events, events_last_fetch_ids, unique_id_key, expected_result):
        """
        Given:
            - Case 1: All events from the current fetch cycle have the same timestamp.
            - Case 2: Most recent event has later timestamp then other events in the response.
            - Case 3: Empty event list (no new events received from API response).
        When:
            - Using the dedup mechanism while fetching events.
        Then:
            - Case 1: Add the list of fetched events IDs to current 'events_last_fetch_ids' from last run,
                      return list of dedup event and updated list of 'events_last_fetch_ids' for next run.
            - Case 2: Return list of dedup event and new list of 'new_ids' for next run.
            - Case 3: Return empty list and the unchanged list of 'events_last_fetch_ids' for next run.
        """
        event_order_by = "time"
        from ArmisEventCollector import dedup_events

        assert dedup_events(events, events_last_fetch_ids, unique_id_key, event_order_by) == expected_result

    def test_dedup_events_handles_explicit_none_timestamp(self):
        """
        Given: events where the latest event has an explicit None order-by value.
        When:  running the dedup mechanism.
        Then:  no TypeError is raised (None is treated as an empty timestamp), new events
               are returned, and only the trailing None-timestamp event's id is kept for dedup.
        """
        from ArmisEventCollector import dedup_events

        events = [
            {"unique_id": "1", "time": "2023-01-01T01:00:10.123456+00:00"},
            {"unique_id": "2", "time": None},
        ]
        new_events, new_ids = dedup_events(events, [], "unique_id", "time")
        assert new_events == events
        assert new_ids == ["2"]

    @pytest.mark.parametrize(
        "next_pointer, expected_last_run",
        [
            # The response spans multiple distinct seconds, so the resume state advances
            # to the latest second and resets the offset to 0 regardless of the API's
            # 'next' pointer (the watermark decision no longer depends on it).
            (
                4,
                {
                    "events_last_fetch_ids": ["3"],
                    "events_last_fetch_next_field": 0,
                    "events_last_fetch_time": "2023-01-01T01:00:30",
                },
            ),
            (
                0,
                {
                    "events_last_fetch_ids": ["3"],
                    "events_last_fetch_next_field": 0,
                    "events_last_fetch_time": "2023-01-01T01:00:30",
                },
            ),
        ],
    )
    @freeze_time("2024-01-01 01:00:00")
    def test_fetch_by_event_type(self, mocker, dummy_client, next_pointer, expected_last_run):
        """
        Given:
            - A valid event type arguments for API request (unique_id_key, aql_query, type) and a mocker for the response data.
            - Case 1: A response data with a next pointer = 0.
            - Case 2: A response data with a next pointer = 4.
        When:
            - Iterating over which event types to fetch.
        Then:
            - Perform fetch for the specific event type, update event list and update
              last run dictionary for next fetch cycle.
            - Case 1: Should set the next to 0 and take the freezed now time as the next run time.
            - Case 2: Should set the next to 4 and take the time of the last incident.
        """
        from ArmisEventCollector import fetch_by_event_type

        event_type = EVENT_TYPE("unique_id", "example:query", "events", "time", "events")
        events: dict[str, list[dict]] = {}
        next_run: dict = {}
        last_run = {"events_last_fetch_time": "2023-01-01T01:00:20", "events_last_fetch_ids": ["1", "2"]}
        fetch_start_time_param = datetime.now()
        response = [
            {"unique_id": "1", "time": "2023-01-01T01:00:10.123456+00:00"},
            {"unique_id": "2", "time": "2023-01-01T01:00:20.123456+00:00"},
            {"unique_id": "3", "time": "2023-01-01T01:00:30.123456+00:00"},
        ]
        mocker.patch.object(Client, "fetch_by_aql_query", return_value=(response, next_pointer))

        fetch_by_event_type(dummy_client, event_type, events, 1, last_run, next_run, fetch_start_time_param)

        assert events["events"] == [{"unique_id": "3", "time": "2023-01-01T01:00:30.123456+00:00"}]
        assert next_run == expected_last_run

    # test_add_time_to_events parametrize arguments
    case_one_event = (
        [{"time": "2023-01-01T01:00:10.123456+00:00", "unique_id": "1"}],
        [{"time": "2023-01-01T01:00:10.123456+00:00", "_time": "2023-01-01T01:00:10.123456+00:00", "unique_id": "1"}],
        "events",
    )

    case_two_events = (
        [
            {"time": "2023-01-01T01:00:10.123456+00:00", "unique_id": "1"},
            {"time": "2023-01-01T01:00:20.123456+00:00", "unique_id": "2"},
        ],
        [
            {"time": "2023-01-01T01:00:10.123456+00:00", "_time": "2023-01-01T01:00:10.123456+00:00", "unique_id": "1"},
            {"time": "2023-01-01T01:00:20.123456+00:00", "_time": "2023-01-01T01:00:20.123456+00:00", "unique_id": "2"},
        ],
        "events",
    )
    case_empty_event: tuple = ([], [], "events")
    case_devices_events: tuple = (
        [
            {"lastSeen": "2023-01-01T01:00:10.123456+00:00", "unique_id": "1"},
            {"lastSeen": "2023-01-01T01:00:20.123456+00:00", "unique_id": "2"},
        ],
        [
            {"lastSeen": "2023-01-01T01:00:10.123456+00:00", "_time": "2023-01-01T01:00:10.123456+00:00", "unique_id": "1"},
            {"lastSeen": "2023-01-01T01:00:20.123456+00:00", "_time": "2023-01-01T01:00:20.123456+00:00", "unique_id": "2"},
        ],
        "devices",
    )

    @pytest.mark.parametrize(
        "events, expected_result, eventType",
        [
            case_one_event,
            case_two_events,
            case_empty_event,
        ],
    )
    def test_add_time_to_events(self, events, expected_result, eventType):
        """
        Given:
            - Case 1: One event with valid time attribute.
            - Case 2: Two event with valid time attribute.
            - Case 3: Empty list of events.
        When:
            - Preparing to send fetched events to XSIAM.
        Then:
            - Add _time attribute to each event with a valid time attribute.
        """
        from ArmisEventCollector import add_time_to_events

        add_time_to_events(events, eventType)
        assert events == expected_result

    def test_events_to_command_results(self):
        """
        Given:
            - A valid list of fetched events.
        When:
            - Using the 'armis-get-event' command.
        Then:
            - A command result with readable output will be printed to the war-room.
        """
        from ArmisEventCollector import PRODUCT, VENDOR, CommandResults, events_to_command_results, tableToMarkdown

        events_fetched = {
            "events": [
                {"time": "2023-01-01T01:00:10.123456+00:00", "_time": "2023-01-01T01:00:10", "unique_id": "1"},
                {"time": "2023-01-01T01:00:20.123456+00:00", "_time": "2023-01-01T01:00:20", "unique_id": "2"},
            ]
        }
        expected_events_result = events_fetched["events"]
        expected_result = CommandResults(
            raw_response=events_fetched,
            readable_output=tableToMarkdown(name=f"{VENDOR} {PRODUCT}_events events", t=expected_events_result, removeNull=True),
        )
        assert events_to_command_results(events_fetched, "events").readable_output == expected_result.readable_output

    @freeze_time("2023-01-01 01:00:00")
    def test_set_last_run_with_current_time_initial(self, mocker):
        """
        Given:
            - A valid list of fetched events.
            - An empty last_run dictionary.
        When:
            - Initial fetch is running.
        Then:
            - Set the last_run dictionary with the current time for each event type key.
        """
        from ArmisEventCollector import set_last_run_for_last_minute

        last_run: dict[Any, Any] = {}

        set_last_run_for_last_minute(last_run)

        assert last_run["alerts_last_fetch_time"] == last_run["activity_last_fetch_time"] == "2023-01-01T00:59:00"

    @pytest.mark.parametrize("time_delta_since_last_fetch, expected_result", [(2, True), (-0.5, False)])
    def test_should_run_device_fetch(self, time_delta_since_last_fetch, expected_result):
        """
            Fetch devices interval in this test is 1 hour.
        Given:
            - Case 1: Two hours since fetch for devices has been called.
            - Case 2: Half an hour since fetch for devices has been called.
        When:
            - Calling should_run_device_fetch method
        Then:
            - True as last run time is more than the device fetch interval
            - False as last run time was less than the device fetch interval of 1 hour

        """
        from ArmisEventCollector import should_run_device_fetch

        addition_to_fetch_interval = timedelta(hours=time_delta_since_last_fetch)
        time_in_last_fetch = datetime.now() - addition_to_fetch_interval
        last_run: dict = {"devices_last_fetch_time": time_in_last_fetch.strftime("%Y-%m-%dT%H:%M:%S")}
        assert should_run_device_fetch(last_run, timedelta(hours=1), datetime.now()) is expected_result

    def test_handle_from_date_argument(self):
        from ArmisEventCollector import handle_from_date_argument

        from_date_datetime = handle_from_date_argument("2023-01-01T01:00:00")
        assert from_date_datetime == datetime(2023, 1, 1, 1, 0, 0)

    @freeze_time("2023-01-01T01:00:00")
    def test_devices_only_skip_preserves_state(self, mocker, dummy_client):
        """
        Given:
            - A Devices-only instance whose device-fetch interval has NOT elapsed
              (last fetch 1 minute ago, interval 1 hour).
        When:
            - fetch_events runs and skips the device fetch.
        Then:
            - The returned next_run is NOT empty and retains devices_last_fetch_time, so the
              persisted lastRun does not get wiped.
        """
        from ArmisEventCollector import fetch_events

        fetch_start_time = arg_to_datetime("2023-01-01T01:00:00")
        # Frozen now is 01:00:00; last_fetch 1 minute earlier -> interval (1h) not reached -> skip.
        recent = "2023-01-01T00:59:00"
        last_run = {"devices_last_fetch_time": recent, "devices_last_fetch_ids": ["dev1"], "devices_last_fetch_next_field": 0}
        device_fetch_interval = timedelta(hours=1)

        events, next_run = fetch_events(
            client=dummy_client,
            max_fetch=1000,
            devices_max_fetch=1000,
            last_run=last_run,
            fetch_start_time=fetch_start_time,
            event_types_to_fetch=["Devices"],
            device_fetch_interval=device_fetch_interval,
            use_multithreading=False,
            context_manager=None,
        )

        assert events == {}
        assert next_run.get("devices_last_fetch_time") == recent
        assert next_run.get("devices_last_fetch_ids") == ["dev1"]
        assert next_run.get("devices_last_fetch_next_field") == 0


class TestFetchFlow:
    fetch_start_time = arg_to_datetime("2023-01-01T01:00:00")

    events_with_different_time_1 = [
        {"unique_id": "1", "time": "2023-01-01T01:00:10.123456+00:00"},
        {"unique_id": "2", "time": "2023-01-01T01:00:20.123456+00:00"},
        {"unique_id": "3", "time": "2023-01-01T01:00:30.123456+00:00"},
    ]
    events_with_different_time_2 = [
        {"unique_id": "4", "time": "2023-01-01T01:00:40.123456+00:00"},
        {"unique_id": "5", "time": "2023-01-01T01:00:50.123456+00:00"},
        {"unique_id": "6", "time": "2023-01-01T01:01:00.123456+00:00"},
        {"unique_id": "7", "time": "2023-01-01T01:01:00.123456+00:00"},
    ]
    events_with_duplicated_from_1 = [
        {"unique_id": "1", "time": "2023-01-01T01:00:10.123456+00:00"},
        {"unique_id": "2", "time": "2023-01-01T01:00:20.123456+00:00"},
        {"unique_id": "6", "time": "2023-01-01T01:01:00.123456+00:00"},
        {"unique_id": "7", "time": "2023-01-01T01:01:00.123456+00:00"},
    ]
    events_with_same_time = [  # type: ignore
        {"unique_id": "4", "time": "2023-01-01T01:00:30.123456+00:00"},
        {"unique_id": "5", "time": "2023-01-01T01:00:30.123456+00:00"},
        {"unique_id": "6", "time": "2023-01-01T01:00:30.123456+00:00"},
    ]

    case_first_fetch = (  # type: ignore
        # this case test the actual first fetch that runs after the initial fetch (that only sets the last run)
        1000,
        1000,
        {"alerts_last_fetch_time": "2023-01-01T01:00:00"},
        fetch_start_time,
        ["Events"],
        events_with_different_time_1,
        {"events": events_with_different_time_1},
        # Multi-second response -> advance to latest second, reset offset to 0.
        {
            "events_last_fetch_ids": ["3"],
            "events_last_fetch_next_field": 0,
            "events_last_fetch_time": "2023-01-01T01:00:30",
        },
        4,
    )

    case_second_fetch = (  # type: ignore
        1000,
        1000,
        {
            "events_last_fetch_ids": ["1", "2", "3"],
            "events_last_fetch_time": "2023-01-01T01:00:30.123456+00:00",
            "access_token": "test_access_token",
        },
        fetch_start_time,
        ["Events"],
        events_with_different_time_2,
        {"events": events_with_different_time_2},
        # Multi-second response -> advance to latest second, reset offset to 0.
        {
            "events_last_fetch_ids": ["7", "6"],
            "events_last_fetch_next_field": 0,
            "events_last_fetch_time": "2023-01-01T01:01:00",
        },
        8,
    )
    case_second_fetch_with_duplicates = (  # type: ignore
        1000,
        1000,
        {
            "events_last_fetch_ids": ["1", "2", "3"],
            "events_last_fetch_time": "2023-01-01T01:00:30.123456+00:00",
            "access_token": "test_access_token",
        },
        fetch_start_time,
        ["Events"],
        events_with_duplicated_from_1,
        {
            "events": [
                {"unique_id": "6", "time": "2023-01-01T01:01:00.123456+00:00"},
                {"unique_id": "7", "time": "2023-01-01T01:01:00.123456+00:00"},
            ]
        },
        # Multi-second response -> advance to latest second, reset offset to 0.
        {
            "events_last_fetch_ids": ["7", "6"],
            "events_last_fetch_next_field": 0,
            "events_last_fetch_time": "2023-01-01T01:01:00",
        },
        8,
    )

    case_no_new_event_from_fetch = (  # type: ignore
        1000,
        1000,
        {
            "events_last_fetch_ids": ["1", "2", "3"],
            "events_last_fetch_time": "2023-01-01T01:00:30.123456+00:00",
            "access_token": "test_access_token",
        },
        fetch_start_time,
        ["Events"],
        {},
        {},
        # Empty response -> keep watermark and offset unchanged (offset defaults to 0).
        {"events_last_fetch_next_field": 0, "events_last_fetch_time": "2023-01-01T01:00:30.123456+00:00"},
        4,
    )

    case_all_events_from_fetch_have_the_same_time = (  # type: ignore
        1000,
        1000,
        {
            "events_last_fetch_ids": ["1", "2", "3"],
            "events_last_fetch_time": "2023-01-01T01:00:30.123456+00:00",
            "access_token": "test_access_token",
        },
        fetch_start_time,
        ["Events"],
        events_with_same_time,
        {"events": events_with_same_time},
        # Single-second response -> keep watermark, step offset within the second (0 + 3).
        {
            "events_last_fetch_ids": ["1", "2", "3", "4", "5", "6"],
            "events_last_fetch_next_field": 3,
            "events_last_fetch_time": "2023-01-01T01:00:30.123456+00:00",
        },
        7,
    )

    @pytest.mark.parametrize(
        "max_fetch, devices_max_fetch, last_run, fetch_start_time, event_types_to_fetch, response, events,\
        next_run, next",
        [
            case_first_fetch,
            case_second_fetch,
            case_second_fetch_with_duplicates,
            case_no_new_event_from_fetch,
            case_all_events_from_fetch_have_the_same_time,
        ],
    )
    def test_fetch_flow_cases(
        self,
        mocker,
        dummy_client,
        max_fetch,
        devices_max_fetch,
        last_run,
        fetch_start_time,
        event_types_to_fetch,
        response,
        events,
        next_run,
        next,
    ):
        """
        Given:
            - Case 1: First fetch, response has 3 events with different timestamps.
            - Case 2: Second fetch, response has 3 events with different timestamps.
            - Case 3: Second fetch with duplicated, some events in the response have same timestamps as last fetch.
            - Case 4: Second fetch with empty response (no new events from last fetch).
            - Case 5: Second fetch, all events have the same timestamp.
        When:
            - Fetching events.
        Then:
            - Case 1: Handle the fetch, validate events and next_run variables.
            - Case 2: Handle the fetch, validate events and next_run variables.
            - Case 3: Handle the fetch, validate dedup, validate events and next_run variables.
            - Case 4: Handle the fetch, validate dedup, validate events and next_run (same as last_run).
            - Case 5: Handle the fetch, validate dedup, validate events & last_run variable has IDs from current and last fetch.

        """
        from ArmisEventCollector import fetch_events

        mocker.patch.object(Client, "fetch_by_aql_query", return_value=(response, next))
        mocker.patch.dict(EVENT_TYPES, {"Events": EVENT_TYPE("unique_id", "events_query", "events", "time", "events")})
        assert fetch_events(
            dummy_client, max_fetch, devices_max_fetch, last_run, fetch_start_time, event_types_to_fetch, None
        ) == (events, next_run)

    case_access_token_expires_in_runtime = ()

    def test_token_expires_in_runtime(self, mocker, dummy_client):
        """
        Given:
            - Access token has expired in runtime.
        When:
            - Fetching events.
        Then:
            - Catch the specific exception, updated the access token and perform a second attempt
              to fetch events for the current event type iteration.
        """
        from ArmisEventCollector import fetch_events

        events_with_different_time = {
            "data": {
                "results": [
                    {"unique_id": "1", "time": "2023-01-01T01:00:10.123456+00:00"},
                    {"unique_id": "2", "time": "2023-01-01T01:00:20.123456+00:00"},
                    {"unique_id": "3", "time": "2023-01-01T01:00:30.123456+00:00"},
                ],
                "next": 4,
            }
        }
        fetch_start_time = arg_to_datetime("2023-01-01T01:00:00")

        # Mock the token refresh to return a new token
        mocker.patch.object(Client, "get_access_token", return_value="new_test_token")

        # First call fails with invalid token, second succeeds
        mocker.patch.object(
            Client, "_http_request", side_effect=[DemistoException(message="Invalid access token"), events_with_different_time]
        )
        mocker.patch.dict(EVENT_TYPES, {"Events": EVENT_TYPE("unique_id", "events_query", "events", "time", "events")})

        if fetch_start_time:
            # Multi-second response -> advance to latest second, reset offset to 0.
            expected_next_run = {
                "events_last_fetch_ids": ["3"],
                "events_last_fetch_next_field": 0,
                "events_last_fetch_time": "2023-01-01T01:00:30",
            }
            assert fetch_events(dummy_client, 1000, 1000, {}, fetch_start_time, ["Events"], None) == (
                {"events": events_with_different_time["data"]["results"]},
                expected_next_run,
            )

    def test_fetch_alert_flow(self, mocker, dummy_client):
        """
        Given:
            - A single alert with activityUUIDs and deviceIds.
        When:
            - Fetching Alerts event type (which triggers bulk enrichment).
        Then:
            - The alert is enriched with activitiesData and devicesData via bulk_enrich_alerts.
            - The enrichment uses bulk AQL queries (UUID:..., deviceId:...) instead of per-alert calls.
        """
        from ArmisEventCollector import fetch_events

        alerts_response = {
            "data": {
                "results": [
                    {
                        "alertId": "1",
                        "activityUUIDs": ["uuid-aaa", "uuid-bbb"],
                        "deviceIds": [789, 12],
                        "time": "2023-01-01T01:00:10.123456+00:00",
                    }
                ],
                "next": 2,
            }
        }
        # Bulk enrichment AQL responses (UUID:uuid-aaa,uuid-bbb and deviceId:789,12)
        activities_bulk_response = {
            "data": {
                "results": [
                    {"activityUUID": "uuid-aaa", "time": "2023-01-01T01:00:10.123456+00:00"},
                    {"activityUUID": "uuid-bbb", "time": "2023-01-01T01:00:11.123456+00:00"},
                ]
            }
        }
        devices_bulk_response = {
            "data": {
                "results": [
                    {"id": 789, "name": "device-A", "lastSeen": "2023-01-01T01:00:10.123456+00:00"},
                    {"id": 12, "name": "device-B", "lastSeen": "2023-01-01T01:00:10.123456+00:00"},
                ]
            }
        }
        fetch_start_time = arg_to_datetime("2023-01-01T01:00:00")
        # 1st call: fetch alerts; 2nd call: bulk activities; 3rd call: bulk devices
        mocker.patch.object(
            Client, "_http_request", side_effect=[alerts_response, activities_bulk_response, devices_bulk_response]
        )

        # enable_streaming=False keeps alerts in the events dict (legacy non-chunked path)
        # so we can assert on the enriched result. The chunked-ship path is tested
        # separately in TestBulkEnrichAlertsChunked.
        events, next_run = fetch_events(dummy_client, 1, 1, {}, fetch_start_time, ["Alerts"], None, enable_streaming=False)

        # Verify the alert was enriched
        assert len(events["alerts"]) == 1
        enriched_alert = events["alerts"][0]
        assert len(enriched_alert["activitiesData"]) == 2
        assert len(enriched_alert["devicesData"]) == 2
        # Verify activities are mapped by UUID
        activity_uuids = {a["activityUUID"] for a in enriched_alert["activitiesData"]}
        assert activity_uuids == {"uuid-aaa", "uuid-bbb"}
        # Verify devices are mapped by id
        device_ids = {d["id"] for d in enriched_alert["devicesData"]}
        assert device_ids == {789, 12}
        # Verify next_run state: single-second response (one alert) keeps the watermark
        # and steps the offset within the second by the fetched count (0 + 1).
        assert next_run["alerts_last_fetch_next_field"] == 1


class TestMultithreading:
    """Tests for multithreading functionality."""

    def test_integration_context_manager_thread_safety(self):
        """Test that IntegrationContextManager provides thread-safe access.

        Given:
            - An IntegrationContextManager instance.
            - A test access token to be saved and retrieved.
        When:
            - Saving an access token to the context.
            - Retrieving the access token from the context.
        Then:
            - The retrieved token should match the saved token.
            - Operations should be thread-safe.
        """
        context_manager = IntegrationContextManager()

        # Test get and save access token
        test_token = "test_token_123"
        context_manager.save_access_token_to_context(test_token)

        with patch("demistomock.getLastRun", return_value={"access_token": test_token}):
            retrieved_token = context_manager.get_access_token()
            assert retrieved_token == test_token

    def test_integration_context_manager_concurrent_updates(self):
        """Test that concurrent updates to context are handled safely.

        Given:
            - An IntegrationContextManager instance.
            - Multiple threads attempting to update the access token concurrently.
        When:
            - 5 threads simultaneously save different access tokens to the context.
        Then:
            - All 5 updates should complete successfully without race conditions.
            - The context manager's locking mechanism should prevent data corruption.
        """
        context_manager = IntegrationContextManager()
        results = []

        def update_token(token_value):
            with patch("demistomock.getLastRun", return_value={}), patch("demistomock.setLastRun"):
                context_manager.save_access_token_to_context(token_value)
                results.append(token_value)

        # Simulate concurrent updates
        threads = []
        for i in range(5):
            t = threading.Thread(target=update_token, args=(f"token_{i}",))
            threads.append(t)
            t.start()

        for t in threads:
            t.join()

        # All updates should have completed
        assert len(results) == 5

    def test_client_with_context_manager(self, mocker):
        """Test Client initialization with context manager.

        Given:
            - An IntegrationContextManager instance.
            - Valid client initialization parameters.
        When:
            - Initializing a Client with the context manager.
        Then:
            - The client should store the context manager reference.
            - The client should be initialized with the provided access token.
        """
        context_manager = IntegrationContextManager()
        mocker.patch.object(Client, "_is_token_still_fresh", return_value=True)

        client = Client(base_url="test_url", api_key="test_key", access_token="test_token", context_manager=context_manager)

        assert client._context_manager == context_manager
        assert client._access_token == "test_token"

    def test_client_refresh_token_coordination(self, mocker):
        """Test that token refresh is coordinated across threads.

        Given:
            - A Client instance with a context manager.
            - An expired access token that needs refreshing.
        When:
            - Calling refresh_access_token() to get a new token.
        Then:
            - A new token should be generated via the API.
            - The new token should be saved to the integration context.
            - The token refresh should be coordinated to prevent multiple simultaneous refreshes.
        """
        context_manager = IntegrationContextManager()
        mocker.patch.object(Client, "_is_token_still_fresh", return_value=True)
        mocker.patch.object(Client, "get_access_token", return_value="new_token")

        client = Client(base_url="test_url", api_key="test_key", access_token="old_token", context_manager=context_manager)

        # Mock context manager methods
        mocker.patch.object(context_manager, "get_access_token", return_value="old_token")
        mock_save = mocker.patch.object(context_manager, "save_access_token_to_context")

        new_token = client.refresh_access_token()

        assert new_token == "new_token"
        mock_save.assert_called_once_with("new_token")

    def test_fetch_events_with_multithreading_disabled(self, mocker, dummy_client):
        """Test that fetch_events works correctly with multithreading disabled.

        Given:
            - Multithreading is disabled (use_multithreading=False).
            - A single event type (Activities) to fetch.
            - Mock API response with one activity event.
        When:
            - Calling fetch_events() with multithreading disabled.
        Then:
            - Events should be fetched sequentially.
            - The activities should be returned in the events dictionary.
            - One activity event should be fetched successfully.
        """
        fetch_start_time = arg_to_datetime("2023-01-01T01:00:00")
        response = [{"unique_id": "1", "time": "2023-01-01T01:00:10.123456+00:00"}]

        mocker.patch.object(Client, "fetch_by_aql_query", return_value=(response, 0))
        mocker.patch.dict(EVENT_TYPES, {"Activities": EVENT_TYPE("unique_id", "query", "activity", "time", "activities")})

        events, next_run = fetch_events(
            client=dummy_client,
            max_fetch=100,
            devices_max_fetch=100,
            last_run={},
            fetch_start_time=fetch_start_time,
            event_types_to_fetch=["Activities"],
            device_fetch_interval=None,
            use_multithreading=False,
            context_manager=None,
            enable_streaming=False,  # legacy path: collect into events dict
        )

        assert "activities" in events
        assert len(events["activities"]) == 1

    def test_fetch_events_with_multithreading_enabled(self, mocker, dummy_client):
        """Test that fetch_events works correctly with multithreading enabled.

        Given:
            - Multithreading is enabled (use_multithreading=True).
            - Multiple event types to fetch (Activities and Devices).
            - A context manager for thread-safe operations.
            - Mock API responses for both event types.
        When:
            - Calling fetch_events() with multithreading enabled.
        Then:
            - Events should be fetched in parallel using ThreadPoolExecutor.
            - Both Activities and Devices should be fetched successfully.
            - The access token should be included in next_run.
            - Context updates should be thread-safe.
        """
        context_manager = IntegrationContextManager()
        fetch_start_time = arg_to_datetime("2023-01-01T01:00:00")

        activities_response = [{"activityUUID": "1", "time": "2023-01-01T01:00:10.123456+00:00"}]
        devices_response = [{"id": "1", "lastSeen": "2023-01-01T01:00:10.123456+00:00"}]

        def mock_fetch_by_aql(*args, **kwargs):
            event_type = kwargs.get("event_type", "")
            if event_type == "activity":
                return activities_response, 0
            elif event_type == "devices":
                return devices_response, 0
            return [], 0

        mocker.patch.object(Client, "fetch_by_aql_query", side_effect=mock_fetch_by_aql)
        mocker.patch.object(context_manager, "update_event_type_state")

        events, next_run = fetch_events(
            client=dummy_client,
            max_fetch=100,
            devices_max_fetch=100,
            last_run={},
            fetch_start_time=fetch_start_time,
            event_types_to_fetch=["Activities", "Devices"],
            device_fetch_interval=timedelta(hours=1),
            use_multithreading=True,
            context_manager=context_manager,
            enable_streaming=False,  # legacy path: collect into events dict
        )

        # Both event types should be fetched
        assert "activities" in events or "devices" in events

    def test_perform_fetch_with_token_refresh_coordination(self, mocker, dummy_client):
        """Test that perform_fetch coordinates token refresh properly.

        Given:
            - A Client with a context manager.
            - An expired access token that causes the first API call to fail.
            - A fresh token available in the context.
        When:
            - Calling perform_fetch() which encounters an authentication error.
        Then:
            - The client should detect the invalid token error.
            - The client should coordinate token refresh using the context manager.
            - The request should be retried with the refreshed token.
            - The second request should succeed and return results.
        """
        context_manager = IntegrationContextManager()
        dummy_client._context_manager = context_manager

        # First call fails with invalid token, second succeeds
        mocker.patch.object(
            Client, "_http_request", side_effect=[DemistoException("Invalid access token"), {"data": {"results": []}}]
        )
        mocker.patch.object(context_manager, "get_access_token", return_value="fresh_token")
        mocker.patch.object(Client, "refresh_access_token", return_value="new_token")

        result = dummy_client.perform_fetch({"aql": "test"})

        assert result == {"data": {"results": []}}


class TestCollectUniqueEnrichmentIds:
    """Tests for _collect_unique_enrichment_ids."""

    def test_basic_dedup(self):
        """
        Given:
            - Two alerts sharing some activityUUIDs and deviceIds.
        When:
            - Collecting unique enrichment IDs.
        Then:
            - Duplicates are removed and all IDs are str-coerced.
            - Each alert gets empty activitiesData/devicesData lists.
        """
        alerts = [
            {"alertId": "1", "activityUUIDs": ["aaa", "bbb"], "deviceIds": [1, 2]},
            {"alertId": "2", "activityUUIDs": ["bbb", "ccc"], "deviceIds": [2, 3]},
        ]
        uuids, device_ids = _collect_unique_enrichment_ids(alerts)

        assert uuids == {"aaa", "bbb", "ccc"}
        assert device_ids == {"1", "2", "3"}
        # Verify initialization of enrichment fields
        for alert in alerts:
            assert alert["activitiesData"] == []
            assert alert["devicesData"] == []

    def test_str_coercion(self):
        """
        Given:
            - Alerts with integer deviceIds and mixed-type activityUUIDs.
        When:
            - Collecting unique enrichment IDs.
        Then:
            - All IDs are coerced to strings.
        """
        alerts = [{"alertId": "1", "activityUUIDs": [123, "456"], "deviceIds": [789]}]
        uuids, device_ids = _collect_unique_enrichment_ids(alerts)

        assert uuids == {"123", "456"}
        assert device_ids == {"789"}

    def test_empty_arrays(self):
        """
        Given:
            - An alert with empty activityUUIDs and deviceIds arrays.
        When:
            - Collecting unique enrichment IDs.
        Then:
            - Returns empty sets.
        """
        alerts = [{"alertId": "1", "activityUUIDs": [], "deviceIds": []}]
        uuids, device_ids = _collect_unique_enrichment_ids(alerts)

        assert uuids == set()
        assert device_ids == set()

    def test_none_handling(self):
        """
        Given:
            - An alert with None activityUUIDs and missing deviceIds key.
        When:
            - Collecting unique enrichment IDs.
        Then:
            - Returns empty sets without errors.
        """
        alerts = [{"alertId": "1", "activityUUIDs": None}]
        uuids, device_ids = _collect_unique_enrichment_ids(alerts)

        assert uuids == set()
        assert device_ids == set()

    def test_none_values_in_arrays(self):
        """
        Given:
            - An alert with None values inside activityUUIDs and deviceIds arrays.
        When:
            - Collecting unique enrichment IDs.
        Then:
            - None values are filtered out.
        """
        alerts = [{"alertId": "1", "activityUUIDs": ["aaa", None, "bbb"], "deviceIds": [1, None]}]
        uuids, device_ids = _collect_unique_enrichment_ids(alerts)

        assert uuids == {"aaa", "bbb"}
        assert device_ids == {"1"}

    def test_empty_alerts_list(self):
        """
        Given:
            - An empty alerts list.
        When:
            - Collecting unique enrichment IDs.
        Then:
            - Returns empty sets.
        """
        uuids, device_ids = _collect_unique_enrichment_ids([])

        assert uuids == set()
        assert device_ids == set()


class TestBulkFetchEntitiesById:
    """Tests for _bulk_fetch_entities_by_id."""

    def test_empty_ids(self, mocker, dummy_client):
        """
        Given:
            - An empty list of IDs.
        When:
            - Calling _bulk_fetch_entities_by_id.
        Then:
            - Returns empty dict without making any API calls.
        """
        mock_fetch = mocker.patch.object(Client, "fetch_by_ids_in_aql_query")

        result = _bulk_fetch_entities_by_id(
            client=dummy_client,
            entity_type="activity",
            aql_field="UUID",
            ids=[],
            response_key="activityUUID",
            order_by="time",
        )

        assert result == {}
        mock_fetch.assert_not_called()

    def test_single_batch(self, mocker, dummy_client):
        """
        Given:
            - A list of 3 IDs (below BULK_ENRICHMENT_BATCH_SIZE).
        When:
            - Calling _bulk_fetch_entities_by_id.
        Then:
            - Makes a single API call and returns results keyed by response_key.
        """
        api_results = [
            {"activityUUID": "aaa", "data": "x"},
            {"activityUUID": "bbb", "data": "y"},
        ]
        mocker.patch.object(Client, "fetch_by_ids_in_aql_query", return_value=api_results)

        result = _bulk_fetch_entities_by_id(
            client=dummy_client,
            entity_type="activity",
            aql_field="UUID",
            ids=["aaa", "bbb", "ccc"],
            response_key="activityUUID",
            order_by="time",
        )

        assert result == {"aaa": api_results[0], "bbb": api_results[1]}

    def test_batching_over_1000_ids(self, mocker, dummy_client):
        """
        Given:
            - A list of 1500 IDs (exceeds BULK_ENRICHMENT_BATCH_SIZE of 1000).
        When:
            - Calling _bulk_fetch_entities_by_id.
        Then:
            - Makes 2 API calls (batch of 1000 + batch of 500).
        """
        ids = [str(i) for i in range(1500)]
        batch1_results = [{"id": str(i)} for i in range(1000)]
        batch2_results = [{"id": str(i)} for i in range(1000, 1500)]

        mock_fetch = mocker.patch.object(Client, "fetch_by_ids_in_aql_query", side_effect=[batch1_results, batch2_results])

        result = _bulk_fetch_entities_by_id(
            client=dummy_client,
            entity_type="devices",
            aql_field="deviceId",
            ids=ids,
            response_key="id",
            order_by="lastSeen",
        )

        assert mock_fetch.call_count == 2
        assert len(result) == 1500

    def test_api_failure_handling(self, mocker, dummy_client):
        """
        Given:
            - An API call that raises an exception.
        When:
            - Calling _bulk_fetch_entities_by_id.
        Then:
            - The exception is caught and logged; returns empty dict.
        """
        mocker.patch.object(Client, "fetch_by_ids_in_aql_query", side_effect=Exception("API error"))
        mocker.patch("ArmisEventCollector.demisto.error")

        result = _bulk_fetch_entities_by_id(
            client=dummy_client,
            entity_type="activity",
            aql_field="UUID",
            ids=["aaa"],
            response_key="activityUUID",
            order_by="time",
        )

        assert result == {}

    def test_truncation_warning(self, mocker, dummy_client):
        """
        Given:
            - An API response with more results than BULK_ENRICHMENT_BATCH_SIZE.
        When:
            - Calling _bulk_fetch_entities_by_id.
        Then:
            - A warning is logged but results are still returned.
        """
        # Return 1001 results for a batch of 1000 IDs
        api_results = [{"activityUUID": f"uuid-{i}"} for i in range(BULK_ENRICHMENT_BATCH_SIZE + 1)]
        mocker.patch.object(Client, "fetch_by_ids_in_aql_query", return_value=api_results)
        mock_error = mocker.patch("ArmisEventCollector.demisto.error")

        result = _bulk_fetch_entities_by_id(
            client=dummy_client,
            entity_type="activity",
            aql_field="UUID",
            ids=[f"uuid-{i}" for i in range(BULK_ENRICHMENT_BATCH_SIZE)],
            response_key="activityUUID",
            order_by="time",
        )

        assert len(result) == BULK_ENRICHMENT_BATCH_SIZE + 1
        mock_error.assert_called_once()


class TestAttachEnrichment:
    """Tests for _attach_enrichment."""

    def test_basic_mapping(self):
        """
        Given:
            - An alert with activityUUIDs and deviceIds.
            - Lookup dicts with matching entities.
        When:
            - Attaching enrichment.
        Then:
            - activitiesData and devicesData are populated correctly.
        """
        alerts = [
            {"alertId": "1", "activityUUIDs": ["aaa", "bbb"], "deviceIds": [10, 20], "activitiesData": [], "devicesData": []},
        ]
        activities = {"aaa": {"activityUUID": "aaa", "data": "x"}, "bbb": {"activityUUID": "bbb", "data": "y"}}
        devices = {"10": {"id": 10, "name": "d1"}, "20": {"id": 20, "name": "d2"}}

        _attach_enrichment(alerts, activities, devices)

        assert len(alerts[0]["activitiesData"]) == 2
        assert len(alerts[0]["devicesData"]) == 2

    def test_shared_references_across_alerts(self):
        """
        Given:
            - Two alerts sharing the same activityUUID.
        When:
            - Attaching enrichment.
        Then:
            - Both alerts see the *same* underlying entity object (no deepcopy).
            - This is the memory-saving invariant: alerts are write-once after attach
              and serialized to XSIAM as-is, so shared references are safe.
        """
        alerts = [
            {"alertId": "1", "activityUUIDs": ["shared"], "deviceIds": [], "activitiesData": [], "devicesData": []},
            {"alertId": "2", "activityUUIDs": ["shared"], "deviceIds": [], "activitiesData": [], "devicesData": []},
        ]
        shared_entity = {"activityUUID": "shared", "data": "original"}
        activities = {"shared": shared_entity}

        _attach_enrichment(alerts, activities, {})

        # Both alerts should reference the *exact same* dict instance (no deepcopy).
        assert alerts[0]["activitiesData"][0] is shared_entity
        assert alerts[1]["activitiesData"][0] is shared_entity
        assert alerts[0]["activitiesData"][0] is alerts[1]["activitiesData"][0]

    def test_str_coercion_mapping(self):
        """
        Given:
            - An alert with integer deviceIds.
            - A devices lookup keyed by string IDs.
        When:
            - Attaching enrichment.
        Then:
            - Integer IDs are str-coerced for lookup and devices are found.
        """
        alerts = [{"alertId": "1", "activityUUIDs": [], "deviceIds": [42], "activitiesData": [], "devicesData": []}]
        devices = {"42": {"id": 42, "name": "device-42"}}

        _attach_enrichment(alerts, {}, devices)

        assert len(alerts[0]["devicesData"]) == 1
        assert alerts[0]["devicesData"][0]["id"] == 42

    def test_missing_uuids(self):
        """
        Given:
            - An alert with activityUUIDs that don't exist in the lookup.
        When:
            - Attaching enrichment.
        Then:
            - Missing UUIDs are silently skipped; activitiesData is empty.
        """
        alerts = [
            {"alertId": "1", "activityUUIDs": ["missing-uuid"], "deviceIds": [], "activitiesData": [], "devicesData": []},
        ]

        _attach_enrichment(alerts, {}, {})

        assert alerts[0]["activitiesData"] == []

    def test_none_values_in_uuid_list(self):
        """
        Given:
            - An alert with None values in activityUUIDs.
        When:
            - Attaching enrichment.
        Then:
            - None values are filtered out.
        """
        alerts = [
            {"alertId": "1", "activityUUIDs": [None, "aaa"], "deviceIds": [], "activitiesData": [], "devicesData": []},
        ]
        activities = {"aaa": {"activityUUID": "aaa"}}

        _attach_enrichment(alerts, activities, {})

        assert len(alerts[0]["activitiesData"]) == 1


class TestBulkEnrichAlerts:
    """Tests for bulk_enrich_alerts."""

    def test_empty_alerts(self, mocker, dummy_client):
        """
        Given:
            - An empty alerts list.
        When:
            - Calling bulk_enrich_alerts.
        Then:
            - Returns immediately without making API calls.
        """
        mock_fetch = mocker.patch.object(Client, "fetch_by_ids_in_aql_query")

        bulk_enrich_alerts(dummy_client, [])

        mock_fetch.assert_not_called()

    def test_full_enrichment_flow(self, mocker, dummy_client):
        """
        Given:
            - Two alerts with overlapping activityUUIDs and deviceIds.
        When:
            - Calling bulk_enrich_alerts.
        Then:
            - Bulk AQL queries are made for deduplicated IDs.
            - Each alert is enriched with its own activities and devices.
        """
        alerts = [
            {"alertId": "1", "activityUUIDs": ["uuid-1", "uuid-2"], "deviceIds": [100, 200]},
            {"alertId": "2", "activityUUIDs": ["uuid-2", "uuid-3"], "deviceIds": [200, 300]},
        ]
        activities_api_response = [
            {"activityUUID": "uuid-1", "info": "a1"},
            {"activityUUID": "uuid-2", "info": "a2"},
            {"activityUUID": "uuid-3", "info": "a3"},
        ]
        devices_api_response = [
            {"id": 100, "name": "d100"},
            {"id": 200, "name": "d200"},
            {"id": 300, "name": "d300"},
        ]
        mocker.patch.object(Client, "fetch_by_ids_in_aql_query", side_effect=[activities_api_response, devices_api_response])

        bulk_enrich_alerts(dummy_client, alerts)

        # Alert 1 should have uuid-1, uuid-2 activities and devices 100, 200
        assert len(alerts[0]["activitiesData"]) == 2
        assert len(alerts[0]["devicesData"]) == 2
        # Alert 2 should have uuid-2, uuid-3 activities and devices 200, 300
        assert len(alerts[1]["activitiesData"]) == 2
        assert len(alerts[1]["devicesData"]) == 2
        # Memory optimization (v1.3.0): alerts now share the SAME entity dict for the
        # same UUID — deepcopy was removed to save memory. Verify the shared-reference
        # invariant by asserting object identity.
        uuid2_in_alert1 = [a for a in alerts[0]["activitiesData"] if a["activityUUID"] == "uuid-2"][0]
        uuid2_in_alert2 = [a for a in alerts[1]["activitiesData"] if a["activityUUID"] == "uuid-2"][0]
        assert uuid2_in_alert1 is uuid2_in_alert2


class TestWaitForEnrichment:
    """Tests for _wait_for_enrichment (blocks until enrichment+ship completes)."""

    def test_none_future(self):
        # No enrichment scheduled -> returns immediately.
        _wait_for_enrichment(None, None)

    def test_successful_future(self):
        # A completing future joins cleanly.
        executor = ThreadPoolExecutor(max_workers=1)
        future = executor.submit(lambda: None)
        _wait_for_enrichment(future, executor)

    def test_failed_future(self, mocker):
        # A failing future is logged, not re-raised.
        executor = ThreadPoolExecutor(max_workers=1)
        future = executor.submit(lambda: (_ for _ in ()).throw(RuntimeError("enrichment failed")))
        mock_error = mocker.patch("ArmisEventCollector.demisto.error")

        _wait_for_enrichment(future, executor)

        mock_error.assert_called_once()
        assert "enrichment failed" in mock_error.call_args[0][0]


# Store a reference to the real _is_token_still_fresh before any fixture can patch it.
# Must be module-level to avoid Python's descriptor protocol binding it to the test class.
_real_is_token_still_fresh = Client._is_token_still_fresh


class TestIsTokenStillFresh:
    """Tests for Client._is_token_still_fresh.

    These tests call the real (unpatched) _is_token_still_fresh method using a
    MagicMock as `self` — the method never accesses `self`, only
    `demisto.getIntegrationContext()` which is mocked per-test.
    """

    @freeze_time("2023-06-15T12:00:00")
    def test_fresh_token(self, mocker):
        """
        Given:
            - A token generated 10 minutes ago (well within the 25-minute threshold).
        When:
            - Checking if the token is still fresh.
        Then:
            - Returns True.
        """
        generated_at = (datetime(2023, 6, 15, 11, 50, 0, tzinfo=timezone.utc)).isoformat()
        mocker.patch("ArmisEventCollector.demisto.getIntegrationContext", return_value={"token_generated_at": generated_at})

        result = _real_is_token_still_fresh(MagicMock())

        assert result is True

    @freeze_time("2023-06-15T12:00:00")
    def test_stale_token(self, mocker):
        """
        Given:
            - A token generated 26 minutes ago (past the 25-minute threshold).
        When:
            - Checking if the token is still fresh.
        Then:
            - Returns False.
        """
        generated_at = (datetime(2023, 6, 15, 11, 34, 0, tzinfo=timezone.utc)).isoformat()
        mocker.patch("ArmisEventCollector.demisto.getIntegrationContext", return_value={"token_generated_at": generated_at})

        result = _real_is_token_still_fresh(MagicMock())

        assert result is False

    def test_missing_timestamp(self, mocker):
        """
        Given:
            - No token_generated_at in integration context.
        When:
            - Checking if the token is still fresh.
        Then:
            - Returns False (forces refresh for safety).
        """
        mocker.patch("ArmisEventCollector.demisto.getIntegrationContext", return_value={})

        result = _real_is_token_still_fresh(MagicMock())

        assert result is False

    def test_unparseable_timestamp(self, mocker):
        """
        Given:
            - A malformed token_generated_at value.
        When:
            - Checking if the token is still fresh.
        Then:
            - Returns False (forces refresh for safety).
        """
        mocker.patch("ArmisEventCollector.demisto.getIntegrationContext", return_value={"token_generated_at": "not-a-date"})

        result = _real_is_token_still_fresh(MagicMock())

        assert result is False

    @freeze_time("2023-06-15T12:00:00")
    def test_exactly_at_threshold(self, mocker):
        """
        Given:
            - A token generated exactly 25 minutes ago (at the threshold boundary).
        When:
            - Checking if the token is still fresh.
        Then:
            - Returns False (threshold is exclusive: age < threshold).
        """
        # TOKEN_TTL_SECONDS=1800, TOKEN_REFRESH_BUFFER_SECONDS=300, threshold=1500s=25min
        generated_at = (datetime(2023, 6, 15, 11, 35, 0, tzinfo=timezone.utc)).isoformat()
        mocker.patch("ArmisEventCollector.demisto.getIntegrationContext", return_value={"token_generated_at": generated_at})

        result = _real_is_token_still_fresh(MagicMock())

        assert result is False


# ============================================================================
# Memory-optimization tests (Idea 1: stream-and-flush, Idea 3: no deepcopy,
# Idea 7: free enrichment dicts). See v1.3.0 changelog.
# ============================================================================


class TestStreamPageToXsiam:
    """Tests for the _stream_page_to_xsiam callback factory.

    The factory returns a per-page callback that dedupes, ships to XSIAM, and
    mutates a shared running_state across pages. This is the heart of the
    stream-and-flush memory optimization for Activities/Devices.
    """

    def _running_state(self, last_fetch_ids: list[str] | None = None) -> dict:
        # Mirror the schema initialised inside fetch_by_event_type() — all keys the
        # streaming callback may read or mutate must be present.
        return {
            "last_fetch_ids": list(last_fetch_ids or []),
            "first_event_time": None,
            "last_event_time": None,
            "total_fetched": 0,
            "total_shipped": 0,
            "total_send_secs": 0.0,
            "page_count": 0,
        }

    def test_empty_page_no_send(self, mocker):
        """
        Given: An empty page.
        When: Callback is invoked.
        Then: send_events_to_xsiam is NOT called and running_state is unchanged.
        """
        mock_send = mocker.patch("ArmisEventCollector.send_events_to_xsiam")
        state = self._running_state()
        on_page = _stream_page_to_xsiam(EVENT_TYPES["Activities"], state)

        on_page([])

        mock_send.assert_not_called()
        assert state["total_shipped"] == 0
        assert state["last_event_time"] is None

    def test_first_event_time_recorded_from_first_page_even_when_missing(self, mocker):
        """
        Given: two pages where the first event of the first page has no timestamp.
        When: the callback is invoked for both pages.
        Then: first_event_time stays None (matching the non-streaming path, which uses
              response[0]) and is not overwritten by a later timestamped event.
        """
        mocker.patch("ArmisEventCollector.send_events_to_xsiam")
        state = self._running_state()
        on_page = _stream_page_to_xsiam(EVENT_TYPES["Activities"], state)

        on_page([{"activityUUID": "a"}, {"activityUUID": "b", "time": "2023-01-01T01:00:10.000000+00:00"}])
        on_page([{"activityUUID": "c", "time": "2023-01-01T01:00:20.000000+00:00"}])

        assert state["first_event_time"] is None
        assert state["total_fetched"] == 3

    def test_first_event_time_not_set_by_empty_page(self, mocker):
        """
        Given: an empty page followed by a non-empty page.
        When: the callback is invoked for both pages.
        Then: first_event_time comes from the first non-empty page.
        """
        mocker.patch("ArmisEventCollector.send_events_to_xsiam")
        state = self._running_state()
        on_page = _stream_page_to_xsiam(EVENT_TYPES["Activities"], state)

        on_page([])
        on_page([{"activityUUID": "a", "time": "2023-01-01T01:00:10.000000+00:00"}])

        assert state["first_event_time"] == "2023-01-01T01:00:10.000000+00:00"

    def test_last_event_time_recorded_even_when_missing(self, mocker):
        """
        Given: a timestamped page followed by a page whose last event has no timestamp.
        When: the callback is invoked for both pages.
        Then: last_event_time is overwritten with None rather than keeping the older value,
              so the resume logic does not advance the watermark to a stale second.
        """
        mocker.patch("ArmisEventCollector.send_events_to_xsiam")
        state = self._running_state()
        on_page = _stream_page_to_xsiam(EVENT_TYPES["Activities"], state)

        on_page([{"activityUUID": "a", "time": "2023-01-01T01:00:10.000000+00:00"}])
        assert state["last_event_time"] == "2023-01-01T01:00:10.000000+00:00"

        on_page([{"activityUUID": "b", "time": "2023-01-01T01:00:20.000000+00:00"}, {"activityUUID": "c"}])
        assert state["last_event_time"] is None

    def test_single_page_shipped(self, mocker):
        """
        Given: A page with two new (un-deduped) events.
        When: Callback is invoked.
        Then: send_events_to_xsiam is called once with the deduped events,
              total_shipped is incremented, last_event_time is the latest event's time.
        """
        mock_send = mocker.patch("ArmisEventCollector.send_events_to_xsiam")
        state = self._running_state()
        on_page = _stream_page_to_xsiam(EVENT_TYPES["Activities"], state)

        page = [
            {"activityUUID": "a", "time": "2023-01-01T01:00:10.000000+00:00"},
            {"activityUUID": "b", "time": "2023-01-01T01:00:20.000000+00:00"},
        ]
        on_page(page)

        mock_send.assert_called_once()
        # send_events_to_xsiam(events, vendor=..., product=...) — positional events list.
        sent_events = mock_send.call_args[0]
        assert len(sent_events[0]) == 2
        assert state["total_shipped"] == 2
        assert state["last_event_time"] == "2023-01-01T01:00:20.000000+00:00"

    def test_dedup_propagation_across_pages(self, mocker):
        """
        Given: Two pages, the second page contains a duplicate from the first
               (same ID, same timestamp → dedup-case-2 keeps IDs growing).
        When: Callback is invoked twice (simulating pagination).
        Then: The duplicate is dropped on page 2 and running_state.last_fetch_ids
              carries IDs forward so a third page would also dedup correctly.
        """
        mocker.patch("ArmisEventCollector.send_events_to_xsiam")
        # Start with a seed ID already in last_fetch_ids — simulates dedup case 2 carry-over.
        state = self._running_state(last_fetch_ids=["seed-id"])
        on_page = _stream_page_to_xsiam(EVENT_TYPES["Activities"], state)

        # Page 1: all same timestamp → dedup case 2 appends new IDs to last_fetch_ids.
        on_page(
            [
                {"activityUUID": "a", "time": "2023-01-01T01:00:10.000000+00:00"},
                {"activityUUID": "b", "time": "2023-01-01T01:00:10.000000+00:00"},
            ]
        )
        assert state["total_shipped"] == 2
        assert "a" in state["last_fetch_ids"]
        assert "b" in state["last_fetch_ids"]
        assert "seed-id" in state["last_fetch_ids"]  # carried over

        # Page 2: contains a (duplicate) and c (new), same timestamp again.
        on_page(
            [
                {"activityUUID": "a", "time": "2023-01-01T01:00:10.000000+00:00"},
                {"activityUUID": "c", "time": "2023-01-01T01:00:10.000000+00:00"},
            ]
        )
        # Only "c" is new on page 2.
        assert state["total_shipped"] == 3
        assert "c" in state["last_fetch_ids"]

    def test_alerts_product_routing(self, mocker):
        """
        Given: The Alerts event type (whose product is PRODUCT, not PRODUCT_alerts).
        When: Callback ships a page.
        Then: send_events_to_xsiam is called with product == PRODUCT.
        """
        from ArmisEventCollector import PRODUCT

        mock_send = mocker.patch("ArmisEventCollector.send_events_to_xsiam")
        state = self._running_state()
        on_page = _stream_page_to_xsiam(EVENT_TYPES["Alerts"], state)

        on_page([{"alertId": "1", "time": "2023-01-01T01:00:10.000000+00:00"}])

        assert mock_send.call_args.kwargs["product"] == PRODUCT

    def test_devices_product_routing(self, mocker):
        """
        Given: The Devices event type (whose product is PRODUCT_devices).
        When: Callback ships a page.
        Then: send_events_to_xsiam is called with product == "<PRODUCT>_devices".
        """
        from ArmisEventCollector import PRODUCT

        mock_send = mocker.patch("ArmisEventCollector.send_events_to_xsiam")
        state = self._running_state()
        on_page = _stream_page_to_xsiam(EVENT_TYPES["Devices"], state)

        on_page([{"id": "1", "lastSeen": "2023-01-01T01:00:10.000000+00:00"}])

        assert mock_send.call_args.kwargs["product"] == f"{PRODUCT}_devices"

    def test_activities_product_routing(self, mocker):
        """
        Given: The Activities event type (whose ``type`` is singular "activity" but whose
            ``dataset_name`` is plural "activities").
        When: Callback ships a page.
        Then: send_events_to_xsiam is called with product == "<PRODUCT>_activities"
            (plural), so events land in ``armis_security_activities_raw``.
        """
        from ArmisEventCollector import PRODUCT

        mock_send = mocker.patch("ArmisEventCollector.send_events_to_xsiam")
        state = self._running_state()
        on_page = _stream_page_to_xsiam(EVENT_TYPES["Activities"], state)

        on_page([{"activityUUID": "1", "time": "2023-01-01T01:00:10.000000+00:00"}])

        assert mock_send.call_args.kwargs["product"] == f"{PRODUCT}_activities"


class TestFetchByAqlQueryWithCallback:
    """Tests for fetch_by_aql_query in streaming mode (on_page provided)."""

    def test_streaming_returns_empty_results(self, mocker, dummy_client):
        """
        Given: A single-page API response and an on_page callback.
        When: fetch_by_aql_query is called with on_page.
        Then: The returned results list is empty (events streamed via callback,
              not accumulated). The cursor is still returned correctly.
        """
        page = [{"unique_id": "1", "time": "2023-01-01T01:00:10.123456+00:00"}]
        mocker.patch.object(Client, "_http_request", return_value={"data": {"results": page, "next": 0}})
        captured: list[list[dict]] = []

        def on_page(p):
            captured.append(p)

        results, next_cursor = dummy_client.fetch_by_aql_query(
            aql_query="in:activity",
            max_fetch=100,
            after=arg_to_datetime("2023-01-01T01:00:00"),
            on_page=on_page,
        )

        assert results == []  # streaming mode never accumulates
        assert next_cursor == 0
        assert len(captured) == 1
        assert captured[0] == page

    def test_streaming_paginates_and_invokes_callback_per_page(self, mocker, dummy_client):
        """
        Given: A multi-page API response (3 pages) and an on_page callback.
        When: fetch_by_aql_query is called with on_page.
        Then: The callback is invoked exactly 3 times (once per page) and the
              returned results list is empty.
        """
        page1 = [{"unique_id": "1", "time": "2023-01-01T01:00:10.123456+00:00"}]
        page2 = [{"unique_id": "2", "time": "2023-01-01T01:00:20.123456+00:00"}]
        page3 = [{"unique_id": "3", "time": "2023-01-01T01:00:30.123456+00:00"}]
        mocker.patch.object(
            Client,
            "_http_request",
            side_effect=[
                {"data": {"results": page1, "next": 1}},
                {"data": {"results": page2, "next": 2}},
                {"data": {"results": page3, "next": 0}},
            ],
        )
        captured: list[list[dict]] = []

        results, next_cursor = dummy_client.fetch_by_aql_query(
            aql_query="in:activity",
            max_fetch=100,
            after=arg_to_datetime("2023-01-01T01:00:00"),
            on_page=lambda p: captured.append(p),
        )

        assert results == []
        assert next_cursor == 0
        assert len(captured) == 3
        assert captured[0] == page1
        assert captured[1] == page2
        assert captured[2] == page3

    def test_legacy_mode_unaffected(self, mocker, dummy_client):
        """
        Given: A single-page API response and NO on_page callback (legacy mode).
        When: fetch_by_aql_query is called without on_page.
        Then: Results are accumulated and returned (back-compat with Alerts and
              bulk-enrichment fetches).
        """
        page = [{"unique_id": "1", "time": "2023-01-01T01:00:10.123456+00:00"}]
        mocker.patch.object(Client, "_http_request", return_value={"data": {"results": page, "next": 0}})

        results, next_cursor = dummy_client.fetch_by_aql_query(
            aql_query="in:activity",
            max_fetch=100,
            after=arg_to_datetime("2023-01-01T01:00:00"),
        )

        assert results == page
        assert next_cursor == 0


class TestFetchByEventTypeStreamMode:
    """Tests for fetch_by_event_type with stream=True."""

    def test_stream_mode_does_not_populate_events_dict(self, mocker, dummy_client):
        """
        Given: A response with two events and stream=True.
        When: fetch_by_event_type is called.
        Then: send_events_to_xsiam is invoked (events streamed), and the
              ``events`` dict is NOT populated for this dataset.
        """
        mock_send = mocker.patch("ArmisEventCollector.send_events_to_xsiam")
        response = [
            {"activityUUID": "a", "time": "2023-01-01T01:00:10.000000+00:00"},
            {"activityUUID": "b", "time": "2023-01-01T01:00:20.000000+00:00"},
        ]
        mocker.patch.object(Client, "fetch_by_aql_query", side_effect=_streaming_fetch_stub(response))

        events: dict = {}
        next_run: dict = {}
        fetch_by_event_type(
            client=dummy_client,
            event_type=EVENT_TYPES["Activities"],
            events=events,
            max_fetch=100,
            last_run={},
            next_run=next_run,
            fetch_start_time=arg_to_datetime("2023-01-01T01:00:00"),
            stream=True,
        )

        mock_send.assert_called_once()
        # The events dict for the streamed dataset must remain empty.
        assert events.get("activities", []) == []

    def test_stream_mode_updates_next_run(self, mocker, dummy_client):
        """
        Given: A streaming fetch with events spanning two distinct seconds.
        When: fetch_by_event_type is called with stream=True.
        Then: next_run captures last_fetch_ids, advances last_fetch_time to the latest
              seen second, and resets the offset to 0 (matches the non-streaming path).
        """
        mocker.patch("ArmisEventCollector.send_events_to_xsiam")
        response = [
            {"activityUUID": "a", "time": "2023-01-01T01:00:10.000000+00:00"},
            {"activityUUID": "b", "time": "2023-01-01T01:00:20.000000+00:00"},
        ]
        mocker.patch.object(Client, "fetch_by_aql_query", side_effect=_streaming_fetch_stub(response))

        events: dict = {}
        next_run: dict = {}
        fetch_by_event_type(
            client=dummy_client,
            event_type=EVENT_TYPES["Activities"],
            events=events,
            max_fetch=100,
            last_run={},
            next_run=next_run,
            fetch_start_time=arg_to_datetime("2023-01-01T01:00:00"),
            stream=True,
        )

        # Multi-second response -> advance to the latest second and reset the offset.
        assert next_run["activity_last_fetch_next_field"] == 0
        assert next_run["activity_last_fetch_time"] == "2023-01-01T01:00:20"


def _drained_armis_stub(armis_events: list[dict]):
    """Helper: emulate the Armis search API over a mutable, time-ordered event store.

    Returns every event whose second is at or after the ``after`` watermark (the
    ``after:`` AQL filter is second-granular), starting at the ``from`` offset, and
    always reports ``next=0`` — i.e. the query is fully drained in a single call.
    Honours ``on_page`` so it works for both the streaming and non-streaming paths.
    """

    def _stub(*args, **kwargs):
        after_second = kwargs["after"].strftime("%Y-%m-%dT%H:%M:%S")
        matching = [event for event in armis_events if event["time"][:19] >= after_second]
        page = matching[kwargs.get("from_param") or 0 :]
        on_page = kwargs.get("on_page")
        if on_page is not None:
            on_page(page)
            return [], 0
        return page, 0

    return _stub


class TestResumeAfterDrainWithNewEventsInSameSecond:
    """A cycle that fully drains (next == 0) persists the resume offset; when new events
    later arrive in that same second, the next cycle must ship exactly those new events —
    no duplicates of the already-shipped events and no gaps."""

    @staticmethod
    def _run_cycle(mocker, client, last_run: dict, stream: bool) -> tuple[dict, list[str]]:
        mock_send = mocker.patch("ArmisEventCollector.send_events_to_xsiam")
        events: dict = {}
        next_run: dict = {}
        fetch_by_event_type(
            client=client,
            event_type=EVENT_TYPES["Activities"],
            events=events,
            max_fetch=100,
            last_run=last_run,
            next_run=next_run,
            fetch_start_time=arg_to_datetime("2023-01-01T01:00:00"),
            stream=stream,
        )
        if stream:
            shipped = [event for call in mock_send.call_args_list for event in call.args[0]]
        else:
            shipped = events.get("activities", [])
        return next_run, [event["activityUUID"] for event in shipped]

    @pytest.mark.parametrize("stream", [True, False], ids=["streaming", "non_streaming"])
    @pytest.mark.parametrize(
        "initial_events, expected_watermark_after_drain, expected_offset_after_drain",
        [
            pytest.param(
                [
                    {"activityUUID": "a", "time": "2023-01-01T01:00:16.100000+00:00"},
                    {"activityUUID": "b", "time": "2023-01-01T01:00:17.100000+00:00"},
                    {"activityUUID": "c", "time": "2023-01-01T01:00:17.200000+00:00"},
                ],
                "2023-01-01T01:00:17",
                0,
                id="multi_second_drain",
            ),
            pytest.param(
                [
                    {"activityUUID": "a", "time": "2023-01-01T01:00:17.100000+00:00"},
                    {"activityUUID": "b", "time": "2023-01-01T01:00:17.200000+00:00"},
                    {"activityUUID": "c", "time": "2023-01-01T01:00:17.300000+00:00"},
                ],
                "2023-01-01T01:00:16",
                3,
                id="single_second_drain",
            ),
        ],
    )
    @freeze_time("2023-01-01T02:00:00")
    def test_new_events_in_same_second_after_drain(
        self,
        mocker,
        dummy_client,
        stream,
        initial_events,
        expected_watermark_after_drain,
        expected_offset_after_drain,
    ):
        """
        Given: cycle 1 resumes from watermark 01:00:16 and drains all available events
               (Armis returns next=0) whose latest second is 01:00:17, so the watermark
               and offset are persisted (advanced + offset 0 for a multi-second response,
               kept + offset stepped for a single-second response).
        When:  new events then arrive in that same second (01:00:17) and cycle 2 runs
               from the persisted next_run.
        Then:  cycle 2 ships exactly the new events — none of cycle 1's events are
               re-shipped and none of the new events are skipped.
        """
        armis_events = list(initial_events)
        mocker.patch.object(Client, "fetch_by_aql_query", side_effect=_drained_armis_stub(armis_events))
        initial_last_run = {"activity_last_fetch_time": "2023-01-01T01:00:16", "activity_last_fetch_next_field": 0}

        # Cycle 1: drain everything currently available.
        next_run, shipped_cycle_1 = self._run_cycle(mocker, dummy_client, initial_last_run, stream)
        assert shipped_cycle_1 == ["a", "b", "c"]
        assert next_run["activity_last_fetch_time"] == expected_watermark_after_drain
        assert next_run["activity_last_fetch_next_field"] == expected_offset_after_drain

        # New events land in the same (already drained) second.
        armis_events.extend(
            [
                {"activityUUID": "d", "time": "2023-01-01T01:00:17.400000+00:00"},
                {"activityUUID": "e", "time": "2023-01-01T01:00:17.500000+00:00"},
            ]
        )

        # Cycle 2: resume from the persisted state.
        _, shipped_cycle_2 = self._run_cycle(mocker, dummy_client, next_run, stream)
        assert shipped_cycle_2 == ["d", "e"]


def _streaming_fetch_stub(response: list[dict], next_cursor: int = 0):
    """Helper: build a fetch_by_aql_query side_effect that honours the on_page kwarg.

    When ``on_page`` is provided, invoke it with the response and return ([], next_cursor)
    to simulate streaming mode. Otherwise return (response, next_cursor).
    """

    def _stub(*args, **kwargs):
        on_page = kwargs.get("on_page")
        if on_page is not None:
            on_page(response)
            return [], next_cursor
        return response, next_cursor

    return _stub


class TestHandleFetchedEventsAfterStreaming:
    """Tests for handle_fetched_events when Activities/Devices were already streamed."""

    def test_alerts_only_after_streaming(self, mocker):
        """
        Given: An events dict containing only Alerts (Activities/Devices already streamed
               and therefore absent from the dict).
        When: handle_fetched_events is called.
        Then: Only Alerts are shipped via send_events_to_xsiam; no spurious empty calls
              for missing event types.
        """
        mock_send = mocker.patch("ArmisEventCollector.send_events_to_xsiam")
        mocker.patch("ArmisEventCollector.demisto.setLastRun")

        events = {"alerts": [{"alertId": "1", "time": "2023-01-01T01:00:10.000000+00:00"}]}
        handle_fetched_events(events, {})

        assert mock_send.call_count == 1
        assert mock_send.call_args.kwargs["product"] == "security"  # PRODUCT for alerts

    def test_empty_events_dict_sends_heartbeat(self, mocker):
        """
        Given: An empty events dict (e.g., all event types streamed, no Alerts in cycle).
        When: handle_fetched_events is called.
        Then: A single empty heartbeat is sent so XSIAM knows the collector is alive.
        """
        mock_send = mocker.patch("ArmisEventCollector.send_events_to_xsiam")
        mocker.patch("ArmisEventCollector.demisto.setLastRun")

        handle_fetched_events({}, {})

        mock_send.assert_called_once_with([], vendor="armis", product="security")

    def test_skips_empty_event_lists(self, mocker):
        """
        Given: An events dict with one populated type and one empty type
               (the empty type represents a streamed dataset that didn't accumulate).
        When: handle_fetched_events is called.
        Then: Only the populated type is shipped (the empty list is skipped).
        """
        mock_send = mocker.patch("ArmisEventCollector.send_events_to_xsiam")
        mocker.patch("ArmisEventCollector.demisto.setLastRun")

        events = {
            "alerts": [{"alertId": "1", "time": "2023-01-01T01:00:10.000000+00:00"}],
            "activities": [],  # streamed; empty placeholder
        }
        handle_fetched_events(events, {})

        assert mock_send.call_count == 1
        assert mock_send.call_args.kwargs["product"] == "security"


# ============================================================================
# v1.3.1 — Chunked alert enrichment tests.
# _enrich_and_ship_in_chunks slices alerts into batches of ALERT_ENRICHMENT_CHUNK_SIZE,
# enriches each batch via the existing bulk_enrich_alerts, ships it to XSIAM, then frees
# the batch's memory before the next batch starts.
# ============================================================================


class TestEnrichAndShipInChunks:
    """Tests for _enrich_and_ship_in_chunks (v1.3.1 memory-bound enrichment)."""

    def test_single_chunk_when_below_chunk_size(self, mocker, dummy_client):
        """
        Given: An alert list smaller than the chunk size.
        When: _enrich_and_ship_in_chunks is invoked.
        Then: One enrichment + one ship call, all alerts shipped.
        """
        mock_enrich = mocker.patch("ArmisEventCollector.bulk_enrich_alerts")
        mock_send = mocker.patch("ArmisEventCollector.send_events_to_xsiam")
        alerts = [{"alertId": str(i), "time": "2023-01-01T01:00:10.000000+00:00"} for i in range(3)]

        _enrich_and_ship_in_chunks(dummy_client, alerts, chunk_size=10)

        assert mock_enrich.call_count == 1
        assert mock_send.call_count == 1
        assert len(mock_send.call_args[0][0]) == 3

    def test_multiple_chunks_with_custom_size(self, mocker, dummy_client):
        """
        Given: 5 alerts with chunk_size=2.
        When: _enrich_and_ship_in_chunks is invoked.
        Then: 3 chunks of sizes [2, 2, 1] are enriched and shipped in order.
        """
        mock_enrich = mocker.patch("ArmisEventCollector.bulk_enrich_alerts")
        mock_send = mocker.patch("ArmisEventCollector.send_events_to_xsiam")
        alerts = [{"alertId": str(i), "time": "2023-01-01T01:00:10.000000+00:00"} for i in range(5)]

        _enrich_and_ship_in_chunks(dummy_client, alerts, chunk_size=2)

        assert mock_enrich.call_count == 3
        assert mock_send.call_count == 3
        assert [len(c.args[0]) for c in mock_send.call_args_list] == [2, 2, 1]

    def test_alerts_shipped_with_time_field_and_correct_product(self, mocker, dummy_client):
        """
        Given: Raw alerts without _time field.
        When: _enrich_and_ship_in_chunks ships them.
        Then: _time is populated from `time`, and product=PRODUCT (no suffix for alerts).
        """
        from ArmisEventCollector import PRODUCT

        mocker.patch("ArmisEventCollector.bulk_enrich_alerts")
        mock_send = mocker.patch("ArmisEventCollector.send_events_to_xsiam")
        alerts = [{"alertId": "1", "time": "2023-01-01T01:00:10.000000+00:00"}]

        _enrich_and_ship_in_chunks(dummy_client, alerts, chunk_size=10)

        shipped = mock_send.call_args[0][0]
        assert shipped[0]["_time"] == "2023-01-01T01:00:10.000000+00:00"
        assert mock_send.call_args.kwargs["product"] == PRODUCT
        assert mock_send.call_args.kwargs["vendor"] == "armis"

    def test_uses_default_chunk_size_when_omitted(self, mocker, dummy_client):
        """
        Given: Alerts list larger than ALERT_ENRICHMENT_CHUNK_SIZE, no chunk_size override.
        When: _enrich_and_ship_in_chunks is invoked.
        Then: The default constant is used to split the input.
        """
        mocker.patch("ArmisEventCollector.bulk_enrich_alerts")
        mock_send = mocker.patch("ArmisEventCollector.send_events_to_xsiam")
        total = ALERT_ENRICHMENT_CHUNK_SIZE + 5
        alerts = [{"alertId": str(i), "time": "2023-01-01T01:00:10.000000+00:00"} for i in range(total)]

        _enrich_and_ship_in_chunks(dummy_client, alerts)

        assert mock_send.call_count == 2  # first full chunk + remainder
        assert [len(c.args[0]) for c in mock_send.call_args_list] == [ALERT_ENRICHMENT_CHUNK_SIZE, 5]


class TestComputePaginationBudget:
    """Tests for compute_pagination_budget (v1.3.6 dynamic budget-aware pagination cap).

    The cap is derived from the shared ~300s container budget:
        usable = PAGINATION_BUDGET_SECONDS - alerts_elapsed_seconds - (reserve if alerts_present)
        per_type = int(usable // paginating_types)
        result = clamp(per_type, MIN_PAGINATION_DURATION_SECONDS, MAX_PAGINATION_DURATION_SECONDS)
    """

    def test_single_type_no_alerts_clamps_to_max(self):
        """
        Given: One paginating type, no alerts fetched this cycle.
        When: Computing the budget.
        Then: usable=270 // 1 = 270, clamped down to MAX (180). This is the customer's case
              (Alerts=0, Devices skipped -> Activities only).
        """
        assert compute_pagination_budget(paginating_types=1) == MAX_PAGINATION_DURATION_SECONDS

    def test_two_types_no_alerts_splits_budget(self):
        """
        Given: Two paginating types, no alerts.
        When: Computing the budget.
        Then: 270 // 2 = 135, within [90, 180] -> 135 each.
        """
        assert compute_pagination_budget(paginating_types=2) == 135

    def test_three_types_no_alerts_clamps_to_floor(self):
        """
        Given: Three paginating types, no alerts.
        When: Computing the budget.
        Then: 270 // 3 = 90 -> exactly the floor.
        """
        assert compute_pagination_budget(paginating_types=3) == MIN_PAGINATION_DURATION_SECONDS

    def test_many_types_never_drops_below_floor(self):
        """
        Given: More types than the budget can evenly fund (e.g. 5).
        When: Computing the budget.
        Then: 270 // 5 = 54, clamped UP to the floor (90) to preserve the proven behavior.
        """
        assert compute_pagination_budget(paginating_types=5) == MIN_PAGINATION_DURATION_SECONDS

    def test_zero_types_returns_floor(self):
        """
        Given: No paginating types (defensive guard).
        When: Computing the budget.
        Then: The floor is returned without a division-by-zero.
        """
        assert compute_pagination_budget(paginating_types=0) == MIN_PAGINATION_DURATION_SECONDS

    def test_negative_types_returns_floor(self):
        """
        Given: A negative count (defensive guard).
        When: Computing the budget.
        Then: The floor is returned.
        """
        assert compute_pagination_budget(paginating_types=-1) == MIN_PAGINATION_DURATION_SECONDS

    def test_alerts_present_subtracts_reserve_and_elapsed(self):
        """
        Given: One paginating type, alerts present, 30s spent fetching alerts.
        When: Computing the budget.
        Then: usable = 270 - 30 - 60(reserve) = 180 // 1 = 180 -> clamped at MAX (180).
        """
        assert (
            compute_pagination_budget(paginating_types=1, alerts_elapsed_seconds=30.0, alerts_present=True)
            == MAX_PAGINATION_DURATION_SECONDS
        )

    def test_alerts_present_reserve_pushes_two_types_below_floor(self):
        """
        Given: Two paginating types, alerts present, 60s spent on alerts.
        When: Computing the budget.
        Then: usable = 270 - 60 - 60 = 150 // 2 = 75, clamped UP to the floor (90).
        """
        assert (
            compute_pagination_budget(paginating_types=2, alerts_elapsed_seconds=60.0, alerts_present=True)
            == MIN_PAGINATION_DURATION_SECONDS
        )

    def test_reserve_not_applied_when_alerts_absent(self):
        """
        Given: One type, alerts_elapsed is non-zero but alerts_present is False
               (e.g. Alerts queried but returned nothing).
        When: Computing the budget.
        Then: Only elapsed is subtracted, NOT the reserve: usable = 270 - 20 = 250 // 1 = 250 -> MAX.
        """
        assert (
            compute_pagination_budget(paginating_types=1, alerts_elapsed_seconds=20.0, alerts_present=False)
            == MAX_PAGINATION_DURATION_SECONDS
        )

    def test_large_alerts_elapsed_floors_result(self):
        """
        Given: One type but alerts consumed almost the whole window (250s) plus reserve.
        When: Computing the budget.
        Then: usable = 270 - 250 - 60 = -40 // 1 = -40, clamped UP to the floor (90).
        """
        assert (
            compute_pagination_budget(paginating_types=1, alerts_elapsed_seconds=250.0, alerts_present=True)
            == MIN_PAGINATION_DURATION_SECONDS
        )

    def test_result_is_always_an_int(self):
        """
        Given: A fractional alerts_elapsed_seconds.
        When: Computing the budget.
        Then: The returned cap is an int (floor division), never a float.
        """
        result = compute_pagination_budget(paginating_types=2, alerts_elapsed_seconds=10.5, alerts_present=False)
        assert isinstance(result, int)

    @pytest.mark.parametrize(
        "paginating_types, alerts_elapsed, alerts_present, expected",
        [
            (1, 0.0, False, 180),  # customer case -> MAX
            (2, 0.0, False, 135),  # even split, in range
            (3, 0.0, False, 90),  # even split hits the floor
            (4, 0.0, False, 90),  # below floor -> clamped up
            (1, 90.0, True, 120),  # 270-90-60=120 // 1
            (2, 30.0, True, 90),  # (270-30-60)//2 = 90
        ],
    )
    def test_parametrized_matrix(self, paginating_types, alerts_elapsed, alerts_present, expected):
        assert (
            compute_pagination_budget(
                paginating_types=paginating_types,
                alerts_elapsed_seconds=alerts_elapsed,
                alerts_present=alerts_present,
            )
            == expected
        )

    def test_result_never_exceeds_max_or_below_min(self):
        """Invariant sweep: for a wide range of inputs the result stays within [MIN, MAX]."""
        for n in range(1, 10):
            for elapsed in (0.0, 15.0, 60.0, 200.0):
                for present in (True, False):
                    result = compute_pagination_budget(n, elapsed, present)
                    assert MIN_PAGINATION_DURATION_SECONDS <= result <= MAX_PAGINATION_DURATION_SECONDS


# ---------------------------------------------------------------------------
# Resume-window decision (_next_fetch_window / compute_resume_state)
# ---------------------------------------------------------------------------

T15 = "2026-10-06T08:33:15"
T16 = "2026-10-06T08:33:16"
T17 = "2026-10-06T08:33:17"


class TestNextFetchWindow:
    """All branches of _next_fetch_window: empty / multi-second / single-second / missing timestamps."""

    @pytest.mark.parametrize(
        "earliest_second, latest_second, count, last_fetch_time, last_fetch_next, expected",
        [
            pytest.param("", "", 0, T16, 0, (T16, 0), id="empty_steady_state"),
            pytest.param("", "", 0, T16, 30000, (T16, 30000), id="empty_keeps_deep_offset"),
            pytest.param("", "", 0, None, 0, (None, 0), id="empty_first_run"),
            pytest.param(T16, T17, 10, T15, 500, (T17, 0), id="multi_second_advances_and_resets_offset"),
            pytest.param(T16, T16, 10000, T16, 20000, (T16, 30000), id="single_second_steps_offset"),
            pytest.param(T16, T16, 1, T15, 0, (T15, 1), id="single_event_steps_offset"),
            pytest.param(T16, "", 5, T15, 0, (T15, 5), id="missing_latest_never_advances"),
            pytest.param("", T17, 5, T15, 0, (T15, 5), id="missing_earliest_does_not_advance"),
            pytest.param("", "", 5, T15, 10, (T15, 15), id="both_missing_steps_offset"),
        ],
    )
    def test_next_fetch_window(self, earliest_second, latest_second, count, last_fetch_time, last_fetch_next, expected):
        assert _next_fetch_window(earliest_second, latest_second, count, last_fetch_time, last_fetch_next) == expected


class TestComputeResumeStateTimestampFormats:
    """compute_resume_state compares timestamps at second granularity regardless of their format."""

    def test_mixed_formats_in_same_second_are_single_second(self):
        """
        Given: events in the same second but with different timestamp formats (micros+offset, 'Z', bare).
        When:  compute_resume_state runs.
        Then:  they truncate to the same second -> treated as a single-second response (offset steps).
        """
        response = [
            {"time": f"{T16}.123456+00:00"},
            {"time": f"{T16}Z"},
            {"time": T16},
        ]
        assert compute_resume_state(response, T16, 0, "time") == (T16, 3)

    def test_mixed_formats_across_seconds_advance(self):
        """
        Given: first and last events in different seconds, each in a different timestamp format.
        When:  compute_resume_state runs.
        Then:  the watermark advances to the latest second (truncated) and the offset resets.
        """
        response = [{"time": T16}, {"time": f"{T17}.500000Z"}]
        assert compute_resume_state(response, T15, 42, "time") == (T17, 0)


# ---------------------------------------------------------------------------
# Multi-cycle behaviour against a fake Armis search API
# ---------------------------------------------------------------------------


class FakeArmisSearchApi:
    """In-memory stand-in for ``GET /api/v1/search/``.

    Results are ascending by ``order_by``; ``after:`` is inclusive and second-granular;
    paging uses ``from`` (offset) + ``length``; ``next`` is the following offset, or None
    once the query is drained. ``blackout`` simulates a transient empty response.
    """

    def __init__(self, order_by: str = "time"):
        self.events: list[dict] = []
        self.order_by = order_by
        self.blackout = False

    def perform_fetch(self, params: dict) -> dict:
        if self.blackout:
            return {"data": {"results": [], "next": None}}
        after_match = re.search(r"after:(\S+)", params["aql"])
        assert after_match, f"aql has no after: clause: {params['aql']}"
        after_second = after_match.group(1)[:19]
        matching = sorted(
            (event for event in self.events if event[self.order_by][:19] >= after_second),
            key=lambda event: event[self.order_by],
        )
        offset = params.get("from") or 0
        page = matching[offset : offset + params["length"]]
        end = offset + len(page)
        return {"data": {"results": [dict(event) for event in page], "next": end if end < len(matching) else None}}


def _run_one_cycle(client, event_type_name: str, last_run: dict, stream: bool, max_fetch: int, send_mock) -> tuple[dict, list]:
    """Run one fetch_by_event_type cycle; return (next_run, ids shipped in this cycle)."""
    event_type = EVENT_TYPES[event_type_name]
    calls_before = len(send_mock.call_args_list)
    events: dict = {}
    next_run: dict = {}
    fetch_by_event_type(client, event_type, events, max_fetch, last_run, next_run, None, stream=stream)
    if stream:
        shipped = [event for call in send_mock.call_args_list[calls_before:] for event in call.args[0]]
    else:
        shipped = events.get(event_type.dataset_name, [])
    return next_run, [event[event_type.unique_id_key] for event in shipped]


def _activity(uuid: str, time_str: str) -> dict:
    return {"activityUUID": uuid, "time": time_str}


ACT_TIME = "activity_last_fetch_time"
ACT_NEXT = "activity_last_fetch_next_field"
ACT_IDS = "activity_last_fetch_ids"


@pytest.fixture
def fake_armis_api(mocker) -> Iterator[FakeArmisSearchApi]:
    """Patch Client.perform_fetch with an in-memory FakeArmisSearchApi and freeze time."""
    fake_api = FakeArmisSearchApi()
    mocker.patch.object(Client, "perform_fetch", side_effect=fake_api.perform_fetch)
    with freeze_time("2023-01-01T02:00:00"):
        yield fake_api


class TestMultiCycleResume:
    """End-to-end resume behaviour across several fetch cycles (each id shipped exactly once)."""

    def test_quiet_alerts_each_shipped_once(self, mocker, dummy_client, fake_armis_api):
        """
        Given: a quiet Alerts stream — one new alert appears per cycle, each in its own second.
        When:  three cycles run, each resuming from the previous next_run.
        Then:  every alert is shipped exactly once, in its own cycle.
        """
        send_mock = mocker.patch("ArmisEventCollector.send_events_to_xsiam")
        last_run: dict = {"alerts_last_fetch_time": "2023-01-01T01:00:10", "alerts_last_fetch_next_field": 0}
        shipped_per_cycle = []
        for second in (11, 12, 13):
            fake_armis_api.events.append({"alertId": f"alert-{second}", "time": f"2023-01-01T01:00:{second}.000000+00:00"})
            last_run, shipped = _run_one_cycle(dummy_client, "Alerts", last_run, False, 100, send_mock)
            shipped_per_cycle.append(shipped)

        assert shipped_per_cycle == [["alert-11"], ["alert-12"], ["alert-13"]]

    @pytest.mark.parametrize("stream", [True, False], ids=["streaming", "non_streaming"])
    def test_hot_second_larger_than_page_then_later_second(self, mocker, dummy_client, fake_armis_api, stream):
        """
        Given: one second holding more events than a cycle can read (7 events, max_fetch=3),
               followed by an event in the next second.
        When:  cycles run until the watermark moves past the hot second, plus one extra cycle.
        Then:  the offset steps within the hot second (3 -> 6), then resets to 0 when the later
               second appears; every id is shipped exactly once (the re-read is deduped).
        """
        send_mock = mocker.patch("ArmisEventCollector.send_events_to_xsiam")
        fake_armis_api.events = [
            _activity(uuid, f"2023-01-01T01:00:16.{index:06d}+00:00") for index, uuid in enumerate("ABCDEFG")
        ]
        fake_armis_api.events.append(_activity("H", "2023-01-01T01:00:17.000000+00:00"))
        last_run: dict = {ACT_TIME: "2023-01-01T01:00:16", ACT_NEXT: 0}

        all_shipped: list = []
        observed_state = []
        for _ in range(4):
            last_run, shipped = _run_one_cycle(dummy_client, "Activities", last_run, stream, 3, send_mock)
            all_shipped.extend(shipped)
            observed_state.append((last_run[ACT_TIME], last_run[ACT_NEXT]))

        assert observed_state[:3] == [
            ("2023-01-01T01:00:16", 3),
            ("2023-01-01T01:00:16", 6),
            ("2023-01-01T01:00:17", 0),
        ]
        assert sorted(all_shipped) == list("ABCDEFGH")
        assert len(all_shipped) == len(set(all_shipped))

    @pytest.mark.parametrize("stream", [True, False], ids=["streaming", "non_streaming"])
    def test_empty_cycles_between_events_and_during_hot_second(self, mocker, dummy_client, fake_armis_api, stream):
        """
        Given: an empty store at first, then a hot second (5 events, max_fetch=2) plus a later event,
               with a transient empty response in the middle of stepping through the hot second.
        When:  cycles run across the empty periods.
        Then:  empty cycles leave the watermark and offset unchanged (and, when streaming, the dedup
               ids), and every id is shipped exactly once — nothing skipped, nothing duplicated.
        """
        send_mock = mocker.patch("ArmisEventCollector.send_events_to_xsiam")
        initial_last_run: dict = {ACT_TIME: "2023-01-01T01:00:15", ACT_NEXT: 0, ACT_IDS: ["seed"]}

        # Empty period before any events exist.
        next_run, shipped = _run_one_cycle(dummy_client, "Activities", dict(initial_last_run), stream, 2, send_mock)
        assert shipped == []
        assert (next_run[ACT_TIME], next_run[ACT_NEXT]) == ("2023-01-01T01:00:15", 0)
        if stream:
            assert next_run[ACT_IDS] == ["seed"]

        fake_armis_api.events = [_activity(uuid, f"2023-01-01T01:00:16.{index:06d}+00:00") for index, uuid in enumerate("ABCDE")]
        fake_armis_api.events.append(_activity("F", "2023-01-01T01:00:17.000000+00:00"))
        all_shipped: list = []

        last_run, shipped = _run_one_cycle(dummy_client, "Activities", next_run, stream, 2, send_mock)
        all_shipped.extend(shipped)

        # Transient empty response while stepping through the hot second.
        fake_armis_api.blackout = True
        state_before_blackout = dict(last_run)
        last_run, shipped = _run_one_cycle(dummy_client, "Activities", last_run, stream, 2, send_mock)
        fake_armis_api.blackout = False
        assert shipped == []
        assert (last_run[ACT_TIME], last_run[ACT_NEXT]) == (state_before_blackout[ACT_TIME], state_before_blackout[ACT_NEXT])
        if stream:
            assert last_run[ACT_IDS] == state_before_blackout[ACT_IDS]

        for _ in range(3):
            last_run, shipped = _run_one_cycle(dummy_client, "Activities", last_run, stream, 2, send_mock)
            all_shipped.extend(shipped)

        assert sorted(all_shipped) == list("ABCDEF")
        assert len(all_shipped) == len(set(all_shipped))

    @pytest.mark.parametrize("stream", [True, False], ids=["streaming", "non_streaming"])
    def test_reanchor_reread_ships_no_duplicates(self, mocker, dummy_client, fake_armis_api, stream):
        """
        Given: cycle 1 reads a multi-second response, so the watermark re-anchors to the latest
               second (offset 0) and the next cycle re-reads that second.
        When:  new events arrive and cycle 2 runs.
        Then:  the re-read events of the latest second are deduped; only the new events ship.
        """
        send_mock = mocker.patch("ArmisEventCollector.send_events_to_xsiam")
        fake_armis_api.events = [
            _activity("a", "2023-01-01T01:00:16.500000+00:00"),
            _activity("b", "2023-01-01T01:00:17.100000+00:00"),
            _activity("c", "2023-01-01T01:00:17.200000+00:00"),
        ]
        last_run: dict = {ACT_TIME: "2023-01-01T01:00:16", ACT_NEXT: 0}

        last_run, shipped_cycle_1 = _run_one_cycle(dummy_client, "Activities", last_run, stream, 10, send_mock)
        assert shipped_cycle_1 == ["a", "b", "c"]
        assert (last_run[ACT_TIME], last_run[ACT_NEXT]) == ("2023-01-01T01:00:17", 0)

        fake_armis_api.events += [
            _activity("d", "2023-01-01T01:00:17.300000+00:00"),
            _activity("e", "2023-01-01T01:00:18.000000+00:00"),
        ]
        _, shipped_cycle_2 = _run_one_cycle(dummy_client, "Activities", last_run, stream, 10, send_mock)
        assert shipped_cycle_2 == ["d", "e"]


# ---------------------------------------------------------------------------
# fetch_by_event_type resume edge cases (both modes)
# ---------------------------------------------------------------------------


@freeze_time("2023-01-01T02:00:00")
class TestFetchByEventTypeResumeEdges:
    @pytest.mark.parametrize("stream", [True, False], ids=["streaming", "non_streaming"])
    def test_single_second_with_more_pages_steps_offset(self, mocker, dummy_client, stream):
        """
        Given: a single-second response while Armis reports more pages (next > 0).
        When:  fetch_by_event_type runs.
        Then:  the watermark is kept and the offset steps by the number of events read.
        """
        mocker.patch("ArmisEventCollector.send_events_to_xsiam")
        response = [_activity(f"x{index}", f"2023-01-01T01:00:16.{index:06d}+00:00") for index in range(3)]
        mocker.patch.object(Client, "fetch_by_aql_query", side_effect=_streaming_fetch_stub(response, next_cursor=20003))
        next_run: dict = {}
        fetch_by_event_type(
            dummy_client,
            EVENT_TYPES["Activities"],
            {},
            100,
            {ACT_TIME: "2023-01-01T01:00:16", ACT_NEXT: 20000},
            next_run,
            None,
            stream=stream,
        )
        assert (next_run[ACT_TIME], next_run[ACT_NEXT]) == ("2023-01-01T01:00:16", 20003)

    @pytest.mark.parametrize("stream", [True, False], ids=["streaming", "non_streaming"])
    def test_empty_response_preserves_position(self, mocker, dummy_client, stream):
        """
        Given: a previous run at a deep offset and an empty response.
        When:  fetch_by_event_type runs.
        Then:  the watermark and offset are preserved unchanged (and, when streaming, the dedup ids).
        """
        mocker.patch("ArmisEventCollector.send_events_to_xsiam")
        mocker.patch.object(Client, "fetch_by_aql_query", side_effect=_streaming_fetch_stub([]))
        last_run = {ACT_TIME: "2023-01-01T01:00:16", ACT_NEXT: 30000, ACT_IDS: ["x"]}
        next_run: dict = {}
        fetch_by_event_type(dummy_client, EVENT_TYPES["Activities"], {}, 100, last_run, next_run, None, stream=stream)
        assert (next_run[ACT_TIME], next_run[ACT_NEXT]) == ("2023-01-01T01:00:16", 30000)
        if stream:
            assert next_run[ACT_IDS] == ["x"]

    def test_all_deduped_streaming_page_still_advances_watermark(self, mocker, dummy_client):
        """
        Given: a streaming page spanning two seconds whose events were all shipped last cycle.
        When:  fetch_by_event_type runs with stream=True.
        Then:  nothing is shipped, but last_event_time is still tracked so the watermark advances
               to the latest second and the offset resets.
        """
        mock_send = mocker.patch("ArmisEventCollector.send_events_to_xsiam")
        response = [
            _activity("a", "2023-01-01T01:00:10.500000+00:00"),
            _activity("b", "2023-01-01T01:00:20.500000+00:00"),
        ]
        mocker.patch.object(Client, "fetch_by_aql_query", side_effect=_streaming_fetch_stub(response))
        last_run = {ACT_TIME: "2023-01-01T01:00:10", ACT_NEXT: 0, ACT_IDS: ["a", "b"]}
        next_run: dict = {}
        fetch_by_event_type(dummy_client, EVENT_TYPES["Activities"], {}, 100, last_run, next_run, None, stream=True)
        mock_send.assert_not_called()
        assert (next_run[ACT_TIME], next_run[ACT_NEXT]) == ("2023-01-01T01:00:20", 0)

    @pytest.mark.parametrize("stream", [True, False], ids=["streaming", "non_streaming"])
    def test_max_pagination_seconds_forwarded(self, mocker, dummy_client, stream):
        """
        Given: a custom max_pagination_seconds.
        When:  fetch_by_event_type runs.
        Then:  the value is forwarded unchanged to Client.fetch_by_aql_query.
        """
        mocker.patch("ArmisEventCollector.send_events_to_xsiam")
        mock_fetch = mocker.patch.object(Client, "fetch_by_aql_query", side_effect=_streaming_fetch_stub([]))
        fetch_by_event_type(
            dummy_client, EVENT_TYPES["Activities"], {}, 100, {}, {}, None, stream=stream, max_pagination_seconds=123
        )
        assert mock_fetch.call_args.kwargs["max_pagination_seconds"] == 123


# ---------------------------------------------------------------------------
# fetch_events: pagination budget wiring
# ---------------------------------------------------------------------------


class TestFetchEventsPaginationBudgetWiring:
    def test_budget_receives_measured_alert_time_and_presence(self, mocker, dummy_client):
        """
        Given: an Alerts fetch that takes 25s and returns alerts, plus one paginating type.
        When:  fetch_events runs.
        Then:  compute_pagination_budget receives the measured alert time and alerts_present=True.
        """
        budget_spy = mocker.patch("ArmisEventCollector.compute_pagination_budget", wraps=compute_pagination_budget)
        mocker.patch("ArmisEventCollector._enrich_and_ship_in_chunks")
        with freeze_time("2023-01-01T02:00:00") as frozen_time:

            def fake_fetch_by_event_type(client, event_type, events, *args, **kwargs):
                if event_type.type == "alerts":
                    frozen_time.tick(timedelta(seconds=25))
                    events.setdefault("alerts", []).append({"alertId": "1"})

            mocker.patch("ArmisEventCollector.fetch_by_event_type", side_effect=fake_fetch_by_event_type)
            fetch_events(
                client=dummy_client,
                max_fetch=10,
                devices_max_fetch=10,
                last_run={},
                fetch_start_time=None,
                event_types_to_fetch=["Alerts", "Activities"],
                device_fetch_interval=None,
                use_multithreading=False,
            )

        kwargs = budget_spy.call_args.kwargs
        assert kwargs["paginating_types"] == 1
        assert kwargs["alerts_present"] is True
        assert kwargs["alerts_elapsed_seconds"] == pytest.approx(25.0)

    def test_budget_reports_no_alerts_when_alerts_empty(self, mocker, dummy_client):
        """
        Given: an Alerts fetch that returns nothing.
        When:  fetch_events runs.
        Then:  compute_pagination_budget receives alerts_present=False (no enrichment reserve).
        """
        budget_spy = mocker.patch("ArmisEventCollector.compute_pagination_budget", wraps=compute_pagination_budget)
        mocker.patch("ArmisEventCollector.fetch_by_event_type")
        fetch_events(
            client=dummy_client,
            max_fetch=10,
            devices_max_fetch=10,
            last_run={},
            fetch_start_time=None,
            event_types_to_fetch=["Alerts", "Activities"],
            device_fetch_interval=None,
            use_multithreading=False,
        )
        assert budget_spy.call_args.kwargs["alerts_present"] is False

    def test_cap_forwarded_to_every_sequential_call(self, mocker, dummy_client):
        """
        Given: two paginating types processed sequentially and a computed cap of 123s.
        When:  fetch_events runs.
        Then:  every fetch_by_event_type call receives max_pagination_seconds=123.
        """
        mocker.patch("ArmisEventCollector.compute_pagination_budget", return_value=123)
        mock_fetch = mocker.patch("ArmisEventCollector.fetch_by_event_type")
        fetch_events(
            client=dummy_client,
            max_fetch=10,
            devices_max_fetch=10,
            last_run={},
            fetch_start_time=None,
            event_types_to_fetch=["Activities", "Devices"],
            device_fetch_interval=timedelta(hours=1),
            use_multithreading=False,
        )
        assert mock_fetch.call_count == 2
        assert all(call.kwargs["max_pagination_seconds"] == 123 for call in mock_fetch.call_args_list)

    def test_cap_forwarded_to_every_parallel_worker(self, mocker, dummy_client):
        """
        Given: two paginating types processed in parallel and a computed cap of 123s.
        When:  fetch_events runs.
        Then:  every fetch_event_type_worker receives max_pagination_seconds=123.
        """
        mocker.patch("ArmisEventCollector.compute_pagination_budget", return_value=123)
        received_caps: dict = {}

        def fake_worker(
            client,
            event_type_name,
            event_type,
            max_fetch,
            last_run,
            fetch_start_time,
            fetch_delay,
            context_manager,
            stream,
            max_pagination_seconds,
        ):
            received_caps[event_type_name] = max_pagination_seconds
            return event_type_name, {}, {}

        mocker.patch("ArmisEventCollector.fetch_event_type_worker", side_effect=fake_worker)
        fetch_events(
            client=dummy_client,
            max_fetch=10,
            devices_max_fetch=10,
            last_run={},
            fetch_start_time=None,
            event_types_to_fetch=["Activities", "Devices"],
            device_fetch_interval=timedelta(hours=1),
            use_multithreading=True,
            context_manager=IntegrationContextManager(),
        )
        assert received_caps == {"Activities": 123, "Devices": 123}

    def test_devices_not_starved_when_activities_hits_cap(self, mocker, dummy_client):
        """
        Given: an Activities backlog that never drains (every page reports more) and 60s per page,
               processed sequentially before Devices.
        When:  fetch_events runs.
        Then:  Activities stops at its pagination cap and Devices is still fetched and shipped.
        """
        mock_send = mocker.patch("ArmisEventCollector.send_events_to_xsiam")
        search_calls: dict = {"activity": 0, "devices": 0}

        with freeze_time("2023-01-01T02:00:00") as frozen_time:

            def fake_perform_fetch(params):
                frozen_time.tick(timedelta(seconds=60))
                offset = params.get("from") or 0
                if "in:devices" in params["aql"]:
                    search_calls["devices"] += 1
                    device = {"id": "d1", "lastSeen": "2023-01-01T01:00:00.000000+00:00"}
                    return {"data": {"results": [device], "next": None}}
                search_calls["activity"] += 1
                page_second = f"2023-01-01T01:{offset // 60:02d}:{offset % 60:02d}"
                page = [_activity(f"a{offset + index}", f"{page_second}.{index:06d}+00:00") for index in range(2)]
                return {"data": {"results": page, "next": offset + 2}}

            mocker.patch.object(Client, "perform_fetch", side_effect=fake_perform_fetch)
            fetch_events(
                client=dummy_client,
                max_fetch=1000,
                devices_max_fetch=10,
                last_run={},
                fetch_start_time=None,
                event_types_to_fetch=["Activities", "Devices"],
                device_fetch_interval=timedelta(hours=1),
                use_multithreading=False,
            )

        # 2 types, no alerts -> cap = min(MAX, 270 // 2) = 135s; at 60s/page the loop breaks after
        # the 3rd request (elapsed 180s >= 135s, measured from before the first request).
        assert search_calls["activity"] == 3
        assert search_calls["devices"] == 1
        assert any(call.kwargs.get("product") == "security_devices" for call in mock_send.call_args_list)


# ---------------------------------------------------------------------------
# fetch_by_aql_query: custom pagination cap
# ---------------------------------------------------------------------------


class TestFetchByAqlQueryCustomCap:
    @staticmethod
    def _paged_perform_fetch(frozen_time, total_pages: int, seconds_per_page: int):
        def perform_fetch(params):
            frozen_time.tick(timedelta(seconds=seconds_per_page))
            offset = params.get("from") or 0
            page = [{"unique_id": str(offset), "time": f"2023-01-01T01:00:{offset:02d}.000000+00:00"}]
            return {"data": {"results": page, "next": offset + 1 if offset + 1 < total_pages else None}}

        return perform_fetch

    def test_custom_cap_stops_early_with_next(self, mocker, dummy_client):
        """
        Given: 5 pages at 20s each and max_pagination_seconds=30.
        When:  fetch_by_aql_query runs.
        Then:  it stops after the elapsed time passes 30s and returns a non-zero next for resume.
        """
        with freeze_time("2023-01-01T02:00:00") as frozen_time:
            mocker.patch.object(Client, "perform_fetch", side_effect=self._paged_perform_fetch(frozen_time, 5, 20))
            results, next_pointer = dummy_client.fetch_by_aql_query(
                aql_query="in:activity", max_fetch=100, after=datetime.now() - timedelta(minutes=1), max_pagination_seconds=30
            )
        # timer starts before the first request: 20s (<30) after page 1, 40s (>=30) after page 2 -> break.
        assert len(results) == 2
        assert next_pointer == 2

    def test_first_page_counts_towards_cap(self, mocker, dummy_client):
        """
        Given: pages of 60s each and max_pagination_seconds=90.
        When:  fetch_by_aql_query runs.
        Then:  the first page's time is counted, so pagination stops after 2 pages (120s), not 3 (180s),
               keeping the worst-case cycle at cap + one page.
        """
        with freeze_time("2023-01-01T02:00:00") as frozen_time:
            mocked_fetch = mocker.patch.object(
                Client, "perform_fetch", side_effect=self._paged_perform_fetch(frozen_time, 10, 60)
            )
            results, next_pointer = dummy_client.fetch_by_aql_query(
                aql_query="in:activity", max_fetch=100, after=datetime.now() - timedelta(minutes=1), max_pagination_seconds=90
            )
        assert mocked_fetch.call_count == 2
        assert len(results) == 2
        assert next_pointer == 2

    def test_large_cap_drains_all_pages(self, mocker, dummy_client):
        """
        Given: 5 pages at 20s each and a cap well above the total time.
        When:  fetch_by_aql_query runs.
        Then:  every page is read and next is 0 (drained).
        """
        with freeze_time("2023-01-01T02:00:00") as frozen_time:
            mocker.patch.object(Client, "perform_fetch", side_effect=self._paged_perform_fetch(frozen_time, 5, 20))
            results, next_pointer = dummy_client.fetch_by_aql_query(
                aql_query="in:activity", max_fetch=100, after=datetime.now() - timedelta(minutes=1), max_pagination_seconds=1000
            )
        assert len(results) == 5
        assert next_pointer == 0


# ---------------------------------------------------------------------------
# handle_fetched_events: next_run logging vs persistence
# ---------------------------------------------------------------------------


class TestHandleFetchedEventsNextRunLogging:
    def test_summary_log_collapses_lists_and_full_state_persisted(self, mocker):
        """
        Given: a next_run containing a dedup id list and scalar fields.
        When:  handle_fetched_events runs.
        Then:  the summary log shows the list as '<N ids>' (no raw ids) but keeps scalars,
               while setLastRun receives the full, uncollapsed list.
        """
        mocker.patch("ArmisEventCollector.send_events_to_xsiam")
        mock_debug = mocker.patch("ArmisEventCollector.demisto.debug")
        mock_set_last_run = mocker.patch("ArmisEventCollector.demisto.setLastRun")
        ids = ["id-1", "id-2", "id-3"]
        next_run: dict = {ACT_IDS: list(ids), ACT_TIME: "2023-01-01T01:00:17", ACT_NEXT: 0}

        handle_fetched_events({}, next_run)

        summary_logs = [call.args[0] for call in mock_debug.call_args_list if "[handle_fetched_events]" in str(call.args[0])]
        assert len(summary_logs) == 1
        assert "<3 ids>" in summary_logs[0]
        assert "id-1" not in summary_logs[0]
        assert "2023-01-01T01:00:17" in summary_logs[0]
        assert mock_set_last_run.call_args.args[0][ACT_IDS] == ids


class TestSequentialFailureKeepsProgress:
    def test_alerts_progress_kept_when_activities_fails(self, mocker, dummy_client):
        """
        Given: Alerts and Activities fetched in the same cycle (sequential path), and the Activities
               request fails with an API error after the alerts were already fetched.
        When:  fetch_events runs as the periodic fetch (streaming enabled).
        Then:  no error is raised, so the cycle completes and the last run can be saved. The returned
               next_run has the new alerts cursor and the unchanged activities cursor, so the alerts
               are not re-sent and no activities are skipped in the next cycle.
        """
        last_run = {
            "alerts_last_fetch_time": "2026-11-04T13:08:45",
            "activity_last_fetch_time": "2026-11-03T17:31:34",
            "activity_last_fetch_ids": ["id-1"],
            "activity_last_fetch_next_field": 0,
        }

        def fake_fetch_by_event_type(client, event_type, events, max_fetch, last_run, next_run, *args, **kwargs):
            if event_type.type == "alerts":
                next_run["alerts_last_fetch_time"] = "2026-11-04T14:13:02"
                return
            raise DemistoException("Error in API call [500] - Internal Server Error")

        mocker.patch("ArmisEventCollector.fetch_by_event_type", side_effect=fake_fetch_by_event_type)
        mocker.patch("ArmisEventCollector.demisto.error")

        _, next_run = fetch_events(
            client=dummy_client,
            max_fetch=10,
            devices_max_fetch=10,
            last_run=last_run,
            fetch_start_time=None,
            event_types_to_fetch=["Alerts", "Activities"],
            device_fetch_interval=None,
            use_multithreading=True,
            context_manager=IntegrationContextManager(),
            enable_streaming=True,
        )

        assert next_run["alerts_last_fetch_time"] == "2026-11-04T14:13:02"
        assert next_run["activity_last_fetch_time"] == "2026-11-03T17:31:34"
        assert next_run["activity_last_fetch_ids"] == ["id-1"]
        assert next_run["activity_last_fetch_next_field"] == 0

    def test_failed_event_type_reported_to_caller(self, mocker, dummy_client):
        """
        Given: the periodic fetch (streaming enabled) and a failing Activities fetch.
        When:  fetch_events runs with a failed_event_types list.
        Then:  the failure is appended to the list as "<event type>: <error>" and logged at error level.
        """
        mocker.patch("ArmisEventCollector.fetch_by_event_type", side_effect=DemistoException("Error in API call [500]"))
        mock_error = mocker.patch("ArmisEventCollector.demisto.error")
        failed_event_types: list[str] = []

        fetch_events(
            client=dummy_client,
            max_fetch=10,
            devices_max_fetch=10,
            last_run={},
            fetch_start_time=None,
            event_types_to_fetch=["Activities"],
            device_fetch_interval=None,
            use_multithreading=True,
            context_manager=IntegrationContextManager(),
            enable_streaming=True,
            failed_event_types=failed_event_types,
        )

        assert len(failed_event_types) == 1
        assert failed_event_types[0].startswith("Activities: ")
        assert "500" in failed_event_types[0]
        assert mock_error.call_args.args[0].startswith("[Fetch] Fetching Activities failed")

    def test_main_reports_failure_to_module_health_after_saving_last_run(self, mocker):
        """
        Given: the fetch-events command and an event type that fails during fetch_events.
        When:  main runs.
        Then:  the last run is saved first, and the failure is then reported to module health as an error.
        """
        import ArmisEventCollector

        def fake_fetch_events(*args, **kwargs):
            kwargs["failed_event_types"].append("Activities: Error in API call [500]")
            return {}, {"alerts_last_fetch_time": "2026-11-04T14:13:02"}

        mocker.patch.object(ArmisEventCollector.demisto, "command", return_value="fetch-events")
        mocker.patch.object(
            ArmisEventCollector.demisto,
            "params",
            return_value={"server_url": "test_url", "event_types_to_fetch": "Alerts,Activities"},
        )
        mocker.patch.object(ArmisEventCollector.demisto, "args", return_value={})
        mocker.patch.object(ArmisEventCollector.demisto, "getLastRun", return_value={"alerts_last_fetch_time": "x"})
        mocker.patch.object(ArmisEventCollector.demisto, "getIntegrationContext", return_value={})
        mocker.patch("ArmisEventCollector.Client")  # fetch_events is mocked, so no real API calls are needed
        mocker.patch("ArmisEventCollector.fetch_events", side_effect=fake_fetch_events)
        mocker.patch("ArmisEventCollector.send_events_to_xsiam")
        calls = MagicMock()
        mocker.patch.object(ArmisEventCollector.demisto, "setLastRun", side_effect=calls.setLastRun)
        mocker.patch.object(ArmisEventCollector.demisto, "updateModuleHealth", side_effect=calls.updateModuleHealth)

        ArmisEventCollector.main()

        assert [c[0] for c in calls.mock_calls] == ["setLastRun", "updateModuleHealth"]
        assert calls.updateModuleHealth.call_args.args[0] == "[Fetch] Failed to fetch: Activities: Error in API call [500]"
        assert calls.updateModuleHealth.call_args.kwargs == {"is_error": True}

    def test_last_run_not_touched_for_manual_get_events(self, mocker, dummy_client):
        """
        Given: the manual armis-get-events path (streaming disabled) and a failing Activities fetch.
        When:  fetch_events runs.
        Then:  the error is raised and the last run is not modified.
        """
        mocker.patch("ArmisEventCollector.fetch_by_event_type", side_effect=DemistoException("boom"))
        mock_set_last_run = mocker.patch("ArmisEventCollector.demisto.setLastRun")

        with pytest.raises(DemistoException, match="boom"):
            fetch_events(
                client=dummy_client,
                max_fetch=10,
                devices_max_fetch=10,
                last_run={},
                fetch_start_time=None,
                event_types_to_fetch=["Activities"],
                device_fetch_interval=None,
                use_multithreading=False,
                enable_streaming=False,
            )

        mock_set_last_run.assert_not_called()


@pytest.mark.parametrize(
    "activities_aql_filter, expected_query",
    [
        ('type:"Connection Start"', 'in:activity type:"Connection Start"'),
        ("  !type:Login  ", "in:activity !type:Login"),
        (None, "in:activity"),
        ("", "in:activity"),
        ("   ", "in:activity"),
    ],
)
def test_apply_activities_aql_filter(mocker, activities_aql_filter, expected_query):
    """
    Given:
        - An Activities AQL filter parameter (set, padded with spaces, or empty).
    When:
        - Applying the filter to the Activities event type.
    Then:
        - The filter is appended as is (stripped) to the Activities base query, or the query is unchanged when empty.
        - The Alerts and Devices queries are not affected.
    """
    mocker.patch.dict(
        EVENT_TYPES,
        {
            "Activities": EVENT_TYPE("activityUUID", "in:activity", "activity", "time", "activities"),
            "Alerts": EVENT_TYPE("alertId", "in:alerts", "alerts", "time", "alerts"),
            "Devices": EVENT_TYPE("id", "in:devices", "devices", "lastSeen", "devices"),
        },
    )

    apply_activities_aql_filter(activities_aql_filter)

    assert EVENT_TYPES["Activities"].aql_query == expected_query
    assert EVENT_TYPES["Alerts"].aql_query == "in:alerts"
    assert EVENT_TYPES["Devices"].aql_query == "in:devices"


def test_activities_aql_filter_sent_with_time_range(mocker, dummy_client):
    """
    Given:
        - An Activities AQL filter applied to the Activities event type.
    When:
        - Fetching activities with fetch_by_aql_query.
    Then:
        - The request AQL keeps the in: clause first, followed by the user filter and the after:/before: time range.
    """
    mocker.patch.dict(EVENT_TYPES, {"Activities": EVENT_TYPE("activityUUID", "in:activity", "activity", "time", "activities")})
    apply_activities_aql_filter('type:"Connection Start"')
    perform_fetch = mocker.patch.object(dummy_client, "perform_fetch", return_value={"data": {"results": [], "next": None}})

    dummy_client.fetch_by_aql_query(
        aql_query=EVENT_TYPES["Activities"].aql_query,
        max_fetch=10,
        after=datetime(2026, 11, 11, 10, 0, 0),
        before=datetime(2026, 11, 11, 10, 5, 0),
    )

    assert perform_fetch.call_args[0][0]["aql"] == (
        'in:activity type:"Connection Start" after:2026-11-11T10:00:00 before:2026-11-11T10:05:00'
    )
