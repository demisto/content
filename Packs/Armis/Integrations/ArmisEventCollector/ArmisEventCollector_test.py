import threading
from concurrent.futures import ThreadPoolExecutor
from unittest.mock import MagicMock, patch

import pytest
from ArmisEventCollector import (
    BULK_ENRICHMENT_BATCH_SIZE,
    EVENT_TYPE,
    EVENT_TYPES,
    Any,
    Client,
    DemistoException,
    IntegrationContextManager,
    _attach_enrichment,
    _bulk_fetch_entities_by_id,
    _collect_unique_enrichment_ids,
    _wait_for_enrichment,
    arg_to_datetime,
    bulk_enrich_alerts,
    datetime,
    fetch_events,
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

    @pytest.mark.parametrize(
        "next_pointer, expected_last_run",
        [
            (
                4,
                {
                    "events_last_fetch_ids": ["3"],
                    "events_last_fetch_next_field": 4,
                    "events_last_fetch_time": "2023-01-01T01:00:20",
                },
            ),
            (
                0,
                {
                    "events_last_fetch_ids": ["3"],
                    "events_last_fetch_next_field": 0,
                    "events_last_fetch_time": "2023-01-01T01:00:30.123456+00:00",
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
        {
            "events_last_fetch_ids": ["3"],
            "events_last_fetch_next_field": 4,
            "events_last_fetch_time": "2023-01-01T01:00:00",
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
        {
            "events_last_fetch_ids": ["7", "6"],
            "events_last_fetch_next_field": 8,
            "events_last_fetch_time": "2023-01-01T01:00:30",
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
        {
            "events_last_fetch_ids": ["7", "6"],
            "events_last_fetch_next_field": 8,
            "events_last_fetch_time": "2023-01-01T01:00:30",
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
        {"events_last_fetch_next_field": 4, "events_last_fetch_time": "2023-01-01T01:00:30"},
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
        {
            "events_last_fetch_ids": ["1", "2", "3", "4", "5", "6"],
            "events_last_fetch_next_field": 7,
            "events_last_fetch_time": "2023-01-01T01:00:30",
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
            expected_next_run = {
                "events_last_fetch_ids": ["3"],
                "events_last_fetch_next_field": 4,
                "events_last_fetch_time": "2023-01-01T01:00:00",
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

        events, next_run = fetch_events(dummy_client, 1, 1, {}, fetch_start_time, ["Alerts"], None)

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
        # Verify next_run state
        assert next_run["alerts_last_fetch_next_field"] == 2


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

    def test_deepcopy_shared_references(self):
        """
        Given:
            - Two alerts sharing the same activityUUID.
        When:
            - Attaching enrichment.
        Then:
            - Each alert gets its own copy (deepcopy) — modifying one doesn't affect the other.
        """
        alerts = [
            {"alertId": "1", "activityUUIDs": ["shared"], "deviceIds": [], "activitiesData": [], "devicesData": []},
            {"alertId": "2", "activityUUIDs": ["shared"], "deviceIds": [], "activitiesData": [], "devicesData": []},
        ]
        activities = {"shared": {"activityUUID": "shared", "data": "original"}}

        _attach_enrichment(alerts, activities, {})

        # Modify one alert's enrichment data
        alerts[0]["activitiesData"][0]["data"] = "modified"
        # The other alert should be unaffected
        assert alerts[1]["activitiesData"][0]["data"] == "original"

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
        # Verify deepcopy: shared uuid-2 should be independent copies
        alerts[0]["activitiesData"][1]["info"] = "modified"
        uuid2_in_alert2 = [a for a in alerts[1]["activitiesData"] if a["activityUUID"] == "uuid-2"][0]
        assert uuid2_in_alert2["info"] == "a2"  # unmodified


class TestWaitForEnrichment:
    """Tests for _wait_for_enrichment."""

    def test_none_future(self):
        """
        Given:
            - future is None (no enrichment was scheduled).
        When:
            - Calling _wait_for_enrichment.
        Then:
            - Returns immediately without error.
        """
        _wait_for_enrichment(None, None)  # Should not raise

    def test_successful_future(self):
        """
        Given:
            - A future that completes successfully.
        When:
            - Calling _wait_for_enrichment.
        Then:
            - Joins the future and shuts down the executor.
        """
        executor = ThreadPoolExecutor(max_workers=1)
        future = executor.submit(lambda: None)

        _wait_for_enrichment(future, executor)  # Should not raise

    def test_failed_future(self, mocker):
        """
        Given:
            - A future that raises an exception.
        When:
            - Calling _wait_for_enrichment.
        Then:
            - The exception is logged but NOT re-raised (graceful degradation).
        """
        executor = ThreadPoolExecutor(max_workers=1)
        future = executor.submit(lambda: (_ for _ in ()).throw(RuntimeError("enrichment failed")))

        mock_error = mocker.patch("ArmisEventCollector.demisto.error")

        _wait_for_enrichment(future, executor)  # Should not raise

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
