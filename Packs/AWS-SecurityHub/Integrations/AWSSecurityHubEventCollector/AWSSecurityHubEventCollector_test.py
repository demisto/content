from pathlib import Path
import datetime as dt

import pytest
from freezegun import freeze_time
from AWSSecurityHubEventCollector import *

# Import test findings data from dedicated test data file
from test_data.test_constants import SAMPLE_FINDINGS, IGNORED_FINDINGS

# Test configuration constants - moved to top for parametrized test
FIXED_END_TIME = dt.datetime(2023, 1, 1, 13, 0, 0)
FIRST_FETCH_TIME = dt.datetime(2023, 1, 1, 10, 0, 0)
TEST_START_TIME = dt.datetime(2023, 1, 1, 10, 0, 0)
TEST_END_TIME = dt.datetime(2023, 1, 1, 14, 0, 0)

# Common ignore list patterns used in multiple tests
STANDARD_IGNORE_LIST = ["ignore-me", "also-ignore"]
DUPLICATE_IGNORE_LIST = ["ignore-1", "ignore-2"]


def load_test_data(folder: str, file_name: str) -> dict:
    """
    A function for loading and returning data from json files within the "test_data" folder.

    Args:
        folder (str): Name of the parent folder of the file within `test_data`.
        file_name (str): Name of a json file to load data from.

    Returns:
        dict: Dictionary data loaded from the json file.
    """
    with open(Path("test_data") / folder / f"{file_name}.json") as f:
        return json.load(f)


class MockClient:
    """
    A client mocking Boto3.client
    """

    findings_data = load_test_data("api_mock", "get_findings_10")
    calls_count = 0
    last_index = 0  # Used to mock pagination

    def __init__(self, *args, **kwargs):
        pass

    def get_findings(self, **kwargs) -> dict:
        """
        A function for mocking the get_findings function.

        Args:
            kwargs: Keyword arguments that would be passed to the get_findings function.
        """
        max_index = self.last_index + kwargs["MaxResults"]

        return_events = self.findings_data[self.last_index : max_index]
        self.last_index += len(return_events)
        result = {"Findings": return_events}

        if self.last_index < len(self.findings_data):
            result["NextToken"] = "next_token"

        self.calls_count += 1
        return result

    def reset(self):
        """
        A function for resetting the mock client.
        """
        self.calls_count = 0
        self.last_index = 0


@pytest.fixture
def client():
    """
    A fixture for creating a mock client.
    """
    return MockClient()


@pytest.mark.parametrize(
    "page_size, limit, expected_api_calls_count, expected_output_file",
    [
        (100, 1000, 1, "fetch_events_expected_results_0"),
        (2, 1000, 5, "fetch_events_expected_results_0"),
        (3, 1000, 4, "fetch_events_expected_results_0"),
        (2, 5, 3, "fetch_events_expected_results_1"),
        (100, 5, 1, "fetch_events_expected_results_1"),
    ],
)
def test_fetch(client, page_size: int, limit: int, expected_api_calls_count: int, expected_output_file: str):
    """
    Given: A page size parameter for the fetch events function.
    When: Fetching events from the API.
    Then: Assert the returned events are valid, and the number of API calls is as expected.

    Note: This is a test for both 'fetch_events' and 'get_events_command' functions.
    """
    expected_output = load_test_data("expected_results", expected_output_file)

    first_fetch_time = dt.datetime(2021, 1, 1)
    events, _, _ = fetch_events(client=client, last_run={}, first_fetch_time=first_fetch_time, page_size=page_size, limit=limit)

    assert client.calls_count == expected_api_calls_count
    assert len(events) == len(expected_output)
    assert events == expected_output

    client.reset()

    result = get_events_command(
        client=client, should_push_events=False, page_size=page_size, limit=limit, start_time=None, end_time=None
    )

    assert client.calls_count == expected_api_calls_count
    assert result.readable_output == tableToMarkdown("AWS Security Hub Events", expected_output, sort_headers=False)


class TestParseAwsTimestamp:
    """Test the new flexible timestamp parsing functionality."""

    @pytest.mark.parametrize(
        "timestamp_str, expected_result",
        [
            # Valid timestamp with milliseconds
            ("2023-01-01T12:30:45.123Z", dt.datetime(2023, 1, 1, 12, 30, 45, 123000)),
            # Valid timestamp without milliseconds
            ("2023-01-01T12:30:45Z", dt.datetime(2023, 1, 1, 12, 30, 45)),
        ],
    )
    def test_parse_timestamp_valid_formats(self, timestamp_str, expected_result):
        """
        Given: A valid timestamp string from AWS API (with or without milliseconds).
        When: Parsing the timestamp using parse_aws_timestamp.
        Then: Should return the correct datetime object.
        """
        result = parse_aws_timestamp(timestamp_str)
        assert result == expected_result

    def test_parse_timestamp_invalid_format(self):
        """
        Given: An invalid timestamp string.
        When: Parsing the timestamp using parse_aws_timestamp.
        Then: Should raise ValueError.
        """
        invalid_timestamp = "2023/01/01 12:30:45"
        with pytest.raises(ValueError):
            parse_aws_timestamp(invalid_timestamp)


class TestGenerateLastRunWithSmartAccumulation:
    """Test the smart ignore list accumulation functionality."""

    def test_generate_last_run_same_timestamp_accumulates_ignore_list(self):
        """
        Given: Events with same timestamp as previous run.
        When: Generating last run with previous_last_run parameter.
        Then: Should accumulate ignore list instead of replacing it.
        """
        events = [
            {"CreatedAt": "2023-01-01T12:00:00.000Z", "Id": "finding-3", "_time": "2023-01-01T12:00:00.000Z"},
            {"CreatedAt": "2023-01-01T12:00:00.000Z", "Id": "finding-4", "_time": "2023-01-01T12:00:00.000Z"},
        ]
        previous_last_run = {
            "last_update_date": "2023-01-01T12:00:00.000Z",
            "last_update_date_finding_ids": ["finding-1", "finding-2"],
        }

        result = generate_last_run(events, previous_last_run)

        assert result["last_update_date"] == "2023-01-01T12:00:00.000Z"
        assert len(result["last_update_date_finding_ids"]) == 4
        assert "finding-1" in result["last_update_date_finding_ids"]
        assert "finding-2" in result["last_update_date_finding_ids"]
        assert "finding-3" in result["last_update_date_finding_ids"]
        assert "finding-4" in result["last_update_date_finding_ids"]

    def test_generate_last_run_new_timestamp_starts_fresh(self):
        """
        Given: Events with new timestamp different from previous run.
        When: Generating last run with previous_last_run parameter.
        Then: Should start fresh ignore list instead of accumulating.
        """
        events = [
            {"CreatedAt": "2023-01-01T13:00:00.000Z", "Id": "finding-3", "_time": "2023-01-01T13:00:00.000Z"},
            {"CreatedAt": "2023-01-01T13:00:00.000Z", "Id": "finding-4", "_time": "2023-01-01T13:00:00.000Z"},
        ]
        previous_last_run = {
            "last_update_date": "2023-01-01T12:00:00.000Z",
            "last_update_date_finding_ids": ["finding-1", "finding-2"],
        }

        result = generate_last_run(events, previous_last_run)
        assert result["last_update_date"] == "2023-01-01T13:00:00.000Z"
        assert len(result["last_update_date_finding_ids"]) == 2
        assert "finding-3" in result["last_update_date_finding_ids"]
        assert "finding-4" in result["last_update_date_finding_ids"]
        assert "finding-1" not in result["last_update_date_finding_ids"]
        assert "finding-2" not in result["last_update_date_finding_ids"]

    def test_generate_last_run_no_previous_run(self):
        """
        Given: Events and no previous run data
        When: Generating last run
        Then: Should create fresh ignore list
        """
        # Given
        events = [
            {"CreatedAt": "2023-01-01T12:00:00.000Z", "Id": "finding-1", "_time": "2023-01-01T12:00:00.000Z"},
            {"CreatedAt": "2023-01-01T12:00:00.000Z", "Id": "finding-2", "_time": "2023-01-01T12:00:00.000Z"},
        ]

        # When
        result = generate_last_run(events, None)

        # Then
        assert result["last_update_date"] == "2023-01-01T12:00:00.000Z"
        assert len(result["last_update_date_finding_ids"]) == 2
        assert "finding-1" in result["last_update_date_finding_ids"]
        assert "finding-2" in result["last_update_date_finding_ids"]


@pytest.mark.parametrize(
    (
        "scenario, mock_api_responses, start_time, end_time, id_ignore_list, "
        "page_size, limit, start_token, expected_events_count, expected_next_token, expected_api_calls, expected_debug_messages"
    ),
    [
        (
            "single_page_no_pagination",
            # Mock API returns findings in single call, no NextToken
            [{"Findings": SAMPLE_FINDINGS[:3]}],
            TEST_START_TIME,  # start_time
            TEST_END_TIME,  # end_time
            None,  # id_ignore_list
            50,  # page_size
            0,  # limit (no limit)
            None,  # start_token
            3,  # expected_events_count
            None,  # expected_next_token
            1,  # expected_api_calls (single page)
            [
                "Starting get_events pagination",
                "No more pages available from AWS",
                "Pagination completed after",
            ],  # expected_debug_messages
        ),
        (
            "multiple_pages_with_pagination",
            # Mock API returns findings across multiple calls with NextToken
            [
                {"Findings": SAMPLE_FINDINGS[:2], "NextToken": "page-2-token"},
                {"Findings": SAMPLE_FINDINGS[2:4], "NextToken": "page-3-token"},
                {"Findings": SAMPLE_FINDINGS[4:5]},
            ],
            TEST_START_TIME,  # start_time
            None,  # end_time (use current time)
            None,  # id_ignore_list
            2,  # page_size (forces pagination)
            5,  # limit
            None,  # start_token
            5,  # expected_events_count
            None,  # expected_next_token (no more pages)
            3,  # expected_api_calls (3 pages: 2+2+1 events)
            [  # expected_debug_messages
                "Starting get_events pagination",
                "Continuing pagination",
                "Pagination completed after",
            ],
        ),
        (
            "with_ignore_list_filters_duplicates",
            # Mock API returns findings, some filtered by ignore list
            [{"Findings": [SAMPLE_FINDINGS[0], IGNORED_FINDINGS[0], SAMPLE_FINDINGS[2], IGNORED_FINDINGS[1]]}],
            TEST_START_TIME,  # start_time
            TEST_END_TIME,  # end_time
            STANDARD_IGNORE_LIST,  # id_ignore_list
            50,  # page_size
            10,  # limit
            None,  # start_token
            2,  # expected_events_count (2 not ignored)
            None,  # expected_next_token
            1,  # expected_api_calls (single page, filtering happens after)
            ["Starting get_events pagination", "2 duplicates filtered", "Pagination completed after"],  # expected_debug_messages
        ),
        (
            "limit_stops_pagination_early",
            # Mock API has more pages but limit stops collection
            [
                {"Findings": SAMPLE_FINDINGS[:2], "NextToken": "has-more-pages"},
                {"Findings": SAMPLE_FINDINGS[2:3], "NextToken": "still-more-pages"},
            ],
            None,  # start_time (no time filter)
            None,  # end_time
            None,  # id_ignore_list
            2,  # page_size
            3,  # limit (stops after 3 events)
            None,  # start_token
            3,  # expected_events_count
            "still-more-pages",  # expected_next_token (stopped due to limit)
            2,  # expected_api_calls (2 pages: 2+1 events, stops at limit)
            [  # expected_debug_messages
                "Starting get_events pagination",
                "Reached limit",
                "Pagination completed after",
            ],
        ),
        (
            "continuation_from_start_token",
            # Mock API continues from provided start_token
            [{"Findings": SAMPLE_FINDINGS[3:5]}],
            TEST_START_TIME,  # start_time
            TEST_END_TIME,  # end_time
            None,  # id_ignore_list
            50,  # page_size
            0,  # limit
            "continue-from-here",  # start_token
            2,  # expected_events_count
            None,  # expected_next_token
            1,  # expected_api_calls (single page from token)
            [
                "Starting get_events pagination",
                "No more pages available from AWS",
                "Pagination completed after",
            ],  # expected_debug_messages
        ),
        (
            "empty_response_no_events",
            # Mock API returns no findings
            [{"Findings": []}],
            TEST_START_TIME,  # start_time
            TEST_END_TIME,  # end_time
            None,  # id_ignore_list
            50,  # page_size
            10,  # limit
            None,  # start_token
            0,  # expected_events_count
            None,  # expected_next_token
            1,  # expected_api_calls (single empty response)
            [  # expected_debug_messages
                "Starting get_events pagination",
                "AWS returned 0 findings",
                "Pagination completed after",
            ],
        ),
        (
            "all_events_filtered_by_ignore_list",
            # Mock API returns findings but all are in ignore list
            [{"Findings": IGNORED_FINDINGS[2:4]}],
            None,  # start_time (no time filter)
            None,  # end_time
            DUPLICATE_IGNORE_LIST,  # id_ignore_list
            50,  # page_size
            0,  # limit
            None,  # start_token
            0,  # expected_events_count (all filtered)
            None,  # expected_next_token
            1,  # expected_api_calls (single page, all filtered after)
            ["Starting get_events pagination", "2 duplicates filtered", "Pagination completed after"],  # expected_debug_messages
        ),
    ],
)
@freeze_time("2023-01-01 15:00:00")
def test_get_events__end_to_end(
    mocker,
    scenario,
    mock_api_responses,
    start_time,
    end_time,
    id_ignore_list,
    page_size,
    limit,
    start_token,
    expected_events_count,
    expected_next_token,
    expected_api_calls,
    expected_debug_messages,
):
    """
    Test end-to-end get_events functionality covering all scenarios:

    Case 1 (single_page_no_pagination): Single API call returns all findings, no NextToken pagination
    Case 2 (multiple_pages_with_pagination): Multiple API calls with NextToken pagination until completion
    Case 3 (with_ignore_list_filters_duplicates): Ignore list properly filters out specified finding IDs
    Case 4 (limit_stops_pagination_early): Limit parameter stops pagination before all pages processed
    Case 5 (continuation_from_start_token): Pagination continues from provided start_token
    Case 6 (empty_response_no_events): API returns empty findings list gracefully
    Case 7 (all_events_filtered_by_ignore_list): All findings filtered out by ignore list

    Given:
        - A mocked AWS SecurityHub client that returns predefined API response sequences
        - Various time ranges, ignore lists, page sizes, limits, and pagination tokens
        - Mocked demisto.debug for logging verification
        - Frozen time at 2023-01-01 15:00:00 for consistent datetime.now() calls
        - Expected API call counts and specific debug messages for each scenario
    When:
        - Calling get_events with different parameter combinations and scenarios
    Then:
        - Ensure correct number of events are returned after deduplication and filtering
        - Ensure pagination works correctly with NextToken handling and limit enforcement
        - Ensure ignore list properly filters duplicate finding IDs
        - Ensure time filtering parameters are correctly passed to AWS API
        - Ensure continuation tokens work for resuming pagination from specific points
        - Ensure correct number of API calls are made (pagination iteration validation)
        - Ensure scenario-specific debug messages are logged correctly
        - Ensure events have proper structure (Id and CreatedAt fields)
    """
    # Mock demisto.debug to capture logging
    mock_debug = mocker.patch("AWSSecurityHubEventCollector.demisto.debug")

    # Create mock client with sequential API responses
    mock_client = mocker.Mock()
    mock_client.get_findings.side_effect = mock_api_responses

    # Call get_events
    events, next_token = get_events(
        client=mock_client,
        start_time=start_time,
        end_time=end_time,
        id_ignore_list=id_ignore_list,
        page_size=page_size,
        limit=limit,
        start_token=start_token,
    )

    # Verify events count
    assert len(events) == expected_events_count

    # Verify next_token
    assert next_token == expected_next_token

    # Verify expected number of API calls (pagination iterations)
    assert mock_client.get_findings.call_count == expected_api_calls

    # Verify first API call parameters
    first_call = mock_client.get_findings.call_args_list[0]
    call_kwargs = first_call.kwargs

    # Check sorting
    assert call_kwargs["SortCriteria"] == [{"Field": "CreatedAt", "SortOrder": "asc"}]

    # Check time filters
    expected_filters = {}
    expected_end_time = end_time or dt.datetime(2023, 1, 1, 15, 0, 0)  # frozen time
    expected_start_time_str = start_time.strftime("%Y-%m-%dT%H:%M:%S.%fZ") if start_time else None
    expected_end_time_str = expected_end_time.strftime("%Y-%m-%dT%H:%M:%S.%fZ")

    if start_time:
        expected_filters["CreatedAt"] = [{"Start": expected_start_time_str, "End": expected_end_time_str}]
        assert call_kwargs["Filters"] == expected_filters
    else:
        # No Filters key when no start_time
        assert "Filters" not in call_kwargs

    # Check pagination token
    if start_token:
        assert call_kwargs["NextToken"] == start_token
    else:
        assert "NextToken" not in call_kwargs

    # Check page size (MaxResults)
    expected_max_results = page_size if limit == 0 or page_size <= limit else min(page_size, limit)
    assert call_kwargs["MaxResults"] == expected_max_results

    # Verify ignore list filtering worked correctly
    if id_ignore_list:
        returned_ids = {event["Id"] for event in events}
        ignored_ids = set(id_ignore_list)
        assert returned_ids.isdisjoint(ignored_ids), "Ignored IDs should not appear in results"

    # Verify events have proper structure
    for event in events:
        assert "Id" in event
        assert "CreatedAt" in event

    # Verify expected debug messages are present
    debug_calls = [call.args[0] for call in mock_debug.call_args_list]

    for expected_msg in expected_debug_messages:
        assert any(
            expected_msg in msg for msg in debug_calls
        ), f"Expected debug message '{expected_msg}' not found in: {debug_calls}"


# Test findings data and constants imported at top of file


@pytest.fixture
def fetch_events_mocks(mocker):
    """Common mocks for fetch_events tests."""
    mocks = {
        "debug": mocker.patch("AWSSecurityHubEventCollector.demisto.debug"),
        "info": mocker.patch("AWSSecurityHubEventCollector.demisto.info"),
        "error": mocker.patch("AWSSecurityHubEventCollector.demisto.error"),
        "generate_last_run": mocker.patch("AWSSecurityHubEventCollector.generate_last_run"),
        "parse_timestamp": mocker.patch("AWSSecurityHubEventCollector.parse_aws_timestamp"),
        "datetime_now": mocker.patch("AWSSecurityHubEventCollector.dt.datetime"),
        "get_events": mocker.patch("AWSSecurityHubEventCollector.get_events"),
        "client": mocker.Mock(),
    }

    # Configure common mock behaviors
    mocks["datetime_now"].now.return_value = FIXED_END_TIME
    mocks["parse_timestamp"].side_effect = lambda ts: dt.datetime.strptime(ts, "%Y-%m-%dT%H:%M:%S.%fZ")

    return mocks


def _verify_debug_messages(debug_calls, info_calls, expected_debug=None, expected_info=None):
    """Helper to verify debug/info messages."""
    # Always check for initial fetch message
    assert any("Fetching events with last_run:" in msg for msg in debug_calls)

    if expected_debug:
        for msg in expected_debug:
            assert any(msg in call for call in debug_calls), f"Expected debug message '{msg}' not found"

    if expected_info:
        for msg in expected_info:
            assert any(msg in call for call in info_calls), f"Expected info message '{msg}' not found"


def test_fetch_events_first_fetch_success(fetch_events_mocks):
    """
    Test fetch_events for first fetch scenario: empty last_run with first_fetch_time.

    Given: Empty last_run and valid first_fetch_time
    When: Calling fetch_events
    Then: Should fetch new events and create proper next_run structure
    """
    mocks = fetch_events_mocks

    # Configure test-specific mocks
    mocks["get_events"].return_value = (SAMPLE_FINDINGS[:2], None)
    next_run = {
        "last_update_date": "2023-01-01T12:01:00.000Z",
        "last_update_date_finding_ids": ["finding-2"],
    }
    mocks["generate_last_run"].return_value = next_run

    # Call fetch_events
    events, actual_next_run, error = fetch_events(
        client=mocks["client"], last_run={}, first_fetch_time=FIRST_FETCH_TIME, page_size=50, limit=0
    )

    # Verify results
    assert len(events) == 2
    assert error is None
    assert "last_update_date" in str(actual_next_run)
    assert "finding-2" in str(actual_next_run)

    # Verify get_events was called correctly
    assert mocks["get_events"].call_count == 1
    call_kwargs = mocks["get_events"].call_args_list[0].kwargs

    assert call_kwargs["client"] == mocks["client"]
    assert call_kwargs["page_size"] == 50
    assert call_kwargs["end_time"] == FIXED_END_TIME  # Fixed end_time consistency
    assert call_kwargs["id_ignore_list"] == []  # Empty ignore list for first fetch

    # Verify generate_last_run was called
    mocks["generate_last_run"].assert_called_once_with(events, {})

    # Verify debug messages
    debug_calls = [call.args[0] for call in mocks["debug"].call_args_list]
    info_calls = [call.args[0] for call in mocks["info"].call_args_list]

    _verify_debug_messages(
        debug_calls, info_calls, expected_debug=["Successfully fetched 2 new events"], expected_info=["Fetched 2 findings."]
    )


def test_fetch_events_infinite_loop_prevention(fetch_events_mocks):
    """
    Test fetch_events infinite loop prevention: all duplicates but AWS has more events.

    Given: All events are duplicates but AWS has continuation token
    When: Calling fetch_events
    Then: Should make retry with increased limit, then exit when no more events
    """
    mocks = fetch_events_mocks

    # Configure test-specific mocks for infinite loop scenario
    mocks["get_events"].side_effect = [
        ([], "continuation-token"),  # First call: all duplicates, has next token -> triggers retry
        ([], None),  # Second call: still no events, no more pages -> exits loop
    ]
    mocks["generate_last_run"].return_value = {
        "last_update_date": "2023-01-01T12:00:00.000Z",
        "last_update_date_finding_ids": ["duplicate-1"],
    }

    # Call fetch_events
    events, next_run, error = fetch_events(
        client=mocks["client"],
        last_run={"last_update_date": "2023-01-01T12:00:00.000Z", "last_update_date_finding_ids": ["duplicate-1"]},
        first_fetch_time=None,
        page_size=50,
        limit=10,
    )

    # Verify results
    assert len(events) == 0  # No new events (all duplicates)
    assert error is None

    # Verify loop behavior: should make 2 calls
    assert mocks["get_events"].call_count == 2

    # Verify second call has increased limit (RETRY_LIMIT_INCREMENT = 100)
    second_call = mocks["get_events"].call_args_list[1]
    expected_retry_limit = 100  # RETRY_LIMIT_INCREMENT value from code
    assert second_call.kwargs["limit"] == expected_retry_limit

    # Verify both calls use same fixed end_time
    for call_args in mocks["get_events"].call_args_list:
        assert call_args.kwargs["end_time"] == FIXED_END_TIME

    # Verify debug messages
    debug_calls = [call.args[0] for call in mocks["debug"].call_args_list]
    info_calls = [call.args[0] for call in mocks["info"].call_args_list]

    _verify_debug_messages(
        debug_calls,
        info_calls,
        expected_debug=["All events were duplicates and AWS has no more events"],
        expected_info=["No new findings were found.", "Infinite loop prevention"],
    )


def test_fetch_events_api_error_handling(fetch_events_mocks):
    """
    Test fetch_events error handling: API raises exception.

    Given: get_events raises an exception
    When: Calling fetch_events
    Then: Should capture error and return it without raising
    """
    mocks = fetch_events_mocks

    # Configure test-specific mocks for error scenario
    test_exception = Exception("AWS API Error: Rate limit exceeded")
    mocks["get_events"].side_effect = test_exception
    mocks["generate_last_run"].return_value = {"last_update_date": "2023-01-01T12:00:00.000Z", "last_update_date_finding_ids": []}

    # Call fetch_events
    events, next_run, error = fetch_events(
        client=mocks["client"],
        last_run={"last_update_date": "2023-01-01T12:00:00.000Z", "last_update_date_finding_ids": []},
        first_fetch_time=None,
        page_size=50,
        limit=10,
    )

    # Verify error handling
    assert len(events) == 0  # No events due to error
    assert error is not None
    assert isinstance(error, Exception)
    assert str(error) == "AWS API Error: Rate limit exceeded"

    # Verify error logging
    error_calls = [call.args[0] for call in mocks["error"].call_args_list]
    assert any("Error while fetching events" in msg for msg in error_calls)
