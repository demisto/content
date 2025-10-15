from pathlib import Path
import datetime as dt

import pytest
from AWSSecurityHubEventCollector import *


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

    result = get_events_command(client=client, should_push_events=False, page_size=page_size, limit=limit)

    assert client.calls_count == expected_api_calls_count
    assert result.readable_output == tableToMarkdown("AWS Security Hub Events", expected_output, sort_headers=False)


class TestParseAwsTimestamp:
    """Test the new flexible timestamp parsing functionality."""

    def test_parse_timestamp_with_milliseconds(self):
        """
        Given: A timestamp string with milliseconds from AWS API.
        When: Parsing the timestamp using parse_aws_timestamp.
        Then: Should return correct datetime object.
        """
        timestamp_with_ms = "2023-01-01T12:30:45.123Z"
        result = parse_aws_timestamp(timestamp_with_ms)
        expected = dt.datetime(2023, 1, 1, 12, 30, 45, 123000)
        assert result == expected

    def test_parse_timestamp_without_milliseconds(self):
        """
        Given: A timestamp string without milliseconds from AWS API.
        When: Parsing the timestamp using parse_aws_timestamp.
        Then: Should return correct datetime object using fallback format.
        """
        timestamp_without_ms = "2023-01-01T12:30:45Z"
        result = parse_aws_timestamp(timestamp_without_ms)
        expected = dt.datetime(2023, 1, 1, 12, 30, 45)
        assert result == expected

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


class TestGetEvents:
    def test_get_events_filters_duplicates_correctly(self):
        """
        Given: Events from AWS with some IDs in ignore list
        When: Calling get_events with id_ignore_list
        Then: Should return only non-duplicate events
        """
        # Given
        client = MockClient()
        client.findings_data = [
            {"Id": "keep-1", "CreatedAt": "2023-01-01T12:00:00.000Z"},
            {"Id": "ignore-1", "CreatedAt": "2023-01-01T12:00:00.000Z"},
            {"Id": "keep-2", "CreatedAt": "2023-01-01T12:00:00.000Z"},
            {"Id": "ignore-2", "CreatedAt": "2023-01-01T12:00:00.000Z"},
        ]
        ignore_list = ["ignore-1", "ignore-2"]

        # When
        events, next_token = get_events(client=client, id_ignore_list=ignore_list, limit=10)

        # Then
        assert len(events) == 2
        assert events[0]["Id"] == "keep-1"
        assert events[1]["Id"] == "keep-2"
        # Verify ignored events are not present
        returned_ids = [event["Id"] for event in events]
        assert "ignore-1" not in returned_ids
        assert "ignore-2" not in returned_ids
