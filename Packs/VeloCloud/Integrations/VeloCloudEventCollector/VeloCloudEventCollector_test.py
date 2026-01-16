"""Unit tests for VeloCloudEventCollector integration."""

import json
import os
from datetime import datetime, timedelta, UTC
from unittest.mock import patch

import pytest

from VeloCloudEventCollector import (
    Client,
    get_events_command,
    test_module as velocloud_test_module,
    fetch_events,
    fetch_events_command,
    velocloud_parse_date_range,
    format_events,
)


def load_test_data(test_data_filename):
    """Load test data from a JSON file.

    Args:
        test_data_filename: Name of the test data file

    Returns:
        Parsed JSON data from the file
    """
    with open(os.path.join("./test_data", test_data_filename)) as f:
        return json.load(f)


@pytest.fixture()
def client(requests_mock):
    """Create a VeloCloud client with mocked requests.

    Args:
        requests_mock: requests_mock fixture

    Returns:
        Configured VeloCloud Client instance
    """
    base_url = "https://tenant123.velocloud.net"
    enterprise_id = "12345678"
    return Client(
        base_url=base_url,
        enterprise_id=enterprise_id,
        verify=False,
        headers={},
        proxy=False,
    )


class TestGetEventsCommand:
    """Test get_events_command functionality."""

    def test_get_events_command_successful(self, requests_mock, client):
        """
        Given:
            - VeloCloud client is configured
        When:
            - Executing get_events_command
        Then:
            - Ensure command returns events with correct structure
        """
        # Load test data
        events_data = load_test_data("output-get-events.json")

        # Mock the API response
        requests_mock.post(
            "https://tenant123.velocloud.net/portal/rest/event/getEnterpriseEvents",
            json={"data": events_data, "metadata": {}},
        )

        # Prepare command arguments
        args = {
            "start_time": "2025-11-02T21:02:42.829772",
            "end_time": "2025-11-03T21:02:42.831369",
            "limit": "100",
        }

        # Execute command
        result = get_events_command(client, args)

        # Assertions
        assert result.outputs_prefix == "VeloCloud.Event"
        assert result.outputs_key_field == "logicalId"
        assert isinstance(result.outputs, list)
        assert len(result.outputs) == 3
        assert result.outputs[0]["event"] == "EDGE_NEW_DEVICE"
        assert result.outputs[0]["category"] == "EDGE"

    def test_get_events_command_with_default_values(self, requests_mock, client):
        """
        Given:
            - VeloCloud client is configured
        When:
            - Executing get_events_command without optional parameters
        Then:
            - Ensure default values are used
        """
        events_data = load_test_data("output-get-events.json")

        requests_mock.post(
            "https://tenant123.velocloud.net/portal/rest/event/getEnterpriseEvents",
            json={"data": events_data, "metadata": {}},
        )

        # Minimal args - let defaults apply
        args = {}

        result = get_events_command(client, args)

        assert result.outputs_prefix == "VeloCloud.Event"
        assert len(result.outputs) == len(events_data)

    def test_get_events_command_empty_response(self, requests_mock, client):
        """
        Given:
            - VeloCloud client is configured
        When:
            - API returns no events
        Then:
            - Ensure command handles empty response gracefully
        """
        requests_mock.post(
            "https://tenant123.velocloud.net/portal/rest/event/getEnterpriseEvents",
            json={"data": [], "metadata": {}},
        )

        args = {"limit": "10"}

        result = get_events_command(client, args)

        assert isinstance(result.outputs, list)
        assert len(result.outputs) == 0


class TestTestModule:
    """Test test_module functionality."""

    def test_test_module_success(self, requests_mock, client):
        """
        Given:
            - VeloCloud client is configured
            - API is accessible
        When:
            - Executing test_module
        Then:
            - Ensure 'ok' is returned
        """
        # Load real sample data and use first event
        sample_events = load_test_data("output-get-events.json")
        first_event = sample_events[0]

        requests_mock.post(
            "https://tenant123.velocloud.net/portal/rest/event/getEnterpriseEvents",
            json={"data": [first_event], "metadata": {}},
        )

        result = velocloud_test_module(client)

        assert result == "ok"

    def test_test_module_authentication_error(self, requests_mock, client):
        """
        Given:
            - VeloCloud client is configured
            - API authentication fails
        When:
            - Executing test_module
        Then:
            - Ensure authentication error message is returned
        """
        # Load real sample data for failed auth event
        failed_auth_event = load_test_data("failed-auth.json")

        requests_mock.post(
            "https://tenant123.velocloud.net/portal/rest/event/getEnterpriseEvents",
            status_code=200,
            json=failed_auth_event,
        )

        result = velocloud_test_module(client)

        assert "Invalid API Token" in result


class TestVelocloudParseDateRange:
    """Test velocloud_parse_date_range functionality."""

    def test_parse_date_range_with_last_run_time(self):
        """
        Given:
            - last_run_time is provided
        When:
            - Calling velocloud_parse_date_range
        Then:
            - Ensure start_time is incremented by 1 second
        """
        first_fetch = "3 days ago"
        last_run_time = "2025-11-02T10:00:00Z"

        start_time, end_time = velocloud_parse_date_range(first_fetch, last_run_time)

        parsed_start = datetime.fromisoformat(start_time)
        # Should be 1 second after last_run_time
        expected = datetime(2025, 11, 2, 10, 0, 1, tzinfo=UTC)
        assert parsed_start == expected

    def test_parse_date_range_without_last_run_time(self):
        """
        Given:
            - last_run_time is empty
        When:
            - Calling velocloud_parse_date_range
        Then:
            - Ensure start_time is based on first_fetch
        """
        first_fetch = "2 days ago"
        last_run_time = ""

        start_time, end_time = velocloud_parse_date_range(first_fetch, last_run_time)

        parsed_start = datetime.fromisoformat(start_time)

        # Start should be approximately 2 days ago
        # Using a larger tolerance since dateparser can have variations
        now = datetime.now(UTC)
        expected_time = now - timedelta(days=2)
        delta = abs((parsed_start - expected_time).total_seconds())
        assert delta < 86400  # Within 1 day of tolerance

    def test_parse_date_range_invalid_last_run_time_falls_back_to_first_fetch(self):
        """
        Given:
            - last_run_time is invalid
        When:
            - Calling velocloud_parse_date_range
        Then:
            - Ensure start_time falls back to first_fetch
        """
        first_fetch = "1 day ago"
        last_run_time = "invalid-date-string"

        start_time, end_time = velocloud_parse_date_range(first_fetch, last_run_time)

        parsed_start = datetime.fromisoformat(start_time)

        # Should fall back to first_fetch (1 day ago)
        now = datetime.now(UTC)
        expected_time = now - timedelta(days=1)
        delta = abs((parsed_start - expected_time).total_seconds())
        assert delta < 86400  # Within 1 day of tolerance

    def test_parse_date_range_invalid_both_uses_default(self):
        """
        Given:
            - Both last_run_time and first_fetch are invalid
        When:
            - Calling velocloud_parse_date_range
        Then:
            - Ensure start_time defaults to 1 day ago
        """
        first_fetch = "completely-invalid"
        last_run_time = ""

        start_time, end_time = velocloud_parse_date_range(first_fetch, last_run_time)

        parsed_start = datetime.fromisoformat(start_time)

        # Should default to 1 day ago
        now = datetime.now(UTC)
        expected_time = now - timedelta(days=1)
        delta = abs((parsed_start - expected_time).total_seconds())
        assert delta < 60

    def test_parse_date_range_end_time_is_now(self):
        """
        Given:
            - Any valid first_fetch
        When:
            - Calling velocloud_parse_date_range
        Then:
            - Ensure end_time is approximately now
        """
        first_fetch = "1 day ago"
        last_run_time = ""

        start_time, end_time = velocloud_parse_date_range(first_fetch, last_run_time)

        parsed_end = datetime.fromisoformat(end_time)
        now = datetime.now(UTC)

        # End time should be within 5 seconds of now
        delta = abs((parsed_end - now).total_seconds())
        assert delta < 5


class TestFormatEvents:
    """Test format_events functionality."""

    def test_format_events_with_event_time(self):
        """
        Given:
            - Events with eventTime field
        When:
            - Calling format_events
        Then:
            - Ensure _time is set to eventTime
        """
        # Load real test data and use first event (has eventTime)
        events_data = load_test_data("output-get-events.json")
        events = [events_data[0]]

        formatted = format_events(events)

        assert len(formatted) == 1
        assert formatted[0]["_time"] == events_data[0]["eventTime"]
        assert formatted[0]["logicalId"] == events_data[0]["logicalId"]
        assert formatted[0]["message"] == events_data[0]["message"]

    def test_format_events_with_created_fallback(self):
        """
        Given:
            - Events with created field instead of eventTime
        When:
            - Calling format_events
        Then:
            - Ensure _time is set to created as fallback
        """
        # Create event with only created field (remove eventTime)
        events_data = load_test_data("output-get-events.json")
        event = events_data[1].copy()
        event_created_time = event["created"]
        del event["eventTime"]
        events = [event]

        formatted = format_events(events)

        assert len(formatted) == 1
        assert formatted[0]["_time"] == event_created_time

    def test_format_events_prioritizes_event_time_over_created(self):
        """
        Given:
            - Events with both eventTime and created fields
        When:
            - Calling format_events
        Then:
            - Ensure eventTime is prioritized
        """
        # Load real test data (has both eventTime and created)
        events_data = load_test_data("output-get-events.json")
        events = [events_data[0]]

        formatted = format_events(events)

        # Should use eventTime, not created
        assert formatted[0]["_time"] == events_data[0]["eventTime"]
        assert formatted[0]["_time"] != events_data[0]["created"]

    def test_format_events_skips_events_without_timestamp(self):
        """
        Given:
            - Mix of events with and without timestamps
        When:
            - Calling format_events
        Then:
            - Ensure events without timestamps are skipped
        """
        # Load real test data and create mix with one event missing timestamps
        events_data = load_test_data("output-get-events.json")
        event_with_timestamp = events_data[0]
        event_without_timestamp = events_data[1].copy()
        del event_without_timestamp["eventTime"]
        del event_without_timestamp["created"]
        event_with_created = events_data[2]

        events = [event_with_timestamp, event_without_timestamp, event_with_created]

        formatted = format_events(events)

        assert len(formatted) == 2
        logical_ids = [e["logicalId"] for e in formatted]
        assert event_with_timestamp["logicalId"] in logical_ids
        assert event_without_timestamp["logicalId"] not in logical_ids
        assert event_with_created["logicalId"] in logical_ids

    def test_format_events_empty_list(self):
        """
        Given:
            - Empty events list
        When:
            - Calling format_events
        Then:
            - Ensure empty list is returned
        """
        events = []

        formatted = format_events(events)

        assert isinstance(formatted, list)
        assert len(formatted) == 0

    def test_format_events_preserves_all_fields(self):
        """
        Given:
            - Events with multiple fields
        When:
            - Calling format_events
        Then:
            - Ensure all original fields are preserved and _time is added
        """
        # Load real test data with all fields
        events_data = load_test_data("output-get-events.json")
        events = [events_data[0]]

        formatted = format_events(events)

        # Verify _time is added using eventTime
        assert formatted[0]["_time"] == events_data[0]["eventTime"]
        # Verify all original fields are preserved
        assert formatted[0]["logicalId"] == events_data[0]["logicalId"]
        assert formatted[0]["category"] == events_data[0]["category"]
        assert formatted[0]["severity"] == events_data[0]["severity"]
        assert formatted[0]["message"] == events_data[0]["message"]
        assert formatted[0]["edgeName"] == events_data[0]["edgeName"]
        assert formatted[0]["event"] == events_data[0]["event"]
        assert formatted[0]["created"] == events_data[0]["created"]


class TestFetchEvents:
    """Test fetch_events functionality."""

    def test_fetch_events_successful(self, requests_mock, client):
        """
        Given:
            - VeloCloud client is configured
            - API returns events
        When:
            - Calling fetch_events
        Then:
            - Ensure events and last_timestamp are returned
        """
        events_data = load_test_data("output-get-events.json")
        expected_new_timestamp = events_data[0].get("eventTime", "")
        requests_mock.post(
            "https://tenant123.velocloud.net/portal/rest/event/getEnterpriseEvents",
            json={"data": events_data, "metadata": {}},
        )

        last_timestamp = ""
        first_fetch = "1 day ago"

        fetched_events, new_timestamp = fetch_events(client, last_timestamp, first_fetch, limit=1000)

        assert isinstance(fetched_events, list)
        assert len(fetched_events) == len(events_data)
        assert new_timestamp == expected_new_timestamp

    def test_fetch_events_with_pagination(self, requests_mock, client):
        """
        Given:
            - VeloCloud client is configured
            - API returns events with pagination metadata
        When:
            - Calling fetch_events
        Then:
            - Ensure pagination is handled correctly
        """
        # Load real pagination test data
        pagination_data = load_test_data("output-fetch-events-pagination.json")
        page1 = pagination_data["page1"]
        page2 = pagination_data["page2"]

        # First request returns first page with nextPageLink
        requests_mock.post(
            "https://tenant123.velocloud.net/portal/rest/event/getEnterpriseEvents",
            [
                {"json": page1},
                {"json": page2},
            ],
        )

        last_timestamp = ""
        first_fetch = "1 day ago"

        fetched_events, new_timestamp = fetch_events(client, last_timestamp, first_fetch, limit=100)

        # Dynamically extract expected logicalIds from pagination data
        expected_events = page1["data"] + page2["data"]
        expected_logicalIds = [event["logicalId"] for event in expected_events]

        assert len(fetched_events) == len(expected_logicalIds)
        for i, event in enumerate(fetched_events):
            assert event["logicalId"] == expected_logicalIds[i]


class TestFetchEventsCommand:
    """Test fetch_events_command functionality."""

    @patch("VeloCloudEventCollector.send_events_to_xsiam")
    @patch("VeloCloudEventCollector.demisto")
    def test_fetch_events_command_successful(self, mock_demisto, mock_send_events, requests_mock, client):
        """
        Given:
            - VeloCloud client is configured
            - demisto functions are mocked
        When:
            - Executing fetch_events_command
        Then:
            - Ensure events are sent to XSIAM and last run is updated
        """
        events_data = load_test_data("output-get-events.json")

        requests_mock.post(
            "https://tenant123.velocloud.net/portal/rest/event/getEnterpriseEvents",
            json={"data": events_data, "metadata": {}},
        )

        # Setup demisto mocks
        mock_demisto.params.return_value = {
            "first_fetch": "1 day ago",
            "max_fetch": 1000,
        }
        mock_demisto.getLastRun.return_value = {}

        fetch_events_command(client)

        # Verify send_events_to_xsiam was called
        assert mock_send_events.called
        # Verify setLastRun was called
        assert mock_demisto.setLastRun.called

    @patch("VeloCloudEventCollector.send_events_to_xsiam")
    @patch("VeloCloudEventCollector.demisto")
    def test_fetch_events_command_with_last_run(self, mock_demisto, mock_send_events, requests_mock, client):
        """
        Given:
            - VeloCloud client is configured
            - Last run timestamp exists
        When:
            - Executing fetch_events_command
        Then:
            - Ensure only new events are fetched
        """
        events_data = load_test_data("output-get-events.json")

        requests_mock.post(
            "https://tenant123.velocloud.net/portal/rest/event/getEnterpriseEvents",
            json={"data": events_data, "metadata": {}},
        )

        last_run_timestamp = "2025-11-02T10:00:00Z"
        mock_demisto.params.return_value = {
            "first_fetch": "1 day ago",
            "max_fetch": 1000,
        }
        mock_demisto.getLastRun.return_value = {"last_event_time": last_run_timestamp}

        fetch_events_command(client)

        assert mock_send_events.called
        assert mock_demisto.setLastRun.called

    @patch("VeloCloudEventCollector.send_events_to_xsiam")
    @patch("VeloCloudEventCollector.demisto")
    def test_fetch_events_command_no_events(self, mock_demisto, mock_send_events, requests_mock, client):
        """
        Given:
            - VeloCloud client is configured
            - API returns no events
        When:
            - Executing fetch_events_command
        Then:
            - Ensure command handles empty response gracefully
        """
        requests_mock.post(
            "https://tenant123.velocloud.net/portal/rest/event/getEnterpriseEvents",
            json={"data": [], "metadata": {}},
        )

        mock_demisto.params.return_value = {
            "first_fetch": "1 day ago",
            "max_fetch": 1000,
        }
        mock_demisto.getLastRun.return_value = {}

        fetch_events_command(client)

        # setLastRun should still be called even with no events
        assert mock_demisto.setLastRun.called
