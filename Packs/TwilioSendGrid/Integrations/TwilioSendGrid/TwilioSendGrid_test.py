import json
import queue
import threading
from typing import Any
from unittest.mock import MagicMock, patch

import pytest
from freezegun import freeze_time

from TwilioSendGrid import (
    Client,
    EventBatch,
    ProducerConsumerMetrics,
    _event_consumer,
    _event_producer,
    build_query_filter,
    deduplicate_events,
    enrich_events,
    fetch_events_command,
    get_events_command,
    get_last_event_time,
    sg_test_module,
    update_last_run,
)

DATE_FORMAT = "%Y-%m-%dT%H:%M:%SZ"


def load_test_data(filename: str) -> dict:
    """Load test data from a JSON file."""
    with open(f"test_data/{filename}") as f:
        return json.load(f)


@pytest.fixture
def client() -> Client:
    """Create a mock client for testing."""
    return Client(base_url="https://api.sendgrid.com", api_key="test_key")


@pytest.fixture
def mock_events() -> list[dict[str, Any]]:
    """Load mock events from test data."""
    return load_test_data("email_activity_response.json")["messages"]


""" HELPER FUNCTION TESTS """


@pytest.mark.parametrize(
    "from_time, to_time, expected_query",
    [
        (
            "2024-01-15T10:00:00Z",
            "2024-01-15T11:00:00Z",
            "last_event_time BETWEEN TIMESTAMP '2024-01-15T10:00:00Z' AND TIMESTAMP '2024-01-15T11:00:00Z'",
        ),
        ("2024-01-15T10:00:00Z", None, "last_event_time > TIMESTAMP '2024-01-15T10:00:00Z'"),
    ],
)
def test_build_query_filter(from_time: str, to_time: str | None, expected_query: str, capfd):
    """Test the build_query_filter function."""
    with capfd.disabled():
        assert build_query_filter(from_time, to_time) == expected_query


@freeze_time("2024-01-15 12:00:00")
@pytest.mark.parametrize(
    "last_run, expected_time",
    [
        ({"last_event_time": "2024-01-15T10:00:00Z"}, "2024-01-15T10:00:00Z"),
        ({}, "2024-01-15T11:59:00Z"),  # Changed from 11:30 to 11:59 (1 minute ago)
    ],
)
def test_get_last_event_time(last_run: dict[str, Any], expected_time: str, capfd):
    """Test the get_last_event_time function."""
    with capfd.disabled():
        assert get_last_event_time(last_run) == expected_time


def test_enrich_events(mock_events: list[dict[str, Any]]):
    """Test the enrich_events function."""
    enriched = enrich_events(mock_events)
    for event in enriched:
        assert "_time" in event
        assert "source_log_type" in event
        assert event["_time"] == event["last_event_time"]
        assert event["source_log_type"] == "email_activity"


def test_update_last_run(mock_events: list[dict[str, Any]], capfd):
    """Test the update_last_run function."""
    with capfd.disabled():
        last_run: dict[str, Any] = {}
        previous_ids = {"msg_xyz789abc123"}
        updated_last_run = update_last_run(last_run, mock_events, previous_ids)

        assert "last_event_time" in updated_last_run
        assert "previous_ids" in updated_last_run
        assert updated_last_run["last_event_time"] == "2024-01-15T10:40:00Z"
        assert set(updated_last_run["previous_ids"]) == previous_ids


def test_deduplicate_events(mock_events: list[dict[str, Any]], capfd):
    """Test the deduplicate_events function."""
    with capfd.disabled():
        # Scenario 1: No duplicates
        unique_events, new_ids = deduplicate_events(mock_events, set(), "2024-01-15T10:00:00Z")
        assert len(unique_events) == 3
        assert len(new_ids) == 1

        # Scenario 2: One duplicate
        previous_ids = {"msg_abc123def456"}
        unique_events, new_ids = deduplicate_events(mock_events, previous_ids, "2024-01-15T10:30:00Z")
        assert len(unique_events) == 2
        assert "msg_abc123def456" not in [e["msg_id"] for e in unique_events]

        # Scenario 3: All duplicates
        previous_ids = {e["msg_id"] for e in mock_events}
        unique_events, new_ids = deduplicate_events(mock_events, previous_ids, "2024-01-15T10:40:00Z")
        assert len(unique_events) == 0


""" CLIENT CLASS TESTS """


def test_client_get_email_activity_success(client: Client, mock_events: list[dict[str, Any]], capfd):
    """Test the get_email_activity method for a successful API call."""
    with capfd.disabled(), patch.object(client, "_http_request") as mock_http:
        mock_http.return_value = {"messages": mock_events}
        query = "last_event_time > TIMESTAMP '2024-01-15T10:00:00Z'"
        events = client.get_email_activity(query=query, limit=100)

        assert events == mock_events
        mock_http.assert_called_once_with(
            method="GET",
            url_suffix="/v3/messages",
            params={"query": query, "limit": 100},
            timeout=60,
            retries=3,
            backoff_factor=2,
        )


@pytest.mark.parametrize(
    "status_code, error_message, expected_exception",
    [
        (401, "Unauthorized", "Authentication failed"),
        (403, "Forbidden", "Authentication failed"),
        (429, "Rate limit exceeded", "Rate limit hit"),
        (500, "Internal Server Error", "Server error"),
    ],
)
def test_client_get_email_activity_error_handling(
    client: Client, status_code: int, error_message: str, expected_exception: str, capfd
):
    """Test the error handling in the get_email_activity method."""
    from CommonServerPython import DemistoException

    with capfd.disabled(), patch.object(client, "_http_request") as mock_http:
        mock_http.side_effect = DemistoException(f"[{status_code}] {error_message}")

        with pytest.raises(DemistoException) as excinfo:
            client.get_email_activity(query="test", limit=100)

        assert expected_exception in str(excinfo.value)


def test_client_invalid_limit(client: Client):
    """Test that an invalid limit raises a DemistoException."""
    with pytest.raises(Exception) as excinfo:
        client.get_email_activity(query="test", limit=0)
    assert "Limit must be between 1 and 1000" in str(excinfo.value)

    with pytest.raises(Exception) as excinfo:
        client.get_email_activity(query="test", limit=1001)
    assert "Limit must be between 1 and 1000" in str(excinfo.value)


""" COMMAND FUNCTION TESTS """


def test_sg_test_module_success(client: Client, capfd):
    """Test the sg_test_module for a successful connection."""
    with capfd.disabled(), patch.object(client, "get_email_activity", return_value=[]) as mock_get_activity:
        result = sg_test_module(client)
        assert result == "ok"
        mock_get_activity.assert_called_once()


def test_sg_test_module_failure(client: Client, capfd):
    """Test the sg_test_module for a failed connection."""
    with (
        capfd.disabled(),
        patch.object(client, "get_email_activity", side_effect=Exception("API error")),
        pytest.raises(Exception) as excinfo,
    ):
        sg_test_module(client)
    assert "Test failed: API error" in str(excinfo.value)


def test_get_events_command(client: Client, mock_events: list[dict[str, Any]], capfd):
    """Test the get_events_command."""
    with capfd.disabled(), patch.object(client, "get_email_activity", return_value=mock_events) as mock_get_activity:
        args = {"limit": "10"}
        last_run: dict[str, Any] = {}
        events, results = get_events_command(client, args, last_run)

        assert len(events) == 3
        assert "Twilio SendGrid Email Activity Events" in results.readable_output
        mock_get_activity.assert_called_once()


@patch("TwilioSendGrid.send_events_to_xsiam")
def test_fetch_events_command(mock_send_events: MagicMock, client: Client, mock_events: list[dict[str, Any]], capfd):
    """Test the fetch_events_command with the producer-consumer model."""
    with capfd.disabled(), patch.object(client, "get_email_activity") as mock_get_activity:
        # Simulate two batches of events
        mock_get_activity.side_effect = [mock_events, []]
        last_run: dict[str, Any] = {}
        events, next_run = fetch_events_command(client, last_run, max_fetch=100)

        assert events == []  # fetch_events_command now returns an empty list
        assert "last_event_time" in next_run
        assert "previous_ids" in next_run
        assert mock_send_events.called


@patch("TwilioSendGrid.send_events_to_xsiam")
def test_fetch_events_command_no_events(mock_send_events: MagicMock, client: Client, capfd):
    """Test the fetch_events_command when no new events are found."""
    with capfd.disabled(), patch.object(client, "get_email_activity", return_value=[]) as mock_get_activity:
        last_run: dict[str, Any] = {"last_event_time": "2024-01-15T12:00:00Z"}
        events, next_run = fetch_events_command(client, last_run, max_fetch=100)

        assert events == []
        assert next_run == last_run  # last_run should be unchanged
        mock_get_activity.assert_called_once()
        mock_send_events.assert_not_called()


""" PRODUCER-CONSUMER TESTS """


@patch("TwilioSendGrid.send_events_to_xsiam")
@patch("TwilioSendGrid._event_consumer")
@patch("TwilioSendGrid._event_producer")
def test_fetch_events_producer_consumer_orchestration(
    mock_producer: MagicMock, mock_consumer: MagicMock, mock_send_events: MagicMock, client: Client, capfd
):
    """Test that the main producer-consumer function orchestrates the threads correctly."""
    with capfd.disabled():
        last_run: dict[str, Any] = {}
        fetch_events_command(client, last_run, max_fetch=100)

        # Assert that producer and consumer threads were started
        assert mock_producer.called
        assert mock_consumer.called


@patch("queue.Queue")
def test_producer_stops_when_no_events(mock_queue: MagicMock, client: Client, capfd):
    """Test that the producer stops when the API returns no events."""
    with capfd.disabled(), patch.object(client, "get_email_activity", return_value=[]) as mock_get_activity:
        metrics = ProducerConsumerMetrics()
        stop_event = threading.Event()
        event_queue: queue.Queue = mock_queue()

        _event_producer(client, event_queue, stop_event, metrics, {}, 100)

        mock_get_activity.assert_called_once()
        assert stop_event.is_set()
        assert metrics.events_produced == 0


@patch("TwilioSendGrid.send_events_to_xsiam")
def test_consumer_processes_batch(mock_send_events: MagicMock, mock_events: list[dict[str, Any]], capfd):
    """Test that the consumer correctly processes a batch of events."""
    with capfd.disabled():
        metrics = ProducerConsumerMetrics()
        stop_event = threading.Event()
        event_queue: queue.Queue = queue.Queue()
        last_run: dict[str, Any] = {"previous_ids": [], "last_event_time": "2024-01-15T10:00:00Z"}

        # Put a batch in the queue
        event_batch = EventBatch(events=mock_events, batch_id=1)
        event_queue.put(event_batch)

        # Stop the consumer after one loop
        stop_event.set()

        _event_consumer(event_queue, stop_event, metrics, last_run)

        mock_send_events.assert_called_once()
        assert metrics.events_consumed == 3
        assert "last_event_time" in last_run
        assert last_run["last_event_time"] == "2024-01-15T10:40:00Z"
