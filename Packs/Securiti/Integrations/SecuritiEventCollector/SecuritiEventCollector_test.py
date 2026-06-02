import pytest
from unittest.mock import patch
from SecuritiEventCollector import (
    Client,
    fetch_events,
    get_events_command,
    test_module,
    add_time_to_events,
    dedup_events,
    get_events_for_type,
)


def create_client() -> Client:
    """Create a test client instance."""
    return Client(
        base_url="https://test.securiti.ai",
        api_key="test_api_key",
        api_secret="test_api_secret",
        tenant_id="test_tenant_id",
        verify=False,
        proxy=False,
    )


def generate_events(count: int, start_time: int = 1000000, start_id: int = 1, same_time: bool = False) -> list[dict]:
    """Generate mock events for testing.

    Args:
        count: Number of events to generate.
        start_time: Starting event_time in epoch ms.
        start_id: Starting ID number.
        same_time: If True, all events share the same event_time.

    Returns:
        List of mock event dictionaries.
    """
    events = []
    for i in range(count):
        event_time = start_time if same_time else start_time + i
        events.append({
            "id": f"event_{start_id + i}",
            "event_time": event_time,
            "activity_type": "login",
            "object_type": "session",
            "user_email": f"user{start_id + i}@test.com",
            "message": f"Test event {start_id + i}",
            "ip_address": "127.0.0.1",
        })
    return events


class TestAddTimeToEvents:
    """Tests for the add_time_to_events function."""

    def test_add_time_to_events_with_valid_events(self):
        """
        Given:
            A list of events with event_time fields.
        When:
            add_time_to_events is called.
        Then:
            Each event should have a _time field derived from event_time.
        """
        events = generate_events(2, start_time=1618933647673)
        add_time_to_events(events)

        assert events[0].get("_time") is not None
        assert events[1].get("_time") is not None

    def test_add_time_to_events_with_none(self):
        """
        Given:
            None is passed as events.
        When:
            add_time_to_events is called.
        Then:
            No exception should be raised.
        """
        add_time_to_events(None)

    def test_add_time_to_events_with_empty_list(self):
        """
        Given:
            An empty list of events.
        When:
            add_time_to_events is called.
        Then:
            No exception should be raised.
        """
        add_time_to_events([])

    def test_add_time_to_events_missing_event_time(self):
        """
        Given:
            An event without an event_time field.
        When:
            add_time_to_events is called.
        Then:
            The _time field should not be set.
        """
        events = [{"id": "1", "message": "no time"}]
        add_time_to_events(events)
        assert "_time" not in events[0]


class TestDedupEvents:
    """Tests for the dedup_events function."""

    def test_dedup_removes_known_ids(self):
        """
        Given:
            Events with IDs that overlap with last_run_ids.
        When:
            dedup_events is called.
        Then:
            Events with matching IDs should be removed.
        """
        events = generate_events(5)
        last_run_ids = ["event_1", "event_2"]

        result = dedup_events(events, last_run_ids)

        assert len(result) == 3
        result_ids = [e["id"] for e in result]
        assert "event_1" not in result_ids
        assert "event_2" not in result_ids

    def test_dedup_with_empty_last_run_ids(self):
        """
        Given:
            Events and an empty last_run_ids list.
        When:
            dedup_events is called.
        Then:
            All events should be returned unchanged.
        """
        events = generate_events(3)
        result = dedup_events(events, [])
        assert len(result) == 3

    def test_dedup_with_no_overlap(self):
        """
        Given:
            Events whose IDs don't overlap with last_run_ids.
        When:
            dedup_events is called.
        Then:
            All events should be returned unchanged.
        """
        events = generate_events(3, start_id=10)
        last_run_ids = ["event_1", "event_2"]

        result = dedup_events(events, last_run_ids)
        assert len(result) == 3

    def test_dedup_all_duplicates(self):
        """
        Given:
            All events are duplicates.
        When:
            dedup_events is called.
        Then:
            An empty list should be returned.
        """
        events = generate_events(3)
        last_run_ids = ["event_1", "event_2", "event_3"]

        result = dedup_events(events, last_run_ids)
        assert len(result) == 0


class TestGetEventsForType:
    """Tests for the get_events_for_type pagination function."""

    def test_single_page_fetch(self):
        """
        Given:
            The API returns fewer events than the limit (partial page).
        When:
            get_events_for_type is called.
        Then:
            All events should be returned, pagination should stop,
            and next_run should reflect the last event's timestamp with boundary IDs.
        """
        mock_events = generate_events(3, start_time=1000)
        client = create_client()

        with patch.object(client, "get_audit_trail_events", return_value=mock_events):
            events, next_run = get_events_for_type(
                client=client,
                from_time=1000,
                last_run_ids=[],
                start_offset=0,
                max_events=100,
            )

        assert len(events) == 3
        assert next_run["from_time"] == 1002  # last event's time
        assert "event_3" in next_run["last_fetched_ids"]
        assert next_run["offset"] == 0  # normal case, no offset

    def test_multi_page_fetch(self):
        """
        Given:
            The API returns full pages requiring multiple requests.
        When:
            get_events_for_type is called with max_events > page size.
        Then:
            Events from all pages should be collected.
        """
        page1 = generate_events(10, start_time=1000, start_id=1)
        page2 = generate_events(5, start_time=1010, start_id=11)

        client = create_client()

        with patch.object(client, "get_audit_trail_events", side_effect=[page1, page2]):
            events, next_run = get_events_for_type(
                client=client,
                from_time=1000,
                last_run_ids=[],
                start_offset=0,
                max_events=20,
            )

        assert len(events) == 15
        assert next_run["from_time"] == 1014

    def test_empty_response_preserves_state(self):
        """
        Given:
            The API returns an empty response.
        When:
            get_events_for_type is called.
        Then:
            An empty list should be returned and next_run should preserve
            the original from_time and last_run_ids.
        """
        client = create_client()

        with patch.object(client, "get_audit_trail_events", return_value=[]):
            events, next_run = get_events_for_type(
                client=client,
                from_time=5000,
                last_run_ids=["old_id"],
                start_offset=0,
                max_events=100,
            )

        assert len(events) == 0
        assert next_run["from_time"] == 5000
        assert next_run["last_fetched_ids"] == ["old_id"]

    def test_dedup_on_first_page(self):
        """
        Given:
            The first page contains events that overlap with last_run_ids.
        When:
            get_events_for_type is called.
        Then:
            Duplicate events should be removed from the first page only.
        """
        mock_events = generate_events(5, start_time=1000)
        client = create_client()

        with patch.object(client, "get_audit_trail_events", return_value=mock_events):
            events, next_run = get_events_for_type(
                client=client,
                from_time=1000,
                last_run_ids=["event_1", "event_2"],
                start_offset=0,
                max_events=100,
            )

        assert len(events) == 3
        assert events[0]["id"] == "event_3"

    def test_offset_exceeds_max_switches_to_time_based(self):
        """
        Given:
            Pagination offset would exceed API_MAX_OFFSET (10000)
            and events have different timestamps.
        When:
            get_events_for_type is called.
        Then:
            Pagination should switch to time-based continuation by advancing
            from_time to the last event's event_time, resetting offset,
            and tracking boundary IDs for dedup.
        """
        page1 = generate_events(5000, start_time=1000, start_id=1)
        page2 = generate_events(5000, start_time=6000, start_id=5001)
        # After offset reaches 10000, should switch to time-based
        page3 = generate_events(100, start_time=11000, start_id=10001)

        client = create_client()

        with patch.object(client, "get_audit_trail_events", side_effect=[page1, page2, page3]):
            events, next_run = get_events_for_type(
                client=client,
                from_time=1000,
                last_run_ids=[],
                start_offset=0,
                max_events=15000,
            )

        assert len(events) == 10100
        assert next_run["offset"] == 0  # normal case

    def test_all_same_timestamp_full_page_at_offset_boundary_saves_offset(self):
        """
        Given:
            All events on a full page share the same event_time at the offset
            boundary (offset would exceed API_MAX_OFFSET).
        When:
            get_events_for_type processes the page.
        Then:
            The function should save the offset in next_run (special case)
            instead of advancing time, to avoid losing events.
            No dedup IDs should be stored since offset handles resumption.
        """
        # All events have the same timestamp
        page1 = generate_events(5000, start_time=1000, start_id=1, same_time=True)
        page2 = generate_events(5000, start_time=1000, start_id=5001, same_time=True)

        client = create_client()

        with patch.object(client, "get_audit_trail_events", side_effect=[page1, page2]):
            events, next_run = get_events_for_type(
                client=client,
                from_time=1000,
                last_run_ids=[],
                start_offset=0,
                max_events=20000,
            )

        assert len(events) == 10000
        # Special case: offset should be saved
        assert next_run["from_time"] == 1000
        assert next_run["offset"] == 10000
        assert next_run["last_fetched_ids"] == []

    def test_resume_from_saved_offset(self):
        """
        Given:
            A previous fetch stopped at the special case (all same timestamp,
            offset boundary) and saved offset=10000 in last_run.
        When:
            The next fetch resumes with start_offset=10000.
        Then:
            Events should be fetched starting from offset 10000 at the same
            timestamp, continuing without data loss.
        """
        # Resuming from offset 10000 at timestamp 1000
        page = generate_events(500, start_time=1000, start_id=10001, same_time=True)

        client = create_client()

        with patch.object(client, "get_audit_trail_events", return_value=page) as mock_fetch:
            events, next_run = get_events_for_type(
                client=client,
                from_time=1000,
                last_run_ids=[],
                start_offset=10000,
                max_events=5000,
            )

        assert len(events) == 500
        # Verify the API was called with offset=10000
        call_args = mock_fetch.call_args
        assert call_args.kwargs["offset"] == 10000

    def test_partial_page_stops_pagination(self):
        """
        Given:
            The API returns fewer events than the requested limit (partial page).
        When:
            get_events_for_type processes the response.
        Then:
            Pagination should stop immediately since a partial page means
            there are no more events available.
        """
        partial_page = generate_events(30, start_time=1000)
        client = create_client()

        call_count = 0

        def mock_fetch(**kwargs):
            nonlocal call_count
            call_count += 1
            return partial_page

        with patch.object(client, "get_audit_trail_events", side_effect=mock_fetch):
            events, next_run = get_events_for_type(
                client=client,
                from_time=1000,
                last_run_ids=[],
                start_offset=0,
                max_events=1000,
            )

        # Should have made exactly 1 API call since partial page = no more data
        assert call_count == 1
        assert len(events) == 30
        assert next_run["from_time"] == 1029  # last event's time

    def test_max_events_stops_and_saves_state(self):
        """
        Given:
            max_events is reached before all available events are fetched.
        When:
            get_events_for_type is called with max_events=50.
        Then:
            Exactly max_events should be returned, and next_run should contain
            the from_time and boundary IDs so the next fetch resumes correctly.
        """
        page = generate_events(50, start_time=1000)
        client = create_client()

        with patch.object(client, "get_audit_trail_events", return_value=page):
            events, next_run = get_events_for_type(
                client=client,
                from_time=1000,
                last_run_ids=[],
                start_offset=0,
                max_events=50,
            )

        assert len(events) == 50
        assert next_run["from_time"] == 1049
        assert "event_50" in next_run["last_fetched_ids"]

    def test_boundary_ids_tracked_correctly(self):
        """
        Given:
            Multiple events share the same event_time at the end of a fetch.
        When:
            get_events_for_type completes.
        Then:
            next_run should contain all IDs at the boundary timestamp
            so they can be deduplicated on the next fetch.
        """
        events = [
            {"id": "a", "event_time": 1000, "activity_type": "login"},
            {"id": "b", "event_time": 1001, "activity_type": "login"},
            {"id": "c", "event_time": 1001, "activity_type": "create"},
            {"id": "d", "event_time": 1001, "activity_type": "delete"},
        ]
        client = create_client()

        with patch.object(client, "get_audit_trail_events", return_value=events):
            _, next_run = get_events_for_type(
                client=client,
                from_time=1000,
                last_run_ids=[],
                start_offset=0,
                max_events=100,
            )

        assert next_run["from_time"] == 1001
        assert set(next_run["last_fetched_ids"]) == {"b", "c", "d"}

    def test_all_duplicates_advances_offset(self):
        """
        Given:
            All events returned are duplicates of previously fetched events
            and offset has not reached the max.
        When:
            get_events_for_type processes the page.
        Then:
            Offset should advance and retry.
        """
        dup_events = generate_events(3, start_time=1000)
        new_events = generate_events(2, start_time=1001, start_id=10)

        client = create_client()

        with patch.object(client, "get_audit_trail_events", side_effect=[dup_events, new_events]):
            events, next_run = get_events_for_type(
                client=client,
                from_time=1000,
                last_run_ids=["event_1", "event_2", "event_3"],
                start_offset=0,
                max_events=100,
            )

        assert len(events) == 2
        assert events[0]["id"] == "event_10"

    def test_different_timestamps_at_offset_boundary_uses_dedup(self):
        """
        Given:
            Events at the offset boundary have different timestamps
            (not all the same).
        When:
            Offset would exceed API_MAX_OFFSET.
        Then:
            from_time should advance to the last event's timestamp (NOT save offset)
            and boundary IDs should be tracked for dedup.
        """
        # Mix of timestamps - last event has time 2000
        events = [
            {"id": f"e{i}", "event_time": 1000 + (i % 3) * 500}
            for i in range(5000)
        ]
        events[-1]["event_time"] = 2000
        events[-1]["id"] = "last_event"

        client = create_client()

        with patch.object(client, "get_audit_trail_events", side_effect=[events, []]):
            result_events, next_run = get_events_for_type(
                client=client,
                from_time=1000,
                last_run_ids=[],
                start_offset=0,
                max_events=10000,
            )

        # Should use time-based (dedup), NOT offset-based
        assert next_run["from_time"] == 2000
        assert next_run["offset"] == 0
        assert "last_event" in next_run["last_fetched_ids"]


class TestFetchEvents:
    """Tests for the fetch_events function."""

    def test_fetch_events_first_run(self):
        """
        Given:
            First fetch run with empty last_run.
        When:
            fetch_events is called.
        Then:
            Events should be fetched starting from 1 minute ago (default).
        """
        mock_events = generate_events(3, start_time=1000)
        client = create_client()

        with patch.object(client, "get_audit_trail_events", return_value=mock_events):
            next_run, events = fetch_events(
                client=client,
                last_run={},
                max_events_per_fetch=100,
                fetch_audit_trails=True,
            )

        assert len(events) == 3
        assert "audit_trail" in next_run
        assert next_run["audit_trail"]["from_time"] == 1002

    def test_fetch_events_subsequent_run_with_dedup(self):
        """
        Given:
            A subsequent fetch run with existing last_run state (normal case with IDs).
        When:
            fetch_events is called.
        Then:
            Events should be fetched from the stored from_time with deduplication.
        """
        mock_events = generate_events(5, start_time=2000)
        client = create_client()

        last_run = {
            "audit_trail": {
                "from_time": 2000,
                "offset": 0,
                "last_fetched_ids": ["event_1"],
            }
        }

        with patch.object(client, "get_audit_trail_events", return_value=mock_events):
            next_run, events = fetch_events(
                client=client,
                last_run=last_run,
                max_events_per_fetch=100,
                fetch_audit_trails=True,
            )

        # event_1 should be deduped
        assert len(events) == 4
        assert events[0]["id"] == "event_2"

    def test_fetch_events_subsequent_run_with_offset(self):
        """
        Given:
            A subsequent fetch run resuming from the special case (saved offset).
        When:
            fetch_events is called.
        Then:
            Events should be fetched using the saved offset, no dedup needed.
        """
        mock_events = generate_events(3, start_time=1000, start_id=10001, same_time=True)
        client = create_client()

        last_run = {
            "audit_trail": {
                "from_time": 1000,
                "offset": 10000,
                "last_fetched_ids": [],
            }
        }

        with patch.object(client, "get_audit_trail_events", return_value=mock_events) as mock_fetch:
            next_run, events = fetch_events(
                client=client,
                last_run=last_run,
                max_events_per_fetch=100,
                fetch_audit_trails=True,
            )

        assert len(events) == 3
        # Verify offset was passed to the API
        call_args = mock_fetch.call_args
        assert call_args.kwargs["offset"] == 10000

    def test_fetch_events_audit_trails_disabled(self):
        """
        Given:
            fetch_audit_trails is set to False.
        When:
            fetch_events is called.
        Then:
            No events should be fetched and next_run should be empty.
        """
        client = create_client()

        next_run, events = fetch_events(
            client=client,
            last_run={},
            max_events_per_fetch=100,
            fetch_audit_trails=False,
        )

        assert len(events) == 0
        assert next_run == {}

    def test_fetch_events_uses_stored_from_time(self):
        """
        Given:
            A last_run with a stored from_time.
        When:
            fetch_events is called.
        Then:
            The stored from_time should be used, not the default first fetch time.
        """
        mock_events = generate_events(2, start_time=5000)
        client = create_client()

        last_run = {
            "audit_trail": {
                "from_time": 5000,
                "offset": 0,
                "last_fetched_ids": [],
            }
        }

        with patch.object(client, "get_audit_trail_events", return_value=mock_events) as mock_fetch:
            fetch_events(
                client=client,
                last_run=last_run,
                max_events_per_fetch=100,
                fetch_audit_trails=True,
            )

        call_args = mock_fetch.call_args
        assert call_args.kwargs["from_time"] == 5000


class TestTestModule:
    """Tests for the test_module function."""

    def test_test_module_success(self):
        """
        Given:
            A valid API connection.
        When:
            test_module is called.
        Then:
            'ok' should be returned.
        """
        client = create_client()

        with patch.object(client, "get_audit_trail_events", return_value=[]):
            result = test_module(client, {})

        assert result == "ok"

    def test_test_module_auth_error(self):
        """
        Given:
            An invalid API key causing a Forbidden error.
        When:
            test_module is called.
        Then:
            An authorization error message should be returned.
        """
        client = create_client()

        with patch.object(client, "get_audit_trail_events", side_effect=Exception("403 Forbidden")):
            result = test_module(client, {})

        assert "Authorization Error" in result

    def test_test_module_unexpected_error(self):
        """
        Given:
            An unexpected error occurs.
        When:
            test_module is called.
        Then:
            The exception should be re-raised.
        """
        client = create_client()

        with patch.object(client, "get_audit_trail_events", side_effect=Exception("Connection timeout")):
            with pytest.raises(Exception, match="Connection timeout"):
                test_module(client, {})


class TestGetEventsCommand:
    """Tests for the get_events_command function."""

    def test_get_events_command_default_args(self):
        """
        Given:
            Default command arguments.
        When:
            get_events_command is called.
        Then:
            Events and human-readable output should be returned.
        """
        mock_events = generate_events(3, start_time=1000)
        client = create_client()

        with patch.object(client, "get_audit_trail_events", return_value=mock_events):
            events, results = get_events_command(client, {})

        assert len(events) == 3
        assert "Securiti Audit Trail Events" in results.readable_output

    def test_get_events_command_with_limit(self):
        """
        Given:
            A limit argument is provided.
        When:
            get_events_command is called.
        Then:
            No more than limit events should be returned.
        """
        mock_events = generate_events(5, start_time=1000)
        client = create_client()

        with patch.object(client, "get_audit_trail_events", return_value=mock_events):
            events, results = get_events_command(client, {"limit": "5"})

        assert len(events) == 5

    def test_get_events_command_with_from_date(self):
        """
        Given:
            A from_date argument is provided.
        When:
            get_events_command is called.
        Then:
            Events should be fetched from the specified date.
        """
        mock_events = generate_events(2, start_time=1618933647673)
        client = create_client()

        with patch.object(client, "get_audit_trail_events", return_value=mock_events) as mock_fetch:
            events, results = get_events_command(client, {"from_date": "2021-04-20T15:00:00Z"})

        assert len(events) == 2
        call_args = mock_fetch.call_args
        assert call_args.kwargs["from_time"] > 0


class TestClientHeaders:
    """Tests for the Client class header configuration."""

    def test_client_sets_correct_headers(self):
        """
        Given:
            API key, secret, and tenant ID.
        When:
            A Client is created.
        Then:
            The correct headers should be set.
        """
        client = create_client()

        assert client._headers["X-API-KEY"] == "test_api_key"
        assert client._headers["X-API-SECRET"] == "test_api_secret"
        assert client._headers["X-TIDENT"] == "test_tenant_id"
        assert client._headers["Content-Type"] == "application/json"
