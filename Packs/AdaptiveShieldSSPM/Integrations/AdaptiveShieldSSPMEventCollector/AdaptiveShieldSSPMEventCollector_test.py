import pytest
import demistomock as demisto
from AdaptiveShieldSSPMEventCollector import (
    Client,
    AdaptiveShieldSSPMParams,
    fetch_events_command,
    get_events_command,
    test_module_command,
)
import AdaptiveShieldSSPMEventCollector


NEXT_PAGE_URI = "https://api.adaptive-shield.com/api/v1/accounts/ACCT/security_checks?offset={offset}&limit={limit}"


def mock_params() -> AdaptiveShieldSSPMParams:
    return AdaptiveShieldSSPMParams(
        url="https://api.adaptive-shield.com",
        account_id="test-account",
        credentials={"password": "test-api-key"},
        max_fetch=1000,
    )


def mock_client(mocker) -> Client:
    """Create a Client instance without making real HTTP calls during __init__."""
    mocker.patch.object(Client, "__init__", return_value=None)
    client = Client.__new__(Client)
    client.account_id = "test-account"
    client.api_key = "test-api-key"
    return client


class TestGetSecurityChecksWithPagination:
    """Tests for Client.get_security_checks_with_pagination."""

    def test_single_page_no_next(self, mocker):
        """
        Given:
            - A single page response with no next_page_uri.
        When:
            - Calling get_security_checks_with_pagination.
        Then:
            - All items are returned and offset stays at initial value.
        """
        client = mock_client(mocker)
        response = {
            "data": [
                {"id": "1", "creation_date": "2026-01-01T00:00:00Z"},
                {"id": "2", "creation_date": "2026-01-02T00:00:00Z"},
            ],
            "total_size": 2,
        }
        mocker.patch.object(client, "get_security_checks", return_value=response)

        events, offset = client.get_security_checks_with_pagination(max_fetch=10)

        assert len(events) == 2
        assert events[0]["id"] == "1"
        assert events[1]["id"] == "2"
        assert offset == 0
        for event in events:
            assert "_time" in event

    def test_multi_page_pagination(self, mocker):
        """
        Given:
            - Two pages of results with next_page_uri on the first page.
        When:
            - Calling get_security_checks_with_pagination.
        Then:
            - Events from both pages are returned and offset advances.
        """
        client = mock_client(mocker)
        page1 = {
            "data": [
                {"id": "1", "creation_date": "2026-01-01T00:00:00Z"},
                {"id": "2", "creation_date": "2026-01-02T00:00:00Z"},
            ],
            "total_size": 4,
            "next_page_uri": NEXT_PAGE_URI.format(offset=2, limit=2),
        }
        page2 = {
            "data": [
                {"id": "3", "creation_date": "2026-01-03T00:00:00Z"},
                {"id": "4", "creation_date": "2026-01-04T00:00:00Z"},
            ],
            "total_size": 4,
        }
        mocker.patch.object(client, "get_security_checks", side_effect=[page1, page2])

        events, offset = client.get_security_checks_with_pagination(max_fetch=10)

        assert len(events) == 4
        assert [e["id"] for e in events] == ["1", "2", "3", "4"]
        assert offset == 2  # Advanced from first page's next_page_uri

    def test_max_fetch_limits_results(self, mocker):
        """
        Given:
            - A page with more items than max_fetch allows.
        When:
            - Calling get_security_checks_with_pagination with max_fetch=2.
        Then:
            - Only max_fetch events are returned.
        """
        client = mock_client(mocker)
        response = {
            "data": [
                {"id": "1", "creation_date": "2026-01-01T00:00:00Z"},
                {"id": "2", "creation_date": "2026-01-02T00:00:00Z"},
                {"id": "3", "creation_date": "2026-01-03T00:00:00Z"},
            ],
            "total_size": 3,
            "next_page_uri": NEXT_PAGE_URI.format(offset=3, limit=3),
        }
        mocker.patch.object(client, "get_security_checks", return_value=response)

        events, offset = client.get_security_checks_with_pagination(max_fetch=2)

        assert len(events) == 2

    def test_deduplication_by_last_fetched_ids(self, mocker):
        """
        Given:
            - Events at the same timestamp as last_run_date, some already fetched.
        When:
            - Calling get_security_checks_with_pagination with last_fetched_ids.
        Then:
            - Already-fetched events are skipped.
        """
        client = mock_client(mocker)
        response = {
            "data": [
                {"id": "1", "creation_date": "2026-01-01T00:00:00Z"},
                {"id": "2", "creation_date": "2026-01-01T00:00:00Z"},
                {"id": "3", "creation_date": "2026-01-02T00:00:00Z"},
            ],
            "total_size": 3,
        }
        mocker.patch.object(client, "get_security_checks", return_value=response)

        events, _ = client.get_security_checks_with_pagination(
            max_fetch=10,
            last_run_date="2026-01-01T00:00:00Z",
            last_fetched_ids=["1"],
        )

        assert len(events) == 2
        assert [e["id"] for e in events] == ["2", "3"]

    def test_skip_events_before_last_run_date(self, mocker):
        """
        Given:
            - Events with creation_date before last_run_date.
        When:
            - Calling get_security_checks_with_pagination.
        Then:
            - Events older than last_run_date are skipped.
        """
        client = mock_client(mocker)
        response = {
            "data": [
                {"id": "1", "creation_date": "2025-12-01T00:00:00Z"},
                {"id": "2", "creation_date": "2026-01-01T00:00:00Z"},
                {"id": "3", "creation_date": "2026-01-02T00:00:00Z"},
            ],
            "total_size": 3,
        }
        mocker.patch.object(client, "get_security_checks", return_value=response)

        events, _ = client.get_security_checks_with_pagination(
            max_fetch=10,
            last_run_date="2026-01-01T00:00:00Z",
        )

        assert len(events) == 2
        assert [e["id"] for e in events] == ["2", "3"]

    def test_skip_events_before_start_date(self, mocker):
        """
        Given:
            - Events with creation_date before start_date.
        When:
            - Calling get_security_checks_with_pagination with start_date.
        Then:
            - Events before start_date are skipped.
        """
        client = mock_client(mocker)
        response = {
            "data": [
                {"id": "1", "creation_date": "2025-12-01T00:00:00Z"},
                {"id": "2", "creation_date": "2026-01-15T00:00:00Z"},
            ],
            "total_size": 2,
        }
        mocker.patch.object(client, "get_security_checks", return_value=response)

        events, _ = client.get_security_checks_with_pagination(
            max_fetch=10,
            start_date="2026-01-01T00:00:00Z",
        )

        assert len(events) == 1
        assert events[0]["id"] == "2"

    def test_empty_response(self, mocker):
        """
        Given:
            - An empty data response from the API.
        When:
            - Calling get_security_checks_with_pagination.
        Then:
            - An empty list is returned.
        """
        client = mock_client(mocker)
        response = {"data": [], "total_size": 0}
        mocker.patch.object(client, "get_security_checks", return_value=response)

        events, offset = client.get_security_checks_with_pagination(max_fetch=10)

        assert events == []
        assert offset == 0

    def test_offset_not_advanced_when_last_item_filtered(self, mocker):
        """
        Given:
            - A page where the last item is filtered out (e.g., by deduplication).
            - The response has a next_page_uri.
        When:
            - Calling get_security_checks_with_pagination.
        Then:
            - The offset is NOT advanced because the last response item
              is not the last item in all_events.
        """
        client = mock_client(mocker)
        # All items at the same timestamp, and the last one ("3") is already fetched
        page1 = {
            "data": [
                {"id": "1", "creation_date": "2026-01-01T00:00:00Z"},
                {"id": "2", "creation_date": "2026-01-01T00:00:00Z"},
                {"id": "3", "creation_date": "2026-01-01T00:00:00Z"},
            ],
            "total_size": 6,
            "next_page_uri": NEXT_PAGE_URI.format(offset=3, limit=3),
        }
        page2 = {
            "data": [
                {"id": "4", "creation_date": "2026-01-02T00:00:00Z"},
            ],
            "total_size": 6,
        }
        mocker.patch.object(client, "get_security_checks", side_effect=[page1, page2])

        events, offset = client.get_security_checks_with_pagination(
            max_fetch=10,
            last_run_date="2026-01-01T00:00:00Z",
            last_fetched_ids=["3"],
        )

        # "3" is filtered out, so last item in page1 ("3") != last item in all_events ("2")
        # offset should NOT advance to 3
        assert "3" not in [e["id"] for e in events]
        assert offset == 0  # Stays at initial offset

    def test_offset_advanced_when_last_item_collected(self, mocker):
        """
        Given:
            - A page where the last item IS collected into all_events.
            - The response has a next_page_uri.
        When:
            - Calling get_security_checks_with_pagination.
        Then:
            - The offset IS advanced from the next_page_uri.
        """
        client = mock_client(mocker)
        page1 = {
            "data": [
                {"id": "1", "creation_date": "2026-01-01T00:00:00Z"},
                {"id": "2", "creation_date": "2026-01-02T00:00:00Z"},
                {"id": "3", "creation_date": "2026-01-03T00:00:00Z"},
            ],
            "total_size": 6,
            "next_page_uri": NEXT_PAGE_URI.format(offset=3, limit=3),
        }
        page2 = {
            "data": [
                {"id": "4", "creation_date": "2026-01-04T00:00:00Z"},
            ],
            "total_size": 6,
        }
        mocker.patch.object(client, "get_security_checks", side_effect=[page1, page2])

        events, offset = client.get_security_checks_with_pagination(max_fetch=10)

        assert len(events) == 4
        assert offset == 3  # Advanced from next_page_uri

    def test_initial_offset_used(self, mocker):
        """
        Given:
            - An initial_offset of 5.
        When:
            - Calling get_security_checks_with_pagination.
        Then:
            - The API is called with offset=5.
        """
        client = mock_client(mocker)
        response = {
            "data": [{"id": "6", "creation_date": "2026-01-06T00:00:00Z"}],
            "total_size": 6,
        }
        mock_get = mocker.patch.object(client, "get_security_checks", return_value=response)

        events, offset = client.get_security_checks_with_pagination(
            max_fetch=10,
            initial_offset=5,
        )

        mock_get.assert_called_once_with(limit=10, offset=5)
        assert len(events) == 1
        assert offset == 5

    def test_events_sorted_by_creation_date(self, mocker):
        """
        Given:
            - Events returned in non-chronological order.
        When:
            - Calling get_security_checks_with_pagination.
        Then:
            - Events are sorted by creation_date ascending.
        """
        client = mock_client(mocker)
        response = {
            "data": [
                {"id": "2", "creation_date": "2026-01-03T00:00:00Z"},
                {"id": "1", "creation_date": "2026-01-01T00:00:00Z"},
                {"id": "3", "creation_date": "2026-01-02T00:00:00Z"},
            ],
            "total_size": 3,
        }
        mocker.patch.object(client, "get_security_checks", return_value=response)

        events, _ = client.get_security_checks_with_pagination(max_fetch=10)

        assert [e["id"] for e in events] == ["1", "3", "2"]

    def test_time_field_set_on_events(self, mocker):
        """
        Given:
            - Events with creation_date.
        When:
            - Calling get_security_checks_with_pagination.
        Then:
            - Each event has '_time' set to its creation_date.
        """
        client = mock_client(mocker)
        response = {
            "data": [
                {"id": "1", "creation_date": "2026-01-01T00:00:00Z"},
            ],
            "total_size": 1,
        }
        mocker.patch.object(client, "get_security_checks", return_value=response)

        events, _ = client.get_security_checks_with_pagination(max_fetch=10)

        assert events[0]["_time"] == "2026-01-01T00:00:00Z"


class TestFetchEventsCommand:
    """Tests for fetch_events_command."""

    def test_first_fetch(self, mocker):
        """
        Given:
            - No previous last_run (first fetch).
        When:
            - Running fetch_events_command.
        Then:
            - Events are returned and last_run is populated.
        """
        client = mock_client(mocker)
        mock_events = [
            {"id": "1", "creation_date": "2026-01-01T00:00:00Z", "_time": "2026-01-01T00:00:00Z"},
            {"id": "2", "creation_date": "2026-01-02T00:00:00Z", "_time": "2026-01-02T00:00:00Z"},
        ]
        mocker.patch.object(
            client, "get_security_checks_with_pagination", return_value=(mock_events, 0)
        )

        events, last_run = fetch_events_command(client, max_fetch=10, last_run={})

        assert len(events) == 2
        assert last_run["last_run_date"] == "2026-01-02T00:00:00Z"
        assert last_run["last_fetched_ids"] == ["2"]
        assert last_run["offset"] == 0

    def test_fetch_with_existing_last_run(self, mocker):
        """
        Given:
            - An existing last_run with date and IDs.
        When:
            - Running fetch_events_command.
        Then:
            - last_run_date and last_fetched_ids are passed to pagination method.
        """
        client = mock_client(mocker)
        mock_events = [
            {"id": "3", "creation_date": "2026-01-03T00:00:00Z", "_time": "2026-01-03T00:00:00Z"},
        ]
        mock_pagination = mocker.patch.object(
            client, "get_security_checks_with_pagination", return_value=(mock_events, 5)
        )

        last_run = {
            "last_run_date": "2026-01-02T00:00:00Z",
            "last_fetched_ids": ["2"],
            "offset": 2,
        }
        events, new_last_run = fetch_events_command(client, max_fetch=10, last_run=last_run)

        # Verify the pagination method was called with the correct parameters
        call_kwargs = mock_pagination.call_args[1]
        assert call_kwargs["last_run_date"] == "2026-01-02T00:00:00Z"
        assert call_kwargs["last_fetched_ids"] == ["2"]
        assert call_kwargs["initial_offset"] == 2

        assert new_last_run["last_run_date"] == "2026-01-03T00:00:00Z"
        assert new_last_run["offset"] == 5

    def test_no_events_keeps_last_run(self, mocker):
        """
        Given:
            - No events returned from pagination.
        When:
            - Running fetch_events_command.
        Then:
            - The original last_run is preserved.
        """
        client = mock_client(mocker)
        mocker.patch.object(
            client, "get_security_checks_with_pagination", return_value=([], 0)
        )

        original_last_run = {
            "last_run_date": "2026-01-01T00:00:00Z",
            "last_fetched_ids": ["1"],
            "offset": 0,
        }
        events, last_run = fetch_events_command(client, max_fetch=10, last_run=original_last_run)

        assert events == []
        assert last_run == original_last_run

    def test_multiple_ids_at_same_timestamp(self, mocker):
        """
        Given:
            - Multiple events at the latest timestamp.
        When:
            - Running fetch_events_command.
        Then:
            - All IDs at the latest timestamp are stored in last_fetched_ids.
        """
        client = mock_client(mocker)
        mock_events = [
            {"id": "1", "creation_date": "2026-01-01T00:00:00Z", "_time": "2026-01-01T00:00:00Z"},
            {"id": "2", "creation_date": "2026-01-02T00:00:00Z", "_time": "2026-01-02T00:00:00Z"},
            {"id": "3", "creation_date": "2026-01-02T00:00:00Z", "_time": "2026-01-02T00:00:00Z"},
        ]
        mocker.patch.object(
            client, "get_security_checks_with_pagination", return_value=(mock_events, 0)
        )

        events, last_run = fetch_events_command(client, max_fetch=10, last_run={})

        assert last_run["last_run_date"] == "2026-01-02T00:00:00Z"
        assert sorted(last_run["last_fetched_ids"]) == ["2", "3"]


class TestGetEventsCommand:
    """Tests for get_events_command."""

    def test_get_events_returns_results(self, mocker):
        """
        Given:
            - A request to get events with limit=2.
        When:
            - Running get_events_command.
        Then:
            - CommandResults with events are returned.
        """
        client = mock_client(mocker)
        mock_events = [
            {"id": "1", "creation_date": "2026-01-01T00:00:00Z", "_time": "2026-01-01T00:00:00Z"},
            {"id": "2", "creation_date": "2026-01-02T00:00:00Z", "_time": "2026-01-02T00:00:00Z"},
        ]
        mocker.patch.object(
            client, "get_security_checks_with_pagination", return_value=(mock_events, 0)
        )

        result = get_events_command(client, args={"limit": "2", "should_push_events": "false"})

        assert result.outputs == mock_events
        assert len(result.outputs) == 2

    def test_get_events_push_events(self, mocker):
        """
        Given:
            - should_push_events is True.
        When:
            - Running get_events_command.
        Then:
            - send_events_to_xsiam is called.
        """
        client = mock_client(mocker)
        mock_events = [
            {"id": "1", "creation_date": "2026-01-01T00:00:00Z", "_time": "2026-01-01T00:00:00Z"},
        ]
        mocker.patch.object(
            client, "get_security_checks_with_pagination", return_value=(mock_events, 0)
        )
        mock_send = mocker.patch.object(AdaptiveShieldSSPMEventCollector, "send_events_to_xsiam")

        get_events_command(client, args={"limit": "1", "should_push_events": "true"})

        mock_send.assert_called_once_with(mock_events, vendor="AdaptiveShield", product="SSPM")

    def test_get_events_default_limit(self, mocker):
        """
        Given:
            - No limit specified in args.
        When:
            - Running get_events_command.
        Then:
            - Default limit of 10 is used.
        """
        client = mock_client(mocker)
        mock_pagination = mocker.patch.object(
            client, "get_security_checks_with_pagination", return_value=([], 0)
        )

        get_events_command(client, args={})

        mock_pagination.assert_called_once_with(max_fetch=10)


class TestTestModuleCommand:
    """Tests for test_module_command."""

    def test_test_module_success(self, mocker):
        """
        Given:
            - A successful API call.
        When:
            - Running test_module_command.
        Then:
            - 'ok' is returned.
        """
        client = mock_client(mocker)
        mocker.patch.object(client, "get_security_checks", return_value={"data": []})

        result = test_module_command(client)

        assert result == "ok"
