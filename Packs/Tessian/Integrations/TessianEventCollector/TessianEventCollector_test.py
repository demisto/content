"""Unit tests for TessianEventCollector integration."""

import json

import pytest
from freezegun import freeze_time


def util_load_json(path: str) -> dict:
    """Load a JSON file for testing."""
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def create_mock_client(mocker):
    """Create a mock client for testing."""
    from TessianEventCollector import Client

    # Mock ContentClient initialization
    mocker.patch("TessianEventCollector.ContentClient.__init__", return_value=None)

    client = Client.__new__(Client)
    client._base_url = "https://example.tessian-platform.com"
    client._verify = False
    return client


class TestFormatUrl:
    """Test cases for the format_url helper function."""

    @pytest.mark.parametrize(
        "input_url, expected_url",
        [
            pytest.param(
                "https://example.tessian-platform.com",
                "https://example.tessian-platform.com",
                id="valid_https_url",
            ),
            pytest.param(
                "http://example.tessian-platform.com",
                "https://example.tessian-platform.com",
                id="http_prefix",
            ),
            pytest.param(
                "example.tessian-platform.com",
                "https://example.tessian-platform.com",
                id="no_prefix",
            ),
            pytest.param(
                "https://example.tessian-platform.com/",
                "https://example.tessian-platform.com",
                id="trailing_slash",
            ),
            pytest.param(
                "https://example.tessian-platform.com/api/v1/events",
                "https://example.tessian-platform.com",
                id="trailing_path",
            ),
            pytest.param(
                "http://example.tessian-app.com/some/path",
                "https://example.tessian-app.com",
                id="http_with_path",
            ),
        ],
    )
    def test_format_url(self, input_url: str, expected_url: str):
        """Test URL formatting with various inputs."""
        from TessianEventCollector import format_url

        assert format_url(input_url) == expected_url


class TestEnrichEvents:
    """Test cases for the enrich_events helper function."""

    def test_enrich_events_new_status(self):
        """Test enrichment when updated_at equals created_at (new event)."""
        from TessianEventCollector import enrich_events

        events = [
            {
                "id": "event-001",
                "created_at": "2024-06-15T10:30:00Z",
                "updated_at": "2024-06-15T10:30:00Z",
            }
        ]

        result = enrich_events(events)

        assert result[0]["_time"] == "2024-06-15T10:30:00Z"
        assert result[0]["_ENTRY_STATUS"] == "new"

    def test_enrich_events_updated_status(self):
        """Test enrichment when updated_at is after created_at (updated event)."""
        from TessianEventCollector import enrich_events

        events = [
            {
                "id": "event-002",
                "created_at": "2024-06-15T11:00:00Z",
                "updated_at": "2024-06-15T12:00:00Z",
            }
        ]

        result = enrich_events(events)

        assert result[0]["_time"] == "2024-06-15T11:00:00Z"
        assert result[0]["_ENTRY_STATUS"] == "updated"

    def test_enrich_events_missing_timestamps(self):
        """Test enrichment when timestamps are missing."""
        from TessianEventCollector import enrich_events

        events = [{"id": "event-003"}]

        result = enrich_events(events)

        assert "_time" not in result[0]
        assert "_ENTRY_STATUS" not in result[0]

    def test_enrich_events_multiple(self):
        """Test enrichment of multiple events."""
        from TessianEventCollector import enrich_events

        events = [
            {
                "id": "event-001",
                "created_at": "2024-06-15T10:30:00Z",
                "updated_at": "2024-06-15T10:30:00Z",
            },
            {
                "id": "event-002",
                "created_at": "2024-06-15T11:00:00Z",
                "updated_at": "2024-06-15T12:00:00Z",
            },
        ]

        result = enrich_events(events)

        assert len(result) == 2
        assert result[0]["_ENTRY_STATUS"] == "new"
        assert result[1]["_ENTRY_STATUS"] == "updated"


class TestClient:
    """Test cases for the Client class."""

    def test_list_events(self, mocker):
        """Test fetching events from the API."""
        mock_response = util_load_json("test_data/security_events_response.json")

        client = create_mock_client(mocker)
        mocker.patch.object(client, "_http_request", return_value=mock_response)

        result = client.list_events(limit=100)

        assert len(result["results"]) == 3
        assert result["checkpoint"] == "test_checkpoint_abc123"
        assert result["additional_results"] is True

    def test_list_events_empty(self, mocker):
        """Test fetching events when no events are returned."""
        mock_response = util_load_json("test_data/security_events_empty_response.json")

        client = create_mock_client(mocker)
        mocker.patch.object(client, "_http_request", return_value=mock_response)

        result = client.list_events(limit=100)

        assert len(result["results"]) == 0
        assert result["additional_results"] is False


class TestFetchEventsWithPagination:
    """Test cases for the fetch_events_with_pagination function."""

    def test_single_page(self, mocker):
        """Test fetching events that fit in a single page."""
        from TessianEventCollector import fetch_events_with_pagination

        mock_response = {
            "checkpoint": "checkpoint_1",
            "additional_results": False,
            "results": [
                {
                    "id": "event-001",
                    "created_at": "2024-06-15T10:30:00Z",
                    "updated_at": "2024-06-15T10:30:00Z",
                }
            ],
        }

        client = create_mock_client(mocker)
        mocker.patch.object(client, "list_events", return_value=mock_response)

        events, checkpoint = fetch_events_with_pagination(
            client=client,
            created_after="2024-06-15T00:00:00Z",
            initial_checkpoint=None,
            max_fetch=100,
        )

        assert len(events) == 1
        assert checkpoint == "checkpoint_1"

    def test_multiple_pages(self, mocker):
        """Test fetching events across multiple pages."""
        from TessianEventCollector import fetch_events_with_pagination

        page1_response = {
            "checkpoint": "checkpoint_1",
            "additional_results": True,
            "results": [{"id": f"event-{i}", "created_at": f"2024-06-15T{i:02d}:00:00Z"} for i in range(100)],
        }
        page2_response = {
            "checkpoint": "checkpoint_2",
            "additional_results": False,
            "results": [{"id": f"event-{i}", "created_at": f"2024-06-16T{i:02d}:00:00Z"} for i in range(50)],
        }

        client = create_mock_client(mocker)
        call_count = 0

        def mock_list_events(**kwargs):
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                return page1_response
            return page2_response

        mocker.patch.object(client, "list_events", side_effect=mock_list_events)

        events, checkpoint = fetch_events_with_pagination(
            client=client,
            created_after="2024-06-15T00:00:00Z",
            initial_checkpoint=None,
            max_fetch=200,
        )

        assert len(events) == 150
        assert checkpoint == "checkpoint_2"
        assert call_count == 2

    def test_respects_max_fetch(self, mocker):
        """Test that pagination respects the max_fetch limit."""
        from TessianEventCollector import fetch_events_with_pagination

        page_response = {
            "checkpoint": "checkpoint_1",
            "additional_results": True,
            "results": [{"id": f"event-{i}", "created_at": f"2024-06-15T{i:02d}:00:00Z"} for i in range(50)],
        }

        client = create_mock_client(mocker)
        mock_list = mocker.patch.object(client, "list_events", return_value=page_response)

        events, checkpoint = fetch_events_with_pagination(
            client=client,
            created_after="2024-06-15T00:00:00Z",
            initial_checkpoint=None,
            max_fetch=50,
        )

        # Should request limit=50 and return 50 events
        mock_list.assert_called_once_with(limit=50, created_after="2024-06-15T00:00:00Z")
        assert len(events) == 50
        assert checkpoint == "checkpoint_1"

    def test_uses_checkpoint_over_created_after(self, mocker):
        """Test that checkpoint is used instead of created_after when available."""
        from TessianEventCollector import fetch_events_with_pagination

        mock_response = {
            "checkpoint": "checkpoint_new",
            "additional_results": False,
            "results": [{"id": "event-001", "created_at": "2024-06-15T10:30:00Z"}],
        }

        client = create_mock_client(mocker)
        mock_list = mocker.patch.object(client, "list_events", return_value=mock_response)

        events, checkpoint = fetch_events_with_pagination(
            client=client,
            created_after="2024-06-15T00:00:00Z",
            initial_checkpoint="existing_checkpoint",
            max_fetch=100,
        )

        # Verify checkpoint was used, not created_after
        mock_list.assert_called_once_with(
            limit=100,
            after_checkpoint="existing_checkpoint",
        )

    def test_empty_response(self, mocker):
        """Test handling of empty response."""
        from TessianEventCollector import fetch_events_with_pagination

        mock_response = {
            "checkpoint": "checkpoint_empty",
            "additional_results": False,
            "results": [],
        }

        client = create_mock_client(mocker)
        mocker.patch.object(client, "list_events", return_value=mock_response)

        events, checkpoint = fetch_events_with_pagination(
            client=client,
            created_after="2024-06-15T00:00:00Z",
            initial_checkpoint=None,
            max_fetch=100,
        )

        assert len(events) == 0
        assert checkpoint == "checkpoint_empty"


class TestCommands:
    """Test cases for command functions."""

    def test_test_module_success(self, mocker):
        """Test successful test-module command."""
        from TessianEventCollector import test_module

        client = create_mock_client(mocker)
        mocker.patch.object(
            client,
            "list_events",
            return_value={
                "checkpoint": "test_checkpoint",
                "additional_results": False,
                "results": [],
            },
        )

        result = test_module(client)
        assert result == "ok"

    def test_test_module_no_checkpoint(self, mocker):
        """Test test-module when response has no checkpoint."""
        from TessianEventCollector import test_module

        client = create_mock_client(mocker)
        mocker.patch.object(
            client,
            "list_events",
            return_value={"results": []},
        )

        result = test_module(client)
        assert "Unexpected result" in result

    def test_test_module_auth_error(self, mocker):
        """Test test-module with authorization error."""
        from TessianEventCollector import test_module

        client = create_mock_client(mocker)
        mocker.patch.object(
            client,
            "list_events",
            side_effect=Exception("403 Forbidden"),
        )

        result = test_module(client)
        assert "Authorization Error" in result

    def test_get_events_command(self, mocker):
        """Test get-events command."""
        from TessianEventCollector import get_events_command

        mock_response = util_load_json("test_data/security_events_response.json")
        # Override additional_results to stop pagination after one call
        mock_response["additional_results"] = False

        client = create_mock_client(mocker)
        mocker.patch.object(client, "list_events", return_value=mock_response)

        events, results = get_events_command(
            client=client,
            args={"limit": "10"},
        )

        assert len(events) == 3
        assert events[0]["_ENTRY_STATUS"] == "new"
        assert events[1]["_ENTRY_STATUS"] == "updated"
        assert "Tessian Security Events" in results.readable_output

    def test_get_events_command_with_push(self, mocker):
        """Test get-events command with should_push_events=true."""
        from TessianEventCollector import get_events_command

        mock_response = {
            "checkpoint": "test_cp",
            "additional_results": False,
            "results": [
                {
                    "id": "event-001",
                    "created_at": "2024-06-15T10:30:00Z",
                    "updated_at": "2024-06-15T10:30:00Z",
                }
            ],
        }

        client = create_mock_client(mocker)
        mocker.patch.object(client, "list_events", return_value=mock_response)
        mock_send = mocker.patch("TessianEventCollector.send_events_to_xsiam")

        events, results = get_events_command(
            client=client,
            args={"limit": "10", "should_push_events": "true"},
        )

        assert len(events) == 1
        mock_send.assert_called_once()

    @freeze_time("2024-06-15T12:00:00Z")
    def test_fetch_events_command_first_run(self, mocker):
        """Test fetch-events command on first run (no last_run)."""
        from TessianEventCollector import fetch_events_command

        mock_response = {
            "checkpoint": "first_checkpoint",
            "additional_results": False,
            "results": [
                {
                    "id": "event-001",
                    "created_at": "2024-06-15T12:00:00Z",
                    "updated_at": "2024-06-15T12:00:00Z",
                }
            ],
        }

        client = create_mock_client(mocker)
        mocker.patch.object(client, "list_events", return_value=mock_response)

        events, next_run = fetch_events_command(
            client=client,
            last_run={},
            max_fetch=1000,
        )

        assert len(events) == 1
        assert next_run["checkpoint"] == "first_checkpoint"
        assert events[0]["_ENTRY_STATUS"] == "new"

    def test_fetch_events_command_with_checkpoint(self, mocker):
        """Test fetch-events command with existing checkpoint."""
        from TessianEventCollector import fetch_events_command

        mock_response = {
            "checkpoint": "new_checkpoint",
            "additional_results": False,
            "results": [
                {
                    "id": "event-002",
                    "created_at": "2024-06-15T13:00:00Z",
                    "updated_at": "2024-06-15T14:00:00Z",
                }
            ],
        }

        client = create_mock_client(mocker)
        mock_list = mocker.patch.object(client, "list_events", return_value=mock_response)

        last_run = {"checkpoint": "old_checkpoint"}
        events, next_run = fetch_events_command(
            client=client,
            last_run=last_run,
            max_fetch=1000,
        )

        assert len(events) == 1
        assert next_run["checkpoint"] == "new_checkpoint"
        assert events[0]["_ENTRY_STATUS"] == "updated"

        # Verify checkpoint was used
        mock_list.assert_called_once_with(
            limit=100,
            after_checkpoint="old_checkpoint",
        )

    @freeze_time("2024-06-15T12:00:00Z")
    def test_fetch_events_command_no_events(self, mocker):
        """Test fetch-events command when no events are returned."""
        from TessianEventCollector import fetch_events_command

        mock_response = {
            "checkpoint": "empty_checkpoint",
            "additional_results": False,
            "results": [],
        }

        client = create_mock_client(mocker)
        mocker.patch.object(client, "list_events", return_value=mock_response)

        events, next_run = fetch_events_command(
            client=client,
            last_run={},
            max_fetch=1000,
        )

        assert len(events) == 0
        assert next_run["checkpoint"] == "empty_checkpoint"

    def test_fetch_events_preserves_checkpoint_on_empty(self, mocker):
        """Test that existing checkpoint is preserved when no new checkpoint is returned."""
        from TessianEventCollector import fetch_events_command

        mock_response = {
            "additional_results": False,
            "results": [],
        }

        client = create_mock_client(mocker)
        mocker.patch.object(client, "list_events", return_value=mock_response)

        last_run = {"checkpoint": "existing_checkpoint"}
        events, next_run = fetch_events_command(
            client=client,
            last_run=last_run,
            max_fetch=1000,
        )

        assert len(events) == 0
        assert next_run["checkpoint"] == "existing_checkpoint"
