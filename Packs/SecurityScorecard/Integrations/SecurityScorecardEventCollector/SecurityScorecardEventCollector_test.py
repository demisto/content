# pylint: disable=E9010, E9011

from unittest.mock import MagicMock

import pytest
from CommonServerPython import *

from SecurityScorecardEventCollector import (  # noqa: E402
    Client,
    RateLimitError,
    add_time_to_events,
    calculate_last_run,
    deduplicate_events,
    enrich_events_with_details,
    fetch_events_command,
    get_events_command,
    get_fetch_start_time,
    test_module as _test_module,
    _safe_enrich_events,
)

# ========================================
# Constants
# ========================================

SERVER_URL = "https://api.securityscorecard.io"
MOCK_API_TOKEN = "mock_api_token_12345"
MOCK_SCORECARD_ID = "example.com"

MOCK_EVENTS = [
    {
        "id": 23751008,
        "date": "2026-03-18T15:06:17.467Z",
        "event_type": "issues",
        "group_status": "resolved",
        "issue_count": 2,
        "total_score_impact": 0.469,
        "issue_type": "outdated_browser",
        "severity": "high",
        "factor": "endpoint_security",
        "detail_url": "https://api.securityscorecard.io/companies/example.com/history/events/2026-03-18/issues/outdated_browser?group_status=resolved",
    },
    {
        "id": 37991923,
        "date": "2026-03-18T15:06:17.467Z",
        "event_type": "issues",
        "group_status": "active",
        "issue_count": 1,
        "total_score_impact": 0,
        "issue_type": "unsafe_sri_v2",
        "severity": "low",
        "factor": "application_security",
        "detail_url": "https://api.securityscorecard.io/companies/example.com/history/events/2026-03-18/issues/unsafe_sri_v2?group_status=active",
    },
]

MOCK_EVENTS_DIFFERENT_DATES = [
    {
        "id": 100,
        "date": "2026-03-17T10:00:00.000Z",
        "event_type": "issues",
        "group_status": "active",
        "issue_count": 1,
        "total_score_impact": 0.1,
        "issue_type": "type_a",
        "severity": "low",
        "factor": "network_security",
        "detail_url": "https://api.securityscorecard.io/companies/example.com/history/events/2026-03-17/issues/type_a?group_status=active",
    },
    {
        "id": 200,
        "date": "2026-03-18T15:06:17.467Z",
        "event_type": "issues",
        "group_status": "resolved",
        "issue_count": 2,
        "total_score_impact": 0.5,
        "issue_type": "type_b",
        "severity": "high",
        "factor": "endpoint_security",
        "detail_url": "https://api.securityscorecard.io/companies/example.com/history/events/2026-03-18/issues/type_b?group_status=resolved",
    },
]

MOCK_DETAIL_RESPONSE = {
    "entries": [
        {
            "issue_id": "abc123",
            "hostname": "example.com",
            "severity": "high",
        }
    ]
}


def _make_mock_response(json_data: dict | None = None, status_code: int = 200, headers: dict | None = None):
    """Create a mock httpx-like response object."""
    mock_resp = MagicMock()
    mock_resp.status_code = status_code
    mock_resp.headers = headers or {}
    mock_resp.json.return_value = json_data or {}
    mock_resp.content = b"mock" if json_data else b""
    return mock_resp


# ========================================
# Fixtures
# ========================================


@pytest.fixture()
def client(mocker):
    """Returns a Client instance for testing."""
    mocker.patch("ContentClientApiModule.support_multithreading")
    return Client(
        base_url=SERVER_URL,
        api_token=MOCK_API_TOKEN,
        scorecard_identifier=MOCK_SCORECARD_ID,
        verify=True,
        proxy=False,
    )


# ========================================
# Tests: Helper Functions
# ========================================


class TestAddTimeToEvents:
    """Tests for the add_time_to_events function."""

    def test_adds_time_field(self):
        """Test that _time is set from the date field."""
        events = [{"id": 1, "date": "2026-03-18T15:06:17.467Z"}]
        add_time_to_events(events)
        assert events[0]["_time"] == "2026-03-18T15:06:17.467Z"

    def test_missing_date_field(self):
        """Test that events without date field don't get _time."""
        events = [{"id": 1}]
        add_time_to_events(events)
        assert "_time" not in events[0]

    def test_empty_events(self):
        """Test with empty events list."""
        events: list = []
        add_time_to_events(events)
        assert events == []


class TestDeduplicateEvents:
    """Tests for the deduplicate_events function."""

    def test_no_duplicates(self):
        """Test when there are no duplicates."""
        events = [{"id": 1}, {"id": 2}]
        result = deduplicate_events(events, [3, 4])
        assert len(result) == 2

    def test_with_duplicates(self):
        """Test when some events are duplicates."""
        events = [{"id": 1}, {"id": 2}, {"id": 3}]
        result = deduplicate_events(events, [1, 2])
        assert len(result) == 1
        assert result[0]["id"] == 3

    def test_all_duplicates(self):
        """Test when all events are duplicates."""
        events = [{"id": 1}, {"id": 2}]
        result = deduplicate_events(events, [1, 2])
        assert len(result) == 0

    def test_empty_events(self):
        """Test with empty events list."""
        result = deduplicate_events([], [1, 2])
        assert result == []

    def test_empty_last_fetched_ids(self):
        """Test with no previous IDs (first run)."""
        events = [{"id": 1}, {"id": 2}]
        result = deduplicate_events(events, [])
        assert len(result) == 2

    def test_none_last_fetched_ids(self):
        """Test with None-like empty list."""
        events = [{"id": 1}]
        result = deduplicate_events(events, [])
        assert len(result) == 1


class TestCalculateLastRun:
    """Tests for the calculate_last_run function."""

    def test_single_event(self):
        """Test with a single event."""
        events = [{"id": 1, "date": "2026-03-18T15:06:17.467Z"}]
        result = calculate_last_run(events)
        assert result["last_fetch"] == "2026-03-18T15:06:17.467Z"
        assert result["last_fetched_ids"] == [1]

    def test_multiple_events_same_date(self):
        """Test with multiple events sharing the same date."""
        result = calculate_last_run(MOCK_EVENTS)
        assert result["last_fetch"] == "2026-03-18T15:06:17.467Z"
        assert set(result["last_fetched_ids"]) == {23751008, 37991923}

    def test_multiple_events_different_dates(self):
        """Test with events having different dates - only last date IDs saved."""
        result = calculate_last_run(MOCK_EVENTS_DIFFERENT_DATES)
        assert result["last_fetch"] == "2026-03-18T15:06:17.467Z"
        assert result["last_fetched_ids"] == [200]

    def test_empty_events(self):
        """Test with empty events list."""
        result = calculate_last_run([])
        assert result == {}


class TestGetFetchStartTime:
    """Tests for the get_fetch_start_time function."""

    def test_with_last_run(self):
        """Test that last_run is used when available."""
        params = {"first_fetch": "3 days"}
        last_run = {"last_fetch": "2026-03-18T15:06:17.467Z"}
        result = get_fetch_start_time(params, last_run)
        assert result == "2026-03-18T15:06:17.467Z"

    def test_first_run(self):
        """Test that first_fetch param is used on first run."""
        params = {"first_fetch": "3 days"}
        last_run = {}
        result = get_fetch_start_time(params, last_run)
        # Should return a valid date string
        assert result is not None
        assert "T" in result

    def test_default_first_fetch(self):
        """Test default first_fetch when not specified."""
        params = {}
        last_run = {}
        result = get_fetch_start_time(params, last_run)
        assert result is not None


# ========================================
# Tests: RateLimitError
# ========================================


class TestRateLimitError:
    """Tests for the RateLimitError exception."""

    def test_default_retry_after(self):
        """Test default retry_after value."""
        error = RateLimitError()
        assert error.retry_after == "60"

    def test_custom_retry_after(self):
        """Test custom retry_after value."""
        error = RateLimitError(retry_after="120")
        assert error.retry_after == "120"

    def test_error_message(self):
        """Test error message format."""
        error = RateLimitError(retry_after="30")
        assert "30" in str(error)


# ========================================
# Tests: Client
# ========================================


class TestClient:
    """Tests for the Client class."""

    def test_get_history_events_success(self, client, mocker):
        """Test successful history events fetch."""
        mock_response = _make_mock_response(
            json_data={"entries": MOCK_EVENTS},
            status_code=200,
        )
        mocker.patch.object(client, "_http_request", return_value=mock_response)

        result = client.get_history_events(
            date_from="2026-03-17T00:00:00.000Z",
            date_to="2026-03-19T00:00:00.000Z",
        )

        assert len(result) == 2
        assert result[0]["id"] == 23751008

    def test_get_history_events_rate_limit(self, client, mocker):
        """Test rate limit handling on history events."""
        mock_response = _make_mock_response(
            status_code=429,
            headers={"Retry-After": "120"},
        )
        mocker.patch.object(client, "_http_request", return_value=mock_response)

        with pytest.raises(RateLimitError) as exc_info:
            client.get_history_events(
                date_from="2026-03-17T00:00:00.000Z",
                date_to="2026-03-19T00:00:00.000Z",
            )

        assert exc_info.value.retry_after == "120"

    def test_get_history_events_empty(self, client, mocker):
        """Test empty response from history events."""
        mock_response = _make_mock_response(
            json_data={"entries": []},
            status_code=200,
        )
        mocker.patch.object(client, "_http_request", return_value=mock_response)

        result = client.get_history_events(
            date_from="2026-03-17T00:00:00.000Z",
            date_to="2026-03-19T00:00:00.000Z",
        )

        assert result == []

    def test_get_detail_url_response_success(self, client, mocker):
        """Test successful detail URL fetch."""
        mock_response = _make_mock_response(
            json_data=MOCK_DETAIL_RESPONSE,
            status_code=200,
        )
        mocker.patch.object(client, "_http_request", return_value=mock_response)

        detail_url = "https://api.securityscorecard.io/companies/example.com/history/events/2026-03-18/issues/outdated_browser?group_status=resolved"
        result = client.get_detail_url_response(detail_url)
        assert result == MOCK_DETAIL_RESPONSE

    def test_get_detail_url_response_rate_limit(self, client, mocker):
        """Test rate limit handling on detail URL."""
        mock_response = _make_mock_response(
            status_code=429,
            headers={"Retry-After": "60"},
        )
        mocker.patch.object(client, "_http_request", return_value=mock_response)

        detail_url = "https://api.securityscorecard.io/companies/example.com/history/events/2026-03-18/issues/outdated_browser?group_status=resolved"
        with pytest.raises(RateLimitError):
            client.get_detail_url_response(detail_url)


# ========================================
# Tests: Enrich Events
# ========================================


class TestEnrichEvents:
    """Tests for event enrichment functions."""

    def test_enrich_events_success(self, client, mocker):
        """Test successful enrichment of all events."""
        mocker.patch.object(client, "get_detail_url_response", return_value=MOCK_DETAIL_RESPONSE)

        import copy

        events = copy.deepcopy(MOCK_EVENTS)
        result = enrich_events_with_details(client, events)

        assert len(result) == 2
        assert result[0]["detail_url_response"] == MOCK_DETAIL_RESPONSE
        assert result[1]["detail_url_response"] == MOCK_DETAIL_RESPONSE

    def test_enrich_events_rate_limit(self, client, mocker):
        """Test enrichment stops on rate limit and raises."""
        # First event succeeds, second hits rate limit
        mocker.patch.object(
            client,
            "get_detail_url_response",
            side_effect=[MOCK_DETAIL_RESPONSE, RateLimitError(retry_after="60")],
        )

        import copy

        events = copy.deepcopy(MOCK_EVENTS)

        with pytest.raises(RateLimitError):
            enrich_events_with_details(client, events)

    def test_safe_enrich_events_rate_limit(self, client, mocker):
        """Test safe enrichment returns partial results on rate limit."""
        mocker.patch.object(
            client,
            "get_detail_url_response",
            side_effect=[MOCK_DETAIL_RESPONSE, RateLimitError(retry_after="60")],
        )

        import copy

        events = copy.deepcopy(MOCK_EVENTS)
        result, rate_limited = _safe_enrich_events(client, events)

        assert len(result) == 1
        assert result[0]["id"] == 23751008
        assert result[0]["detail_url_response"] == MOCK_DETAIL_RESPONSE
        assert rate_limited is True

    def test_safe_enrich_events_no_rate_limit(self, client, mocker):
        """Test safe enrichment returns all events when no rate limit."""
        mocker.patch.object(client, "get_detail_url_response", return_value=MOCK_DETAIL_RESPONSE)

        import copy

        events = copy.deepcopy(MOCK_EVENTS)
        result, rate_limited = _safe_enrich_events(client, events)

        assert len(result) == 2
        assert rate_limited is False

    def test_enrich_events_no_detail_url(self, client):
        """Test enrichment skips events without detail_url."""
        events = [{"id": 1, "date": "2026-03-18T15:06:17.467Z"}]
        result = enrich_events_with_details(client, events)

        assert len(result) == 1
        assert "detail_url_response" not in result[0]


# ========================================
# Tests: Commands
# ========================================


class TestTestModule:
    """Tests for the test_module command."""

    def test_success(self, client, mocker):
        """Test successful test module."""
        mocker.patch.object(client, "get_history_events", return_value=[])

        result = _test_module(client)
        assert result == "ok"

    def test_rate_limit_still_ok(self, client, mocker):
        """Test that rate limit during test still returns ok."""
        mocker.patch.object(
            client,
            "get_history_events",
            side_effect=RateLimitError(retry_after="60"),
        )

        result = _test_module(client)
        assert result == "ok"

    def test_auth_error(self, client, mocker):
        """Test authentication error handling."""
        mocker.patch.object(
            client,
            "get_history_events",
            side_effect=Exception("Error in API call [401] - Unauthorized"),
        )

        result = _test_module(client)
        assert result == "Authorization Error: Verify your API Token."


class TestGetEventsCommand:
    """Tests for the get_events_command."""

    def test_get_events_returns_results(self, client, mocker):
        """Test get events returns CommandResults."""
        mocker.patch.object(client, "get_history_events", return_value=MOCK_EVENTS)
        mocker.patch.object(client, "get_detail_url_response", return_value=MOCK_DETAIL_RESPONSE)

        args = {"date_from": "3 days ago", "limit": "10", "should_push_events": "false"}
        result = get_events_command(client, args)

        assert isinstance(result, CommandResults)
        assert result.outputs is not None
        assert len(result.outputs) == 2

    def test_get_events_push_to_xsiam(self, client, mocker):
        """Test get events with push to XSIAM."""
        mocker.patch.object(client, "get_history_events", return_value=MOCK_EVENTS)
        mocker.patch.object(client, "get_detail_url_response", return_value=MOCK_DETAIL_RESPONSE)
        mock_send = mocker.patch("SecurityScorecardEventCollector.send_events_to_xsiam")

        args = {"date_from": "3 days ago", "limit": "10", "should_push_events": "true"}
        result = get_events_command(client, args)

        assert isinstance(result, str)
        assert "2" in result
        mock_send.assert_called_once()

    def test_get_events_with_limit(self, client, mocker):
        """Test get events respects limit."""
        mocker.patch.object(client, "get_history_events", return_value=MOCK_EVENTS)
        mocker.patch.object(client, "get_detail_url_response", return_value=MOCK_DETAIL_RESPONSE)

        args = {"date_from": "3 days ago", "limit": "1", "should_push_events": "false"}
        result = get_events_command(client, args)

        assert isinstance(result, CommandResults)
        assert len(result.outputs) == 1


class TestFetchEventsCommand:
    """Tests for the fetch_events_command."""

    def test_fetch_first_run(self, client, mocker):
        """Test first fetch run."""
        mocker.patch.object(client, "get_history_events", return_value=MOCK_EVENTS)
        mocker.patch.object(client, "get_detail_url_response", return_value=MOCK_DETAIL_RESPONSE)

        mocker.patch.object(
            demisto,
            "params",
            return_value={
                "max_fetch": "1000",
                "first_fetch": "3 days",
            },
        )
        mocker.patch.object(demisto, "getLastRun", return_value={})
        mock_set_last_run = mocker.patch.object(demisto, "setLastRun")
        mock_send = mocker.patch("SecurityScorecardEventCollector.send_events_to_xsiam")

        fetch_events_command(client)

        mock_send.assert_called_once()
        sent_events = mock_send.call_args[1]["events"]
        assert len(sent_events) == 2

        mock_set_last_run.assert_called_once()
        last_run_arg = mock_set_last_run.call_args[0][0]
        assert last_run_arg["last_fetch"] == "2026-03-18T15:06:17.467Z"
        assert set(last_run_arg["last_fetched_ids"]) == {23751008, 37991923}

    def test_fetch_with_deduplication(self, client, mocker):
        """Test fetch deduplicates against previous run."""
        mocker.patch.object(client, "get_history_events", return_value=MOCK_EVENTS)
        mocker.patch.object(client, "get_detail_url_response", return_value=MOCK_DETAIL_RESPONSE)

        mocker.patch.object(
            demisto,
            "params",
            return_value={
                "max_fetch": "1000",
                "first_fetch": "3 days",
            },
        )
        mocker.patch.object(
            demisto,
            "getLastRun",
            return_value={
                "last_fetch": "2026-03-18T15:06:17.467Z",
                "last_fetched_ids": [23751008],
            },
        )
        mocker.patch.object(demisto, "setLastRun")
        mock_send = mocker.patch("SecurityScorecardEventCollector.send_events_to_xsiam")

        fetch_events_command(client)

        mock_send.assert_called_once()
        sent_events = mock_send.call_args[1]["events"]
        assert len(sent_events) == 1
        assert sent_events[0]["id"] == 37991923

    def test_fetch_all_duplicates(self, client, mocker):
        """Test fetch when all events are duplicates."""
        mocker.patch.object(client, "get_history_events", return_value=MOCK_EVENTS)

        mocker.patch.object(
            demisto,
            "params",
            return_value={
                "max_fetch": "1000",
                "first_fetch": "3 days",
            },
        )
        mocker.patch.object(
            demisto,
            "getLastRun",
            return_value={
                "last_fetch": "2026-03-18T15:06:17.467Z",
                "last_fetched_ids": [23751008, 37991923],
            },
        )
        mock_set_last_run = mocker.patch.object(demisto, "setLastRun")
        mock_send = mocker.patch("SecurityScorecardEventCollector.send_events_to_xsiam")

        fetch_events_command(client)

        mock_send.assert_not_called()
        mock_set_last_run.assert_not_called()

    def test_fetch_rate_limit_on_history(self, client, mocker):
        """Test fetch handles rate limit on history events API."""
        mocker.patch.object(
            client,
            "get_history_events",
            side_effect=RateLimitError(retry_after="120"),
        )

        mocker.patch.object(
            demisto,
            "params",
            return_value={
                "max_fetch": "1000",
                "first_fetch": "3 days",
            },
        )
        mocker.patch.object(demisto, "getLastRun", return_value={})
        mock_send = mocker.patch("SecurityScorecardEventCollector.send_events_to_xsiam")

        fetch_events_command(client)

        mock_send.assert_not_called()

    def test_fetch_rate_limit_on_detail_url(self, client, mocker):
        """Test fetch handles rate limit on detail URL - sends partial results."""
        mocker.patch.object(client, "get_history_events", return_value=MOCK_EVENTS)
        # First detail URL succeeds, second hits rate limit
        mocker.patch.object(
            client,
            "get_detail_url_response",
            side_effect=[MOCK_DETAIL_RESPONSE, RateLimitError(retry_after="60")],
        )

        mocker.patch.object(
            demisto,
            "params",
            return_value={
                "max_fetch": "1000",
                "first_fetch": "3 days",
            },
        )
        mocker.patch.object(demisto, "getLastRun", return_value={})
        mock_set_last_run = mocker.patch.object(demisto, "setLastRun")
        mock_send = mocker.patch("SecurityScorecardEventCollector.send_events_to_xsiam")

        fetch_events_command(client)

        # Should send only the first event (enriched before rate limit)
        mock_send.assert_called_once()
        sent_events = mock_send.call_args[1]["events"]
        assert len(sent_events) == 1
        assert sent_events[0]["id"] == 23751008
        assert sent_events[0]["detail_url_response"] == MOCK_DETAIL_RESPONSE

        # Last run should be updated based on the sent event
        mock_set_last_run.assert_called_once()
        last_run_arg = mock_set_last_run.call_args[0][0]
        assert last_run_arg["last_fetch"] == "2026-03-18T15:06:17.467Z"

    def test_fetch_no_events(self, client, mocker):
        """Test fetch with no events returned."""
        mocker.patch.object(client, "get_history_events", return_value=[])

        mocker.patch.object(
            demisto,
            "params",
            return_value={
                "max_fetch": "1000",
                "first_fetch": "3 days",
            },
        )
        mocker.patch.object(demisto, "getLastRun", return_value={})
        mock_send = mocker.patch("SecurityScorecardEventCollector.send_events_to_xsiam")

        fetch_events_command(client)

        mock_send.assert_not_called()

    def test_fetch_respects_max_fetch(self, client, mocker):
        """Test fetch respects max_fetch limit."""
        mocker.patch.object(client, "get_history_events", return_value=MOCK_EVENTS)
        mocker.patch.object(client, "get_detail_url_response", return_value=MOCK_DETAIL_RESPONSE)

        mocker.patch.object(
            demisto,
            "params",
            return_value={
                "max_fetch": "1",
                "first_fetch": "3 days",
            },
        )
        mocker.patch.object(demisto, "getLastRun", return_value={})
        mocker.patch.object(demisto, "setLastRun")
        mock_send = mocker.patch("SecurityScorecardEventCollector.send_events_to_xsiam")

        fetch_events_command(client)

        mock_send.assert_called_once()
        sent_events = mock_send.call_args[1]["events"]
        assert len(sent_events) == 1
