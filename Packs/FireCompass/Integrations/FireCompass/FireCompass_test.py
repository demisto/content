import pytest
from freezegun import freeze_time
from FireCompass import (
    Client,
    get_events_command,
    fetch_events_command,
    _add_fields_to_events,
    _deduplicate_events,
    _fetch_events_with_pagination,
    _update_last_run,
    _parse_date_string,
    _datetime_to_api_date,
)
from CommonServerPython import DemistoException
from datetime import UTC


BASE_URL = "https://apis.firecompass.com"
API_KEY = "test-api-key"


@pytest.fixture(autouse=True)
def mock_content_client_init(mocker):
    """Mock ContentClient.__init__ to avoid httpx/anyio initialization in tests."""
    mocker.patch("FireCompass.ContentClient.__init__", return_value=None)


@pytest.fixture
def client():
    """
    Given:
        - Base URL and API key credentials
    When:
        - Creating a Client instance
    Then:
        - Ensure the client is properly initialized
    """
    c = Client(
        base_url=BASE_URL,
        api_key=API_KEY,
        verify=False,
        proxy=False,
    )
    # Set required attributes that would be set by ContentClient.__init__
    c._base_url = BASE_URL
    c._verify = False
    return c


def _create_risk_event(
    event_id: str,
    created_at: str = "2026-03-01T12:00:00.000000Z",
    updated_at: str = "2026-03-01T12:00:00.000000Z",
    title: str = "Test Risk",
    severity: str = "HIGH",
) -> dict:
    """Helper to create a mock risk event."""
    return {
        "id": event_id,
        "title": title,
        "description": "Test risk description",
        "asset": "testdomain.com",
        "asset_ref": "domain",
        "primary_domain": "testdomain.com",
        "severity": severity,
        "state": "OPEN",
        "type": "TAKEOVER_RISK",
        "category": "DNS",
        "created_at": created_at,
        "updated_at": updated_at,
        "version": 1,
    }


class TestAddFieldsToEvents:
    """Tests for _add_fields_to_events function."""

    def test_add_fields_new_event(self):
        """
        Given:
            - An event where updated_at equals created_at
        When:
            - Calling _add_fields_to_events
        Then:
            - Ensure _time is set to created_at and _ENTRY_STATUS is 'new'
        """
        events = [_create_risk_event("event-1", created_at="2026-03-01T12:00:00Z", updated_at="2026-03-01T12:00:00Z")]
        _add_fields_to_events(events)
        assert events[0]["_time"] == "2026-03-01T12:00:00Z"
        assert events[0]["_ENTRY_STATUS"] == "new"

    def test_add_fields_modified_event(self):
        """
        Given:
            - An event where updated_at is greater than created_at
        When:
            - Calling _add_fields_to_events
        Then:
            - Ensure _ENTRY_STATUS is 'modified'
        """
        events = [_create_risk_event("event-1", created_at="2026-03-01T12:00:00Z", updated_at="2026-03-02T12:00:00Z")]
        _add_fields_to_events(events)
        assert events[0]["_time"] == "2026-03-01T12:00:00Z"
        assert events[0]["_ENTRY_STATUS"] == "modified"

    def test_add_fields_empty_list(self):
        """
        Given:
            - An empty list of events
        When:
            - Calling _add_fields_to_events
        Then:
            - Ensure no errors are raised
        """
        events: list = []
        _add_fields_to_events(events)
        assert events == []

    def test_add_fields_missing_timestamps(self):
        """
        Given:
            - An event missing created_at and updated_at fields
        When:
            - Calling _add_fields_to_events
        Then:
            - Ensure no _time or _ENTRY_STATUS fields are added
        """
        events = [{"id": "event-1", "title": "No timestamps"}]
        _add_fields_to_events(events)
        assert "_time" not in events[0]
        assert "_ENTRY_STATUS" not in events[0]


class TestDeduplicateEvents:
    """Tests for _deduplicate_events function."""

    def test_deduplicate_removes_known_ids(self):
        """
        Given:
            - Events with IDs that overlap with last_run_ids
        When:
            - Calling _deduplicate_events
        Then:
            - Ensure duplicate events are removed
        """
        events = [
            _create_risk_event("event-1"),
            _create_risk_event("event-2"),
            _create_risk_event("event-3"),
        ]
        last_run_ids = ["event-1", "event-2"]
        result = _deduplicate_events(events, last_run_ids)
        assert len(result) == 1
        assert result[0]["id"] == "event-3"

    def test_deduplicate_no_previous_ids(self):
        """
        Given:
            - Events with no previous IDs to deduplicate against
        When:
            - Calling _deduplicate_events
        Then:
            - Ensure all events are returned
        """
        events = [
            _create_risk_event("event-1"),
            _create_risk_event("event-2"),
        ]
        result = _deduplicate_events(events, [])
        assert len(result) == 2

    def test_deduplicate_empty_events(self):
        """
        Given:
            - An empty list of events
        When:
            - Calling _deduplicate_events
        Then:
            - Ensure an empty list is returned
        """
        result = _deduplicate_events([], ["event-1"])
        assert result == []

    def test_deduplicate_event_without_id(self):
        """
        Given:
            - An event without an ID field
        When:
            - Calling _deduplicate_events
        Then:
            - Ensure the event is included (not filtered out)
        """
        events = [{"title": "No ID event", "created_at": "2026-03-01T12:00:00Z"}]
        result = _deduplicate_events(events, ["event-1"])
        assert len(result) == 1

    def test_deduplicate_all_duplicates(self):
        """
        Given:
            - All events are duplicates of previous IDs
        When:
            - Calling _deduplicate_events
        Then:
            - Ensure an empty list is returned
        """
        events = [
            _create_risk_event("event-1"),
            _create_risk_event("event-2"),
        ]
        result = _deduplicate_events(events, ["event-1", "event-2"])
        assert result == []


class TestUpdateLastRun:
    """Tests for _update_last_run function."""

    def test_update_last_run_with_new_events(self):
        """
        Given:
            - New events with a newer timestamp than last_run
        When:
            - Calling _update_last_run
        Then:
            - Ensure last_fetch_time is updated and IDs are tracked
        """
        events = [
            _create_risk_event("event-1", created_at="2026-03-01T12:00:00Z"),
            _create_risk_event("event-2", created_at="2026-03-02T12:00:00Z"),
        ]
        last_run = {"last_fetch_time": "2026-02-28T12:00:00Z", "last_fetch_ids": []}
        result = _update_last_run(events, last_run)
        assert result["last_fetch_time"] == "2026-03-02T12:00:00Z"
        assert "event-2" in result["last_fetch_ids"]

    def test_update_last_run_same_timestamp(self):
        """
        Given:
            - New events with the same timestamp as last_run
        When:
            - Calling _update_last_run
        Then:
            - Ensure IDs are combined
        """
        events = [
            _create_risk_event("event-2", created_at="2026-03-01T12:00:00Z"),
        ]
        last_run = {"last_fetch_time": "2026-03-01T12:00:00Z", "last_fetch_ids": ["event-1"]}
        result = _update_last_run(events, last_run)
        assert result["last_fetch_time"] == "2026-03-01T12:00:00Z"
        assert set(result["last_fetch_ids"]) == {"event-1", "event-2"}

    def test_update_last_run_no_events(self):
        """
        Given:
            - No new events
        When:
            - Calling _update_last_run
        Then:
            - Ensure last_run state is preserved
        """
        last_run = {"last_fetch_time": "2026-03-01T12:00:00Z", "last_fetch_ids": ["event-1"]}
        result = _update_last_run([], last_run)
        assert result == last_run

    def test_update_last_run_multiple_events_same_latest_time(self):
        """
        Given:
            - Multiple events sharing the latest created_at timestamp
        When:
            - Calling _update_last_run
        Then:
            - Ensure all IDs at the latest timestamp are tracked
        """
        events = [
            _create_risk_event("event-1", created_at="2026-03-01T12:00:00Z"),
            _create_risk_event("event-2", created_at="2026-03-02T12:00:00Z"),
            _create_risk_event("event-3", created_at="2026-03-02T12:00:00Z"),
        ]
        last_run: dict = {"last_fetch_time": "", "last_fetch_ids": []}
        result = _update_last_run(events, last_run)
        assert result["last_fetch_time"] == "2026-03-02T12:00:00Z"
        assert set(result["last_fetch_ids"]) == {"event-2", "event-3"}


class TestFetchEventsWithPagination:
    """Tests for _fetch_events_with_pagination function."""

    def test_single_page_fetch(self, client, mocker):
        """
        Given:
            - API returns fewer events than page_size
        When:
            - Calling _fetch_events_with_pagination
        Then:
            - Ensure all events are returned without additional pages
        """
        mock_response = {
            "data": [
                _create_risk_event("event-1", created_at="2026-03-01T10:00:00Z"),
                _create_risk_event("event-2", created_at="2026-03-01T12:00:00Z"),
            ]
        }
        mocker.patch.object(client, "_http_request", return_value=mock_response)

        events = _fetch_events_with_pagination(client, "2026-03-01", "2026-03-01", limit=100)
        assert len(events) == 2
        assert events[0]["id"] == "event-1"
        assert events[1]["id"] == "event-2"

    def test_multi_page_fetch(self, client, mocker):
        """
        Given:
            - API returns a full page of events requiring pagination
        When:
            - Calling _fetch_events_with_pagination with a limit larger than page_size
        Then:
            - Ensure events from multiple pages are combined
        """
        page1_events = [_create_risk_event(f"event-{i}", created_at=f"2026-03-01T{10 + i}:00:00Z") for i in range(100)]
        page2_events = [_create_risk_event(f"event-{100 + i}", created_at=f"2026-03-02T{i}:00:00Z") for i in range(50)]

        mocker.patch.object(
            client,
            "_http_request",
            side_effect=[
                {"data": page1_events},
                {"data": page2_events},
            ],
        )

        events = _fetch_events_with_pagination(client, "2026-03-01", "2026-03-02", limit=200)
        assert len(events) == 150

    def test_empty_response(self, client, mocker):
        """
        Given:
            - API returns an empty response
        When:
            - Calling _fetch_events_with_pagination
        Then:
            - Ensure an empty list is returned
        """
        mocker.patch.object(client, "_http_request", return_value={"data": []})

        events = _fetch_events_with_pagination(client, "2026-03-01", "2026-03-01", limit=100)
        assert events == []

    def test_limit_respected(self, client, mocker):
        """
        Given:
            - API has many events available, but limit is set to 10
        When:
            - Calling _fetch_events_with_pagination with limit=10
        Then:
            - Ensure only 10 events are returned (API respects page_size)
        """
        mock_events = [_create_risk_event(f"event-{i}", created_at=f"2026-03-01T{i:02d}:00:00Z") for i in range(10)]
        mocker.patch.object(client, "_http_request", return_value={"data": mock_events})

        events = _fetch_events_with_pagination(client, "2026-03-01", "2026-03-01", limit=10)
        assert len(events) == 10

    def test_page_beyond_data_returns_error(self, client, mocker):
        """
        Given:
            - First page returns a full batch, second page returns a 400 error
              (API returns error for out-of-range page instead of empty result)
        When:
            - Calling _fetch_events_with_pagination
        Then:
            - Ensure events from the first page are returned and pagination stops gracefully
        """
        page1_events = [_create_risk_event(f"event-{i}", created_at=f"2026-03-01T{i:02d}:00:00Z") for i in range(100)]

        mocker.patch.object(
            client,
            "_http_request",
            side_effect=[
                {"data": page1_events},
                DemistoException("Error in API call [400] - Bad Request"),
            ],
        )

        events = _fetch_events_with_pagination(client, "2026-03-01", "2026-03-01", limit=200)
        assert len(events) == 100

    def test_page_beyond_data_returns_404(self, client, mocker):
        """
        Given:
            - First page returns events, second page returns a 404 error
        When:
            - Calling _fetch_events_with_pagination
        Then:
            - Ensure events from the first page are returned and pagination stops gracefully
        """
        page1_events = [_create_risk_event(f"event-{i}", created_at=f"2026-03-01T{i:02d}:00:00Z") for i in range(100)]

        mocker.patch.object(
            client,
            "_http_request",
            side_effect=[
                {"data": page1_events},
                DemistoException("Error in API call [404] - Not Found"),
            ],
        )

        events = _fetch_events_with_pagination(client, "2026-03-01", "2026-03-01", limit=200)
        assert len(events) == 100

    def test_unexpected_error_is_raised(self, client, mocker):
        """
        Given:
            - API returns a 500 server error during pagination
        When:
            - Calling _fetch_events_with_pagination
        Then:
            - Ensure the error is re-raised (not swallowed)
        """
        mocker.patch.object(
            client, "_http_request", side_effect=DemistoException("Error in API call [500] - Internal Server Error")
        )

        with pytest.raises(DemistoException, match="500"):
            _fetch_events_with_pagination(client, "2026-03-01", "2026-03-01", limit=100)

    def test_auth_error_is_raised(self, client, mocker):
        """
        Given:
            - API returns a 401 unauthorized error during pagination
        When:
            - Calling _fetch_events_with_pagination
        Then:
            - Ensure the auth error is re-raised (not treated as end of data)
        """
        mocker.patch.object(client, "_http_request", side_effect=DemistoException("Error in API call [401] - Unauthorized"))

        with pytest.raises(DemistoException, match="401"):
            _fetch_events_with_pagination(client, "2026-03-01", "2026-03-01", limit=100)


class TestTestModuleCommand:
    """Tests for test_module_command function."""

    def test_test_module_success(self, client, mocker):
        """
        Given:
            - A valid API key and reachable server
        When:
            - Calling test_module_command
        Then:
            - Ensure 'ok' is returned
        """
        from FireCompass import test_module_command

        mocker.patch.object(client, "_http_request", return_value={"data": []})
        result = test_module_command(client)
        assert result == "ok"

    def test_test_module_auth_failure(self, client, mocker):
        """
        Given:
            - An invalid API key
        When:
            - Calling test_module_command
        Then:
            - Ensure an authorization error message is returned
        """
        from FireCompass import test_module_command

        mocker.patch.object(client, "_http_request", side_effect=Exception("401 Unauthorized"))
        result = test_module_command(client)
        assert "Authorization Error" in result

    def test_test_module_server_error(self, client, mocker):
        """
        Given:
            - A server error response
        When:
            - Calling test_module_command
        Then:
            - Ensure an exception is raised
        """
        from FireCompass import test_module_command

        mocker.patch.object(client, "_http_request", side_effect=DemistoException("500 Internal Server Error"))
        with pytest.raises(DemistoException):
            test_module_command(client)


class TestGetEventsCommand:
    """Tests for get_events_command function."""

    def test_get_events_default_args(self, client, mocker):
        """
        Given:
            - Default command arguments
        When:
            - Calling get_events_command
        Then:
            - Ensure events are returned with a CommandResults object
        """
        mock_events = [_create_risk_event("event-1"), _create_risk_event("event-2")]
        mocker.patch.object(client, "_http_request", return_value={"data": mock_events})

        events, results = get_events_command(client, {})
        assert len(events) == 2
        assert results.readable_output is not None
        assert "FireCompass" in results.readable_output

    def test_get_events_with_limit(self, client, mocker):
        """
        Given:
            - A limit argument of 1
        When:
            - Calling get_events_command
        Then:
            - Ensure only 1 event is returned (API respects page_size=1)
        """
        mock_events = [_create_risk_event("event-1")]
        mocker.patch.object(client, "_http_request", return_value={"data": mock_events})

        events, results = get_events_command(client, {"limit": "1"})
        assert len(events) == 1

    @freeze_time("2026-03-15T12:00:00Z")
    def test_get_events_with_date_range(self, client, mocker):
        """
        Given:
            - Specific from_date and to_date arguments
        When:
            - Calling get_events_command
        Then:
            - Ensure the correct date range is passed to the API call
        """
        mock_http = mocker.patch.object(client, "_http_request", return_value={"data": []})

        get_events_command(client, {"from_date": "2026-03-10", "to_date": "2026-03-15"})

        mock_http.assert_called_once()
        call_kwargs = mock_http.call_args
        params = call_kwargs.kwargs.get("params") or call_kwargs[1].get("params")
        assert params["from_date"] == "2026-03-10"
        assert params["to_date"] == "2026-03-15"


class TestFetchEventsCommand:
    """Tests for fetch_events_command function."""

    @freeze_time("2026-03-15T12:00:00Z")
    def test_first_fetch(self, client, mocker):
        """
        Given:
            - No previous last_run state (first fetch)
        When:
            - Calling fetch_events_command
        Then:
            - Ensure events are fetched from the hardcoded first fetch time range
            - Ensure next_run state is properly set
        """
        mock_events = [
            _create_risk_event("event-1", created_at="2026-03-13T10:00:00Z", updated_at="2026-03-13T10:00:00Z"),
            _create_risk_event("event-2", created_at="2026-03-14T12:00:00Z", updated_at="2026-03-15T08:00:00Z"),
        ]
        mocker.patch.object(client, "_http_request", return_value={"data": mock_events})

        next_run, events = fetch_events_command(
            client=client,
            last_run={},
            max_events=1000,
        )

        assert len(events) == 2
        assert next_run["last_fetch_time"] == "2026-03-14T12:00:00Z"
        assert "event-2" in next_run["last_fetch_ids"]

    @freeze_time("2026-03-15T12:00:00Z")
    def test_subsequent_fetch_with_dedup(self, client, mocker):
        """
        Given:
            - Previous last_run state with known event IDs
        When:
            - Calling fetch_events_command with overlapping events
        Then:
            - Ensure duplicate events are removed
        """
        mock_events = [
            _create_risk_event("event-2", created_at="2026-03-14T12:00:00Z"),
            _create_risk_event("event-3", created_at="2026-03-15T08:00:00Z"),
        ]
        mocker.patch.object(client, "_http_request", return_value={"data": mock_events})

        last_run = {
            "last_fetch_time": "2026-03-14T12:00:00Z",
            "last_fetch_ids": ["event-1", "event-2"],
        }

        next_run, events = fetch_events_command(
            client=client,
            last_run=last_run,
            max_events=1000,
        )

        # event-2 should be deduplicated
        assert len(events) == 1
        assert events[0]["id"] == "event-3"
        assert next_run["last_fetch_time"] == "2026-03-15T08:00:00Z"

    @freeze_time("2026-03-15T12:00:00Z")
    def test_fetch_no_new_events(self, client, mocker):
        """
        Given:
            - API returns no new events
        When:
            - Calling fetch_events_command
        Then:
            - Ensure last_run state is preserved
        """
        mocker.patch.object(client, "_http_request", return_value={"data": []})

        last_run = {
            "last_fetch_time": "2026-03-14T12:00:00Z",
            "last_fetch_ids": ["event-1"],
        }

        next_run, events = fetch_events_command(
            client=client,
            last_run=last_run,
            max_events=1000,
        )

        assert len(events) == 0
        assert next_run == last_run


class TestParseDateString:
    """Tests for _parse_date_string function."""

    @freeze_time("2026-03-15T12:00:00Z")
    def test_parse_none_default(self):
        """
        Given:
            - None date string
        When:
            - Calling _parse_date_string
        Then:
            - Ensure the result is the current UTC time (today)
        """
        result = _parse_date_string(None)
        assert result.day == 15
        assert result.month == 3
        assert result.year == 2026

    def test_parse_iso_date(self):
        """
        Given:
            - An ISO format date string
        When:
            - Calling _parse_date_string
        Then:
            - Ensure the correct datetime is returned
        """
        result = _parse_date_string("2026-03-10T00:00:00Z")
        assert result.day == 10
        assert result.month == 3

    def test_parse_invalid_date(self):
        """
        Given:
            - An invalid date string
        When:
            - Calling _parse_date_string
        Then:
            - Ensure a ValueError is raised
        """
        with pytest.raises(ValueError):
            _parse_date_string("not-a-date")

    @freeze_time("2026-03-15T12:00:00Z")
    def test_parse_none_with_days_ago(self):
        """
        Given:
            - None date string with default_days_ago=3
        When:
            - Calling _parse_date_string
        Then:
            - Ensure the result is 3 days before now
        """
        result = _parse_date_string(None, default_days_ago=3)
        assert result.day == 12
        assert result.month == 3
        assert result.year == 2026


class TestDatetimeToApiDate:
    """Tests for _datetime_to_api_date function."""

    def test_convert_datetime(self):
        """
        Given:
            - A datetime object
        When:
            - Calling _datetime_to_api_date
        Then:
            - Ensure the correct YYYY-MM-DD string is returned
        """
        from datetime import datetime

        dt = datetime(2026, 3, 15, 12, 0, 0, tzinfo=UTC)
        result = _datetime_to_api_date(dt)
        assert result == "2026-03-15"
