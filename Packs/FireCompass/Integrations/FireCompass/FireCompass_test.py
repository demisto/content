import pytest
from freezegun import freeze_time
from FireCompass import (
    Client,
    get_events_command,
    fetch_events_command,
    _add_fields_to_events,
    _deduplicate_events,
    _fetch_events_with_pagination,
    _build_next_run,
    _advance_day,
    _parse_date_string,
    _datetime_to_api_date,
    _send_events,
    MAX_PAGE_SIZE,
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


def _make_api_response(
    results: list[dict],
    page: int = 1,
    total_pages: int = 1,
    count: int | None = None,
    page_size: int = MAX_PAGE_SIZE,
) -> dict:
    """Helper to create a mock API response with metadata."""
    return {
        "results": results,
        "page": page,
        "total_pages": total_pages,
        "count": count if count is not None else len(results),
        "page_size": page_size,
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
            - Events with IDs that overlap with last_page_fetched_ids
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
        last_page_ids = ["event-1", "event-2"]
        result = _deduplicate_events(events, last_page_ids)
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


class TestAdvanceDay:
    """Tests for _advance_day function."""

    def test_advance_normal_day(self):
        """
        Given:
            - A date string '2026-03-15'
        When:
            - Calling _advance_day
        Then:
            - Ensure '2026-03-16' is returned
        """
        assert _advance_day("2026-03-15") == "2026-03-16"

    def test_advance_end_of_month(self):
        """
        Given:
            - A date string at end of month '2026-03-31'
        When:
            - Calling _advance_day
        Then:
            - Ensure '2026-04-01' is returned
        """
        assert _advance_day("2026-03-31") == "2026-04-01"

    def test_advance_end_of_year(self):
        """
        Given:
            - A date string at end of year '2026-12-31'
        When:
            - Calling _advance_day
        Then:
            - Ensure '2027-01-01' is returned
        """
        assert _advance_day("2026-12-31") == "2027-01-01"


class TestBuildNextRun:
    """Tests for _build_next_run function."""

    def test_build_next_run_basic(self):
        """
        Given:
            - A completed page fetch with events
        When:
            - Calling _build_next_run
        Then:
            - Ensure the state dictionary is correctly built
        """
        events = [_create_risk_event("event-1"), _create_risk_event("event-2")]
        result = _build_next_run(
            current_date="2026-03-15",
            last_page_fetched=3,
            total_pages=5,
            count=487,
            last_batch=events,
        )
        assert result["current_date"] == "2026-03-15"
        assert result["next_page"] == 4
        assert result["total_pages"] == 5
        assert result["count"] == 487
        assert set(result["last_page_fetched_ids"]) == {"event-1", "event-2"}

    def test_build_next_run_no_ids(self):
        """
        Given:
            - Events without ID fields
        When:
            - Calling _build_next_run
        Then:
            - Ensure last_page_fetched_ids is empty
        """
        events = [{"title": "No ID", "created_at": "2026-03-15T12:00:00Z"}]
        result = _build_next_run(
            current_date="2026-03-15",
            last_page_fetched=1,
            total_pages=1,
            count=1,
            last_batch=events,
        )
        assert result["last_page_fetched_ids"] == []

    def test_build_next_run_empty_batch(self):
        """
        Given:
            - An empty last batch
        When:
            - Calling _build_next_run
        Then:
            - Ensure state is built with empty IDs
        """
        result = _build_next_run(
            current_date="2026-03-15",
            last_page_fetched=1,
            total_pages=1,
            count=0,
            last_batch=[],
        )
        assert result["last_page_fetched_ids"] == []
        assert result["next_page"] == 2


class TestFetchEventsWithPagination:
    """Tests for _fetch_events_with_pagination function."""

    def test_single_page_fetch(self, client, mocker):
        """
        Given:
            - API returns fewer events than MAX_PAGE_SIZE on a single page
        When:
            - Calling _fetch_events_with_pagination
        Then:
            - Ensure all events are returned with correct metadata
        """
        events_data = [
            _create_risk_event("event-1", created_at="2026-03-01T10:00:00Z"),
            _create_risk_event("event-2", created_at="2026-03-01T12:00:00Z"),
        ]
        mocker.patch.object(client, "_http_request", return_value=_make_api_response(events_data, count=2))

        events, last_page, total_pages, count = _fetch_events_with_pagination(
            client,
            "2026-03-01",
            "2026-03-01",
            start_page=1,
            limit=100,
        )
        assert len(events) == 2
        assert last_page == 1
        assert total_pages == 1
        assert count == 2

    def test_multi_page_fetch(self, client, mocker):
        """
        Given:
            - API returns events across multiple pages
        When:
            - Calling _fetch_events_with_pagination
        Then:
            - Ensure events from all pages are combined
        """
        page1 = [_create_risk_event(f"event-{i}") for i in range(100)]
        page2 = [_create_risk_event(f"event-{100 + i}") for i in range(50)]

        mocker.patch.object(
            client,
            "_http_request",
            side_effect=[
                _make_api_response(page1, page=1, total_pages=2, count=150),
                _make_api_response(page2, page=2, total_pages=2, count=150),
            ],
        )

        events, last_page, total_pages, count = _fetch_events_with_pagination(
            client,
            "2026-03-01",
            "2026-03-01",
            start_page=1,
            limit=200,
        )
        assert len(events) == 150
        assert last_page == 2
        assert total_pages == 2
        assert count == 150

    def test_empty_response(self, client, mocker):
        """
        Given:
            - API returns an empty results list
        When:
            - Calling _fetch_events_with_pagination
        Then:
            - Ensure an empty list is returned
        """
        mocker.patch.object(client, "_http_request", return_value=_make_api_response([], count=0, total_pages=0))

        events, last_page, total_pages, count = _fetch_events_with_pagination(
            client,
            "2026-03-01",
            "2026-03-01",
            start_page=1,
            limit=100,
        )
        assert events == []
        assert count == 0

    def test_limit_trims_results(self, client, mocker):
        """
        Given:
            - API returns 100 events but limit is 30
        When:
            - Calling _fetch_events_with_pagination with limit=30
        Then:
            - Ensure only 30 events are returned (trimmed from full page)
        """
        page_events = [_create_risk_event(f"event-{i}") for i in range(100)]
        mocker.patch.object(
            client,
            "_http_request",
            return_value=_make_api_response(page_events, page=1, total_pages=5, count=487),
        )

        events, last_page, total_pages, count = _fetch_events_with_pagination(
            client,
            "2026-03-01",
            "2026-03-01",
            start_page=1,
            limit=30,
        )
        assert len(events) == 30
        assert total_pages == 5
        assert count == 487

    def test_start_page_respected(self, client, mocker):
        """
        Given:
            - start_page is set to 3
        When:
            - Calling _fetch_events_with_pagination
        Then:
            - Ensure the API is called starting from page 3
        """
        page3_events = [_create_risk_event(f"event-{i}") for i in range(50)]
        mock_http = mocker.patch.object(
            client,
            "_http_request",
            return_value=_make_api_response(page3_events, page=3, total_pages=3, count=250),
        )

        events, last_page, total_pages, count = _fetch_events_with_pagination(
            client,
            "2026-03-01",
            "2026-03-01",
            start_page=3,
            limit=100,
        )
        assert len(events) == 50
        assert last_page == 3

        # Verify page=3 was passed to the API
        call_params = mock_http.call_args.kwargs["params"]
        assert call_params["page"] == 3

    def test_page_size_uses_limit_when_smaller(self, client, mocker):
        """
        Given:
            - A limit (10) smaller than MAX_PAGE_SIZE (100)
        When:
            - Calling _fetch_events_with_pagination
        Then:
            - Ensure page_size equals the limit (not MAX_PAGE_SIZE)
        """
        page_events = [_create_risk_event(f"event-{i}") for i in range(10)]
        mock_http = mocker.patch.object(
            client,
            "_http_request",
            return_value=_make_api_response(page_events, count=10),
        )

        _fetch_events_with_pagination(client, "2026-03-01", "2026-03-01", start_page=1, limit=10, page_size=10)

        call_params = mock_http.call_args.kwargs["params"]
        assert call_params["page_size"] == 10

    def test_page_size_capped_at_max(self, client, mocker):
        """
        Given:
            - A limit (500) larger than MAX_PAGE_SIZE (100)
        When:
            - Calling _fetch_events_with_pagination
        Then:
            - Ensure page_size is capped at MAX_PAGE_SIZE
        """
        page_events = [_create_risk_event(f"event-{i}") for i in range(100)]
        mock_http = mocker.patch.object(
            client,
            "_http_request",
            return_value=_make_api_response(page_events, page=1, total_pages=5, count=500),
        )

        _fetch_events_with_pagination(client, "2026-03-01", "2026-03-01", start_page=1, limit=500)

        call_params = mock_http.call_args_list[0].kwargs["params"]
        assert call_params["page_size"] == MAX_PAGE_SIZE

    def test_stops_at_total_pages(self, client, mocker):
        """
        Given:
            - API reports total_pages=2 and limit allows more
        When:
            - Calling _fetch_events_with_pagination
        Then:
            - Ensure pagination stops at total_pages (no page 3 call)
        """
        page1 = [_create_risk_event(f"event-{i}") for i in range(100)]
        page2 = [_create_risk_event(f"event-{100 + i}") for i in range(100)]

        mock_http = mocker.patch.object(
            client,
            "_http_request",
            side_effect=[
                _make_api_response(page1, page=1, total_pages=2, count=200),
                _make_api_response(page2, page=2, total_pages=2, count=200),
            ],
        )

        events, last_page, total_pages, count = _fetch_events_with_pagination(
            client,
            "2026-03-01",
            "2026-03-01",
            start_page=1,
            limit=500,
        )
        assert len(events) == 200
        assert last_page == 2
        assert mock_http.call_count == 2  # No page 3 call

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
            _fetch_events_with_pagination(client, "2026-03-01", "2026-03-01", start_page=1, limit=100)


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

        mocker.patch.object(client, "_http_request", return_value=_make_api_response([]))
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
        mocker.patch.object(client, "_http_request", return_value=_make_api_response(mock_events, count=2))

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
            - Ensure only 1 event is returned (trimmed from full page)
        """
        mock_events = [_create_risk_event("event-1"), _create_risk_event("event-2")]
        mocker.patch.object(client, "_http_request", return_value=_make_api_response(mock_events, count=2))

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
        mock_http = mocker.patch.object(client, "_http_request", return_value=_make_api_response([]))

        get_events_command(client, {"from_date": "2026-03-10", "to_date": "2026-03-15"})

        mock_http.assert_called_once()
        call_kwargs = mock_http.call_args
        params = call_kwargs.kwargs.get("params") or call_kwargs[1].get("params")
        assert params["from_date"] == "2026-03-10"
        assert params["to_date"] == "2026-03-15"


class TestFetchEventsCommand:
    """Tests for fetch_events_command with page-resumption strategy."""

    @freeze_time("2026-03-15T12:00:00Z")
    def test_first_fetch(self, client, mocker):
        """
        Given:
            - No previous last_run state (first fetch)
        When:
            - Calling fetch_events_command
        Then:
            - Ensure events are fetched for today with page-resumption state
        """
        mock_events = [
            _create_risk_event("event-1", created_at="2026-03-15T10:00:00Z"),
            _create_risk_event("event-2", created_at="2026-03-15T12:00:00Z"),
        ]
        mocker.patch.object(
            client,
            "_http_request",
            return_value=_make_api_response(mock_events, page=1, total_pages=1, count=2),
        )

        next_run, events = fetch_events_command(client=client, last_run={}, max_events=1000)

        assert len(events) == 2
        assert next_run["current_date"] == "2026-03-15"
        assert next_run["next_page"] == 2
        assert next_run["total_pages"] == 1
        assert next_run["count"] == 2
        assert "event-1" in next_run["last_page_fetched_ids"]
        assert "event-2" in next_run["last_page_fetched_ids"]

    @freeze_time("2026-03-15T12:00:00Z")
    def test_resume_pagination(self, client, mocker):
        """
        Given:
            - Previous state with next_page=3 and total_pages=5
        When:
            - Calling fetch_events_command
        Then:
            - Ensure pagination resumes from page 3
        """
        page3_events = [_create_risk_event(f"event-{i}") for i in range(100)]
        page4_events = [_create_risk_event(f"event-{100 + i}") for i in range(100)]
        page5_events = [_create_risk_event(f"event-{200 + i}") for i in range(50)]

        mock_http = mocker.patch.object(
            client,
            "_http_request",
            side_effect=[
                _make_api_response(page3_events, page=3, total_pages=5, count=450),
                _make_api_response(page4_events, page=4, total_pages=5, count=450),
                _make_api_response(page5_events, page=5, total_pages=5, count=450),
            ],
        )

        last_run = {
            "current_date": "2026-03-15",
            "next_page": 3,
            "total_pages": 5,
            "count": 450,
            "last_page_fetched_ids": ["prev-event-1"],
        }

        next_run, events = fetch_events_command(client=client, last_run=last_run, max_events=1000)

        assert len(events) == 250
        assert next_run["next_page"] == 6
        assert next_run["total_pages"] == 5

        # Verify first API call was for page 3
        first_call_params = mock_http.call_args_list[0].kwargs["params"]
        assert first_call_params["page"] == 3

    @freeze_time("2026-03-16T12:00:00Z")
    def test_day_advancement(self, client, mocker):
        """
        Given:
            - All pages consumed for 2026-03-15, now it's 2026-03-16
        When:
            - Calling fetch_events_command
        Then:
            - Ensure probe finds no late events on 2026-03-15, then advances to 2026-03-16
        """
        # First call: probe March 15 (count unchanged → no late events)
        probe_response = _make_api_response(
            [_create_risk_event("old-event")],
            page=5,
            total_pages=5,
            count=487,
        )
        # Second call: fetch March 16
        new_day_events = [_create_risk_event("event-new-1", created_at="2026-03-16T08:00:00Z")]
        new_day_response = _make_api_response(new_day_events, page=1, total_pages=1, count=1)

        mock_http = mocker.patch.object(
            client,
            "_http_request",
            side_effect=[probe_response, new_day_response],
        )

        last_run = {
            "current_date": "2026-03-15",
            "next_page": 6,
            "total_pages": 5,
            "count": 487,
            "last_page_fetched_ids": ["old-event"],
        }

        next_run, events = fetch_events_command(client=client, last_run=last_run, max_events=1000)

        assert len(events) == 1
        assert next_run["current_date"] == "2026-03-16"
        assert next_run["next_page"] == 2

        # Verify probe was called for March 15, then fetch for March 16
        assert mock_http.call_count == 2
        probe_params = mock_http.call_args_list[0].kwargs["params"]
        assert probe_params["from_date"] == "2026-03-15"
        fetch_params = mock_http.call_args_list[1].kwargs["params"]
        assert fetch_params["from_date"] == "2026-03-16"

    @freeze_time("2026-03-16T12:00:00Z")
    def test_day_advancement_with_late_events(self, client, mocker):
        """
        Given:
            - All pages consumed for 2026-03-15, now it's 2026-03-16
            - But new events were added to 2026-03-15 after the last fetch
        When:
            - Calling fetch_events_command
        Then:
            - Ensure late events on 2026-03-15 are fetched before advancing
        """
        # Probe March 15: count increased (487 → 490), same total_pages
        probe_events = [
            _create_risk_event("old-event"),
            _create_risk_event("late-event-1"),
            _create_risk_event("late-event-2"),
            _create_risk_event("late-event-3"),
        ]
        mocker.patch.object(
            client,
            "_http_request",
            return_value=_make_api_response(probe_events, page=5, total_pages=5, count=490),
        )

        last_run = {
            "current_date": "2026-03-15",
            "next_page": 6,
            "total_pages": 5,
            "count": 487,
            "last_page_fetched_ids": ["old-event"],
        }

        next_run, events = fetch_events_command(client=client, last_run=last_run, max_events=1000)

        # Should get 3 late events (old-event deduped)
        assert len(events) == 3
        assert next_run["current_date"] == "2026-03-15"  # Did NOT advance yet
        assert next_run["count"] == 490

    @freeze_time("2026-03-15T12:00:00Z")
    def test_same_day_no_new_events(self, client, mocker):
        """
        Given:
            - All pages consumed, same day, count unchanged
        When:
            - Calling fetch_events_command
        Then:
            - Ensure empty list is returned and state is preserved
        """
        # Probe returns same count
        probe_events = [_create_risk_event("event-old")]
        mocker.patch.object(
            client,
            "_http_request",
            return_value=_make_api_response(probe_events, page=5, total_pages=5, count=487),
        )

        last_run = {
            "current_date": "2026-03-15",
            "next_page": 6,
            "total_pages": 5,
            "count": 487,
            "last_page_fetched_ids": ["event-old"],
        }

        next_run, events = fetch_events_command(client=client, last_run=last_run, max_events=1000)

        assert len(events) == 0
        assert next_run == last_run

    @freeze_time("2026-03-15T12:00:00Z")
    def test_same_day_new_events_same_total_pages(self, client, mocker):
        """
        Given:
            - All pages consumed, same day, count increased but total_pages unchanged
            (new events landed on the last page which wasn't full)
        When:
            - Calling fetch_events_command
        Then:
            - Ensure only new events are returned (deduped against last_page_fetched_ids)
        """
        # Probe returns increased count, same total_pages
        probe_events = [
            _create_risk_event("event-old-1"),
            _create_risk_event("event-old-2"),
            _create_risk_event("event-new-1"),
        ]
        mocker.patch.object(
            client,
            "_http_request",
            return_value=_make_api_response(probe_events, page=3, total_pages=3, count=210),
        )

        last_run = {
            "current_date": "2026-03-15",
            "next_page": 4,
            "total_pages": 3,
            "count": 200,
            "last_page_fetched_ids": ["event-old-1", "event-old-2"],
        }

        next_run, events = fetch_events_command(client=client, last_run=last_run, max_events=1000)

        assert len(events) == 1
        assert events[0]["id"] == "event-new-1"
        assert next_run["count"] == 210

    @freeze_time("2026-03-15T12:00:00Z")
    def test_same_day_new_events_more_total_pages(self, client, mocker):
        """
        Given:
            - All pages consumed, same day, count and total_pages both increased
        When:
            - Calling fetch_events_command
        Then:
            - Ensure the old last page is deduped and new pages are fetched
        """
        # Probe re-fetches old last page (page 3) — has old + new events
        probe_events = [
            _create_risk_event("event-old-1"),
            _create_risk_event("event-old-2"),
            _create_risk_event("event-new-on-old-page"),
        ]
        # New page 4
        page4_events = [_create_risk_event("event-new-page4")]

        mocker.patch.object(
            client,
            "_http_request",
            side_effect=[
                # Probe call (re-fetches page 3)
                _make_api_response(probe_events, page=3, total_pages=4, count=310),
                # Fetch page 4
                _make_api_response(page4_events, page=4, total_pages=4, count=310),
            ],
        )

        last_run = {
            "current_date": "2026-03-15",
            "next_page": 4,
            "total_pages": 3,
            "count": 300,
            "last_page_fetched_ids": ["event-old-1", "event-old-2"],
        }

        next_run, events = fetch_events_command(client=client, last_run=last_run, max_events=1000)

        # Should get: event-new-on-old-page (deduped from probe) + event-new-page4
        assert len(events) == 2
        event_ids = [e["id"] for e in events]
        assert "event-new-on-old-page" in event_ids
        assert "event-new-page4" in event_ids
        assert next_run["total_pages"] == 4
        assert next_run["count"] == 310

    @freeze_time("2026-03-15T12:00:00Z")
    def test_first_fetch_no_events(self, client, mocker):
        """
        Given:
            - First fetch with no events available
        When:
            - Calling fetch_events_command
        Then:
            - Ensure minimal state is saved
        """
        mocker.patch.object(
            client,
            "_http_request",
            return_value=_make_api_response([], total_pages=0, count=0),
        )

        next_run, events = fetch_events_command(client=client, last_run={}, max_events=1000)

        assert len(events) == 0
        assert next_run["current_date"] == "2026-03-15"
        assert next_run["count"] == 0

    @freeze_time("2026-03-15T12:00:00Z")
    def test_mid_pagination_limit_reached(self, client, mocker):
        """
        Given:
            - API has 5 pages but max_events allows only 2 pages worth
        When:
            - Calling fetch_events_command
        Then:
            - Ensure pagination stops at limit and state saves the resume point
        """
        page1 = [_create_risk_event(f"event-{i}") for i in range(100)]
        page2 = [_create_risk_event(f"event-{100 + i}") for i in range(100)]

        mocker.patch.object(
            client,
            "_http_request",
            side_effect=[
                _make_api_response(page1, page=1, total_pages=5, count=487),
                _make_api_response(page2, page=2, total_pages=5, count=487),
            ],
        )

        next_run, events = fetch_events_command(client=client, last_run={}, max_events=150)

        # Fetched 200 events (2 full pages), trimmed to 150
        assert len(events) == 150
        # State should allow resuming from page 3
        assert next_run["next_page"] == 3
        assert next_run["total_pages"] == 5


class TestSendEvents:
    """Tests for _send_events function."""

    def test_send_events_adds_fields_and_sends(self, mocker):
        """
        Given:
            - A list of events without _time and _ENTRY_STATUS fields
        When:
            - Calling _send_events
        Then:
            - Ensure _add_fields_to_events is called and events are sent via send_events_to_xsiam
        """
        events = [
            _create_risk_event("event-1", created_at="2026-03-01T12:00:00Z", updated_at="2026-03-01T12:00:00Z"),
            _create_risk_event("event-2", created_at="2026-03-02T12:00:00Z", updated_at="2026-03-03T12:00:00Z"),
        ]
        mock_send = mocker.patch("FireCompass.send_events_to_xsiam")

        _send_events(events)

        # Verify fields were added
        assert events[0]["_time"] == "2026-03-01T12:00:00Z"
        assert events[0]["_ENTRY_STATUS"] == "new"
        assert events[1]["_ENTRY_STATUS"] == "modified"

        # Verify send was called with correct vendor/product
        mock_send.assert_called_once_with(events, vendor="FireCompass", product="FireCompass")

    def test_send_events_empty_list(self, mocker):
        """
        Given:
            - An empty list of events
        When:
            - Calling _send_events
        Then:
            - Ensure send_events_to_xsiam is still called (with empty list)
        """
        mock_send = mocker.patch("FireCompass.send_events_to_xsiam")

        _send_events([])

        mock_send.assert_called_once_with([], vendor="FireCompass", product="FireCompass")


class TestClientGetRisks:
    """Tests for Client.get_risks method."""

    def test_get_risks_passes_correct_params(self, client, mocker):
        """
        Given:
            - Specific page, page_size, from_date, and to_date parameters
        When:
            - Calling client.get_risks
        Then:
            - Ensure _http_request is called with the correct params
        """
        mock_http = mocker.patch.object(client, "_http_request", return_value=_make_api_response([]))

        client.get_risks(page=2, page_size=50, from_date="2026-03-01", to_date="2026-03-15")

        mock_http.assert_called_once_with(
            method="GET",
            url_suffix="/rest/v4/risk",
            params={
                "page": 2,
                "page_size": 50,
                "from_date": "2026-03-01",
                "to_date": "2026-03-15",
            },
            resp_type="json",
        )

    def test_get_risks_caps_page_size(self, client, mocker):
        """
        Given:
            - A page_size larger than MAX_PAGE_SIZE (100)
        When:
            - Calling client.get_risks
        Then:
            - Ensure page_size is capped at 100
        """
        mock_http = mocker.patch.object(client, "_http_request", return_value=_make_api_response([]))

        client.get_risks(page=1, page_size=500, from_date="2026-03-01", to_date="2026-03-15")

        call_params = mock_http.call_args.kwargs["params"]
        assert call_params["page_size"] == 100


class TestEndToEndFetch:
    """End-to-end tests simulating multiple fetch cycles with page-resumption."""

    @freeze_time("2026-03-15T12:00:00Z")
    def test_full_day_pagination_then_probe(self, client, mocker):
        """
        Given:
            - Day has 3 pages of events, max_events=150 (1.5 pages)
        When:
            - Running multiple fetch cycles
        Then:
            - Cycle 1: fetches pages 1-2, trims to 150, saves next_page=3
            - Cycle 2: fetches page 3 (remaining), saves next_page=4
            - Cycle 3: probes, count unchanged → empty
        """
        page1 = [_create_risk_event(f"e-{i}") for i in range(100)]
        page2 = [_create_risk_event(f"e-{100 + i}") for i in range(100)]
        page3 = [_create_risk_event(f"e-{200 + i}") for i in range(50)]

        # Cycle 1: pages 1 and 2
        mocker.patch.object(
            client,
            "_http_request",
            side_effect=[
                _make_api_response(page1, page=1, total_pages=3, count=250),
                _make_api_response(page2, page=2, total_pages=3, count=250),
            ],
        )
        next_run_1, events_1 = fetch_events_command(client=client, last_run={}, max_events=150)
        assert len(events_1) == 150
        assert next_run_1["next_page"] == 3
        assert next_run_1["total_pages"] == 3

        # Cycle 2: page 3 (resume)
        mocker.patch.object(
            client,
            "_http_request",
            return_value=_make_api_response(page3, page=3, total_pages=3, count=250),
        )
        next_run_2, events_2 = fetch_events_command(client=client, last_run=next_run_1, max_events=150)
        assert len(events_2) == 50
        assert next_run_2["next_page"] == 4
        assert next_run_2["total_pages"] == 3

        # Cycle 3: probe — count unchanged
        mocker.patch.object(
            client,
            "_http_request",
            return_value=_make_api_response(page3, page=3, total_pages=3, count=250),
        )
        next_run_3, events_3 = fetch_events_command(client=client, last_run=next_run_2, max_events=150)
        assert len(events_3) == 0
        assert next_run_3 == next_run_2

    def test_multi_day_catchup(self, client, mocker):
        """
        Given:
            - Integration was down from March 13 to March 15
        When:
            - Running fetch cycles starting from March 13
        Then:
            - Each cycle processes one day, probes for late events, then advances
        """
        # Cycle 1: Fetch March 13 events (resume path: next_page=1 <= total_pages=1)
        with freeze_time("2026-03-15T12:00:00Z"):
            march13_events = [_create_risk_event("e-13", created_at="2026-03-13T10:00:00Z")]
            mocker.patch.object(
                client,
                "_http_request",
                return_value=_make_api_response(march13_events, count=1),
            )
            next_run_1, events_1 = fetch_events_command(
                client=client,
                last_run={
                    "current_date": "2026-03-13",
                    "next_page": 1,
                    "total_pages": 1,
                    "count": 0,
                    "last_page_fetched_ids": [],
                },
                max_events=1000,
            )
            assert len(events_1) == 1
            assert next_run_1["current_date"] == "2026-03-13"

        # Cycle 2: Probe March 13 (count unchanged) → advance to March 14 → fetch
        with freeze_time("2026-03-15T12:00:00Z"):
            march14_events = [_create_risk_event("e-14", created_at="2026-03-14T10:00:00Z")]
            mocker.patch.object(
                client,
                "_http_request",
                side_effect=[
                    # Probe March 13: count=1 (unchanged) → no late events
                    _make_api_response(march13_events, count=1),
                    # Fetch March 14
                    _make_api_response(march14_events, count=1),
                ],
            )
            next_run_2, events_2 = fetch_events_command(client=client, last_run=next_run_1, max_events=1000)
            assert len(events_2) == 1
            assert next_run_2["current_date"] == "2026-03-14"

        # Cycle 3: Probe March 14 (count unchanged) → advance to March 15 → fetch
        with freeze_time("2026-03-15T12:00:00Z"):
            march15_events = [_create_risk_event("e-15", created_at="2026-03-15T10:00:00Z")]
            mocker.patch.object(
                client,
                "_http_request",
                side_effect=[
                    # Probe March 14: count=1 (unchanged)
                    _make_api_response(march14_events, count=1),
                    # Fetch March 15
                    _make_api_response(march15_events, count=1),
                ],
            )
            next_run_3, events_3 = fetch_events_command(client=client, last_run=next_run_2, max_events=1000)
            assert len(events_3) == 1
            assert next_run_3["current_date"] == "2026-03-15"

    @freeze_time("2026-03-15T12:00:00Z")
    def test_same_day_new_events_then_no_change(self, client, mocker):
        """
        Given:
            - Day fully consumed, then new events appear, then no more changes
        When:
            - Running multiple fetch cycles
        Then:
            - Cycle 1: fetches all events for the day
            - Cycle 2: probes, detects new events, fetches only new ones
            - Cycle 3: probes, no change → empty
        """
        # Cycle 1: initial fetch
        initial_events = [_create_risk_event(f"e-{i}") for i in range(50)]
        mocker.patch.object(
            client,
            "_http_request",
            return_value=_make_api_response(initial_events, page=1, total_pages=1, count=50),
        )
        next_run_1, events_1 = fetch_events_command(client=client, last_run={}, max_events=1000)
        assert len(events_1) == 50

        # Cycle 2: probe detects new events (count 50 → 55, total_pages still 1)
        updated_page = initial_events + [_create_risk_event(f"e-new-{i}") for i in range(5)]
        mocker.patch.object(
            client,
            "_http_request",
            return_value=_make_api_response(updated_page, page=1, total_pages=1, count=55),
        )
        next_run_2, events_2 = fetch_events_command(client=client, last_run=next_run_1, max_events=1000)
        assert len(events_2) == 5  # Only new events

        # Cycle 3: probe, no change
        mocker.patch.object(
            client,
            "_http_request",
            return_value=_make_api_response(updated_page, page=1, total_pages=1, count=55),
        )
        next_run_3, events_3 = fetch_events_command(client=client, last_run=next_run_2, max_events=1000)
        assert len(events_3) == 0


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
