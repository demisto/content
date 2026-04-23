import json

import pytest

import demistomock as demisto
from MenloSecurity import (
    Client,
    DEFAULT_FIRST_FETCH,
    LOG_TYPE_MAP,
    MAX_EVENTS_PER_PAGE,
    SOURCE_LOG_TYPE_MAP,
    ALL_LOG_TYPES,
    fetch_events,
    get_boundary_hashes,
    get_events_command,
    get_events_for_log_type,
    hash_event,
    test_module,
)


# ─── Helpers ─────────────────────────────────────────────────────────────────

API_URL = "https://logs.menlosecurity.com/api/rep/v1/fetch/client_select"


def load_test_data(filename: str) -> dict:
    """Load JSON test data from the test_data directory."""
    with open(f"test_data/{filename}") as f:
        return json.load(f)


@pytest.fixture
def client() -> Client:
    return Client(
        base_url="https://logs.menlosecurity.com",
        token="test-token-12345",
        verify=False,
        proxy=False,
    )


# ─── Client Tests ─────────────────────────────────────────────────────────────


class TestClient:
    def test_fetch_log_page_first_page(self, client: Client, requests_mock):
        """
        Given:
            - A first-page request (no pagingIdentifiers).
        When:
            - Calling fetch_log_page without paging_identifiers.
        Then:
            - The request body must NOT contain pagingIdentifiers.
            - The correct log_type and token are sent.
        """
        web_response = load_test_data("web_logs_response.json")
        requests_mock.post(API_URL, json=web_response)

        result = client.fetch_log_page(log_type="web", start=1700000000, end=1700003600, limit=1000)

        assert result == web_response
        body = requests_mock.last_request.json()
        assert "pagingIdentifiers" not in body
        assert body["log_type"] == "web"
        assert body["token"] == "test-token-12345"

    def test_fetch_log_page_with_paging(self, client: Client, requests_mock):
        """
        Given:
            - A subsequent page request with pagingIdentifiers from the previous response.
        When:
            - Calling fetch_log_page with paging_identifiers.
        Then:
            - The pagingIdentifiers are included in the request body.
        """
        empty_response = load_test_data("empty_response.json")
        requests_mock.post(API_URL, json=empty_response)

        paging = {"next_time": "2024-01-15T10:00:00.000Z", "hashes": {"abc123": 0}, "last_iteration": True}
        client.fetch_log_page(log_type="web", start=1700000000, end=1700003600, limit=1000, paging_identifiers=paging)

        body = requests_mock.last_request.json()
        assert body["pagingIdentifiers"] == paging

    def test_fetch_log_page_url_params(self, client: Client, requests_mock):
        """
        Given:
            - A log page request with specific start, end, and limit values.
        When:
            - Calling fetch_log_page.
        Then:
            - start, end, limit, and format=json are passed as URL query parameters.
        """
        requests_mock.post(API_URL, json=load_test_data("empty_response.json"))

        client.fetch_log_page(log_type="audit", start=1700000000, end=1700003600, limit=500)

        qs = requests_mock.last_request.qs
        assert qs["start"] == ["1700000000"]
        assert qs["end"] == ["1700003600"]
        assert qs["limit"] == ["500"]
        assert qs["format"] == ["json"]


# ─── get_events_for_log_type Tests ───────────────────────────────────────────


class TestGetEventsForLogType:
    def test_single_page_fetch_enriches_events(self, client: Client, requests_mock):
        """
        Given:
            - A single page of web logs followed by an empty response.
        When:
            - Calling get_events_for_log_type with enrich=True (default).
        Then:
            - Events are returned with _time and source_log_type fields added.
            - The event envelope {"event": {...}} is unwrapped.
        """
        requests_mock.post(
            API_URL,
            [{"json": load_test_data("web_logs_response.json")}, {"json": load_test_data("empty_response.json")}],
        )

        events = get_events_for_log_type(client=client, log_type_ui="web", start_epoch=1700000000, end_epoch=1700003600, max_events=5000)

        assert len(events) == 1
        assert events[0]["source_log_type"] == "web_logs"
        assert "_time" in events[0]
        assert "2024-01-15" in events[0]["_time"]
        assert events[0]["domain"] == "example.com"

    def test_no_enrichment_when_enrich_false(self, client: Client, requests_mock):
        """
        Given:
            - A single page of web logs.
        When:
            - Calling get_events_for_log_type with enrich=False.
        Then:
            - Events are returned WITHOUT _time or source_log_type fields.
        """
        requests_mock.post(
            API_URL,
            [{"json": load_test_data("web_logs_response.json")}, {"json": load_test_data("empty_response.json")}],
        )

        events = get_events_for_log_type(client=client, log_type_ui="web", start_epoch=1700000000, end_epoch=1700003600, max_events=5000, enrich=False)

        assert len(events) == 1
        assert "_time" not in events[0]
        assert "source_log_type" not in events[0]

    def test_safemail_maps_to_email_api_type(self, client: Client, requests_mock):
        """
        Given:
            - The "safemail" UI log type is selected.
        When:
            - Calling get_events_for_log_type.
        Then:
            - The API is called with log_type="email" (not "safemail").
            - Events have source_log_type="email_logs".
        """
        email_response = {
            "timestamp": "2024-01-15T10:00:00.000Z",
            "result": {
                "events": [{"event": {"event_time": "2024-01-15T10:00:00", "name": "url-rewrite", "domain": "cnn.com"}}],
                "pagingIdentifiers": {},
            },
        }
        requests_mock.post(API_URL, [{"json": email_response}, {"json": load_test_data("empty_response.json")}])

        events = get_events_for_log_type(client=client, log_type_ui="safemail", start_epoch=1700000000, end_epoch=1700003600, max_events=5000)

        assert len(events) == 1
        assert events[0]["source_log_type"] == "email_logs"
        assert requests_mock.request_history[0].json()["log_type"] == "email"

    def test_max_events_controls_page_limit_sent_to_api(self, client: Client, requests_mock):
        """
        Given:
            - max_events is set to 50 (less than MAX_EVENTS_PER_PAGE=1000).
        When:
            - Calling get_events_for_log_type.
        Then:
            - The API is called with limit=50 in the URL query params.
        """
        requests_mock.post(API_URL, json=load_test_data("empty_response.json"))

        get_events_for_log_type(client=client, log_type_ui="web", start_epoch=1700000000, end_epoch=1700003600, max_events=50)

        assert requests_mock.last_request.qs["limit"] == ["50"]

    def test_empty_response_stops_pagination(self, client: Client, requests_mock):
        """
        Given:
            - The API returns an empty events list on the first call.
        When:
            - Calling get_events_for_log_type.
        Then:
            - Pagination stops immediately and no events are returned.
            - Only one API call is made.
        """
        requests_mock.post(API_URL, json=load_test_data("empty_response.json"))

        events = get_events_for_log_type(client=client, log_type_ui="audit", start_epoch=1700000000, end_epoch=1700003600, max_events=5000)

        assert events == []
        assert requests_mock.call_count == 1

    def test_api_error_returns_partial_results(self, client: Client, requests_mock):
        """
        Given:
            - The first API call succeeds but the second raises a connection error.
        When:
            - Calling get_events_for_log_type.
        Then:
            - Events from the first page are returned despite the error.
        """
        requests_mock.post(
            API_URL,
            [{"json": load_test_data("web_logs_response.json")}, {"exc": Exception("Connection error")}],
        )

        events = get_events_for_log_type(client=client, log_type_ui="web", start_epoch=1700000000, end_epoch=1700003600, max_events=5000)

        assert len(events) == 1


# ─── fetch_events Tests ───────────────────────────────────────────────────────


class TestFetchEvents:
    def test_first_fetch_uses_first_fetch_time(self, client: Client, requests_mock):
        """
        Given:
            - No last_run (first fetch cycle).
        When:
            - Calling fetch_events with first_fetch_time="1 day".
        Then:
            - Events are fetched and next_run is populated with last_fetch_time.
        """
        requests_mock.post(API_URL, json=load_test_data("empty_response.json"))

        next_run, events = fetch_events(client=client, last_run={}, log_types=["web"], first_fetch_time="1 day", max_events_per_fetch=5000)

        assert events == []
        assert "web" in next_run
        assert "last_fetch_time" in next_run["web"]

    def test_subsequent_fetch_uses_last_run_time(self, client: Client, requests_mock):
        """
        Given:
            - A last_run with last_fetch_time="2024-01-15T09:00:00Z".
        When:
            - Calling fetch_events.
        Then:
            - The API is called with start=1705312800 (epoch of 2024-01-15T09:00:00Z).
        """
        requests_mock.post(API_URL, json=load_test_data("empty_response.json"))

        fetch_events(
            client=client,
            last_run={"web": {"last_fetch_time": "2024-01-15T09:00:00Z"}},
            log_types=["web"],
            first_fetch_time="3 days",
            max_events_per_fetch=5000,
        )

        assert int(requests_mock.last_request.qs["start"][0]) == 1705312800

    def test_all_selected_log_types_are_fetched(self, client: Client, requests_mock):
        """
        Given:
            - Three log types are selected: web, audit, dlp.
        When:
            - Calling fetch_events.
        Then:
            - One API request is made per log type.
            - next_run contains an entry for each log type.
        """
        requests_mock.post(API_URL, json=load_test_data("empty_response.json"))

        next_run, _ = fetch_events(client=client, last_run={}, log_types=["web", "audit", "dlp"], first_fetch_time="1 hour", max_events_per_fetch=5000)

        assert requests_mock.call_count == 3
        assert "web" in next_run
        assert "audit" in next_run
        assert "dlp" in next_run

    def test_next_run_uses_request_end_time_when_no_events(self, client: Client, requests_mock):
        """
        Given:
            - No events are returned by the API.
        When:
            - Calling fetch_events.
        Then:
            - next_run["web"]["last_fetch_time"] is set to the request's end time (a valid ISO timestamp).
        """
        from CommonServerPython import arg_to_datetime

        requests_mock.post(API_URL, json=load_test_data("empty_response.json"))

        next_run, _ = fetch_events(client=client, last_run={}, log_types=["web"], first_fetch_time="1 hour", max_events_per_fetch=5000)

        assert "last_fetch_time" in next_run["web"]
        assert arg_to_datetime(next_run["web"]["last_fetch_time"]) is not None

    def test_next_run_uses_last_event_time_when_events_exist(self, client: Client, requests_mock):
        """
        Given:
            - One event is returned with event_time "2024-01-15T10:00:40.548000".
        When:
            - Calling fetch_events.
        Then:
            - next_run["web"]["last_fetch_time"] equals the event's event_time.
            - next_run["web"]["boundary_hashes"] contains one hash.
        """
        requests_mock.post(
            API_URL,
            [{"json": load_test_data("web_logs_response.json")}, {"json": load_test_data("empty_response.json")}],
        )

        next_run, events = fetch_events(client=client, last_run={}, log_types=["web"], first_fetch_time="1 hour", max_events_per_fetch=5000)

        assert len(events) == 1
        assert "2024-01-15" in next_run["web"]["last_fetch_time"]
        assert "boundary_hashes" in next_run["web"]
        assert len(next_run["web"]["boundary_hashes"]) == 1

    def test_dedup_removes_events_matching_boundary_hash(self, client: Client, requests_mock):
        """
        Given:
            - A previous cycle ended with an event whose hash is stored in boundary_hashes.
        When:
            - The same event is returned at the start of the next cycle.
        Then:
            - The duplicate event is filtered out.
        """
        requests_mock.post(
            API_URL,
            [{"json": load_test_data("web_logs_response.json")}, {"json": load_test_data("empty_response.json")}],
        )

        # First cycle: get the event and its hash
        _, events_cycle1 = fetch_events(client=client, last_run={}, log_types=["web"], first_fetch_time="1 hour", max_events_per_fetch=5000)
        assert len(events_cycle1) == 1
        boundary_hash = hash_event(events_cycle1[0])

        # Second cycle: same event returned, should be deduped
        requests_mock.post(
            API_URL,
            [{"json": load_test_data("web_logs_response.json")}, {"json": load_test_data("empty_response.json")}],
        )
        last_run = {"web": {"last_fetch_time": "2024-01-15T10:00:40.548000", "boundary_hashes": [boundary_hash]}}
        _, events_cycle2 = fetch_events(client=client, last_run=last_run, log_types=["web"], first_fetch_time="1 hour", max_events_per_fetch=5000)

        assert len(events_cycle2) == 0

    def test_dedup_keeps_events_with_different_hash(self, client: Client, requests_mock):
        """
        Given:
            - An event has the same event_time as last_fetch_time but a different hash.
        When:
            - Calling fetch_events.
        Then:
            - The event is NOT filtered out (different content = not a duplicate).
        """
        requests_mock.post(
            API_URL,
            [{"json": load_test_data("web_logs_response.json")}, {"json": load_test_data("empty_response.json")}],
        )

        last_run = {"web": {"last_fetch_time": "2024-01-15T10:00:40.548000", "boundary_hashes": ["deadbeef00000000"]}}
        _, events = fetch_events(client=client, last_run=last_run, log_types=["web"], first_fetch_time="1 hour", max_events_per_fetch=5000)

        assert len(events) == 1

    def test_no_dedup_on_first_fetch(self, client: Client, requests_mock):
        """
        Given:
            - No last_run (first fetch cycle, no boundary_hashes).
        When:
            - Calling fetch_events.
        Then:
            - All events are returned without any dedup filtering.
        """
        requests_mock.post(
            API_URL,
            [{"json": load_test_data("web_logs_response.json")}, {"json": load_test_data("empty_response.json")}],
        )

        _, events = fetch_events(client=client, last_run={}, log_types=["web"], first_fetch_time="1 hour", max_events_per_fetch=5000)

        assert len(events) == 1


# ─── Hash / Dedup Helper Tests ────────────────────────────────────────────────


class TestHashHelpers:
    def test_hash_event_is_deterministic(self):
        """
        Given:
            - The same event dict.
        When:
            - Calling hash_event twice.
        Then:
            - Both calls return the same hash.
        """
        event = {"event_time": "2024-01-15T10:00:00", "domain": "example.com", "userid": "user@test.com"}
        assert hash_event(event) == hash_event(event)

    def test_hash_event_differs_for_different_events(self):
        """
        Given:
            - Two events with the same timestamp but different domain.
        When:
            - Calling hash_event on each.
        Then:
            - The hashes are different.
        """
        event1 = {"event_time": "2024-01-15T10:00:00", "domain": "example.com"}
        event2 = {"event_time": "2024-01-15T10:00:00", "domain": "other.com"}
        assert hash_event(event1) != hash_event(event2)

    def test_get_boundary_hashes_returns_hashes_of_last_events(self):
        """
        Given:
            - Three events: one at T0, two at T1 (boundary).
        When:
            - Calling get_boundary_hashes with boundary_time=T1.
        Then:
            - Two hashes are returned (for the two events at T1).
        """
        events = [
            {"event_time": "2024-01-15T10:00:00", "domain": "a.com"},
            {"event_time": "2024-01-15T10:00:01", "domain": "b.com"},
            {"event_time": "2024-01-15T10:00:01", "domain": "c.com"},
        ]
        hashes = get_boundary_hashes(events, "2024-01-15T10:00:01")
        assert len(hashes) == 2
        assert hash_event(events[1]) in hashes
        assert hash_event(events[2]) in hashes
        assert hash_event(events[0]) not in hashes

    def test_get_boundary_hashes_stops_at_different_timestamp(self):
        """
        Given:
            - Two events at different timestamps.
        When:
            - Calling get_boundary_hashes with the later timestamp.
        Then:
            - Only the event at the boundary timestamp is hashed.
        """
        events = [
            {"event_time": "2024-01-15T10:00:00", "domain": "a.com"},
            {"event_time": "2024-01-15T10:00:01", "domain": "b.com"},
        ]
        hashes = get_boundary_hashes(events, "2024-01-15T10:00:01")
        assert len(hashes) == 1
        assert hash_event(events[1]) in hashes

    def test_get_boundary_hashes_single_event(self):
        """
        Given:
            - A single event.
        When:
            - Calling get_boundary_hashes.
        Then:
            - One hash is returned.
        """
        events = [{"event_time": "2024-01-15T10:00:00", "domain": "a.com"}]
        hashes = get_boundary_hashes(events, "2024-01-15T10:00:00")
        assert len(hashes) == 1


# ─── get_events_command Tests ─────────────────────────────────────────────────


class TestGetEventsCommand:
    def test_returns_readable_output(self, client: Client, requests_mock):
        """
        Given:
            - One web log event is available.
        When:
            - Calling get_events_command with should_push_events=False.
        Then:
            - CommandResults with readable output containing "Menlo" is returned.
        """
        requests_mock.post(
            API_URL,
            [{"json": load_test_data("web_logs_response.json")}, {"json": load_test_data("empty_response.json")}],
        )

        results = get_events_command(
            client=client,
            args={"start_time": "1 hour", "end_time": "now", "log_types": "web", "limit": "5000"},
            log_types=["web"],
            max_events_per_fetch=5000,
        )

        assert results.readable_output is not None
        assert "Menlo" in results.readable_output

    def test_no_enrichment_when_not_pushing(self, client: Client, requests_mock):
        """
        Given:
            - should_push_events=False.
        When:
            - Calling get_events_command.
        Then:
            - Events in raw_response do NOT have _time or source_log_type fields.
        """
        requests_mock.post(
            API_URL,
            [{"json": load_test_data("web_logs_response.json")}, {"json": load_test_data("empty_response.json")}],
        )

        results = get_events_command(
            client=client,
            args={"start_time": "1 hour", "end_time": "now", "log_types": "web", "should_push_events": "False"},
            log_types=["web"],
            max_events_per_fetch=5000,
        )

        raw = results.raw_response
        assert isinstance(raw, list) and len(raw) == 1
        assert "_time" not in raw[0]
        assert "source_log_type" not in raw[0]

    def test_enrichment_when_pushing(self, client: Client, requests_mock):
        """
        Given:
            - should_push_events=True.
        When:
            - Calling get_events_command.
        Then:
            - Events in raw_response have _time and source_log_type fields.
        """
        requests_mock.post(
            API_URL,
            [{"json": load_test_data("web_logs_response.json")}, {"json": load_test_data("empty_response.json")}],
        )

        results = get_events_command(
            client=client,
            args={"start_time": "1 hour", "end_time": "now", "log_types": "web", "should_push_events": "True"},
            log_types=["web"],
            max_events_per_fetch=5000,
        )

        raw = results.raw_response
        assert isinstance(raw, list) and len(raw) == 1
        assert "_time" in raw[0]
        assert raw[0]["source_log_type"] == "web_logs"

    def test_uses_default_log_types_when_not_specified(self, client: Client, requests_mock):
        """
        Given:
            - No log_types specified in args.
        When:
            - Calling get_events_command with default log_types=["web", "audit"].
        Then:
            - Two API requests are made (one per default log type).
        """
        requests_mock.post(API_URL, json=load_test_data("empty_response.json"))

        get_events_command(
            client=client,
            args={"start_time": "1 hour", "end_time": "now"},
            log_types=["web", "audit"],
            max_events_per_fetch=5000,
        )

        assert requests_mock.call_count == 2


# ─── test_module Tests ────────────────────────────────────────────────────────


class TestTestModule:
    def test_returns_ok_when_all_log_types_succeed(self, client: Client, requests_mock):
        """
        Given:
            - Two log types configured: web and audit.
        When:
            - Calling test_module.
        Then:
            - Returns "ok" and makes one API request per log type.
        """
        requests_mock.post(API_URL, json=load_test_data("empty_response.json"))

        result = test_module(client, ["web", "audit"])

        assert result == "ok"
        assert requests_mock.call_count == 2

    def test_tests_all_configured_log_types(self, client: Client, requests_mock):
        """
        Given:
            - Three log types configured: web, audit, dlp.
        When:
            - Calling test_module.
        Then:
            - One API request is made per log type with the correct log_type value.
        """
        requests_mock.post(API_URL, json=load_test_data("empty_response.json"))

        test_module(client, ["web", "audit", "dlp"])

        assert requests_mock.call_count == 3
        log_types_called = [r.json()["log_type"] for r in requests_mock.request_history]
        assert "web" in log_types_called
        assert "audit" in log_types_called
        assert "dlp" in log_types_called

    def test_safemail_sends_email_api_type(self, client: Client, requests_mock):
        """
        Given:
            - "safemail" is the configured log type.
        When:
            - Calling test_module.
        Then:
            - The API is called with log_type="email".
        """
        requests_mock.post(API_URL, json=load_test_data("empty_response.json"))

        test_module(client, ["safemail"])

        assert requests_mock.last_request.json()["log_type"] == "email"

    def test_returns_auth_error_on_401(self, client: Client, requests_mock):
        """
        Given:
            - The API returns a 401 Unauthorized response.
        When:
            - Calling test_module.
        Then:
            - A descriptive "Authorization Error" string is returned (not raised).
        """
        requests_mock.post(API_URL, status_code=401, text="401: Unauthorized")

        result = test_module(client, ["web"])

        assert "Authorization Error" in result
        assert "Auth Token" in result

    def test_returns_auth_error_on_403(self, client: Client, requests_mock):
        """
        Given:
            - The API returns a 403 Forbidden response.
        When:
            - Calling test_module.
        Then:
            - A descriptive "Authorization Error" string is returned.
        """
        requests_mock.post(API_URL, status_code=403, text="403: Forbidden")

        result = test_module(client, ["web"])

        assert "Authorization Error" in result

    def test_raises_on_unexpected_error(self, client: Client, requests_mock):
        """
        Given:
            - The API returns a 500 Internal Server Error.
        When:
            - Calling test_module.
        Then:
            - The exception is re-raised (not swallowed).
        """
        requests_mock.post(API_URL, status_code=500, text="Internal Server Error")

        with pytest.raises(Exception):
            test_module(client, ["web"])


# ─── Constants Tests ──────────────────────────────────────────────────────────


class TestConstants:
    def test_log_type_map_contains_all_types(self):
        """
        Given / When / Then:
            - LOG_TYPE_MAP must contain exactly the 7 expected log type keys.
        """
        expected = {"web", "safemail", "audit", "smtp", "attachment", "dlp", "isoc"}
        assert set(LOG_TYPE_MAP.keys()) == expected

    def test_safemail_maps_to_email_api_type(self):
        """
        Given / When / Then:
            - The "safemail" UI label must map to "email" as the API log_type value.
        """
        assert LOG_TYPE_MAP["safemail"] == "email"

    def test_source_log_type_map_matches_log_type_map(self):
        """
        Given / When / Then:
            - SOURCE_LOG_TYPE_MAP must have an entry for every key in LOG_TYPE_MAP.
        """
        assert set(SOURCE_LOG_TYPE_MAP.keys()) == set(LOG_TYPE_MAP.keys())

    def test_all_log_types_list_matches_log_type_map(self):
        """
        Given / When / Then:
            - ALL_LOG_TYPES must contain exactly the same keys as LOG_TYPE_MAP.
        """
        assert set(ALL_LOG_TYPES) == set(LOG_TYPE_MAP.keys())

    def test_max_events_per_page_is_1000(self):
        """
        Given / When / Then:
            - MAX_EVENTS_PER_PAGE must be 1000 (the API hard limit per request).
        """
        assert MAX_EVENTS_PER_PAGE == 1000

    def test_default_first_fetch_is_3_hours(self):
        """
        Given / When / Then:
            - DEFAULT_FIRST_FETCH must be "3 hours".
        """
        assert DEFAULT_FIRST_FETCH == "3 hours"
