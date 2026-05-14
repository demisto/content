import json

import pytest

from MenloSecurity import (
    Client,
    MAX_EVENTS_PER_PAGE,
    fetch_events,
    get_boundary_hashes,
    get_events_command,
    get_events_for_log_type,
    hash_event,
)


# ─── Helpers ─────────────────────────────────────────────────────────────────


def load_test_data(filename: str) -> dict:
    """Load JSON test data from the test_data directory."""
    with open(f"test_data/{filename}") as f:
        return json.load(f)


@pytest.fixture
def mock_client(mocker) -> Client:
    """Return a mocked Client instance with ContentClient.__init__ patched."""
    mocker.patch("MenloSecurity.ContentClient.__init__", return_value=None)
    client = Client.__new__(Client)
    client._token = "test-token-12345"
    client._base_url = "https://logs.menlosecurity.com"
    # Default to v2 (Admin token) — matches DEFAULT_TOKEN_TYPE in production code.
    client._api_path = "/api/rep/v2/fetch/client_select"
    return client


# All event/response examples live in test_data/. The integration enriches event dicts
# in-place, so each helper returns a fresh deep copy to avoid cross-test pollution.
_WEB_RESPONSE = load_test_data("web_logs_response.json")
_EMAIL_RESPONSE = load_test_data("email_logs_response.json")
_EMPTY_RESPONSE = load_test_data("empty_response.json")


def make_web_response(event_time: str = "2024-01-15T10:00:40.548000") -> dict:
    """Return a fresh deep-copied web response with an optional event_time override."""
    response = json.loads(json.dumps(_WEB_RESPONSE))
    response["result"]["events"][0]["event"]["event_time"] = event_time
    return response


def make_email_response() -> dict:
    """Return a fresh deep-copied email response."""
    return json.loads(json.dumps(_EMAIL_RESPONSE))


def make_empty_response() -> dict:
    """Return a fresh deep-copied empty response."""
    return json.loads(json.dumps(_EMPTY_RESPONSE))


def make_response(payload: dict | list, mocker):
    """Mock an httpx.Response for fetch_log_page tests (post() returns a Response object)."""
    body = json.dumps(payload).encode()
    return mocker.MagicMock(content=body, status_code=200, headers={}, **{"json.return_value": payload})


# ─── Client Tests ─────────────────────────────────────────────────────────────


class TestClient:
    def test_fetch_log_page_first_page_no_paging_identifiers(self, mock_client: Client, mocker):
        """
        Given:
            - A first-page request (no pagingIdentifiers).
        When:
            - Calling fetch_log_page without paging_identifiers.
        Then:
            - The underlying post() call does NOT include pagingIdentifiers in the body.
            - The correct log_type and token are in the body.
        """
        web_response = load_test_data("web_logs_response.json")
        mock_post = mocker.patch.object(mock_client, "post", return_value=make_response(web_response, mocker))

        result = mock_client.fetch_log_page(log_type="web", start=1700000000, end=1700003600, limit=1000)

        assert result == web_response
        call_kwargs = mock_post.call_args.kwargs
        body = call_kwargs["json_data"]
        assert "pagingIdentifiers" not in body
        assert body["log_type"] == "web"
        assert body["token"] == "test-token-12345"

    def test_fetch_log_page_with_paging_identifiers(self, mock_client: Client, mocker):
        """
        Given:
            - A subsequent page request with pagingIdentifiers from the previous response.
        When:
            - Calling fetch_log_page with paging_identifiers.
        Then:
            - The pagingIdentifiers are included in the POST body.
        """
        mock_post = mocker.patch.object(mock_client, "post", return_value=make_response(make_empty_response(), mocker))

        paging = {"next_time": "2024-01-15T10:00:00.000Z", "hashes": {"abc123": 0}, "last_iteration": True}
        mock_client.fetch_log_page(log_type="web", start=1700000000, end=1700003600, limit=1000, paging_identifiers=paging)

        body = mock_post.call_args.kwargs["json_data"]
        assert body["pagingIdentifiers"] == paging

    def test_fetch_log_page_url_params(self, mock_client: Client, mocker):
        """
        Given:
            - A log page request with specific start, end, and limit values.
        When:
            - Calling fetch_log_page.
        Then:
            - start, end, limit, and format=json are passed as URL query parameters.
        """
        mock_post = mocker.patch.object(mock_client, "post", return_value=make_response(make_empty_response(), mocker))

        mock_client.fetch_log_page(log_type="audit", start=1700000000, end=1700003600, limit=500)

        params = mock_post.call_args.kwargs["params"]
        assert params["start"] == 1700000000
        assert params["end"] == 1700003600
        assert params["limit"] == 500
        assert params["format"] == "json"

    def test_fetch_log_page_returns_none_on_empty_body(self, mock_client: Client, mocker):
        """
        Given:
            - The API returns an empty 200 response (Content-Length: 0).
        When:
            - Calling fetch_log_page.
        Then:
            - Returns None (not an error).
        """
        mock_resp = mocker.MagicMock(content=b"", status_code=200, headers={})
        mocker.patch.object(mock_client, "post", return_value=mock_resp)

        result = mock_client.fetch_log_page(log_type="web", start=1700000000, end=1700003600)

        assert result is None

    def test_fetch_log_page_raises_on_non_json_body(self, mock_client: Client, mocker):
        """
        Given:
            - The API returns a non-JSON body (e.g. HTML auth error page).
        When:
            - Calling fetch_log_page.
        Then:
            - Raises ValueError with the response snippet.
        """
        html = b"<html><title>401:Unauthorized</title></html>"
        mock_resp = mocker.MagicMock(content=html, status_code=401, headers={})
        mock_resp.json.side_effect = json.JSONDecodeError("Expecting value", "", 0)
        mock_resp.text = html.decode()
        mocker.patch.object(mock_client, "post", return_value=mock_resp)

        with pytest.raises(ValueError, match="Non-JSON response"):
            mock_client.fetch_log_page(log_type="web", start=1700000000, end=1700003600)


# ─── get_events_for_log_type Tests ───────────────────────────────────────────


class TestGetEventsForLogType:
    def test_single_page_fetch_enriches_events(self, mock_client: Client, mocker):
        """
        Given:
            - A single page of web logs followed by an empty response.
        When:
            - Calling get_events_for_log_type with enrich=True (default).
        Then:
            - Events are returned with _time and source_log_type fields added.
            - The event envelope {"event": {...}} is unwrapped.
        """
        mocker.patch.object(mock_client, "fetch_log_page", side_effect=[make_web_response(), make_empty_response()])

        events = get_events_for_log_type(
            client=mock_client, log_type_ui="web", start_epoch=1700000000, end_epoch=1700003600, max_events=5000
        )

        assert len(events) == 1
        assert events[0]["source_log_type"] == "web_logs"
        assert "_time" in events[0]
        assert "2024-01-15" in events[0]["_time"]
        assert events[0]["domain"] == "example.com"

    def test_no_enrichment_when_enrich_false(self, mock_client: Client, mocker):
        """
        Given:
            - A single page of web logs.
        When:
            - Calling get_events_for_log_type with enrich=False.
        Then:
            - Events are returned WITHOUT _time or source_log_type fields.
        """
        mocker.patch.object(mock_client, "fetch_log_page", side_effect=[make_web_response(), make_empty_response()])

        events = get_events_for_log_type(
            client=mock_client, log_type_ui="web", start_epoch=1700000000, end_epoch=1700003600, max_events=5000, enrich=False
        )

        assert len(events) == 1
        assert "_time" not in events[0]
        assert "source_log_type" not in events[0]

    def test_safemail_maps_to_email_api_type(self, mock_client: Client, mocker):
        """
        Given:
            - The "safemail" UI log type is selected.
        When:
            - Calling get_events_for_log_type.
        Then:
            - fetch_log_page is called with log_type="email" (not "safemail").
            - Events have source_log_type="email_logs".
        """
        mock_fetch = mocker.patch.object(
            mock_client, "fetch_log_page", side_effect=[make_email_response(), make_empty_response()]
        )

        events = get_events_for_log_type(
            client=mock_client, log_type_ui="safemail", start_epoch=1700000000, end_epoch=1700003600, max_events=5000
        )

        assert len(events) == 1
        assert events[0]["source_log_type"] == "email_logs"
        # Verify the API was called with log_type="email" (not "safemail")
        assert mock_fetch.call_args_list[0].kwargs["log_type"] == "email"

    def test_single_call_uses_max_events_as_limit_when_below_page_size(self, mock_client: Client, mocker):
        """
        Given: max_events=50 (less than MAX_EVENTS_PER_PAGE).
        When: Calling get_events_for_log_type.
        Then: One API call with limit=50 (no pagination needed).
        """
        mock_fetch = mocker.patch.object(mock_client, "fetch_log_page", return_value=make_empty_response())

        get_events_for_log_type(
            client=mock_client, log_type_ui="web", start_epoch=1700000000, end_epoch=1700003600, max_events=50
        )

        assert mock_fetch.call_count == 1
        assert mock_fetch.call_args.kwargs["limit"] == 50

    def test_paginated_calls_keep_constant_page_size_and_trim_overshoot(self, mock_client: Client, mocker):
        """
        Given: max_events exceeds MAX_EVENTS_PER_PAGE — requires pagination, and the API
               returns full pages.
        When: Calling get_events_for_log_type.
        Then: All calls use limit=MAX_EVENTS_PER_PAGE (page size stays constant), and the
              result is trimmed to exactly max_events.
        """
        # Use a max_events that forces 2 paginated calls: one full page + a trim on the second.
        max_events = MAX_EVENTS_PER_PAGE + (MAX_EVENTS_PER_PAGE // 2)  # e.g. 15000 with page=10000
        # Build full pages by replicating a fresh deep-copy per event so in-place enrichment
        # by the integration doesn't pollute the shared template.
        events_page_1 = [make_web_response()["result"]["events"][0] for _ in range(MAX_EVENTS_PER_PAGE)]
        events_page_2 = [make_web_response()["result"]["events"][0] for _ in range(MAX_EVENTS_PER_PAGE)]
        full_page_with_cursor = {
            "result": {
                "events": events_page_1,
                "pagingIdentifiers": {"next_time": "2024-01-15T11:00:00.000Z"},
            }
        }
        full_page_no_cursor = {
            "result": {"events": events_page_2, "pagingIdentifiers": {}},
        }
        mock_fetch = mocker.patch.object(mock_client, "fetch_log_page", side_effect=[full_page_with_cursor, full_page_no_cursor])

        events = get_events_for_log_type(
            client=mock_client, log_type_ui="web", start_epoch=1700000000, end_epoch=1700003600, max_events=max_events
        )

        assert mock_fetch.call_count == 2
        assert mock_fetch.call_args_list[0].kwargs["limit"] == MAX_EVENTS_PER_PAGE
        assert mock_fetch.call_args_list[1].kwargs["limit"] == MAX_EVENTS_PER_PAGE
        assert len(events) == max_events

    def test_empty_response_stops_pagination(self, mock_client: Client, mocker):
        """
        Given:
            - The API returns an empty events list on the first call.
        When:
            - Calling get_events_for_log_type.
        Then:
            - Pagination stops immediately and no events are returned.
            - Only one API call is made.
        """
        mock_fetch = mocker.patch.object(mock_client, "fetch_log_page", return_value=make_empty_response())

        events = get_events_for_log_type(
            client=mock_client, log_type_ui="audit", start_epoch=1700000000, end_epoch=1700003600, max_events=5000
        )

        assert events == []
        assert mock_fetch.call_count == 1

    def test_list_of_wrappers_response_flattens_events(self, mock_client: Client, mocker):
        """
        Given:
            - The API returns a list of response wrappers (observed live behavior).
        When:
            - Calling get_events_for_log_type.
        Then:
            - Events from all wrappers are flattened into a single list.
        """
        wrapper1 = {
            "timestamp": "2024-01-15T10:00:00.000Z",
            "result": {
                "events": [{"event": {"event_time": "2024-01-15T10:00:00", "domain": "a.com"}}],
                "pagingIdentifiers": {},
            },
        }
        wrapper2 = {
            "timestamp": "2024-01-15T10:00:01.000Z",
            "result": {
                "events": [{"event": {"event_time": "2024-01-15T10:00:01", "domain": "b.com"}}],
                "pagingIdentifiers": {},
            },
        }
        # Return a list of 2 wrappers, then empty to stop pagination.
        mocker.patch.object(mock_client, "fetch_log_page", side_effect=[[wrapper1, wrapper2], None])

        events = get_events_for_log_type(mock_client, "web", 1700000000, 1700003600, max_events=100)

        assert len(events) == 2
        assert events[0]["domain"] == "a.com"
        assert events[1]["domain"] == "b.com"

    def test_api_error_returns_partial_results(self, mock_client: Client, mocker):
        """
        Given:
            - The first API call succeeds but the second raises a connection error.
        When:
            - Calling get_events_for_log_type.
        Then:
            - Events from the first page are returned despite the error.
        """
        mocker.patch("MenloSecurity.demisto.error")  # suppress stdout that conftest treats as failure
        mocker.patch.object(mock_client, "fetch_log_page", side_effect=[make_web_response(), Exception("Connection error")])

        events = get_events_for_log_type(
            client=mock_client, log_type_ui="web", start_epoch=1700000000, end_epoch=1700003600, max_events=5000
        )

        assert len(events) == 1


# ─── fetch_events Tests ───────────────────────────────────────────────────────


class TestFetchEvents:
    def test_first_fetch_uses_first_fetch_time(self, mock_client: Client, mocker):
        """
        Given:
            - No last_run (first fetch cycle).
        When:
            - Calling fetch_events with first_fetch_time="1 day".
        Then:
            - Events are fetched and next_run is populated with last_fetch_time.
        """
        mocker.patch.object(mock_client, "fetch_log_page", return_value=make_empty_response())

        next_run, events = fetch_events(
            client=mock_client, last_run={}, log_types=["web"], first_fetch_time="1 day", max_events_per_fetch_per_type=5000
        )

        assert events == []
        assert "web" in next_run
        assert "last_fetch_time" in next_run["web"]

    def test_subsequent_fetch_uses_last_run_time(self, mock_client: Client, mocker):
        """
        Given:
            - A last_run with last_fetch_time="2024-01-15T09:00:00Z".
        When:
            - Calling fetch_events.
        Then:
            - fetch_log_page is called with start equal to the epoch of 2024-01-15T09:00:00Z.
        """
        from MenloSecurity import timestamp_to_epoch

        last_fetch_time = "2024-01-15T09:00:00Z"
        expected_start = timestamp_to_epoch(last_fetch_time)

        mock_fetch = mocker.patch.object(mock_client, "fetch_log_page", return_value=make_empty_response())

        fetch_events(
            client=mock_client,
            last_run={"web": {"last_fetch_time": last_fetch_time}},
            log_types=["web"],
            first_fetch_time="3 days",
            max_events_per_fetch_per_type=5000,
        )

        assert mock_fetch.call_args.kwargs["start"] == expected_start

    def test_all_selected_log_types_are_fetched(self, mock_client: Client, mocker):
        """
        Given:
            - Three log types are selected: web, audit, dlp.
        When:
            - Calling fetch_events.
        Then:
            - fetch_log_page is called at least once per log type.
            - next_run contains an entry for each log type.
        """
        mocker.patch.object(mock_client, "fetch_log_page", return_value=make_empty_response())

        next_run, _ = fetch_events(
            client=mock_client,
            last_run={},
            log_types=["web", "audit", "dlp"],
            first_fetch_time="1 hour",
            max_events_per_fetch_per_type=5000,
        )

        assert "web" in next_run
        assert "audit" in next_run
        assert "dlp" in next_run

    def test_next_run_advances_to_now_on_first_fetch_with_no_events(self, mock_client: Client, mocker):
        """
        Given:
            - No last_run (first fetch cycle) and no events returned.
        When:
            - Calling fetch_events.
        Then:
            - next_run["web"]["last_fetch_time"] is set to the request's end time (advances the window).
            - boundary_hashes is empty.
        """
        from CommonServerPython import arg_to_datetime

        mocker.patch.object(mock_client, "fetch_log_page", return_value=make_empty_response())

        next_run, _ = fetch_events(
            client=mock_client, last_run={}, log_types=["web"], first_fetch_time="1 hour", max_events_per_fetch_per_type=5000
        )

        assert "last_fetch_time" in next_run["web"]
        assert arg_to_datetime(next_run["web"]["last_fetch_time"]) is not None
        assert next_run["web"]["boundary_hashes"] == []

    def test_next_run_preserves_last_run_state_when_no_events_on_subsequent_fetch(self, mock_client: Client, mocker):
        """
        Given:
            - A last_run with last_fetch_time and boundary_hashes already set.
            - No events are returned in this cycle.
        When:
            - Calling fetch_events.
        Then:
            - next_run["web"] is identical to the previous last_run["web"] (state preserved).
        """
        mocker.patch.object(mock_client, "fetch_log_page", return_value=make_empty_response())

        prev_state = {"last_fetch_time": "2024-01-15T09:00:00Z", "boundary_hashes": ["abc123hash"]}
        last_run = {"web": prev_state}

        next_run, events = fetch_events(
            client=mock_client,
            last_run=last_run,
            log_types=["web"],
            first_fetch_time="1 hour",
            max_events_per_fetch_per_type=5000,
        )

        assert events == []
        assert next_run["web"] == prev_state

    def test_next_run_uses_last_event_time_when_events_exist(self, mock_client: Client, mocker):
        """
        Given:
            - One event is returned with event_time "2024-01-15T10:00:40.548000".
        When:
            - Calling fetch_events.
        Then:
            - next_run["web"]["last_fetch_time"] equals the event's event_time.
            - next_run["web"]["boundary_hashes"] contains one hash.
        """
        mocker.patch.object(mock_client, "fetch_log_page", side_effect=[make_web_response(), make_empty_response()])

        next_run, events = fetch_events(
            client=mock_client, last_run={}, log_types=["web"], first_fetch_time="1 hour", max_events_per_fetch_per_type=5000
        )

        assert len(events) == 1
        assert "2024-01-15" in next_run["web"]["last_fetch_time"]
        assert "boundary_hashes" in next_run["web"]
        assert len(next_run["web"]["boundary_hashes"]) == 1

    def test_dedup_removes_events_matching_boundary_hash(self, mock_client: Client, mocker):
        """
        Given:
            - A previous cycle ended with an event whose hash is stored in boundary_hashes.
        When:
            - The same event is returned at the start of the next cycle.
        Then:
            - The duplicate event is filtered out.
        """
        mocker.patch.object(mock_client, "fetch_log_page", side_effect=[make_web_response(), make_empty_response()])

        # First cycle: get the event and its hash
        _, events_cycle1 = fetch_events(
            client=mock_client, last_run={}, log_types=["web"], first_fetch_time="1 hour", max_events_per_fetch_per_type=5000
        )
        assert len(events_cycle1) == 1
        boundary_hash = hash_event(events_cycle1[0])

        # Second cycle: same event returned, should be deduped
        mocker.patch.object(mock_client, "fetch_log_page", side_effect=[make_web_response(), make_empty_response()])
        last_run = {"web": {"last_fetch_time": "2024-01-15T10:00:40.548000", "boundary_hashes": [boundary_hash]}}
        _, events_cycle2 = fetch_events(
            client=mock_client,
            last_run=last_run,
            log_types=["web"],
            first_fetch_time="1 hour",
            max_events_per_fetch_per_type=5000,
        )

        assert len(events_cycle2) == 0

    def test_dedup_keeps_events_with_different_hash(self, mock_client: Client, mocker):
        """
        Given:
            - An event has the same event_time as last_fetch_time but a different hash.
        When:
            - Calling fetch_events.
        Then:
            - The event is NOT filtered out (different content = not a duplicate).
        """
        mocker.patch.object(mock_client, "fetch_log_page", side_effect=[make_web_response(), make_empty_response()])

        last_run = {"web": {"last_fetch_time": "2024-01-15T10:00:40.548000", "boundary_hashes": ["deadbeef00000000"]}}
        _, events = fetch_events(
            client=mock_client,
            last_run=last_run,
            log_types=["web"],
            first_fetch_time="1 hour",
            max_events_per_fetch_per_type=5000,
        )

        assert len(events) == 1

    def test_no_dedup_on_first_fetch(self, mock_client: Client, mocker):
        """
        Given:
            - No last_run (first fetch cycle, no boundary_hashes).
        When:
            - Calling fetch_events.
        Then:
            - All events are returned without any dedup filtering.
        """
        mocker.patch.object(mock_client, "fetch_log_page", side_effect=[make_web_response(), make_empty_response()])

        _, events = fetch_events(
            client=mock_client, last_run={}, log_types=["web"], first_fetch_time="1 hour", max_events_per_fetch_per_type=5000
        )

        assert len(events) == 1

    def test_failed_log_type_preserves_previous_state(self, mock_client: Client, mocker):
        """
        Given:
            - "web" log type raises an exception during fetch.
            - "audit" log type succeeds.
        When:
            - Calling fetch_events.
        Then:
            - "audit" events are returned.
            - "web" state is preserved from last_run (not overwritten).
        """
        mocker.patch("MenloSecurity.demisto.error")  # suppress stdout output that conftest treats as failure

        def side_effect_by_log_type(log_type: str, **kwargs):
            if log_type == "web":
                raise Exception("API error for web")
            return make_empty_response()

        mocker.patch.object(mock_client, "fetch_log_page", side_effect=side_effect_by_log_type)

        prev_web_state = {"last_fetch_time": "2024-01-15T09:00:00Z", "boundary_hashes": []}
        last_run = {"web": prev_web_state}

        next_run, events = fetch_events(
            client=mock_client,
            last_run=last_run,
            log_types=["web", "audit"],
            first_fetch_time="1 hour",
            max_events_per_fetch_per_type=5000,
        )

        # web state preserved from last_run
        assert next_run["web"] == prev_web_state
        # audit state updated
        assert "audit" in next_run

    # ─── Hash / Dedup Helper Tests ────────────────────────────────────────────────

    def test_end_to_end_multi_type_with_dedup_and_state(self, mock_client: Client, mocker):
        """
        Given:
            - Two log types (web, audit) configured.
            - web has a previous last_run with a boundary hash matching the first returned event.
            - audit is a first fetch with events.
        When:
            - Calling fetch_events.
        Then:
            - web: the duplicate event is removed, remaining events are returned.
            - audit: all events are returned (no dedup on first fetch).
            - next_run has updated state for both types.
        """
        web_event_dup = {"event": {"event_time": "2024-01-15T10:00:00", "domain": "dup.com"}}
        web_event_new = {"event": {"event_time": "2024-01-15T10:00:01", "domain": "new.com"}}
        audit_event = {"event": {"event_time": "2024-01-15T10:00:00", "name": "login"}}

        web_response = {
            "result": {
                "events": [web_event_dup, web_event_new],
                "pagingIdentifiers": {},
            }
        }
        audit_response = {
            "result": {
                "events": [audit_event],
                "pagingIdentifiers": {},
            }
        }

        # The hash must match the ENRICHED event (after _time and source_log_type are added).
        enriched_dup = {**web_event_dup["event"], "_time": "2024-01-15T10:00:00Z", "source_log_type": "web_logs"}
        dup_hash = hash_event(enriched_dup)

        # Each type calls fetch_log_page twice: once for data, once returns None to stop pagination.
        call_results: dict[str, list] = {
            "web": [web_response, None],
            "audit": [audit_response, None],
        }

        def mock_fetch(log_type, **kwargs):
            return call_results[log_type].pop(0) if call_results.get(log_type) else None

        mocker.patch.object(mock_client, "fetch_log_page", side_effect=mock_fetch)

        last_run = {
            "web": {
                "last_fetch_time": "2024-01-15T10:00:00",
                "boundary_hashes": [dup_hash],
            }
        }

        next_run, events = fetch_events(
            client=mock_client,
            last_run=last_run,
            log_types=["web", "audit"],
            first_fetch_time="3 hours",
            max_events_per_fetch_per_type=5000,
        )

        # web: 1 dup removed, 1 new event kept. audit: 1 event (no dedup on first fetch).
        assert len(events) == 2
        domains = {e.get("domain") for e in events if "domain" in e}
        assert "new.com" in domains
        assert "dup.com" not in domains

        # Both types have updated state in next_run.
        assert "web" in next_run
        assert "audit" in next_run
        assert next_run["web"]["last_fetch_time"] == "2024-01-15T10:00:01"
        assert next_run["audit"]["last_fetch_time"] == "2024-01-15T10:00:00"


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
    def test_returns_readable_output(self, mock_client: Client, mocker):
        """
        Given:
            - One web log event is available.
        When:
            - Calling get_events_command with should_push_events=False.
        Then:
            - CommandResults with readable output containing "Menlo" is returned.
        """
        mocker.patch.object(mock_client, "fetch_log_page", side_effect=[make_web_response(), make_empty_response()])

        results = get_events_command(
            client=mock_client,
            args={"start_time": "1 hour", "end_time": "now", "log_types": "web", "limit": "5000"},
            log_types=["web"],
            max_events_per_fetch_per_type=5000,
        )

        assert results.readable_output is not None
        assert "Menlo" in results.readable_output

    def test_no_enrichment_when_not_pushing(self, mock_client: Client, mocker):
        """
        Given:
            - should_push_events=False.
        When:
            - Calling get_events_command.
        Then:
            - Events in raw_response do NOT have _time or source_log_type fields.
        """
        mocker.patch.object(mock_client, "fetch_log_page", side_effect=[make_web_response(), make_empty_response()])

        results = get_events_command(
            client=mock_client,
            args={"start_time": "1 hour", "end_time": "now", "log_types": "web", "should_push_events": "False"},
            log_types=["web"],
            max_events_per_fetch_per_type=5000,
        )

        raw = results.raw_response
        assert isinstance(raw, list)
        assert len(raw) == 1
        assert "_time" not in raw[0]
        assert "source_log_type" not in raw[0]

    def test_enrichment_when_pushing(self, mock_client: Client, mocker):
        """
        Given:
            - should_push_events=True.
        When:
            - Calling get_events_command.
        Then:
            - Events in raw_response have _time and source_log_type fields.
            - A push confirmation message is included.
        """
        mocker.patch.object(mock_client, "fetch_log_page", side_effect=[make_web_response(), make_empty_response()])
        mocker.patch("MenloSecurity.send_events_to_xsiam")

        results = get_events_command(
            client=mock_client,
            args={"start_time": "1 hour", "end_time": "now", "log_types": "web", "should_push_events": "True"},
            log_types=["web"],
            max_events_per_fetch_per_type=5000,
        )

        # When pushing, returns [table_results, push_message].
        assert isinstance(results, list)
        raw = results[0].raw_response
        assert isinstance(raw, list)
        assert len(raw) == 1
        assert "_time" in raw[0]
        assert raw[0]["source_log_type"] == "web_logs"
        assert "pushed" in results[1].readable_output.lower()

    def test_uses_default_log_types_when_not_specified(self, mock_client: Client, mocker):
        """
        Given:
            - No log_types specified in args.
        When:
            - Calling get_events_command with default log_types=["web", "audit"].
        Then:
            - fetch_log_page is called for both default log types.
        """
        mock_fetch = mocker.patch.object(mock_client, "fetch_log_page", return_value=make_empty_response())

        get_events_command(
            client=mock_client,
            args={"start_time": "1 hour", "end_time": "now"},
            log_types=["web", "audit"],
            max_events_per_fetch_per_type=5000,
        )

        log_types_called = {call.kwargs["log_type"] for call in mock_fetch.call_args_list}
        assert "web" in log_types_called
        assert "audit" in log_types_called

    def test_raises_on_invalid_log_type(self, mock_client: Client, mocker):
        """
        Given:
            - An invalid log type "invalid_type" in the command args.
        When:
            - Calling get_events_command.
        Then:
            - A ValueError is raised listing the invalid type and valid options.
        """
        with pytest.raises(ValueError, match="Unknown log type.*invalid_type"):
            get_events_command(
                client=mock_client,
                args={"start_time": "1 hour", "end_time": "now", "log_types": "invalid_type"},
                log_types=["web"],
                max_events_per_fetch_per_type=100,
            )


# ─── test_module Tests ────────────────────────────────────────────────────────


class TestTestModule:
    def test_returns_ok_when_all_log_types_succeed(self, mock_client: Client, mocker):
        """
        Given:
            - Two log types configured: web and audit.
        When:
            - Calling test_module.
        Then:
            - Returns "ok" and makes one API request per log type.
        """
        from MenloSecurity import test_module  # noqa: PLC0415

        mock_fetch = mocker.patch.object(mock_client, "fetch_log_page", return_value=make_empty_response())

        result = test_module(mock_client, ["web", "audit"])

        assert result == "ok"
        assert mock_fetch.call_count == 2

    def test_tests_all_configured_log_types(self, mock_client: Client, mocker):
        """
        Given:
            - Three log types configured: web, audit, dlp.
        When:
            - Calling test_module.
        Then:
            - One API request is made per log type with the correct log_type value.
        """
        from MenloSecurity import test_module  # noqa: PLC0415

        mock_fetch = mocker.patch.object(mock_client, "fetch_log_page", return_value=make_empty_response())

        test_module(mock_client, ["web", "audit", "dlp"])

        assert mock_fetch.call_count == 3
        log_types_called = {call.kwargs["log_type"] for call in mock_fetch.call_args_list}
        assert "web" in log_types_called
        assert "audit" in log_types_called
        assert "dlp" in log_types_called

    def test_safemail_sends_email_api_type(self, mock_client: Client, mocker):
        """
        Given:
            - "safemail" is the configured log type.
        When:
            - Calling test_module.
        Then:
            - fetch_log_page is called with log_type="email".
        """
        from MenloSecurity import test_module  # noqa: PLC0415

        mock_fetch = mocker.patch.object(mock_client, "fetch_log_page", return_value=make_empty_response())

        test_module(mock_client, ["safemail"])

        assert mock_fetch.call_args.kwargs["log_type"] == "email"

    def test_returns_auth_error_on_401(self, mock_client: Client, mocker):
        """
        Given:
            - fetch_log_page raises an exception containing "401".
        When:
            - Calling test_module.
        Then:
            - A descriptive "Authorization Error" string is returned (not raised).
        """
        from MenloSecurity import test_module  # noqa: PLC0415

        mocker.patch.object(mock_client, "fetch_log_page", side_effect=Exception("401 Unauthorized"))

        result = test_module(mock_client, ["web"])

        assert "Authorization Error" in result
        assert "Auth Token" in result

    def test_returns_auth_error_on_403(self, mock_client: Client, mocker):
        """
        Given:
            - fetch_log_page raises an exception containing "403".
        When:
            - Calling test_module.
        Then:
            - A descriptive "Authorization Error" string is returned.
        """
        from MenloSecurity import test_module  # noqa: PLC0415

        mocker.patch.object(mock_client, "fetch_log_page", side_effect=Exception("403 Forbidden"))

        result = test_module(mock_client, ["web"])

        assert "Authorization Error" in result

    def test_raises_on_unexpected_error(self, mock_client: Client, mocker):
        """
        Given:
            - fetch_log_page raises an unexpected exception (500).
        When:
            - Calling test_module.
        Then:
            - The exception is re-raised (not swallowed).
        """
        from MenloSecurity import test_module  # noqa: PLC0415

        mocker.patch.object(mock_client, "fetch_log_page", side_effect=Exception("500 Internal Server Error"))

        with pytest.raises(Exception, match="500"):
            test_module(mock_client, ["web"])

    def test_returns_connection_error_message(self, mock_client: Client, mocker):
        """
        Given:
            - fetch_log_page raises a ConnectionError.
        When:
            - Calling test_module.
        Then:
            - Returns a user-friendly connection error message.
        """
        from MenloSecurity import test_module  # noqa: PLC0415

        mocker.patch.object(mock_client, "fetch_log_page", side_effect=Exception("ConnectionError: Failed to establish"))

        result = test_module(mock_client, ["web"])

        assert "Connection Error" in result
