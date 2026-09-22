import json

import pytest
from IBMSecretsManager import (
    Client,
    add_time_to_events,
    dedup_events,
    fetch_events,
    get_event_timestamp,
    get_events_command,
    parse_sse_results,
)

SERVER_URL = "https://guid.api.eu-de.logs.cloud.ibm.com"
IAM_URL = "https://iam.cloud.ibm.com"


def build_client() -> Client:
    return Client(server_url=SERVER_URL, api_key="dummy-api-key", iam_url=IAM_URL, verify=False, proxy=False)


def make_event(event_id: str, timestamp: str, action: str = "secrets-manager.secret.create") -> dict:
    return {
        "id": event_id,
        "metadata": {"timestamp": timestamp},
        "userData": {"action": action},
    }


def sse_frame(results: list[dict]) -> str:
    """Build a single SSE frame carrying a query-result payload."""
    payload = json.dumps({"result": {"results": results}})
    return f"data: {payload}\n\n"


""" parse_sse_results """


def test_parse_sse_results_single_frame():
    """
    Given: an SSE body with one frame containing two results.
    When: parsing the SSE stream.
    Then: both result records are returned.
    """
    body = sse_frame([make_event("1", "2026-07-13T00:00:00.000Z"), make_event("2", "2026-07-13T00:00:01.000Z")])
    events = parse_sse_results(body)
    assert len(events) == 2
    assert events[0]["id"] == "1"


def test_parse_sse_results_multiple_frames_and_keepalives():
    """
    Given: an SSE body with multiple frames, keep-alive comments, and multi-line data.
    When: parsing the SSE stream.
    Then: all results across frames are flattened and comment lines are ignored.
    """
    body = (
        ": keep-alive\n\n"
        + sse_frame([make_event("1", "2026-07-13T00:00:00.000Z")])
        + sse_frame([make_event("2", "2026-07-13T00:00:02.000Z")])
    )
    events = parse_sse_results(body)
    assert [e["id"] for e in events] == ["1", "2"]


def test_parse_sse_results_trailing_frame_without_blank_line():
    """
    Given: an SSE body whose final frame is not terminated by a blank line.
    When: parsing the SSE stream.
    Then: the trailing frame is still flushed and parsed.
    """
    payload = json.dumps({"result": {"results": [make_event("9", "2026-07-13T00:00:09.000Z")]}})
    body = f"data: {payload}"
    events = parse_sse_results(body)
    assert len(events) == 1
    assert events[0]["id"] == "9"


def test_parse_sse_results_ignores_malformed_json():
    """
    Given: an SSE body with a malformed JSON frame followed by a valid one.
    When: parsing the SSE stream.
    Then: the malformed frame is skipped and the valid frame is returned.
    """
    body = "data: {not-json}\n\n" + sse_frame([make_event("1", "2026-07-13T00:00:00.000Z")])
    events = parse_sse_results(body)
    assert len(events) == 1


""" enrichment """


def test_add_time_to_events():
    """
    Given: raw events with metadata timestamps.
    When: enriching events for XSIAM.
    Then: each event gets _time from the timestamp and the correct _source_log_type.
    """
    events = [make_event("1", "2026-07-13T00:00:00.000Z")]
    add_time_to_events(events)
    assert events[0]["_time"] == "2026-07-13T00:00:00.000Z"
    assert events[0]["_source_log_type"] == "ibm_secrets_manager_audit"


def test_get_event_timestamp_missing_metadata():
    """
    Given: an event without metadata.
    When: extracting the timestamp.
    Then: an empty string is returned.
    """
    assert get_event_timestamp({}) == ""


""" dedup_events """


def test_dedup_events_removes_boundary_duplicates():
    """
    Given: events where one shares the previous run's boundary timestamp and ID.
    When: de-duplicating against the persisted boundary state.
    Then: the boundary duplicate is removed and new state reflects the latest timestamp.
    """
    boundary_ts = "2026-07-13T00:00:00.000Z"
    events = [
        make_event("1", boundary_ts),  # already ingested last run -> should be dropped
        make_event("2", "2026-07-13T00:00:05.000Z"),
        make_event("3", "2026-07-13T00:00:05.000Z"),
    ]
    new_events, new_ids, new_ts = dedup_events(events, last_ids={"1"}, boundary_ts=boundary_ts)
    assert {e["id"] for e in new_events} == {"2", "3"}
    assert new_ts == "2026-07-13T00:00:05.000Z"
    assert new_ids == {"2", "3"}


def test_dedup_events_no_new_events_keeps_state():
    """
    Given: only boundary events already ingested in the previous run.
    When: de-duplicating.
    Then: no events are returned and the previous boundary state is preserved.
    """
    boundary_ts = "2026-07-13T00:00:00.000Z"
    events = [make_event("1", boundary_ts)]
    new_events, new_ids, new_ts = dedup_events(events, last_ids={"1"}, boundary_ts=boundary_ts)
    assert new_events == []
    assert new_ids == {"1"}
    assert new_ts == boundary_ts


""" fetch_events (integration with mocked HTTP) """


def test_fetch_events_first_run(requests_mock, mocker):
    """
    Given: a first run (empty last_run) and a Cloud Logs query response with two events.
    When: fetching events.
    Then: a token is minted, events are enriched, and last_run captures the latest timestamp.
    """
    mocker.patch("IBMSecretsManager.DEFAULT_FIRST_FETCH", "1 hour")
    requests_mock.post(f"{IAM_URL}/identity/token", json={"access_token": "tok", "expires_in": 3600})
    requests_mock.post(
        f"{SERVER_URL}/v1/query",
        text=sse_frame(
            [
                make_event("1", "2026-07-13T00:00:01.000Z"),
                make_event("2", "2026-07-13T00:00:02.000Z"),
            ]
        ),
    )
    client = build_client()
    events, new_last_run = fetch_events(client, query="source logs", page_size=100, last_run={})
    assert len(events) == 2
    assert all(e["_source_log_type"] == "ibm_secrets_manager_audit" for e in events)
    assert new_last_run["last_timestamp"] == "2026-07-13T00:00:02.000Z"
    assert new_last_run["last_ids"] == ["2"]


def test_fetch_events_stops_on_short_page(requests_mock):
    """
    Given: a single page with fewer results than page_size.
    When: fetching events.
    Then: only one query call is made (the loop stops on the short page).
    """
    requests_mock.post(f"{IAM_URL}/identity/token", json={"access_token": "tok", "expires_in": 3600})
    query_adapter = requests_mock.post(
        f"{SERVER_URL}/v1/query",
        text=sse_frame([make_event(str(i), f"2026-07-13T00:00:0{i}.000Z") for i in range(5)]),
    )
    client = build_client()
    events, _ = fetch_events(client, query="source logs", page_size=50, last_run={})
    assert len(events) == 5
    assert query_adapter.call_count == 1


def test_fetch_events_paginates_across_multiple_calls(requests_mock, mocker):
    """
    Given: full pages (== page_size) followed by a short page.
    When: fetching events.
    Then: the loop keeps calling /v1/query (advancing the window) until a short page is returned,
          collecting events across all pages.
    """
    mocker.patch("IBMSecretsManager.MAX_CALLS_PER_FETCH", 10)
    requests_mock.post(f"{IAM_URL}/identity/token", json={"access_token": "tok", "expires_in": 3600})
    # page_size=2: two full pages then a short (1-event) page -> 3 calls total.
    responses = [
        {"text": sse_frame([make_event("1", "2026-07-13T00:00:01.000Z"), make_event("2", "2026-07-13T00:00:02.000Z")])},
        {"text": sse_frame([make_event("3", "2026-07-13T00:00:03.000Z"), make_event("4", "2026-07-13T00:00:04.000Z")])},
        {"text": sse_frame([make_event("5", "2026-07-13T00:00:05.000Z")])},
    ]
    query_adapter = requests_mock.post(f"{SERVER_URL}/v1/query", responses)
    client = build_client()
    events, new_last_run = fetch_events(client, query="source logs", page_size=2, last_run={})
    assert {e["id"] for e in events} == {"1", "2", "3", "4", "5"}
    assert query_adapter.call_count == 3
    assert new_last_run["last_timestamp"] == "2026-07-13T00:00:05.000Z"


def test_fetch_events_respects_max_calls_budget(requests_mock, mocker):
    """
    Given: every page is full (== page_size), so there is always "more" data.
    When: fetching events.
    Then: the loop is bounded by MAX_CALLS_PER_FETCH calls.
    """
    mocker.patch("IBMSecretsManager.MAX_CALLS_PER_FETCH", 3)
    requests_mock.post(f"{IAM_URL}/identity/token", json={"access_token": "tok", "expires_in": 3600})

    counter = {"n": 0}

    def always_full_page(request, context):
        counter["n"] += 1
        base = counter["n"] * 10
        # Always return a full page (2 events) with strictly increasing timestamps.
        return sse_frame(
            [
                make_event(str(base + 1), f"2026-07-13T00:00:{base + 1:02d}.000Z"),
                make_event(str(base + 2), f"2026-07-13T00:00:{base + 2:02d}.000Z"),
            ]
        )

    query_adapter = requests_mock.post(f"{SERVER_URL}/v1/query", text=always_full_page)
    client = build_client()
    events, _ = fetch_events(client, query="source logs", page_size=2, last_run={})
    assert query_adapter.call_count == 3  # capped by MAX_CALLS_PER_FETCH
    assert len(events) == 6  # 2 per call x 3 calls


def test_get_access_token_failure(requests_mock, mocker):
    """
    Given: an IAM token endpoint that returns no access_token and an empty integration context.
    When: requesting an access token.
    Then: a DemistoException is raised.
    """
    from CommonServerPython import DemistoException

    mocker.patch("IBMSecretsManager.get_integration_context", return_value={})
    mocker.patch("IBMSecretsManager.set_integration_context")
    requests_mock.post(f"{IAM_URL}/identity/token", json={})
    client = build_client()
    with pytest.raises(DemistoException):
        client.get_access_token()


def test_get_access_token_mints_and_caches_when_context_empty(requests_mock, mocker):
    """
    Given: an empty integration context and a successful token exchange.
    When: requesting an access token.
    Then: a new token is minted and stored in the integration context with an expiry.
    """
    mocker.patch("IBMSecretsManager.get_integration_context", return_value={})
    set_context = mocker.patch("IBMSecretsManager.set_integration_context")
    mocker.patch("IBMSecretsManager.time.time", return_value=1000)
    adapter = requests_mock.post(f"{IAM_URL}/identity/token", json={"access_token": "tok", "expires_in": 3600})

    client = build_client()
    assert client.get_access_token() == "tok"
    assert adapter.call_count == 1
    set_context.assert_called_once_with({"access_token": "tok", "expires_at": 1000 + 3600})


def test_get_access_token_reuses_valid_cached_token(requests_mock, mocker):
    """
    Given: a cached, still-valid token in the integration context.
    When: requesting an access token.
    Then: the cached token is returned and the IAM endpoint is not called.
    """
    mocker.patch("IBMSecretsManager.time.time", return_value=1000)
    mocker.patch(
        "IBMSecretsManager.get_integration_context",
        return_value={"access_token": "cached", "expires_at": 5000},
    )
    adapter = requests_mock.post(f"{IAM_URL}/identity/token", json={"access_token": "new", "expires_in": 3600})

    client = build_client()
    assert client.get_access_token() == "cached"
    assert adapter.call_count == 0


def test_get_access_token_remints_when_within_safety_window(requests_mock, mocker):
    """
    Given: a cached token whose expiry falls inside the safety window.
    When: requesting an access token.
    Then: a fresh token is minted instead of reusing the almost-expired cached token.
    """
    # now=1000, expires_at=1030 -> 1000 >= (1030 - 60) so it must re-mint.
    mocker.patch("IBMSecretsManager.time.time", return_value=1000)
    mocker.patch(
        "IBMSecretsManager.get_integration_context",
        return_value={"access_token": "cached", "expires_at": 1030},
    )
    mocker.patch("IBMSecretsManager.set_integration_context")
    adapter = requests_mock.post(f"{IAM_URL}/identity/token", json={"access_token": "new", "expires_in": 3600})

    client = build_client()
    assert client.get_access_token() == "new"
    assert adapter.call_count == 1


""" get_events_command """


def test_get_events_command_with_explicit_date_range(requests_mock):
    """
    Given: explicit start_date and end_date arguments.
    When: running the get-events command.
    Then: the query is issued for that window and events are returned and enriched.
    """
    requests_mock.post(f"{IAM_URL}/identity/token", json={"access_token": "tok", "expires_in": 3600})
    query_adapter = requests_mock.post(
        f"{SERVER_URL}/v1/query",
        text=sse_frame([make_event("1", "2026-07-13T00:00:01.000Z")]),
    )
    client = build_client()
    args = {"start_date": "2026-07-13T00:00:00Z", "end_date": "2026-07-13T01:00:00Z", "limit": "10"}
    events, results = get_events_command(client, args)

    assert len(events) == 1
    assert events[0]["_source_log_type"] == "ibm_secrets_manager_audit"
    body = query_adapter.last_request.json()
    assert body["metadata"]["start_date"].startswith("2026-07-13T00:00:00")
    assert body["metadata"]["end_date"].startswith("2026-07-13T01:00:00")
    assert "IBM Secrets Manager Events" in results.readable_output


def test_get_events_command_defaults_window_when_dates_missing(requests_mock):
    """
    Given: no start_date/end_date arguments.
    When: running the get-events command.
    Then: a default one-hour look-back window is used and a query is still issued.
    """
    requests_mock.post(f"{IAM_URL}/identity/token", json={"access_token": "tok", "expires_in": 3600})
    query_adapter = requests_mock.post(
        f"{SERVER_URL}/v1/query",
        text=sse_frame([make_event("1", "2026-07-13T00:00:01.000Z")]),
    )
    client = build_client()
    events, _ = get_events_command(client, {})

    assert len(events) == 1
    body = query_adapter.last_request.json()
    assert "start_date" in body["metadata"]
    assert "end_date" in body["metadata"]
