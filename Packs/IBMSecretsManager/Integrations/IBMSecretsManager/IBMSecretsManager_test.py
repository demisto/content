import json

import pytest
from IBMSecretsManager import (
    Client,
    add_time_to_events,
    dedup_events,
    fetch_events,
    get_event_timestamp,
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
    events, new_last_run = fetch_events(client, query="source logs", max_events=100, last_run={})
    assert len(events) == 2
    assert all(e["_source_log_type"] == "ibm_secrets_manager_audit" for e in events)
    assert new_last_run["last_timestamp"] == "2026-07-13T00:00:02.000Z"
    assert new_last_run["last_ids"] == ["2"]


def test_fetch_events_respects_max_events(requests_mock):
    """
    Given: a query response with more events than max_events.
    When: fetching events with a small max_events cap.
    Then: only up to max_events events are returned.
    """
    requests_mock.post(f"{IAM_URL}/identity/token", json={"access_token": "tok", "expires_in": 3600})
    requests_mock.post(
        f"{SERVER_URL}/v1/query",
        text=sse_frame([make_event(str(i), f"2026-07-13T00:00:0{i}.000Z") for i in range(5)]),
    )
    client = build_client()
    events, _ = fetch_events(client, query="source logs", max_events=3, last_run={})
    assert len(events) == 3


def test_get_access_token_failure(requests_mock):
    """
    Given: an IAM token endpoint that returns no access_token.
    When: requesting an access token.
    Then: a DemistoException is raised.
    """
    from CommonServerPython import DemistoException

    requests_mock.post(f"{IAM_URL}/identity/token", json={})
    client = build_client()
    with pytest.raises(DemistoException):
        client.get_access_token()


def test_get_access_token_cached(requests_mock):
    """
    Given: a successful token exchange.
    When: requesting the token twice.
    Then: the token is cached and the IAM endpoint is called only once.
    """
    adapter = requests_mock.post(f"{IAM_URL}/identity/token", json={"access_token": "tok", "expires_in": 3600})
    client = build_client()
    assert client.get_access_token() == "tok"
    assert client.get_access_token() == "tok"
    assert adapter.call_count == 1
