import json
from datetime import UTC, datetime, timedelta
from unittest.mock import MagicMock

import pytest
from CommonServerPython import DemistoException

from CiscoETDConnector import (
    ETDClient,
    FetchState,
    calculate_fetch_window,
    cisco_etd_get_events_command,
    deduplicate_events,
    fetch_events,
    format_event_time,
    generate_intervals,
    get_credential,
    get_event_id,
    get_event_time,
    get_object_path,
    is_fatal_error,
    parse_command_range,
    parse_timestamp,
)

# Imported under an alias so pytest does not collect the integration's test-module command
# as if it were a test case.
from CiscoETDConnector import test_module as run_test_module

WINDOW_START = datetime(2026, 7, 1, 10, 0, tzinfo=UTC)
LINK = "https://bucket.s3.amazonaws.com/tenant_id%3Dt1/log_date%3D2026-07-01/hour%3D10/log_type%3Dmessage/0000.jsonl?X-Amz-Signature=abc"
LINK_PATH = "/tenant_id%3Dt1/log_date%3D2026-07-01/hour%3D10/log_type%3Dmessage/0000.jsonl"


def recent_link(hours_ago: int = 1, part: str = "0000") -> tuple[str, str]:
    """Build a link inside the live fetch window, so state is not pruned as out of retention."""
    moment = datetime.now(UTC) - timedelta(hours=hours_ago)
    path = (
        f"/tenant_id%3Dt1/log_date%3D{moment.strftime('%Y-%m-%d')}"
        f"/hour%3D{moment.strftime('%H')}/log_type%3Dmessage/{part}.jsonl"
    )
    return f"https://bucket.s3.amazonaws.com{path}?X-Amz-Signature=abc", path


def build_client() -> ETDClient:
    """Create a client without running the network-dependent constructor."""
    client = ETDClient.__new__(ETDClient)
    client.params = {}
    client.api_key = "api-key"
    client._headers = {}
    client._verify = True
    client._download_session = MagicMock()
    return client


def mock_download(client: ETDClient, lines: list[str], status_code: int = 200) -> MagicMock:
    response = MagicMock()
    response.status_code = status_code
    response.text = "error body"
    response.iter_lines.return_value = iter(lines)
    response.__enter__ = MagicMock(return_value=response)
    response.__exit__ = MagicMock(return_value=False)
    client._download_session.get.return_value = response
    return response


""" CREDENTIALS """


@pytest.mark.parametrize(
    "param, expected",
    [
        ("secret", "secret"),
        ({"password": "secret"}, "secret"),
        ({"credentials": {"password": "secret"}}, "secret"),
        (None, ""),
        ({}, ""),
        ("", ""),
    ],
)
def test_get_credential(param, expected):
    """Every credential shape resolves to a string, never to None, so auth tuples stay valid."""
    assert get_credential(param) == expected


""" TIME HANDLING """


def test_parse_timestamp_converts_offset_to_utc():
    """Regression: a non-UTC offset must be converted, not relabelled as Z."""
    assert parse_timestamp("2026-07-01T10:00:00+03:00") == datetime(2026, 7, 1, 7, 0, tzinfo=UTC)


def test_parse_timestamp_treats_naive_as_utc():
    """ETD audit logs emit naive timestamps that are documented as UTC."""
    assert parse_timestamp("2026-06-16 06:54:55") == datetime(2026, 6, 16, 6, 54, 55, tzinfo=UTC)


@pytest.mark.parametrize("value", ["", "   ", "not-a-date", None, 12345, {}])
def test_parse_timestamp_invalid(value):
    assert parse_timestamp(value) is None


def test_format_event_time_keeps_milliseconds():
    """Sub-second precision is retained so events in the same second stay distinguishable."""
    assert format_event_time(datetime(2026, 7, 1, 10, 0, 0, 123456, tzinfo=UTC)) == "2026-07-01T10:00:00.123Z"


def test_get_event_time_offset_is_converted():
    """Regression: the full event path must normalize an offset timestamp to real UTC."""
    event = {"message": {"timestamp": "2026-07-01T13:00:00+03:00"}}
    assert get_event_time(event, "message", WINDOW_START) == "2026-07-01T10:00:00.000Z"


def test_get_event_time_falls_back_to_action_then_verdict():
    """Update events carry no top-level timestamp, only an action or verdict timestamp."""
    action_event = {"message": {"action": {"timestamp": "2026-07-01T12:36:50.764Z"}}}
    assert get_event_time(action_event, "message", WINDOW_START).startswith("2026-07-01T12:36:50")

    verdict_event = {"message": {"verdict": {"timestamp": "2026-07-01T12:36:28.412Z"}}}
    assert get_event_time(verdict_event, "message", WINDOW_START).startswith("2026-07-01T12:36:28")


def test_get_event_time_falls_back_to_partition():
    """When no timestamp exists, the logDate/logHour partition gives a real, bounded time."""
    event = {"message": {}, "logDate": "2026-07-01", "logHour": "06"}
    assert get_event_time(event, "message", WINDOW_START) == "2026-07-01T06:00:00.000Z"


def test_get_event_time_falls_back_to_window_start_not_now():
    """Regression: an untimed event must not be stamped 'now', which would skew the checkpoint."""
    assert get_event_time({"message": {}}, "message", WINDOW_START) == "2026-07-01T10:00:00.000Z"


def test_get_event_time_handles_non_dict_message():
    """Regression: a malformed message field must not raise and abort the whole file."""
    assert get_event_time({"message": "unexpected string"}, "message", WINDOW_START) == "2026-07-01T10:00:00.000Z"


def test_get_event_time_handles_non_dict_action():
    assert get_event_time({"message": {"action": ["unexpected"]}}, "message", WINDOW_START) == "2026-07-01T10:00:00.000Z"


""" EVENT IDENTITY """


def test_get_event_id_message_is_stable_for_unrelated_changes():
    """Regression: re-exporting the same message state must not create a new id."""
    first = {"message": {"id": "abc", "eventType": "create", "subject": "hello"}, "logHour": "10"}
    second = {"message": {"id": "abc", "eventType": "create", "subject": "hello", "urls": [{"url": "x"}]}, "logHour": "11"}
    assert get_event_id(first, "message") == get_event_id(second, "message")


def test_get_event_id_message_changes_on_new_verdict():
    """A reclassification is a genuinely new event and must produce a distinct id."""
    created = {"message": {"id": "abc", "eventType": "create"}}
    updated = {"message": {"id": "abc", "eventType": "update", "verdict": {"timestamp": "2026-07-01T12:00:00Z"}}}
    assert get_event_id(created, "message") != get_event_id(updated, "message")


def test_get_event_id_message_changes_on_new_action():
    base = {"message": {"id": "abc", "eventType": "update"}}
    remediated = {"message": {"id": "abc", "eventType": "update", "action": {"timestamp": "2026-07-01T12:36:50Z"}}}
    assert get_event_id(base, "message") != get_event_id(remediated, "message")


def test_get_event_id_message_without_id_hashes_body():
    """Without the ETD id there is nothing stable to key on, so the body is hashed."""
    assert len(get_event_id({"message": {"subject": "x"}}, "message")) == 64


def test_get_event_id_distinct_messages_differ():
    first = {"message": {"id": "abc", "eventType": "create"}}
    second = {"message": {"id": "def", "eventType": "create"}}
    assert get_event_id(first, "message") != get_event_id(second, "message")


def test_get_event_id_connection_distinguishes_records():
    """Regression: two records sharing a connection id must not collapse into one event."""
    first = {"connection_id": "c1", "timestamp": "2026-07-01T10:00:00Z", "reason": "blocked"}
    second = {"connection_id": "c1", "timestamp": "2026-07-01T10:05:00Z", "reason": "allowed"}
    assert get_event_id(first, "connection") != get_event_id(second, "connection")


def test_get_event_id_audit_is_deterministic():
    event = {"category": "user", "timestamp": "2026-06-16 06:54:55", "action": "login", "user": {"id": "u1"}}
    assert get_event_id(event, "audit") == get_event_id(dict(reversed(list(event.items()))), "audit")


""" DEDUPLICATION """


def test_deduplicate_events_removes_repeats_and_tracks_ids():
    seen: set[str] = set()
    events = [{"event_id": "1"}, {"event_id": "1"}, {"event_id": "2"}]
    assert deduplicate_events(events, seen) == [{"event_id": "1"}, {"event_id": "2"}]
    assert seen == {"1", "2"}


def test_deduplicate_events_across_calls():
    """Ids carry across files within a cycle, since one event can appear in two export files."""
    seen: set[str] = set()
    deduplicate_events([{"event_id": "1"}], seen)
    assert deduplicate_events([{"event_id": "1"}, {"event_id": "2"}], seen) == [{"event_id": "2"}]


""" INTERVALS AND WINDOW """


def test_generate_intervals_splits_and_covers_range():
    start, end = datetime(2026, 7, 1, 0, tzinfo=UTC), datetime(2026, 7, 1, 5, tzinfo=UTC)
    intervals = generate_intervals(start, end, 3)
    assert intervals == [(start, datetime(2026, 7, 1, 3, tzinfo=UTC)), (datetime(2026, 7, 1, 3, tzinfo=UTC), end)]


def test_generate_intervals_empty_when_start_not_before_end():
    """Regression: an inverted range yields no work instead of looping or raising."""
    start = datetime(2026, 7, 1, 5, tzinfo=UTC)
    assert generate_intervals(start, start, 1) == []
    assert generate_intervals(start, start - timedelta(hours=2), 1) == []


def test_generate_intervals_rejects_oversized_window():
    """The API rejects ranges longer than 3 hours, so the error is raised before the call."""
    start, end = datetime(2026, 7, 1, 0, tzinfo=UTC), datetime(2026, 7, 1, 9, tzinfo=UTC)
    with pytest.raises(DemistoException, match="exceeds the API maximum"):
        generate_intervals(start, end, 4)


def test_calculate_fetch_window_first_run_is_recent_only():
    """First run collects the last completed hour, never historical data."""
    now = datetime(2026, 7, 1, 10, 42, tzinfo=UTC)
    start, end = calculate_fetch_window(None, now)
    assert (start, end) == (datetime(2026, 7, 1, 9, tzinfo=UTC), datetime(2026, 7, 1, 10, tzinfo=UTC))


def test_calculate_fetch_window_never_requests_current_hour():
    """Regression: the API rejects a range extending into the in-progress hour."""
    now = datetime(2026, 7, 1, 10, 59, tzinfo=UTC)
    _, end = calculate_fetch_window("2026-07-01T05", now)
    assert end == datetime(2026, 7, 1, 10, tzinfo=UTC)


def test_calculate_fetch_window_applies_lookback():
    """Recent hours are re-read because ETD keeps writing export files after an hour closes."""
    now = datetime(2026, 7, 1, 10, 5, tzinfo=UTC)
    start, _ = calculate_fetch_window("2026-07-01T08", now)
    assert start == datetime(2026, 7, 1, 6, tzinfo=UTC)


def test_calculate_fetch_window_clamps_to_retention():
    """The API rejects timestamps older than 30 days, so the start is moved forward."""
    now = datetime(2026, 7, 1, 10, 0, tzinfo=UTC)
    start, end = calculate_fetch_window("2026-01-01T00", now)
    assert start == end - timedelta(days=30)


def test_calculate_fetch_window_handles_future_checkpoint():
    """A checkpoint ahead of now must not produce an inverted window that stalls the fetch."""
    now = datetime(2026, 7, 1, 10, 0, tzinfo=UTC)
    start, end = calculate_fetch_window("2026-07-05T00", now)
    assert start < end


""" FETCH STATE """


def test_get_object_path_ignores_signature():
    """The signature changes every request, so only the object path identifies the file."""
    assert get_object_path(LINK) == LINK_PATH
    assert get_object_path(LINK.replace("abc", "zzz")) == LINK_PATH


def test_fetch_state_tracks_and_prunes_files():
    state = FetchState({})
    state.mark_complete("/log_date%3D2026-07-01/hour%3D10/a.jsonl")
    state.mark_complete("/log_date%3D2026-06-01/hour%3D10/old.jsonl")
    last_run = state.to_last_run("2026-07-01T11")
    assert "/log_date%3D2026-07-01/hour%3D10/a.jsonl" in last_run["processed_files"]
    assert "/log_date%3D2026-06-01/hour%3D10/old.jsonl" not in last_run["processed_files"]


def test_fetch_state_resume_offset_roundtrip():
    state = FetchState({"partial_file": {"path": LINK_PATH, "offset": 120}})
    assert state.resume_offset(LINK_PATH) == 120
    assert state.resume_offset("/other") == 0
    state.mark_complete(LINK_PATH)
    assert state.resume_offset(LINK_PATH) == 0


""" DOWNLOAD """


def test_stream_events_parses_and_enriches():
    client = build_client()
    mock_download(client, ['{"message":{"id":"1","timestamp":"2026-07-01T10:00:00Z"}}'])
    events, offset, completed = client.stream_events("message", LINK, WINDOW_START, 100)
    assert len(events) == 1
    assert events[0]["source_log_type"] == "message"
    assert events[0]["_time"] == "2026-07-01T10:00:00.000Z"
    assert events[0]["event_id"]
    assert (offset, completed) == (1, True)


def test_stream_events_skips_blank_and_malformed_lines():
    """A bad line must not discard the good lines that follow it in the same file."""
    client = build_client()
    mock_download(client, ['{"message":{"id":"1"}}', "", "   ", "not json", "[1,2]", '{"message":{"id":"2"}}'])
    events, _, completed = client.stream_events("message", LINK, WINDOW_START, 100)
    assert [event["message"]["id"] for event in events] == ["1", "2"]
    assert completed is True


def test_stream_events_stops_at_limit_and_reports_offset():
    """Hitting the limit mid-file reports the resume point instead of dropping the remainder."""
    client = build_client()
    mock_download(client, ['{"message":{"id":"1"}}', '{"message":{"id":"2"}}', '{"message":{"id":"3"}}'])
    events, offset, completed = client.stream_events("message", LINK, WINDOW_START, 2)
    assert len(events) == 2
    assert (offset, completed) == (2, False)


def test_stream_events_resumes_from_offset():
    client = build_client()
    mock_download(client, ['{"message":{"id":"1"}}', '{"message":{"id":"2"}}'])
    events, _, _ = client.stream_events("message", LINK, WINDOW_START, 100, start_offset=1)
    assert [event["message"]["id"] for event in events] == ["2"]


def test_stream_events_uses_streaming():
    """Regression: the file must be streamed so a large export is not buffered in memory."""
    client = build_client()
    mock_download(client, ['{"message":{"id":"1"}}'])
    client.stream_events("message", LINK, WINDOW_START, 100)
    assert client._download_session.get.call_args.kwargs["stream"] is True


def test_stream_events_raises_on_http_error():
    client = build_client()
    mock_download(client, [], status_code=500)
    with pytest.raises(DemistoException, match="Failed downloading"):
        client.stream_events("message", LINK, WINDOW_START, 100)


""" LINKS """


def test_get_links_collects_per_type():
    client = build_client()
    response = {"data": {"message": ["a"], "audit": ["b"], "connection": ["c"]}}
    assert client.get_links(response, ["message", "audit", "connection"]) == [
        ("message", "a"),
        ("audit", "b"),
        ("connection", "c"),
    ]


@pytest.mark.parametrize("payload", [{"data": {}}, {}, {"data": {"message": "oops", "audit": None, "connection": {}}}])
def test_get_links_tolerates_malformed_payloads(payload):
    client = build_client()
    assert client.get_links(payload, ["message", "audit", "connection"]) == []


def test_get_links_warns_when_api_truncates(mocker):
    """The API caps the response at 200 links and silently drops the rest, so it is surfaced."""
    error = mocker.patch("CiscoETDConnector.demisto.error")
    client = build_client()
    client.get_links({"data": {"message": [f"link{i}" for i in range(200)]}}, ["message"])
    assert "truncated" in error.call_args[0][0]


""" AUTHENTICATION """


def test_get_access_token_uses_cache(mocker):
    mocker.patch(
        "CiscoETDConnector.demisto.getIntegrationContext",
        return_value={"access_token": "cached", "token_expiry": (datetime.now(UTC) + timedelta(hours=1)).timestamp()},
    )
    client = build_client()
    request = mocker.patch.object(ETDClient, "_http_request")
    assert client.get_access_token() == "cached"
    request.assert_not_called()


def test_get_access_token_refreshes_near_expiry(mocker):
    """A token about to expire is replaced up front rather than failing mid-fetch."""
    mocker.patch(
        "CiscoETDConnector.demisto.getIntegrationContext",
        return_value={"access_token": "stale", "token_expiry": (datetime.now(UTC) + timedelta(seconds=30)).timestamp()},
    )
    mocker.patch("CiscoETDConnector.demisto.setIntegrationContext")
    client = build_client()
    mocker.patch.object(ETDClient, "_http_request", return_value={"accessToken": "fresh", "expiresIn": 3600})
    assert client.get_access_token() == "fresh"


def test_get_access_token_honours_expires_in(mocker):
    """The TTL comes from the API response rather than a hardcoded assumption."""
    mocker.patch("CiscoETDConnector.demisto.getIntegrationContext", return_value={})
    set_context = mocker.patch("CiscoETDConnector.demisto.setIntegrationContext")
    client = build_client()
    mocker.patch.object(ETDClient, "_http_request", return_value={"accessToken": "t", "expiresIn": 120})
    client.get_access_token()
    saved = set_context.call_args[0][0]
    assert saved["token_expiry"] - datetime.now(UTC).timestamp() == pytest.approx(120, abs=5)


def test_get_access_token_preserves_existing_context(mocker):
    """The context is merged, not overwritten, so unrelated keys survive."""
    mocker.patch("CiscoETDConnector.demisto.getIntegrationContext", return_value={"unrelated": "keep"})
    set_context = mocker.patch("CiscoETDConnector.demisto.setIntegrationContext")
    client = build_client()
    mocker.patch.object(ETDClient, "_http_request", return_value={"accessToken": "t"})
    client.get_access_token()
    assert set_context.call_args[0][0]["unrelated"] == "keep"


def test_get_access_token_missing_token(mocker):
    mocker.patch("CiscoETDConnector.demisto.getIntegrationContext", return_value={})
    client = build_client()
    mocker.patch.object(ETDClient, "_http_request", return_value={})
    with pytest.raises(DemistoException, match="no access token"):
        client.get_access_token()


def test_request_log_export_retries_once_on_401(mocker):
    """A token expiring mid-fetch is refreshed and the request retried, not failed."""
    client = build_client()
    expired = DemistoException("expired", res=MagicMock(status_code=401))
    request = mocker.patch.object(ETDClient, "_http_request", side_effect=[expired, {"data": {}}])
    authenticate = mocker.patch.object(ETDClient, "_authenticate")
    assert client.request_log_export("2026-07-01T10", "2026-07-01T11", ["message"]) == {"data": {}}
    authenticate.assert_called_once_with(force_refresh=True)
    assert request.call_count == 2


@pytest.mark.parametrize(
    "status_code, expected",
    [
        (403, "Verify the API Key"),
        (429, "rate limit"),
        (503, "temporarily unavailable"),
    ],
)
def test_request_log_export_translates_errors(mocker, status_code, expected):
    """API errors are surfaced with the action the user needs to take."""
    client = build_client()
    mocker.patch.object(ETDClient, "_http_request", side_effect=DemistoException("x", res=MagicMock(status_code=status_code)))
    with pytest.raises(DemistoException, match=expected):
        client.request_log_export("2026-07-01T10", "2026-07-01T11", ["message"])


@pytest.mark.parametrize("status_code, fatal", [(401, True), (403, True), (400, True), (429, False), (503, False), (None, False)])
def test_is_fatal_error(status_code, fatal):
    assert is_fatal_error(DemistoException("x", res=MagicMock(status_code=status_code))) is fatal


""" FETCH """


@pytest.fixture
def fetch_mocks(mocker):
    mocker.patch("CiscoETDConnector.demisto.getLastRun", return_value={})
    return {
        "set_last_run": mocker.patch("CiscoETDConnector.demisto.setLastRun"),
        "send": mocker.patch("CiscoETDConnector.send_events_to_xsiam"),
    }


def test_fetch_events_sends_with_vendor_and_product(mocker, fetch_mocks):
    client = build_client()
    mocker.patch.object(ETDClient, "request_log_export", return_value={"data": {"message": [LINK]}})
    mocker.patch.object(
        ETDClient,
        "stream_events",
        return_value=([{"event_id": "1", "_time": "2026-07-01T10:00:00.000Z"}], 1, True),
    )
    fetch_events(client, {"max_fetch": 100, "event_type": ["message"]})

    kwargs = fetch_mocks["send"].call_args.kwargs
    assert kwargs["vendor"] == "Cisco"
    assert kwargs["product"] == "ETD"
    assert len(kwargs["events"]) == 1


def test_fetch_events_saves_checkpoint_with_processed_files(mocker, fetch_mocks):
    """The checkpoint records the hour reached and the files already ingested."""
    link, path = recent_link()
    client = build_client()
    mocker.patch.object(ETDClient, "request_log_export", return_value={"data": {"message": [link]}})
    mocker.patch.object(ETDClient, "stream_events", return_value=([{"event_id": "1", "_time": "t"}], 1, True))
    fetch_events(client, {"max_fetch": 100, "event_type": ["message"]})

    last_run = fetch_mocks["set_last_run"].call_args[0][0]
    assert last_run["last_hour"]
    assert path in last_run["processed_files"]


def test_fetch_state_prunes_files_outside_the_lookback_window():
    """Files older than the next lookback window are dropped so the state cannot grow forever."""
    state = FetchState({})
    _, recent_path = recent_link()
    state.mark_complete(recent_path)
    state.mark_complete(LINK_PATH)  # dated 2026-07-01, far outside the window
    retained = state.to_last_run(datetime.now(UTC).strftime("%Y-%m-%dT%H"))["processed_files"]
    assert recent_path in retained
    assert LINK_PATH not in retained


def test_fetch_events_skips_already_processed_files(mocker):
    """Regression: re-reading an hour must not re-ingest files from the previous cycle."""
    now_hour = datetime.now(UTC).replace(minute=0, second=0, microsecond=0)
    mocker.patch(
        "CiscoETDConnector.demisto.getLastRun",
        return_value={"last_hour": (now_hour - timedelta(hours=1)).strftime("%Y-%m-%dT%H"), "processed_files": [LINK_PATH]},
    )
    mocker.patch("CiscoETDConnector.demisto.setLastRun")
    send = mocker.patch("CiscoETDConnector.send_events_to_xsiam")
    client = build_client()
    mocker.patch.object(ETDClient, "request_log_export", return_value={"data": {"message": [LINK]}})
    stream = mocker.patch.object(ETDClient, "stream_events")

    fetch_events(client, {"max_fetch": 100, "event_type": ["message"]})
    stream.assert_not_called()
    send.assert_not_called()


def test_fetch_events_no_events_still_advances_checkpoint(mocker, fetch_mocks):
    """An empty hour is a completed hour, so the window must move forward."""
    client = build_client()
    mocker.patch.object(ETDClient, "request_log_export", return_value={"data": {"message": []}})
    fetch_events(client, {"max_fetch": 100, "event_type": ["message"]})
    fetch_mocks["send"].assert_not_called()
    fetch_mocks["set_last_run"].assert_called_once()


def test_fetch_events_truncates_at_max_fetch_and_resumes(mocker, fetch_mocks):
    """Regression: the remainder of a truncated file is recorded so nothing is lost."""
    client = build_client()
    mocker.patch.object(ETDClient, "request_log_export", return_value={"data": {"message": [LINK]}})
    mocker.patch.object(
        ETDClient,
        "stream_events",
        return_value=([{"event_id": "1", "_time": "t"}, {"event_id": "2", "_time": "t"}], 2, False),
    )
    fetch_events(client, {"max_fetch": 2, "event_type": ["message"]})

    last_run = fetch_mocks["set_last_run"].call_args[0][0]
    assert last_run["partial_file"] == {"path": LINK_PATH, "offset": 2}
    assert LINK_PATH not in last_run["processed_files"]


def test_fetch_events_deduplicates_across_files(mocker, fetch_mocks):
    """The same event appearing in two export files of one hour is sent only once."""
    client = build_client()
    second_link = LINK.replace("0000.jsonl", "0001.jsonl")
    mocker.patch.object(ETDClient, "request_log_export", return_value={"data": {"message": [LINK, second_link]}})
    mocker.patch.object(ETDClient, "stream_events", return_value=([{"event_id": "dup", "_time": "t"}], 1, True))
    fetch_events(client, {"max_fetch": 100, "event_type": ["message"]})

    total_sent = sum(len(call.kwargs["events"]) for call in fetch_mocks["send"].call_args_list)
    assert total_sent == 1


def test_fetch_events_raises_and_preserves_window_on_error(mocker, fetch_mocks):
    """Regression: a failure must surface and must not advance past the failed hour."""
    client = build_client()
    mocker.patch.object(
        ETDClient, "request_log_export", side_effect=DemistoException("denied", res=MagicMock(status_code=403))
    )
    with pytest.raises(DemistoException, match="denied"):
        fetch_events(client, {"max_fetch": 100, "event_type": ["message"]})

    last_run = fetch_mocks["set_last_run"].call_args[0][0]
    assert last_run["processed_files"] == []


def test_fetch_events_partial_progress_is_kept_on_error(mocker):
    """Files ingested before a mid-cycle failure are not downloaded again on the retry."""
    now_hour = datetime.now(UTC).replace(minute=0, second=0, microsecond=0)
    link, path = recent_link(hours_ago=3)
    mocker.patch(
        "CiscoETDConnector.demisto.getLastRun",
        return_value={"last_hour": (now_hour - timedelta(hours=3)).strftime("%Y-%m-%dT%H")},
    )
    set_last_run = mocker.patch("CiscoETDConnector.demisto.setLastRun")
    mocker.patch("CiscoETDConnector.send_events_to_xsiam")
    client = build_client()
    mocker.patch.object(
        ETDClient,
        "request_log_export",
        side_effect=[{"data": {"message": [link]}}, DemistoException("boom", res=MagicMock(status_code=503))],
    )
    mocker.patch.object(ETDClient, "stream_events", return_value=([{"event_id": "1", "_time": "t"}], 1, True))

    with pytest.raises(DemistoException):
        fetch_events(client, {"max_fetch": 100, "event_type": ["message"]})
    assert path in set_last_run.call_args[0][0]["processed_files"]


def test_fetch_events_stops_on_time_budget(mocker, fetch_mocks):
    """The fetch yields before the container timeout so the checkpoint can be saved."""
    client = build_client()
    mocker.patch("CiscoETDConnector.time.time", side_effect=[0] + [10**9] * 20)
    request = mocker.patch.object(ETDClient, "request_log_export", return_value={"data": {"message": []}})
    fetch_events(client, {"max_fetch": 100, "event_type": ["message"]})
    request.assert_not_called()
    fetch_mocks["set_last_run"].assert_called_once()


def test_fetch_events_defaults_to_all_log_types(mocker, fetch_mocks):
    """An unset Event Types parameter collects every type rather than failing."""
    client = build_client()
    request = mocker.patch.object(ETDClient, "request_log_export", return_value={"data": {}})
    fetch_events(client, {})
    assert request.call_args[0][2] == ["message", "audit", "connection"]


@pytest.mark.parametrize("max_fetch", ["", None, "abc"])
def test_fetch_events_invalid_max_fetch_uses_default(mocker, fetch_mocks, max_fetch):
    """Regression: a blank or non-numeric max_fetch must not crash the fetch."""
    client = build_client()
    mocker.patch.object(ETDClient, "request_log_export", return_value={"data": {}})
    fetch_events(client, {"max_fetch": max_fetch, "event_type": ["message"]})
    fetch_mocks["set_last_run"].assert_called_once()


""" GET EVENTS COMMAND """


def test_parse_command_range_accepts_relative_time(mocker):
    """Regression: time arguments are parsed with dateparser, not a single rigid format."""
    mocker.patch("CiscoETDConnector.datetime", wraps=datetime)
    start, end = parse_command_range({"start_time": "2026-07-01T09:30:00Z", "end_time": "2026-07-01T11:45:00Z"})
    assert (start, end) == (datetime(2026, 7, 1, 9, tzinfo=UTC), datetime(2026, 7, 1, 11, tzinfo=UTC))


def test_parse_command_range_rejects_inverted_range():
    with pytest.raises(DemistoException, match="at least one full hour earlier"):
        parse_command_range({"start_time": "2026-07-01T11:00:00Z", "end_time": "2026-07-01T10:00:00Z"})


def test_parse_command_range_rejects_beyond_retention():
    with pytest.raises(DemistoException, match="30 days"):
        parse_command_range({"start_time": "40 days ago", "end_time": "now"})


def test_get_events_command_does_not_push_by_default(mocker):
    client = build_client()
    send = mocker.patch("CiscoETDConnector.send_events_to_xsiam")
    mocker.patch.object(ETDClient, "request_log_export", return_value={"data": {"message": [LINK]}})
    mocker.patch.object(ETDClient, "stream_events", return_value=([{"event_id": "1", "_time": "t"}], 1, True))
    results = cisco_etd_get_events_command(client, {"start_time": "3 hours ago", "end_time": "1 hour ago"})
    send.assert_not_called()
    assert "Cisco ETD events" in results.readable_output


def test_get_events_command_pushes_when_requested(mocker):
    client = build_client()
    send = mocker.patch("CiscoETDConnector.send_events_to_xsiam")
    mocker.patch.object(ETDClient, "request_log_export", return_value={"data": {"message": [LINK]}})
    mocker.patch.object(ETDClient, "stream_events", return_value=([{"event_id": "1", "_time": "t"}], 1, True))
    cisco_etd_get_events_command(
        client, {"start_time": "3 hours ago", "end_time": "1 hour ago", "should_push_events": "true"}
    )
    send.assert_called_once()


def test_get_events_command_does_not_touch_last_run(mocker):
    """The debug command must never move the fetch checkpoint."""
    client = build_client()
    set_last_run = mocker.patch("CiscoETDConnector.demisto.setLastRun")
    mocker.patch("CiscoETDConnector.send_events_to_xsiam")
    mocker.patch.object(ETDClient, "request_log_export", return_value={"data": {"message": [LINK]}})
    mocker.patch.object(ETDClient, "stream_events", return_value=([{"event_id": "1", "_time": "t"}], 1, True))
    cisco_etd_get_events_command(client, {"start_time": "3 hours ago", "end_time": "1 hour ago"})
    set_last_run.assert_not_called()


def test_get_events_command_respects_limit(mocker):
    client = build_client()
    mocker.patch.object(ETDClient, "request_log_export", return_value={"data": {"message": [LINK]}})
    stream = mocker.patch.object(
        ETDClient, "stream_events", return_value=([{"event_id": str(i), "_time": "t"} for i in range(5)], 5, False)
    )
    cisco_etd_get_events_command(client, {"start_time": "3 hours ago", "end_time": "1 hour ago", "limit": "5"})
    assert stream.call_args[0][3] == 5


def test_get_events_command_empty_result(mocker):
    client = build_client()
    mocker.patch.object(ETDClient, "request_log_export", return_value={"data": {}})
    results = cisco_etd_get_events_command(client, {"start_time": "3 hours ago", "end_time": "1 hour ago"})
    assert "No events were found" in results.readable_output


""" TEST MODULE """


def test_test_module_does_not_download(mocker):
    """Connectivity is verified without downloading export files, so Test stays fast."""
    client = build_client()
    request = mocker.patch.object(ETDClient, "request_log_export", return_value={"data": {}})
    stream = mocker.patch.object(ETDClient, "stream_events")
    assert run_test_module(client) == "ok"
    request.assert_called_once()
    stream.assert_not_called()


def test_test_module_propagates_auth_error(mocker):
    client = build_client()
    mocker.patch.object(
        ETDClient, "request_log_export", side_effect=DemistoException("Verify the API Key", res=MagicMock(status_code=403))
    )
    with pytest.raises(DemistoException, match="Verify the API Key"):
        run_test_module(client)


""" MAIN """


def test_main_reports_the_real_error(mocker):
    """Regression: failures must not all be reported as an authentication problem."""
    mocker.patch("CiscoETDConnector.demisto.params", return_value={"etd_base_url": "https://api.us.etd.cisco.com"})
    mocker.patch("CiscoETDConnector.demisto.command", return_value="fetch-events")
    mocker.patch.object(ETDClient, "__init__", return_value=None)
    mocker.patch("CiscoETDConnector.fetch_events", side_effect=DemistoException("rate limit exceeded"))
    return_error = mocker.patch("CiscoETDConnector.return_error")

    from CiscoETDConnector import main

    main()
    message = return_error.call_args[0][0]
    assert "rate limit exceeded" in message
    assert "Authentication failed" not in message


def test_main_rejects_unknown_command(mocker):
    mocker.patch("CiscoETDConnector.demisto.params", return_value={})
    mocker.patch("CiscoETDConnector.demisto.command", return_value="cisco-etd-unknown")
    mocker.patch.object(ETDClient, "__init__", return_value=None)
    return_error = mocker.patch("CiscoETDConnector.return_error")

    from CiscoETDConnector import main

    main()
    assert "not implemented" in return_error.call_args[0][0]


""" SAMPLE PAYLOADS FROM THE API DOCUMENTATION """


# Payloads copied from the Cisco Log Export API documentation.
CREATE_SAMPLE = (
    '{"message":{"eventType":"create","id":"0540d1c3","timestamp":"2025-07-16T05:59:42Z"},'
    '"tenantId":"07fa4225","logType":"message","logDate":"2025-07-16","logHour":"06"}'
)
UPDATE_SAMPLE = (
    '{"message":{"eventType":"update","id":"74572252","verdict":{"verdict":"phishing",'
    '"timestamp":"2025-07-21T12:36:28.412718327Z"}},"logDate":"2025-07-21","logHour":"12"}'
)
AUDIT_SAMPLE = (
    '{"category":"user","timestamp":"2025-06-16 06:54:55","action":"get_token","status":"success",'
    '"user":{"id":"0b74ee5b"},"metadata":null}'
)


@pytest.mark.parametrize(
    "raw, log_type",
    [
        (CREATE_SAMPLE, "message"),
        (UPDATE_SAMPLE, "message"),
        (AUDIT_SAMPLE, "audit"),
    ],
)
def test_parse_line_against_documented_samples(raw, log_type):
    """Parsing is verified against the payloads published in the Cisco API documentation."""
    event = ETDClient.parse_line(raw, log_type, WINDOW_START)
    assert event is not None
    assert event["source_log_type"] == log_type
    assert event["event_id"]
    assert event["_time"].endswith("Z")
    # The resolved time comes from the payload, not from the window fallback.
    assert event["_time"] != format_event_time(WINDOW_START)
    assert json.loads(raw).keys() <= event.keys()
