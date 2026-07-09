"""Unit tests for the SaaS Security Event Collector integration."""

import json

import pytest
from CommonServerPython import *  # noqa
from SaasSecurityEventCollector import Client

BASE_PARAMS = {
    "url": "https://test.com/",
    "credentials": {"identifier": "1234", "password": "1234"},
}


@pytest.fixture
def mock_client():
    return Client(base_url="https://test.com/api", client_id="", client_secret="", verify=False, proxy=False)


def create_events(start_id=1, end_id=100, should_dump=True):
    events = {"events": [{"id": i} for i in range(start_id, end_id + 1)]}
    return json.dumps(events) if should_dump else events


class MockedResponse:
    def __init__(self, status_code, text="{}"):
        self.status_code = status_code
        self.text = text

    def json(self):
        return json.loads(self.text)


def test_module(mocker, mock_client):
    """
    Given a valid access token, when testing the module, then it returns 'ok'.
    """
    from SaasSecurityEventCollector import test_module

    mocker.patch.object(Client, "get_token_request")
    assert test_module(client=mock_client) == "ok"


def test_get_new_access_token(mocker, mock_client):
    mocker.patch.object(mock_client, "get_token_request", return_value=("123", "100"))
    assert mock_client.get_access_token() == "123"


# ---------------------------------------------------------------------------
# get_max_iterations - the code-level floor (fix #1)
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "configured, expected",
    [
        (None, 900),  # not configured -> default
        (0, 900),  # non-positive -> default
        (50, 900),  # stale legacy value below the floor -> raised to floor
        (300, 900),  # previous default, now below the floor -> raised
        (899, 900),  # just below the floor -> raised
        (900, 900),  # at the floor
        (1200, 1200),  # above the floor -> honored
    ],
)
def test_get_max_iterations_floor(configured, expected):
    """
    Given a configured max_iterations value (including a stale low one that cannot be edited on the instance),
    when resolving the effective value,
    then it is never below MIN_MAX_ITERATIONS so throughput cannot be capped by a stale instance param.
    """
    from SaasSecurityEventCollector import get_max_iterations

    assert get_max_iterations(configured) == expected


# ---------------------------------------------------------------------------
# get_concurrency - clamping
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "configured, expected",
    [(None, 10), (0, 10), (-5, 10), (5, 5), (30, 30), (100, 30)],
)
def test_get_concurrency(configured, expected):
    from SaasSecurityEventCollector import get_concurrency

    assert get_concurrency(configured) == expected


# ---------------------------------------------------------------------------
# build_client - a fresh client (own session) per call (fix #2, thread safety)
# ---------------------------------------------------------------------------


def test_build_client_returns_independent_instances():
    """
    Given params, when building clients for concurrent workers,
    then each call returns a distinct Client with its own session (required for thread safety).
    """
    from SaasSecurityEventCollector import build_client

    c1 = build_client(BASE_PARAMS)
    c2 = build_client(BASE_PARAMS)
    assert c1 is not c2
    assert c1._session is not c2._session


# ---------------------------------------------------------------------------
# get_events_batch
# ---------------------------------------------------------------------------


def test_get_events_batch_204_is_drained(mocker, mock_client):
    from SaasSecurityEventCollector import get_events_batch

    mocker.patch.object(Client, "http_request", return_value=MockedResponse(status_code=204))
    events, drained = get_events_batch(mock_client)
    assert events == []
    assert drained is True


def test_get_events_batch_200_returns_events(mocker, mock_client):
    from SaasSecurityEventCollector import get_events_batch

    mocker.patch.object(Client, "http_request", return_value=MockedResponse(status_code=200, text=create_events(1, 100)))
    events, drained = get_events_batch(mock_client)
    assert len(events) == 100
    assert drained is False


# ---------------------------------------------------------------------------
# send_events_in_chunks - resilient chunked send (fix #3, context self-heal)
# ---------------------------------------------------------------------------


def test_send_events_in_chunks_success_empties_list(mocker):
    """
    Given events and a working send, when sending in chunks,
    then all events are sent and the source list is emptied (all acknowledged).
    """
    import SaasSecurityEventCollector

    send_mock = mocker.patch.object(SaasSecurityEventCollector, "send_events_to_xsiam")
    events = [{"id": i} for i in range(2500)]
    sent = SaasSecurityEventCollector.send_events_in_chunks(events, send_batch_size=1000, vendor="v", product="p")
    assert sent == 2500
    assert events == []  # fully drained
    assert send_mock.call_count == 3  # 1000 + 1000 + 500


def test_send_events_in_chunks_failure_keeps_only_remainder(mocker):
    """
    Given a stashed batch and a send that fails on the 2nd chunk,
    when sending in chunks,
    then the successfully-sent chunk is removed and only the unsent remainder is left in the list.

    This is the self-heal guarantee: the poisoned/oversized stash shrinks every cycle instead of being
    re-stashed whole and retried forever.
    """
    import SaasSecurityEventCollector

    calls = {"n": 0}

    def flaky_send(events, vendor, product, **kwargs):
        calls["n"] += 1
        if calls["n"] == 2:
            raise ValueError("Expecting value: line 1 column 1 (char 0)")

    mocker.patch.object(SaasSecurityEventCollector, "send_events_to_xsiam", side_effect=flaky_send)
    events = [{"id": i} for i in range(2500)]
    with pytest.raises(ValueError):
        SaasSecurityEventCollector.send_events_in_chunks(events, send_batch_size=1000, vendor="v", product="p")
    # First 1000 acknowledged and removed; remaining 1500 preserved for retry.
    assert len(events) == 1500
    assert events[0]["id"] == 1000


def _json_decode_error(body: str):
    """Build a real json.JSONDecodeError as raised by response.json() on the given (bad) body."""
    try:
        json.loads(body)
    except json.JSONDecodeError as exc:
        return exc
    raise AssertionError("body was valid JSON; expected a decode error")


# ---------------------------------------------------------------------------
# describe_xsiam_response_failure - capture the ACTUAL XSIAM response body
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "body, expect_benign",
    [
        ("", True),            # completely empty body -> benign empty-body case
        ("   \n\t ", True),    # whitespace-only body -> benign empty-body case
        ("<html>502</html>", False),  # non-empty unparseable body -> real failure
        ('{"ok":true}xtra', False),   # trailing garbage (Extra data) -> real failure
    ],
)
def test_describe_xsiam_response_failure_classification(body, expect_benign):
    """
    Given the JSONDecodeError raised by response.json() on a bad XSIAM response body,
    then the helper surfaces the ACTUAL body length and classifies blank bodies as benign
    (pass-over candidate) while non-empty unparseable bodies are NOT benign.
    """
    import SaasSecurityEventCollector

    exc = _json_decode_error(body)
    description, benign = SaasSecurityEventCollector.describe_xsiam_response_failure(exc)
    assert benign is expect_benign
    assert f"response_body_len={len(body)}" in description
    assert "response_body_preview=" in description


def test_describe_xsiam_response_failure_non_decode_error():
    """
    Given an exception that is NOT a JSONDecodeError (e.g. a network/DemistoException),
    then there is no response body to show and it is not classified as a benign empty body.
    """
    import SaasSecurityEventCollector

    description, benign = SaasSecurityEventCollector.describe_xsiam_response_failure(RuntimeError("boom"))
    assert benign is False
    assert "response_body=<unavailable>" in description
    assert "exc_type=RuntimeError" in description


def test_send_events_in_chunks_passes_over_empty_body(mocker):
    """
    Given XSIAM returns a 200 with an empty body (JSONDecodeError on char 0),
    when sending in chunks with pass_over_empty_response=True,
    then the chunk is treated as delivered: it is removed, counted as sent, and no exception propagates.

    This is the "catch and pass over a benign empty response while the platform team fixes it" behavior.
    """
    import SaasSecurityEventCollector

    def empty_body_send(events, vendor, product, **kwargs):
        raise _json_decode_error("")  # empty response body

    mocker.patch.object(SaasSecurityEventCollector, "send_events_to_xsiam", side_effect=empty_body_send)
    events = [{"id": i} for i in range(2500)]
    sent = SaasSecurityEventCollector.send_events_in_chunks(
        events, send_batch_size=1000, vendor="v", product="p", pass_over_empty_response=True
    )
    assert sent == 2500
    assert events == []  # all passed over as delivered


def test_send_events_in_chunks_does_not_pass_over_non_empty_body(mocker):
    """
    Given XSIAM returns a 200 with a NON-empty unparseable body,
    when sending in chunks with pass_over_empty_response=True,
    then it is treated as a real failure: the exception propagates and the unsent remainder is preserved.
    """
    import SaasSecurityEventCollector

    def truncated_body_send(events, vendor, product, **kwargs):
        raise _json_decode_error("<html>bad gateway</html>")

    mocker.patch.object(SaasSecurityEventCollector, "send_events_to_xsiam", side_effect=truncated_body_send)
    events = [{"id": i} for i in range(2500)]
    with pytest.raises(json.JSONDecodeError):
        SaasSecurityEventCollector.send_events_in_chunks(
            events, send_batch_size=1000, vendor="v", product="p", pass_over_empty_response=True
        )
    assert len(events) == 2500  # nothing acknowledged - all preserved for retry


def test_send_events_in_chunks_empty_body_not_passed_over_when_disabled(mocker):
    """
    Given the pass-over is disabled, when XSIAM returns an empty body,
    then even a benign empty body is treated as a failure (exception propagates) and events are preserved.
    """
    import SaasSecurityEventCollector

    def empty_body_send(events, vendor, product, **kwargs):
        raise _json_decode_error("")

    mocker.patch.object(SaasSecurityEventCollector, "send_events_to_xsiam", side_effect=empty_body_send)
    events = [{"id": i} for i in range(2500)]
    with pytest.raises(json.JSONDecodeError):
        SaasSecurityEventCollector.send_events_in_chunks(
            events, send_batch_size=1000, vendor="v", product="p", pass_over_empty_response=False
        )
    assert len(events) == 2500


# ---------------------------------------------------------------------------
# fetch_and_send_events_concurrently
# ---------------------------------------------------------------------------


def test_concurrent_fetch_uses_own_client_per_worker(mocker):
    """
    Given the concurrent drain, when it issues GET calls,
    then it builds a fresh client per worker (never shares a session across threads).
    """
    import SaasSecurityEventCollector

    build_client_mock = mocker.patch.object(
        SaasSecurityEventCollector, "build_client", wraps=SaasSecurityEventCollector.build_client
    )
    # First round returns events, second round drains.
    batches = [([{"id": 1}], False)] * 3 + [([], True)] * 10
    mocker.patch.object(SaasSecurityEventCollector, "get_events_batch", side_effect=batches)
    mocker.patch.object(SaasSecurityEventCollector, "send_events_to_xsiam")

    SaasSecurityEventCollector.fetch_and_send_events_concurrently(params=BASE_PARAMS, max_iterations=6, concurrency=3)
    # build_client is called once per worker submission (never zero -> proves per-thread clients).
    assert build_client_mock.call_count >= 3


def test_concurrent_fetch_flushes_pending_first(mocker):
    """
    Given pending events restored from a poisoned context and an immediately-drained queue,
    when running the concurrent drain,
    then the pending events are flushed to XSIAM (context self-heal) before/independent of new fetches.
    """
    import SaasSecurityEventCollector

    send_mock = mocker.patch.object(SaasSecurityEventCollector, "send_events_to_xsiam")
    mocker.patch.object(SaasSecurityEventCollector, "get_events_batch", return_value=([], True))
    pending = [{"id": i} for i in range(3077)]

    fetched, sent, drained, unsent, exc = SaasSecurityEventCollector.fetch_and_send_events_concurrently(
        params=BASE_PARAMS, max_iterations=150, concurrency=10, send_batch_size=2000, pending_events=pending
    )
    assert exc is None
    assert unsent == []
    assert sent == 3077  # the whole stuck stash was drained
    assert send_mock.called


def test_concurrent_fetch_send_failure_returns_shrunk_unsent(mocker):
    """
    Given a poisoned stash and a send that fails after the first chunk,
    when running the concurrent drain,
    then the exception is captured and the returned unsent list is smaller than the original stash
    (so the next cycle retries a strictly smaller batch - no infinite full-batch replay).
    """
    import SaasSecurityEventCollector

    calls = {"n": 0}

    def flaky_send(events, vendor, product, **kwargs):
        calls["n"] += 1
        if calls["n"] >= 2:
            raise ValueError("Extra data: line 1 column 4 (char 3)")

    mocker.patch.object(SaasSecurityEventCollector, "send_events_to_xsiam", side_effect=flaky_send)
    mocker.patch.object(SaasSecurityEventCollector, "get_events_batch", return_value=([], True))
    pending = [{"id": i} for i in range(3077)]

    fetched, sent, drained, unsent, exc = SaasSecurityEventCollector.fetch_and_send_events_concurrently(
        params=BASE_PARAMS, max_iterations=150, concurrency=10, send_batch_size=2000, pending_events=pending
    )
    assert isinstance(exc, ValueError)
    assert 0 < len(unsent) < 3077  # stash shrank -> self-heals over cycles
    assert sent == 2000


def test_concurrent_fetch_stops_at_time_budget(mocker):
    """
    Given a queue that never drains, when the wall-clock budget is already exhausted (0s),
    then the drain stops before issuing any GET round and returns queue_drained=False (so main persists
    state and re-fires, instead of the engine hard-killing the execution at 5 minutes with progress lost).
    """
    import SaasSecurityEventCollector

    get_batch_mock = mocker.patch.object(SaasSecurityEventCollector, "get_events_batch", return_value=([{"id": 1}], False))
    mocker.patch.object(SaasSecurityEventCollector, "send_events_to_xsiam")

    fetched, sent, drained, unsent, exc = SaasSecurityEventCollector.fetch_and_send_events_concurrently(
        params=BASE_PARAMS, max_iterations=150, concurrency=10, time_budget_seconds=0
    )
    assert drained is False  # not drained -> caller will re-fire via nextTrigger
    assert exc is None
    assert fetched == 0  # exited before issuing any GET round
    assert get_batch_mock.call_count == 0  # budget check short-circuited the loop


def test_concurrent_fetch_stops_at_max_iterations(mocker):
    """
    Given a queue that never drains, when running the concurrent drain,
    then it stops at max_iterations and reports queue_drained=False (backlog signal).
    """
    import SaasSecurityEventCollector

    mocker.patch.object(SaasSecurityEventCollector, "get_events_batch", return_value=([{"id": 1}], False))
    mocker.patch.object(SaasSecurityEventCollector, "send_events_to_xsiam")

    fetched, sent, drained, unsent, exc = SaasSecurityEventCollector.fetch_and_send_events_concurrently(
        params=BASE_PARAMS, max_iterations=6, concurrency=3
    )
    assert drained is False
    assert exc is None


# ---------------------------------------------------------------------------
# get_max_fetch (unchanged behavior, kept for coverage)
# ---------------------------------------------------------------------------


def test_get_max_fetch_default():
    from SaasSecurityEventCollector import get_max_fetch

    assert get_max_fetch(None) == 1000


def test_get_max_fetch_clamped_and_rounded():
    from SaasSecurityEventCollector import get_max_fetch

    assert get_max_fetch(99999) == 5000  # clamp to MAX_LIMIT
    assert get_max_fetch(105) == 100  # round down to multiple of 10


def test_get_max_fetch_negative_number():
    from SaasSecurityEventCollector import get_max_fetch

    with pytest.raises(DemistoException):
        get_max_fetch(-1)


# ---------------------------------------------------------------------------
# events_integrity_fingerprint - context-boundary diagnostics
# ---------------------------------------------------------------------------


def test_events_integrity_fingerprint_healthy_payload():
    """
    Given a clean list[dict] of events,
    when fingerprinting for the context-boundary diagnostic,
    then it reports all_dicts=true and json_serializable=true (proves the payload is well-formed).
    """
    from SaasSecurityEventCollector import events_integrity_fingerprint

    fp = events_integrity_fingerprint([{"id": 1}, {"id": 2}])
    assert "count=2" in fp
    assert "container=list" in fp
    assert "all_dicts=True" in fp
    assert "json_serializable=true" in fp


def test_events_integrity_fingerprint_empty():
    from SaasSecurityEventCollector import events_integrity_fingerprint

    fp = events_integrity_fingerprint([])
    assert "count=0" in fp
    assert "first_type=n/a" in fp
    assert "json_serializable=true" in fp


def test_events_integrity_fingerprint_non_serializable_flagged():
    """
    Given a payload that is NOT JSON-serializable (i.e. malformed for the send path),
    when fingerprinting,
    then json_serializable=false is reported - this is the signal that would prove context corruption.
    """
    from SaasSecurityEventCollector import events_integrity_fingerprint

    fp = events_integrity_fingerprint([{"id": {1, 2, 3}}])  # a set is not JSON-serializable
    assert "json_serializable=false" in fp
    assert "serialize_error=" in fp
