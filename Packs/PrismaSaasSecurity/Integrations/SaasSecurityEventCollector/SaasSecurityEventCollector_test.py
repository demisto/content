"""Unit tests for the SaaS Security Event Collector integration."""

import json

import pytest
import SaasSecurityEventCollector
from CommonServerPython import *  # noqa

BASE_PARAMS = {
    "url": "https://test.com/",
    "credentials": {"identifier": "1234", "password": "1234"},
}


@pytest.fixture
def mock_client():
    return SaasSecurityEventCollector.Client(
        base_url="https://test.com/api", client_id="", client_secret="", verify=False, proxy=False
    )


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
    mocker.patch.object(SaasSecurityEventCollector.Client, "get_token_request")
    assert SaasSecurityEventCollector.test_module(client=mock_client) == "ok"


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
    assert SaasSecurityEventCollector.get_max_iterations(configured) == expected


# ---------------------------------------------------------------------------
# get_concurrency - clamping
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "configured, expected",
    [(None, 10), (0, 10), (-5, 10), (5, 5), (30, 30), (100, 30)],
)
def test_get_concurrency(configured, expected):
    assert SaasSecurityEventCollector.get_concurrency(configured) == expected


# ---------------------------------------------------------------------------
# build_client - a fresh client (own session) per call (fix #2, thread safety)
# ---------------------------------------------------------------------------


def test_build_client_returns_independent_instances():
    """
    Given params, when building clients for concurrent workers,
    then each call returns a distinct Client with its own session (required for thread safety).
    """
    c1 = SaasSecurityEventCollector.build_client(BASE_PARAMS)
    c2 = SaasSecurityEventCollector.build_client(BASE_PARAMS)
    assert c1 is not c2
    assert c1._session is not c2._session


# ---------------------------------------------------------------------------
# get_events_batch
# ---------------------------------------------------------------------------


def test_get_events_batch_204_is_drained(mocker, mock_client):
    mocker.patch.object(SaasSecurityEventCollector.Client, "http_request", return_value=MockedResponse(status_code=204))
    events, drained = SaasSecurityEventCollector.get_events_batch(mock_client)
    assert events == []
    assert drained is True


def test_get_events_batch_200_returns_events(mocker, mock_client):
    mocker.patch.object(
        SaasSecurityEventCollector.Client,
        "http_request",
        return_value=MockedResponse(status_code=200, text=create_events(1, 100)),
    )
    events, drained = SaasSecurityEventCollector.get_events_batch(mock_client)
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
    mocker.patch.object(SaasSecurityEventCollector, "demisto")
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
        ("", True),  # completely empty body -> benign empty-body case
        ("   \n\t ", True),  # whitespace-only body -> benign empty-body case
        ("<html>502</html>", False),  # non-empty unparseable body -> real failure
        ('{"ok":true}xtra', False),  # trailing garbage (Extra data) -> real failure
    ],
)
def test_describe_xsiam_response_failure_classification(body, expect_benign):
    """
    Given the JSONDecodeError raised by response.json() on a bad XSIAM response body,
    then the helper surfaces the ACTUAL body length and classifies blank bodies as benign
    (pass-over candidate) while non-empty unparseable bodies are NOT benign.
    """
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
    mocker.patch.object(SaasSecurityEventCollector, "demisto")

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
    mocker.patch.object(SaasSecurityEventCollector, "demisto")

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
    mocker.patch.object(SaasSecurityEventCollector, "demisto")

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
    mocker.patch.object(SaasSecurityEventCollector, "demisto")
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
    mocker.patch.object(SaasSecurityEventCollector, "get_events_batch", return_value=([{"id": 1}], False))
    mocker.patch.object(SaasSecurityEventCollector, "send_events_to_xsiam")

    fetched, sent, drained, unsent, exc = SaasSecurityEventCollector.fetch_and_send_events_concurrently(
        params=BASE_PARAMS, max_iterations=6, concurrency=3
    )
    assert drained is False
    assert exc is None


def test_concurrent_fetch_keeps_sibling_batches_when_one_worker_raises(mocker):
    """
    Given a round where one worker's ``get_events_batch`` raises while its siblings return already-dequeued
    batches, when running the concurrent drain, then the siblings' batches are NOT lost - they are preserved
    (returned as unsent so the caller stashes and retries them).

    /log_events_bulk is a destructive-read (pop) queue: a sibling batch that a completed worker already
    popped off the server queue is gone from the server. If a peer worker in the same round fails, the
    function must still carry those sibling events out (buffered, then stashed) instead of discarding them
    when the worker exception propagates - otherwise those events are lost forever (data-loss bug guard).
    """
    mocker.patch.object(SaasSecurityEventCollector, "demisto")
    mocker.patch.object(SaasSecurityEventCollector, "send_events_to_xsiam")

    # In the first round one worker raises while the two siblings return real, already-dequeued batches.
    outcomes = [
        RuntimeError("worker network blip"),
        ([{"id": "sibling-a"}], False),
        ([{"id": "sibling-b"}], False),
    ]

    def flaky_batch(client):
        outcome = outcomes.pop(0)
        if isinstance(outcome, Exception):
            raise outcome
        return outcome

    mocker.patch.object(SaasSecurityEventCollector, "get_events_batch", side_effect=flaky_batch)

    fetched, sent, drained, unsent, exc = SaasSecurityEventCollector.fetch_and_send_events_concurrently(
        params=BASE_PARAMS, max_iterations=3, concurrency=3, send_batch_size=1000
    )

    # The worker error propagated (so the caller will stash-and-retry)...
    assert isinstance(exc, RuntimeError)
    # ...but the sibling batches that were already popped off the queue survived in the returned unsent list.
    preserved_ids = {event["id"] for event in unsent}
    assert "sibling-a" in preserved_ids
    assert "sibling-b" in preserved_ids
    assert fetched == 2  # both sibling batches were counted as fetched, not dropped


# ---------------------------------------------------------------------------
# handle_fetch_events - fetch-events orchestration (extracted from main for coverage)
# ---------------------------------------------------------------------------


def _patch_fetch_result(mocker, *, fetched=0, sent=0, queue_drained=True, unsent=None, exception=None):
    """Patch fetch_and_send_events_concurrently to return a canned result tuple."""
    return mocker.patch.object(
        SaasSecurityEventCollector,
        "fetch_and_send_events_concurrently",
        return_value=(fetched, sent, queue_drained, unsent or [], exception),
    )


def test_handle_fetch_events_clean_drain_clears_backlog_state(mocker):
    """
    Given a fully drained queue and a prior backlog carried in last_run,
    when handling fetch-events,
    then nextTrigger and consecutive_backlog_cycles are cleared and the stash is emptied.
    """
    demisto_mock = mocker.patch.object(SaasSecurityEventCollector, "demisto")
    demisto_mock.getLastRun.return_value = {"nextTrigger": "1", "consecutive_backlog_cycles": 7}
    demisto_mock.getIntegrationContext.return_value = {}
    _patch_fetch_result(mocker, fetched=100, sent=100, queue_drained=True)

    last_run = SaasSecurityEventCollector.handle_fetch_events(
        params=BASE_PARAMS, max_iterations=900, concurrency=10, pass_over_empty_response=True
    )

    assert "nextTrigger" not in last_run
    assert "consecutive_backlog_cycles" not in last_run
    demisto_mock.setIntegrationContext.assert_called_once_with({})


def test_handle_fetch_events_backlog_sets_next_trigger_and_increments_counter(mocker):
    """
    Given a queue that did not drain (backlog) with no prior backlog state,
    when handling fetch-events,
    then nextTrigger is set and consecutive_backlog_cycles is incremented to 1.
    """
    demisto_mock = mocker.patch.object(SaasSecurityEventCollector, "demisto")
    demisto_mock.getLastRun.return_value = {}
    demisto_mock.getIntegrationContext.return_value = {}
    _patch_fetch_result(mocker, fetched=5000, sent=5000, queue_drained=False)

    last_run = SaasSecurityEventCollector.handle_fetch_events(
        params=BASE_PARAMS, max_iterations=900, concurrency=10, pass_over_empty_response=True
    )

    assert last_run["nextTrigger"] == SaasSecurityEventCollector.NEXT_TRIGGER_VALUE
    assert last_run["consecutive_backlog_cycles"] == 1


def test_handle_fetch_events_backlog_counter_accumulates(mocker):
    """
    Given a backlog and a prior consecutive_backlog_cycles in last_run,
    when handling fetch-events,
    then the counter is incremented (accumulates across back-to-back cycles).
    """
    demisto_mock = mocker.patch.object(SaasSecurityEventCollector, "demisto")
    demisto_mock.getLastRun.return_value = {"consecutive_backlog_cycles": 3}
    demisto_mock.getIntegrationContext.return_value = {}
    _patch_fetch_result(mocker, queue_drained=False)

    last_run = SaasSecurityEventCollector.handle_fetch_events(
        params=BASE_PARAMS, max_iterations=900, concurrency=10, pass_over_empty_response=True
    )

    assert last_run["consecutive_backlog_cycles"] == 4


@pytest.mark.parametrize(
    "prior_cycles, expect_warning",
    [
        (SaasSecurityEventCollector.BACKLOG_WARNING_THRESHOLD - 2, False),  # below threshold -> silent
        (SaasSecurityEventCollector.BACKLOG_WARNING_THRESHOLD - 1, True),  # reaches threshold -> warn
        (SaasSecurityEventCollector.BACKLOG_WARNING_THRESHOLD, False),  # one past threshold -> silent
        (
            SaasSecurityEventCollector.BACKLOG_WARNING_THRESHOLD + SaasSecurityEventCollector.BACKLOG_WARNING_INTERVAL - 1,
            True,
        ),  # exactly one interval later -> re-warn
    ],
)
def test_handle_fetch_events_backlog_warning_threshold_and_interval(mocker, prior_cycles, expect_warning):
    """
    Given a sustained backlog, when handling fetch-events,
    then demisto.error (the high-visibility backlog warning) fires exactly at BACKLOG_WARNING_THRESHOLD and
    then only every BACKLOG_WARNING_INTERVAL cycles, and stays silent otherwise (no log flooding).
    """
    demisto_mock = mocker.patch.object(SaasSecurityEventCollector, "demisto")
    demisto_mock.getLastRun.return_value = {"consecutive_backlog_cycles": prior_cycles}
    demisto_mock.getIntegrationContext.return_value = {}
    _patch_fetch_result(mocker, queue_drained=False)

    SaasSecurityEventCollector.handle_fetch_events(
        params=BASE_PARAMS, max_iterations=900, concurrency=10, pass_over_empty_response=True
    )

    backlog_warning_emitted = any(
        "ingestion backlog" in str(call.args[0]) for call in demisto_mock.error.call_args_list if call.args
    )
    assert backlog_warning_emitted is expect_warning


def test_handle_fetch_events_send_failure_stashes_unsent_and_forces_retry(mocker):
    """
    Given a send failure mid-drain that returns unsent events,
    when handling fetch-events,
    then the unsent events are persisted via setIntegrationContext and an immediate retry is forced
    (nextTrigger set), even though the concurrent drain reported queue_drained=True.
    """
    demisto_mock = mocker.patch.object(SaasSecurityEventCollector, "demisto")
    demisto_mock.getLastRun.return_value = {}
    demisto_mock.getIntegrationContext.return_value = {}
    unsent = [{"id": i} for i in range(500)]
    _patch_fetch_result(mocker, fetched=2500, sent=2000, queue_drained=True, unsent=unsent, exception=ValueError("send failed"))

    last_run = SaasSecurityEventCollector.handle_fetch_events(
        params=BASE_PARAMS, max_iterations=900, concurrency=10, pass_over_empty_response=True
    )

    demisto_mock.setIntegrationContext.assert_called_once_with({"events": unsent})
    assert last_run["nextTrigger"] == SaasSecurityEventCollector.NEXT_TRIGGER_VALUE
    assert last_run["consecutive_backlog_cycles"] == 1


def test_handle_fetch_events_stash_flushed_first_and_shrinks_next_cycle(mocker):
    """
    Given a stash of unsent events persisted from a prior failed cycle,
    when the next fetch-events cycle runs,
    then the stash is passed to the drain as pending_events (flushed first) and, on partial success, the
    re-stashed remainder is strictly smaller than the original stash (self-heals over cycles).
    """
    demisto_mock = mocker.patch.object(SaasSecurityEventCollector, "demisto")
    original_stash = [{"id": i} for i in range(1000)]
    demisto_mock.getLastRun.return_value = {}
    demisto_mock.getIntegrationContext.return_value = {"events": original_stash}

    # The drain flushes part of the stash, then fails again leaving a smaller remainder.
    shrunk_remainder = [{"id": i} for i in range(400)]
    fetch_mock = _patch_fetch_result(
        mocker, fetched=1000, sent=600, queue_drained=True, unsent=shrunk_remainder, exception=ValueError("boom")
    )

    SaasSecurityEventCollector.handle_fetch_events(
        params=BASE_PARAMS, max_iterations=900, concurrency=10, pass_over_empty_response=True
    )

    # The prior stash was handed to the drain to be flushed first.
    assert fetch_mock.call_args.kwargs["pending_events"] == original_stash
    # The re-stashed remainder shrank -> the stash self-heals instead of replaying forever.
    persisted = demisto_mock.setIntegrationContext.call_args.args[0]
    assert 0 < len(persisted["events"]) < len(original_stash)


# ---------------------------------------------------------------------------
# get_max_fetch (unchanged behavior, kept for coverage)
# ---------------------------------------------------------------------------


def test_get_max_fetch_default():
    assert SaasSecurityEventCollector.get_max_fetch(None) == 1000


def test_get_max_fetch_clamped_and_rounded():
    assert SaasSecurityEventCollector.get_max_fetch(99999) == 5000  # clamp to MAX_LIMIT
    assert SaasSecurityEventCollector.get_max_fetch(105) == 100  # round down to multiple of 10


def test_get_max_fetch_negative_number():
    with pytest.raises(DemistoException):
        SaasSecurityEventCollector.get_max_fetch(-1)
