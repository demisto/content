from CommonServerPython import *
from RecordedFutureEventCollector import BASE_URL, DATE_FORMAT
from freezegun import freeze_time
import requests_mock
import pytest

""" HELPER FUNCTIONS """


def util_load_json(path):
    with open(path, encoding="utf-8") as f:
        return json.loads(f.read())


def mock_set_last_run(last_run):
    return last_run


def mock_send_events_to_xsiam(events, vendor, product):
    return events, vendor, product


@pytest.fixture(autouse=True)
def disable_seconds_probe(mocker):
    """The seconds probe makes extra API calls; tests that need it enable it explicitly."""
    mocker.patch("RecordedFutureEventCollector.DEBUG_PROBE_SECONDS", False)


""" TEST FUNCTIONS """


def test_module_succeed(mocker):
    from RecordedFutureEventCollector import Client, test_module

    client = Client(BASE_URL)
    mock_results = mocker.patch("RecordedFutureEventCollector.return_results")

    with requests_mock.Mocker() as m:
        m.get(f"{BASE_URL}/config/info", status_code=200, text='{"name": "admin"}')
        test_module(client)

    assert mock_results.call_args[0][0] == "ok"


def test_module_failed():
    from RecordedFutureEventCollector import Client, test_module

    client = Client(BASE_URL)

    with requests_mock.Mocker() as m:
        m.get(f"{BASE_URL}/config/info", status_code=401, text='{"error":{"status":401}}')
        with pytest.raises(DemistoException) as e:
            test_module(client)

    assert e.value.message == 'Failed due to - Error in API call [401] - None\n{"error": {"status": 401}}'


def test_get_events():
    from RecordedFutureEventCollector import Client, get_events

    client = Client(BASE_URL)

    with requests_mock.Mocker() as m:
        m.get(f"{BASE_URL}/alert/search", json=util_load_json("test_data/first_fetch.json"))

        mock_events = get_events(client, {"limit": 2})

    assert len(mock_events) == 2


@freeze_time("2023-12-24T01:02:03.000Z")
def test_fetch_events(mocker):
    from RecordedFutureEventCollector import Client, fetch_events, demisto

    client = Client(BASE_URL)

    with requests_mock.Mocker() as m:
        first_mock_request = m.get(f"{BASE_URL}/alert/search", json=util_load_json("test_data/first_fetch.json"))

        mock_events, next_last_run = fetch_events(client, limit=2, last_run=arg_to_datetime("3 days").strftime(DATE_FORMAT))

    assert len(mock_events) == 2
    assert next_last_run["last_run_ids"] == ["a12b-5"]
    assert next_last_run["last_run_time"] == "2023-12-23T00:00:10"
    assert first_mock_request.last_request.qs.get("triggered")[0].upper() == "[2023-12-21T01:02:03.000000Z,]"

    mocker.patch.object(demisto, "getLastRun", return_value=next_last_run)
    last_run_time = next_last_run.get("last_run_time")

    with requests_mock.Mocker() as m:
        second_mock_request = m.get(f"{BASE_URL}/alert/search", json=util_load_json("test_data/second_fetch.json"))

        mock_events, next_last_run = fetch_events(client, limit=2, last_run=last_run_time)

    assert len(mock_events) == 1
    assert next_last_run["last_run_ids"] == ["a12b-8"]
    assert next_last_run["last_run_time"] == "2023-12-23T00:10:20"
    assert second_mock_request.last_request.qs.get("triggered")[0].upper() == "[2023-12-23T00:00:10,]"


def make_event(event_id: str, triggered: str) -> dict:
    return {"id": event_id, "log": {"triggered": triggered}}


ASC_EVENTS = [
    make_event("a", "2026-11-06T03:00:01.000Z"),
    make_event("b", "2026-11-06T03:00:05.000Z"),
    make_event("c", "2026-11-06T03:00:09.000Z"),
]


@pytest.mark.parametrize(
    "cursor_mode, expected",
    [
        ("legacy", {"last_run_time": "2026-11-06T03:00:01", "last_run_ids": ["a"]}),
        ("newest", {"last_run_time": "2026-11-06T03:00:09", "last_run_ids": ["c"]}),
    ],
)
def test_compute_next_run_asc_response(cursor_mode, expected):
    """
    Given: An API response sorted ascending by triggered (as requested with direction=asc).
    When: Computing the next run.
    Then: legacy mode takes the oldest event (the XSUP-80326 suspect), newest mode takes the latest one.
    """
    from RecordedFutureEventCollector import compute_next_run

    assert compute_next_run(ASC_EVENTS, limit=1000, cursor_mode=cursor_mode) == expected


def test_compute_next_run_empty():
    from RecordedFutureEventCollector import compute_next_run

    assert compute_next_run([], limit=1000, cursor_mode="newest") == {}


@pytest.mark.parametrize(
    "events, expected",
    [
        (ASC_EVENTS, "asc"),
        (list(reversed(ASC_EVENTS)), "desc"),
        ([ASC_EVENTS[1], ASC_EVENTS[0], ASC_EVENTS[2]], "unsorted"),
        (ASC_EVENTS[:1], "n/a"),
    ],
)
def test_get_response_order(events, expected):
    from RecordedFutureEventCollector import get_response_order

    assert get_response_order(events) == expected


def test_fetch_events_logs_overlap_with_previous_run(mocker):
    """
    Given: A previous run that already sent events a, b, c and stored the oldest one as the cursor (legacy behaviour).
    When: The API returns the same window again.
    Then: The debug print reports that b and c are being re-sent.
    """
    from RecordedFutureEventCollector import Client, fetch_events

    info = mocker.patch.object(demisto, "info")
    previous_last_run = {"last_run_time": "2026-11-06T03:00:01", "last_run_ids": ["a"], "debug_sent_ids": ["a", "b", "c"]}

    with requests_mock.Mocker() as m:
        m.get(f"{BASE_URL}/alert/search", json={"data": ASC_EVENTS, "counts": {"returned": 3, "total": 3}})
        events, next_run = fetch_events(
            Client(BASE_URL), limit=1000, last_run="2026-11-06T03:00:01", previous_last_run=previous_last_run
        )

    assert [event["id"] for event in events] == ["b", "c"]
    assert next_run["debug_sent_ids"] == ["b", "c"]
    logged = "\n".join(str(call.args[0]) for call in info.call_args_list)
    assert "overlap with previous run: 2 of 2 events were already sent by the previous run" in logged
    assert "response order by log.triggered: asc" in logged


def test_fetch_events_newest_mode_advances_cursor():
    """
    Given: cursor_mode=newest.
    When: Two consecutive rounds where the API returns everything after the cursor (inclusive).
    Then: The second round sends only new events (no re-sends).
    """
    from RecordedFutureEventCollector import Client, fetch_events

    client = Client(BASE_URL)
    with requests_mock.Mocker() as m:
        m.get(f"{BASE_URL}/alert/search", json={"data": ASC_EVENTS})
        first_events, first_next_run = fetch_events(
            client, limit=1000, last_run="2026-11-06T03:00:00", cursor_mode="newest", previous_last_run={}
        )

    second_page = [ASC_EVENTS[2], make_event("d", "2026-11-06T03:00:20.000Z")]
    with requests_mock.Mocker() as m:
        request = m.get(f"{BASE_URL}/alert/search", json={"data": second_page})
        second_events, _ = fetch_events(
            client,
            limit=1000,
            last_run=first_next_run["last_run_time"],
            cursor_mode="newest",
            previous_last_run=first_next_run,
        )

    assert [event["id"] for event in first_events] == ["a", "b", "c"]
    assert request.last_request.qs.get("triggered")[0].upper() == "[2026-11-06T03:00:09,]"
    assert [event["id"] for event in second_events] == ["d"]


def run_fetch_events_main(mocker, integration_context: dict, stored_last_run: dict):
    """Runs main() as fetch-events with a mocked API, integration context and last run. Returns (request, setLastRun mock)."""
    from RecordedFutureEventCollector import main

    mocker.patch("RecordedFutureEventCollector.get_integration_context", side_effect=lambda: dict(integration_context))
    mocker.patch(
        "RecordedFutureEventCollector.set_integration_context",
        side_effect=lambda ctx: (integration_context.clear(), integration_context.update(ctx)),
    )
    mocker.patch.object(demisto, "params", return_value={"credentials": {"password": "x"}, "max_fetch": "1000"})
    mocker.patch.object(demisto, "command", return_value="fetch-events")
    mocker.patch.object(demisto, "args", return_value={})
    mocker.patch.object(demisto, "getLastRun", return_value=stored_last_run)
    set_last_run = mocker.patch.object(demisto, "setLastRun")
    mocker.patch("RecordedFutureEventCollector.send_events_to_xsiam")
    with requests_mock.Mocker() as m:
        request = m.get(f"{BASE_URL}/alert/search", json={"data": ASC_EVENTS})
        main()
    return request, set_last_run


def test_force_start_time_applied_once(mocker):
    """
    Given: DEBUG_FORCE_START_TIME set in the code.
    When: fetch-events runs twice.
    Then: The first run starts from the forced time and saves its own result as the last run;
        the second run ignores the forced time and continues from the stored last run.
    """
    import RecordedFutureEventCollector

    mocker.patch.object(RecordedFutureEventCollector, "DEBUG_FORCE_START_TIME", "2026-11-03T00:00:00Z")
    integration_context: dict = {}
    stored_last_run = {"last_run_time": "2026-11-06T03:00:01", "last_run_ids": ["a"]}

    request, set_last_run = run_fetch_events_main(mocker, integration_context, stored_last_run)
    assert request.last_request.qs.get("triggered")[0].upper() == "[2026-11-03T00:00:00.000000Z,]"
    assert set_last_run.call_args[0][0]["last_run_time"] == "2026-11-06T03:00:01"
    assert integration_context[RecordedFutureEventCollector.APPLIED_FORCE_START_CONTEXT_KEY] == "2026-11-03T00:00:00Z"

    request, _ = run_fetch_events_main(mocker, integration_context, set_last_run.call_args[0][0])
    assert request.last_request.qs.get("triggered")[0].upper() == "[2026-11-06T03:00:01,]"


def test_fetch_events_uses_debug_cursor_mode(mocker):
    """
    Given: DEBUG_CURSOR_MODE=newest set in the code (no customer configuration involved).
    When: fetch-events runs.
    Then: The saved last run uses the newest event.
    """
    import RecordedFutureEventCollector

    mocker.patch.object(RecordedFutureEventCollector, "DEBUG_CURSOR_MODE", "newest")
    _, set_last_run = run_fetch_events_main(mocker, {}, {"last_run_time": "2026-11-06T03:00:00", "last_run_ids": []})
    assert set_last_run.call_args[0][0]["last_run_time"] == "2026-11-06T03:00:09"


def test_fetch_events_default_is_legacy(mocker):
    """
    Given: The default debug controls (legacy mode, no forced start).
    When: fetch-events runs.
    Then: The behaviour matches the original code (cursor from events[0]).
    """
    _, set_last_run = run_fetch_events_main(mocker, {}, {"last_run_time": "2026-11-06T03:00:00", "last_run_ids": []})
    assert set_last_run.call_args[0][0]["last_run_time"] == "2026-11-06T03:00:01"


def fake_api_honouring_seconds(all_events: list):
    """requests_mock callback that filters all_events by triggered=[start,end] at second precision (like a real API)."""

    def callback(request, context):
        start, end = request.qs["triggered"][0].upper().strip("[]").split(",")
        start, end = start[:19], end[:19]
        matched = [
            event
            for event in all_events
            if (not start or event["log"]["triggered"][:19] >= start) and (not end or event["log"]["triggered"][:19] <= end)
        ]
        return {"data": matched, "counts": {"returned": len(matched), "total": len(matched)}}

    return callback


def test_seconds_probe_api_honours_seconds(mocker):
    """
    Given: An API that honours second precision for both start and end of the triggered filter.
    When: The seconds probe runs.
    Then: The verdict reports start and end are honoured, and the probe uses the oldest second of the response.
    """
    from RecordedFutureEventCollector import Client, run_seconds_probe

    all_events = [*ASC_EVENTS, make_event("late", "2026-11-06T03:05:00.000Z")]
    with requests_mock.Mocker() as m:
        request = m.get(f"{BASE_URL}/alert/search", json=fake_api_honouring_seconds(all_events))
        verdict = run_seconds_probe(Client(BASE_URL), ASC_EVENTS)

    filters = [req.qs["triggered"][0].upper() for req in request.request_history]
    assert filters[:2] == ["[2026-11-06T03:00:01,2026-11-06T03:00:11]", "[2026-11-06T03:00:02,2026-11-06T03:00:11]"]
    assert verdict == {
        "start_includes_anchor_second": True,
        "start_honours_seconds": True,
        "end_bound_honoured": True,
        "hit_response_cap": False,
    }


def test_seconds_probe_api_ignores_seconds():
    """
    Given: An API that ignores the filter and always returns the same events (including one outside the window).
    When: The seconds probe runs.
    Then: The verdict reports that second precision and the end bound are not honoured.
    """
    from RecordedFutureEventCollector import Client, run_seconds_probe

    response = {"data": [*ASC_EVENTS, make_event("late", "2026-11-06T03:05:00.000Z")]}
    with requests_mock.Mocker() as m:
        m.get(f"{BASE_URL}/alert/search", json=response)
        verdict = run_seconds_probe(Client(BASE_URL), ASC_EVENTS)

    assert verdict["start_honours_seconds"] is False
    assert verdict["end_bound_honoured"] is False


def test_seconds_probe_does_not_change_fetch_result(mocker):
    """
    Given: DEBUG_PROBE_SECONDS enabled.
    When: fetch_events runs.
    Then: The events and next run are the same as without the probe, and the verdict is logged.
    """
    import RecordedFutureEventCollector
    from RecordedFutureEventCollector import Client, fetch_events

    info = mocker.patch.object(demisto, "info")
    kwargs = {"limit": 1000, "last_run": "2026-11-06T03:00:00", "previous_last_run": {}}
    with requests_mock.Mocker() as m:
        m.get(f"{BASE_URL}/alert/search", json=fake_api_honouring_seconds(ASC_EVENTS))
        without_probe = fetch_events(Client(BASE_URL), **kwargs)
        mocker.patch.object(RecordedFutureEventCollector, "DEBUG_PROBE_SECONDS", True)
        with_probe = fetch_events(Client(BASE_URL), **kwargs)

    assert with_probe == without_probe
    assert "seconds probe verdict" in "\n".join(str(call.args[0]) for call in info.call_args_list)


def test_seconds_probe_failure_does_not_break_fetch(mocker):
    """
    Given: DEBUG_PROBE_SECONDS enabled and the probe requests fail.
    When: fetch_events runs.
    Then: The fetch still returns its events and the verdict is inconclusive.
    """
    import RecordedFutureEventCollector
    from RecordedFutureEventCollector import Client, fetch_events

    mocker.patch.object(RecordedFutureEventCollector, "DEBUG_PROBE_SECONDS", True)
    client = Client(BASE_URL)

    def get_alerts(params: dict) -> dict:
        if params["triggered"].endswith(",]"):  # the fetch request has an open end; probes always have an end bound
            return {"data": ASC_EVENTS}
        raise DemistoException("boom")

    mocker.patch.object(client, "get_alerts", side_effect=get_alerts)
    probe = mocker.spy(RecordedFutureEventCollector, "evaluate_seconds_probe")
    events, _ = fetch_events(client, limit=1000, last_run="2026-11-06T03:00:00", previous_last_run={})

    assert len(events) == 3
    assert probe.spy_return == {"result": "inconclusive", "reason": "probe request failed (see probe lines)"}


@pytest.mark.parametrize(
    "args, expected",
    [
        ({"limit": 5}, {"limit": 5}),
        (
            {"limit": 5, "start_time": "2026-11-09T00:00:00Z", "end_time": "2026-11-09T23:59:59Z"},
            {"limit": 5, "triggered": "[2026-11-09T00:00:00,2026-11-09T23:59:59]", "orderby": "triggered", "direction": "asc"},
        ),
        (
            {"start_time": "2026-11-09T00:00:00.123Z"},
            {"limit": 10, "triggered": "[2026-11-09T00:00:00,]", "orderby": "triggered", "direction": "asc"},
        ),
        (
            {"end_time": "2026-11-09T12:00:00Z"},
            {"limit": 10, "triggered": "[,2026-11-09T12:00:00]", "orderby": "triggered", "direction": "asc"},
        ),
    ],
)
def test_build_get_events_params(args, expected):
    from RecordedFutureEventCollector import build_get_events_params

    assert build_get_events_params(args) == expected


def test_get_events_command_with_time_range_shows_api_counts(mocker):
    """
    Given: recorded-future-get-events with start_time and end_time.
    When: The command runs.
    Then: The request carries triggered=[start,end] and the output shows the API counts (total/returned).
    """
    from RecordedFutureEventCollector import main

    mocker.patch.object(demisto, "command", return_value="recorded-future-get-events")
    mocker.patch.object(
        demisto,
        "args",
        return_value={"should_push_events": "false", "start_time": "2026-11-09T00:00:00Z", "end_time": "2026-11-09T23:59:59Z"},
    )
    results = mocker.patch("RecordedFutureEventCollector.return_results")
    with requests_mock.Mocker() as m:
        request = m.get(f"{BASE_URL}/alert/search", json={"data": ASC_EVENTS, "counts": {"returned": 3, "total": 1291}})
        main()

    assert request.last_request.qs["triggered"][0].upper() == "[2026-11-09T00:00:00,2026-11-09T23:59:59]"
    readable = results.call_args[0][0].readable_output
    assert "total=1291 returned=3" in readable


def test_main(mocker):
    from RecordedFutureEventCollector import main, VENDOR, PRODUCT

    mocker.patch.object(demisto, "command", return_value="recorded-future-get-events")
    mocker.patch.object(demisto, "args", return_value={"should_push_events": True, "limit": 2})
    events = mocker.patch("RecordedFutureEventCollector.send_events_to_xsiam", side_effect=mock_send_events_to_xsiam)

    with requests_mock.Mocker() as m:
        mock_request = m.get(f"{BASE_URL}/alert/search", json=util_load_json("test_data/first_fetch.json"))

        main()

    assert len(events.call_args[0][0]) == 2
    event = events.call_args[0][0][0]
    assert event.get("_time") == event.get("log", {}).get("triggered")
    assert events.call_args[1].get("vendor") == VENDOR
    assert events.call_args[1].get("product") == PRODUCT
    assert mock_request.last_request.query == "limit=2"
