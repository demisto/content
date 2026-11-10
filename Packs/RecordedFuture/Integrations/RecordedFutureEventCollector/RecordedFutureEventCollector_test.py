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


def test_set_fetch_start_override_applied_once(mocker):
    """
    Given: A start-time override set via recorded-future-debug-set-fetch-start.
    When: fetch-events runs.
    Then: The request starts from the override, the last run is overwritten by the fetch result, and the override is cleared.
    """
    from RecordedFutureEventCollector import OVERRIDE_CONTEXT_KEY, main

    integration_context: dict = {}
    mocker.patch("RecordedFutureEventCollector.get_integration_context", side_effect=lambda: dict(integration_context))
    mocker.patch(
        "RecordedFutureEventCollector.set_integration_context",
        side_effect=lambda ctx: (integration_context.clear(), integration_context.update(ctx)),
    )
    mocker.patch.object(demisto, "params", return_value={"credentials": {"password": "x"}, "max_fetch": "1000"})

    mocker.patch.object(demisto, "command", return_value="recorded-future-debug-set-fetch-start")
    mocker.patch.object(demisto, "args", return_value={"start_time": "2026-11-03T00:00:00Z"})
    mocker.patch("RecordedFutureEventCollector.return_results")
    main()
    assert integration_context[OVERRIDE_CONTEXT_KEY] == "2026-11-03T00:00:00.000000Z"

    mocker.patch.object(demisto, "command", return_value="fetch-events")
    mocker.patch.object(demisto, "args", return_value={})
    mocker.patch.object(demisto, "getLastRun", return_value={"last_run_time": "2026-11-06T03:00:01", "last_run_ids": ["a"]})
    set_last_run = mocker.patch.object(demisto, "setLastRun")
    mocker.patch("RecordedFutureEventCollector.send_events_to_xsiam")
    with requests_mock.Mocker() as m:
        request = m.get(f"{BASE_URL}/alert/search", json={"data": ASC_EVENTS})
        main()

    assert request.last_request.qs.get("triggered")[0].upper() == "[2026-11-03T00:00:00.000000Z,]"
    assert set_last_run.call_args[0][0]["last_run_time"] == "2026-11-06T03:00:01"
    assert OVERRIDE_CONTEXT_KEY not in integration_context


def test_debug_fetch_is_dry_run(mocker):
    """
    Given: The recorded-future-debug-fetch command.
    When: It runs.
    Then: No events are sent and the last run is not changed, and both cursor modes are reported.
    """
    from RecordedFutureEventCollector import Client, debug_fetch_command

    mocker.patch.object(demisto, "getLastRun", return_value={"last_run_time": "2026-11-06T03:00:01", "last_run_ids": ["a"]})
    set_last_run = mocker.patch.object(demisto, "setLastRun")
    send = mocker.patch("RecordedFutureEventCollector.send_events_to_xsiam")

    with requests_mock.Mocker() as m:
        request = m.get(f"{BASE_URL}/alert/search", json={"data": ASC_EVENTS})
        result = debug_fetch_command(Client(BASE_URL), {}, {"max_fetch": "1000"})

    assert request.last_request.qs.get("triggered")[0].upper() == "[2026-11-06T03:00:01,]"
    assert result.outputs["NextRunLegacy"]["last_run_time"] == "2026-11-06T03:00:01"
    assert result.outputs["NextRunNewest"]["last_run_time"] == "2026-11-06T03:00:09"
    assert result.outputs["Events"][0]["in_last_run_ids"] is True
    set_last_run.assert_not_called()
    send.assert_not_called()


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
