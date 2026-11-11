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
    assert [event["id"] for event in mock_events] == ["a12b-6", "a12b-5"]  # sorted oldest first
    assert next_last_run == {"last_run_ids": ["a12b-5"], "last_run_time": "2023-12-23T00:00:10"}
    assert first_mock_request.call_count == 1
    query = first_mock_request.last_request.qs
    assert query.get("triggered")[0].upper() == "[2023-12-21T01:02:03.000000Z,]"
    assert query.get("direction") == ["desc"]
    assert query.get("orderby") == ["triggered"]
    assert query.get("limit") == ["2"]
    assert query.get("from") == ["0"]

    mocker.patch.object(demisto, "getLastRun", return_value=next_last_run)
    last_run_time = next_last_run.get("last_run_time")

    with requests_mock.Mocker() as m:
        second_mock_request = m.get(f"{BASE_URL}/alert/search", json=util_load_json("test_data/second_fetch.json"))

        mock_events, next_last_run = fetch_events(client, limit=2, last_run=last_run_time)

    assert len(mock_events) == 1
    assert next_last_run == {"last_run_ids": ["a12b-8"], "last_run_time": "2023-12-23T00:10:20"}
    assert second_mock_request.last_request.qs.get("triggered")[0].upper() == "[2023-12-23T00:00:10,]"


def make_alert(alert_id: str, triggered: str) -> dict:
    return {"id": alert_id, "log": {"triggered": triggered}}


def make_page(alerts: list) -> dict:
    return {"json": {"data": alerts, "counts": {"returned": len(alerts), "total": len(alerts)}}}


def test_fetch_events_pages_with_from(mocker):
    """
    Given: More alerts than a single page (the API caps every response at 50).
    When: Fetching with a limit of 120.
    Then: Pages are requested with from=0/50/100 and limits 50/50/20, all events are returned oldest first,
          and the cursor is the latest trigger time.
    """
    from RecordedFutureEventCollector import Client, fetch_events, demisto

    mocker.patch.object(demisto, "getLastRun", return_value={})
    alerts = [make_alert(f"id-{i}", f"2026-11-10T10:{i // 60:02d}:{i % 60:02d}.123Z") for i in range(120)]
    # With direction=desc each page holds the oldest alerts after the cursor, displayed newest first.
    pages = [make_page(list(reversed(alerts[i : i + 50]))) for i in range(0, 120, 50)]

    with requests_mock.Mocker() as m:
        mock_request = m.get(f"{BASE_URL}/alert/search", pages)
        events, next_run = fetch_events(Client(BASE_URL), limit=120, last_run="2026-11-10T10:00:00")

    assert [(r.qs["from"][0], r.qs["limit"][0]) for r in mock_request.request_history] == [
        ("0", "50"),
        ("50", "50"),
        ("100", "20"),
    ]
    assert [event["id"] for event in events] == [alert["id"] for alert in alerts]
    assert next_run == {"last_run_time": "2026-11-10T10:01:59", "last_run_ids": ["id-119"]}


def test_fetch_events_stops_on_short_page(mocker):
    """
    Given: Fewer alerts available than the limit.
    When: Fetching.
    Then: Paging stops after the first short page.
    """
    from RecordedFutureEventCollector import Client, fetch_events, demisto

    mocker.patch.object(demisto, "getLastRun", return_value={})
    with requests_mock.Mocker() as m:
        mock_request = m.get(f"{BASE_URL}/alert/search", **make_page([make_alert("a", "2026-11-10T10:00:01.000Z")]))
        events, _ = fetch_events(Client(BASE_URL), limit=1000, last_run="2026-11-10T10:00:00")

    assert mock_request.call_count == 1
    assert len(events) == 1


def test_fetch_events_dedupes_last_run_and_pages(mocker):
    """
    Given: The previous fetch saved IDs at the cursor second, and an alert repeats across pages.
    When: Fetching.
    Then: Previously fetched and duplicate alerts are dropped, and since the cursor did not move,
          the previous IDs are kept so they are still filtered next time.
    """
    from RecordedFutureEventCollector import Client, fetch_events, demisto, PAGE_SIZE

    mocker.patch.object(demisto, "getLastRun", return_value={"last_run_ids": ["old"]})
    first_page = [make_alert("old", "2026-11-10T10:00:00.100Z")] + [
        make_alert(f"n-{i}", "2026-11-10T10:00:00.500Z") for i in range(PAGE_SIZE - 1)
    ]
    second_page = [make_alert("n-0", "2026-11-10T10:00:00.500Z")]

    with requests_mock.Mocker() as m:
        m.get(f"{BASE_URL}/alert/search", [make_page(first_page), make_page(second_page)])
        events, next_run = fetch_events(Client(BASE_URL), limit=1000, last_run="2026-11-10T10:00:00")

    assert len(events) == PAGE_SIZE - 1
    assert "old" not in [event["id"] for event in events]
    assert next_run["last_run_time"] == "2026-11-10T10:00:00"
    assert set(next_run["last_run_ids"]) == {"old"} | {f"n-{i}" for i in range(PAGE_SIZE - 1)}


def test_fetch_events_stuck_guard(mocker):
    """
    Given: The limit is reached and all fetched alerts were triggered at the same second.
    When: Fetching.
    Then: The cursor is moved forward by one second so the fetch does not get stuck.
    """
    from RecordedFutureEventCollector import Client, fetch_events, demisto

    mocker.patch.object(demisto, "getLastRun", return_value={})
    alerts = [make_alert(f"s-{i}", "2026-11-10T10:00:05.000Z") for i in range(2)]
    with requests_mock.Mocker() as m:
        m.get(f"{BASE_URL}/alert/search", **make_page(alerts))
        events, next_run = fetch_events(Client(BASE_URL), limit=2, last_run="2026-11-10T10:00:00")

    assert len(events) == 2
    assert next_run["last_run_time"] == "2026-11-10T10:00:06"


def test_fetch_events_limit_capped(mocker):
    """
    Given: A limit above the maximum.
    When: Fetching.
    Then: At most MAX_FETCH alerts are requested.
    """
    from RecordedFutureEventCollector import Client, fetch_events, demisto, MAX_FETCH, PAGE_SIZE

    mocker.patch.object(demisto, "getLastRun", return_value={})
    counter = iter(range(10**6))

    def full_page(request, context):
        return {"data": [make_alert(f"c-{next(counter)}", "2026-11-10T10:00:01.000Z") for _ in range(PAGE_SIZE)]}

    with requests_mock.Mocker() as m:
        mock_request = m.get(f"{BASE_URL}/alert/search", json=full_page)
        events, _ = fetch_events(Client(BASE_URL), limit=5000, last_run="2026-11-10T10:00:00")

    assert mock_request.call_count == MAX_FETCH // PAGE_SIZE
    assert len(events) == MAX_FETCH


def test_fetch_events_no_alerts(mocker):
    """
    Given: No new alerts.
    When: Fetching.
    Then: No events and an empty next run (the last run is kept as is).
    """
    from RecordedFutureEventCollector import Client, fetch_events, demisto

    mocker.patch.object(demisto, "getLastRun", return_value={})
    with requests_mock.Mocker() as m:
        m.get(f"{BASE_URL}/alert/search", json={"data": [], "counts": {"returned": 0, "total": 0}})
        events, next_run = fetch_events(Client(BASE_URL), limit=10, last_run="2026-11-10T10:00:00")

    assert events == []
    assert next_run == {}


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
