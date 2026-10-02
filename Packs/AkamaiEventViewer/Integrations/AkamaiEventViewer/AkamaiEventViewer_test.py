import json
from datetime import datetime, UTC
from urllib.parse import parse_qs, urlparse

import pytest
from CommonServerPython import DemistoException

import AkamaiEventViewer
from AkamaiEventViewer import (
    Client,
    build_client,
    collect_events,
    fetch_events,
    fetch_events_command,
    get_events_command,
    get_next_cursor,
    parse_limit,
    resolve_event_type_ids,
)

HOST = "https://akaa-test.luna.akamaiapis.net"
EVENTS_URL = f"{HOST}/event-viewer-api/v1/events"
EVENT_TYPES_URL = f"{HOST}/event-viewer-api/v1/event-types"
NOW = datetime(2026, 7, 14, 11, 38, 0, tzinfo=UTC)
PARAMS = {
    "host": HOST,
    "clienttoken_creds": {"password": "client-token"},
    "accesstoken_creds": {"password": "access-token"},
    "clientsecret_creds": {"password": "client-secret"},
}


def load_json(name: str):
    with open(f"test_data/{name}", encoding="utf-8") as f:
        return json.load(f)


def make_event(event_id: str, event_time: str = "2026-07-14T11:37:30.000Z") -> dict:
    return {"eventId": event_id, "eventTime": event_time, "eventType": {"eventTypeId": "16", "eventTypeName": "All Logins"}}


def make_page(event_ids: list[str], next_cursor: str | None = None, event_time: str = "2026-07-14T11:37:30.000Z") -> dict:
    links = [{"rel": "self", "href": "/event-viewer-api/v1/events"}]
    if next_cursor:
        links.append({"rel": "next", "href": f"/event-viewer-api/v1/events?beforeEventId={next_cursor}"})
    return {"events": [make_event(event_id, event_time) for event_id in event_ids], "links": links}


@pytest.fixture
def client() -> Client:
    return build_client(PARAMS)


def query(request) -> dict:
    """Case-preserving query params (requests_mock's request.qs lowercases values)."""
    return {key: values[0] for key, values in parse_qs(urlparse(request.url).query).items()}


def test_build_client_base_url_and_account_switch_key(requests_mock):
    """
    Given: Instance params with an account switch key.
    When: Building the client and calling the events endpoint.
    Then: The base path is appended to the host and accountSwitchKey is sent.
    """
    requests_mock.get(EVENTS_URL, json=make_page([]))
    client = build_client(PARAMS | {"account_switch_key": "1-ABC"})
    client.get_events("2026-07-14T11:37:00", "2026-07-14T11:38:00")
    request = requests_mock.last_request
    assert request.headers["Authorization"].startswith("EG1-HMAC-SHA256")
    assert request.headers["Accept"] == "application/json"
    assert query(request)["accountSwitchKey"] == "1-ABC"
    assert query(request)["limit"] == "50"


def test_get_next_cursor():
    """
    Given: HATEOAS links from the official API example.
    When: Extracting the next cursor.
    Then: The beforeEventId of the rel=next link is returned, and None when no next link exists.
    """
    assert get_next_cursor(load_json("events.json")["links"]) == "038a9f69-121f-4248-acd2-74103012c680"
    assert get_next_cursor([{"rel": "self", "href": "/event-viewer-api/v1/events"}]) is None
    assert get_next_cursor([{"rel": "next", "href": "/event-viewer-api/v1/events"}]) is None


def test_test_module_success(client, requests_mock):
    """
    Given: Valid credentials.
    When: Running test-module with "all" event types.
    Then: "ok" is returned and the event types endpoint is not called.
    """
    requests_mock.get(EVENTS_URL, json=make_page([]))
    types_mock = requests_mock.get(EVENT_TYPES_URL, json=load_json("event_types.json"))
    assert AkamaiEventViewer.test_module(client, ["all"], "500") == "ok"
    assert not types_mock.called


def test_test_module_failure(client, requests_mock):
    """
    Given: Invalid credentials.
    When: Running test-module.
    Then: An exception is raised.
    """
    requests_mock.get(EVENTS_URL, status_code=401, json={"title": "Unauthorized"})
    with pytest.raises(DemistoException):
        AkamaiEventViewer.test_module(client, [], "500")


def test_test_module_invalid_max_events(client):
    """
    Given: max_events_per_fetch above the 500 ceiling.
    When: Running test-module.
    Then: A clear error is raised.
    """
    with pytest.raises(DemistoException, match="between 1 and 500"):
        AkamaiEventViewer.test_module(client, [], "501")


@pytest.mark.parametrize("value, expected", [(None, 500), ("20", 20), ("500", 500)])
def test_parse_limit(value, expected):
    assert parse_limit(value, 500, "limit") == expected


@pytest.mark.parametrize("value", ["0", "501", "-1"])
def test_parse_limit_invalid(value):
    with pytest.raises(DemistoException):
        parse_limit(value, 500, "limit")


class TestResolveEventTypeIds:
    def test_resolves_names_case_insensitively(self, client, requests_mock):
        requests_mock.get(EVENT_TYPES_URL, json=load_json("event_types.json"))
        ids, cache = resolve_event_type_ids(client, ["all logins", " API Definition "], {})
        assert ids == ["16", "198"]
        assert cache == {"all logins": "16", "api definition": "198"}

    def test_uses_cache_without_api_call(self, client, requests_mock):
        types_mock = requests_mock.get(EVENT_TYPES_URL, json=[])
        ids, _ = resolve_event_type_ids(client, ["All Logins"], {"all logins": "16"})
        assert ids == ["16"]
        assert not types_mock.called

    def test_all_and_empty_mean_no_filter(self, client):
        assert resolve_event_type_ids(client, [], {}) == ([], {})
        assert resolve_event_type_ids(client, ["All"], {}) == ([], {})

    def test_unknown_name_raises(self, client, requests_mock):
        requests_mock.get(EVENT_TYPES_URL, json=load_json("event_types.json"))
        with pytest.raises(DemistoException, match="Unknown event type name"):
            resolve_event_type_ids(client, ["Nope"], {})

    def test_more_than_ten_raises(self, client):
        with pytest.raises(DemistoException, match="At most 10"):
            resolve_event_type_ids(client, [f"type {i}" for i in range(11)], {})


class TestCollectEvents:
    def test_pagination_follows_next_cursor(self, client, requests_mock):
        """
        Given: Two pages, the first with a rel=next link.
        When: Collecting events.
        Then: The second call carries beforeEventId plus the original window, and the window is exhausted.
        """
        requests_mock.get(EVENTS_URL, [{"json": make_page(["a", "b"], "b")}, {"json": make_page(["c"])}])
        events, cursor = collect_events(client, "16", "2026-07-14T11:37:00", "2026-07-14T11:38:00", 500, 10)
        assert [e["eventId"] for e in events] == ["a", "b", "c"]
        assert cursor is None
        second = query(requests_mock.request_history[1])
        assert second["beforeEventId"] == "b"
        assert second["start"] == "2026-07-14T11:37:00"
        assert second["eventTypeId"] == "16"

    def test_call_budget_returns_cursor(self, client, requests_mock):
        requests_mock.get(EVENTS_URL, [{"json": make_page(["a"], "a")}, {"json": make_page(["b"], "b")}])
        events, cursor = collect_events(client, None, "s", "e", 500, 2)
        assert len(events) == 2
        assert cursor == "b"
        assert requests_mock.call_count == 2

    def test_limit_mid_page_returns_last_event_as_cursor(self, client, requests_mock):
        requests_mock.get(EVENTS_URL, json=make_page(["a", "b", "c"], "c"))
        events, cursor = collect_events(client, None, "s", "e", 2, 10)
        assert [e["eventId"] for e in events] == ["a", "b"]
        assert cursor == "b"

    def test_limit_at_page_end_returns_next_cursor(self, client, requests_mock):
        requests_mock.get(EVENTS_URL, json=make_page(["a", "b"], "b"))
        _, cursor = collect_events(client, None, "s", "e", 2, 10)
        assert cursor == "b"

    def test_empty_page_stops(self, client, requests_mock):
        requests_mock.get(EVENTS_URL, json={"events": [], "links": []})
        assert collect_events(client, None, "s", "e", 50, 10) == ([], None)


class TestFetchEvents:
    def test_first_run(self, client, requests_mock):
        """
        Given: An empty last run.
        When: Fetching events.
        Then: The window covers the last minute, and the window is closed with boundary IDs recorded.
        """
        requests_mock.get(EVENTS_URL, json=make_page(["a", "b"]))
        events, next_run = fetch_events(client, {}, [], 500, NOW)
        assert [e["eventId"] for e in events] == ["a", "b"]
        request = query(requests_mock.last_request)
        assert request["start"] == "2026-07-14T11:37:00"
        assert request["end"] == "2026-07-14T11:38:00"
        assert "eventTypeId" not in request
        window = next_run["windows"]["all"]
        assert window["before_event_id"] is None
        assert window["window_end"] == "2026-07-14T11:38:00"
        assert window["boundary_ids"] == []  # events at 11:37:30 are before the 11:37:59 boundary

    def test_subsequent_run_and_dedup(self, client, requests_mock):
        """
        Given: A closed window whose last-second events were recorded.
        When: Fetching the next window, which overlaps by one second.
        Then: The window starts one second before the previous end and boundary events are not re-sent.
        """
        last_run = {
            "windows": {
                "all": {
                    "window_start": "x",
                    "window_end": "2026-07-14T11:37:00",
                    "before_event_id": None,
                    "boundary_ids": ["dup"],
                    "skip_ids": [],
                }
            }
        }
        requests_mock.get(EVENTS_URL, json=make_page(["new", "dup"], event_time="2026-07-14T11:37:59.500Z"))
        events, next_run = fetch_events(client, last_run, [], 500, NOW)
        assert [e["eventId"] for e in events] == ["new"]
        assert query(requests_mock.last_request)["start"] == "2026-07-14T11:36:59"
        window = next_run["windows"]["all"]
        assert window["skip_ids"] == ["dup"]
        assert window["boundary_ids"] == ["new", "dup"]

    def test_resumes_unfinished_window(self, client, requests_mock):
        """
        Given: A window left open with a cursor because the budget ran out.
        When: Fetching again.
        Then: The same window is resumed from the cursor instead of skipping older events.
        """
        open_window = {
            "window_start": "2026-07-14T11:30:00",
            "window_end": "2026-07-14T11:31:00",
            "before_event_id": "cursor",
            "boundary_ids": [],
            "skip_ids": [],
        }
        requests_mock.get(EVENTS_URL, json=make_page(["older"]))
        _, next_run = fetch_events(client, {"windows": {"all": open_window}}, [], 500, NOW)
        request = query(requests_mock.last_request)
        assert request["beforeEventId"] == "cursor"
        assert request["start"] == "2026-07-14T11:30:00"
        assert next_run["windows"]["all"]["before_event_id"] is None

    def test_respects_max_events_per_fetch(self, client, requests_mock):
        requests_mock.get(EVENTS_URL, json=make_page([str(i) for i in range(50)], "49"))
        events, next_run = fetch_events(client, {}, [], 120, NOW)
        assert len(events) == 120
        assert requests_mock.call_count == 3
        assert next_run["windows"]["all"]["before_event_id"] == "19"

    def test_budget_shared_across_event_types(self, client, requests_mock):
        """
        Given: Three event types and a 500 events budget.
        When: Fetching events.
        Then: Each type gets floor(10 / 3) = 3 calls, so 9 calls in total.
        """
        requests_mock.get(EVENTS_URL, json=make_page([str(i) for i in range(50)], "49"))
        events, next_run = fetch_events(client, {}, ["1", "2", "3"], 500, NOW)
        assert requests_mock.call_count == 9
        assert len(events) == 450
        assert set(next_run["windows"]) == {"1", "2", "3"}
        assert {query(r)["eventTypeId"] for r in requests_mock.request_history} == {"1", "2", "3"}


def test_fetch_events_command(client, requests_mock, mocker):
    """
    Given: A configured event type name.
    When: Running fetch-events.
    Then: Events get _time and are sent with the right vendor/product, and the last run caches the type IDs.
    """
    requests_mock.get(EVENT_TYPES_URL, json=load_json("event_types.json"))
    requests_mock.get(EVENTS_URL, json=load_json("events.json") | {"links": []})
    mocker.patch.object(AkamaiEventViewer.demisto, "getLastRun", return_value={})
    set_last_run = mocker.patch.object(AkamaiEventViewer.demisto, "setLastRun")
    send = mocker.patch.object(AkamaiEventViewer, "send_events_to_xsiam")
    fetch_events_command(client, ["All Logins"], 500)
    events = send.call_args[0][0]
    assert send.call_args[1] == {"vendor": "akamai", "product": "event_viewer"}
    assert events[0]["_time"] == "2017-07-27T12:13:37.15Z"
    next_run = set_last_run.call_args[0][0]
    assert next_run["event_type_ids"] == {"all logins": "16"}
    assert "16" in next_run["windows"]


def test_get_events_command_no_push(client, requests_mock, mocker):
    requests_mock.get(EVENTS_URL, json=load_json("events.json") | {"links": []})
    send = mocker.patch.object(AkamaiEventViewer, "send_events_to_xsiam")
    result = get_events_command(
        client, {"limit": "10", "start_time": "2026-07-14T10:00:00Z", "end_time": "2026-07-14T11:00:00Z"}, []
    )
    assert isinstance(result.raw_response, list)
    assert len(result.raw_response) == 2
    assert "All Logins" in result.readable_output
    assert query(requests_mock.last_request)["start"] == "2026-07-14T10:00:00"
    send.assert_not_called()


def test_get_events_command_with_push(client, requests_mock, mocker):
    requests_mock.get(EVENTS_URL, json=load_json("events.json") | {"links": []})
    send = mocker.patch.object(AkamaiEventViewer, "send_events_to_xsiam")
    get_events_command(client, {"should_push_events": "true"}, [])
    assert send.call_args[1] == {"vendor": "akamai", "product": "event_viewer"}
    assert all("_time" in event for event in send.call_args[0][0])
