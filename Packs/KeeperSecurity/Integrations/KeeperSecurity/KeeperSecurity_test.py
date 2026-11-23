from datetime import datetime, UTC

import httpx
import pytest
from CommonServerPython import DemistoException
from KeeperSecurity import (
    Client,
    add_time_to_events,
    dedup_events,
    event_hash,
    fetch_events,
    get_audit_logs,
    normalize_base_url,
)
from pytest_mock import MockerFixture

BASE_URL = "https://keepersecurity.com"


def make_event(ts: int, audit_event: str = "login", username: str = "user@example.com") -> dict:
    return {
        "audit_event": audit_event,
        "remote_address": "1.2.3.4",
        "category": "web",
        "client_version": "Web App 17.0.0",
        "enterprise_id": 1,
        "username": username,
        "timestamp": ts,
    }


@pytest.fixture
def client() -> Client:
    return Client(base_url=BASE_URL, api_key="token", verify=False)


def mock_transport(mocker: MockerFixture, client: Client, response: httpx.Response) -> list[httpx.Request]:
    """Routes the ContentClient's httpx requests to a canned response and returns the list of captured requests."""
    requests: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        return response

    mocker.patch.object(
        client,
        "_get_async_client",
        side_effect=lambda: httpx.AsyncClient(base_url=BASE_URL, transport=httpx.MockTransport(handler)),
    )
    return requests


@pytest.mark.parametrize(
    "url, expected",
    [
        ("keepersecurity.com", "https://keepersecurity.com"),
        ("https://keepersecurity.eu/", "https://keepersecurity.eu"),
        ("", "https://keepersecurity.com"),
    ],
)
def test_normalize_base_url(url, expected):
    assert normalize_base_url(url) == expected


def test_get_events_sends_auth_header_and_params(client: Client, mocker: MockerFixture):
    requests = mock_transport(mocker, client, httpx.Response(200, json={"events": [], "has_more": False}))
    client.get_events(
        datetime(2024, 1, 1, tzinfo=UTC),
        datetime(2024, 1, 2, tzinfo=UTC),
        limit=5,
        continuation_token="tok",
    )
    request = requests[0]
    assert request.headers["x-api-token"] == "Bearer token"
    assert request.url.params["start_date"] == "2024-01-01T00:00:00Z"
    assert request.url.params["end_date"] == "2024-01-02T00:00:00Z"
    assert request.url.params["limit"] == "5"
    assert request.url.params["continuation_token"] == "tok"


def test_get_events_forbidden(client: Client, mocker: MockerFixture, capfd):
    mock_transport(mocker, client, httpx.Response(403, json={"error": "invalid_token"}))
    with pytest.raises(DemistoException, match="SIEM:1"):
        client.get_events(datetime.now(UTC), datetime.now(UTC))
    capfd.readouterr()  # ContentClient logs authentication errors to stdout


def test_event_hash_is_stable_and_distinguishes_events():
    assert event_hash(make_event(1)) == event_hash(make_event(1))
    assert event_hash(make_event(1)) != event_hash(make_event(2))
    assert event_hash(make_event(1)) != event_hash(make_event(1, audit_event="logout"))


def test_dedup_events():
    old, same_ts_seen, same_ts_new, newer = (
        make_event(1000),
        make_event(2000, "a"),
        make_event(2000, "b"),
        make_event(3000),
    )
    result = dedup_events([old, same_ts_seen, same_ts_new, newer], 2000, {event_hash(same_ts_seen)})
    assert result == [same_ts_new, newer]


def test_add_time_to_events():
    events = [make_event(1704067200000)]
    add_time_to_events(events)
    assert events[0]["_time"] == "2024-01-01T00:00:00.000Z"


def test_get_audit_logs_follows_continuation_token(mocker: MockerFixture):
    client_mock = mocker.Mock()
    first, second = [make_event(1000), make_event(2000)], [make_event(2000, "b"), make_event(3000)]
    client_mock.get_events.side_effect = [
        {"events": first, "has_more": True, "continuation_token": "next"},
        {"events": second, "has_more": False},
    ]
    events, latest_ms, latest_hashes = get_audit_logs(client_mock, 0, 10, set())

    assert [e["timestamp"] for e in events] == [1000, 2000, 2000, 3000]
    assert latest_ms == 3000
    assert latest_hashes == {event_hash(make_event(3000))}
    first_call, second_call = client_mock.get_events.call_args_list
    assert first_call.kwargs["continuation_token"] is None
    assert second_call.kwargs["continuation_token"] == "next"
    # The same date range must be used for every page
    assert first_call.kwargs["start_date"] == second_call.kwargs["start_date"]
    assert first_call.kwargs["end_date"] == second_call.kwargs["end_date"]


def test_get_audit_logs_respects_max_fetch(mocker: MockerFixture):
    client_mock = mocker.Mock()
    client_mock.get_events.return_value = {
        "events": [make_event(1000), make_event(2000, "b"), make_event(3000, "c")],
        "has_more": True,
        "continuation_token": "next",
    }
    events, latest_ms, _ = get_audit_logs(client_mock, 0, 2, set())
    assert len(events) == 2
    assert latest_ms == 2000
    assert client_mock.get_events.call_count == 1


def test_get_audit_logs_no_events_keeps_state(mocker: MockerFixture):
    client_mock = mocker.Mock()
    client_mock.get_events.return_value = {"events": [], "has_more": False}
    events, latest_ms, latest_hashes = get_audit_logs(client_mock, 5000, 10, {"h"})
    assert events == []
    assert latest_ms == 5000
    assert latest_hashes == {"h"}


def test_fetch_events_first_run_uses_first_fetch(mocker: MockerFixture):
    first_fetch = datetime(2024, 1, 1, tzinfo=UTC)
    mock_get = mocker.patch("KeeperSecurity.get_audit_logs", return_value=([], 1704067200000, set()))
    _, next_run = fetch_events(mocker.Mock(), {}, 10, first_fetch)
    assert mock_get.call_args.kwargs["start_time_ms"] == 1704067200000
    assert next_run == {"last_fetch_time_ms": 1704067200000, "last_fetch_hashes": []}


def test_fetch_events_uses_last_run(mocker: MockerFixture):
    mock_get = mocker.patch("KeeperSecurity.get_audit_logs", return_value=([{"x": 1}], 9000, {"h2"}))
    events, next_run = fetch_events(
        mocker.Mock(), {"last_fetch_time_ms": 5000, "last_fetch_hashes": ["h1"]}, 10, datetime.now(UTC)
    )
    assert mock_get.call_args.kwargs["start_time_ms"] == 5000
    assert mock_get.call_args.kwargs["last_fetched_hashes"] == {"h1"}
    assert events == [{"x": 1}]
    assert next_run == {"last_fetch_time_ms": 9000, "last_fetch_hashes": ["h2"]}
