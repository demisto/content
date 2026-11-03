import json
import threading
from datetime import datetime, timedelta, timezone
from typing import Any
from unittest.mock import MagicMock

import pytest
from ContentClientApiModule import ContentClientAuthenticationError, ContentClientError, ContentClientRetryError
from GitGuardianSaaS import (
    AUDIT_LOGS,
    FETCH_LAG_SECONDS,
    SECRET_INCIDENTS,
    Client,
    UntrustedNextUrlError,
    build_base_url,
    enrich_events,
    fetch_events,
    fetch_events_for_type,
    get_boundary_keys,
    get_dedup_key,
    get_entry_status,
    get_events_command,
    parse_event_types,
    parse_next_link,
    parse_positive_int,
)
from GitGuardianSaaS import test_module as run_test_module

BASE_URL = "https://api.gitguardian.com/v1"
NEXT_URL = "https://api.gitguardian.com/v1/incidents/secrets?cursor=cD03Mjc%3D&per_page=100"
FOREIGN_NEXT_URL = "https://attacker.example.com/v1/incidents/secrets?cursor=cD03Mjc%3D"
WINDOW_START = "2024-01-01T09:00:00Z"
WINDOW_END = "2024-01-01T12:00:00Z"
NEXT_WINDOW_END = "2024-01-01T13:00:00Z"


def load_test_data(file_name: str) -> list[dict[str, Any]]:
    with open(f"test_data/{file_name}") as file:
        return json.load(file)


def create_test_client() -> Client:
    return Client(base_url=BASE_URL, api_key="test-key", verify=True, proxy=False)


@pytest.fixture
def client() -> Client:
    return create_test_client()


@pytest.fixture
def clients() -> dict[str, Client]:
    return {SECRET_INCIDENTS.key: create_test_client(), AUDIT_LOGS.key: create_test_client()}


def make_event(event_id: int, date: str, triggered_at: str | None = None) -> dict[str, Any]:
    event: dict[str, Any] = {"id": event_id, "date": date}
    if triggered_at:
        event["triggered_at"] = triggered_at
    return event


def make_http_error(status_code: int) -> ContentClientError:
    return ContentClientError(f"Request failed with status {status_code}", response=MagicMock(status_code=status_code))


# parse_next_link


@pytest.mark.parametrize(
    "link_header, expected",
    [
        (f'<{NEXT_URL}>; rel="next"', NEXT_URL),
        (f'<https://api.gitguardian.com/v1/x?cursor=prev>; rel="prev", <{NEXT_URL}>; rel="next"', NEXT_URL),
        ('<https://api.gitguardian.com/v1/x?cursor=prev>; rel="prev"', None),
        ("", None),
    ],
)
def test_parse_next_link(link_header: str, expected: str | None):
    """
    Given: A Link response header.
    When: Parsing it for the next page.
    Then: The rel="next" URL is returned verbatim, or None when there is no next page.
    """
    assert parse_next_link(link_header) == expected


# build_base_url / parse_positive_int


@pytest.mark.parametrize(
    "server_url, expected",
    [
        (None, BASE_URL),
        ("https://api.gitguardian.com", BASE_URL),
        ("https://api.gitguardian.com/", BASE_URL),
        ("https://api.gitguardian.com/v1", BASE_URL),
        ("https://api.gitguardian.com/v1/", BASE_URL),
        ("https://api.eu1.gitguardian.com", "https://api.eu1.gitguardian.com/v1"),
    ],
)
def test_build_base_url(server_url: str | None, expected: str):
    """
    Given: A server URL with or without a trailing slash or /v1 suffix.
    When: Building the API base URL.
    Then: /v1 is appended exactly once.
    """
    assert build_base_url(server_url) == expected


@pytest.mark.parametrize("value, expected", [(None, 7), ("", 7), ("5", 5), (1000, 1000)])
def test_parse_positive_int_valid(value: Any, expected: int):
    """
    Given: An empty or positive value.
    When: Parsing it as a positive integer.
    Then: The value is returned, or the default when it is empty.
    """
    assert parse_positive_int(value, "limit", 7) == expected


@pytest.mark.parametrize("value", ["0", "-1", -100])
def test_parse_positive_int_invalid(value: Any):
    """
    Given: A zero or negative value.
    When: Parsing it as a positive integer.
    Then: An error is raised, so the fetch never runs with a value that would skip the window.
    """
    with pytest.raises(Exception, match="limit must be a positive integer"):
        parse_positive_int(value, "limit", 7)


# get_entry_status / enrich_events


@pytest.mark.parametrize(
    "event, expected",
    [
        (make_event(1, "2024-01-01T10:00:00Z", "2024-01-01T10:00:00Z"), "new"),
        (make_event(1, "2024-01-01T10:00:00Z", "2024-01-01T10:00:00.000000Z"), "new"),
        (make_event(1, "2024-01-01T11:00:00Z", "2024-01-01T09:00:00Z"), "updated"),
        (make_event(1, "2024-01-01T11:00:00Z"), "new"),
    ],
)
def test_get_entry_status(event: dict[str, Any], expected: str):
    """
    Given: An event with or without triggered_at.
    When: Calculating the entry status.
    Then: 'new' when date == triggered_at or triggered_at is missing (audit logs), otherwise 'updated'.
    """
    assert get_entry_status(event) == expected


def test_enrich_events_secret_incidents():
    """
    Given: Secret incidents from the API, one new and one re-triggered.
    When: Enriching them.
    Then: _time comes from date, _source_log_type is incident_secret and _ENTRY_STATUS follows the rule.
    """
    events = enrich_events(load_test_data("secret_incidents.json"), SECRET_INCIDENTS)
    assert [event["_time"] for event in events] == ["2024-01-01T10:00:00Z", "2024-01-01T11:00:00Z"]
    assert {event["_source_log_type"] for event in events} == {"incident_secret"}
    assert [event["_ENTRY_STATUS"] for event in events] == ["new", "updated"]


def test_enrich_events_audit_logs():
    """
    Given: Audit logs from the API (no triggered_at field).
    When: Enriching them.
    Then: _source_log_type is audit_log and _ENTRY_STATUS is always new.
    """
    events = enrich_events(load_test_data("audit_logs.json"), AUDIT_LOGS)
    assert events[0]["_time"] == "2024-01-01T10:30:00.123456Z"
    assert {event["_source_log_type"] for event in events} == {"audit_log"}
    assert {event["_ENTRY_STATUS"] for event in events} == {"new"}


# get_boundary_keys / get_dedup_key


def test_get_boundary_keys():
    """
    Given: Events, some dated at the window end (including one with sub-second precision).
    When: Extracting the boundary keys.
    Then: Only the events dated at the window end second are returned.
    """
    events = [
        make_event(1, "2024-01-01T11:59:59Z"),
        make_event(2, WINDOW_END),
        make_event(3, "2024-01-01T12:00:00.500000Z"),
    ]
    assert get_boundary_keys(events, WINDOW_END) == [get_dedup_key(events[1]), get_dedup_key(events[2])]


def test_get_dedup_key_changes_on_retrigger():
    """
    Given: The same incident before and after it was re-triggered.
    When: Building the dedup keys.
    Then: The keys differ, so the re-triggered incident is not dropped as a duplicate.
    """
    assert get_dedup_key(make_event(1, "2024-01-01T10:00:00Z")) != get_dedup_key(make_event(1, "2024-01-01T11:00:00Z"))


def test_get_dedup_key_normalizes_date_format():
    """
    Given: The same event timestamp in two ISO-8601 formats.
    When: Building the dedup keys.
    Then: The keys are equal, so a format change does not create duplicates.
    """
    assert get_dedup_key(make_event(1, "2024-01-01T10:00:00Z")) == get_dedup_key(
        make_event(1, "2024-01-01T10:00:00.000000+00:00")
    )


# parse_event_types


def test_parse_event_types():
    """
    Given: Event type display names.
    When: Parsing them.
    Then: Valid names map to EventType objects, and invalid or empty input raises an error.
    """
    assert parse_event_types(["Audit Logs", "Secret Incidents"]) == [AUDIT_LOGS, SECRET_INCIDENTS]
    with pytest.raises(Exception, match="Invalid event types: Alerts"):
        parse_event_types(["Alerts"])
    with pytest.raises(Exception, match="at least one event type"):
        parse_event_types([])


# Client.get_page


def test_get_page_first_page(client: Client, mocker):
    """
    Given: No next URL.
    When: Requesting a page.
    Then: The endpoint and params are used, and the events and next URL are returned.
    """
    response = MagicMock()
    response.json.return_value = load_test_data("secret_incidents.json")
    response.headers = {"Link": f'<{NEXT_URL}>; rel="next"'}
    http_request = mocker.patch.object(client, "_http_request", return_value=response)

    events, next_url = client.get_page("/incidents/secrets", params={"per_page": 100})

    assert len(events) == 2
    assert next_url == NEXT_URL
    http_request.assert_called_once_with(
        method="GET", url_suffix="/incidents/secrets", params={"per_page": 100}, resp_type="response"
    )


def test_get_page_follows_next_url_verbatim(client: Client, mocker):
    """
    Given: A next URL from a previous Link header, on the configured host.
    When: Requesting a page.
    Then: The next URL is called verbatim, and None is returned on the last page.
    """
    response = MagicMock()
    response.json.return_value = []
    response.headers = {}
    http_request = mocker.patch.object(client, "_http_request", return_value=response)

    events, next_url = client.get_page("/incidents/secrets", params={"per_page": 100}, next_url=NEXT_URL)

    assert events == []
    assert next_url is None
    http_request.assert_called_once_with(method="GET", full_url=NEXT_URL, resp_type="response")


def test_get_page_rejects_foreign_next_url(client: Client, mocker):
    """
    Given: A next URL that points to a different host than the server URL.
    When: Requesting a page.
    Then: An error is raised and no request is sent, so the API key is never sent to the foreign host.
    """
    http_request = mocker.patch.object(client, "_http_request")

    with pytest.raises(UntrustedNextUrlError):
        client.get_page("/incidents/secrets", next_url=FOREIGN_NEXT_URL)

    http_request.assert_not_called()


def test_client_sends_token_auth_header(client: Client):
    """
    Given: A client configured with an API key.
    When: Inspecting the auth handler.
    Then: The Authorization header uses the Token scheme.
    """
    assert client._auth_handler.header_name == "Authorization"  # type: ignore[union-attr]
    assert client._auth_handler.key == "Token test-key"  # type: ignore[union-attr]


# fetch_events_for_type


def test_fetch_events_for_type_single_page(client: Client, mocker):
    """
    Given: A first fetch where the API returns a single page.
    When: Fetching events for a type.
    Then: The window params are sent, all events are returned and the next state moves to the window end.
    """
    events_page = [make_event(1, "2024-01-01T10:00:00Z"), make_event(2, WINDOW_END)]
    get_page = mocker.patch.object(client, "get_page", return_value=(events_page, None))

    events, next_state = fetch_events_for_type(
        client, SECRET_INCIDENTS, {"last_date": WINDOW_START, "last_ids": []}, WINDOW_END, 1000
    )

    assert events == events_page
    assert next_state == {"last_date": WINDOW_END, "last_ids": [get_dedup_key(events_page[1])]}
    get_page.assert_called_once_with(
        "/incidents/secrets", params={"per_page": 100, "date_after": WINDOW_START, "date_before": WINDOW_END}
    )


def test_fetch_events_for_type_follows_pages_until_last(client: Client, mocker):
    """
    Given: The API returns two pages.
    When: Fetching events for a type with a large budget.
    Then: The rel="next" URL is followed and pagination stops when there is no next link.
    """
    mocker.patch.object(
        client,
        "get_page",
        side_effect=[([make_event(1, "2024-01-01T10:00:00Z")], NEXT_URL), ([make_event(2, "2024-01-01T11:00:00Z")], None)],
    )

    events, next_state = fetch_events_for_type(
        client, SECRET_INCIDENTS, {"last_date": WINDOW_START, "last_ids": []}, WINDOW_END, 1000
    )

    assert [event["id"] for event in events] == [1, 2]
    assert client.get_page.call_args_list[1].kwargs["next_url"] == NEXT_URL  # type: ignore[attr-defined]
    assert "next_url" not in next_state


def test_fetch_events_for_type_stops_at_budget_and_saves_cursor(client: Client, mocker):
    """
    Given: More pages are available than the max events budget allows.
    When: Fetching events for a type.
    Then: Fetching stops at the budget, and the next URL and window end are saved to resume next cycle.
    """
    page = [make_event(index, "2024-01-01T10:00:00Z") for index in range(100)]
    get_page = mocker.patch.object(client, "get_page", return_value=(page, NEXT_URL))

    events, next_state = fetch_events_for_type(
        client, SECRET_INCIDENTS, {"last_date": WINDOW_START, "last_ids": []}, WINDOW_END, 200
    )

    assert get_page.call_count == 2
    assert len(events) == 200
    assert next_state == {"last_date": WINDOW_START, "last_ids": [], "window_end": WINDOW_END, "next_url": NEXT_URL}


def test_fetch_events_for_type_page_cap_stops_empty_pages(client: Client, mocker):
    """
    Given: The API keeps returning empty pages that still have a next link.
    When: Fetching events for a type with a budget of 200 events (2 pages).
    Then: Fetching stops after 2 pages instead of looping forever, and the cursor is saved.
    """
    get_page = mocker.patch.object(client, "get_page", return_value=([], NEXT_URL))

    events, next_state = fetch_events_for_type(
        client, SECRET_INCIDENTS, {"last_date": WINDOW_START, "last_ids": []}, WINDOW_END, 200
    )

    assert get_page.call_count == 2
    assert events == []
    assert next_state["next_url"] == NEXT_URL


def test_fetch_events_for_type_resumes_pagination(client: Client, mocker):
    """
    Given: A saved state with a pagination cursor from the previous cycle.
    When: Fetching events for a type with a newer window end.
    Then: The saved next URL is followed and the saved window end (not the new one) becomes the next last_date.
    """
    get_page = mocker.patch.object(client, "get_page", return_value=([make_event(5, "2024-01-01T11:00:00Z")], None))
    saved_state = {"last_date": WINDOW_START, "last_ids": [], "window_end": WINDOW_END, "next_url": NEXT_URL}

    _, next_state = fetch_events_for_type(client, SECRET_INCIDENTS, saved_state, NEXT_WINDOW_END, 1000)

    assert get_page.call_args.kwargs["next_url"] == NEXT_URL
    assert next_state["last_date"] == WINDOW_END


def test_fetch_events_for_type_restarts_window_when_cursor_rejected(client: Client, mocker):
    """
    Given: A saved cursor that the API rejects with 400 (for example, an expired cursor).
    When: Fetching events for a type.
    Then: The cursor is dropped and the window restarts from last_date up to the new window end, so the type is not stuck.
    """
    mocker.patch("GitGuardianSaaS.demisto.info")
    get_page = mocker.patch.object(
        client, "get_page", side_effect=[make_http_error(400), ([make_event(5, "2024-01-01T12:30:00Z")], None)]
    )
    saved_state = {"last_date": WINDOW_START, "last_ids": [], "window_end": WINDOW_END, "next_url": NEXT_URL}

    events, next_state = fetch_events_for_type(client, SECRET_INCIDENTS, saved_state, NEXT_WINDOW_END, 1000)

    assert [event["id"] for event in events] == [5]
    assert get_page.call_args.kwargs["params"] == {"per_page": 100, "date_after": WINDOW_START, "date_before": NEXT_WINDOW_END}
    assert next_state == {"last_date": NEXT_WINDOW_END, "last_ids": []}


@pytest.mark.parametrize(
    "error",
    [make_http_error(429), make_http_error(403), ContentClientRetryError("Exceeded retry attempts: 503")],
)
def test_fetch_events_for_type_keeps_cursor_on_transient_errors(client: Client, mocker, error: Exception):
    """
    Given: A saved cursor and an error that does not mean the cursor is invalid (rate limit, auth or server error).
    When: Fetching events for a type.
    Then: The error is raised, so the caller keeps the saved cursor and retries it next cycle.
    """
    mocker.patch.object(client, "get_page", side_effect=error)
    saved_state = {"last_date": WINDOW_START, "last_ids": [], "window_end": WINDOW_END, "next_url": NEXT_URL}

    with pytest.raises(type(error)):
        fetch_events_for_type(client, SECRET_INCIDENTS, saved_state, NEXT_WINDOW_END, 1000)


def test_fetch_events_for_type_restarts_window_when_cursor_host_is_foreign(client: Client, mocker):
    """
    Given: A saved cursor on a different host than the server URL (for example, after the server URL was changed).
    When: Fetching events for a type.
    Then: The cursor is never requested and the window restarts from last_date.
    """
    mocker.patch("GitGuardianSaaS.demisto.info")
    get_page = mocker.patch.object(client, "get_page", return_value=([], None))
    saved_state = {"last_date": WINDOW_START, "last_ids": [], "window_end": WINDOW_END, "next_url": FOREIGN_NEXT_URL}

    _, next_state = fetch_events_for_type(client, SECRET_INCIDENTS, saved_state, NEXT_WINDOW_END, 1000)

    get_page.assert_called_once_with(
        "/incidents/secrets", params={"per_page": 100, "date_after": WINDOW_START, "date_before": NEXT_WINDOW_END}
    )
    assert next_state["last_date"] == NEXT_WINDOW_END


def test_fetch_events_for_type_deduplicates(client: Client, mocker):
    """
    Given: Events already collected at the boundary of the previous window, and a re-triggered incident.
    When: Fetching events for a type.
    Then: The already-collected events are dropped and the re-triggered incident is kept.
    """
    duplicate = make_event(1, WINDOW_START)
    retriggered = make_event(1, "2024-01-01T10:00:00Z")
    mocker.patch.object(client, "get_page", return_value=([duplicate, retriggered], None))

    events, _ = fetch_events_for_type(
        client, SECRET_INCIDENTS, {"last_date": WINDOW_START, "last_ids": [get_dedup_key(duplicate)]}, WINDOW_END, 1000
    )

    assert events == [retriggered]


def test_fetch_events_for_type_two_runs_boundary_flow(client: Client, mocker):
    """
    Given: A first run that ends with an event dated exactly at the window end.
    When: The second run starts at that timestamp and the API returns the boundary event again with a new event.
    Then: The boundary event is collected once in total, and the new event is collected in the second run.
    """
    boundary_event = make_event(1, WINDOW_END)
    new_event = make_event(2, "2024-01-01T12:30:00Z")
    get_page = mocker.patch.object(
        client,
        "get_page",
        side_effect=[([make_event(0, "2024-01-01T10:00:00Z"), boundary_event], None), ([boundary_event, new_event], None)],
    )

    first_events, first_state = fetch_events_for_type(
        client, SECRET_INCIDENTS, {"last_date": WINDOW_START, "last_ids": []}, WINDOW_END, 1000
    )
    second_events, second_state = fetch_events_for_type(client, SECRET_INCIDENTS, first_state, NEXT_WINDOW_END, 1000)

    assert [event["id"] for event in first_events] == [0, 1]
    assert [event["id"] for event in second_events] == [2]
    assert get_page.call_args.kwargs["params"]["date_after"] == WINDOW_END
    assert second_state == {"last_date": NEXT_WINDOW_END, "last_ids": []}


# fetch_events


def mock_fetch_for_type(results: dict[str, Any]):
    """Returns a fetch_events_for_type side effect that returns or raises the configured result per event type."""

    def side_effect(client, event_type, type_state, window_end, max_events):
        result = results[event_type.key]
        if isinstance(result, Exception):
            raise result
        return result

    return side_effect


def test_fetch_events_all_types(clients: dict[str, Client], mocker):
    """
    Given: Both event types configured.
    When: Running fetch-events.
    Then: The events of both types are enriched and returned, and each type's state is saved.
    """
    incidents_state = {"last_date": WINDOW_END, "last_ids": []}
    audit_state = {"last_date": WINDOW_END, "last_ids": ["1001|x"]}
    mocker.patch(
        "GitGuardianSaaS.fetch_events_for_type",
        side_effect=mock_fetch_for_type(
            {
                "secret_incidents": (load_test_data("secret_incidents.json"), incidents_state),
                "audit_logs": (load_test_data("audit_logs.json"), audit_state),
            }
        ),
    )

    events, next_run, errors = fetch_events(clients, {}, [SECRET_INCIDENTS, AUDIT_LOGS], 1000, WINDOW_START)

    assert len(events) == 4
    assert {event["_source_log_type"] for event in events} == {"incident_secret", "audit_log"}
    assert next_run == {"secret_incidents": incidents_state, "audit_logs": audit_state}
    assert errors == []


def test_fetch_events_uses_a_client_per_event_type(clients: dict[str, Client], mocker):
    """
    Given: A separate client per event type.
    When: Running fetch-events.
    Then: Each event type is fetched with its own client, so their circuit breakers are independent.
    """
    fetch_for_type = mocker.patch(
        "GitGuardianSaaS.fetch_events_for_type", return_value=([], {"last_date": WINDOW_END, "last_ids": []})
    )

    fetch_events(clients, {}, [SECRET_INCIDENTS, AUDIT_LOGS], 1000, WINDOW_START)

    used_clients = {call.args[1].key: call.args[0] for call in fetch_for_type.call_args_list}
    assert used_clients[SECRET_INCIDENTS.key] is clients[SECRET_INCIDENTS.key]
    assert used_clients[AUDIT_LOGS.key] is clients[AUDIT_LOGS.key]
    assert clients[SECRET_INCIDENTS.key]._circuit_breaker is not clients[AUDIT_LOGS.key]._circuit_breaker


def test_fetch_events_window_ends_before_now(clients: dict[str, Client], mocker):
    """
    Given: A fetch cycle.
    When: Running fetch-events.
    Then: The window ends FETCH_LAG_SECONDS before now, so events indexed with a short delay are collected next cycle.
    """
    fetch_for_type = mocker.patch(
        "GitGuardianSaaS.fetch_events_for_type", return_value=([], {"last_date": WINDOW_END, "last_ids": []})
    )

    before_fetch = datetime.now(timezone.utc)  # noqa: UP017
    fetch_events(clients, {}, [AUDIT_LOGS], 1000, WINDOW_START)

    window_end = datetime.strptime(fetch_for_type.call_args.args[3], "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)  # noqa: UP017
    assert window_end <= before_fetch - timedelta(seconds=FETCH_LAG_SECONDS - 1)
    assert window_end >= before_fetch - timedelta(seconds=FETCH_LAG_SECONDS + 5)


def test_fetch_events_first_fetch_uses_first_fetch_time(clients: dict[str, Client], mocker):
    """
    Given: An empty last run.
    When: Running fetch-events.
    Then: Each type starts from the first fetch time.
    """
    fetch_for_type = mocker.patch(
        "GitGuardianSaaS.fetch_events_for_type", return_value=([], {"last_date": WINDOW_END, "last_ids": []})
    )

    fetch_events(clients, {}, [AUDIT_LOGS], 1000, WINDOW_START)

    assert fetch_for_type.call_args.args[2] == {"last_date": WINDOW_START, "last_ids": []}


def test_fetch_events_partial_failure_keeps_state(clients: dict[str, Client], mocker):
    """
    Given: One event type fails and the other succeeds.
    When: Running fetch-events.
    Then: The successful type's events and state are kept, and the failed type keeps its previous state.
    """
    mocker.patch("GitGuardianSaaS.demisto.error")
    previous_audit_state = {"last_date": WINDOW_START, "last_ids": []}
    incidents_state = {"last_date": WINDOW_END, "last_ids": []}
    mocker.patch(
        "GitGuardianSaaS.fetch_events_for_type",
        side_effect=mock_fetch_for_type(
            {
                "secret_incidents": (load_test_data("secret_incidents.json"), incidents_state),
                "audit_logs": Exception("Service unavailable"),
            }
        ),
    )

    events, next_run, errors = fetch_events(
        clients, {"audit_logs": previous_audit_state}, [SECRET_INCIDENTS, AUDIT_LOGS], 1000, WINDOW_START
    )

    assert len(events) == 2
    assert next_run == {"audit_logs": previous_audit_state, "secret_incidents": incidents_state}
    assert errors == ["Audit Logs: Service unavailable"]


def test_fetch_events_sets_next_trigger_when_paginating(clients: dict[str, Client], mocker):
    """
    Given: An event type that still has pages to fetch.
    When: Running fetch-events.
    Then: nextTrigger is set to 0 so the next cycle runs immediately.
    """
    paginating_state = {"last_date": WINDOW_START, "last_ids": [], "window_end": WINDOW_END, "next_url": NEXT_URL}
    mocker.patch("GitGuardianSaaS.fetch_events_for_type", return_value=([], paginating_state))

    _, next_run, _ = fetch_events(clients, {"nextTrigger": "0"}, [SECRET_INCIDENTS], 1000, WINDOW_START)

    assert next_run["nextTrigger"] == "0"


def test_fetch_events_threads_one_type_fails_other_continues(clients: dict[str, Client], mocker):
    """
    Given: Real worker threads (fetch_events_for_type is not mocked), where every audit-log API call
           raises an error and the secret-incident calls succeed.
    When: Running fetch-events.
    Then: The secret incidents are still returned, enriched and their state advances,
          while the audit-log state stays unchanged so the failed window is retried next cycle.
    """
    mocker.patch("GitGuardianSaaS.demisto.error")
    previous_audit_state = {"last_date": WINDOW_START, "last_ids": ["999|x"]}
    mocker.patch.object(clients[AUDIT_LOGS.key], "get_page", side_effect=ContentClientRetryError("Exceeded retry attempts: 503"))
    mocker.patch.object(clients[SECRET_INCIDENTS.key], "get_page", return_value=(load_test_data("secret_incidents.json"), None))

    events, next_run, errors = fetch_events(
        clients, {"audit_logs": previous_audit_state}, [SECRET_INCIDENTS, AUDIT_LOGS], 1000, WINDOW_START
    )

    assert [event["id"] for event in events] == [3759, 3760]
    assert {event["_source_log_type"] for event in events} == {"incident_secret"}
    assert next_run["audit_logs"] == previous_audit_state
    assert next_run["secret_incidents"]["last_date"] != WINDOW_START
    assert len(errors) == 1
    assert errors[0].startswith("Audit Logs: Exceeded retry attempts")


def test_fetch_events_runs_event_types_in_parallel(clients: dict[str, Client], mocker):
    """
    Given: Two event types, where each API call waits until both calls have started.
    When: Running fetch-events.
    Then: Both calls complete, which is only possible when the event types run in separate threads at the same time.
    """
    both_started = threading.Barrier(2, timeout=5)

    def get_page(endpoint, params=None, next_url=None):
        both_started.wait()  # Raises BrokenBarrierError after 5 seconds if the calls run one after the other.
        return [], None

    for type_client in clients.values():
        mocker.patch.object(type_client, "get_page", side_effect=get_page)

    _, next_run, errors = fetch_events(clients, {}, [SECRET_INCIDENTS, AUDIT_LOGS], 1000, WINDOW_START)

    assert errors == []
    assert set(next_run) == {"secret_incidents", "audit_logs"}


def test_fetch_events_clears_next_trigger_when_done(clients: dict[str, Client], mocker):
    """
    Given: A previous cycle that set nextTrigger, and no more pages now.
    When: Running fetch-events.
    Then: nextTrigger is removed.
    """
    mocker.patch("GitGuardianSaaS.fetch_events_for_type", return_value=([], {"last_date": WINDOW_END, "last_ids": []}))

    _, next_run, _ = fetch_events(clients, {"nextTrigger": "0"}, [SECRET_INCIDENTS], 1000, WINDOW_START)

    assert "nextTrigger" not in next_run


# get_events_command


def test_get_events_command_without_push(client: Client, mocker):
    """
    Given: limit=1, a single event type and should_push_events=false.
    When: Running gitguardian-saas-get-events.
    Then: Only the requested type is fetched and limited, the events are not enriched and nothing is sent to XSIAM.
    """
    fetch_for_type = mocker.patch("GitGuardianSaaS.fetch_events_for_type", return_value=(load_test_data("audit_logs.json"), {}))
    send_events = mocker.patch("GitGuardianSaaS.send_events_to_xsiam")

    results = get_events_command(
        client,
        {"limit": "1", "event_types": "Audit Logs", "start_date": WINDOW_START, "should_push_events": "false"},
        [SECRET_INCIDENTS, AUDIT_LOGS],
    )

    assert fetch_for_type.call_count == 1
    assert fetch_for_type.call_args.args[1] == AUDIT_LOGS
    assert fetch_for_type.call_args.args[2]["last_date"] == WINDOW_START
    assert len(results.raw_response) == 1
    assert not {"_time", "_source_log_type", "_ENTRY_STATUS"} & set(results.raw_response[0])
    assert "GitGuardian SaaS Audit Logs" in results.readable_output
    send_events.assert_not_called()


def test_get_events_command_with_push(client: Client, mocker):
    """
    Given: Both event types and should_push_events=true.
    When: Running gitguardian-saas-get-events.
    Then: The events are enriched and sent to XSIAM once, with the GitGuardian SaaS vendor and product.
    """
    mocker.patch(
        "GitGuardianSaaS.fetch_events_for_type",
        side_effect=[(load_test_data("secret_incidents.json"), {}), (load_test_data("audit_logs.json"), {})],
    )
    send_events = mocker.patch("GitGuardianSaaS.send_events_to_xsiam")

    get_events_command(client, {"limit": "10", "should_push_events": "true"}, [SECRET_INCIDENTS, AUDIT_LOGS])

    send_events.assert_called_once()
    sent_events = send_events.call_args.args[0]
    assert len(sent_events) == 4
    assert all({"_time", "_source_log_type", "_ENTRY_STATUS"} <= set(event) for event in sent_events)
    assert send_events.call_args.kwargs == {"vendor": "gitguardian", "product": "saas"}


def test_get_events_command_uses_end_date(client: Client, mocker):
    """
    Given: start_date and end_date arguments.
    When: Running gitguardian-saas-get-events.
    Then: The fetch window is bounded by end_date instead of the current time.
    """
    fetch_for_type = mocker.patch("GitGuardianSaaS.fetch_events_for_type", return_value=([], {}))

    get_events_command(client, {"start_date": WINDOW_START, "end_date": WINDOW_END}, [AUDIT_LOGS])

    assert fetch_for_type.call_args.args[2]["last_date"] == WINDOW_START
    assert fetch_for_type.call_args.args[3] == WINDOW_END


def test_get_events_command_start_after_end(client: Client, mocker):
    """
    Given: start_date later than end_date.
    When: Running gitguardian-saas-get-events.
    Then: An error is raised before any API call.
    """
    fetch_for_type = mocker.patch("GitGuardianSaaS.fetch_events_for_type")

    with pytest.raises(Exception, match="start_date must be earlier than end_date"):
        get_events_command(client, {"start_date": WINDOW_END, "end_date": WINDOW_START}, [AUDIT_LOGS])

    fetch_for_type.assert_not_called()


@pytest.mark.parametrize("limit", ["0", "-5"])
def test_get_events_command_invalid_limit(client: Client, mocker, limit: str):
    """
    Given: A zero or negative limit.
    When: Running gitguardian-saas-get-events.
    Then: An error is raised before any API call.
    """
    fetch_for_type = mocker.patch("GitGuardianSaaS.fetch_events_for_type")

    with pytest.raises(Exception, match="limit must be a positive integer"):
        get_events_command(client, {"limit": limit}, [SECRET_INCIDENTS])

    fetch_for_type.assert_not_called()


# test_module


def test_test_module_success(client: Client, mocker):
    """
    Given: Valid credentials.
    When: Running test-module.
    Then: 'ok' is returned after requesting each configured type.
    """
    get_page = mocker.patch.object(client, "get_page", return_value=([], None))
    assert run_test_module(client, [SECRET_INCIDENTS, AUDIT_LOGS]) == "ok"
    assert get_page.call_count == 2


def test_test_module_auth_error_names_event_type(client: Client, mocker):
    """
    Given: An API key that can read secret incidents but not audit logs.
    When: Running test-module.
    Then: The error message names the event type that failed and its required scope.
    """
    mocker.patch.object(client, "get_page", side_effect=[([], None), ContentClientAuthenticationError("Authentication failed")])

    result = run_test_module(client, [SECRET_INCIDENTS, AUDIT_LOGS])

    assert result.startswith("Authorization Error")
    assert "Audit Logs" in result
    assert "audit_logs:read" in result
