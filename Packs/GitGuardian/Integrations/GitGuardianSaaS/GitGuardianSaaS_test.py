import json
from typing import Any
from unittest.mock import MagicMock

import pytest
from ContentClientApiModule import ContentClientAuthenticationError
from GitGuardianSaaS import (
    AUDIT_LOGS,
    AUTH_ERROR_MESSAGE,
    SECRET_INCIDENTS,
    Client,
    enrich_events,
    fetch_events,
    fetch_events_for_type,
    get_boundary_keys,
    get_dedup_key,
    get_entry_status,
    get_events_command,
    parse_event_types,
    parse_next_link,
)
from GitGuardianSaaS import test_module as run_test_module

BASE_URL = "https://api.gitguardian.com/v1"
NEXT_URL = "https://api.gitguardian.com/v1/incidents/secrets?cursor=cD03Mjc%3D&per_page=100"
WINDOW_START = "2024-01-01T09:00:00Z"
WINDOW_END = "2024-01-01T12:00:00Z"


def load_test_data(file_name: str) -> list[dict[str, Any]]:
    with open(f"test_data/{file_name}") as file:
        return json.load(file)


@pytest.fixture
def client() -> Client:
    return Client(base_url=BASE_URL, api_key="test-key", verify=True, proxy=False)


def make_event(event_id: int, date: str, triggered_at: str | None = None) -> dict[str, Any]:
    event: dict[str, Any] = {"id": event_id, "date": date}
    if triggered_at:
        event["triggered_at"] = triggered_at
    return event


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
    Given: Secret incidents from the API.
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
    Given: A next URL from a previous Link header.
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
        "/incidents/secrets",
        params={"per_page": 100, "date_after": WINDOW_START, "date_before": WINDOW_END},
        next_url=None,
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


def test_fetch_events_for_type_resumes_pagination(client: Client, mocker):
    """
    Given: A saved state with a pagination cursor from the previous cycle.
    When: Fetching events for a type with a newer window end.
    Then: The saved next URL is followed and the saved window end (not the new one) becomes the next last_date.
    """
    get_page = mocker.patch.object(client, "get_page", return_value=([make_event(5, "2024-01-01T11:00:00Z")], None))
    saved_state = {"last_date": WINDOW_START, "last_ids": [], "window_end": WINDOW_END, "next_url": NEXT_URL}

    _, next_state = fetch_events_for_type(client, SECRET_INCIDENTS, saved_state, "2024-01-01T13:00:00Z", 1000)

    assert get_page.call_args.kwargs["next_url"] == NEXT_URL
    assert next_state["last_date"] == WINDOW_END


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


# fetch_events


def mock_fetch_for_type(results: dict[str, Any]):
    """Returns a fetch_events_for_type side effect that returns or raises the configured result per event type."""

    def side_effect(client, event_type, type_state, window_end, max_events):
        result = results[event_type.key]
        if isinstance(result, Exception):
            raise result
        return result

    return side_effect


def test_fetch_events_all_types(client: Client, mocker):
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

    events, next_run, errors = fetch_events(client, {}, [SECRET_INCIDENTS, AUDIT_LOGS], 1000, WINDOW_START)

    assert len(events) == 4
    assert {event["_source_log_type"] for event in events} == {"incident_secret", "audit_log"}
    assert next_run == {"secret_incidents": incidents_state, "audit_logs": audit_state}
    assert errors == []


def test_fetch_events_first_fetch_uses_first_fetch_time(client: Client, mocker):
    """
    Given: An empty last run.
    When: Running fetch-events.
    Then: Each type starts from the first fetch time.
    """
    fetch_for_type = mocker.patch(
        "GitGuardianSaaS.fetch_events_for_type", return_value=([], {"last_date": WINDOW_END, "last_ids": []})
    )

    fetch_events(client, {}, [AUDIT_LOGS], 1000, WINDOW_START)

    assert fetch_for_type.call_args.args[2] == {"last_date": WINDOW_START, "last_ids": []}


def test_fetch_events_partial_failure_keeps_state(client: Client, mocker):
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
        client, {"audit_logs": previous_audit_state}, [SECRET_INCIDENTS, AUDIT_LOGS], 1000, WINDOW_START
    )

    assert len(events) == 2
    assert next_run == {"audit_logs": previous_audit_state, "secret_incidents": incidents_state}
    assert errors == ["Audit Logs: Service unavailable"]


def test_fetch_events_sets_next_trigger_when_paginating(client: Client, mocker):
    """
    Given: An event type that still has pages to fetch.
    When: Running fetch-events.
    Then: nextTrigger is set to 0 so the next cycle runs immediately.
    """
    paginating_state = {"last_date": WINDOW_START, "last_ids": [], "window_end": WINDOW_END, "next_url": NEXT_URL}
    mocker.patch("GitGuardianSaaS.fetch_events_for_type", return_value=([], paginating_state))

    _, next_run, _ = fetch_events(client, {"nextTrigger": "0"}, [SECRET_INCIDENTS], 1000, WINDOW_START)

    assert next_run["nextTrigger"] == "0"


def test_fetch_events_clears_next_trigger_when_done(client: Client, mocker):
    """
    Given: A previous cycle that set nextTrigger, and no more pages now.
    When: Running fetch-events.
    Then: nextTrigger is removed.
    """
    mocker.patch("GitGuardianSaaS.fetch_events_for_type", return_value=([], {"last_date": WINDOW_END, "last_ids": []}))

    _, next_run, _ = fetch_events(client, {"nextTrigger": "0"}, [SECRET_INCIDENTS], 1000, WINDOW_START)

    assert "nextTrigger" not in next_run


# get_events_command


def test_get_events_command(client: Client, mocker):
    """
    Given: limit=1 and a single event type.
    When: Running gitguardian-saas-get-events.
    Then: Only the requested type is fetched, the result is limited and enriched, and a table is returned.
    """
    fetch_for_type = mocker.patch("GitGuardianSaaS.fetch_events_for_type", return_value=(load_test_data("audit_logs.json"), {}))

    events, results = get_events_command(
        client, {"limit": "1", "event_types": "Audit Logs", "start_date": WINDOW_START}, [SECRET_INCIDENTS, AUDIT_LOGS]
    )

    assert fetch_for_type.call_count == 1
    assert fetch_for_type.call_args.args[1] == AUDIT_LOGS
    assert fetch_for_type.call_args.args[2]["last_date"] == WINDOW_START
    assert len(events) == 1
    assert events[0]["_source_log_type"] == "audit_log"
    assert "GitGuardian SaaS Audit Logs" in results.readable_output


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


def test_test_module_auth_error(client: Client, mocker):
    """
    Given: Invalid credentials.
    When: Running test-module.
    Then: A clear authorization error message is returned.
    """
    mocker.patch.object(client, "get_page", side_effect=ContentClientAuthenticationError("Authentication failed"))
    assert run_test_module(client, [SECRET_INCIDENTS]) == AUTH_ERROR_MESSAGE
