import json
import datetime
import pytest
import requests_mock
from freezegun import freeze_time

from CiscoWebexEventCollectorV2 import (
    ADMIN_AUDIT_EVENTS,
    COMPLIANCE_EVENTS,
    SECURITY_AUDIT_EVENTS,
    Client,
    add_fields_to_events,
    date_time_to_iso_format,
    fetch_events,
    get_events_command,
    increase_datetime_for_next_fetch,
    test_module as run_test_module,
)

BASE_URL = "https://url.com/"
ALL_EVENT_TYPES = [ADMIN_AUDIT_EVENTS, SECURITY_AUDIT_EVENTS, COMPLIANCE_EVENTS]
TYPE_TO_PATH = {
    ADMIN_AUDIT_EVENTS: "adminAudit/events",
    SECURITY_AUDIT_EVENTS: "admin/securityAudit/events",
    COMPLIANCE_EVENTS: "events",
}
TYPE_TO_FILE = {
    ADMIN_AUDIT_EVENTS: "admin_audits",
    SECURITY_AUDIT_EVENTS: "security_audits",
    COMPLIANCE_EVENTS: "events",
}


def util_load_text(path: str) -> str:
    with open(path) as f:
        return f.read()


def util_load_json(path: str) -> dict:
    return json.loads(util_load_text(path))


@pytest.fixture
def client() -> Client:
    return Client(base_url=BASE_URL, verify=False, proxy=False, org_id="1")


@freeze_time("2023-12-20 13:40:00 UTC")
def test_date_time_to_iso_format():
    """
    Given a frozen datetime, when formatting it, then an ISO string with milliseconds and Z is returned.
    """
    assert date_time_to_iso_format(datetime.datetime.utcnow()) == "2023-12-20T13:40:00.000Z"


def test_add_fields_to_events():
    """
    Given events of one type, when adding fields, then `_time` equals `created` and `source_log_type` is set.
    """
    events = util_load_json("test_data/admin_audits.json")["items"]
    add_fields_to_events(events, ADMIN_AUDIT_EVENTS)
    assert events[0]["_time"] == events[0]["created"]
    assert events[0]["source_log_type"] == ADMIN_AUDIT_EVENTS


@pytest.mark.parametrize(
    "latest_datetime_previous_fetch, expected_datetime",
    [
        ("2023-12-04T07:40:06.680Z", "2023-12-04T07:40:06.691Z"),
        ("2023-12-04T07:40:06.695Z", "2023-12-04T07:40:06.696Z"),
    ],
)
def test_increase_datetime_for_next_fetch(latest_datetime_previous_fetch, expected_datetime):
    """
    Given events and the previous checkpoint, when computing the next checkpoint,
    then the later of the two plus one millisecond is returned.
    """
    events = util_load_json("test_data/events.json")["items"]
    assert increase_datetime_for_next_fetch(events, latest_datetime_previous_fetch) == expected_datetime


@pytest.mark.parametrize("event_type", ALL_EVENT_TYPES)
def test_get_events_command(client, event_type):
    """
    Given each event type, when running the get events command, then events are returned and titled by type.
    """
    with requests_mock.Mocker() as m:
        m.get(f"{BASE_URL}{TYPE_TO_PATH[event_type]}", text=util_load_text(f"test_data/{TYPE_TO_FILE[event_type]}.json"))
        command_results, events = get_events_command(client, event_type, {})

    assert events
    assert all(event["source_log_type"] == event_type for event in events)
    assert event_type in command_results.readable_output


def test_get_events_sends_org_id_only_for_audit_types(client):
    """
    Given the admin audit and compliance event types, when querying, then only the audit request carries orgId.
    """
    with requests_mock.Mocker() as m:
        m.get(f"{BASE_URL}adminAudit/events", text=util_load_text("test_data/no_events.json"))
        m.get(f"{BASE_URL}events", text=util_load_text("test_data/no_events.json"))
        client.get_events(ADMIN_AUDIT_EVENTS, "2023-12-13T13:40:00.000Z", 1)
        client.get_events(COMPLIANCE_EVENTS, "2023-12-13T13:40:00.000Z", 1)

    assert m.request_history[0].qs["orgid"] == ["1"]
    assert "orgid" not in m.request_history[1].qs


def test_test_module_all_pass(client):
    """
    Given all selected event types succeed, when running test-module, then "ok" is returned.
    """
    with requests_mock.Mocker() as m:
        for path in TYPE_TO_PATH.values():
            m.get(f"{BASE_URL}{path}", text=util_load_text("test_data/no_events.json"))
        assert run_test_module(client, ALL_EVENT_TYPES) == "ok"


def test_test_module_reports_each_failure(client):
    """
    Given a missing compliance scope (403), no Pro Pack (403 on security audits) and a working admin audit,
    when running test-module, then one error lists a specific message per failed type and omits the working one.
    """
    with requests_mock.Mocker() as m:
        m.get(f"{BASE_URL}adminAudit/events", text=util_load_text("test_data/no_events.json"))
        m.get(f"{BASE_URL}admin/securityAudit/events", status_code=403, json={})
        m.get(f"{BASE_URL}events", status_code=403, json={})
        with pytest.raises(Exception) as error:
            run_test_module(client, ALL_EVENT_TYPES)

    message = str(error.value)
    assert "Webex Pro Pack license" in message
    assert "missing spark-compliance:events_read scope" in message
    assert ADMIN_AUDIT_EVENTS not in message


def test_test_module_unauthorized(client):
    """
    Given an expired or missing authorization (401), when running test-module, then the re-authorize message is shown.
    """
    with requests_mock.Mocker() as m:
        m.get(f"{BASE_URL}events", status_code=401, json={})
        with pytest.raises(Exception, match="Re-authorize"):
            run_test_module(client, [COMPLIANCE_EVENTS])


def test_test_module_only_checks_selected_types(client):
    """
    Given only Events is selected and security audits would fail, when running test-module, then it passes.
    """
    with requests_mock.Mocker() as m:
        m.get(f"{BASE_URL}admin/securityAudit/events", status_code=403, json={})
        m.get(f"{BASE_URL}events", text=util_load_text("test_data/no_events.json"))
        assert run_test_module(client, [COMPLIANCE_EVENTS]) == "ok"


@freeze_time("2023-12-20 13:40:00 UTC")
def test_fetch_events_with_pagination(client):
    """
    Given all event types and an empty last run, when fetching twice,
    then the first fetch returns events and stores next links, and the second follows them and clears them.
    """
    with requests_mock.Mocker() as m:
        for event_type, path in TYPE_TO_PATH.items():
            m.get(
                f"{BASE_URL}{path}",
                text=util_load_text(f"test_data/{TYPE_TO_FILE[event_type]}.json"),
                headers={"Link": f'<{BASE_URL}{path}?nexturl=true>; rel="next"'},
            )
        events, next_run = fetch_events(client, {}, 1, ALL_EVENT_TYPES)

    assert events
    assert next_run == {
        "admin_audits": {"next_url": f"{BASE_URL}adminAudit/events?nexturl=true", "since_datetime": "2023-12-20T09:33:26.409Z"},
        "security_audits": {
            "next_url": f"{BASE_URL}admin/securityAudit/events?nexturl=true",
            "since_datetime": "2023-12-19T07:01:26.487Z",
        },
        "compliance_officer_events": {"next_url": f"{BASE_URL}events?nexturl=true", "since_datetime": "2023-12-13T13:40:00.001Z"},
    }

    with requests_mock.Mocker() as m:
        for path in TYPE_TO_PATH.values():
            m.get(f"{BASE_URL}{path}?nexturl=true", text=util_load_text("test_data/no_events.json"))
        events, next_run = fetch_events(client, next_run, 1, ALL_EVENT_TYPES)

    assert events == []
    assert all(type_run["next_url"] == "" for type_run in next_run.values())


@freeze_time("2023-12-20 13:40:00 UTC")
def test_fetch_events_isolates_failures(client, mocker):
    """
    Given compliance events fail with 403, when fetching admin audits and compliance events,
    then admin audit events are still returned and the failed type keeps its original checkpoint.
    """
    error_log = mocker.patch("CiscoWebexEventCollectorV2.demisto.error")
    last_run = {"compliance_officer_events": {"since_datetime": "2023-12-13T13:40:00.000Z", "next_url": ""}}
    with requests_mock.Mocker() as m:
        m.get(f"{BASE_URL}adminAudit/events", text=util_load_text("test_data/admin_audits.json"))
        m.get(f"{BASE_URL}events", status_code=403, json={})
        events, next_run = fetch_events(client, last_run, 10, [ADMIN_AUDIT_EVENTS, COMPLIANCE_EVENTS])

    assert events
    assert all(event["source_log_type"] == ADMIN_AUDIT_EVENTS for event in events)
    assert next_run["compliance_officer_events"] == {"since_datetime": "2023-12-13T13:40:00.000Z", "next_url": ""}
    assert "security_audits" not in next_run
    error_log.assert_called_once()
