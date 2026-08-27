import json

import pytest
from GitGuardianEventCollector import fetch_events, get_events


def util_load_json(path):
    with open(path, encoding="utf-8") as f:
        return json.loads(f.read())


def http_mock(method: str, url_suffix: str = "", full_url: str = "", params: dict = {}, retries: int = 3):
    if url_suffix == "/incidents/secrets" or full_url.endswith("/incidents/secrets"):
        return util_load_json("test_data/incident_response.json")
    elif full_url == "next_url":
        return util_load_json("test_data/audit_log_response_next_link.json")
    else:
        return util_load_json("test_data/audit_log_response.json")


@pytest.fixture(autouse=True)
def client(mocker):
    from GitGuardianEventCollector import Client

    headers = {"Authorization": "Token mock"}
    mocker.patch.object(Client, "_http_request", side_effect=http_mock)
    return Client(
        base_url="https://mock.gitguardian.com",
        verify=False,
        proxy=False,
        headers=headers,
    )


def test_get_events_command_limit(client):
    """
    Given: A mock GitGuardian client.
    When: Running get_events with a limit of 1, while there are two events.
    Then: Ensure only one event of each type is returned.
    """

    mock_args = {"limit": "1"}
    incidents, audit_logs, _ = get_events(client=client, args=mock_args)
    assert len(incidents) == 1
    assert len(audit_logs) == 1


def test_extract_event_ids_with_same_to_fetch_time(client):
    """
    Given: A mock GitGuardian client.
    When: Running extract_incident_ids_with_same_last_occurrence_date.
    Then: Ensure the indicators returned have the same last_occurence_date as the one provided
    """

    incidents = [
        {"id": 1, "last_occurrence_date": "2024-01-03T21:05:38Z"},
        {"id": 2, "last_occurrence_date": "2024-02-03T21:05:38Z"},
        {"id": 3, "last_occurrence_date": "2024-01-03T21:05:38Z"},
    ]
    ids_with_same_occurrence_date = client.extract_event_ids_with_same_to_fetch_time(
        incidents, "2024-01-03T21:05:38Z", "incident"
    )
    assert ids_with_same_occurrence_date == [1, 3]


def test_remove_duplicated_incidents(client):
    """
    Given: A mock GitGuardian client.
    When: Running remove_duplicated_incidents.
    Then: Ensure the indicators returned without the incidents that were fetched before
    """

    incidents = [
        {"id": 1, "last_occurrence_date": "2024-02-03T21:05:38Z"},
        {"id": 2, "last_occurrence_date": "2024-01-03T21:05:38Z"},
        {"id": 3, "last_occurrence_date": "2024-03-03T21:05:38Z"},
    ]
    last_fetched_ids = [1]
    sorted_incidents = client.remove_duplicated_events(incidents, last_fetched_ids)
    assert sorted_incidents == [
        {"id": 2, "last_occurrence_date": "2024-01-03T21:05:38Z"},
        {"id": 3, "last_occurrence_date": "2024-03-03T21:05:38Z"},
    ]


def test_fetch_events_without_nextTrigger(client, mocker):
    """
    Given: A mock GitGuardian client.
    When: Running fetch_events with a limit of 3
    Then: Ensure all of the events are returned, and the next run include the new fetch times.
    """

    max_events_per_fetch = 2
    last_run = {
        "incident": {
            "from_fetch_time": "2024-01-03T21:10:40Z",
            "to_fetch_time": "2024-01-03T21:10:40Z",
            "last_fetched_event_ids": [],
            "next_url_link": "",
        },
        "audit_log": {
            "from_fetch_time": "2024-01-03T21:10:40Z",
            "to_fetch_time": "2024-01-03T21:10:40Z",
            "last_fetched_event_ids": [],
            "next_url_link": "",
        },
    }

    mocker.patch("GitGuardianEventCollector.send_events_to_xsiam")
    next_run, incidents, audit_logs = fetch_events(client, last_run, max_events_per_fetch)
    assert len(incidents) == 2
    assert len(audit_logs) == 2
    assert next_run["incident"].get("from_fetch_time") == "2024-01-03T21:10:40Z"
    assert next_run["incident"].get("last_fetched_event_ids") == []
    assert "nextTrigger" not in next_run  # fetched all of the events


def test_fetch_events_with_nextTrigger(client, mocker):
    """
    Given: A mock GitGuardian client.
    When: Running fetch_events with a limit of 1
    Then: Ensure next run include the new fetch times, the next_url link, and fetch timing
    """

    max_events_per_fetch = 1
    last_run = {
        "incident": {
            "from_fetch_time": "2024-01-03T21:10:40Z",
            "to_fetch_time": "2024-01-03T21:10:42Z",
            "last_fetched_event_ids": [],
            "next_url_link": "",
        },
        "audit_log": {
            "from_fetch_time": "2024-01-03T21:10:40Z",
            "to_fetch_time": "2024-01-03T21:10:42Z",
            "last_fetched_event_ids": [],
            "next_url_link": "",
        },
    }

    mocker.patch("GitGuardianEventCollector.send_events_to_xsiam")
    next_run, _, _ = fetch_events(client, last_run, max_events_per_fetch)
    assert "nextTrigger" in next_run  # did not fetch all of the events
    assert next_run["audit_log"].get("next_url_link") == "next_url"
    # Did not update the time window due to next url
    assert next_run["audit_log"].get("from_fetch_time") == "2024-01-03T21:10:40Z"
    assert next_run["audit_log"]["is_pagination_in_progress"]
    assert next_run["incident"].get("next_url_link") == ""
    assert not next_run["incident"]["is_pagination_in_progress"]
    assert next_run["incident"].get("from_fetch_time") == "2024-01-03T21:10:42Z"


def test_retrieve_events_uses_incidents_secrets_endpoint(client, mocker):
    """
    Given: A mock GitGuardian client.
    When: Retrieving incident events.
    Then: Ensure the request is made against the '/incidents/secrets' endpoint (SaaS-compatible),
          and not the deprecated '/secrets' endpoint.
    """
    http_request_mock = mocker.patch.object(client, "_http_request", side_effect=http_mock)
    last_run = {"from_fetch_time": "2024-01-03T21:10:40Z", "to_fetch_time": "2024-01-03T21:10:40Z"}
    client.search_events(last_run, 1, "incident")
    assert http_request_mock.call_args.kwargs["url_suffix"] == "/incidents/secrets"


def test_add_time_to_events_sets_entry_status_new(client):
    """
    Given: An incident whose last_occurrence_date equals its first_occurrence_date.
    When: Running add_time_to_events.
    Then: Ensure the _ENTRY_STATUS is set to 'new'.
    """
    events = [{"id": 1, "first_occurrence_date": "2024-01-03T21:05:38Z", "last_occurrence_date": "2024-01-03T21:05:38Z"}]
    client.add_time_to_events(events, "incident")
    assert events[0]["_ENTRY_STATUS"] == "new"


def test_add_time_to_events_sets_entry_status_updated(client):
    """
    Given: An incident whose last_occurrence_date is later than its first_occurrence_date.
    When: Running add_time_to_events.
    Then: Ensure the _ENTRY_STATUS is set to 'updated'.
    """
    events = [{"id": 1, "first_occurrence_date": "2024-01-03T21:05:38Z", "last_occurrence_date": "2024-02-03T21:05:38Z"}]
    client.add_time_to_events(events, "incident")
    assert events[0]["_ENTRY_STATUS"] == "updated"


def test_add_time_to_events_omits_entry_status_without_first_occurrence(client):
    """
    Given: An incident missing the first_occurrence_date field.
    When: Running add_time_to_events.
    Then: Ensure the _ENTRY_STATUS is omitted.
    """
    events = [{"id": 1, "last_occurrence_date": "2024-01-03T21:05:38Z"}]
    client.add_time_to_events(events, "incident")
    assert "_ENTRY_STATUS" not in events[0]


def test_add_time_to_events_omits_entry_status_for_audit_logs(client):
    """
    Given: An audit log event.
    When: Running add_time_to_events.
    Then: Ensure the _ENTRY_STATUS is not added (it applies to incidents only).
    """
    events = [{"id": 1, "gg_created_at": "2024-01-03T21:05:38Z"}]
    client.add_time_to_events(events, "audit_log")
    assert "_ENTRY_STATUS" not in events[0]
