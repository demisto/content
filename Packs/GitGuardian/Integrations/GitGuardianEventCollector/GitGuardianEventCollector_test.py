import json
from GitGuardianEventCollector import get_events, fetch_events
import pytest


def util_load_json(path):
    with open(path, encoding="utf-8") as f:
        return json.loads(f.read())


def http_mock(method: str, url_suffix: str = "", full_url: str = "", params: dict = {}, retries: int = 3):
    if url_suffix == "/secrets" or full_url.endswith("/secrets"):
        return util_load_json("test_data/incident_response.json")
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

    incidents = [{"id": 1, "last_occurrence_date": "2024-01-03T21:05:38Z"},
                 {"id": 2, "last_occurrence_date": "2024-02-03T21:05:38Z"},
                 {"id": 3, "last_occurrence_date": "2024-01-03T21:05:38Z"}]
    ids_with_same_occurrence_date = client.extract_event_ids_with_same_to_fetch_time(
        incidents, '2024-01-03T21:05:38Z', 'incident')
    assert ids_with_same_occurrence_date == [1, 3]


def test_remove_duplicated_incidents(client):
    """
    Given: A mock GitGuardian client.
    When: Running remove_duplicated_incidents.
    Then: Ensure the indicators returned without the incidents that were fetched before
    """

    incidents = [{"id": 1, "last_occurrence_date": "2024-02-03T21:05:38Z"},
                 {"id": 2, "last_occurrence_date": "2024-01-03T21:05:38Z"},
                 {"id": 3, "last_occurrence_date": "2024-03-03T21:05:38Z"}]
    last_fetched_ids = [1]
    sorted_incidents = client.remove_duplicated_events(incidents, last_fetched_ids)
    assert sorted_incidents == [{"id": 2, "last_occurrence_date": "2024-01-03T21:05:38Z"},
                                {"id": 3, "last_occurrence_date": "2024-03-03T21:05:38Z"}]


def test_fetch_events(client, mocker):
    """
    Given: A mock GitGuardian client.
    When: Running fetch_events with a limit of 3
    Then: Ensure all of the events are returned, and the next run include the new fetch times.
    """

    max_events_per_fetch = 3
    last_run = {
        "incident": {"from_fetch_time": "2024-01-03T21:10:40Z",
                     "to_fetch_time": "2024-01-03T21:10:40Z",
                     "last_fetched_event_ids": [],
                     "next_url_link": ''},
        "audit_log": {
            "from_fetch_time": "2024-01-03T21:10:40Z",
            "to_fetch_time": "2024-01-03T21:10:40Z",
            "last_fetched_event_ids": [],
            "next_url_link": ''
        }
    }

    mocker.patch('GitGuardianEventCollector.send_events_to_xsiam')
    next_run, incidents, audit_logs = fetch_events(
        client, last_run, max_events_per_fetch
    )
    assert len(incidents) == 2
    assert len(audit_logs) == 1
    assert next_run["incident"].get("from_fetch_time") == "2024-01-03T21:10:40Z"
    assert next_run["incident"].get("last_fetched_event_ids") == []
