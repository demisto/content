import json
import os
from http import HTTPStatus
from datetime import datetime, timezone, timedelta

import pytest
from freezegun import freeze_time
from CommonServerPython import *
from Cymulate_v3 import Client


@pytest.fixture(autouse=True)
def mock_client():
    """Create a Cymulate client with base URL and dummy token."""
    return Client(
        base_url="https://cymulate.test",
        token="dummy-token",
        verify=False,
        proxy=False,
    )


def load_mock_response(file_name: str) -> dict:
    """
    Load mock JSON file for Cymulate API response.
    Args:
        file_name (str): file name from test_data directory.
    Returns:
        dict: JSON content parsed from the file.
    """
    file_path = os.path.join("test_data", file_name)
    with open(file_path, "r") as f:
        return json.load(f)


@freeze_time("2025-11-06T12:00:00Z")
@pytest.mark.parametrize(
    "json_file, expected_length",
    [
        ("list_findings.json", 1),
        ("list_findings_empty.json", 0),
    ],
)
def test_fetch_incidents_parametrized(requests_mock, mock_client: Client, monkeypatch, json_file, expected_length):
    """
    Scenario: Fetch incidents based on given Cymulate findings file.
    Given:
     - A Cymulate findings response file.
    When:
     - The fetch_incidents function is executed.
    Then:
     - The number of returned incidents should match the expected length.
     - The function should return a string last_run.
    """
    from Cymulate_v3 import fetch_incidents

    json_response = load_mock_response(json_file)

    if json_response.get("data", {}).get("findings"):
        json_response["data"]["findings"][0]["latest"] = expected_length > 0

    requests_mock.post(
        "https://cymulate.test/msfinding/api/v2/search",
        json=json_response,
        status_code=HTTPStatus.OK,
    )

    monkeypatch.setattr("Cymulate_v3.demisto.getLastRun", lambda: {"time": None})
    monkeypatch.setattr("Cymulate_v3.demisto.integrationInstance", lambda: "Cymulate_v3Instance")
    monkeypatch.setattr("Cymulate_v3.demisto.debug", lambda _: None)
    monkeypatch.setattr("Cymulate_v3.get_integration_context", lambda: {})
    monkeypatch.setattr("Cymulate_v3.set_integration_context", lambda _: None)

    first_fetch = datetime(2025, 11, 5, 12, 0, tzinfo=timezone.utc)

    incidents, last_run = fetch_incidents(
        client=mock_client,
        first_fetch=first_fetch,
        max_fetch=10,
        categories=[],
        environment_ids=[],
        mirror_direction="In",
    )

    assert isinstance(incidents, list)
    assert len(incidents) == expected_length
    assert isinstance(last_run, str)


@freeze_time("2025-11-06T12:00:00Z")
@pytest.mark.parametrize(
    "json_file, expected_modified_count",
    [
        ("list_findings_modified.json", 1),
        ("list_findings.json", 0),
    ],
)
def test_get_modified_remote_data_command_parametrized(requests_mock, mock_client: Client, monkeypatch, json_file, expected_modified_count):
    """
    Scenario: Query for Cymulate findings that are modified (latest=False) since last update.
    Given:
     - Integration context contains a first_incident_time.
     - The API returns findings within the relevant date range.
    When:
     - The `get_modified_remote_data_command` is executed.
    Then:
     - Only findings with `latest=False` and `date` > `first_incident_time` are returned.
    """
    from Cymulate_v3 import get_modified_remote_data_command

    json_response = load_mock_response(json_file)

    requests_mock.post(
        "https://cymulate.test/msfinding/api/v2/search",
        json=json_response,
        status_code=HTTPStatus.OK,
    )

    monkeypatch.setattr("Cymulate_v3.demisto.debug", lambda _: None)
    monkeypatch.setattr("Cymulate_v3.get_integration_context", lambda: {
        "first_incident_time": "2025-11-06T10:00:00Z"
    })

    args = {"lastUpdate": "2024-11-06T11:00:00Z"}

    response = get_modified_remote_data_command(
        client=mock_client,
        args=args,
        categories=[],
        environment_ids=[],
        max_page_size=100,
    )

    assert isinstance(response, GetModifiedRemoteDataResponse)
    assert isinstance(response.modified_incident_ids, list)
    assert len(response.modified_incident_ids) == expected_modified_count

    if expected_modified_count > 0:
        assert all(isinstance(i, str) for i in response.modified_incident_ids)


@freeze_time("2025-11-06T12:00:00Z")
@pytest.mark.parametrize(
    "json_file, expected_entry_count, expected_closed",
    [
        ("get_finding.json", 1, True),
        ("get_finding_empty.json", 0, False),
    ],
)
def test_get_remote_data_command_parametrized(requests_mock, mock_client: Client, monkeypatch, json_file, expected_entry_count, expected_closed):
    """
    Scenario: Fetch remote data for a Cymulate finding (mirrored-in incident).
    Given:
     - A remote incident ID.
     - The Cymulate API returns either a valid finding or an empty result.
    When:
     - The `get_remote_data_command` is executed.
    Then:
     - If a finding exists, a closure note entry is created.
     - If no finding exists, response should be empty.
    """
    from Cymulate_v3 import get_remote_data_command

    json_response = load_mock_response(json_file)

    remote_id = "abc123"
    requests_mock.get(
        f"https://cymulate.test/msfinding/api/v2/info/{remote_id}",
        json=json_response,
        status_code=HTTPStatus.OK,
    )

    monkeypatch.setattr("Cymulate_v3.demisto.debug", lambda _: None)

    args = {
        "id": remote_id,
        "lastUpdate": "2025-11-06T11:00:00Z",
    }

    response = get_remote_data_command(mock_client, args)

    assert isinstance(response, GetRemoteDataResponse)
    if expected_closed:
        assert isinstance(response.mirrored_object, dict)
        assert response.mirrored_object["id"] == remote_id
        assert len(response.entries) == expected_entry_count

        entry = response.entries[0]
        assert entry["Type"] == EntryType.NOTE
        assert entry["Contents"]["dbotIncidentClose"] is True
        assert entry["Contents"]["closeReason"] == "Closed from Cymulate (latest=false)."
        assert entry["ContentsFormat"] == EntryFormat.JSON
    else:
        assert response.mirrored_object == {}
        assert response.entries == []
