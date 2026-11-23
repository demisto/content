from datetime import datetime
import json
import time
import pytest
import demistomock as demisto
from unittest.mock import MagicMock
from Doppel import (
    test_module,
    fetch_incidents_command,
    get_remote_data_command,
    update_remote_system_command,
    get_mapping_fields_command,
    doppel_get_alert_command,
    doppel_update_alert_command,
    doppel_get_alerts_command,
    doppel_create_alert_command,
    doppel_create_abuse_alert_command,
    doppel_get_alert_screenshot_command,
    _screenshot_blob_path,
    _attach_screenshot_if_new,
    _track_screenshot_version,
    get_modified_remote_data_command,
    format_datetime,
    _paginated_call_to_get_alerts,
    _fetch_products_to_modules,
    _get_last_fetch_datetime,
    _get_mirroring_fields,
    _get_remote_updated_incident_data_with_entry,
    _normalize_entity_content_for_grid,
    _reopen_entry_if_revived,
    _parse_fetch_timeout,
    _parse_max_fetch,
    _incident_alert_id,
    _alert_to_incident,
    _xsoar_severity,
    Client,
)

from CommonServerPython import *
from CommonServerUserPython import *

ALERTS_RESPONSE = [
    {"id": "1", "created_at": "2025-02-01T12:00:00.000000Z"},
    {"id": "2", "created_at": "2025-02-01T12:05:00.000000Z"},
]

DOPPEL_API_DATE_FORMAT = "%Y-%m-%dT%H:%M:%S"

MIRROR_DIRECTION = {
    "None": None,
    "Incoming": "In",
    "Outgoing": "Out",
    "Incoming And Outgoing": "Both",
}


def util_load_json(path):
    """Helper function to load JSON data from a file."""
    with open(path, encoding="utf-8") as f:
        return json.loads(f.read())


# Mock function for _http_request


def mock_http_request(method, url_suffix, params=None, headers=None, data=None, json_data=None):
    if url_suffix == "alert":
        return util_load_json("test_data/get-alert.json")
    return {}


# Mock function to return alerts in the expected format
def mock_get_alerts(*args, **kwargs):
    if kwargs.get("page", 0) > 0:  # Simulate an empty response after the first page
        return {"alerts": []}

    modified_alerts = [{**alert, "created_at": alert["created_at"].rstrip("Z")} for alert in ALERTS_RESPONSE]
    return {"alerts": modified_alerts}  # Ensure response is a dictionary


@pytest.fixture
def client():
    # Create a mock client
    client = MagicMock()

    # Assign the mock function to get_alerts
    client.get_alerts.side_effect = mock_get_alerts

    # Mocking fetch single alert (Used in update_remote_system_command)
    client.get_alert.return_value = {"id": "123", "queue_state": "open", "entity_state": "active"}

    # Mocking update alert (Used in update_remote_system_command)
    client.update_alert.return_value = None  # Assume update succeeds

    return client


def test_test_module(mocker, client):
    """
    Given:
        - A mock Client instance
    When:
        - Running test_module() to test connectivity
    Then:
        - The function should return 'ok' if the API request is successful
    """

    # Mock the _http_request method
    mocker.patch.object(client, "_http_request", side_effect=mock_http_request)

    # Pass an empty dictionary `{}` as `args`, not a string
    result = test_module(client)

    # Assert the expected output
    assert result == "ok"


def test_fetch_incidents_command(mocker):
    """
    Test the `fetch_incidents_command` function for multiple fetch cycles.
    """

    # Mocking demisto functions
    mocker.patch.object(demisto, "params", return_value={"max_fetch": 1, "fetch_timeout": "30"})
    mocker.patch.object(demisto, "setLastRun")
    mocker.patch.object(demisto, "debug")
    mocker.patch.object(demisto, "info")
    mocker.patch.object(demisto, "incidents")

    # Load mock data
    mock_alerts = util_load_json("test_data/get-all-alerts.json")  # List of alerts from Doppel

    # Mock `_paginated_call_to_get_alerts` to simulate API responses in different cycles
    mocker.patch(
        "Doppel._paginated_call_to_get_alerts",
        side_effect=[
            mock_alerts["alerts"][:50],  # First fetch - fill queue
            mock_alerts["alerts"][50:100],  # Second fetch - next batch
            [],  # Third fetch - No new alerts, return remaining
            [],  # Fourth fetch - No new alerts, return empty
        ],
    )

    # Run test cycles
    last_run = None
    incidents_queue = []

    # for current_flow in ['first', 'second', 'third', 'forth']:
    # Mock last run data
    mocker.patch.object(demisto, "getLastRun", return_value={"last_run": last_run, "incidents_queue": incidents_queue})

    # Call function
    fetch_incidents_command(client=None, args={})

    # Verify incidents pushed to XSOAR
    incidents_pushed = demisto.incidents.call_args[0][0]
    assert len(incidents_pushed) == 1, "Mismatch in incidents"

    incident = incidents_pushed[0]
    assert "name" in incident
    assert "type" in incident
    assert "rawJSON" in incident
    assert incident["name"].startswith("Doppel Alert"), "Incident name format mismatch"
    assert incident["occurred"] != "", "Occurred timestamp should not be empty"

    # Verify last run update
    last_run_data = demisto.setLastRun.call_args[0][0]
    assert "last_run" in last_run_data, "last_run not updated"

    # The cursor advances, but no raw incident data may be persisted in lastRun.
    last_run = last_run_data["last_run"]
    assert "incidents_queue" not in last_run_data, "lastRun must not store raw incident data"


def test_fetch_incidents_timeout(mocker):
    """
    Test the `fetch_incidents_command` function for multiple fetch cycles.
    """

    # Mocking demisto functions
    mocker.patch.object(demisto, "params", return_value={"max_fetch": 1, "fetch_timeout": "10"})
    mocker.patch.object(demisto, "setLastRun")
    mocker.patch.object(demisto, "debug")
    mocker.patch.object(demisto, "info")
    mocker.patch.object(demisto, "incidents")

    # Load mock data
    mock_alerts = util_load_json("test_data/get-all-alerts.json")  # List of alerts from Doppel

    # Mock `_paginated_call_to_get_alerts` to simulate API responses in different cycles
    mocker.patch(
        "Doppel._paginated_call_to_get_alerts",
        side_effect=[
            mock_alerts["alerts"][:50],  # First fetch - fill queue
            mock_alerts["alerts"][50:100],  # Second fetch - next batch
            [],  # Third fetch - No new alerts, return remaining
            [],  # Fourth fetch - No new alerts, return empty
        ],
    )

    # Run test cycles
    last_run = None
    incidents_queue = []

    # for current_flow in ['first', 'second', 'third', 'forth']:
    # Mock last run data
    mocker.patch.object(demisto, "getLastRun", return_value={"last_run": last_run, "incidents_queue": incidents_queue})

    # Call function
    fetch_incidents_command(client=None, args={})

    # Verify incidents pushed to XSOAR
    incidents_pushed = demisto.incidents.call_args[0][0]
    assert len(incidents_pushed) == 1, "Mismatch in incidents"

    incident = incidents_pushed[0]
    assert "name" in incident
    assert "type" in incident
    assert "rawJSON" in incident
    assert incident["name"].startswith("Doppel Alert"), "Incident name format mismatch"
    assert incident["occurred"] != "", "Occurred timestamp should not be empty"

    # Verify last run update
    last_run_data = demisto.setLastRun.call_args[0][0]
    assert "last_run" in last_run_data, "last_run not updated"

    # The cursor advances, but no raw incident data may be persisted in lastRun.
    last_run = last_run_data["last_run"]
    assert "incidents_queue" not in last_run_data, "lastRun must not store raw incident data"


def test_fetch_incidents_max_fetch(mocker):
    """
    Test the `fetch_incidents_command` function for multiple fetch cycles.
    """

    # Mocking demisto functions
    mocker.patch.object(demisto, "params", return_value={"max_fetch": 3, "fetch_timeout": "30"})
    mocker.patch.object(demisto, "setLastRun")
    mocker.patch.object(demisto, "debug")
    mocker.patch.object(demisto, "info")
    mocker.patch.object(demisto, "incidents")

    # Load mock data
    mock_alerts = util_load_json("test_data/get-all-alerts.json")  # List of alerts from Doppel

    # Mock `_paginated_call_to_get_alerts` to simulate API responses in different cycles
    mocker.patch(
        "Doppel._paginated_call_to_get_alerts",
        side_effect=[
            mock_alerts["alerts"][:50],  # First fetch - fill queue
            mock_alerts["alerts"][50:100],  # Second fetch - next batch
            [],  # Third fetch - No new alerts, return remaining
            [],  # Fourth fetch - No new alerts, return empty
        ],
    )

    # Run test cycles
    last_run = None
    incidents_queue = []

    # for current_flow in ['first', 'second', 'third', 'forth']:
    # Mock last run data
    mocker.patch.object(demisto, "getLastRun", return_value={"last_run": last_run, "incidents_queue": incidents_queue})

    # Call function
    fetch_incidents_command(client=None, args={})

    # Verify incidents pushed to XSOAR
    incidents_pushed = demisto.incidents.call_args[0][0]
    assert len(incidents_pushed) == 3, "Mismatch in incidents"

    incident = incidents_pushed[0]
    assert "name" in incident
    assert "type" in incident
    assert "rawJSON" in incident
    assert incident["name"].startswith("Doppel Alert"), "Incident name format mismatch"
    assert incident["occurred"] != "", "Occurred timestamp should not be empty"

    # Verify last run update
    last_run_data = demisto.setLastRun.call_args[0][0]
    assert "last_run" in last_run_data, "last_run not updated"

    # The cursor advances, but no raw incident data may be persisted in lastRun.
    last_run = last_run_data["last_run"]
    assert "incidents_queue" not in last_run_data, "lastRun must not store raw incident data"


def test_fetch_incidents_no_alerts(mocker):
    """Test fetch_incidents_command when there are no incidents to fetch."""
    # Mock Demisto functions
    mocker.patch.object(demisto, "params", return_value={"max_fetch": 1, "fetch_timeout": "10"})
    mocker.patch.object(demisto, "getLastRun", return_value={"last_run": None, "incidents_queue": []})
    mocker.patch.object(demisto, "setLastRun")
    mocker.patch.object(demisto, "incidents")
    mocker.patch.object(demisto, "info")
    mocker.patch.object(demisto, "debug")

    # Create a mock client
    mock_client = MagicMock()
    mocker.patch("Doppel._paginated_call_to_get_alerts", return_value=[])  # Simulating no alerts returned

    fetch_incidents_command(client=mock_client, args={})

    fetch_incidents_command(client=None, args={})

    # Assertions
    demisto.incidents.assert_called_with([])  # Ensure no incidents are created
    demisto.debug.assert_any_call("Doppel - Created 0 incident(s) in XSOAR.")


def test_get_remote_data_command(mocker, requests_mock):
    """
    Given:
        - A remote incident ID and last update timestamp.
    When:
        - Running get_remote_data_command to fetch updates.
    Then:
        - It returns the relevant incident entity from the remote system with the expected mirroring fields.
    """

    # Mock API response for fetching incident updates
    requests_mock.get(
        "https://example.com/api/alerts", json={"data": [{"id": "123456", "status": "updated", "name": "Test Alert"}]}
    )

    # Mock necessary demisto functions
    mocker.patch.object(demisto, "debug")
    mocker.patch.object(demisto, "error")
    mocker.patch.object(demisto, "args", return_value={"id": "123456", "lastUpdate": "2025-01-27T07:55:10.063742"})
    mocker.patch.object(demisto, "command", return_value="get-remote-data")

    mock_get_remote_updated_incident_data_with_entry = mocker.patch(
        "Doppel._get_remote_updated_incident_data_with_entry",
        return_value=(
            {
                "id": "123456",
                "status": "updated",
                "name": "Test Alert",
            },
            [],
        ),
    )

    # Prepare client mock
    client = mocker.Mock()

    # Call the function
    result = get_remote_data_command(client, demisto.args())

    assert result.mirrored_object == {"id": "123456", "status": "updated", "name": "Test Alert"}
    assert result.entries == []

    mock_get_remote_updated_incident_data_with_entry.assert_called_once()

    demisto.debug.assert_called()


def test_get_remote_data_command_rate_limit_exception(mocker, capfd):
    """
    Given:
        - A remote incident ID and last update timestamp.
        - A Rate limit exceeded exception is raised during _get_remote_updated_incident_data_with_entry.
    When:
        - Running get_remote_data_command to fetch updates.
    Then:
        - It returns a GetRemoteDataResponse with the error message in mirrored_object and logs API rate limit.
    """
    mocker.patch.object(demisto, "debug")
    mocker.patch.object(demisto, "error", side_effect=demisto.error)
    mocker.patch.object(demisto, "args", return_value={"id": "123456", "lastUpdate": "2025-01-27T07:55:10.063742"})
    mocker.patch.object(demisto, "command", return_value="get-remote-data")

    mock_get_remote_updated_incident_data_with_entry = mocker.patch(
        "Doppel._get_remote_updated_incident_data_with_entry",
        side_effect=Exception("Rate limit exceeded"),
    )

    client = MagicMock()
    with capfd.disabled():
        result = get_remote_data_command(client, demisto.args())

    assert result.mirrored_object == {"in_mirror_error": "Rate limit exceeded"}
    assert result.entries == []
    demisto.debug.assert_called_with("API rate limit")

    mock_get_remote_updated_incident_data_with_entry.assert_called_once()


def test_update_remote_system_command(client, mocker):
    """Closing an XSOAR incident archives the Doppel alert and preserves live entity_state."""
    mocker.patch.object(demisto, "debug")
    mocker.patch.object(demisto, "error")
    client.get_alert.return_value = {
        "id": "123",
        "queue_state": "needs_review",
        "entity_state": "down",
    }

    args = {
        "data": {"queue_state": "needs_review"},
        "delta": {"closeNotes": "Resolved in XSOAR"},
        "incidentChanged": True,
        "remoteId": "123",
        "status": IncidentStatus.DONE,
    }

    result = update_remote_system_command(client, args)

    assert result == "123"
    client.get_alert.assert_called_once_with(id="123", entity="")
    client.update_alert.assert_called_once_with(
        queue_state="archived",
        entity_state="down",
        comment="Resolved in XSOAR",
        alert_id="123",
    )
    demisto.error.assert_not_called()


def test_update_remote_system_incident_not_closed(mocker, capfd):
    """Test update_remote_system_command when the incident is not closed."""

    mocker.patch.object(demisto, "debug")
    mocker.patch.object(demisto, "error")
    mocker.patch.object(demisto, "command", return_value="update-remote-system")

    client = MagicMock()
    args = {
        "data": {"queue_state": "active"},
        "entries": [],
        "incidentChanged": True,
        "remoteId": "123456",
        "status": IncidentStatus.ACTIVE,
    }

    with capfd.disabled():
        update_remote_system_command(client, args)

    demisto.debug.assert_called_with("Incident not closed. Skipping update for remote ID [123456].")
    client.get_alert.assert_not_called()
    client.update_alert.assert_not_called()


def test_update_remote_system_already_archived_with_comment(client, mocker):
    """Already-archived alerts still receive close notes when the XSOAR incident is closed."""
    mocker.patch.object(demisto, "debug")
    mocker.patch.object(demisto, "error")
    client.get_alert.return_value = {
        "id": "123",
        "queue_state": "archived",
        "entity_state": "down",
    }

    args = {
        "data": {},
        "delta": {"closeNotes": "Closing note"},
        "incidentChanged": True,
        "remoteId": "123",
        "status": IncidentStatus.DONE,
    }

    assert update_remote_system_command(client, args) == "123"
    client.update_alert.assert_called_once_with(
        queue_state="archived",
        entity_state="down",
        comment="Closing note",
        alert_id="123",
    )


def test_update_remote_system_already_archived_without_comment(client, mocker):
    """Skip the API call when the alert is already archived and there are no close notes."""
    mocker.patch.object(demisto, "debug")
    mocker.patch.object(demisto, "error")
    client.get_alert.return_value = {
        "id": "123",
        "queue_state": "archived",
        "entity_state": "down",
    }

    args = {
        "data": {},
        "delta": {},
        "incidentChanged": True,
        "remoteId": "123",
        "status": IncidentStatus.DONE,
    }

    assert update_remote_system_command(client, args) == "123"
    client.update_alert.assert_not_called()


def test_normalize_entity_content_for_grid_root_domain():
    """Domains entity_content.root_domain becomes a one-row grid list."""
    entity_content = {
        "root_domain": {
            "domain": "1.com",
            "registrar": None,
            "ip_address": None,
            "mx_records": [],
            "nameservers": [],
        }
    }
    assert _normalize_entity_content_for_grid(entity_content) == [
        {
            "domain": "1.com",
            "registrar": None,
            "ip_address": None,
            "mx_records": [],
            "nameservers": [],
        }
    ]


def test_normalize_entity_content_for_grid_passthrough_list():
    """Already-normalized lists are returned unchanged (dict rows only)."""
    rows = [{"domain": "a.com"}, {"domain": "b.com"}]
    assert _normalize_entity_content_for_grid(rows) == rows
    assert _normalize_entity_content_for_grid([]) == []
    assert _normalize_entity_content_for_grid(None) == []


def test_normalize_entity_content_for_grid_single_nested_dict():
    """Non-domain archetypes ({archetype_key: {fields}}) unwrap the single nested dict."""
    entity_content = {"social_media_post": {"full_text": "spam", "num_upvotes": 3}}
    assert _normalize_entity_content_for_grid(entity_content) == [{"full_text": "spam", "num_upvotes": 3}]


def test_normalize_entity_content_for_grid_flat_dict_fallback():
    """A flat dict with no nested objects is used as the grid row so no data is dropped."""
    entity_content = {"domain": "flat.com", "registrar": "R"}
    assert _normalize_entity_content_for_grid(entity_content) == [{"domain": "flat.com", "registrar": "R"}]
    # Ambiguous shapes with multiple nested dicts still return no rows.
    ambiguous = {"a": {"x": 1}, "b": {"y": 2}}
    assert _normalize_entity_content_for_grid(ambiguous) == []


def test_alert_to_incident_normalizes_entity_content():
    """Fetched incidents put grid-shaped entity_content into rawJSON for the mapper."""
    alert = {
        "id": "TST-3620",
        "created_at": "2026-07-31T13:18:52.149692",
        "severity": "medium",
        "entity_content": {"root_domain": {"domain": "1.com", "registrar": None}},
    }
    incident = _alert_to_incident(alert, {"mirror_direction": "Both"})
    raw = json.loads(incident["rawJSON"])
    assert raw["entity_content"] == [{"domain": "1.com", "registrar": None}]


def test_get_remote_updated_incident_data_normalizes_entity_content():
    """Incoming mirror sync also shapes entity_content for the grid field."""
    mock_client = MagicMock()
    mock_client.get_alert.return_value = {
        "id": "TST-3620",
        "queue_state": "archived",
        "entity_content": {"root_domain": {"domain": "1.com"}},
        "audit_logs": [],
    }

    updated_alert, _entries = _get_remote_updated_incident_data_with_entry(mock_client, "TST-3620", "2025-02-24T14:30:00.120000Z")

    assert updated_alert is not None
    assert updated_alert["entity_content"] == [{"domain": "1.com"}]


def test_get_mapping_fields_command(client, mocker):
    """Test get_mapping_fields_command function."""

    # Mocking demisto functions using mocker.patch.object
    mock_debug = mocker.patch.object(demisto, "debug")

    # Run the function
    result = get_mapping_fields_command(client, {})

    # Assertions
    assert result is not None, "Result should not be None"
    assert hasattr(result, "extract_mapping"), "Result should have extract_mapping method"

    mapping = result.extract_mapping()
    assert mapping["Doppel Alert"]["queue_state"] == "Queue State of the Doppel Alert"
    assert mapping["Doppel Alert"]["entity_state"] == "Current state of the alert entity"
    assert mapping["Doppel Alert"]["doppel_link"] == "Link to the alert in the Doppel platform"
    assert mapping["Doppel Alert"]["entity_content"] == "Additional content related to the alert entity"

    mock_debug.assert_called()  # Ensure debug logs are generated


def test_get_mapping_fields_command_raises_exception(mocker):
    """Test get_mapping_fields_command function when an exception occurs."""

    # Mock the SchemeTypeMapping to raise an exception
    mock_scheme = mocker.patch("Doppel.SchemeTypeMapping")
    mock_scheme.return_value.add_field.side_effect = Exception("Unexpected Error")

    # Run the function and verify it raises an exception
    with pytest.raises(Exception, match="Unexpected Error"):
        get_mapping_fields_command(client=None, args={})


def test_doppel_get_alert_command(client, mocker):
    # Mock API response
    mocker.patch.object(client, "get_alert", return_value={"id": "TET-1953443", "status": "Open", "name": "Test Alert"})

    args = {"id": "TET-1953443"}
    result = doppel_get_alert_command(client, args)

    assert isinstance(result, CommandResults), f"Expected CommandResults but got {type(result)}"
    assert result.outputs_prefix == "Doppel.Alert"
    assert result.outputs_key_field == "id"
    assert result.outputs.get("id") == "TET-1953443"
    assert "Alert Summary" in result.readable_output


def test_doppel_get_alert_command_with_invalid_params(client):
    args = {"id": "TET-1953443", "entity": "http://test-doppel.com"}

    with pytest.raises(ValueError):
        doppel_get_alert_command(client, args)


def test_doppel_get_alert_command_with_missing_params(client):
    args = {}

    with pytest.raises(ValueError):
        doppel_get_alert_command(client, args)


def mock_no_alert_found(*args, **kwargs):
    raise DemistoException("No alert found with the given parameters.")


def test_doppel_get_alert_command_with_no_alert_found(client, mocker):
    mocker.patch.object(client, "get_alert", side_effect=mock_no_alert_found)

    args = {"id": "NON_EXISTENT_ID"}

    with pytest.raises(Exception):
        doppel_get_alert_command(client, args)


def test_doppel_update_alert_command(mocker):
    """Test doppel_update_alert_command function with an inline mock client."""

    # Mocking the Client instance
    mock_client = MagicMock()
    mock_client.update_alert.return_value = {"id": "123", "queue_state": "archived", "entity_state": "closed"}

    # Sample arguments
    args = {"alert_id": "123", "queue_state": "archived", "entity_state": "closed", "comment": "Resolved"}

    # Run the function
    result = doppel_update_alert_command(mock_client, args)

    # Assertions
    assert result.outputs_prefix == "Doppel.UpdatedAlert", "Incorrect outputs prefix"
    assert result.outputs_key_field == "id", "Incorrect key field"
    assert result.outputs == {"id": "123", "queue_state": "archived", "entity_state": "closed"}, "Unexpected output"


def test_doppel_update_alert_command_negative_cases():
    """Test doppel_update_alert_command for various negative scenarios."""

    mock_client = MagicMock()

    # Case 1: Both alert_id and entity are provided
    args_conflict = {"alert_id": "123", "entity": "some_entity", "queue_state": "archived"}
    with pytest.raises(ValueError, match="Only one of 'alert_id' or 'entity' can be specified."):
        doppel_update_alert_command(mock_client, args_conflict)

    # Case 2: No update fields provided
    args_missing_fields = {"alert_id": "123"}
    with pytest.raises(ValueError, match="At least one of 'queue_state', 'entity_state', or 'comment' must be provided."):
        doppel_update_alert_command(mock_client, args_missing_fields)

    # Case 3: API Failure (Simulated by raising an exception in mock)
    mock_client.update_alert.side_effect = Exception("API error: Alert not found")
    args_api_error = {"alert_id": "999", "queue_state": "archived"}
    with pytest.raises(Exception, match="Failed to update the alert with the given parameters :- API error: Alert not found"):
        doppel_update_alert_command(mock_client, args_api_error)


def test_doppel_update_alert_command_with_entity(client, mocker):
    # Prepare the mock response for the _http_request function
    mocker.patch.object(client, "_http_request", side_effect=mock_http_request)

    # Sample arguments to simulate the command input, using 'entity' instead of 'alert_id'
    args = {
        "alert_id": "",  # Empty alert_id to test entity usage
        "queue_state": "doppel_review",
        "entity_state": "active",
        "entity": "http://test-doppel.com",  # Provide an entity for testing
        "comment": "Test update comment",
    }

    mock_response = util_load_json("test_data/get-alert.json")

    # Set up the mock return value
    client.update_alert.return_value = mock_response

    # Call the command function
    result = doppel_update_alert_command(client, args)

    # Assert that the result's human-readable output is generated correctly
    assert "Alert Summary" in result.readable_output  # Check if the title exists
    assert isinstance(result, CommandResults)  # Ensure the result is a CommandResults object
    assert result.outputs_prefix == "Doppel.UpdatedAlert"  # Ensure the outputs prefix is correct
    assert result.outputs_key_field == "id"  # Ensure the key field is correct
    assert result.outputs == mock_response  # Ensure the correct output is returned


def test_doppel_get_alerts_command(client, mocker):
    mock_data = util_load_json("test_data/get-all-alerts.json")
    mocker.patch.object(client, "get_alerts", return_value=mock_data)

    args = {
        "search_key": "test-key",
        "queue_state": "open",
        "product": "domains",
        "created_before": "2025-01-01T00:00:00Z",
        "created_after": "2025-01-01T00:00:00Z",
        "sort_type": "created",
        "sort_order": "asc",
        "page": 1,
        "tags": "tag1,tag2",
    }

    result = doppel_get_alerts_command(client, args)

    assert isinstance(result, CommandResults)

    assert result.outputs_prefix == "Doppel.GetAlerts"
    assert result.outputs_key_field == "id"
    assert result.outputs["alerts"][0]["id"] == "TET-1953443"
    assert "Alert Summary" in result.readable_output


def test_doppel_get_alerts_command_no_results(client, mocker):
    """Test doppel_get_alerts_command when no alerts are found."""

    # Mock the API response to return an empty list
    mocker.patch.object(client, "get_alerts", return_value={"alerts": []})

    args = {
        "search_key": "non-existent-key",
        "queue_state": "closed",
        "product": "unknown",
        "created_before": "2025-01-01T00:00:00Z",
        "created_after": "2025-01-01T00:00:00Z",
        "sort_type": "created",
        "sort_order": "asc",
        "page": 1,
        "tags": "invalid-tag",
    }

    result = doppel_get_alerts_command(client, args)

    assert isinstance(result, CommandResults)
    assert result.outputs == {"alerts": []}  # Expecting an empty result
    assert "No alerts were found" not in result.readable_output  # Should not raise an error, just be empty


def test_doppel_get_alerts_command_api_error(client, mocker):
    """Test doppel_get_alerts_command when API raises an exception."""

    # Mock the API call to raise an exception
    mocker.patch.object(client, "get_alerts", side_effect=Exception("API failure"))

    args = {
        "search_key": "test-key",
        "queue_state": "open",
        "product": "domains",
        "created_before": "2025-01-01T00:00:00Z",
        "created_after": "2025-01-01T00:00:00Z",
        "sort_type": "created",
        "sort_order": "asc",
        "page": 1,
        "tags": "tag1,tag2",
    }

    with pytest.raises(Exception, match="No alerts were found with the given parameters :- API failure."):
        doppel_get_alerts_command(client, args)


def test_doppel_create_alert_command(client, mocker):
    test_response = util_load_json("test_data/create-alert.json")

    client.create_alert.return_value = test_response

    args = {
        "entity": "test-doppel.com"  # Ensure 'entity' is included in the arguments
    }

    result = doppel_create_alert_command(client, args)

    assert isinstance(result, CommandResults)

    assert result.outputs_prefix == "Doppel.CreatedAlert"
    assert result.outputs_key_field == "id"
    assert result.outputs == test_response  # Check if the result matches the mocked response

    assert "Alert Summary" in result.readable_output


def test_doppel_create_alert_command_missing_entity(client):
    """Test case when 'entity' is missing in the arguments."""
    args = {}  # Missing 'entity'

    with pytest.raises(ValueError, match="Entity must be specified to create an alert."):
        doppel_create_alert_command(client, args)


def test_doppel_create_alert_command_failure(mocker):
    """Test doppel_create_alert_command when alert creation fails."""
    # Mock client
    mock_client = MagicMock()

    # Simulate API failure
    mock_client.create_alert.side_effect = Exception("API call failed")

    # Define arguments
    test_args = {"entity": "test_entity"}

    # Verify exception is raised
    with pytest.raises(Exception, match="Failed to create the alert with the given parameters:- API call failed"):
        doppel_create_alert_command(client=mock_client, args=test_args)


def test_doppel_get_alerts_no_results(mocker):
    """Test when no alerts are found (empty response)."""

    mock_client = MagicMock()
    mock_client.get_alerts.return_value = {"alerts": []}

    test_args = {"queue_state": "resolved"}

    result = doppel_get_alerts_command(mock_client, test_args)

    assert isinstance(result, CommandResults)
    assert result.outputs_prefix == "Doppel.GetAlerts"
    assert result.outputs == {"alerts": []}
    assert "No alerts were found" not in result.readable_output


def test_doppel_get_alerts_missing_params(mocker):
    """Test when query parameters are missing."""

    mock_client = MagicMock()
    mock_client.get_alerts.return_value = {"alerts": [{"id": "125", "name": "Alert"}]}

    test_args = {}  # No parameters provided

    result = doppel_get_alerts_command(mock_client, test_args)

    assert isinstance(result, CommandResults)
    assert result.outputs_prefix == "Doppel.GetAlerts"
    assert len(result.outputs) == 1
    assert result.outputs["alerts"][0]["id"] == "125"


def test_doppel_get_alerts_optional_params(mocker):
    """Test handling of optional parameters like tags and pagination."""

    mock_client = MagicMock()
    mock_client.get_alerts.return_value = {"alerts": [{"id": "126", "name": "Optional Param Test"}]}

    test_args = {"tags": "phishing,low", "page": "2"}

    result = doppel_get_alerts_command(mock_client, test_args)

    assert isinstance(result, CommandResults)
    assert result.outputs_prefix == "Doppel.GetAlerts"
    assert len(result.outputs) == 1
    assert result.outputs["alerts"][0]["name"] == "Optional Param Test"


def test_doppel_create_abuse_alert_command(client, mocker):
    test_response = util_load_json("test_data/create-abuse-alert.json")

    client.create_abuse_alert.return_value = test_response

    args = {"entity": "test-doppel.com"}

    result = doppel_create_abuse_alert_command(client, args)

    assert isinstance(result, CommandResults)

    assert result.outputs_prefix == "Doppel.AbuseAlert"
    assert result.outputs_key_field == "id"

    expected_output = util_load_json("test_data/create-abuse-alert.json")

    assert result.outputs == expected_output

    assert "Alert Summary" in result.readable_output


def test_doppel_create_abuse_alert_command_missing_entity(client):
    args = {}

    with pytest.raises(ValueError, match="Entity must be specified to create an abuse alert."):
        doppel_create_abuse_alert_command(client, args)


def test_doppel_create_abuse_alert_command_failure(mocker):
    """Test doppel_create_abuse_alert_command when abuse alert creation fails."""
    # Mock client
    mock_client = MagicMock()

    # Simulate API failure
    mock_client.create_abuse_alert.side_effect = Exception("API call failed")

    # Define arguments
    test_args = {"entity": "test_entity"}

    # Verify exception is raised
    with pytest.raises(Exception, match="Failed to create the abuse alert with the given parameters:- API call failed"):
        doppel_create_abuse_alert_command(client=mock_client, args=test_args)


def test_get_modified_remote_data_command(mocker):
    """
    Test that `get_modified_remote_data_command` returns modified incident IDs.
    """
    mock_client = MagicMock()
    mock_alerts = [
        {"id": "alert-001", "name": "Alert 1"},
        {"id": "alert-002", "name": "Alert 2"},
    ]
    mock_client.get_alerts.return_value = {"alerts": mock_alerts}

    args = {"lastUpdate": "2025-02-24T14:30:00Z"}

    mocker.patch.object(demisto, "debug")

    result = get_modified_remote_data_command(mock_client, args)

    assert result.modified_incident_ids == ["alert-001", "alert-002"]


def test_doppel_update_alert_both_alert_id_and_entity(mocker):
    """Test failure when both alert_id and entity are provided."""

    mock_client = MagicMock()

    test_args = {"alert_id": "123", "entity": "TestEntity", "queue_state": "open"}

    with pytest.raises(ValueError, match="Only one of 'alert_id' or 'entity' can be specified."):
        doppel_update_alert_command(mock_client, test_args)


def test_doppel_update_alert_no_update_fields(mocker):
    """Test failure when no update fields are provided."""

    mock_client = MagicMock()

    test_args = {"alert_id": "123"}

    with pytest.raises(ValueError, match="At least one of 'queue_state', 'entity_state', or 'comment' must be provided."):
        doppel_update_alert_command(mock_client, test_args)


def test_doppel_update_alert_api_failure(mocker):
    """Test API failure handling when an exception is raised."""

    mock_client = MagicMock()
    mock_client.update_alert.side_effect = Exception("API error")

    test_args = {"alert_id": "123", "queue_state": "open"}

    with pytest.raises(Exception, match="Failed to update the alert with the given parameters"):
        doppel_update_alert_command(mock_client, test_args)


def test_doppel_update_alert_partial_update(mocker):
    """Test updating an alert with only one field (entity_state)."""

    mock_client = MagicMock()
    mock_client.update_alert.return_value = {"id": "124", "entity_state": "investigating"}

    test_args = {"alert_id": "124", "entity_state": "investigating"}

    result = doppel_update_alert_command(mock_client, test_args)

    assert isinstance(result, CommandResults)
    assert result.outputs_prefix == "Doppel.UpdatedAlert"
    assert result.outputs["id"] == "124"
    assert result.outputs["entity_state"] == "investigating"


def test_doppel_update_alert_only_entity(mocker):
    """Test updating an alert using 'entity' instead of 'alert_id'."""

    mock_client = MagicMock()
    mock_client.update_alert.return_value = {"id": "125", "queue_state": "open", "entity": "TestEntity"}

    test_args = {"entity": "TestEntity", "queue_state": "open"}

    result = doppel_update_alert_command(mock_client, test_args)

    assert isinstance(result, CommandResults)
    assert result.outputs_prefix == "Doppel.UpdatedAlert"
    assert result.outputs["entity"] == "TestEntity"
    assert result.outputs["queue_state"] == "open"


def test_doppel_update_alert_only_queue_state(mocker):
    """Test updating an alert with only queue_state provided."""

    mock_client = MagicMock()
    mock_client.update_alert.return_value = {"id": "126", "queue_state": "archived"}

    test_args = {"alert_id": "126", "queue_state": "archived"}

    result = doppel_update_alert_command(mock_client, test_args)

    assert isinstance(result, CommandResults)
    assert result.outputs_prefix == "Doppel.UpdatedAlert"
    assert result.outputs["queue_state"] == "archived"


def test_format_datetime():
    """Test format_datetime with various datetime formats."""

    # Test valid ISO 8601 format
    assert format_datetime("2025-02-27T14:30:00") == "2025-02-27T14:30:00"

    # Test ISO 8601 with 'Z'
    assert format_datetime("2025-02-27T14:30:00Z") == "2025-02-27T14:30:00+00:00"

    # Test empty input
    assert format_datetime("") is None

    # Test None input
    assert format_datetime(None) is None

    # Test invalid format
    with pytest.raises(ValueError):
        format_datetime("invalid-date")


def test_paginated_call_to_get_alerts():
    """Test the _paginated_call_to_get_alerts function."""

    # Mock client and response
    mock_client = MagicMock()
    mock_client.get_alerts.return_value = {"alerts": [{"id": "alert1"}, {"id": "alert2"}]}

    # Define test inputs
    page = 1
    last_fetch_datetime = datetime(2025, 2, 27, 14, 30, 0)

    # Call function
    result = _paginated_call_to_get_alerts(mock_client, page, last_fetch_datetime)

    # Assertions
    expected_query_params = {
        "created_after": last_fetch_datetime.strftime(DOPPEL_API_DATE_FORMAT),
        "sort_type": "date_sourced",
        "sort_order": "asc",
        "page": page,
        "page_size": 200,
    }

    mock_client.get_alerts.assert_called_once_with(params=expected_query_params)  # Ensure correct API call
    assert isinstance(result, list)  # Should return a list
    assert len(result) == 2  # Should return 2 alerts
    assert result[0]["id"] == "alert1"  # Validate alert content
    assert result[1]["id"] == "alert2"

    # Test case where no alerts are returned
    mock_client.get_alerts.return_value = {}
    result = _paginated_call_to_get_alerts(mock_client, page, last_fetch_datetime)
    assert result is None  # Should return None if no alerts key exists


def test_get_last_fetch_datetime():
    """Test _get_last_fetch_datetime with different inputs."""

    # Test case: Valid last_run timestamp
    last_run = "2025-02-24T14:30:00Z"
    expected_datetime = datetime.strptime(last_run, "%Y-%m-%dT%H:%M:%SZ")
    assert _get_last_fetch_datetime(last_run) == expected_datetime

    # Test case: No last_run, using first_fetch with "3 days"
    result = _get_last_fetch_datetime(None)
    assert isinstance(result, datetime)  # Ensure result is a datetime object

    # Test case: Invalid last_run format should raise ValueError
    with pytest.raises(ValueError):
        _get_last_fetch_datetime("invalid-date")


def test_get_mirroring_fields():
    """Test _get_mirroring_fields function."""

    # Mocking expected return values
    demisto_params = {"mirror_direction": "Both"}
    demisto_instance = "Test_Integration"

    # Setting mock values manually
    demisto.params = lambda: demisto_params
    demisto.integrationInstance = lambda: demisto_instance

    expected_result = {
        "mirror_direction": MIRROR_DIRECTION.get("Both"),
        "mirror_instance": "Test_Integration",
        "incident_type": "Doppel_Incident",
    }

    assert _get_mirroring_fields() == expected_result


def test_get_remote_updated_incident_data_with_entry():
    """Test _get_remote_updated_incident_data_with_entry with a mock client."""

    # Mock client
    mock_client = MagicMock()

    # Test data
    doppel_alert_id = "12345"
    last_update_str = "2025-02-24T14:30:00.120000Z"  # ISO format

    # Mock API response
    mock_client.get_alert.return_value = {
        "id": doppel_alert_id,
        "audit_logs": [
            {"timestamp": "2024-11-27T06:51:50.357664", "type": "alert_create"},
            {"timestamp": "2024-11-27T06:51:50.357664", "type": "alert_create"},
        ],
    }

    # Call function
    updated_alert, entries = _get_remote_updated_incident_data_with_entry(mock_client, doppel_alert_id, last_update_str)

    # Assertions
    assert updated_alert or updated_alert is None, "Updated alert should be either valid or None"


def test_get_remote_updated_incident_data_never_synced_timestamp():
    """
    Given:
        - A lastUpdate timestamp of a never-synced incident ("0001-01-01T00:00:00Z", no microseconds).
    When:
        - Running _get_remote_updated_incident_data_with_entry.
    Then:
        - The unparseable timestamp does not raise, and the updated alert is still returned
          so the first incoming mirror sync completes.
    """
    mock_client = MagicMock()
    mock_client.get_alert.return_value = {
        "id": "12345",
        "queue_state": "actioned",
        "audit_logs": [{"timestamp": "2024-11-27T06:51:50.357664", "type": "alert_create"}],
    }

    updated_alert, entries = _get_remote_updated_incident_data_with_entry(mock_client, "12345", "0001-01-01T00:00:00Z")

    assert updated_alert is not None
    assert updated_alert["queue_state"] == "actioned"
    assert len(entries) == 1


def test_get_remote_updated_incident_data_no_audit_logs():
    """
    Given:
        - An updated alert whose payload has no audit logs.
    When:
        - Running _get_remote_updated_incident_data_with_entry.
    Then:
        - The alert field updates are still returned (not discarded), with no note entries.
    """
    mock_client = MagicMock()
    mock_client.get_alert.return_value = {
        "id": "12345",
        "queue_state": "actioned",
    }

    updated_alert, entries = _get_remote_updated_incident_data_with_entry(mock_client, "12345", "2025-02-24T14:30:00.120000Z")

    assert updated_alert is not None
    assert updated_alert["queue_state"] == "actioned"
    assert entries == []


def test_get_remote_updated_incident_data_empty_audit_logs():
    """
    Given:
        - An updated alert whose audit_logs list is empty.
    When:
        - Running _get_remote_updated_incident_data_with_entry.
    Then:
        - No exception is raised and the alert field updates are still returned.
    """
    mock_client = MagicMock()
    mock_client.get_alert.return_value = {
        "id": "12345",
        "queue_state": "actioned",
        "audit_logs": [],
    }

    updated_alert, entries = _get_remote_updated_incident_data_with_entry(mock_client, "12345", "2025-02-24T14:30:00.120000Z")

    assert updated_alert is not None
    assert updated_alert["queue_state"] == "actioned"
    assert entries == []


def test_get_modified_remote_data_command_paginates(mocker):
    """
    Given:
        - More modified alerts than fit in a single API page.
    When:
        - Running get_modified_remote_data_command.
    Then:
        - All pages are drained and every modified alert ID is returned exactly once.
    """
    mock_client = MagicMock()
    first_page = [{"id": f"alert-{i:03d}"} for i in range(200)]
    second_page = [{"id": f"alert-{i:03d}"} for i in range(200, 250)]
    mock_client.get_alerts.side_effect = [{"alerts": first_page}, {"alerts": second_page}]

    mocker.patch.object(demisto, "debug")

    result = get_modified_remote_data_command(mock_client, {"lastUpdate": "2025-02-24T14:30:00Z"})

    assert len(result.modified_incident_ids) == 250
    assert result.modified_incident_ids[0] == "alert-000"
    assert result.modified_incident_ids[-1] == "alert-249"
    assert mock_client.get_alerts.call_count == 2
    first_call_params = mock_client.get_alerts.call_args_list[0][1]["params"]
    second_call_params = mock_client.get_alerts.call_args_list[1][1]["params"]
    assert first_call_params["page"] == 0
    assert second_call_params["page"] == 1
    assert first_call_params["page_size"] == 200


def test_client_initialization_with_proxy(mocker):
    """Test Client initialization with proxy enabled."""
    base_url = "https://api.doppel.com/v1"
    api_key = "test-api-key"

    # Mock BaseClient.__init__ to verify proxy is passed correctly
    mock_base_init = mocker.patch("Doppel.BaseClient.__init__", return_value=None)

    # Create client with proxy enabled
    Client(base_url=base_url, api_key=api_key, proxy=True, verify=True)

    # Verify BaseClient was initialized with proxy=True
    mock_base_init.assert_called_once()
    call_kwargs = mock_base_init.call_args[1]
    assert call_kwargs["proxy"]
    assert call_kwargs["verify"]


def test_client_initialization_without_proxy(mocker):
    """Test Client initialization with proxy disabled."""
    base_url = "https://api.doppel.com/v1"
    api_key = "test-api-key"

    # Mock BaseClient.__init__
    mock_base_init = mocker.patch("Doppel.BaseClient.__init__", return_value=None)

    # Create client with proxy disabled
    Client(base_url=base_url, api_key=api_key, proxy=False, verify=True)

    # Verify BaseClient was initialized with proxy=False
    mock_base_init.assert_called_once()
    call_kwargs = mock_base_init.call_args[1]
    assert call_kwargs["proxy"] is False


def test_client_initialization_proxy_default_none(mocker):
    """Test Client initialization with proxy parameter not specified (defaults to None)."""
    base_url = "https://api.doppel.com/v1"
    api_key = "test-api-key"

    # Mock BaseClient.__init__
    mock_base_init = mocker.patch("Doppel.BaseClient.__init__", return_value=None)

    # Create client without specifying proxy
    Client(base_url=base_url, api_key=api_key, verify=True)

    # Verify BaseClient was initialized with proxy=None
    mock_base_init.assert_called_once()
    call_kwargs = mock_base_init.call_args[1]
    assert call_kwargs["proxy"] is None


def test_client_sends_attribution_headers(requests_mock):
    """Every Doppel API request carries the x-doppel-client attribution header and User-Agent."""
    from Doppel import CLIENT_ATTRIBUTION, PACK_VERSION

    client = Client(base_url="https://api.doppel.com/v1", api_key="test-api-key", verify=True)
    alert_mock = requests_mock.get("https://api.doppel.com/v1/alert", json={"id": "TET-1"})

    client.get_alert(id="TET-1", entity="")

    assert f"xsoar/{PACK_VERSION}" == CLIENT_ATTRIBUTION
    assert alert_mock.last_request.headers["x-doppel-client"] == CLIENT_ATTRIBUTION
    assert alert_mock.last_request.headers["User-Agent"] == f"doppel-{CLIENT_ATTRIBUTION}"
    # Attribution never replaces auth headers.
    assert alert_mock.last_request.headers["x-api-key"] == "test-api-key"


SIGNED_URL_V1 = "https://storage.googleapis.com/screenshots-bucket/TET-1234/shot-v1.png?X-Goog-Signature=abc&X-Goog-Expires=3600"
SIGNED_URL_V1_RESIGNED = (
    "https://storage.googleapis.com/screenshots-bucket/TET-1234/shot-v1.png?X-Goog-Signature=zzz&X-Goog-Expires=3600"
)
SIGNED_URL_V2 = "https://storage.googleapis.com/screenshots-bucket/TET-1234/shot-v2.png?X-Goog-Signature=def&X-Goog-Expires=3600"


def _mock_screenshot_context(mocker, initial=None):
    """Mock the integration context read/write used for screenshot version tracking.

    Returns copies on read and stores copies on write, mirroring the real server
    behavior (the context is serialized, so callers never share object references).
    """
    import copy

    state = {"screenshot_versions": dict(initial or {})}
    mocker.patch("Doppel.get_integration_context", side_effect=lambda: copy.deepcopy(state))

    def _set(new_context):
        snapshot = copy.deepcopy(new_context)
        state.clear()
        state.update(snapshot)

    mocker.patch("Doppel.set_integration_context", side_effect=_set)
    return state


def test_screenshot_blob_path_ignores_signature():
    """Re-signed URLs for the same object must map to the same dedup key."""
    assert _screenshot_blob_path(SIGNED_URL_V1) == _screenshot_blob_path(SIGNED_URL_V1_RESIGNED)
    assert _screenshot_blob_path(SIGNED_URL_V1) != _screenshot_blob_path(SIGNED_URL_V2)
    assert _screenshot_blob_path(SIGNED_URL_V1) == "storage.googleapis.com/screenshots-bucket/TET-1234/shot-v1.png"


def test_get_alert_screenshot_command_attaches_new_screenshot(mocker):
    """First run downloads the screenshot and returns a file entry plus summary."""
    _mock_screenshot_context(mocker)
    file_entry = {"Type": 3, "File": "TET-1234-screenshot-shot-v1.png"}
    mocker.patch("Doppel.fileResult", return_value=file_entry)

    mock_client = MagicMock()
    mock_client.get_alert.return_value = {"id": "TET-1234", "screenshot_url": SIGNED_URL_V1}
    mock_client.download_screenshot.return_value = b"png-bytes"

    results = doppel_get_alert_screenshot_command(mock_client, {"id": "TET-1234"})

    mock_client.download_screenshot.assert_called_once_with(SIGNED_URL_V1)
    assert results[0] is file_entry
    summary = results[1]
    assert summary.outputs["attached"] is True
    assert summary.outputs["version"] == "shot-v1.png"


def test_get_alert_screenshot_command_skips_unchanged_screenshot(mocker):
    """A re-signed URL for the already-attached version attaches nothing."""
    _mock_screenshot_context(mocker, {"TET-1234": _screenshot_blob_path(SIGNED_URL_V1)})
    file_result = mocker.patch("Doppel.fileResult")

    mock_client = MagicMock()
    mock_client.get_alert.return_value = {"id": "TET-1234", "screenshot_url": SIGNED_URL_V1_RESIGNED}

    results = doppel_get_alert_screenshot_command(mock_client, {"id": "TET-1234"})

    mock_client.download_screenshot.assert_not_called()
    file_result.assert_not_called()
    assert len(results) == 1
    assert results[0].outputs["attached"] is False
    assert "already current" in results[0].readable_output


def test_get_alert_screenshot_command_force_reattaches(mocker):
    """force=true re-downloads even when the version is current."""
    _mock_screenshot_context(mocker, {"TET-1234": _screenshot_blob_path(SIGNED_URL_V1)})
    mocker.patch("Doppel.fileResult", return_value={"Type": 3})

    mock_client = MagicMock()
    mock_client.get_alert.return_value = {"id": "TET-1234", "screenshot_url": SIGNED_URL_V1_RESIGNED}
    mock_client.download_screenshot.return_value = b"png-bytes"

    results = doppel_get_alert_screenshot_command(mock_client, {"id": "TET-1234", "force": "true"})

    mock_client.download_screenshot.assert_called_once()
    assert results[-1].outputs["attached"] is True


def test_get_alert_screenshot_command_new_version_replaces_tracked(mocker):
    """A new screenshot version is attached and becomes the tracked version."""
    context = _mock_screenshot_context(mocker, {"TET-1234": _screenshot_blob_path(SIGNED_URL_V1)})
    mocker.patch("Doppel.fileResult", return_value={"Type": 3})

    mock_client = MagicMock()
    mock_client.get_alert.return_value = {"id": "TET-1234", "screenshot_url": SIGNED_URL_V2}
    mock_client.download_screenshot.return_value = b"new-png-bytes"

    results = doppel_get_alert_screenshot_command(mock_client, {"id": "TET-1234"})

    assert results[-1].outputs["attached"] is True
    assert context["screenshot_versions"]["TET-1234"] == _screenshot_blob_path(SIGNED_URL_V2)


def test_get_alert_screenshot_command_no_screenshot(mocker):
    """Alerts without screenshots return a readable message and no file."""
    _mock_screenshot_context(mocker)

    mock_client = MagicMock()
    mock_client.get_alert.return_value = {"id": "TET-1234"}

    results = doppel_get_alert_screenshot_command(mock_client, {"id": "TET-1234"})

    mock_client.download_screenshot.assert_not_called()
    assert len(results) == 1
    assert "no screenshot available" in results[0].readable_output


def test_get_alert_screenshot_command_requires_id(mocker):
    with pytest.raises(ValueError, match="id must be specified"):
        doppel_get_alert_screenshot_command(MagicMock(), {})


def test_mirroring_attaches_screenshot_when_param_enabled(mocker):
    """get-remote-data appends the screenshot file entry when the opt-in param is set."""
    from Doppel import _get_remote_updated_incident_data_with_entry

    _mock_screenshot_context(mocker)
    file_entry = {"Type": 3, "File": "TET-1234-screenshot-shot-v1.png"}
    mocker.patch("Doppel.fileResult", return_value=file_entry)
    mock_client = MagicMock()
    mock_client.get_alert.return_value = {"queue_state": "archived", "screenshot_url": SIGNED_URL_V1, "audit_logs": []}
    mock_client.download_screenshot.return_value = b"png-bytes"

    _, entries = _get_remote_updated_incident_data_with_entry(
        mock_client, "TET-1234", "2025-01-19T08:44:52Z", attach_screenshots=True
    )

    assert file_entry in entries


def test_mirroring_skips_screenshot_when_param_disabled(mocker):
    """Default behavior: no screenshot download during mirroring."""
    from Doppel import _get_remote_updated_incident_data_with_entry

    mock_client = MagicMock()
    mock_client.get_alert.return_value = {"queue_state": "archived", "screenshot_url": SIGNED_URL_V1, "audit_logs": []}

    _, entries = _get_remote_updated_incident_data_with_entry(mock_client, "TET-1234", "2025-01-19T08:44:52Z")

    mock_client.download_screenshot.assert_not_called()
    assert entries == []


def test_mirroring_skips_unchanged_screenshot_version(mocker):
    """Re-signed URL for an unchanged screenshot never duplicates the file on sync."""
    from Doppel import _get_remote_updated_incident_data_with_entry

    _mock_screenshot_context(mocker, {"TET-1234": _screenshot_blob_path(SIGNED_URL_V1)})
    file_result = mocker.patch("Doppel.fileResult")

    mock_client = MagicMock()
    mock_client.get_alert.return_value = {"queue_state": "archived", "screenshot_url": SIGNED_URL_V1_RESIGNED, "audit_logs": []}

    _, entries = _get_remote_updated_incident_data_with_entry(
        mock_client, "TET-1234", "2025-01-19T08:44:52Z", attach_screenshots=True
    )

    mock_client.download_screenshot.assert_not_called()
    file_result.assert_not_called()
    assert entries == []


def test_mirroring_screenshot_failure_does_not_block_sync(mocker):
    """A download error must not prevent the field sync itself."""
    from Doppel import _get_remote_updated_incident_data_with_entry

    _mock_screenshot_context(mocker)

    mock_client = MagicMock()
    mock_client.get_alert.return_value = {"queue_state": "archived", "screenshot_url": SIGNED_URL_V1, "audit_logs": []}
    mock_client.download_screenshot.side_effect = Exception("GCS unreachable")

    updated_alert, entries = _get_remote_updated_incident_data_with_entry(
        mock_client, "TET-1234", "2025-01-19T08:44:52Z", attach_screenshots=True
    )

    assert updated_alert is not None
    assert entries == []


def test_download_screenshot_rejects_non_https():
    """The screenshot downloader refuses cleartext URLs outright."""
    from CommonServerPython import DemistoException

    client = Client(base_url="https://api.doppel.com/v1", api_key="test-api-key", verify=True)
    with pytest.raises(DemistoException, match="non-HTTPS"):
        client.download_screenshot("http://storage.googleapis.com/screenshots-bucket/TET-1234/shot-v1.png")


def test_track_screenshot_version_prunes_oldest(mocker):
    """The tracking map never grows beyond the cap; oldest entries are evicted first."""
    import Doppel as doppel_module

    context = _mock_screenshot_context(mocker)
    mocker.patch.object(doppel_module, "SCREENSHOT_VERSIONS_MAX_TRACKED", 3)

    for i in range(5):
        _track_screenshot_version(f"TET-{i}", f"bucket/shot-{i}.png")

    versions = context["screenshot_versions"]
    assert len(versions) == 3
    assert set(versions) == {"TET-2", "TET-3", "TET-4"}


def test_attach_screenshot_if_new_reports_missing_url(mocker):
    _mock_screenshot_context(mocker)
    file_entry, blob_path, message = _attach_screenshot_if_new(MagicMock(), "TET-1", None)
    assert file_entry is None
    assert blob_path is None
    assert "no screenshot available" in message


def test_pack_version_matches_pack_metadata():
    """PACK_VERSION (used in attribution headers) must match pack_metadata.json.

    pack_metadata.json is not readable at runtime, so Doppel.py carries the version as a
    hardcoded constant that must be bumped manually on every release. This test makes CI
    fail if the two ever drift apart.
    """
    from pathlib import Path

    from Doppel import PACK_VERSION

    pack_metadata_path = Path(__file__).resolve().parents[2] / "pack_metadata.json"
    pack_metadata = json.loads(pack_metadata_path.read_text())

    assert pack_metadata["currentVersion"] == PACK_VERSION, (
        f"pack_metadata.json currentVersion ({pack_metadata['currentVersion']}) does not match "
        f"PACK_VERSION ({PACK_VERSION}) in Doppel.py; bump the constant so the x-doppel-client "
        f"attribution header reports the released pack version."
    )


def test_main_function_with_proxy_enabled(mocker):
    """Test main function when proxy is enabled in params."""
    # Mock demisto functions
    mocker.patch.object(
        demisto,
        "params",
        return_value={
            "url": "https://api.doppel.com",
            "credentials": {"password": "test-api-key"},
            "proxy": True,
            "insecure": False,
        },
    )
    mocker.patch.object(demisto, "command", return_value="test-module")
    mocker.patch.object(demisto, "args", return_value={})

    # Mock Client initialization
    mock_client_init = mocker.patch("Doppel.Client")

    # Mock test_module to return 'ok'
    mocker.patch("Doppel.test_module", return_value="ok")
    mocker.patch("Doppel.return_results")

    # Call main
    from Doppel import main

    main()

    # Verify Client was called with proxy=True
    mock_client_init.assert_called_once()
    call_kwargs = mock_client_init.call_args[1]
    assert call_kwargs["proxy"] is True
    assert call_kwargs["verify"] is True


def test_main_function_with_proxy_disabled(mocker):
    """Test main function when proxy is disabled in params."""
    # Mock demisto functions
    mocker.patch.object(
        demisto,
        "params",
        return_value={
            "url": "https://api.doppel.com",
            "credentials": {"password": "test-api-key"},
            "proxy": False,
            "insecure": False,
        },
    )
    mocker.patch.object(demisto, "command", return_value="test-module")
    mocker.patch.object(demisto, "args", return_value={})

    # Mock Client initialization
    mock_client_init = mocker.patch("Doppel.Client")

    # Mock test_module to return 'ok'
    mocker.patch("Doppel.test_module", return_value="ok")
    mocker.patch("Doppel.return_results")

    # Call main
    from Doppel import main

    main()

    # Verify Client was called with proxy=False
    mock_client_init.assert_called_once()
    call_kwargs = mock_client_init.call_args[1]
    assert call_kwargs["proxy"] is False


def test_parse_fetch_timeout(mocker):
    """fetch_timeout is parsed to a float; blank/invalid/missing yields no limit (None)."""
    mocker.patch.object(demisto, "params", return_value={"fetch_timeout": "30"})
    assert _parse_fetch_timeout() == 30.0
    mocker.patch.object(demisto, "params", return_value={"fetch_timeout": ""})
    assert _parse_fetch_timeout() is None
    mocker.patch.object(demisto, "params", return_value={"fetch_timeout": None})
    assert _parse_fetch_timeout() is None
    mocker.patch.object(demisto, "params", return_value={"fetch_timeout": "abc"})
    assert _parse_fetch_timeout() is None
    mocker.patch.object(demisto, "params", return_value={})
    assert _parse_fetch_timeout() is None


def test_parse_max_fetch(mocker):
    """max_fetch is parsed to a positive int; blank/invalid/non-positive falls back to the default."""
    mocker.patch.object(demisto, "params", return_value={"max_fetch": "25"})
    assert _parse_max_fetch() == 25
    mocker.patch.object(demisto, "params", return_value={"max_fetch": ""})
    assert _parse_max_fetch() == 10
    mocker.patch.object(demisto, "params", return_value={"max_fetch": "0"})
    assert _parse_max_fetch() == 10
    mocker.patch.object(demisto, "params", return_value={"max_fetch": "-5"})
    assert _parse_max_fetch() == 10
    mocker.patch.object(demisto, "params", return_value={})
    assert _parse_max_fetch() == 10


def test_incident_alert_id():
    """The Doppel alert id is read from dbotMirrorId first, then from rawJSON, else empty."""
    assert _incident_alert_id({"dbotMirrorId": "TET-1"}) == "TET-1"
    assert _incident_alert_id({"rawJSON": json.dumps({"id": "TET-2"})}) == "TET-2"
    assert _incident_alert_id({"rawJSON": "not-json"}) == ""
    assert _incident_alert_id({}) == ""


def test_alert_to_incident():
    """An alert becomes an incident named by its external id, with dbotMirrorId, severity, and merged mirroring fields."""
    alert = {"id": "TET-1953443", "created_at": "2025-01-27T07:55:10.063742", "severity": "high"}
    incident = _alert_to_incident(alert, {"mirror_direction": "In"})
    assert incident["name"] == "Doppel Alert TET-1953443"
    assert incident["type"] == "Doppel Alert"
    assert incident["dbotMirrorId"] == "TET-1953443"
    assert incident["occurred"] == "2025-01-27T07:55:10Z"
    assert incident["severity"] == 3
    raw = json.loads(incident["rawJSON"])
    assert raw["mirror_direction"] == "In"


def test_xsoar_severity():
    """Doppel severities map to XSOAR numeric severities; unknown/blank values default to 0 (Unknown)."""
    assert _xsoar_severity({"severity": "low"}) == 1
    assert _xsoar_severity({"severity": "Medium"}) == 2
    assert _xsoar_severity({"severity": "HIGH"}) == 3
    assert _xsoar_severity({"severity": "critical"}) == 4
    assert _xsoar_severity({"severity": "bogus"}) == 0
    assert _xsoar_severity({}) == 0


def _fetch_demisto_mocks(mocker, params, last_run):
    mocker.patch.object(demisto, "params", return_value=params)
    mocker.patch.object(demisto, "getLastRun", return_value=last_run)
    set_last_run = mocker.patch.object(demisto, "setLastRun")
    mocker.patch.object(demisto, "incidents")
    mocker.patch.object(demisto, "info")
    mocker.patch.object(demisto, "debug")
    mocker.patch.object(demisto, "integrationInstance", return_value="inst")
    return set_last_run


def test_fetch_incidents_dedupes_within_run(mocker):
    """A duplicated alert id inside a single page creates only one incident."""
    _fetch_demisto_mocks(
        mocker,
        params={"max_fetch": 50, "fetch_timeout": "30", "mirror_direction": "None"},
        last_run={},
    )
    page = [
        {"id": "TET-1", "created_at": "2025-01-27T07:55:10.063742"},
        {"id": "TET-1", "created_at": "2025-01-27T07:55:10.063742"},  # duplicate id in same page
        {"id": "TET-2", "created_at": "2025-01-27T07:55:11.063742"},
    ]
    mocker.patch("Doppel._paginated_call_to_get_alerts", side_effect=[page, []])

    fetch_incidents_command(client=MagicMock(), args={})

    created = demisto.incidents.call_args[0][0]
    assert sorted(i["name"] for i in created) == ["Doppel Alert TET-1", "Doppel Alert TET-2"]


def test_fetch_incidents_skips_recently_seen_ids(mocker):
    """Ids persisted from the previous run's boundary second are not re-created on the inclusive re-pull."""
    _fetch_demisto_mocks(
        mocker,
        params={"max_fetch": 50, "fetch_timeout": "30", "mirror_direction": "None"},
        last_run={"last_run": "2025-01-27T07:55:10Z", "incidents_queue": [], "recently_seen_ids": ["TET-1"]},
    )
    page = [
        {"id": "TET-1", "created_at": "2025-01-27T07:55:10.063742"},  # seen on the prior run
        {"id": "TET-2", "created_at": "2025-01-27T07:55:12.063742"},  # genuinely new
    ]
    mocker.patch("Doppel._paginated_call_to_get_alerts", side_effect=[page, []])

    fetch_incidents_command(client=MagicMock(), args={})

    created = demisto.incidents.call_args[0][0]
    assert [i["name"] for i in created] == ["Doppel Alert TET-2"]


def test_fetch_incidents_persists_boundary_ids(mocker):
    """The cursor advances to the newest alert second and only that second's ids are persisted."""
    set_last_run = _fetch_demisto_mocks(
        mocker,
        params={"max_fetch": 50, "fetch_timeout": "30", "mirror_direction": "None"},
        last_run={},
    )
    page = [
        {"id": "TET-1", "created_at": "2025-01-27T07:55:10.063742"},
        {"id": "TET-2", "created_at": "2025-01-27T07:55:12.063742"},  # newest second
    ]
    mocker.patch("Doppel._paginated_call_to_get_alerts", side_effect=[page, []])

    fetch_incidents_command(client=MagicMock(), args={})

    created = demisto.incidents.call_args[0][0]
    assert all(i["dbotMirrorId"] for i in created)
    last_run_data = set_last_run.call_args[0][0]
    assert last_run_data["last_run"] == "2025-01-27T07:55:12Z"
    assert last_run_data["recently_seen_ids"] == ["TET-2"]


# ---------------- Product fetch filter (Select products to fetch) ----------------

V1_ALERTS_URL = "https://api.doppel.com/v1/alerts"
FETCH_FILTER_PARAMS = {"max_fetch": 50, "fetch_timeout": "30", "mirror_direction": "None"}
FETCH_FILTER_LAST_RUN = {"last_run": "2025-01-27T07:55:00Z", "recently_seen_ids": []}
FETCH_FILTER_PAGE = {
    "alerts": [
        {"id": "TET-1", "created_at": "2025-01-27T07:55:10.063742", "product": "domains"},
        {"id": "TET-2", "created_at": "2025-01-27T07:55:12.063742", "product": "social_media"},
    ]
}
# The exact query the fetch sends when no product is selected (page 0, cursor from FETCH_FILTER_LAST_RUN).
UNFILTERED_FETCH_QUERY = {
    "created_after": ["2025-01-27t07:55:00"],
    "sort_type": ["date_sourced"],
    "sort_order": ["asc"],
    "page": ["0"],
    "page_size": ["200"],
}


def _v1_client():
    return Client(base_url="https://api.doppel.com/v1", api_key="test-api-key", verify=True)


def _mock_alert_pages(requests_mock):
    """Serve one page of alerts, then an empty page, from the V1 alerts endpoint."""
    return requests_mock.get(V1_ALERTS_URL, [{"json": FETCH_FILTER_PAGE}, {"json": {"alerts": []}}])


@pytest.mark.parametrize(
    "fetch_products, expected_modules",
    [
        (None, None),
        ("", None),
        ([], None),
        ([""], None),
        (["domains"], "domains"),
        ("domains", "domains"),
        (["domains", "social_media", "telco"], "domains,social_media,telco"),
        ("domains, social_media", "domains,social_media"),
        ([" Domains ", "SOCIAL_MEDIA", "domains"], "domains,social_media"),
        (
            ["domains", "social_media", "mobile_apps", "ecommerce", "crypto", "email", "paid_ads", "telco", "darkweb"],
            "domains,social_media,mobile_apps,ecommerce,crypto,email,paid_ads,telco,darkweb",
        ),
    ],
)
def test_fetch_products_to_modules(fetch_products, expected_modules):
    """The selection becomes one comma-separated string (trimmed, lower-cased, de-duplicated), or None when empty."""
    assert _fetch_products_to_modules(fetch_products) == expected_modules


@pytest.mark.parametrize(
    "fetch_products, unsupported",
    [
        (["not_a_product"], "not_a_product"),
        (["domains", "not_a_product"], "not_a_product"),
        ("domains,severity", "severity"),
    ],
)
def test_fetch_products_to_modules_rejects_unsupported_value(fetch_products, unsupported):
    """An unsupported value raises an error that names it; it is never dropped silently."""
    with pytest.raises(DemistoException) as error:
        _fetch_products_to_modules(fetch_products)

    assert f"parameter: {unsupported}." in str(error.value)
    assert "Supported values are: domains, social_media" in str(error.value)


def test_fetch_products_match_integration_yml():
    """The values the code accepts are exactly the options the fetch_products parameter offers in Doppel.yml."""
    from pathlib import Path

    from Doppel import FETCH_PRODUCTS

    lines = (Path(__file__).resolve().parent / "Doppel.yml").read_text().splitlines()
    options_start = lines.index("  options:", lines.index("  name: fetch_products")) + 1
    options = []
    for line in lines[options_start:]:
        if not line.startswith("  - "):
            break
        options.append(line[4:].strip())

    assert tuple(options) == FETCH_PRODUCTS


def test_paginated_call_to_get_alerts_with_modules():
    """A modules value is added to the fetch query as given; product is never added."""
    mock_client = MagicMock()
    mock_client.get_alerts.return_value = {"alerts": [{"id": "alert1"}]}
    last_fetch_datetime = datetime(2025, 2, 27, 14, 30, 0)

    _paginated_call_to_get_alerts(mock_client, 0, last_fetch_datetime, "domains,social_media")

    mock_client.get_alerts.assert_called_once_with(
        params={
            "created_after": "2025-02-27T14:30:00",
            "sort_type": "date_sourced",
            "sort_order": "asc",
            "page": 0,
            "page_size": 200,
            "modules": "domains,social_media",
        }
    )


@pytest.mark.parametrize("fetch_products", [None, "", []])
def test_fetch_incidents_without_product_selection_sends_unchanged_request(mocker, requests_mock, fetch_products):
    """With no product selected, the HTTP request carries exactly the pre-filter query: no modules, no product."""
    _fetch_demisto_mocks(mocker, params=FETCH_FILTER_PARAMS, last_run=FETCH_FILTER_LAST_RUN)
    alerts_mock = _mock_alert_pages(requests_mock)

    fetch_incidents_command(_v1_client(), {}, fetch_products=fetch_products)

    assert alerts_mock.request_history[0].qs == UNFILTERED_FETCH_QUERY
    assert [i["name"] for i in demisto.incidents.call_args[0][0]] == ["Doppel Alert TET-1", "Doppel Alert TET-2"]


def test_fetch_incidents_default_argument_sends_unchanged_request(mocker, requests_mock):
    """Callers that do not pass fetch_products at all get the unfiltered request."""
    _fetch_demisto_mocks(mocker, params=FETCH_FILTER_PARAMS, last_run=FETCH_FILTER_LAST_RUN)
    alerts_mock = _mock_alert_pages(requests_mock)

    fetch_incidents_command(_v1_client(), {})

    assert alerts_mock.request_history[0].qs == UNFILTERED_FETCH_QUERY


@pytest.mark.parametrize(
    "fetch_products, expected_modules",
    [
        (["domains"], "domains"),
        (["domains", "social_media", "telco"], "domains,social_media,telco"),
    ],
)
def test_fetch_incidents_with_product_selection_sends_single_modules_value(
    mocker, requests_mock, fetch_products, expected_modules
):
    """A selection adds one comma-separated modules value to every page request and never sends product."""
    set_last_run = _fetch_demisto_mocks(mocker, params=FETCH_FILTER_PARAMS, last_run=FETCH_FILTER_LAST_RUN)
    alerts_mock = _mock_alert_pages(requests_mock)

    fetch_incidents_command(_v1_client(), {}, fetch_products=fetch_products)

    assert alerts_mock.call_count == 2
    for page, request in enumerate(alerts_mock.request_history):
        # One value in the list means the parameter was sent once, not repeated per product.
        assert request.qs == {**UNFILTERED_FETCH_QUERY, "page": [str(page)], "modules": [expected_modules]}
        assert "product" not in request.qs
    # The filter runs in the API; the cursor still advances to the newest fetched alert.
    assert set_last_run.call_args[0][0] == {"last_run": "2025-01-27T07:55:12Z", "recently_seen_ids": ["TET-2"]}


def test_fetch_incidents_with_unsupported_product_fails_before_any_request(mocker, requests_mock):
    """An unsupported value stops the fetch with an error naming it: no request, no incidents, cursor untouched."""
    set_last_run = _fetch_demisto_mocks(mocker, params=FETCH_FILTER_PARAMS, last_run=FETCH_FILTER_LAST_RUN)
    alerts_mock = _mock_alert_pages(requests_mock)

    with pytest.raises(DemistoException, match="not_a_product"):
        fetch_incidents_command(_v1_client(), {}, fetch_products=["domains", "not_a_product"])

    assert alerts_mock.call_count == 0
    demisto.incidents.assert_not_called()
    set_last_run.assert_not_called()


def test_test_module_without_product_selection_sends_unchanged_request(requests_mock):
    """With no product selected, the test request carries only its date window."""
    alerts_mock = requests_mock.get(V1_ALERTS_URL, json={"alerts": []})

    assert test_module(_v1_client()) == "ok"

    assert set(alerts_mock.last_request.qs) == {"created_before", "created_after"}


def test_test_module_sends_configured_product_filter(requests_mock):
    """The test request carries the same single modules value as fetch, and no product."""
    alerts_mock = requests_mock.get(V1_ALERTS_URL, json={"alerts": []})

    assert test_module(_v1_client(), fetch_products=["domains", "darkweb"]) == "ok"

    assert alerts_mock.last_request.qs["modules"] == ["domains,darkweb"]
    assert set(alerts_mock.last_request.qs) == {"created_before", "created_after", "modules"}


def test_test_module_fails_when_api_rejects_product_filter(requests_mock):
    """A filter the API rejects fails the test with the API's message instead of returning ok."""
    requests_mock.get(V1_ALERTS_URL, status_code=400, json={"message": "domains is not a valid modules"})

    with pytest.raises(DemistoException, match="not a valid modules"):
        test_module(_v1_client(), fetch_products=["domains"])


def test_test_module_with_unsupported_product_fails_before_any_request(requests_mock):
    """An unsupported value fails the test with an error naming it, without calling the API."""
    alerts_mock = requests_mock.get(V1_ALERTS_URL, json={"alerts": []})

    with pytest.raises(DemistoException, match="not_a_product"):
        test_module(_v1_client(), fetch_products=["not_a_product"])

    assert alerts_mock.call_count == 0


@pytest.mark.parametrize("command", ["test-module", "fetch-incidents"])
def test_main_passes_fetch_products_param_to_request(mocker, requests_mock, command):
    """main() wires the fetch_products instance param into both the test and the fetch request."""
    from Doppel import main

    _fetch_demisto_mocks(
        mocker,
        params={
            "url": "https://api.doppel.com/",
            "credentials": {"password": "test-api-key"},
            "fetch_products": ["domains", "social_media"],
            **FETCH_FILTER_PARAMS,
        },
        last_run=FETCH_FILTER_LAST_RUN,
    )
    mocker.patch.object(demisto, "command", return_value=command)
    mocker.patch.object(demisto, "args", return_value={})
    mocker.patch("Doppel.return_results")
    return_error_mock = mocker.patch("Doppel.return_error")
    alerts_mock = _mock_alert_pages(requests_mock)

    main()

    return_error_mock.assert_not_called()
    assert alerts_mock.request_history[0].qs["modules"] == ["domains,social_media"]
    assert "product" not in alerts_mock.request_history[0].qs


@pytest.mark.parametrize("command", ["test-module", "fetch-incidents"])
def test_main_reports_unsupported_fetch_product(mocker, requests_mock, command):
    """An unsupported fetch_products value surfaces as a command error that names the value."""
    from Doppel import main

    _fetch_demisto_mocks(
        mocker,
        params={
            "url": "https://api.doppel.com/",
            "credentials": {"password": "test-api-key"},
            "fetch_products": ["not_a_product"],
            **FETCH_FILTER_PARAMS,
        },
        last_run=FETCH_FILTER_LAST_RUN,
    )
    mocker.patch.object(demisto, "command", return_value=command)
    mocker.patch.object(demisto, "args", return_value={})
    return_error_mock = mocker.patch("Doppel.return_error")
    alerts_mock = _mock_alert_pages(requests_mock)

    main()

    assert alerts_mock.call_count == 0
    assert "not_a_product" in return_error_mock.call_args[0][0]


def test_main_ignores_fetch_products_for_other_commands(mocker, requests_mock):
    """Commands other than fetch and test never read the fetch filter, so doppel-get-alerts stays unfiltered."""
    from Doppel import main

    mocker.patch.object(
        demisto,
        "params",
        return_value={
            "url": "https://api.doppel.com/",
            "credentials": {"password": "test-api-key"},
            "fetch_products": ["domains"],
        },
    )
    mocker.patch.object(demisto, "command", return_value="doppel-get-alerts")
    mocker.patch.object(demisto, "args", return_value={})
    mocker.patch("Doppel.return_results")
    return_error_mock = mocker.patch("Doppel.return_error")
    alerts_mock = requests_mock.get(V1_ALERTS_URL, json=FETCH_FILTER_PAGE)

    main()

    return_error_mock.assert_not_called()
    assert "modules" not in alerts_mock.last_request.qs


# ---------------- Revival reopen entries ----------------


def test_reopen_entry_emitted_for_fresh_transition_into_active_queue():
    """A queue move into an active queue after lastUpdate produces a dbotIncidentReopen entry."""
    last_update = datetime(2025, 3, 1, 12, 0, 0)
    alert = {"queue_state": "doppel_review"}
    audit_logs = [
        {"type": "queue_state_change", "value": "monitoring", "timestamp": "2025-02-01T09:00:00"},
        {"type": "queue_state_change", "value": "Doppel Review", "timestamp": "2025-03-02T10:00:00"},
    ]

    entry = _reopen_entry_if_revived(alert, audit_logs, last_update)

    assert entry is not None
    assert entry["Contents"] == {"dbotIncidentReopen": True}


def test_reopen_entry_not_emitted_for_inactive_queue():
    """Alerts sitting in monitoring or archived never trigger a reopen."""
    last_update = datetime(2025, 3, 1, 12, 0, 0)
    audit_logs = [{"type": "queue_state_change", "value": "archived", "timestamp": "2025-03-02T10:00:00"}]

    assert _reopen_entry_if_revived({"queue_state": "archived"}, audit_logs, last_update) is None
    assert _reopen_entry_if_revived({"queue_state": "monitoring"}, audit_logs, last_update) is None


def test_reopen_entry_not_emitted_for_stale_transition():
    """An active queue state reached before lastUpdate does not reopen on every mirror cycle."""
    last_update = datetime(2025, 3, 1, 12, 0, 0)
    alert = {"queue_state": "actioned"}
    audit_logs = [{"type": "queue_state_change", "value": "actioned", "timestamp": "2025-01-15T10:00:00"}]

    assert _reopen_entry_if_revived(alert, audit_logs, last_update) is None


def test_reopen_entry_requires_parseable_last_update():
    """Without a usable lastUpdate there is no safe transition baseline, so no reopen."""
    alert = {"queue_state": "actioned"}
    audit_logs = [{"type": "queue_state_change", "value": "actioned", "timestamp": "2025-03-02T10:00:00"}]

    assert _reopen_entry_if_revived(alert, audit_logs, None) is None


# ---------------- API V2 (OAuth 2.0 client credentials) ----------------

V2_BASE_URL = "https://api.doppel.com/v2"
V2_TOKEN_URL = "https://api.doppel.com/oauth/token"


def _v2_client():
    return Client(
        base_url=V2_BASE_URL,
        verify=True,
        api_version="v2",
        oauth_client_id="test-client-id",
        oauth_client_secret="test-client-secret",
        token_url=V2_TOKEN_URL,
    )


def _mock_integration_context(mocker, initial=None):
    """Replace the integration context with an in-memory store; returns the store."""
    store = {"ctx": initial or {}}
    mocker.patch("Doppel.get_integration_context", side_effect=lambda: store["ctx"])
    mocker.patch("Doppel.set_integration_context", side_effect=lambda ctx: store.update(ctx=ctx))
    return store


def test_v2_mints_token_and_sends_bearer(mocker, requests_mock):
    """With no cached token, a request first mints a token, caches it, and sends it as a Bearer header."""
    store = _mock_integration_context(mocker)
    token_mock = requests_mock.post(V2_TOKEN_URL, json={"access_token": "tok-1", "expires_in": 86400})
    alert_mock = requests_mock.get(f"{V2_BASE_URL}/alert", json={"id": "TET-1"})

    result = _v2_client().get_alert(id="TET-1", entity="")

    assert result == {"id": "TET-1"}
    assert token_mock.call_count == 1
    assert token_mock.last_request.json() == {
        "client_id": "test-client-id",
        "client_secret": "test-client-secret",
        "audience": "doppel-external",
        "grant_type": "client_credentials",
    }
    assert alert_mock.last_request.headers["Authorization"] == "Bearer tok-1"
    assert store["ctx"]["oauth_token"]["access_token"] == "tok-1"
    # Attribution headers ride along on both the token mint and the API request.
    from Doppel import CLIENT_ATTRIBUTION

    assert token_mock.last_request.headers["x-doppel-client"] == CLIENT_ATTRIBUTION
    assert alert_mock.last_request.headers["x-doppel-client"] == CLIENT_ATTRIBUTION
    assert alert_mock.last_request.headers["User-Agent"] == f"doppel-{CLIENT_ATTRIBUTION}"


def test_v2_reuses_cached_token(mocker, requests_mock):
    """A cached, unexpired token is reused without calling the token endpoint."""
    future_expiry = int(time.time()) + 3600
    _mock_integration_context(mocker, {"oauth_token": {"access_token": "cached-tok", "expiry_epoch": future_expiry}})
    token_mock = requests_mock.post(V2_TOKEN_URL, json={"access_token": "should-not-be-minted"})
    alert_mock = requests_mock.get(f"{V2_BASE_URL}/alert", json={"id": "TET-1"})

    _v2_client().get_alert(id="TET-1", entity="")

    assert token_mock.call_count == 0
    assert alert_mock.last_request.headers["Authorization"] == "Bearer cached-tok"


def test_v2_expired_token_is_reminted(mocker, requests_mock):
    """A cached token past its expiry is replaced with a freshly minted one."""
    past_expiry = int(time.time()) - 10
    store = _mock_integration_context(mocker, {"oauth_token": {"access_token": "old-tok", "expiry_epoch": past_expiry}})
    requests_mock.post(V2_TOKEN_URL, json={"access_token": "fresh-tok", "expires_in": 86400})
    alert_mock = requests_mock.get(f"{V2_BASE_URL}/alert", json={"id": "TET-1"})

    _v2_client().get_alert(id="TET-1", entity="")

    assert alert_mock.last_request.headers["Authorization"] == "Bearer fresh-tok"
    assert store["ctx"]["oauth_token"]["access_token"] == "fresh-tok"


def test_v2_401_retries_once_with_fresh_token(mocker, requests_mock):
    """A 401 on a cached token invalidates the cache, mints once, and retries the request once."""
    future_expiry = int(time.time()) + 3600
    _mock_integration_context(mocker, {"oauth_token": {"access_token": "revoked-tok", "expiry_epoch": future_expiry}})
    token_mock = requests_mock.post(V2_TOKEN_URL, json={"access_token": "fresh-tok", "expires_in": 86400})
    alert_mock = requests_mock.get(
        f"{V2_BASE_URL}/alert",
        [
            {"status_code": 401, "json": {"error": "unauthorized"}},
            {"status_code": 200, "json": {"id": "TET-1"}},
        ],
    )

    result = _v2_client().get_alert(id="TET-1", entity="")

    assert result == {"id": "TET-1"}
    assert token_mock.call_count == 1
    assert alert_mock.call_count == 2
    assert alert_mock.request_history[0].headers["Authorization"] == "Bearer revoked-tok"
    assert alert_mock.request_history[1].headers["Authorization"] == "Bearer fresh-tok"


def test_v2_token_429_raises_readable_error(mocker, requests_mock):
    """A 429 from the token endpoint surfaces the mint quota and the Retry-After value."""
    _mock_integration_context(mocker)
    requests_mock.post(V2_TOKEN_URL, status_code=429, headers={"Retry-After": "1200"}, json={})

    with pytest.raises(DemistoException, match="token request limit.*1200"):
        _v2_client().get_alert(id="TET-1", entity="")


def test_v2_token_401_raises_credentials_error(mocker, requests_mock):
    """A 401 from the token endpoint points at the Client ID / Client Secret."""
    _mock_integration_context(mocker)
    requests_mock.post(V2_TOKEN_URL, status_code=401, json={})

    with pytest.raises(DemistoException, match="Client ID and.*Client Secret"):
        _v2_client().get_alert(id="TET-1", entity="")


def test_v1_client_sends_api_key_not_bearer(requests_mock):
    """A V1 client keeps the legacy header auth and never touches the OAuth flow."""
    client = Client(base_url="https://api.doppel.com/v1", api_key="test-api-key", verify=True)
    alert_mock = requests_mock.get("https://api.doppel.com/v1/alert", json={"id": "TET-1"})

    client.get_alert(id="TET-1", entity="")

    assert alert_mock.last_request.headers["x-api-key"] == "test-api-key"
    assert "Authorization" not in alert_mock.last_request.headers


def test_main_v2_requires_client_credentials(mocker):
    """Selecting V2 without client credentials fails fast with a clear message."""
    from Doppel import main

    mocker.patch.object(
        demisto,
        "params",
        return_value={"url": "https://api.doppel.com/", "api_version": "V2 (OAuth 2.0 Client Credentials)"},
    )
    mocker.patch.object(demisto, "command", return_value="test-module")
    return_error_mock = mocker.patch("Doppel.return_error")

    main()

    assert "Client ID and a Client Secret" in return_error_mock.call_args[0][0]


def test_main_v1_requires_api_key(mocker):
    """The V1 default without an API Key fails fast with a clear message."""
    from Doppel import main

    mocker.patch.object(demisto, "params", return_value={"url": "https://api.doppel.com/"})
    mocker.patch.object(demisto, "command", return_value="test-module")
    return_error_mock = mocker.patch("Doppel.return_error")

    main()

    assert "requires an API Key" in return_error_mock.call_args[0][0]


# ---------------- Oversized alert searches (HTTP 422 result_window_exceeded) ----------------

RESULT_WINDOW_BODY = {
    "code": "result_window_exceeded",
    "message": "Result window exceeds 50000 alerts; narrow the activity time range",
    "maximum_results": 50000,
}
RESULT_WINDOW_REFUSAL = {"status_code": 422, "json": RESULT_WINDOW_BODY}
EMPTY_PAGE = {"json": {"alerts": []}}
# FETCH_FILTER_LAST_RUN puts the cursor at 07:55:00; the run starts four hours later.
REFUSAL_RUN_START = datetime(2025, 1, 27, 11, 55, 0)
# The exact request URLs sent before this handling existed (same parameters, order and encoding).
UNREFUSED_FETCH_URL = (
    "https://api.doppel.com/v1/alerts?created_after=2025-01-27T07%3A55%3A00"
    "&sort_type=date_sourced&sort_order=asc&page={page}&page_size=200"
)
UNREFUSED_MIRROR_URL = (
    "https://api.doppel.com/v1/alerts?last_activity_timestamp=2025-02-24T14%3A30%3A00&page={page}&page_size=200"
)


def _refusal_fetch_mocks(mocker, last_run=None, params=None):
    set_last_run = _fetch_demisto_mocks(
        mocker, params=params or FETCH_FILTER_PARAMS, last_run=FETCH_FILTER_LAST_RUN if last_run is None else last_run
    )
    mocker.patch("Doppel._utc_now", return_value=REFUSAL_RUN_START)
    return set_last_run


def _error_with_response(status_code, body):
    response = MagicMock()
    response.status_code = status_code
    if isinstance(body, Exception):
        response.json.side_effect = body
    else:
        response.json.return_value = body
    return DemistoException("Error in API call", res=response)


class FakeAlertsApi:
    """A stand-in for GET /alerts that applies Doppel's result-window rules with a lowered limit.

    Like the real API it refuses a request whose offset reaches the limit, and a time-filtered
    request that matches more alerts than the limit (counted after the modules filter), with
    HTTP 422 and code result_window_exceeded. Both ends of a time range are inclusive.
    """

    TIME_FILTERS = ("created_after", "created_before", "last_activity_timestamp", "last_activity_before")

    def __init__(self, alerts, limit):
        self.alerts = sorted(alerts, key=lambda alert: alert["created_at"])
        self.limit = limit
        self.queries = []
        self.statuses = []

    @staticmethod
    def _time(value):
        return datetime.strptime(value, "%Y-%m-%dT%H:%M:%S.%f" if "." in value else "%Y-%m-%dT%H:%M:%S")

    def _matches(self, alert, query):
        created = self._time(alert["created_at"])
        activity = self._time(alert.get("last_activity_timestamp") or alert["created_at"])
        if "modules" in query and alert.get("product") not in query["modules"].split(","):
            return False
        if "created_after" in query and created < self._time(query["created_after"]):
            return False
        if "created_before" in query and created > self._time(query["created_before"]):
            return False
        if "last_activity_timestamp" in query and activity < self._time(query["last_activity_timestamp"]):
            return False
        return not ("last_activity_before" in query and activity > self._time(query["last_activity_before"]))

    def __call__(self, request, context):
        from urllib.parse import parse_qs, urlsplit

        query = {key: values[0] for key, values in parse_qs(urlsplit(request.url).query).items()}
        self.queries.append(query)
        page, page_size = int(query["page"]), int(query["page_size"])
        matches = [alert for alert in self.alerts if self._matches(alert, query)]
        time_filtered = any(name in query for name in self.TIME_FILTERS)
        if page * page_size >= self.limit or (time_filtered and len(matches) > self.limit):
            self.statuses.append(422)
            context.status_code = 422
            return {**RESULT_WINDOW_BODY, "maximum_results": self.limit}
        self.statuses.append(200)
        return {"alerts": [dict(alert) for alert in matches[page * page_size : (page + 1) * page_size]]}


def _fake_alerts_api(mocker, requests_mock, alerts, limit=6, page_size=2):
    """Serve the fake API. The page size is lowered with the limit, so that ranges still span several pages."""
    mocker.patch("Doppel.DOPPEL_MAX_PAGE_SIZE", page_size)
    api = FakeAlertsApi(alerts, limit)
    requests_mock.get(V1_ALERTS_URL, json=api)
    return api


def _run_fetch_until_idle(mocker, fetch_products=None, max_fetch=3, last_run=None, max_runs=100):
    """Run fetch-incidents repeatedly with real lastRun hand-over until a run changes nothing.

    Returns the created incidents, the last lastRun, and for every run the lastRun it started with.
    """
    state = {"last_run": dict(last_run or {"last_run": "2025-01-27T00:00:00Z", "recently_seen_ids": []})}
    created: list = []
    started_with: list = []
    mocker.patch.object(demisto, "params", return_value={"max_fetch": max_fetch, "fetch_timeout": "", "mirror_direction": "None"})
    mocker.patch.object(demisto, "getLastRun", side_effect=lambda: state["last_run"])
    mocker.patch.object(demisto, "setLastRun", side_effect=lambda value: state.update(last_run=value))
    mocker.patch.object(demisto, "incidents", side_effect=created.extend)
    mocker.patch.object(demisto, "debug")
    mocker.patch.object(demisto, "integrationInstance", return_value="inst")
    mocker.patch("Doppel._utc_now", return_value=datetime(2025, 1, 28, 0, 0, 0))
    client = _v1_client()
    for _ in range(max_runs):
        before = (dict(state["last_run"]), len(created))
        started_with.append(before[0])
        fetch_incidents_command(client, {}, fetch_products=fetch_products)
        if (state["last_run"], len(created)) == before:
            return created, state["last_run"], started_with
    raise AssertionError("fetch did not settle")


def _backlog():
    """36 alerts over one day: an early burst, a gap, alerts on and around the midday midpoint, and a late burst."""
    times = [f"2025-01-27T00:00:{second:02d}.{second:02d}0000" for second in range(1, 13)]
    times += ["2025-01-27T00:00:12.900000", "2025-01-27T00:00:12.950000"]  # share a second with the alert before
    times += ["2025-01-27T12:00:00.000000", "2025-01-27T12:00:00.500000", "2025-01-27T12:00:01.000000"]
    times += [f"2025-01-27T18:{minute:02d}:30.250000" for minute in range(10)]
    times += [f"2025-01-27T23:59:{second:02d}.750000" for second in range(50, 59)]
    products = ("domains", "social_media", "telco")
    return [
        {"id": f"TET-{index}", "created_at": created_at, "product": products[index % 3]}
        for index, created_at in enumerate(times, start=1)
    ]


@pytest.mark.parametrize(
    "status_code, body, expected",
    [
        (422, RESULT_WINDOW_BODY, True),
        (422, {"code": "result_window_exceeded"}, True),
        (422, {"code": "something_else", "message": "Unprocessable"}, False),
        (422, {"message": "Result window exceeds 50000 alerts; narrow the activity time range"}, False),
        (422, ["result_window_exceeded"], False),
        (422, ValueError("not JSON"), False),
        (400, RESULT_WINDOW_BODY, False),
        (500, RESULT_WINDOW_BODY, False),
    ],
)
def test_is_result_window_exceeded(status_code, body, expected):
    """Only HTTP 422 with code result_window_exceeded in a JSON object body is a refusal."""
    from Doppel import _is_result_window_exceeded

    assert _is_result_window_exceeded(_error_with_response(status_code, body)) is expected


@pytest.mark.parametrize("error", [DemistoException("Error in API call [422]"), Exception("API failure"), ValueError("boom")])
def test_is_result_window_exceeded_without_response(error):
    """An error that carries no HTTP response is never a refusal, whatever its text says."""
    from Doppel import _is_result_window_exceeded

    assert _is_result_window_exceeded(error) is False


@pytest.mark.parametrize(
    "start, end, expected",
    [
        (datetime(2025, 1, 27, 7, 55, 0), datetime(2025, 1, 27, 11, 55, 0), datetime(2025, 1, 27, 9, 55, 0)),
        (datetime(2025, 1, 27, 7, 55, 0), datetime(2025, 1, 27, 7, 55, 5), datetime(2025, 1, 27, 7, 55, 2)),
        (datetime(2025, 1, 27, 7, 55, 0), datetime(2025, 1, 27, 7, 55, 2), datetime(2025, 1, 27, 7, 55, 1)),
        (datetime(2025, 1, 27, 7, 55, 0), datetime(2025, 1, 27, 7, 55, 1), None),
        (datetime(2025, 1, 27, 7, 55, 0), datetime(2025, 1, 27, 7, 55, 0), None),
        (datetime(2025, 1, 27, 7, 55, 0), datetime(2025, 1, 27, 7, 54, 0), None),
    ],
)
def test_narrowed_window_end(start, end, expected):
    """A refused range is cut at its midpoint in whole seconds; a range under two seconds cannot be cut."""
    from Doppel import _narrowed_window_end

    assert _narrowed_window_end(start, end) == expected


def test_paginated_call_to_get_alerts_with_created_before():
    """The upper limit is added to the fetch query only when given, after the unchanged parameters."""
    mock_client = MagicMock()
    mock_client.get_alerts.return_value = {"alerts": []}
    last_fetch_datetime = datetime(2025, 2, 27, 14, 30, 0)

    _paginated_call_to_get_alerts(mock_client, 3, last_fetch_datetime, "domains", datetime(2025, 2, 27, 16, 30, 0))
    _paginated_call_to_get_alerts(mock_client, 3, last_fetch_datetime, "domains", None)

    unchanged = {
        "created_after": "2025-02-27T14:30:00",
        "sort_type": "date_sourced",
        "sort_order": "asc",
        "page": 3,
        "page_size": 200,
        "modules": "domains",
    }
    assert mock_client.get_alerts.call_args_list[0][1]["params"] == {**unchanged, "created_before": "2025-02-27T16:30:00"}
    assert mock_client.get_alerts.call_args_list[1][1]["params"] == unchanged


def test_fetch_incidents_not_refused_sends_unchanged_requests(mocker, requests_mock):
    """A fetch that Doppel does not refuse sends the same URLs as before and writes only the two lastRun keys."""
    set_last_run = _refusal_fetch_mocks(mocker)
    full_page = {"alerts": [{"id": f"OLD-{i}", "created_at": "2025-01-27T07:55:10.063742"} for i in range(200)]}
    alerts_mock = requests_mock.get(V1_ALERTS_URL, [{"json": full_page}, {"json": FETCH_FILTER_PAGE}, EMPTY_PAGE])
    params = {**FETCH_FILTER_PARAMS, "max_fetch": 500}
    mocker.patch.object(demisto, "params", return_value=params)

    fetch_incidents_command(_v1_client(), {})

    assert [request.url for request in alerts_mock.request_history] == [
        UNREFUSED_FETCH_URL.format(page=0),
        UNREFUSED_FETCH_URL.format(page=1),
        UNREFUSED_FETCH_URL.format(page=2),
    ]
    assert len(demisto.incidents.call_args[0][0]) == 202
    assert set_last_run.call_args[0][0] == {"last_run": "2025-01-27T07:55:12Z", "recently_seen_ids": ["TET-2"]}


def test_fetch_incidents_not_refused_ignores_other_422(mocker, requests_mock):
    """A 422 that is not the refusal, and a 500, fail the run as before: one request, no narrowing, cursor untouched."""
    for failure in ({"status_code": 422, "json": {"code": "invalid", "message": "Unprocessable"}}, {"status_code": 500}):
        set_last_run = _refusal_fetch_mocks(mocker)
        alerts_mock = requests_mock.get(V1_ALERTS_URL, [failure, {"json": FETCH_FILTER_PAGE}])

        with pytest.raises(DemistoException, match=f"\\[{failure['status_code']}\\]"):
            fetch_incidents_command(_v1_client(), {})

        assert [request.url for request in alerts_mock.request_history] == [UNREFUSED_FETCH_URL.format(page=0)]
        set_last_run.assert_not_called()
        demisto.incidents.assert_not_called()


def test_fetch_incidents_refusal_halves_range_until_accepted(mocker, requests_mock):
    """A refusal is retried with created_before at the midpoint, and again at the next midpoint when refused again."""
    set_last_run = _refusal_fetch_mocks(mocker)
    alerts_mock = requests_mock.get(
        V1_ALERTS_URL,
        [RESULT_WINDOW_REFUSAL, RESULT_WINDOW_REFUSAL, {"json": FETCH_FILTER_PAGE}, EMPTY_PAGE, EMPTY_PAGE],
    )

    fetch_incidents_command(_v1_client(), {})

    history = alerts_mock.request_history
    # The first request of the run is the unchanged one.
    assert history[0].url == UNREFUSED_FETCH_URL.format(page=0)
    assert history[1].qs == {**UNFILTERED_FETCH_QUERY, "created_before": ["2025-01-27t09:55:00"]}
    assert history[2].qs == {**UNFILTERED_FETCH_QUERY, "created_before": ["2025-01-27t08:55:00"]}
    assert history[3].qs == {**UNFILTERED_FETCH_QUERY, "created_before": ["2025-01-27t08:55:00"], "page": ["1"]}
    # The accepted range is read to its end, so the rest is requested from its end with no upper limit.
    assert history[4].qs == {**UNFILTERED_FETCH_QUERY, "created_after": ["2025-01-27t08:55:00"]}
    assert len(history) == 5
    assert [i["name"] for i in demisto.incidents.call_args[0][0]] == ["Doppel Alert TET-1", "Doppel Alert TET-2"]
    assert set_last_run.call_args[0][0] == {"last_run": "2025-01-27T08:55:00Z", "recently_seen_ids": []}


def test_fetch_incidents_refusal_keeps_product_filter(mocker, requests_mock):
    """Narrowed requests keep the sort, the page size and the selected products."""
    _refusal_fetch_mocks(mocker)
    alerts_mock = requests_mock.get(V1_ALERTS_URL, [RESULT_WINDOW_REFUSAL, {"json": FETCH_FILTER_PAGE}, EMPTY_PAGE, EMPTY_PAGE])

    fetch_incidents_command(_v1_client(), {}, fetch_products=["domains", "telco"])

    filtered = {**UNFILTERED_FETCH_QUERY, "modules": ["domains,telco"]}
    assert [request.qs for request in alerts_mock.request_history] == [
        filtered,
        {**filtered, "created_before": ["2025-01-27t09:55:00"]},
        {**filtered, "created_before": ["2025-01-27t09:55:00"], "page": ["1"]},
        {**filtered, "created_after": ["2025-01-27t09:55:00"]},
    ]


def test_fetch_incidents_limit_inside_range_saves_upper_limit(mocker, requests_mock):
    """When the incident limit is reached inside a narrowed range, the cursor is saved as before, with the upper limit."""
    set_last_run = _refusal_fetch_mocks(mocker, params={**FETCH_FILTER_PARAMS, "max_fetch": 1})
    requests_mock.get(V1_ALERTS_URL, [RESULT_WINDOW_REFUSAL, {"json": FETCH_FILTER_PAGE}])

    fetch_incidents_command(_v1_client(), {})

    assert [i["name"] for i in demisto.incidents.call_args[0][0]] == ["Doppel Alert TET-1"]
    assert set_last_run.call_args[0][0] == {
        "last_run": "2025-01-27T07:55:10Z",
        "recently_seen_ids": ["TET-1"],
        "fetch_window_end": "2025-01-27T09:55:00Z",
    }


def test_fetch_incidents_continues_saved_range_without_refused_request(mocker, requests_mock):
    """A run that starts with a saved upper limit sends it on its first request, so nothing is refused again."""
    last_run = {"last_run": "2025-01-27T07:55:10Z", "recently_seen_ids": ["TET-1"], "fetch_window_end": "2025-01-27T09:55:00Z"}
    set_last_run = _refusal_fetch_mocks(mocker, last_run=last_run, params={**FETCH_FILTER_PARAMS, "max_fetch": 1})
    alerts_mock = requests_mock.get(V1_ALERTS_URL, [{"json": FETCH_FILTER_PAGE}])

    fetch_incidents_command(_v1_client(), {})

    assert [request.qs for request in alerts_mock.request_history] == [
        {**UNFILTERED_FETCH_QUERY, "created_after": ["2025-01-27t07:55:10"], "created_before": ["2025-01-27t09:55:00"]}
    ]
    assert [i["name"] for i in demisto.incidents.call_args[0][0]] == ["Doppel Alert TET-2"]
    assert set_last_run.call_args[0][0] == {
        "last_run": "2025-01-27T07:55:12Z",
        "recently_seen_ids": ["TET-2"],
        "fetch_window_end": "2025-01-27T09:55:00Z",
    }


def test_fetch_incidents_range_read_to_end_moves_cursor_and_removes_upper_limit(mocker, requests_mock):
    """When a saved range is read to its end, the cursor moves to its end, the saved limit goes, and the run continues."""
    last_run = {"last_run": "2025-01-27T07:55:12Z", "recently_seen_ids": ["TET-2"], "fetch_window_end": "2025-01-27T09:55:00Z"}
    set_last_run = _refusal_fetch_mocks(mocker, last_run=last_run)
    later_page = {"alerts": [{"id": "TET-3", "created_at": "2025-01-27T10:15:00.500000"}]}
    alerts_mock = requests_mock.get(
        V1_ALERTS_URL, [{"json": {"alerts": FETCH_FILTER_PAGE["alerts"][1:]}}, EMPTY_PAGE, {"json": later_page}, EMPTY_PAGE]
    )

    fetch_incidents_command(_v1_client(), {})

    bounded = {**UNFILTERED_FETCH_QUERY, "created_after": ["2025-01-27t07:55:12"], "created_before": ["2025-01-27t09:55:00"]}
    unbounded = {**UNFILTERED_FETCH_QUERY, "created_after": ["2025-01-27t09:55:00"]}
    assert [request.qs for request in alerts_mock.request_history] == [
        bounded,
        {**bounded, "page": ["1"]},
        unbounded,
        {**unbounded, "page": ["1"]},
    ]
    assert [i["name"] for i in demisto.incidents.call_args[0][0]] == ["Doppel Alert TET-3"]
    assert set_last_run.call_args[0][0] == {"last_run": "2025-01-27T10:15:00Z", "recently_seen_ids": ["TET-3"]}


def test_fetch_incidents_empty_range_moves_cursor(mocker, requests_mock):
    """A narrowed range that holds no alert still moves the cursor to its end, so the fetch cannot stall on it."""
    set_last_run = _refusal_fetch_mocks(mocker)
    alerts_mock = requests_mock.get(V1_ALERTS_URL, [RESULT_WINDOW_REFUSAL, EMPTY_PAGE, EMPTY_PAGE])

    fetch_incidents_command(_v1_client(), {})

    assert alerts_mock.request_history[2].qs == {**UNFILTERED_FETCH_QUERY, "created_after": ["2025-01-27t09:55:00"]}
    demisto.incidents.assert_called_once_with([])
    assert set_last_run.call_args[0][0] == {"last_run": "2025-01-27T09:55:00Z", "recently_seen_ids": []}


def test_fetch_incidents_alert_on_upper_limit_is_created_once(mocker, requests_mock):
    """An alert created exactly on an upper limit is in two ranges; it becomes one incident, within a run and across runs."""
    on_limit = {"id": "TET-9", "created_at": "2025-01-27T09:55:00.000000"}
    set_last_run = _refusal_fetch_mocks(mocker)
    requests_mock.get(V1_ALERTS_URL, [RESULT_WINDOW_REFUSAL, {"json": {"alerts": [on_limit]}}, EMPTY_PAGE, EMPTY_PAGE])

    fetch_incidents_command(_v1_client(), {})

    assert [i["name"] for i in demisto.incidents.call_args[0][0]] == ["Doppel Alert TET-9"]
    saved = set_last_run.call_args[0][0]
    assert saved == {"last_run": "2025-01-27T09:55:00Z", "recently_seen_ids": ["TET-9"]}

    # Next run: the cursor is the upper limit, and the inclusive request returns the same alert again.
    set_last_run = _refusal_fetch_mocks(mocker, last_run=saved)
    requests_mock.get(V1_ALERTS_URL, [{"json": {"alerts": [on_limit]}}, EMPTY_PAGE])

    fetch_incidents_command(_v1_client(), {})

    demisto.incidents.assert_called_once_with([])
    assert set_last_run.call_args[0][0] == saved


def test_fetch_incidents_refusal_on_later_page_restarts_without_duplicates(mocker, requests_mock):
    """A refusal on a later page reads the narrowed range again from page 0 and creates no incident twice."""
    set_last_run = _refusal_fetch_mocks(mocker)
    alerts_mock = requests_mock.get(
        V1_ALERTS_URL,
        [{"json": FETCH_FILTER_PAGE}, RESULT_WINDOW_REFUSAL, {"json": FETCH_FILTER_PAGE}, EMPTY_PAGE, EMPTY_PAGE],
    )

    fetch_incidents_command(_v1_client(), {})

    history = alerts_mock.request_history
    assert history[1].url == UNREFUSED_FETCH_URL.format(page=1)
    assert history[2].qs == {**UNFILTERED_FETCH_QUERY, "created_before": ["2025-01-27t09:55:00"]}
    assert [i["name"] for i in demisto.incidents.call_args[0][0]] == ["Doppel Alert TET-1", "Doppel Alert TET-2"]
    assert set_last_run.call_args[0][0] == {"last_run": "2025-01-27T09:55:00Z", "recently_seen_ids": []}


def test_fetch_incidents_timeout_while_narrowing_saves_progress(mocker, requests_mock):
    """When the time budget ends while a refused range is narrowed, the upper limit reached so far is saved."""
    set_last_run = _refusal_fetch_mocks(mocker)
    clock = {"now": 1000.0}

    def refuse_slowly(request, context):
        clock["now"] += 20  # every refused request takes 20 of the 30 seconds
        context.status_code = 422
        return RESULT_WINDOW_BODY

    mocker.patch("Doppel.time.time", side_effect=lambda: clock["now"])
    alerts_mock = requests_mock.get(V1_ALERTS_URL, json=refuse_slowly)

    fetch_incidents_command(_v1_client(), {})

    assert alerts_mock.call_count == 2
    demisto.incidents.assert_called_once_with([])
    assert set_last_run.call_args[0][0] == {
        "last_run": "2025-01-27T07:55:00Z",
        "recently_seen_ids": [],
        "fetch_window_end": "2025-01-27T08:55:00Z",
    }


@pytest.mark.parametrize("saved_end", ["2025-01-27T07:55:00Z", "2025-01-27T07:00:00Z", "not-a-time", "", None, 0], ids=str)
def test_fetch_incidents_ignores_unusable_saved_upper_limit(mocker, requests_mock, saved_end):
    """A saved upper limit at or before the cursor, or one that cannot be read, is dropped: the request is the unchanged one."""
    set_last_run = _refusal_fetch_mocks(mocker, last_run={**FETCH_FILTER_LAST_RUN, "fetch_window_end": saved_end})
    alerts_mock = _mock_alert_pages(requests_mock)

    fetch_incidents_command(_v1_client(), {})

    assert [request.url for request in alerts_mock.request_history] == [
        UNREFUSED_FETCH_URL.format(page=0),
        UNREFUSED_FETCH_URL.format(page=1),
    ]
    assert set_last_run.call_args[0][0] == {"last_run": "2025-01-27T07:55:12Z", "recently_seen_ids": ["TET-2"]}


def test_fetch_incidents_range_under_two_seconds_fails_clearly(mocker, requests_mock):
    """More alerts than Doppel can page in under two seconds: the run fails with a clear message, lastRun untouched."""
    same_second = [{"id": f"TET-{i}", "created_at": f"2025-01-27T07:55:00.{i}00000"} for i in range(1, 8)]
    set_last_run = _refusal_fetch_mocks(mocker)
    api = _fake_alerts_api(mocker, requests_mock, same_second)

    with pytest.raises(DemistoException) as error:
        fetch_incidents_command(_v1_client(), {})

    assert "result_window_exceeded" in str(error.value)
    assert "2025-01-27 07:55:00 to 2025-01-27 07:55:01 (UTC) is under two seconds" in str(error.value)
    assert set(api.statuses) == {422}
    assert api.queries[-1]["created_before"] == "2025-01-27T07:55:01"
    set_last_run.assert_not_called()
    demisto.incidents.assert_not_called()


def test_fetch_incidents_range_under_two_seconds_keeps_earlier_progress(mocker, requests_mock):
    """Alerts read before a range that cannot be narrowed are still created; the next run reports the failure."""
    alerts = [
        {"id": "TET-A", "created_at": "2025-01-27T07:55:10.000000"},
        {"id": "TET-B", "created_at": "2025-01-27T07:55:20.000000"},
    ] + [{"id": f"TET-{i}", "created_at": f"2025-01-27T09:00:00.{i}00000"} for i in range(1, 8)]
    set_last_run = _refusal_fetch_mocks(mocker)
    _fake_alerts_api(mocker, requests_mock, alerts)

    fetch_incidents_command(_v1_client(), {})

    assert [i["name"] for i in demisto.incidents.call_args[0][0]] == ["Doppel Alert TET-A", "Doppel Alert TET-B"]
    saved = set_last_run.call_args[0][0]
    assert saved["last_run"] == "2025-01-27T09:00:00Z"

    set_last_run = _refusal_fetch_mocks(mocker, last_run=saved)
    with pytest.raises(DemistoException, match="under two seconds"):
        fetch_incidents_command(_v1_client(), {})
    set_last_run.assert_not_called()


@pytest.mark.parametrize("max_fetch", [1, 3, 50])
def test_fetch_incidents_reads_refused_backlog_exactly_once(mocker, requests_mock, max_fetch):
    """Over many runs against the stand-in API, every alert of a refused backlog becomes one incident, oldest first."""
    backlog = _backlog()
    api = _fake_alerts_api(mocker, requests_mock, backlog)

    created, last_run, started_with = _run_fetch_until_idle(mocker, max_fetch=max_fetch)

    assert 422 in api.statuses
    assert [incident["dbotMirrorId"] for incident in created] == [alert["id"] for alert in backlog]
    assert last_run == {"last_run": "2025-01-27T23:59:58Z", "recently_seen_ids": ["TET-36"]}
    # A run that starts inside a saved range sends its upper limit on the first request.
    assert any("fetch_window_end" in run for run in started_with) is (max_fetch < 50)


def test_fetch_incidents_reads_refused_backlog_with_product_filter(mocker, requests_mock):
    """With products selected, every narrowed request carries them and only their alerts become incidents."""
    backlog = _backlog()
    api = _fake_alerts_api(mocker, requests_mock, backlog, limit=4)

    created, last_run, _ = _run_fetch_until_idle(mocker, fetch_products=["domains", "telco"])

    expected = [alert["id"] for alert in backlog if alert["product"] in ("domains", "telco")]
    assert 422 in api.statuses
    assert all(query["modules"] == "domains,telco" for query in api.queries)
    assert [incident["dbotMirrorId"] for incident in created] == expected
    assert "fetch_window_end" not in last_run


def test_fetch_incidents_backlog_below_limit_is_never_narrowed(mocker, requests_mock):
    """Against the stand-in API with a limit the backlog does not reach, no request carries created_before."""
    backlog = _backlog()
    api = _fake_alerts_api(mocker, requests_mock, backlog, limit=200)

    created, last_run, started_with = _run_fetch_until_idle(mocker)

    assert set(api.statuses) == {200}
    assert not any("created_before" in query for query in api.queries)
    assert not any("fetch_window_end" in run for run in started_with)
    assert [incident["dbotMirrorId"] for incident in created] == [alert["id"] for alert in backlog]
    assert last_run == {"last_run": "2025-01-27T23:59:58Z", "recently_seen_ids": ["TET-36"]}


def test_doppel_get_alerts_command_without_new_argument_sends_unchanged_request(requests_mock):
    """Without last_activity_before, the command sends the same URL as before."""
    alerts_mock = requests_mock.get(V1_ALERTS_URL, json=FETCH_FILTER_PAGE)
    args = {
        "created_after": "2025-01-01T00:00:00Z",
        "last_activity_timestamp": "2025-01-02T00:00:00Z",
        "sort_type": "date_sourced",
        "sort_order": "desc",
        "page": "0",
        "page_size": "200",
    }

    doppel_get_alerts_command(_v1_client(), args)

    assert alerts_mock.last_request.url == (
        "https://api.doppel.com/v1/alerts?created_after=2025-01-01T00%3A00%3A00%2B00%3A00"
        "&last_activity_timestamp=2025-01-02T00%3A00%3A00%2B00%3A00&sort_type=date_sourced&sort_order=desc&page=0&page_size=200"
    )


def test_doppel_get_alerts_command_sends_last_activity_before(requests_mock):
    """last_activity_before is sent under the same name, and a date far in the past is passed on as given."""
    alerts_mock = requests_mock.get(V1_ALERTS_URL, json={"alerts": []})

    result = doppel_get_alerts_command(_v1_client(), {"last_activity_before": "2000-01-01T00:00:00Z", "page_size": "1"})

    assert alerts_mock.last_request.qs == {"last_activity_before": ["2000-01-01t00:00:00+00:00"], "page_size": ["1"]}
    assert result.outputs == {"alerts": []}


def test_doppel_get_alerts_command_refusal_has_clear_message(requests_mock):
    """A refused search is reported as too large, with the literal code that callers look for, and is not narrowed."""
    alerts_mock = requests_mock.get(V1_ALERTS_URL, [RESULT_WINDOW_REFUSAL, {"json": FETCH_FILTER_PAGE}])

    with pytest.raises(DemistoException) as error:
        doppel_get_alerts_command(_v1_client(), {"last_activity_timestamp": "2020-01-01T00:00:00Z"})

    assert "result_window_exceeded" in str(error.value)
    assert "too large" in str(error.value)
    assert "last_activity_before" in str(error.value)
    assert "No alerts were found" not in str(error.value)
    assert alerts_mock.call_count == 1


def test_doppel_get_alerts_command_other_422_keeps_previous_message(requests_mock):
    """A 422 that is not the refusal keeps the previous error wording."""
    requests_mock.get(V1_ALERTS_URL, status_code=422, json={"code": "invalid", "message": "Unprocessable"})

    with pytest.raises(Exception, match="No alerts were found with the given parameters :- Error in API call \\[422\\]"):
        doppel_get_alerts_command(_v1_client(), {"page": "0"})


def test_main_reports_refused_get_alerts_search(mocker, requests_mock):
    """Through main(), the command error of a refused search still contains the literal code."""
    from Doppel import main

    mocker.patch.object(
        demisto, "params", return_value={"url": "https://api.doppel.com/", "credentials": {"password": "test-api-key"}}
    )
    mocker.patch.object(demisto, "command", return_value="doppel-get-alerts")
    mocker.patch.object(demisto, "args", return_value={"page": "250", "page_size": "200"})
    return_error_mock = mocker.patch("Doppel.return_error")
    requests_mock.get(V1_ALERTS_URL, [RESULT_WINDOW_REFUSAL])

    main()

    message = return_error_mock.call_args[0][0]
    assert message.startswith("Failed to execute doppel-get-alerts command.")
    assert "result_window_exceeded" in message


def test_get_modified_remote_data_not_refused_sends_unchanged_requests(mocker, requests_mock):
    """A mirroring cycle that Doppel does not refuse sends the same URLs as before."""
    mocker.patch.object(demisto, "debug")
    mocker.patch("Doppel._utc_now", return_value=datetime(2025, 2, 24, 18, 30, 0))
    full_page = {"alerts": [{"id": f"alert-{i:03d}"} for i in range(200)]}
    short_page = {"alerts": [{"id": "alert-200"}, {"id": "alert-001"}]}
    alerts_mock = requests_mock.get(V1_ALERTS_URL, [{"json": full_page}, {"json": short_page}])

    result = get_modified_remote_data_command(_v1_client(), {"lastUpdate": "2025-02-24T14:30:00Z"})

    assert [request.url for request in alerts_mock.request_history] == [
        UNREFUSED_MIRROR_URL.format(page=0),
        UNREFUSED_MIRROR_URL.format(page=1),
    ]
    assert len(result.modified_incident_ids) == 201
    assert result.modified_incident_ids[-1] == "alert-200"


def test_get_modified_remote_data_not_refused_stops_on_empty_page(mocker, requests_mock):
    """As before, an empty first page (or a response without an alert list) ends the cycle after one request."""
    mocker.patch.object(demisto, "debug")
    error_log = mocker.patch.object(demisto, "error")
    for empty_response in (EMPTY_PAGE, {"json": {"alerts": None}}, {"json": {}}):
        alerts_mock = requests_mock.get(V1_ALERTS_URL, [empty_response])

        result = get_modified_remote_data_command(_v1_client(), {"lastUpdate": "2025-02-24T14:30:00Z"})

        assert [request.url for request in alerts_mock.request_history] == [UNREFUSED_MIRROR_URL.format(page=0)]
        assert result.modified_incident_ids == []
    error_log.assert_not_called()


@pytest.mark.parametrize(
    "failure", [{"status_code": 422, "json": {"code": "invalid", "message": "Unprocessable"}}, {"status_code": 500}], ids=str
)
def test_get_modified_remote_data_other_errors_return_empty_list(mocker, requests_mock, failure):
    """A 422 that is not the refusal, and a 500, are logged and return an empty list as before, after one request."""
    mocker.patch.object(demisto, "debug")
    error_log = mocker.patch.object(demisto, "error")
    alerts_mock = requests_mock.get(V1_ALERTS_URL, [failure, {"json": FETCH_FILTER_PAGE}])

    result = get_modified_remote_data_command(_v1_client(), {"lastUpdate": "2025-02-24T14:30:00Z"})

    assert [request.url for request in alerts_mock.request_history] == [UNREFUSED_MIRROR_URL.format(page=0)]
    assert result.modified_incident_ids == []
    assert error_log.call_args[0][0].startswith("Error in get-modified-remote-data:")


def test_get_modified_remote_data_refusal_splits_range(mocker, requests_mock):
    """A refused search is split: the older part gets last_activity_before, the newest part keeps no upper limit."""
    mocker.patch.object(demisto, "debug")
    mocker.patch("Doppel._utc_now", return_value=datetime(2025, 2, 24, 18, 30, 0))
    older = {"alerts": [{"id": "alert-1"}, {"id": "alert-2"}]}
    newer = {"alerts": [{"id": "alert-2"}, {"id": "alert-3"}]}
    alerts_mock = requests_mock.get(
        V1_ALERTS_URL, [RESULT_WINDOW_REFUSAL, RESULT_WINDOW_REFUSAL, {"json": older}, {"json": newer}]
    )

    result = get_modified_remote_data_command(_v1_client(), {"lastUpdate": "2025-02-24T14:30:00Z"})

    start = {"last_activity_timestamp": ["2025-02-24t14:30:00"], "page": ["0"], "page_size": ["200"]}
    assert alerts_mock.request_history[0].url == UNREFUSED_MIRROR_URL.format(page=0)
    assert [request.qs for request in alerts_mock.request_history[1:]] == [
        {**start, "last_activity_before": ["2025-02-24t16:30:00"]},
        {**start, "last_activity_before": ["2025-02-24t15:30:00"]},
        {**start, "last_activity_timestamp": ["2025-02-24t15:30:00"]},
    ]
    assert result.modified_incident_ids == ["alert-1", "alert-2", "alert-3"]


def test_get_modified_remote_data_reads_refused_search_in_one_call(mocker, requests_mock):
    """Against the stand-in API, one call returns every modified alert of a refused search, each id once."""
    mocker.patch.object(demisto, "debug")
    error_log = mocker.patch.object(demisto, "error")
    mocker.patch("Doppel._utc_now", return_value=datetime(2025, 1, 28, 0, 0, 0))
    backlog = [
        {**alert, "last_activity_timestamp": alert["created_at"], "created_at": "2024-06-01T00:00:00.000000"}
        for alert in _backlog()
    ]
    unchanged = {
        "id": "TET-OLD",
        "created_at": "2024-06-01T00:00:00.000000",
        "last_activity_timestamp": "2025-01-26T23:59:59.000000",
    }
    api = _fake_alerts_api(mocker, requests_mock, backlog + [unchanged])

    result = get_modified_remote_data_command(_v1_client(), {"lastUpdate": "2025-01-27T00:00:00Z"})

    assert 422 in api.statuses
    assert "last_activity_before" not in api.queries[0]
    assert sorted(result.modified_incident_ids) == sorted(alert["id"] for alert in backlog)
    error_log.assert_not_called()


def test_get_modified_remote_data_unreadable_range_returns_ids_read(mocker, requests_mock):
    """A range under two seconds that is still refused: the ids read so far are returned and the range is logged."""
    mocker.patch.object(demisto, "debug")
    error_log = mocker.patch.object(demisto, "error")
    mocker.patch("Doppel._utc_now", return_value=datetime(2025, 1, 28, 0, 0, 0))
    readable = [
        {"id": "TET-A", "created_at": "2025-01-27T00:10:00.000000"},
        {"id": "TET-B", "created_at": "2025-01-27T00:20:00.000000"},
    ]
    same_second = [{"id": f"TET-{i}", "created_at": f"2025-01-27T09:00:00.{i}00000"} for i in range(1, 8)]
    _fake_alerts_api(mocker, requests_mock, readable + same_second)

    result = get_modified_remote_data_command(_v1_client(), {"lastUpdate": "2025-01-27T00:00:00Z"})

    assert result.modified_incident_ids == ["TET-A", "TET-B"]
    message = error_log.call_args[0][0]
    assert "result_window_exceeded" in message
    assert "2025-01-27 09:00:00 to 2025-01-27 09:00:01 (UTC), which is under two seconds" in message


def test_get_modified_remote_data_request_limit_after_refusal_is_logged(mocker, requests_mock):
    """When the request limit is reached after a refusal, the ids read are returned and the unread range is logged."""
    mocker.patch.object(demisto, "debug")
    error_log = mocker.patch.object(demisto, "error")
    mocker.patch("Doppel._utc_now", return_value=datetime(2025, 1, 28, 0, 0, 0))
    mocker.patch("Doppel.MAX_FETCH_PAGES_PER_RUN", 40)
    api = _fake_alerts_api(mocker, requests_mock, _backlog())

    result = get_modified_remote_data_command(_v1_client(), {"lastUpdate": "2025-01-27T00:00:00Z"})

    assert len(api.queries) == 40
    assert 0 < len(result.modified_incident_ids) < 36
    assert "the limit of 40 requests was reached" in error_log.call_args[0][0]
