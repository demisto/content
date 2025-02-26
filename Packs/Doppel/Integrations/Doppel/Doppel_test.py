import json
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
    doppel_create_abuse_alert_command
)

from CommonServerPython import *
from CommonServerUserPython import *

ALERTS_RESPONSE = [
    {"id": "1", "created_at": "2025-02-01T12:00:00.000000Z"},
    {"id": "2", "created_at": "2025-02-01T12:05:00.000000Z"}
]


def util_load_json(path):
    """Helper function to load JSON data from a file."""
    with open(path, encoding='utf-8') as f:
        return json.loads(f.read())

# Mock function for _http_request


def mock_http_request(method, url_suffix, params=None, headers=None, data=None, json_data=None):
    if url_suffix == 'alert':
        return util_load_json('test_data/get-alert.json')
    return {}


# Mock function to return alerts in the expected format
def mock_get_alerts(*args, **kwargs):
    if kwargs.get("page", 0) > 0:  # Simulate an empty response after the first page
        return {"alerts": []}

    modified_alerts = [
        {**alert, "created_at": alert["created_at"].rstrip("Z")}
        for alert in ALERTS_RESPONSE
    ]
    return {"alerts": modified_alerts}  # Ensure response is a dictionary


@pytest.fixture
def client():
    # Create a mock client
    client = MagicMock()

    # Assign the mock function to get_alerts
    client.get_alerts.side_effect = mock_get_alerts

    # Mocking fetch single alert (Used in update_remote_system_command)
    client.get_alert.return_value = {
        "id": "123",
        "queue_state": "open",
        "entity_state": "active"
    }

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
    mocker.patch.object(client, '_http_request', side_effect=mock_http_request)

    # Pass an empty dictionary `{}` as `args`, not a string
    result = test_module(client)

    # Assert the expected output
    assert result == 'ok'


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
    mocker.patch("Doppel._paginated_call_to_get_alerts", side_effect=[
        mock_alerts['alerts'][:50],  # First fetch - fill queue
        mock_alerts['alerts'][50:100],  # Second fetch - next batch
        [],  # Third fetch - No new alerts, return remaining
        []   # Fourth fetch - No new alerts, return empty
    ])

    # Run test cycles
    last_run = None
    incidents_queue = []

    # for current_flow in ['first', 'second', 'third', 'forth']:
    # Mock last run data
    mocker.patch.object(demisto, "getLastRun", return_value={'last_run': last_run, 'incidents_queue': incidents_queue})

    # Call function
    fetch_incidents_command(client=None, args={})

    # Verify incidents pushed to XSOAR
    incidents_pushed = demisto.incidents.call_args[0][0]
    assert len(incidents_pushed) == 1, "Mismatch in incidents"

    incident = incidents_pushed[0]
    assert "name" in incident
    assert "type" in incident
    assert "dbotMirrorId" in incident
    assert "rawJSON" in incident
    assert incident["name"].startswith("Doppel Incident"), "Incident name format mismatch"
    assert incident["occurred"] != "", "Occurred timestamp should not be empty"

    # Verify last run update
    last_run_data = demisto.setLastRun.call_args[0][0]
    assert "last_run" in last_run_data, "last_run not updated"

    # Update last run and queue for next cycle
    last_run = last_run_data["last_run"]
    incidents_queue = last_run_data["incidents_queue"]


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
        "https://example.com/api/alerts",
        json={"data": [{"id": "123456", "status": "updated", "name": "Test Alert"}]}
    )

    # Mock necessary demisto functions
    mocker.patch.object(demisto, 'debug')
    mocker.patch.object(demisto, 'error')
    mocker.patch.object(demisto, 'args', return_value={"id": "123456", "lastUpdate": "2025-01-27T07:55:10.063742"})
    mocker.patch.object(demisto, 'command', return_value='get-remote-data')

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


def test_update_remote_system_command(client, mocker):
    """Test update_remote_system_command function."""

    # Mocking demisto functions using mocker.patch.object
    mock_debug = mocker.patch.object(demisto, "debug")
    mock_error = mocker.patch.object(demisto, "error")

    args = {
        "data": {"queue_state": "archived"},
        "incidentChanged": True,
        "remoteId": "123",
    }

    # Run the function
    result = update_remote_system_command(client, args)

    # Assertions
    assert result == "123", "Returned remoteId should match input"
    mock_debug.assert_called()  # Ensure debug logs are being generated
    mock_error.assert_not_called()  # Ensure no errors were logged


def test_get_mapping_fields_command(client, mocker):
    """Test get_mapping_fields_command function."""

    # Mocking demisto functions using mocker.patch.object
    mock_debug = mocker.patch.object(demisto, "debug")

    # Run the function
    result = get_mapping_fields_command(client, {})

    # Assertions
    assert result is not None, "Result should not be None"
    assert hasattr(result, "extract_mapping"), "Result should have extract_mapping method"

    mock_debug.assert_called()  # Ensure debug logs are generated


def test_doppel_get_alert_command(client, mocker):
    # Mock API response
    mocker.patch.object(client, 'get_alert', return_value={
        "id": "TET-1953443",
        "status": "Open",
        "name": "Test Alert"
    })

    args = {'id': 'TET-1953443'}
    result = doppel_get_alert_command(client, args)

    assert isinstance(result, CommandResults), f"Expected CommandResults but got {type(result)}"
    assert result.outputs_prefix == 'Doppel.Alert'
    assert result.outputs_key_field == 'id'
    assert result.outputs.get('id') == 'TET-1953443'
    assert 'Alert Summary' in result.readable_output


def test_doppel_get_alert_command_with_invalid_params(client):
    args = {'id': 'TET-1953443', 'entity': 'http://test-doppel.com'}

    with pytest.raises(ValueError):
        doppel_get_alert_command(client, args)


def test_doppel_get_alert_command_with_missing_params(client):
    args = {}

    with pytest.raises(ValueError):
        doppel_get_alert_command(client, args)


def test_doppel_get_alert_command_with_no_alert_found(client, mocker):
    def mock_no_alert_found(*args, **kwargs):
        raise DemistoException('No alert found with the given parameters.')

    mocker.patch.object(client, 'get_alert', side_effect=mock_no_alert_found)

    args = {'id': 'NON_EXISTENT_ID'}

    with pytest.raises(Exception):
        doppel_get_alert_command(client, args)


def test_doppel_update_alert_command(mocker):
    """Test doppel_update_alert_command function with an inline mock client."""

    # Mocking the Client instance
    mock_client = MagicMock()
    mock_client.update_alert.return_value = {"id": "123", "queue_state": "archived", "entity_state": "closed"}

    # Sample arguments
    args = {
        "alert_id": "123",
        "queue_state": "archived",
        "entity_state": "closed",
        "comment": "Resolved"
    }

    # Run the function
    result = doppel_update_alert_command(mock_client, args)

    # Assertions
    assert result.outputs_prefix == "Doppel.UpdatedAlert", "Incorrect outputs prefix"
    assert result.outputs_key_field == "id", "Incorrect key field"
    assert result.outputs == {"id": "123", "queue_state": "archived", "entity_state": "closed"}, "Unexpected output"


def test_doppel_update_alert_command_with_entity(client, mocker):
    # Prepare the mock response for the _http_request function
    mocker.patch.object(client, '_http_request', side_effect=mock_http_request)

    # Sample arguments to simulate the command input, using 'entity' instead of 'alert_id'
    args = {
        'alert_id': '',  # Empty alert_id to test entity usage
        'queue_state': 'doppel_review',
        'entity_state': 'active',
        'entity': 'http://test-doppel.com',  # Provide an entity for testing
        'comment': 'Test update comment'
    }

    mock_response = util_load_json('test_data/get-alert.json')

    # Set up the mock return value
    client.update_alert.return_value = mock_response

    # Call the command function
    result = doppel_update_alert_command(client, args)

    # Assert that the result's human-readable output is generated correctly
    assert 'Alert Summary' in result.readable_output  # Check if the title exists
    assert isinstance(result, CommandResults)  # Ensure the result is a CommandResults object
    assert result.outputs_prefix == 'Doppel.UpdatedAlert'  # Ensure the outputs prefix is correct
    assert result.outputs_key_field == 'id'  # Ensure the key field is correct
    assert result.outputs == mock_response  # Ensure the correct output is returned


def test_doppel_get_alerts_command(client, mocker):

    mock_data = util_load_json('test_data/get-all-alerts.json')
    mocker.patch.object(client, 'get_alerts', return_value=mock_data)

    args = {
        'search_key': 'test-key',
        'queue_state': 'open',
        'product': 'domains',
        'created_before': '2025-01-01T00:00:00Z',
        'created_after': '2025-01-01T00:00:00Z',
        'sort_type': 'created',
        'sort_order': 'asc',
        'page': 1,
        'tags': 'tag1,tag2'
    }

    result = doppel_get_alerts_command(client, args)

    assert isinstance(result, CommandResults)

    assert result.outputs_prefix == 'Doppel.GetAlerts'
    assert result.outputs_key_field == 'id'
    assert result.outputs['alerts'][0]['id'] == 'TET-1953443'
    assert 'Alert Summary' in result.readable_output


def test_doppel_create_alert_command(client, mocker):
    test_response = util_load_json('test_data/create-alert.json')

    client.create_alert.return_value = test_response

    args = {
        'entity': 'test-doppel.com'  # Ensure 'entity' is included in the arguments
    }

    result = doppel_create_alert_command(client, args)

    assert isinstance(result, CommandResults)

    assert result.outputs_prefix == 'Doppel.CreatedAlert'
    assert result.outputs_key_field == 'id'
    assert result.outputs == test_response  # Check if the result matches the mocked response

    assert "Alert Summary" in result.readable_output


def test_doppel_create_alert_command_missing_entity(client):
    """Test case when 'entity' is missing in the arguments."""
    args = {}  # Missing 'entity'

    with pytest.raises(ValueError, match="Entity must be specified to create an alert."):
        doppel_create_alert_command(client, args)


def test_doppel_create_abuse_alert_command(client, mocker):
    test_response = util_load_json('test_data/create-abuse-alert.json')

    client.create_abuse_alert.return_value = test_response

    args = {'entity': 'test-doppel.com'}

    result = doppel_create_abuse_alert_command(client, args)

    assert isinstance(result, CommandResults)

    assert result.outputs_prefix == 'Doppel.AbuseAlert'
    assert result.outputs_key_field == 'id'

    expected_output = util_load_json('test_data/create-abuse-alert.json')

    assert result.outputs == expected_output

    assert 'Alert Summary' in result.readable_output


def test_doppel_create_abuse_alert_command_missing_entity(client):
    args = {}

    with pytest.raises(ValueError, match="Entity must be specified to create an abuse alert."):
        doppel_create_abuse_alert_command(client, args)
