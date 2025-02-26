import json
import pytest
import demistomock as demisto
from unittest.mock import MagicMock, Mock, patch
from datetime import datetime
from Doppel import test_module, fetch_incidents_command, _get_last_fetch_datetime, _get_mirroring_fields, _paginated_call_to_get_alerts, _get_remote_updated_incident_data_with_entry, get_remote_data_command, update_remote_system_command, get_mapping_fields_command, doppel_get_alert_command, doppel_update_alert_command, doppel_get_alerts_command, doppel_create_alert_command, doppel_create_abuse_alert_command
from Packs.Base.Scripts.CommonServerPython.CommonServerPython import *

ALERTS_RESPONSE = [
    {"id": "1", "created_at": "2025-02-01T12:00:00Z"},
    {"id": "2", "created_at": "2025-02-01T12:05:00Z"}
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

# The test function using pytest and mocker
@pytest.fixture
def client():
    # Create a mock client
    client = MagicMock()
    client.get_alert = mock_http_request
    client.create_abuse_alert = MagicMock(side_effect=mock_http_request)
    return client

def test_test_module(client, mocker):
    mocker.patch.object(client, '_http_request', side_effect=mock_http_request)
    result = test_module(client, {})
    assert result == 'ok'

@pytest.fixture
def mock_client():
    """Fixture to mock the Client object."""
    client = MagicMock(spec=Client)
    
    # Mocking fetch alerts (Used in fetch_incidents_command)
    client.get_alerts.return_value = ALERTS_RESPONSE  
    
    # Mocking fetch single alert (Used in update_remote_system_command)
    client.get_alert.return_value = {
        "id": "123", 
        "queue_state": "open", 
        "entity_state": "active"
    }

    # Mocking update alert (Used in update_remote_system_command)
    client.update_alert.return_value = None  # Assume update succeeds
    
    return client


def test_fetch_incidents_command(mock_client, mocker):
    """Test fetch_incidents_command function."""

    # Mocking demisto functions using mocker.patch.object
    mocker.patch.object(demisto, "params", return_value={"max_fetch": 2, "fetch_timeout": "10"})
    mocker.patch.object(demisto, "getLastRun", return_value={"last_run": "2025-02-01T11:50:00Z", "incidents_queue": []})
    mock_setLastRun = mocker.patch.object(demisto, "setLastRun")
    mock_incidents = mocker.patch.object(demisto, "incidents")
    mock_debug = mocker.patch.object(demisto, "debug")
    mock_info = mocker.patch.object(demisto, "info")

    # Run the function
    fetch_incidents_command(mock_client, {})

    # Assertions
    mock_setLastRun.assert_called_once()
    last_run_data = mock_setLastRun.call_args[0][0]
    assert "last_run" in last_run_data, "last_run key should be in setLastRun data"
    assert isinstance(last_run_data["incidents_queue"], list), "incidents_queue should be a list"

    mock_incidents.assert_called_once()
    incidents_created = mock_incidents.call_args[0][0]
    assert len(incidents_created) == 2, "Expected 2 incidents to be created"
    assert incidents_created[0]["name"].startswith("Doppel Incident"), "Incident name should start with 'Doppel Incident'"

    mock_debug.assert_called()  # Ensure debug logs are being generated
    mock_info.assert_called()   # Ensure info



@pytest.mark.parametrize('remote_incident_id, last_update, expected_result', [
    ('incident123', '2025-01-27T07:55:10.063742', {'id': 'incident123'}),
    ('incident456', None, {'id': 'incident456'})
])
def test_get_remote_data_command(client, mocker, remote_incident_id, last_update, expected_result):
    mock_demisto = MagicMock()
    
    mocker.patch.object(demisto, 'debug')
    mocker.patch.object(demisto, 'error')
    mocker.patch.object(demisto, 'setLastRun')
    mocker.patch.object(demisto, 'incidents')

    mock_get_remote_data_args = mocker.patch(GetRemoteDataArgs)
    mock_get_remote_data_args.return_value.remote_incident_id = remote_incident_id
    mock_get_remote_data_args.return_value.last_update = last_update

    mock_get_remote_updated_incident_data_with_entry = mocker.patch(_get_remote_updated_incident_data_with_entry)
    mock_get_remote_updated_incident_data_with_entry.return_value = (expected_result, [])

    args = {'id': remote_incident_id, 'lastUpdate': last_update}

    result = get_remote_data_command(client, args)

    # Assert that the result matches the expected result
    assert result.mirrored_object == expected_result
    assert result.entries == [{}]

    # Assert that demisto.debug was called
    mock_demisto.debug.assert_called()

    # Assert that demisto.setLastRun was called
    mock_demisto.setLastRun.assert_called()

    # Assert that demisto.incidents was called
    mock_demisto.incidents.assert_called()



def test_update_remote_system_command(mock_client, mocker):
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
    result = update_remote_system_command(mock_client, args)

    # Assertions
    assert result == "123", "Returned remoteId should match input"
    mock_debug.assert_called()  # Ensure debug logs are being generated
    mock_error.assert_not_called()  # Ensure no errors were logged

def test_get_mapping_fields_command(mock_client, mocker):
    """Test get_mapping_fields_command function."""

    # Mocking demisto functions using mocker.patch.object
    mock_debug = mocker.patch.object(demisto, "debug")

    # Run the function
    result = get_mapping_fields_command(mock_client, {})

    # Assertions
    assert result is not None, "Result should not be None"
    assert hasattr(result, "extract_mapping"), "Result should have extract_mapping method"
    
    mock_debug.assert_called()  # Ensure debug logs are generated





def test_doppel_get_alert_command(client, mocker):
    mocker.patch.object(client, '_http_request', side_effect=mock_http_request)

    # Sample arguments for testing
    args = {'id': 'TET-1953443'}  # Example test with an ID (use appropriate values)
    
    result = doppel_get_alert_command(client, args)

    assert isinstance(result, CommandResults)
    assert result.outputs_prefix == 'Doppel.Alert'
    assert result.outputs_key_field == 'id'
    assert result.outputs.get('id') == 'TET-1953443'  # Adjust as per the sample response structure
    assert 'Alert Summary' in result.readable_output  # Check if human-readable output contains expected text
    
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

@patch("demistomock")  # Mock demisto module
def test_doppel_update_alert_command(mock_demisto, client):
    mock_client = Mock(spec=client)

    args = {
        "alert_id": "incident123",
        "queue_state": "archived",
        "entity_state": "closed",
        "comment": "Updated alert"
    }

    mock_client.update_alert.return_value = {"status": "success"}

    # Call the function
    result = doppel_update_alert_command(mock_client, args)

    # Assertions
    assert isinstance(result, CommandResults), "Function should return a CommandResults object"
    assert result.outputs == {"status": "success"}, "Expected correct API response in outputs"

    # Ensure the update_alert method was called with correct parameters
    mock_client.update_alert.assert_called_with(
        queue_state="archived",
        entity_state="closed",
        comment="Updated alert",
        alert_id="incident123"
    )

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

def test_doppel_update_alert_command_missing_params(client):
    """Test the function when required parameters are missing"""
    args = {
        'alert_id': '',  # Neither alert_id nor entity is passed
        'queue_state': '',  # Missing queue_state
        'entity_state': '',  # Missing entity_state
        'entity': '',
        'comment': 'Test update comment'
    }
    
    with pytest.raises(ValueError):
        doppel_update_alert_command(client, args)

def test_doppel_get_alerts_command(client, mocker):
    mocker.patch.object(client, 'get_alerts', side_effect=mock_http_request)
    
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
    
    assert 'outputs_prefix' in result.to_context()
    assert 'outputs_key_field' in result.to_context()
    assert 'outputs' in result.to_context()
    assert 'readable_output' in result.to_context()
    
    assert 'id' in result.to_context()['Doppel.GetAlerts']
    
    assert 'Alert Summary' in result.readable_output
    assert 'test-key' in result.readable_output  # Based on the mock response

def test_doppel_create_alert_command(client, mocker):
    test_response = util_load_json('test_data/create-alert.json')
    
    client.create_alert.return_value = test_response
    
    args = {
        'entity': 'test-doppel.com'  # Ensure 'entity' is included in the arguments
    }

    result = doppel_create_alert_command(client, args)

    assert result.outputs_prefix == 'Doppel.CreatedAlert'
    assert result.outputs_key_field == 'id'
    assert result.outputs == test_response  # Check if the result matches the mocked response

    assert "Alert Summary" in result.readable_output
    assert "test-doppel.com" in result.readable_output.split()  # Ensure the entity is included in the output

def test_doppel_create_alert_command_missing_entity(client):
    """Test case when 'entity' is missing in the arguments."""
    args = {}  # Missing 'entity'

    with pytest.raises(ValueError, match="Entity must be specified to create an alert."):
        doppel_create_alert_command(client, args)

def test_doppel_create_abuse_alert_command(client, mocker):
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
