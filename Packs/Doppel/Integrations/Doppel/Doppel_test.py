import json
import pytest
import demistomock as demisto
from unittest.mock import MagicMock, Mock, patch
from datetime import datetime
from Doppel import test_module, fetch_incidents_command, _get_last_fetch_datetime, _get_mirroring_fields, _paginated_call_to_get_alerts, _get_remote_updated_incident_data_with_entry, get_remote_data_command, update_remote_system_command, get_mapping_fields_command, doppel_get_alert_command, doppel_update_alert_command, doppel_get_alerts_command, doppel_create_alert_command, doppel_create_abuse_alert_command
from Packs.Base.Scripts.CommonServerPython.CommonServerPython import *

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

# @pytest.mark.parametrize('fetch_timeout, max_fetch', [(30, 10)])
# def test_fetch_incidents_command(client, mocker, fetch_timeout, max_fetch):
#     mock_demisto = MagicMock()
#     mocker.patch('demisto.debug')
#     mocker.patch('demisto.setLastRun')
#     mocker.patch('demisto.incidents')

#     mock_get_last_fetch_datetime = mocker.patch(_get_last_fetch_datetime)
#     mock_get_last_fetch_datetime.return_value = (datetime.now(), [])

#     mock_paginated_call = mocker.patch(_paginated_call_to_get_alerts)
#     mock_paginated_call.return_value = [{'created_at': datetime.now().isoformat()}]

#     mock_get_mirroring_fields = mocker.patch(_get_mirroring_fields)
#     mock_get_mirroring_fields.return_value = {'mirroring_field': 'value'}

#     args = {}

#     fetch_incidents_command(client, args)

#     mock_demisto.debug.assert_called()

#     mock_demisto.setLastRun.assert_called()

#     mock_demisto.incidents.assert_called()



@patch("demistomock")
@patch("_get_last_fetch_datetime")
@patch("_paginated_call_to_get_alerts")
@patch("_get_mirroring_fields")
def test_fetch_incidents_command(mock_get_mirroring_fields, mock_paginated_call_to_get_alerts, mock_get_last_fetch_datetime, mock_demisto):
    
    mock_demisto.params.return_value = {"fetch_timeout": 30, "max_fetch": 10}
    mock_demisto.getLastRun.return_value = {"last_run": None, "incidents_queue": []}

    test_last_fetch = datetime.utcnow() - timedelta(days=1)
    mock_get_last_fetch_datetime.return_value = test_last_fetch

    mock_get_mirroring_fields.return_value = {"mirror_direction": "Both"}

    mock_alerts = [
        {
            "id": str(uuid.uuid4()),
            "created_at": test_last_fetch.strftime(DOPPEL_PAYLOAD_DATE_FORMAT)
        }
    ]
    mock_paginated_call_to_get_alerts.side_effect = [mock_alerts, []]  # Simulate one page of alerts

    # Mock incidents and setLastRun
    mock_demisto.incidents = Mock()
    mock_demisto.setLastRun = Mock()

    # Call the function
    fetch_incidents_command(Mock(spec=Client), {})

    # Assertions
    mock_demisto.debug.assert_called()  # Ensure debug logging is used
    mock_demisto.incidents.assert_called()  # Ensure incidents are created
    mock_demisto.setLastRun.assert_called()  # Ensure last run is updated

    # Validate incidents format
    incidents_created = mock_demisto.incidents.call_args[0][0]
    assert len(incidents_created) == 1, "Should create one incident"
    assert incidents_created[0]["type"] == DOPPEL_ALERT, "Incident type mismatch"
    assert "occurred" in incidents_created[0], "Incident should have an 'occurred' field"
    assert "dbotMirrorId" in incidents_created[0], "Incident should have 'dbotMirrorId'"
    assert "rawJSON" in incidents_created[0], "Incident should have 'rawJSON'"


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


@patch("demistomock")
@patch("UpdateRemoteSystemArgs")
def test_update_remote_system_command(mock_update_args, mock_demisto):
    # Mock the client
    mock_client = Mock(spec=Client)

    # Mock parsed arguments
    mock_parsed_args = Mock()
    mock_parsed_args.remote_incident_id = "incident123"
    mock_parsed_args.inc_status = IncidentStatus.DONE  # Simulate incident closure
    mock_parsed_args.incident_changed = True
    mock_parsed_args.data = {"queue_state": "active", "entity_state": "open"}
    mock_parsed_args.delta = {"notes": "Updated in XSOAR"}

    # Set return value for UpdateRemoteSystemArgs
    mock_update_args.return_value = mock_parsed_args

    # Mock `get_alert` response
    mock_client.get_alert.return_value = {"queue_state": "active", "entity_state": "open"}

    # Call the function
    result = update_remote_system_command(mock_client, {"remoteId": "incident123"})

    # Assertions
    assert result == "incident123", "Expected remote incident ID to be returned"

    # Ensure `get_alert` was called to fetch existing data
    mock_client.get_alert.assert_called_with(id="incident123", entity="")

    # Ensure `update_alert` was called to update the remote incident
    mock_client.update_alert.assert_called_with(
        queue_state="archived",
        entity_state="open",
        comment="Updated in XSOAR",
        alert_id="incident123"
    )

    # Ensure debug logs were used
    mock_demisto.debug.assert_called()


# def test_update_remote_system_command(client, mocker):
#     mock_args = {
#         'remote_incident_id': '12345',
#         'inc_status': IncidentStatus.DONE,
#         'delta': {'closeReason': 'Resolved', 'closeNotes': 'Issue fixed', 'closingUserId': 'user1'},
#         'incident_changed': True
#     }
#     mocker.patch.object(UpdateRemoteSystemArgs, '__init__', lambda x, y: None)
#     mocker.patch.object(UpdateRemoteSystemArgs, 'remote_incident_id', mock_args['remote_incident_id'])
#     mocker.patch.object(UpdateRemoteSystemArgs, 'inc_status', mock_args['inc_status'])
#     mocker.patch.object(UpdateRemoteSystemArgs, 'delta', mock_args['delta'])
#     mocker.patch.object(UpdateRemoteSystemArgs, 'incident_changed', mock_args['incident_changed'])

#     mock_get_alert = MagicMock()
#     mock_get_alert.return_value = {'id': '12345', 'entity_state': 'active', 'queue_state': 'open'}
#     client.get_alert = mock_get_alert
#     client.update_alert = MagicMock()

#     result = update_remote_system_command(client, mock_args)

#     client.get_alert.assert_called_once_with(id='12345', entity=None)
#     client.update_alert.assert_called_once_with(
#         queue_state='archived',
#         entity_state='active',
#         alert_id='12345'
#     )
#     assert result == '12345'

# def test_get_mapping_fields_command(client):
#     """Test the get_mapping_fields_command function."""
#     mock_scheme = MagicMock(spec=SchemeTypeMapping)
#     mock_scheme.add_field = MagicMock()

#     mock_response = MagicMock(spec=GetMappingFieldsResponse)
#     mock_response.add_scheme_type = MagicMock()

#     with patch('SchemeTypeMapping', return_value=mock_scheme), \
#          patch('GetMappingFieldsResponse', return_value=mock_response):
#         result = get_mapping_fields_command(client, {})

#     mock_scheme.add_field.assert_called_once_with(name='queue_state', description='Queue State of the Doppel Alert')

#     mock_response.add_scheme_type.assert_called_once_with(mock_scheme)

#     assert result == mock_response


def test_get_mapping_fields_command(client):
    """Test the get_mapping_fields_command function."""
    mock_client = Mock(spec=client)

    response = get_mapping_fields_command(mock_client, {})

    assert isinstance(response, GetMappingFieldsResponse)

    assert len(response.scheme_types_mappings) == 1
    mapping = response.scheme_types_mappings[0]
    assert mapping.type_name == 'Doppel Alert'

    assert len(mapping.fields) == 1
    assert mapping.fields[0].name == 'queue_state'
    assert mapping.fields[0].description == 'Queue State of the Doppel Alert'


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
