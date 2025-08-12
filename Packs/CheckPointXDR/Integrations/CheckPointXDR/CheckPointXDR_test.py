import datetime
import json
from CheckPointXDR import (Client, update_remote_system_command, fetch_incidents,
                           get_instances_id, map_severity, parse_incidents, test_module as check_module)
from CommonServerPython import IncidentStatus


def util_load_json(path):
    with open(path, encoding='utf-8') as f:
        return json.loads(f.read())


def test_test_module(mocker):
    client = Client(
        base_url='https://cloudinfra-gw.portal.checkpoint.com',
        client_id='****',
        access_key='****',
        verify=False,
        proxy=False
    )

    login = mocker.patch.object(
        Client,
        '_login',
        return_value=None,
    )
    mock_response = util_load_json('./test_data/checkpointxdr-get_incidents.json')
    query_events = mocker.patch.object(
        Client,
        'get_incidents',
        return_value=mock_response.get('objects'),
    )
    logout = mocker.patch.object(
        Client,
        '_logout',
        return_value=None,
    )

    result = check_module(client, {}, datetime.datetime(2024, 1, 1))
    login.assert_called_once()
    query_events.assert_called()
    logout.assert_called_once()
    assert result == 'ok'


def test_parse_incidents():
    mock_incidents = util_load_json('./test_data/checkpointxdr-get_incidents.json').get('objects')

    mock_result = (util_load_json('./test_data/checkpointxdr-parse_incident-output.json'),
                   datetime.datetime.fromtimestamp(1703387404.364).isoformat())

    result = parse_incidents(mock_incidents, {}, 10, 0)
    assert result == mock_result


def test_fetch_incidents(mocker):
    client = Client(
        base_url='https://cloudinfra-gw.portal.checkpoint.com',
        client_id='****',
        access_key='****',
        verify=False,
        proxy=False
    )

    login = mocker.patch.object(
        Client,
        '_login',
        return_value=None,
    )
    mock_insights_response = util_load_json('./test_data/checkpointxdr-get_incidents.json')
    query_insights = mocker.patch.object(
        Client,
        'get_incidents',
        return_value=mock_insights_response.get('objects'),
    )
    logout = mocker.patch.object(
        Client,
        '_logout',
        return_value=None,
    )

    fetch_incidents(client, {}, {}, datetime.datetime(2024, 1, 1), 1000)
    login.assert_called_once()
    query_insights.assert_called()
    logout.assert_called_once()


def test_update_remote_system_command_close_true(mocker):
    client = Client("https://dummy.url", "id", "key", False, False)

    mock_update_incident = mocker.patch.object(Client, 'update_incident', return_value={})
    mocker.patch('CheckPointXDR.demisto.params', return_value={"close_out": True})
    mocker.patch('CheckPointXDR.demisto.debug')
    mocker.patch('CheckPointXDR.demisto.error')
    mocker.patch('CheckPointXDR.argToBoolean', return_value=True)

    args = {
        "remote_incident_id": "123",
        "delta": {"closeReason": "False Positive"},
        "incident_changed": True,
        "inc_status": IncidentStatus.DONE,
        "data": {}
    }

    result = update_remote_system_command(client, args)
    assert result == "123"
    mock_update_incident.assert_called_once_with(status=IncidentStatus.DONE, close_reason="False Positive", incident_id="123")


def test_update_remote_system_command_close_false(mocker):
    client = Client("https://dummy.url", "id", "key", False, False)

    mock_update_incident = mocker.patch.object(Client, 'update_incident')
    mocker.patch('CheckPointXDR.demisto.params', return_value={"close_out": False})
    mocker.patch('CheckPointXDR.demisto.debug')
    mocker.patch('CheckPointXDR.argToBoolean', return_value=False)

    args = {
        "remote_incident_id": "321",
        "delta": {"closeReason": "Duplicate"},
        "incident_changed": True,
        "inc_status": IncidentStatus.DONE,
        "data": {}
    }

    result = update_remote_system_command(client, args)
    assert result == "321"
    mock_update_incident.assert_not_called()


def test_map_severity_levels():
    assert map_severity("Low") == 1
    assert map_severity("medium") == 2
    assert map_severity("HIGH") == 3
    assert map_severity("critical") == 4
    assert map_severity("unknown") == 1  # default fallback


def test_get_instances_id_found(mocker):
    mocker.patch('CheckPointXDR.demisto.getIntegrationContext', return_value={"instances_id": "abc123"})
    
    result = get_instances_id()
    assert result == "abc123"


def test_get_instances_id_cached(mocker):
    mocker.patch('CheckPointXDR.demisto.getIntegrationContext', return_value={"instances_id": "cached123"})
    result = get_instances_id()
    assert result == "cached123"
