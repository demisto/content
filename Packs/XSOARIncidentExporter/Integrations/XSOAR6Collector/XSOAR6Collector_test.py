import json
import pytest
from XSOAR6Collector import (
    map_xsoar_incident_to_xsiam,
    test_module,
    get_incidents_command,
    get_incident_command,
)


def load_test_data(filename):
    with open(f'test_data/{filename}') as f:
        return json.load(f)


MOCK_INCIDENTS = load_test_data('search_incidents_response.json')['data']


class TestMapXsoarIncidentToXsiam:
    def test_maps_required_fields(self):
        result = map_xsoar_incident_to_xsiam(MOCK_INCIDENTS[0])
        assert result['name'] == 'Malware Detection'
        assert result['severity'] == 3
        assert result['rawJSON']
        assert result['dbotMirrorId'] == '200'

    def test_custom_incident_type(self):
        result = map_xsoar_incident_to_xsiam(MOCK_INCIDENTS[0], incident_type='CustomType')
        assert result['type'] == 'CustomType'

    def test_default_incident_type(self):
        result = map_xsoar_incident_to_xsiam(MOCK_INCIDENTS[0])
        assert result['type'] == 'Malware'

    def test_custom_fields_mapped(self):
        result = map_xsoar_incident_to_xsiam(MOCK_INCIDENTS[0])
        assert result['CustomFields']['xsoar6incidentid'] == '200'
        assert result['CustomFields']['xsoar6owner'] == 'admin'


class TestTestModule:
    def test_ok(self, mocker):
        mock_client = mocker.MagicMock()
        assert test_module(mock_client) == 'ok'

    def test_failure_raises(self, mocker):
        mock_client = mocker.MagicMock()
        mock_client.search_incidents.side_effect = Exception('connection refused')
        with pytest.raises(Exception):
            test_module(mock_client)


class TestGetIncidentsCommand:
    def test_returns_results(self, mocker):
        mock_client = mocker.MagicMock()
        mock_client.search_incidents.return_value = MOCK_INCIDENTS

        result = get_incidents_command(mock_client, {'limit': '10'})
        assert result.outputs_prefix == 'XSOAR6.Incidents'
        assert len(result.outputs) == 1
        assert 'Malware Detection' in result.readable_output

    def test_empty_results(self, mocker):
        mock_client = mocker.MagicMock()
        mock_client.search_incidents.return_value = []

        result = get_incidents_command(mock_client, {})
        assert result.outputs == []


class TestGetIncidentCommand:
    def test_returns_incident(self, mocker):
        mock_client = mocker.MagicMock()
        mock_client.get_incident.return_value = MOCK_INCIDENTS[0]

        result = get_incident_command(mock_client, {'incident_id': '200'})
        assert result.outputs_prefix == 'XSOAR6.Incident'
        assert result.outputs['id'] == '200'

    def test_incident_not_found(self, mocker):
        mock_client = mocker.MagicMock()
        mock_client.get_incident.return_value = None

        result = get_incident_command(mock_client, {'incident_id': '999'})
        assert 'No incident found' in result.readable_output

    def test_missing_id_raises(self, mocker):
        mock_client = mocker.MagicMock()
        with pytest.raises(Exception):
            get_incident_command(mock_client, {'incident_id': ''})
