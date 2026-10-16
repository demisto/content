import json
import pytest
from XSIAMAlertPusher import (
    map_severity,
    parse_date_to_epoch_ms,
    build_description,
    build_raw_context,
    map_incident_to_alert,
    push_incidents_command,
    push_single_incident_command,
    sync_new_incidents_command,
    reset_sync_command,
    test_module,
)


def load_test_data(filename):
    with open(f'test_data/{filename}') as f:
        return json.load(f)


MOCK_INCIDENTS = load_test_data('search_incidents_response.json')['data']


class TestMapSeverity:
    def test_low_severity(self):
        assert map_severity(1) == 'Low'

    def test_medium_severity(self):
        assert map_severity(2) == 'Medium'

    def test_high_severity(self):
        assert map_severity(3) == 'High'

    def test_critical_severity(self):
        assert map_severity(4) == 'Critical'

    def test_unknown_defaults_to_low(self):
        assert map_severity(99) == 'Low'

    def test_elevate_low_to_medium(self):
        assert map_severity(1, elevate_low=True) == 'Medium'

    def test_elevate_low_does_not_affect_medium(self):
        assert map_severity(2, elevate_low=True) == 'Medium'


class TestParseDateToEpochMs:
    def test_valid_date(self):
        result = parse_date_to_epoch_ms('2026-09-01T12:00:00Z')
        assert isinstance(result, int)
        assert result > 0

    def test_none_returns_current_time(self):
        result = parse_date_to_epoch_ms(None)
        assert isinstance(result, int)
        assert result > 0

    def test_empty_string_returns_current_time(self):
        result = parse_date_to_epoch_ms('')
        assert isinstance(result, int)
        assert result > 0


class TestBuildDescription:
    def test_contains_incident_id(self):
        desc = build_description(MOCK_INCIDENTS[0])
        assert 'XSOAR Incident ID: 100' in desc

    def test_contains_name(self):
        desc = build_description(MOCK_INCIDENTS[0])
        assert 'Name: Test Incident 1' in desc

    def test_contains_close_reason_when_closed(self):
        desc = build_description(MOCK_INCIDENTS[1])
        assert 'Close Reason: Resolved' in desc

    def test_contains_labels(self):
        desc = build_description(MOCK_INCIDENTS[0])
        assert 'Brand: Manual' in desc


class TestBuildRawContext:
    def test_returns_valid_json(self):
        raw = build_raw_context(MOCK_INCIDENTS[0])
        parsed = json.loads(raw)
        assert isinstance(parsed, dict)

    def test_excludes_internal_keys(self):
        incident = {**MOCK_INCIDENTS[0], 'ShardID': '123', 'allRead': True}
        raw = build_raw_context(incident)
        parsed = json.loads(raw)
        assert 'ShardID' not in parsed
        assert 'allRead' not in parsed


class TestMapIncidentToAlert:
    def test_required_fields_present(self):
        alert = map_incident_to_alert(MOCK_INCIDENTS[0])
        assert alert['product'] == 'XSOAR'
        assert alert['vendor'] == 'Palo Alto Networks'
        assert 'event_timestamp' in alert
        assert 'severity' in alert
        assert 'alert_name' in alert

    def test_timestamp_offset_applied(self):
        alert_no_offset = map_incident_to_alert(MOCK_INCIDENTS[0], timestamp_offset=0)
        alert_with_offset = map_incident_to_alert(MOCK_INCIDENTS[0], timestamp_offset=60)
        assert alert_with_offset['event_timestamp'] == alert_no_offset['event_timestamp'] + 60 * 60 * 1000

    def test_elevate_low(self):
        low_incident = {**MOCK_INCIDENTS[0], 'severity': 1}
        alert = map_incident_to_alert(low_incident, elevate_low=True)
        assert alert['severity'] == 'Medium'

    def test_xsoar_fields_mapped(self):
        alert = map_incident_to_alert(MOCK_INCIDENTS[0])
        assert alert['xsoar_incident_id'] == '100'
        assert alert['xsoar_incident_type'] == 'Unclassified'


class TestPushIncidentsCommand:
    def test_no_incidents_found(self, mocker):
        mock_xsoar = mocker.MagicMock()
        mock_xsoar.search_incidents.return_value = []
        mock_xsiam = mocker.MagicMock()

        result = push_incidents_command(mock_xsiam, mock_xsoar, {}, None, 100)
        assert 'No incidents found' in result.readable_output

    def test_pushes_incidents(self, mocker):
        mock_xsoar = mocker.MagicMock()
        mock_xsoar.search_incidents.return_value = MOCK_INCIDENTS
        mock_xsiam = mocker.MagicMock()

        result = push_incidents_command(mock_xsiam, mock_xsoar, {}, None, 100)
        assert mock_xsiam.insert_parsed_alerts.called
        assert '2 incident(s)' in result.readable_output


class TestPushSingleIncidentCommand:
    def test_missing_incident_id(self, mocker):
        mock_xsoar = mocker.MagicMock()
        mock_xsiam = mocker.MagicMock()

        with pytest.raises(Exception, match='incident_id'):
            push_single_incident_command(mock_xsiam, mock_xsoar, {})

    def test_incident_not_found(self, mocker):
        mock_xsoar = mocker.MagicMock()
        mock_xsoar.search_incidents.return_value = []
        mock_xsiam = mocker.MagicMock()

        with pytest.raises(Exception, match='not found'):
            push_single_incident_command(mock_xsiam, mock_xsoar, {'incident_id': '999'})

    def test_pushes_single_incident(self, mocker):
        mock_xsoar = mocker.MagicMock()
        mock_xsoar.search_incidents.return_value = [MOCK_INCIDENTS[0]]
        mock_xsiam = mocker.MagicMock()

        result = push_single_incident_command(mock_xsiam, mock_xsoar, {'incident_id': '100'})
        assert mock_xsiam.insert_parsed_alerts.called
        assert '100' in result.readable_output


class TestSyncNewIncidentsCommand:
    def test_no_new_incidents(self, mocker):
        mocker.patch('XSIAMAlertPusher.demisto')
        from XSIAMAlertPusher import demisto as mock_demisto
        mock_demisto.getIntegrationContext.return_value = {'last_synced_id': 999}

        mock_xsoar = mocker.MagicMock()
        mock_xsoar.search_incidents.return_value = []
        mock_xsiam = mocker.MagicMock()

        result = sync_new_incidents_command(mock_xsiam, mock_xsoar, {}, None, 100)
        assert 'No new incidents' in result.readable_output


class TestResetSyncCommand:
    def test_reset(self, mocker):
        mocker.patch('XSIAMAlertPusher.demisto')
        result = reset_sync_command()
        assert 'reset' in result.readable_output.lower()


class TestTestModule:
    def test_ok(self, mocker):
        mock_xsoar = mocker.MagicMock()
        mock_xsiam = mocker.MagicMock()
        assert test_module(mock_xsiam, mock_xsoar) == 'ok'
