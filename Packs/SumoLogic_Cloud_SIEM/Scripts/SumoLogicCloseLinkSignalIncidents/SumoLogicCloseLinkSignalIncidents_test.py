from SumoLogicCloseLinkSignalIncidents import *


def execute_command_mock(command, args):
    incident_search_raw = [{'Contents': {'total': 1, 'data': [{'id': 'INSIGHT-1234',
                            'rawType': 'Sumo Logic Insight', 'linkedIncidents': ['11', '12']}]}}]
    close_investigation_raw = [{'Contents': {'total': 1, 'data': [{'id': 'INSIGHT-1234',
                                'rawType': 'Sumo Logic Insight', 'linkedIncidents': ['11', '12']}]}}]
    if command == 'getIncidents':
        return incident_search_raw
    if command == 'closeInvestigation':
        return close_investigation_raw
    else:
        raise ValueError("Command is not supported")


def test_close_linked_signal_incidents_command(mocker):
    incident = {'id': 'INSIGHT-1234'}
    mocker.patch('demistomock.incident', return_value=incident)
    mocker.patch('demistomock.executeCommand', side_effect=execute_command_mock)
    response = close_linked_signal_incidents_command({'id': 'INSIGHT-1234'})
    assert response.outputs_prefix == 'BaseScript'
    assert response.outputs['message']['data'][0]['linkedIncidents'][0] == '11'


def test_close_linked_signal_incidents_command_on_signal(mocker):
    incident = {'id': 'SIGNAL-00853cdd-763e-3e31-a2e4-f74277922f9f'}
    mocker.patch('demistomock.incident', return_value=incident)
    response = close_linked_signal_incidents_command({'id': incident['id']})
    assert response.outputs_prefix == 'BaseScript'
    assert response.outputs['message'] == 'Please run this on a valid Sumo Logic Insight incident only'
