from SumoLogicLinkSignalIncidents import *
import demistomock as demisto


def execute_command_mock(command, args):
    incident_search_raw = [{'Contents': {'total': 1, 'data': [{'id': 'INSIGHT-1234',
                                                               'rawType': 'Sumo Logic Insight',
                                                               'labels': [{'type': 'signals', 'value':
                                                                          [{'id': '00853cdd-763e-3e31-a2e4-f74277922f9f'}]}]}]}}]
    signal_search_raw = [{'Contents': {'total': 1,
                                       'data': [{'id': 'SIGNAL-1234', 'rawType': 'Sumo Logic Signal',
                                                'labels': [{'type': 'signals',
                                                            'value': [{'id': '00853cdd-763e-3e31-a2e4-f74277922f9f'}]}]}]}}]
    incident_searchv2_raw = [{'Contents': [{'Contents': {'data': [{'id': '11', 'rawType': 'Sumo Logic Signal'},
                                                                  {'id': '11', 'rawType': 'Sumo Logic Signal'}]}}]}]
    link_incident_raw = [{'Contents': {'total': 1, 'data': [{'id': '11', 'rawType': 'Sumo Logic Insight',
                                                             'linkedIncidents': ['12', '13']}]}}]
    if command == 'getIncidents':
        if args['query'].startswith('id:SIGNAL'):
            return signal_search_raw
        else:
            return incident_search_raw
    if command == 'SearchIncidentsV2':
        return incident_searchv2_raw
    if command == 'linkIncidents':
        return link_incident_raw
    else:
        raise ValueError("Command is not supported")


def test_link_incidents_command(mocker):
    demisto_args = {'id': 'INSIGHT-1234'}
    mocker.patch.object(demisto, 'args', return_value=demisto_args)
    mocker.patch('demistomock.executeCommand', side_effect=execute_command_mock)
    response = link_incidents_command(None)
    assert response.outputs_prefix == 'BaseScript'
    assert response.outputs['message']['data'][0]['linkedIncidents'][0] == '12'


def test_link_incidents_command_on_signal(mocker):
    demisto_args = {'id': 'SIGNAL-00853cdd-763e-3e31-a2e4-f74277922f9f'}
    mocker.patch.object(demisto, 'args', return_value=demisto_args)
    mocker.patch('demistomock.executeCommand', side_effect=execute_command_mock)
    response = link_incidents_command(None)
    assert response.outputs_prefix == 'BaseScript'
    assert response.outputs['message'] == 'Please run this on a valid Sumo Logic Insight incident only'
