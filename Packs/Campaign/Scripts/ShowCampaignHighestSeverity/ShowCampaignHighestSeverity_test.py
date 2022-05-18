from ShowCampaignHighestSeverity import *
import pytest


data_test_get_incident_severity = [
    ('data_test/get_incident.json', 3)
]


@pytest.mark.parametrize('incident_data_path, expected_severity', data_test_get_incident_severity)
def test_get_incident_severity(mocker, incident_data_path, expected_severity):
    with open(incident_data_path, 'r') as incident_data_file:
        incident_data = json.load(incident_data_file)
    mocker.patch.object(demisto, 'executeCommand', return_value=incident_data)
    assert get_incident_severity('test') == expected_severity


data_test_incidents_id = [
    ('data_test/demisto_context.json', ['937', '934', '935', '936', '940', '944', '943', '938', '941', '939'])
]


@pytest.mark.parametrize('context_data_path, expected_ids', data_test_incidents_id)
def test_incidents_id(mocker, context_data_path, expected_ids):
    with open(context_data_path, 'r') as context_data_file:
        context_data = json.load(context_data_file)
    mocker.patch.object(demisto, 'context', return_value=context_data)
    assert list(incidents_id()) == expected_ids
