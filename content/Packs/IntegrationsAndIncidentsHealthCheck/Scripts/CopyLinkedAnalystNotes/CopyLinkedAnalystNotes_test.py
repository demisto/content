import demistomock as demisto
from CopyLinkedAnalystNotes import create_grids
from test_data.constants import CURRENT_INCIDENT, LINKED_INCIDENTS, MAIN_INTEGRATION_GRID, MAIN_INCIDENT_GRID


def test_create_grids(mocker):
    mocker.patch.object(demisto, 'executeCommand', return_value=LINKED_INCIDENTS)
    mocker.patch.object(demisto, 'incidents', return_value=CURRENT_INCIDENT)
    mocker.patch.object(demisto, 'results')

    custom_fields = CURRENT_INCIDENT[0].get('CustomFields')
    linked_incident = custom_fields.get('similarincident')

    integration_grid, incident_grid = create_grids(custom_fields, linked_incident)

    assert integration_grid == MAIN_INTEGRATION_GRID
    assert incident_grid == MAIN_INCIDENT_GRID
