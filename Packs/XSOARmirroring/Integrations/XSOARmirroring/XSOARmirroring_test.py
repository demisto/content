from XSOARmirroring import get_mapping_fields_command, Client, fetch_incidents, update_remote_system_command, XSOAR_DATE_FORMAT
from datetime import datetime, timedelta
import dateparser
import pytest


def generate_dummy_client():
    class Client:
        def __init__(self):
            pass

        def get_incident_fields(self):
            pass

        def get_incident_types(self):
            pass

        def get_incident(self):
            pass

        def update_incident(self):
            pass

    return Client


INCIDENT_FIELDS = [
    {
        'group': 0,
        'associatedToAll': True,
        'name': "field1",
        'type': 'type1',
        'description': 'description1',
        'cliName': 'cliName1',
        'content': False,
        'system': True
    },
    {
        'group': 0,
        'associatedTypes': [
            "test"
        ],
        'name': "field2",
        'type': 'type2',
        'description': 'description2',
        'cliName': 'cliName2',
        'content': True,
        'system': True
    }
]
INCIDENT_TYPES = [
    {
        "name": "Something"
    },
    {
        "name": "test"
    }
]


def test_mirroring(mocker):
    """
    Given:
        - Two incident types and fields.

    When:
        - one field is associated to all while the second is associated to one.

    Then:
        - A correct mapping dict is created, with a "Default Scheme" included
    """
    client = generate_dummy_client()
    mocker.patch.object(client, 'get_incident_fields', return_value=INCIDENT_FIELDS)
    mocker.patch.object(client, 'get_incident_types', return_value=INCIDENT_TYPES)
    response = get_mapping_fields_command(client).extract_mapping()
    assert len(response) == 3
    assert 'Default Mapping' in str(response)
    assert response['Default Mapping'] == {
        'cliName1': 'field1 - type1'
    }
    assert response['test'] == {
        'CustomFields': {'cliName2': 'field2 - type2'},
        'cliName1': 'field1 - type1'
    }
    assert response['Something'] == {
        'cliName1': 'field1 - type1'
    }


INCIDENTS = [
    {
        "id": 1,
        "created": (datetime.now() - timedelta(minutes=10)).strftime(XSOAR_DATE_FORMAT)
    },
    {
        "id": 2,
        "created": (datetime.now() - timedelta(minutes=8)).strftime(XSOAR_DATE_FORMAT)
    },
    {
        "id": 3,
        "created": (datetime.now() - timedelta(minutes=5)).strftime(XSOAR_DATE_FORMAT)
    }
]

INCIDENTS_MIRRORING_PLAYBOOK_ID = [
    {"id": 1,
     "created": (datetime.now() - timedelta(minutes=10)).strftime(XSOAR_DATE_FORMAT),
     "playbookId": "test"}
]

REMOTE_INCIDENT = {
    "id": 1,
    "created": (datetime.now() - timedelta(minutes=10)).strftime(XSOAR_DATE_FORMAT),
    "CustomFields": {"custom_field": "some_custom_field"}
}


def test_fetch_incidents(mocker):
    """
    Given:
        - List of incidents.

    When:
        - Running the fetch_incidents and getting these incidents.

    Then:
        - Ensure the incidents result and the last_fetch in the LastRun object as expected.
    """
    mocker.patch.object(Client, 'search_incidents', return_value=INCIDENTS)

    first_fetch = dateparser.parse('3 days').strftime(XSOAR_DATE_FORMAT)
    client = Client("")

    next_run, incidents_result = fetch_incidents(client=client, max_results=3, last_run={}, first_fetch_time=first_fetch,
                                                 query='', mirror_direction='None', mirror_tag=[])

    assert len(incidents_result) == 3
    assert dateparser.parse(next_run['last_fetch']) == dateparser.parse(INCIDENTS[-1]['created']) + timedelta(milliseconds=1)


@pytest.mark.parametrize('mirror_playbook_id', (True, False))
def test_fetch_incidents_mirror_playbook_id(mocker, mirror_playbook_id: bool):
    """
    Given:
        - a list of incidents.

    When:
        - Running the fetch_incidents and getting this incident, with the *implicit* default `mirror_playbook_id = True`.

    Then:
        - Ensure the incident result does not contain playbookId field if and only if `mirror_playbook_id` is False.
    """
    mocker.patch.object(Client, 'search_incidents', return_value=INCIDENTS_MIRRORING_PLAYBOOK_ID)

    first_fetch = dateparser.parse('3 days').strftime(XSOAR_DATE_FORMAT)
    client = Client("dummy token")

    next_run, incidents_result = fetch_incidents(client=client, max_results=3, last_run={}, first_fetch_time=first_fetch,
                                                 query='', mirror_direction='None', mirror_tag=[],
                                                 mirror_playbook_id=mirror_playbook_id)

    assert len(incidents_result) == 1
    assert ("playbookId" in incidents_result[0]) is mirror_playbook_id


def test_update_remote_system(mocker):
    """
    Given:
        - Old incident and fields that were changed.

    When:
        - Running the update_remote_system_command.

    Then:
        - Ensure the incident was updated.
    """
    args = {'incidentChanged': True,
            'remoteId': 1,
            'delta': {'custom_field': 'updated_field'}
            }
    client = generate_dummy_client()
    mocker.patch.object(client, 'get_incident', return_value=REMOTE_INCIDENT)
    result = mocker.patch.object(client, 'update_incident')
    update_remote_system_command(client, args, {})
    assert result.call_args.kwargs['incident']['CustomFields']['custom_field'] == args['delta']['custom_field']


def test_adding_to_set():
    incidents: list = [{'id': '39', 'version': 337, 'cacheVersn': 0, 'modified': '2023-07-24T10:51:17.77260142Z', 'created': '2023-07-23T08:31:03.517549239Z', 'sizeInBytes': 0, 'sortValues': [' \x01C[]\x0e\x1f3Ur3'], 'dbotCreatedBy': 'admin', 'CustomFields': {'containmentsla': {'accumulatedPause': 0, 'breachTriggered': False, 'dueDate': '0001-01-01T00:00:00Z', 'endDate': '0001-01-01T00:00:00Z', 'lastPauseDate': '0001-01-01T00:00:00Z', 'runStatus': 'idle', 'sla': 30, 'slaStatus': -1, 'startDate': '0001-01-01T00:00:00Z', 'totalDuration': 0}, 'detectionsla': {'accumulatedPause': 0, 'breachTriggered': False, 'dueDate': '0001-01-01T00:00:00Z', 'endDate': '0001-01-01T00:00:00Z', 'lastPauseDate': '0001-01-01T00:00:00Z', 'runStatus': 'idle', 'sla': 20, 'slaStatus': -1, 'startDate': '0001-01-01T00:00:00Z', 'totalDuration': 0}, 'endpoint': [{}], 'failedlogonevents': 0, 'filerelationships': [{}, {}, {}], 'incidentduration': {'accumulatedPause': 0, 'breachTriggered': False, 'dueDate': '0001-01-01T00:00:00Z', 'endDate': '0001-01-01T00:00:00Z', 'lastPauseDate': '0001-01-01T00:00:00Z', 'runStatus': 'idle', 'sla': 0, 'slaStatus': -1, 'startDate': '0001-01-01T00:00:00Z', 'totalDuration': 0}, 'isactive': 'true', 'numberofrelatedincidents': 0, 'numberofsimilarfiles': 0, 'remediationsla': {'accumulatedPause': 0, 'breachTriggered': False, 'dueDate': '0001-01-01T00:00:00Z', 'endDate': '0001-01-01T00:00:00Z', 'lastPauseDate': '0001-01-01T00:00:00Z', 'runStatus': 'idle', 'sla': 7200, 'slaStatus': -1, 'startDate': '0001-01-01T00:00:00Z', 'totalDuration': 0}, 'similarincidentsdbot': [{}], 'timetoassignment': {'accumulatedPause': 0, 'breachTriggered': False, 'dueDate': '0001-01-01T00:00:00Z', 'endDate': '0001-01-01T00:00:00Z', 'lastPauseDate': '0001-01-01T00:00:00Z', 'runStatus': 'idle', 'sla': 0, 'slaStatus': -1, 'startDate': '0001-01-01T00:00:00Z', 'totalDuration': 0}, 'triagesla': {'accumulatedPause': 0, 'breachTriggered': False, 'dueDate': '0001-01-01T00:00:00Z', 'endDate': '0001-01-01T00:00:00Z', 'lastPauseDate': '0001-01-01T00:00:00Z', 'runStatus': 'idle', 'sla': 30, 'slaStatus': -1, 'startDate': '0001-01-01T00:00:00Z', 'totalDuration': 0}, 'urlsslverification': []}, 'account': '', 'autime': 1690101063517549239, 'type': 'Unclassified', 'rawType': 'Unclassified', 'name': 'dawn1', 'rawName': 'dawn1', 'status': 1, 'reason': '', 'occurred': '2023-07-23T08:31:03.517548948Z', 'closed': '0001-01-01T00:00:00Z', 'sla': 0, 'severity': 0, 'investigationId': '39', 'labels': [{'value': 'admin', 'type': 'Instance'}, {'value': 'Manual', 'type': 'Brand'}], 'attachment': None, 'details': '', 'openDuration': 0, 'lastOpen': '0001-01-01T00:00:00Z', 'closingUserId': '', 'owner': 'admin', 'activated': '0001-01-01T00:00:00Z', 'closeReason': '', 'rawCloseReason': '', 'closeNotes': '', 'playbookId': 'playbook0', 'dueDate': '2023-08-02T08:31:03.517549239Z', 'reminder': '0001-01-01T00:00:00Z', 'runStatus': 'error', 'notifyTime': '2023-07-23T08:31:06.096170177Z', 'phase': '', 'rawPhase': '', 'isPlayground': False, 'rawJSON': '', 'parent': '', 'category': '', 'rawCategory': '', 'linkedIncidents': None, 'linkedCount': 0, 'droppedCount': 0, 'sourceInstance': 'admin', 'sourceBrand': 'Manual', 'canvases': None, 'lastJobRunTime': '0001-01-01T00:00:00Z', 'feedBased': False, 'dbotMirrorId': '', 'dbotMirrorInstance': '', 'dbotMirrorDirection': '', 'dbotDirtyFields': None, 'dbotCurrentDirtyFields': None, 'dbotMirrorTags': None, 'dbotMirrorLastSync': '0001-01-01T00:00:00Z', 'isDebug': False, 'changeStatus': 'new', 'insights': 0}, {'id': '40', 'version': 338, 'cacheVersn': 0, 'modified': '2023-07-24T10:51:21.664747027Z', 'created': '2023-07-23T08:31:44.186129904Z', 'sizeInBytes': 0, 'sortValues': [' \x01C[]\x0e\x1f\x7f6\x04~'], 'dbotCreatedBy': 'admin', 'CustomFields': {'containmentsla': {'accumulatedPause': 0, 'breachTriggered': False, 'dueDate': '0001-01-01T00:00:00Z', 'endDate': '0001-01-01T00:00:00Z', 'lastPauseDate': '0001-01-01T00:00:00Z', 'runStatus': 'idle', 'sla': 30, 'slaStatus': -1, 'startDate': '0001-01-01T00:00:00Z', 'totalDuration': 0}, 'detectionsla': {'accumulatedPause': 0, 'breachTriggered': False, 'dueDate': '0001-01-01T00:00:00Z', 'endDate': '0001-01-01T00:00:00Z', 'lastPauseDate': '0001-01-01T00:00:00Z', 'runStatus': 'idle', 'sla': 20, 'slaStatus': -1, 'startDate': '0001-01-01T00:00:00Z', 'totalDuration': 0}, 'endpoint': [{}], 'failedlogonevents': 0, 'filerelationships': [{}, {}, {}], 'incidentduration': {'accumulatedPause': 0, 'breachTriggered': False, 'dueDate': '0001-01-01T00:00:00Z', 'endDate': '0001-01-01T00:00:00Z', 'lastPauseDate': '0001-01-01T00:00:00Z', 'runStatus': 'idle', 'sla': 0, 'slaStatus': -1, 'startDate': '0001-01-01T00:00:00Z', 'totalDuration': 0}, 'isactive': 'true', 'numberofrelatedincidents': 0, 'numberofsimilarfiles': 0, 'remediationsla': {'accumulatedPause': 0, 'breachTriggered': False, 'dueDate': '0001-01-01T00:00:00Z', 'endDate': '0001-01-01T00:00:00Z', 'lastPauseDate': '0001-01-01T00:00:00Z', 'runStatus': 'idle', 'sla': 7200, 'slaStatus': -1, 'startDate': '0001-01-01T00:00:00Z', 'totalDuration': 0}, 'similarincidentsdbot': [{}], 'timetoassignment': {'accumulatedPause': 0, 'breachTriggered': False, 'dueDate': '0001-01-01T00:00:00Z', 'endDate': '0001-01-01T00:00:00Z', 'lastPauseDate': '0001-01-01T00:00:00Z', 'runStatus': 'idle', 'sla': 0, 'slaStatus': -1, 'startDate': '0001-01-01T00:00:00Z', 'totalDuration': 0}, 'triagesla': {'accumulatedPause': 0, 'breachTriggered': False, 'dueDate': '0001-01-01T00:00:00Z', 'endDate': '0001-01-01T00:00:00Z', 'lastPauseDate': '0001-01-01T00:00:00Z', 'runStatus': 'idle', 'sla': 30, 'slaStatus': -1, 'startDate': '0001-01-01T00:00:00Z', 'totalDuration': 0}, 'urlsslverification': []}, 'account': '', 'autime': 1690101104186129904, 'type': 'Unclassified', 'rawType': 'Unclassified', 'name': 'dawn2', 'rawName': 'dawn2', 'status': 1, 'reason': '', 'occurred': '2023-07-23T08:31:44.186129727Z', 'closed': '0001-01-01T00:00:00Z', 'sla': 0, 'severity': 0, 'investigationId': '40', 'labels': [{'value': 'admin', 'type': 'Instance'}, {'value': 'Manual', 'type': 'Brand'}], 'attachment': None, 'details': '', 'openDuration': 0, 'lastOpen': '0001-01-01T00:00:00Z', 'closingUserId': '', 'owner': 'admin', 'activated': '0001-01-01T00:00:00Z', 'closeReason': '', 'rawCloseReason': '', 'closeNotes': '', 'playbookId': 'playbook0', 'dueDate': '2023-08-02T08:31:44.186129904Z', 'reminder': '0001-01-01T00:00:00Z', 'runStatus': 'error', 'notifyTime': '2023-07-23T08:31:46.642443327Z', 'phase': '', 'rawPhase': '', 'isPlayground': False, 'rawJSON': '', 'parent': '', 'category': '', 'rawCategory': '', 'linkedIncidents': None, 'linkedCount': 0, 'droppedCount': 0, 'sourceInstance': 'admin', 'sourceBrand': 'Manual', 'canvases': None, 'lastJobRunTime': '0001-01-01T00:00:00Z', 'feedBased': False, 'dbotMirrorId': '', 'dbotMirrorInstance': '', 'dbotMirrorDirection': '', 'dbotDirtyFields': None, 'dbotCurrentDirtyFields': None, 'dbotMirrorTags': None, 'dbotMirrorLastSync': '0001-01-01T00:00:00Z', 'isDebug': False, 'changeStatus': 'new', 'insights': 0}, {'id': '41', 'version': 14, 'cacheVersn': 0, 'modified': '2023-07-24T10:51:25.559840378Z', 'created': '2023-07-23T14:03:34.559968188Z', 'sizeInBytes': 0, 'sortValues': [' \x01C[]\x10A]1\n\x0c'], 'dbotCreatedBy': 'admin', 'CustomFields': {'containmentsla': {'accumulatedPause': 0, 'breachTriggered': False, 'dueDate': '0001-01-01T00:00:00Z', 'endDate': '0001-01-01T00:00:00Z', 'lastPauseDate': '0001-01-01T00:00:00Z', 'runStatus': 'idle', 'sla': 30, 'slaStatus': -1, 'startDate': '0001-01-01T00:00:00Z', 'totalDuration': 0}, 'detectionsla': {'accumulatedPause': 0, 'breachTriggered': False, 'dueDate': '0001-01-01T00:00:00Z', 'endDate': '0001-01-01T00:00:00Z', 'lastPauseDate': '0001-01-01T00:00:00Z', 'runStatus': 'idle', 'sla': 20, 'slaStatus': -1, 'startDate': '0001-01-01T00:00:00Z', 'totalDuration': 0}, 'endpoint': [{}], 'failedlogonevents': 0, 'filerelationships': [{}, {}, {}], 'incidentduration': {'accumulatedPause': 0, 'breachTriggered': False, 'dueDate': '0001-01-01T00:00:00Z', 'endDate': '0001-01-01T00:00:00Z', 'lastPauseDate': '0001-01-01T00:00:00Z', 'runStatus': 'idle', 'sla': 0, 'slaStatus': -1, 'startDate': '0001-01-01T00:00:00Z', 'totalDuration': 0}, 'isactive': 'true', 'numberofrelatedincidents': 0, 'numberofsimilarfiles': 0, 'remediationsla': {'accumulatedPause': 0, 'breachTriggered': False, 'dueDate': '0001-01-01T00:00:00Z', 'endDate': '0001-01-01T00:00:00Z', 'lastPauseDate': '0001-01-01T00:00:00Z', 'runStatus': 'idle', 'sla': 7200, 'slaStatus': -1, 'startDate': '0001-01-01T00:00:00Z', 'totalDuration': 0}, 'similarincidentsdbot': [{}], 'timetoassignment': {'accumulatedPause': 0, 'breachTriggered': False, 'dueDate': '0001-01-01T00:00:00Z', 'endDate': '0001-01-01T00:00:00Z', 'lastPauseDate': '0001-01-01T00:00:00Z', 'runStatus': 'idle', 'sla': 0, 'slaStatus': -1, 'startDate': '0001-01-01T00:00:00Z', 'totalDuration': 0}, 'triagesla': {'accumulatedPause': 0, 'breachTriggered': False, 'dueDate': '0001-01-01T00:00:00Z', 'endDate': '0001-01-01T00:00:00Z', 'lastPauseDate': '0001-01-01T00:00:00Z', 'runStatus': 'idle', 'sla': 30, 'slaStatus': -1, 'startDate': '0001-01-01T00:00:00Z', 'totalDuration': 0}, 'urlsslverification': []}, 'account': '', 'autime': 1690121014559968188, 'type': 'Unclassified', 'rawType': 'Unclassified', 'name': 'dawn3', 'rawName': 'dawn3', 'status': 1, 'reason': '', 'occurred': '2023-07-23T14:03:34.55996796Z', 'closed': '0001-01-01T00:00:00Z', 'sla': 0, 'severity': 0, 'investigationId': '41', 'labels': [{'value': 'admin', 'type': 'Instance'}, {'value': 'Manual', 'type': 'Brand'}], 'attachment': None, 'details': '', 'openDuration': 0, 'lastOpen': '0001-01-01T00:00:00Z', 'closingUserId': '', 'owner': 'admin', 'activated': '0001-01-01T00:00:00Z', 'closeReason': '', 'rawCloseReason': '', 'closeNotes': '', 'playbookId': 'playbook0', 'dueDate': '2023-08-02T14:03:34.559968188Z', 'reminder': '0001-01-01T00:00:00Z', 'runStatus': 'error', 'notifyTime': '2023-07-23T14:03:36.92298603Z', 'phase': '', 'rawPhase': '', 'isPlayground': False, 'rawJSON': '', 'parent': '', 'category': '', 'rawCategory': '', 'linkedIncidents': None, 'linkedCount': 0, 'droppedCount': 0, 'sourceInstance': 'admin', 'sourceBrand': 'Manual', 'canvases': None, 'lastJobRunTime': '0001-01-01T00:00:00Z', 'feedBased': False, 'dbotMirrorId': '', 'dbotMirrorInstance': '', 'dbotMirrorDirection': '', 'dbotDirtyFields': None, 'dbotCurrentDirtyFields': None, 'dbotMirrorTags': None, 'dbotMirrorLastSync': '0001-01-01T00:00:00Z', 'isDebug': False, 'changeStatus': 'new', 'insights': 0}]
    # incident1 = {'id': 1, 'name': 'dan'}
    # incident2 = {'id': 2, 'name': 'dan2'}
    # incident3 = {'id': 3, 'name': 'dan3'}
    # incidents.append(incident1)
    # incidents.append(incident2)
    # incidents.append(incident3)

    reset: str = ','.join([incident['id'] for incident in incidents])
    
    assert reset == '39,40,41'
    reset.remove('39')
    assert reset == ['40', '41']
    