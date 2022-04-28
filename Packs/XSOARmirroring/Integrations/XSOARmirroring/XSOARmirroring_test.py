from XSOARmirroring import get_mapping_fields_command, Client, fetch_incidents, XSOAR_DATE_FORMAT
from datetime import datetime, timedelta
import dateparser


def generate_dummy_client():
    class Client:
        def __init__(self):
            pass

        def get_incident_fields(self):
            pass

        def get_incident_types(self):
            pass

    return Client


INCIDENT_FIELDS = [
    {
        'group': 0,
        'associatedToAll': True,
        'name': "field1",
        'type': 'type1',
        'description': 'description1',
        'cliName': 'cliName1'
    },
    {
        'group': 0,
        'associatedTypes': [
            "test"
        ],
        'name': "field2",
        'type': 'type2',
        'description': 'description2',
        'cliName': 'cliName2'
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
        'cliName1': 'field1 - type1',
        'cliName2': 'field2 - type2'
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
    assert dateparser.parse(next_run['last_fetch']) == dateparser.parse(INCIDENTS[-1]['created']) + timedelta(microseconds=1)
