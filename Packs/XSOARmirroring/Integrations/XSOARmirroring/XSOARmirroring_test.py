from XSOARmirroring import get_mapping_fields_command, Client, fetch_incidents, update_remote_system_command, \
    validate_and_prepare_basic_params, XSOAR_DATE_FORMAT
from datetime import datetime, timedelta
import dateparser
import pytest
from CommonServerPython import DemistoException


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


@pytest.mark.parametrize('params, expected_url', [
    ({'credentials_api_key': {'identifier': 'key_id', 'password': 'test_password'},
      'url': 'https://my-example.com'}, 'https://my-example.com/xsoar'),
    ({'credentials_api_key': {'identifier': 'key_id', 'password': 'test_password'},
      'url': 'https://my-example.com/xsoar'}, 'https://my-example.com/xsoar'),
    ({'credentials_api_key': {'identifier': '', 'password': 'test_password'},
      'url': 'https://my-example.com'}, 'https://my-example.com'),
    ({'credentials_api_key': {'identifier': ''}, 'url': 'https://my-example.com'}, 'https://my-example.com'),
])
def test_validate_and_prepare_basic_params(params, expected_url):
    """
    Given:
        Case a: parameters with API Key ID (key_id) and a URL not containing the 'xsoar' suffix.
        Case b: parameters with API Key ID (key_id) and a URL containing the 'xsoar' suffix.
        Case c: parameters with no API Key ID (key_id) and a URL not containing the 'xsoar' suffix.
        Case c: parameters with no API Key.

    Whe:
        Validating and preparing the basic params of api_key_id, api_key, base_url

    Then:
        Case a: Make sure the base url receives the 'xsoar' suffix
        Case b: Make sure the base url keeps the 'xsoar' suffix
        Case c: Make sure the base url does not receive the 'xsoar' suffix
        Case d: An exception is thrown with message of: 'API Key must be provided'
    """
    if not params.get('credentials_api_key').get('password'):
        with pytest.raises(DemistoException) as e:
            validate_and_prepare_basic_params(params)

            assert e.message == 'API Key must be provided.'
    else:
        _, _, full_base_url = validate_and_prepare_basic_params(params)
        assert full_base_url == expected_url
