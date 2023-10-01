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

    next_run, incidents_result = fetch_incidents(client=client, max_results=3, last_run={}, last_fetch=first_fetch,
                                                 first_fetch_time=first_fetch,
                                                 query='', mirror_direction='None', mirror_tag=[])

    assert len(incidents_result) == 3
    assert dateparser.parse(next_run['last_fetch']) == dateparser.parse(INCIDENTS[-1]['created'])


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
                                                 last_fetch="",
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


# test_dedup_incidents parametrize arguments
case_incidents_with_different_times = (
    # responses from search_incidents
    [[{'id': '1', 'version': 8, 'created': '2023-09-26T15:13:45Z'},
      {'id': '2', 'version': 8, 'created': '2023-09-26T15:14:45Z'},
        {'id': '3', 'version': 8, 'created': '2023-09-26T15:15:45Z'},
        {'id': '4', 'version': 8, 'created': '2023-09-26T15:16:45Z'},
        {'id': '5', 'version': 8, 'created': '2023-09-26T15:17:45Z'}], []]    # max fetch
    , 5    # incidents_last_fetch_ids
    , [], (
        # expected incident result
        [{'id': '1', 'version': 8, 'created': '2023-09-26T15:13:45Z'},
         {'id': '2', 'version': 8, 'created': '2023-09-26T15:14:45Z'},
            {'id': '3', 'version': 8, 'created': '2023-09-26T15:15:45Z'},
            {'id': '4', 'version': 8, 'created': '2023-09-26T15:16:45Z'},
            {'id': '5', 'version': 8, 'created': '2023-09-26T15:17:45Z'}],
        # expected incidents_last_fetch_ids result
        [{'id': '5', 'created': '2023-09-26T15:17:45Z'}]))


case_incidents_with_the_same_times = (
    # responses from search_incidents
    [[{'id': '1', 'version': 8, 'created': '2023-09-26T15:13:45Z'},
      {'id': '2', 'version': 8, 'created': '2023-09-26T15:13:45Z'},
        {'id': '3', 'version': 8, 'created': '2023-09-26T15:13:45Z'},
        {'id': '4', 'version': 8, 'created': '2023-09-26T15:13:45Z'},
        {'id': '5', 'version': 8, 'created': '2023-09-26T15:13:45Z'}], []]    # max fetch
    , 5    # incidents_last_fetch_ids
    , [], (
        # expected incident result
        [{'id': '1', 'version': 8, 'created': '2023-09-26T15:13:45Z'},
         {'id': '2', 'version': 8, 'created': '2023-09-26T15:13:45Z'},
            {'id': '3', 'version': 8, 'created': '2023-09-26T15:13:45Z'},
            {'id': '4', 'version': 8, 'created': '2023-09-26T15:13:45Z'},
            {'id': '5', 'version': 8, 'created': '2023-09-26T15:13:45Z'}],
        # expected incidents_last_fetch_ids result
        [{'id': '1', 'created': '2023-09-26T15:13:45Z'},
         {'id': '2', 'created': '2023-09-26T15:13:45Z'},
            {'id': '3', 'created': '2023-09-26T15:13:45Z'},
            {'id': '4', 'created': '2023-09-26T15:13:45Z'},
            {'id': '5', 'created': '2023-09-26T15:13:45Z'}]))


case_with_empty_response_with_incidents_last_fetch_ids = (
    # responses from search_incidents
    [[], []]    # max fetch
    , 5    # incidents_last_fetch_ids
    , [{'id': '1', 'created': '2023-09-26T15:13:45Z'},
       {'id': '2', 'created': '2023-09-26T15:13:45Z'},
       {'id': '3', 'created': '2023-09-26T15:13:45Z'},
       {'id': '4', 'created': '2023-09-26T15:13:45Z'},
       {'id': '5', 'created': '2023-09-26T15:13:45Z'}], (
        # expected incident result
        [],
        # expected incidents_last_fetch_ids result
        [{'id': '1', 'created': '2023-09-26T15:13:45Z'},
         {'id': '2', 'created': '2023-09-26T15:13:45Z'},
         {'id': '3', 'created': '2023-09-26T15:13:45Z'},
         {'id': '4', 'created': '2023-09-26T15:13:45Z'},
            {'id': '5', 'created': '2023-09-26T15:13:45Z'}]))


case_with_empty_response_without_incidents_last_fetch_ids = (
    # responses from search_incidents
    [[], []]    # max fetch
    , 5    # incidents_last_fetch_ids
    , [], (
        # expected incident result
        [],
        # expected incidents_last_fetch_ids result
        []))

case_with_more_then_one_API_call_with_incidents_last_fetch_ids = (
    # responses from search_incidents
    [[{'id': '1', 'version': 8, 'created': '2023-09-26T15:13:41Z'},
      {'id': '2', 'version': 8, 'created': '2023-09-26T15:13:42Z'},
        {'id': '3', 'version': 8, 'created': '2023-09-26T15:13:43Z'},
        {'id': '4', 'version': 8, 'created': '2023-09-26T15:13:44Z'},
      {'id': '5', 'version': 8, 'created': '2023-09-26T15:13:45Z'}],
        [{'id': '5', 'version': 8, 'created': '2023-09-26T15:13:45Z'},
         {'id': '6', 'version': 8, 'created': '2023-09-26T15:13:46Z'},
         {'id': '7', 'version': 8, 'created': '2023-09-26T15:13:47Z'},
     {'id': '8', 'version': 8, 'created': '2023-09-26T15:13:48Z'},
     {'id': '9', 'version': 8, 'created': '2023-09-26T15:13:49Z'}], ], 5    # max fetch
    , [{'id': '1', 'created': '2023-09-26T15:13:41Z'}],  # incidents_last_fetch_ids
    (  # expected incident result
        [{'id': '2', 'version': 8, 'created': '2023-09-26T15:13:42Z'},
         {'id': '3', 'version': 8, 'created': '2023-09-26T15:13:43Z'},
            {'id': '4', 'version': 8, 'created': '2023-09-26T15:13:44Z'},
            {'id': '5', 'version': 8, 'created': '2023-09-26T15:13:45Z'},
            {'id': '6', 'version': 8, 'created': '2023-09-26T15:13:46Z'}],
        # expected incidents_last_fetch_ids result
        [{'id': '6', 'created': '2023-09-26T15:13:46Z'}]))

case_with_an_incident_that_was_fetched = (
    # responses from search_incidents
    [[{'id': '1', 'version': 8, 'created': '2023-09-26T15:13:41Z'},
      {'id': '2', 'version': 8, 'created': '2023-09-26T15:13:42Z'},
      {'id': '3', 'version': 8, 'created': '2023-09-26T15:13:43Z'}],
     []], 5    # max fetch
    , [{'id': '1', 'created': '2023-09-26T15:13:41Z'}],  # incidents_last_fetch_ids
    (
        # expected incident result
        [{'id': '2', 'version': 8, 'created': '2023-09-26T15:13:42Z'},
         {'id': '3', 'version': 8, 'created': '2023-09-26T15:13:43Z'}],
        # expected incidents_last_fetch_ids result
        [{'id': '3', 'created': '2023-09-26T15:13:43Z'}]))


@pytest.mark.parametrize('incident_to_return , max_fetch, incidents_last_fetch_ids, expected_result', [
    case_incidents_with_different_times,
    case_incidents_with_the_same_times,
    case_with_empty_response_with_incidents_last_fetch_ids,
    case_with_empty_response_without_incidents_last_fetch_ids,
    case_with_more_then_one_API_call_with_incidents_last_fetch_ids,
    case_with_an_incident_that_was_fetched,
])
def test_dedup_incidents_with_seconds_timestamp(mocker, incident_to_return, max_fetch,
                                                incidents_last_fetch_ids, expected_result):
    """
    Given:
        - Case 1: All incidents from the current fetch cycle have different timestamp.
        - Case 2: All incidents from the current fetch cycle have the same timestamp and were not fetched.
        - Case 3: All incidents from the previous fetch cycle were fetched. No new incidents received from API response.
        - Case 4: Empty response without incidents_last_fetch_ids provided.
        - Case 5: More than one API call received with incidents_last_fetch_ids provided.
        - Cas 6: An incident that was already fetched in the previous run is received again.
    When:
        - Using the dedup mechanism while fetching incidents.
    Then:
        - Verify that the dedup mechanism correctly handles the different test cases by comparing the expected and actual results.
    """
    from XSOARmirroring import get_and_dedup_incidents
    client = Client("")
    mocker.patch.object(Client, 'search_incidents', side_effect=incident_to_return)
    assert get_and_dedup_incidents(client, incidents_last_fetch_ids, "", max_fetch, "") == expected_result
