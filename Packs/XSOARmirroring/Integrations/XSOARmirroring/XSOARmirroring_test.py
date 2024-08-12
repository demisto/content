from freezegun import freeze_time

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

INCIDENTS_IN_CONTEXT = {
    'XSOARMirror_mirror_reset': {
        4: True,
        5: True,
        6: True,
    }
}

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
        - Ensure
            1. The incidents result and the last_fetch in the LastRun object as expected.
            2. The integration context is updated as expected.
    """
    mocker.patch.object(Client, 'search_incidents', return_value=INCIDENTS)
    mock_integration_context = mocker.patch('XSOARmirroring.set_to_integration_context_with_retries')

    first_fetch = dateparser.parse('3 days').strftime(XSOAR_DATE_FORMAT)
    client = Client("")

    next_run, incidents_result = fetch_incidents(client=client, max_results=3, last_run={}, last_fetch=first_fetch,
                                                 first_fetch_time=first_fetch,
                                                 query='', mirror_direction='None', mirror_tag=[], fetch_incident_history=True)

    assert len(incidents_result) == 3
    assert dateparser.parse(next_run['time']) == dateparser.parse(INCIDENTS[-1]['created'])
    assert mock_integration_context.call_args.kwargs['context'] == {'XSOARMirror_mirror_reset': {1: True, 2: True, 3: True}}


def test_fetch_incidents_with_integration_context(mocker):
    """
    Given:
        - List of incidents + List of incident IDs in context (from previous fetch).

    When:
        - Running the fetch_incidents and getting these incidents.

    Then:
        - Ensure
            1. The incidents result and the last_fetch in the LastRun object as expected.
            2. The integration context is updated as expected.
    """
    mocker.patch.object(Client, 'search_incidents', return_value=INCIDENTS)
    mocker.patch('XSOARmirroring.get_integration_context', return_value=INCIDENTS_IN_CONTEXT)
    mock_integration_context = mocker.patch('XSOARmirroring.set_to_integration_context_with_retries')

    first_fetch = dateparser.parse('3 days').strftime(XSOAR_DATE_FORMAT)
    client = Client("")

    next_run, incidents_result = fetch_incidents(client=client, max_results=3, last_run={}, last_fetch=first_fetch,
                                                 first_fetch_time=first_fetch,
                                                 query='', mirror_direction='None', mirror_tag=[], fetch_incident_history=True)

    assert len(incidents_result) == 3
    assert dateparser.parse(next_run['time']) == dateparser.parse(INCIDENTS[-1]['created'])
    assert mock_integration_context.call_args.kwargs['context'] == {
        'XSOARMirror_mirror_reset': {
            4: True,
            5: True,
            6: True,
            1: True,
            2: True,
            3: True,
        }
    }


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
    mocker.patch.object(Client, 'search_incidents', side_effect=[INCIDENTS_MIRRORING_PLAYBOOK_ID, []])

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
    "2023-09-26T15:13:45.000000Z",
    # responses from search_incidents
    [
        [
            {"id": "1", "version": 8, "created": "2023-09-26T15:13:45Z"},
            {"id": "2", "version": 8, "created": "2023-09-26T15:14:45Z"},
            {"id": "3", "version": 8, "created": "2023-09-26T15:15:45Z"},
            {"id": "4", "version": 8, "created": "2023-09-26T15:16:45Z"},
            {"id": "5", "version": 8, "created": "2023-09-26T15:17:45Z"},
        ],
        [],
    ],  # max fetch
    5,  # incidents_last_fetch_ids
    [],
    (
        # expected incident result
        [
            {"id": "1", "version": 8, "created": "2023-09-26T15:13:45Z"},
            {"id": "2", "version": 8, "created": "2023-09-26T15:14:45Z"},
            {"id": "3", "version": 8, "created": "2023-09-26T15:15:45Z"},
            {"id": "4", "version": 8, "created": "2023-09-26T15:16:45Z"},
            {"id": "5", "version": 8, "created": "2023-09-26T15:17:45Z"},
        ],
        # expected incidents_last_fetch_ids result
        ["5"],
        dateparser.parse("2023-09-26T15:17:45Z")
    ),
)

case_incidents_with_the_same_times = (
    "2023-09-26T15:13:45.000000Z",
    # responses from search_incidents
    [
        [
            {"id": "1", "version": 8, "created": "2023-09-26T15:13:45Z"},
            {"id": "2", "version": 8, "created": "2023-09-26T15:13:45Z"},
            {"id": "3", "version": 8, "created": "2023-09-26T15:13:45Z"},
            {"id": "4", "version": 8, "created": "2023-09-26T15:13:45Z"},
            {"id": "5", "version": 8, "created": "2023-09-26T15:13:45Z"},
        ],
        [],
    ],  # max fetch
    5,  # incidents_last_fetch_ids
    [],
    (
        # expected incident result
        [
            {"id": "1", "version": 8, "created": "2023-09-26T15:13:45Z"},
            {"id": "2", "version": 8, "created": "2023-09-26T15:13:45Z"},
            {"id": "3", "version": 8, "created": "2023-09-26T15:13:45Z"},
            {"id": "4", "version": 8, "created": "2023-09-26T15:13:45Z"},
            {"id": "5", "version": 8, "created": "2023-09-26T15:13:45Z"},
        ],
        # expected incidents_last_fetch_ids result
        ["1", "2", "3", "4", "5"],
        dateparser.parse("2023-09-26T15:13:45Z")
    ),
)

case_with_empty_response_with_incidents_last_fetch_ids = (
    "2023-09-26T15:13:41.000000Z",
    # responses from search_incidents
    [[], []],  # max fetch
    5,  # incidents_last_fetch_ids
    ["1", "2", "3", "4", "5"],
    (
        # expected incident result
        [],
        # expected incidents_last_fetch_ids result
        ["1", "2", "3", "4", "5"],
        dateparser.parse("2023-09-26T15:13:41Z")
    ),
)

case_with_empty_response_without_incidents_last_fetch_ids = (
    "2023-09-26T15:13:41.000000Z",
    # responses from search_incidents
    [[], []],  # max fetch
    5,  # incidents_last_fetch_ids
    [],
    (
        # expected incident result
        [],
        # expected incidents_last_fetch_ids result
        [],
        dateparser.parse("2023-09-26T15:13:41Z")
    ),
)

case_with_more_then_one_API_call_with_incidents_last_fetch_ids = (
    "2023-09-26T15:13:41.000000Z",
    # responses from search_incidents
    [
        [
            {"id": "1", "version": 8, "created": "2023-09-26T15:13:41Z"},
            {"id": "2", "version": 8, "created": "2023-09-26T15:13:42Z"},
            {"id": "3", "version": 8, "created": "2023-09-26T15:13:43Z"},
            {"id": "4", "version": 8, "created": "2023-09-26T15:13:44Z"},
            {"id": "5", "version": 8, "created": "2023-09-26T15:13:45Z"},
        ],
        [
            {"id": "5", "version": 8, "created": "2023-09-26T15:13:45Z"},
            {"id": "6", "version": 8, "created": "2023-09-26T15:13:46Z"},
            {"id": "7", "version": 8, "created": "2023-09-26T15:13:47Z"},
            {"id": "8", "version": 8, "created": "2023-09-26T15:13:48Z"},
            {"id": "9", "version": 8, "created": "2023-09-26T15:13:49Z"},
        ],
    ],
    5,  # max fetch
    ["1"],  # incidents_last_fetch_ids
    (  # expected incident result
        [
            {"id": "2", "version": 8, "created": "2023-09-26T15:13:42Z"},
            {"id": "3", "version": 8, "created": "2023-09-26T15:13:43Z"},
            {"id": "4", "version": 8, "created": "2023-09-26T15:13:44Z"},
            {"id": "5", "version": 8, "created": "2023-09-26T15:13:45Z"},
            {"id": "6", "version": 8, "created": "2023-09-26T15:13:46Z"},
        ],
        # expected incidents_last_fetch_ids result
        ["6"],
        dateparser.parse("2023-09-26T15:13:46Z")
    ),
)

case_with_an_incident_that_was_fetched = (
    "2023-09-26T15:13:41.000000Z",
    # responses from search_incidents
    [
        [
            {"id": "1", "version": 8, "created": "2023-09-26T15:13:41Z"},
            {"id": "2", "version": 8, "created": "2023-09-26T15:13:42Z"},
            {"id": "3", "version": 8, "created": "2023-09-26T15:13:43Z"},
        ],
        [],
    ],
    5,  # max fetch
    ["1"],  # incidents_last_fetch_ids
    (
        # expected incident result
        [
            {"id": "2", "version": 8, "created": "2023-09-26T15:13:42Z"},
            {"id": "3", "version": 8, "created": "2023-09-26T15:13:43Z"},
        ],
        # expected incidents_last_fetch_ids result
        ["3"],
        dateparser.parse("2023-09-26T15:13:43Z")
    ),
)

case_with_an_incident_that_was_fetched_and_there_are_more_with_the_same_time = (
    "2023-09-26T15:13:41.000000Z",
    # responses from search_incidents
    [
        [
            {"id": "1", "version": 8, "created": "2023-09-26T15:13:41Z"},
            {"id": "2", "version": 8, "created": "2023-09-26T15:13:41Z"},
            {"id": "3", "version": 8, "created": "2023-09-26T15:13:41Z"},
        ],
        [],
        dateparser.parse("2023-09-26T15:13:41Z")
    ],
    5,  # max fetch
    ["1"],  # incidents_last_fetch_ids
    (
        # expected incident result
        [
            {"id": "2", "version": 8, "created": "2023-09-26T15:13:41Z"},
            {"id": "3", "version": 8, "created": "2023-09-26T15:13:41Z"},
        ],
        # expected incidents_last_fetch_ids result
        ["1", "2", "3"],
        dateparser.parse("2023-09-26T15:13:41Z")
    ),
)

case_incidents_not_utc_time = (
    "2023-11-09T03:25:05.000000Z",
    # responses from search_incidents
    [
        [
            {"id": "1", "version": 8, "created": "2023-11-09T06:25:06.828698605+03:00"},
            {"id": "2", "version": 8, "created": "2023-11-09T06:26:06.828698605+03:00"},
        ],
        [],
    ],  # max fetch
    5,  # incidents_last_fetch_ids
    [],
    (
        # expected incident result
        [
            {"id": "1", "version": 8, "created": "2023-11-09T06:25:06.828698605+03:00"},
            {"id": "2", "version": 8, "created": "2023-11-09T06:26:06.828698605+03:00"},

        ],
        # expected incidents_last_fetch_ids result
        ["2"],
        dateparser.parse("2023-11-09T03:26:06.828698605Z")
    ),
)


def test_get_incident_entries_without_entries(mocker):
    """
    Given:
        - incident_id and date.

    When:
        - Running the get_incident_entries request.

    Then:
        - Ensure that an empty list is returned when there is no entries.
    """
    from XSOARmirroring import Client

    client = Client(base_url="https://test.com")
    mocker.patch.object(
        client,
        "_http_request",
        return_value={
            "closed": "2023-09-20T10:54:00.669862412Z",
            "closingUserId": "DBot",
            "created": "2023-09-20T09:07:46.457488661Z",
            "details": "",
        },
    )
    result = client.get_incident_entries(
        incident_id="1",
        from_date="1696494896",
        max_results=1,
        categories=None,
        tags_and_operator=True,
        tags=None,
    )
    assert result is not None
    assert result == []


class TestFetchIncidentsWithLookBack:
    FREEZE_TIMESTAMP = '2022-07-28T12:09:17Z'

    @staticmethod
    def start_freeze_time(timestamp):
        from freezegun import freeze_time
        _start_freeze_time = freeze_time(timestamp)
        _start_freeze_time.start()
        return datetime.now()

    def create_incidents_queue(self):
        first_incident = {
            'id': '1',
            'created': (
                self.start_freeze_time(self.FREEZE_TIMESTAMP) - timedelta(minutes=2)
            ).strftime(XSOAR_DATE_FORMAT)
        }

        second_incident = {
            'id': '2',
            'created': (
                self.start_freeze_time(self.FREEZE_TIMESTAMP) - timedelta(minutes=5)
            ).strftime(XSOAR_DATE_FORMAT)
        }

        third_incident = {
            'id': '3',
            'created': (
                self.start_freeze_time(self.FREEZE_TIMESTAMP) - timedelta(minutes=10)
            ).strftime(XSOAR_DATE_FORMAT)
        }

        return (
            [[third_incident], [],
             [second_incident, third_incident], [],
             [first_incident, second_incident, third_incident], []]
        )

    @pytest.mark.parametrize('look_back', [30, 40, 400])
    def test_fetch_emails_with_look_back_greater_than_zero(self, mocker, look_back):
        """
        Given
         - a look back parameter.
         - incidents queue.

        When
         - trying to fetch emails with the look-back mechanism.

        Then
         - make sure only one incident is being returned each time, based on the 'cache' look-back mechanism.
         - make sure the correct timestamp to query the api was called based on the look-back parameter.
         - make sure the correct incident is being returned by its name without any duplication whatsoever.
         - make sure the 'time' for the look-back for the last run is being set to the latest incident occurred incident
         - make sure the 'ID' field is being removed from the incidents before fetching.
        """

        last_incidents_mocker = mocker.patch.object(Client, 'search_incidents', side_effect=self.create_incidents_queue())
        mocker.patch('XSOARmirroring.set_to_integration_context_with_retries')

        first_fetch = (self.start_freeze_time(self.FREEZE_TIMESTAMP) - timedelta(days=3)).strftime(XSOAR_DATE_FORMAT)

        client = Client("")

        last_run = {
            'time': (datetime.utcnow() - timedelta(minutes=20)).strftime(XSOAR_DATE_FORMAT)
        }

        expected_last_run_timestamps = ['2022-07-28T12:07:17.000000Z',
                                        '2022-07-28T12:04:17.000000Z',
                                        '2022-07-28T11:59:17.000000Z']

        for i in range(3, 0, -1):
            next_run, incidents_result = fetch_incidents(client=client, max_results=3, last_run=last_run,
                                                         last_fetch=last_run.get('time'), first_fetch_time=first_fetch,
                                                         query='', mirror_direction='None', mirror_tag=[],
                                                         fetch_incident_history=True, look_back=look_back)
            assert last_incidents_mocker.call_args.kwargs['start_time'] == (
                datetime.now() - timedelta(minutes=look_back)
            ).strftime(XSOAR_DATE_FORMAT)
            assert next_run['time'] == expected_last_run_timestamps[i - 1]
            assert len(incidents_result) == 1
            assert 'id' not in incidents_result[0]