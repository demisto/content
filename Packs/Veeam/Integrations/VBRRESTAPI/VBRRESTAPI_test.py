import pytest
import json
from datetime import datetime
from unittest.mock import Mock
import demistomock as demisto
from CommonServerPython import *
from VBRRESTAPI import DATE_FORMAT, MAX_INT, Client, \
    fetch_incidents, search_with_paging, get_malware_incidents, overwrite_last_fetch_time, get_configuration_backup_incident, \
    get_repository_space_incidents, validate_ipv4, validate_ipv6, validate_time, validate_uuid, try_cast_to_bool, \
    try_cast_to_int, try_cast_to_double, process_command, handle_command_with_token_refresh, validate_filter_parameter, \
    convert_to_json, get_vcentername, process_error, fetch_repository_space_incidents, get_inventory_objects_command, \
    get_backup_object_command, get_all_repository_states_command, get_all_malware_events_command, \
    get_all_restore_points_command, start_instant_recovery_command, start_instant_recovery_customized_command, \
    get_session_command, create_malware_event_command, fetch_malware_events, fetch_configuration_backup_incident, update_token

SERVER_URL = 'https://test_url.com'
REQUEST_TIMEOUT = 120


class ApiMock:
    def __init__(self, response: dict) -> None:
        self.response = response
        self.call_count = 0
        self.call_args_list = []

    def __call__(self, **args: dict) -> dict:
        self.call_args_list.append(args)
        skip = args.get('skip')
        limit = args.get('limit')
        data = self.response['data']
        response = data[skip:skip + limit]
        self.call_count += 1
        return {'data': response}


def util_load_json(path):
    with open(path, encoding='utf-8') as f:
        return json.loads(f.read())


@pytest.fixture()
def client():
    return Client(server_url=SERVER_URL, verify=None, proxy=None, headers=None, auth=None, timeout=REQUEST_TIMEOUT)


GET_CONF_BACKUP_RESPONSE = util_load_json('test_data/get_configuration_backup_response.json')


@pytest.mark.parametrize(
    'string, expected',
    [
        ('abc\\def', 'abc'),
        ('xyz', 'xyz'),
        ('', ''),
    ]
)
def test_get_vcentername(string, expected):
    assert get_vcentername(string) == expected


def test_convert_to_json_with_exception():
    string = 'invalid_json'
    with pytest.raises(ValueError):
        convert_to_json(string)


@pytest.mark.parametrize(
    'string, expected',
    [
        ('{"key": "value"}', {'key': 'value'}),
        ('', {})
    ]
)
def test_convert_to_json(string, expected):
    assert convert_to_json(string) == expected


@pytest.mark.parametrize(
    'arg',
    [
        '',  # empty str (skiping arg)
        '127.0.0.1'  # good format ipv4
    ]
)
def test_validate_ipv4(arg):
    try:
        validate_ipv4(arg)
    except Exception as e:
        pytest.fail(f'raised {e}')


@pytest.mark.parametrize(
    'arg',
    [
        'wtgwte'  # bad format ipv4 => exception
    ]
)
def test_validate_ipv4_with_exception(arg):
    with pytest.raises(ValueError):
        validate_ipv4(arg)


@pytest.mark.parametrize(
    'arg',
    [
        '',  # empty str (skiping arg)
        'fe60::b873:6a33:6f1a:809b'  # good format ipv6
    ]
)
def test_validate_ipv6(arg):
    try:
        validate_ipv6(arg)
    except Exception as e:
        pytest.fail(f'raised {e}')


@pytest.mark.parametrize(
    'arg',
    [
        'wtgwte'  # bad format ipv6 => exception
    ]
)
def test_validate_ipv6_with_exception(arg):
    with pytest.raises(ValueError):
        validate_ipv6(arg)


@pytest.mark.parametrize(
    'arg',
    [
        '',  # empty str (skiping arg)
        'af75ddaa-d680-4c50-ac82-07834a007707'  # good format uuid
    ]
)
def test_validate_uuid(arg):
    try:
        validate_uuid(arg)
    except Exception as e:
        pytest.fail(f'raised {e}')


@pytest.mark.parametrize(
    'arg',
    [
        'wtgwte'  # bad format uuid => exception
    ]
)
def test_validate_uuid_with_exception(arg):
    with pytest.raises(ValueError):
        validate_uuid(arg)


@pytest.mark.parametrize(
    'arg',
    [
        '',  # empty str (skiping arg)
        '2024-04-24T16:03:59.204Z'  # good format time
    ]
)
def test_validate_time(arg):
    try:
        validate_time(arg)
    except Exception as e:
        pytest.fail(f'raised {e}')


@pytest.mark.parametrize(
    'arg',
    [
        'wtgwte'  # bad format time => exception
    ]
)
def test_validate_time_with_exception(arg):
    with pytest.raises(ValueError):
        validate_time(arg)


@pytest.mark.parametrize(
    'arg',
    [
        '',  # empty str (skiping arg)
        '202'  # str int
    ]
)
def test_try_cast_to_int(arg):
    try:
        try_cast_to_int(arg)
    except Exception as e:
        pytest.fail(f'raised {e}')


@pytest.mark.parametrize(
    'arg',
    [
        'wtgwte'  # not int => exception
    ]
)
def test_try_cast_to_int_with_exception(arg):
    with pytest.raises(ValueError):
        try_cast_to_int(arg)


@pytest.mark.parametrize(
    'arg',
    [
        '',  # empty str (skiping arg)
        'true',  # only str that represent bool value can be casted
        'False',
        'TRUE',  # any register
    ]
)
def test_try_cast_to_bool(arg):
    try:
        try_cast_to_bool(arg)
    except Exception as e:
        pytest.fail(f'raised {e}')


@pytest.mark.parametrize(
    'arg',
    [
        'wtgwte'  # not our bool value => exception
    ]
)
def test_try_cast_to_bool_with_exception(arg):
    with pytest.raises(ValueError):
        try_cast_to_bool(arg)


@pytest.mark.parametrize(
    'arg',
    [
        '',  # empty str (skiping arg)
        '3.14'  # double value
    ]
)
def test_try_cast_to_double(arg):
    try:
        try_cast_to_double(arg)
    except Exception as e:
        pytest.fail(f'raised {e}')


@pytest.mark.parametrize(
    'arg',
    [
        'wtgwte'  # not our bool value => exception
    ]
)
def test_try_cast_to_double_with_exception(arg):
    with pytest.raises(ValueError):
        try_cast_to_double(arg)


def test_update_token(client, mocker):
    expected_token = 'token'
    mocker.patch('VBRRESTAPI.Client.get_access_token_request', return_value={'access_token': 'token'})

    token = update_token(client, 'username', 'password')

    assert token == expected_token


@pytest.mark.parametrize(
    "response, expected_command_results",
    [
        (
            {
                'data': [
                    {'id': 1, 'name': 'repository 1'},
                    {'id': 2, 'name': 'repository 2'}
                ]
            },
            {
                'outputs_prefix': 'Veeam.VBR.get_repository_states.data',
                'outputs_key_field': '',
                'outputs': [
                    {'id': 1, 'name': 'repository 1'},
                    {'id': 2, 'name': 'repository 2'}
                ],
                'raw_response': [
                    {'id': 1, 'name': 'repository 1'},
                    {'id': 2, 'name': 'repository 2'}
                ]
            }
        )
    ]
)
def test_get_all_repository_states_command(client, mocker, response, expected_command_results):
    mocker.patch('VBRRESTAPI.Client.get_all_repository_states_request', return_value=response)
    mocker.patch('VBRRESTAPI.validate_uuid')
    mocker.patch('VBRRESTAPI.try_cast_to_int')
    mocker.patch('VBRRESTAPI.try_cast_to_bool')
    mocker.patch('VBRRESTAPI.try_cast_to_double')

    args = {}
    command_results = get_all_repository_states_command(client, args)

    assert command_results.outputs_prefix == expected_command_results['outputs_prefix']
    assert command_results.outputs_key_field == expected_command_results['outputs_key_field']
    assert command_results.outputs == expected_command_results['outputs']
    assert command_results.raw_response == expected_command_results['raw_response']


@pytest.mark.parametrize(
    "response, expected_command_results",
    [
        (
            {
                'data': [
                    {'id': 1, 'name': 'event 1'},
                    {'id': 2, 'name': 'event 2'}
                ]
            },
            {
                'outputs_prefix': 'Veeam.VBR.get_malware_events.data',
                'outputs_key_field': '',
                'outputs': [
                    {'id': 1, 'name': 'event 1'},
                    {'id': 2, 'name': 'event 2'}
                ],
                'raw_response': [
                    {'id': 1, 'name': 'event 1'},
                    {'id': 2, 'name': 'event 2'}
                ]
            }
        )
    ]
)
def test_get_all_malware_events_command(client, mocker, response, expected_command_results):
    mocker.patch('VBRRESTAPI.Client.get_all_malware_events_request', return_value=response)
    mocker.patch('VBRRESTAPI.validate_uuid')
    mocker.patch('VBRRESTAPI.try_cast_to_int')
    mocker.patch('VBRRESTAPI.try_cast_to_bool')
    mocker.patch('VBRRESTAPI.validate_time')

    args = {}
    command_results = get_all_malware_events_command(client, args)

    assert command_results.outputs_prefix == expected_command_results['outputs_prefix']
    assert command_results.outputs_key_field == expected_command_results['outputs_key_field']
    assert command_results.outputs == expected_command_results['outputs']
    assert command_results.raw_response == expected_command_results['raw_response']


@pytest.mark.parametrize(
    "response, expected_command_results",
    [
        (
            {
                'data': [
                    {'id': 1, 'name': 'restore point 1'},
                    {'id': 2, 'name': 'restore point 2'}
                ]
            },
            {
                'outputs_prefix': 'Veeam.VBR.get_restore_points.data',
                'outputs_key_field': '',
                'outputs': [
                    {'id': 1, 'name': 'restore point 1'},
                    {'id': 2, 'name': 'restore point 2'}
                ],
                'raw_response': [
                    {'id': 1, 'name': 'restore point 1'},
                    {'id': 2, 'name': 'restore point 2'}
                ]
            }
        )
    ]
)
def test_get_all_restore_points_command(client, mocker, response, expected_command_results):
    mocker.patch('VBRRESTAPI.Client.get_all_restore_points_request', return_value=response)
    mocker.patch('VBRRESTAPI.validate_uuid')
    mocker.patch('VBRRESTAPI.try_cast_to_int')
    mocker.patch('VBRRESTAPI.try_cast_to_bool')
    mocker.patch('VBRRESTAPI.validate_time')

    args = {}
    command_results = get_all_restore_points_command(client, args)

    assert command_results.outputs_prefix == expected_command_results['outputs_prefix']
    assert command_results.outputs_key_field == expected_command_results['outputs_key_field']
    assert command_results.outputs == expected_command_results['outputs']
    assert command_results.raw_response == expected_command_results['raw_response']


@pytest.mark.parametrize(
    "response, expected_command_results, expected_filter",
    [
        (
            {
                'data': [
                    {'id': 1, 'name': 'object 1'},
                    {'id': 2, 'name': 'object 2'}
                ]
            },
            {
                'outputs_prefix': 'Veeam.VBR.get_inventory_objects.data',
                'outputs_key_field': '',
                'outputs': [
                    {'id': 1, 'name': 'object 1'},
                    {'id': 2, 'name': 'object 2'}
                ],
                'raw_response': [
                    {'id': 1, 'name': 'object 1'},
                    {'id': 2, 'name': 'object 2'}
                ]
            },
            {
                'type': 'GroupExpression',
                'operation': 'and',
                'items': [
                    {
                        'type': 'PredicateExpression',
                        'operation': 'equals',
                        'property': 'Name',
                        'value': 'object_name'
                    },
                    {
                        'type': 'PredicateExpression',
                        'operation': 'in',
                        'property': 'Type',
                        'value': 'vi_type'
                    }
                ]
            }

        )
    ]
)
def test_get_inventory_objects_command(client, mocker, response, expected_command_results, expected_filter):
    mock_get_inventory_objects_request = mocker.patch('VBRRESTAPI.Client.get_inventory_objects_request', return_value=response)
    mocker.patch('VBRRESTAPI.convert_to_json', return_value={})
    mocker.patch('VBRRESTAPI.assign_params', return_value={})
    mocker.patch('VBRRESTAPI.try_cast_to_int')
    mocker.patch('VBRRESTAPI.try_cast_to_bool')

    args = {'objectName': 'object_name', 'viType': 'vi_type'}
    command_results = get_inventory_objects_command(client, args)

    func_args = mock_get_inventory_objects_request.call_args[0]
    assert func_args[3] == expected_filter
    assert command_results.outputs_prefix == expected_command_results['outputs_prefix']
    assert command_results.outputs_key_field == expected_command_results['outputs_key_field']
    assert command_results.outputs == expected_command_results['outputs']
    assert command_results.raw_response == expected_command_results['raw_response']


@pytest.mark.parametrize(
    "response, expected_command_results, expected_mode",
    [
        (
            {
                'state': 'Starting',
                'id': '1111'
            },
            {
                'outputs_prefix': 'Veeam.VBR.start_recovery',
                'outputs_key_field': '',
                'outputs': {'state': 'Starting', 'id': '1111'},
                'raw_response': {'state': 'Starting', 'id': '1111'}
            },
            'OriginalLocation'
        )
    ]
)
def test_start_instant_recovery_command(client, mocker, response, expected_command_results, expected_mode):
    mock_start_instant_recovery_request = mocker.patch(
        'VBRRESTAPI.Client.start_instant_recovery_request',
        return_value=response
    )
    mocker.patch('VBRRESTAPI.validate_uuid')
    mocker.patch('VBRRESTAPI.try_cast_to_bool')
    mocker.patch('VBRRESTAPI.assign_params', return_value={})

    args = {}
    command_results = start_instant_recovery_command(client, args)

    func_args = mock_start_instant_recovery_request.call_args[0]
    func_args[1] == expected_mode
    assert command_results.outputs_prefix == expected_command_results['outputs_prefix']
    assert command_results.outputs_key_field == expected_command_results['outputs_key_field']
    assert command_results.outputs == expected_command_results['outputs']
    assert command_results.raw_response == expected_command_results['raw_response']


@pytest.mark.parametrize(
    "response, expected_command_results, expected_mode",
    [
        (
            {
                'state': 'Starting',
                'id': '1111'
            },
            {
                'outputs_prefix': 'Veeam.VBR.start_recovery',
                'outputs_key_field': '',
                'outputs': {'state': 'Starting', 'id': '1111'},
                'raw_response': {'state': 'Starting', 'id': '1111'}
            },
            'Customized'
        )
    ]
)
def test_start_instant_recovery_customized_command(client, mocker, response, expected_command_results, expected_mode):
    mock_start_instant_recovery_customized_request = mocker.patch(
        'VBRRESTAPI.Client.start_instant_recovery_customized_request',
        return_value=response
    )
    mocker.patch('VBRRESTAPI.validate_uuid')
    mocker.patch('VBRRESTAPI.try_cast_to_bool')
    mocker.patch('VBRRESTAPI.assign_params', return_value={})

    args = {}
    command_results = start_instant_recovery_customized_command(client, args)

    func_args = mock_start_instant_recovery_customized_request.call_args[0]
    func_args[1] == expected_mode
    assert command_results.outputs_prefix == expected_command_results['outputs_prefix']
    assert command_results.outputs_key_field == expected_command_results['outputs_key_field']
    assert command_results.outputs == expected_command_results['outputs']
    assert command_results.raw_response == expected_command_results['raw_response']


@pytest.mark.parametrize(
    "response, expected_command_results, expected_args",
    [
        (
            {
                'data': [
                    {'id': 1, 'name': 'event 1'}
                ]
            },
            {
                'outputs_prefix': 'Veeam.VBR',
                'outputs_key_field': '',
                'outputs': [
                    {'id': 1, 'name': 'event 1'}
                ],
                'raw_response': [
                    {'id': 1, 'name': 'event 1'}
                ]
            },
            {'post_event_ids': ['1']}
        )
    ]
)
def test_create_malware_event_command(client, mocker, response, expected_command_results, expected_args):
    mock_create_malware_event_command = mocker.patch('VBRRESTAPI.Client.create_malware_event_request', return_value=response)
    mocker.patch('VBRRESTAPI.validate_uuid')
    mocker.patch('VBRRESTAPI.validate_ipv6')
    mocker.patch('VBRRESTAPI.validate_ipv4')
    mocker.patch('VBRRESTAPI.validate_time')
    mocker.patch('VBRRESTAPI.assign_params', return_value={})
    mocker.patch.object(demisto, 'getIntegrationContext', return_value={})
    mock_set_integration_context = mocker.patch.object(demisto, 'setIntegrationContext')

    args = {}
    command_results = create_malware_event_command(client, args)

    mock_create_malware_event_command.assert_called_once()
    set_context_args = mock_set_integration_context.call_args[0]
    assert set_context_args[0] == expected_args
    assert command_results.outputs_prefix == expected_command_results['outputs_prefix']
    assert command_results.outputs_key_field == expected_command_results['outputs_key_field']
    assert command_results.outputs == expected_command_results['outputs']
    assert command_results.raw_response == expected_command_results['raw_response']


@pytest.mark.parametrize(
    "response, expected_command_results",
    [
        (
            {
                'id': 1,
                'name': 'object 1',
                'path': 'vcentername/path'
            },
            {
                'outputs_prefix': 'Veeam.VBR.backup_object',
                'outputs_key_field': '',
                'outputs': {'id': 1, 'name': 'object 1', 'path': 'vcentername/path', 'vcenter_name': 'vcentername/path'},
                'raw_response': {'id': 1, 'name': 'object 1', 'path': 'vcentername/path', 'vcenter_name': 'vcentername/path'}
            }
        )
    ]
)
def test_get_backup_object_command(client, mocker, response, expected_command_results):
    mocker.patch('VBRRESTAPI.Client.get_backup_object_request', return_value=response)
    mocker.patch('VBRRESTAPI.get_vcentername', return_value=response['path'])
    mocker.patch('VBRRESTAPI.validate_uuid')

    args = {}
    command_results = get_backup_object_command(client, args)

    assert command_results.outputs_prefix == expected_command_results['outputs_prefix']
    assert command_results.outputs_key_field == expected_command_results['outputs_key_field']
    assert command_results.outputs == expected_command_results['outputs']
    assert command_results.raw_response == expected_command_results['raw_response']


@pytest.mark.parametrize(
    "response, expected_command_results",
    [
        (
            {
                'id': 1,
                'name': 'session 1'
            },
            {
                'outputs_prefix': 'Veeam.VBR.get_session',
                'outputs_key_field': '',
                'outputs': {'id': 1, 'name': 'session 1'},
                'raw_response': {'id': 1, 'name': 'session 1'},
                'replace_existing': True
            }
        )
    ]
)
def test_get_session_command(client, mocker, response, expected_command_results):
    mocker.patch('VBRRESTAPI.Client.get_session_request', return_value=response)
    mocker.patch('VBRRESTAPI.validate_uuid')

    args = {}
    command_results = get_session_command(client, args)

    assert command_results.outputs_prefix == expected_command_results['outputs_prefix']
    assert command_results.outputs_key_field == expected_command_results['outputs_key_field']
    assert command_results.outputs == expected_command_results['outputs']
    assert command_results.raw_response == expected_command_results['raw_response']
    assert command_results.replace_existing == expected_command_results['replace_existing']


MALWARE_EVENTS_WITH_NEEDED_TYPE = util_load_json('test_data/get_malware_events.json')
MALWARE_INCIDENTS = [
    {
        'name': 'Veeam - Malware activity detected on string',
        'occurred': '2024-04-24T15:42:22.198Z',
        'rawJSON': ('{"type": "YaraScan", "state": "Created", "source": "External", "severity": '
                    '"Infected", "id": "b9b6d52f-d8ac-448f-ac32-5b86e07d05fa", "detectionTimeUtc": '
                    '"2024-04-24T15:42:22.198Z", "machine": {"displayName": "string", "uuid": "string", '
                    '"backupObjectId": "dd628dc1-3f7b-46ef-9b3c-f7dd6439c999"}, '
                    '"details": "event", "createdBy": "string", "engine": "string", '
                    '"description": "event; Hostname: string", "incident_type": "YaraScan", "type_description": '
                    '"YARA scan", "source_description": "Third-party malware detection software"}'
                    ),
        'severity': IncidentSeverity.CRITICAL
    }
]
MALWARE_EVENTS_WITHOUT_NEEDED_TYPE = [
    {
        "id": "497f6eca-6276-4993-bfeb-53cbbbba6f08",
        "type": "Unknown",
        "detectionTimeUtc": "2019-08-24T14:15:22Z",
        "machine": {
            "displayName": "string",
            "uuid": "string",
            "backupObjectId": "e5daa78c-c0bb-44d5-8a9c-04130e3d324a"
        },
        "state": "Created",
        "details": "string",
        "source": "MarkAsCleanEvent",
        "severity": "Clean",
        "createdBy": "string",
        "engine": "string"
    }
]
MALWARE_EVENTS_WITHOUT_NEEDED_SEVERITY = [
    {
        "id": "497f6eca-6276-4993-bfeb-53cbbbba6f08",
        "type": "Unknown",
        "detectionTimeUtc": "2019-08-24T14:15:22Z",
        "machine": {
            "displayName": "string",
            "uuid": "string",
            "backupObjectId": "e5daa78c-c0bb-44d5-8a9c-04130e3d324a"
        },
        "state": "Created",
        "details": "string",
        "source": "External",
        "severity": "Clean",
        "createdBy": "string",
        "engine": "string"
    }
]
DEFAULT_FETCH = 20


@pytest.mark.parametrize(
    'start_time, existed_ids, max_events_for_fetch, response_data, expected_results',
    [
        # 1 test case: max_events_for_fetch = DEFAULT_FETCH, events with needed type
        # and source => we expect events and its ids;
        (
            datetime.now(), set(), DEFAULT_FETCH, MALWARE_EVENTS_WITH_NEEDED_TYPE,
            (
                MALWARE_INCIDENTS,
                {'b9b6d52f-d8ac-448f-ac32-5b86e07d05fa'},
                {'b9b6d52f-d8ac-448f-ac32-5b86e07d05fa'}
            )
        ),
        # 2 test case: events without needed type and source => we expect 0 events;
        (
            datetime.now(), set(), DEFAULT_FETCH, MALWARE_EVENTS_WITHOUT_NEEDED_TYPE,
            ([], set(), set())
        ),
        # 3 test case: max_events_for_fetch = 0,
        # events with needed type and source => we expect 0 events cause we have 'max_events_for_fetch' = 0;
        (
            datetime.now(), set(), 0, MALWARE_EVENTS_WITH_NEEDED_TYPE,
            ([], set(), set())
        ),
        # 4 test case: events without needed severity => we expect 0 events;
        (
            datetime.now(), set(), DEFAULT_FETCH, MALWARE_EVENTS_WITHOUT_NEEDED_SEVERITY,
            ([], set(), set())
        ),
    ]
)
def test_get_malware_incidents(
    client, mocker, start_time, existed_ids, max_events_for_fetch, response_data, expected_results
):
    mock_search_with_paging = mocker.patch('VBRRESTAPI.search_with_paging')
    mock_search_with_paging.return_value = response_data

    mock_overwrite_last_fetch_time = mocker.patch('VBRRESTAPI.overwrite_last_fetch_time')
    mock_overwrite_last_fetch_time.return_value = start_time.strftime(DATE_FORMAT)

    malware_incidents, malwareIds, last_fetch_time = get_malware_incidents(
        client, start_time, existed_ids, max_events_for_fetch
    )

    assert malware_incidents == expected_results[0]
    assert malwareIds == expected_results[1]

    malware_incidents, malwareIds, last_fetch_time = get_malware_incidents(
        client, start_time, malwareIds, max_events_for_fetch
    )
    assert mock_search_with_paging.call_count == 2
    assert len(malware_incidents) == 0
    assert malwareIds == expected_results[2]


@pytest.mark.parametrize(
    'last_fetch_time, event, expected_result',
    [
        # 1 test case: 'last_fetch_time' = 2024-05-24T15:42:22.198Z => we expect 'last_fetch_time' remain the same
        ('2024-05-24T15:42:22.198Z', MALWARE_EVENTS_WITH_NEEDED_TYPE[0], '2024-05-24T15:42:22.198Z'),
        # 2 test case: 'last_fetch_time' = 2019-08-24T14:15:22Z => we expect 'last_fetch_time' change to event 'detectiontimeutc'
        ('2019-08-24T14:15:22Z', MALWARE_EVENTS_WITH_NEEDED_TYPE[0], '2024-04-24T15:42:22.198Z')
    ]
)
def test_overwrite_last_fetch_time(last_fetch_time, event, expected_result):
    last_time = overwrite_last_fetch_time(last_fetch_time, event)
    assert last_time == expected_result


CONF_BACKUP_INCIDENT = {
    'name': 'Veeam -  has no configuration backups',
    'occurred': datetime.now().strftime(DATE_FORMAT),
    'rawJSON': ('{"isEnabled": true, "backupRepositoryId": "88788f9e-d8f5-4eb4-bc4f-9b3f5403bcec", "restorePointsToKeep": 10, '
                '"notifications": {"SNMPEnabled": true, "SMTPSettings": {"settingsType": "Custom", "isEnabled": false, '
                '"recipients": [], "subject": "[%JobResult%] %JobName% (%Time%)", "notifyOnSuccess": true, '
                '"notifyOnWarning": true, "notifyOnError": true}}, "schedule": {"isEnabled": true, "daily": '
                '{"dailyKind": "Everyday", "isEnabled": true, "localTime": "10:00", "days": '
                '["monday", "tuesday", "wednesday", "thursday", "friday", "saturday", "sunday"]}, "monthly": '
                '{"dayOfWeek": "saturday", "dayNumberInMonth": "Fourth", "isEnabled": false, "localTime": "22:00", '
                '"dayOfMonth": null, "months": ["January", "February", "March", "April", "May", "June", "July", '
                '"August", "September", "October", "November", "December"]}}, "lastSuccessfulBackup": '
                '{"lastSuccessfulTime": "2024-05-13T10:00:51.018689-07:00", "sessionId": '
                '"8465a7d4-6033-45db-b446-bb36fcf1eab5"}, "encryption": {"isEnabled": false, '
                '"passwordId": "00000000-0000-0000-0000-000000000000"}, '
                '"details": "Last successful backup: 2024-05-13T10:00:51.018689-07:00", '
                '"incident_type": "Configuration Backup"}'
                ),
    'severity': IncidentSeverity.MEDIUM
}


@pytest.mark.parametrize(
    'last_successful_backup_date, backup_older_then_days, response_data, expected_results',
    [
        # 1 test case: backup_older_then_days = 0 => we expect events
        # and new 'last_successful_backup_date' cause the last successful backup was a lot of days ago;
        (
            '', 0, GET_CONF_BACKUP_RESPONSE,
            (CONF_BACKUP_INCIDENT, '2024-05-13T10:00:51.018689-07:00')
        ),
        # 2 test case: last_successful_backup_date = 2024-06-13T10:00:51.018689-07:00 =>
        # we expect 0 events and no change of 'last_successful_backup_date'
        # because the last successful backup date is newer than the event's
        (
            '2024-06-13T10:00:51.018689-07:00', 0, GET_CONF_BACKUP_RESPONSE,
            ({}, '2024-06-13T10:00:51.018689-07:00')
        ),
        # 3 test case: last_successful_backup_date = 2024-04-13T10:00:51.018689-07:00 =>
        # we expect events and new 'last_successful_backup_date'
        # because last successfull backup date older than the event's
        (
            '2024-04-13T10:00:51.018689-07:00', 0, GET_CONF_BACKUP_RESPONSE,
            (CONF_BACKUP_INCIDENT, '2024-05-13T10:00:51.018689-07:00')
        )
    ]
)
def test_get_configuration_backup_incident(
    client, mocker, last_successful_backup_date, backup_older_then_days, response_data, expected_results
):
    mock_get_configuration_backup_request = mocker.patch('VBRRESTAPI.Client.get_configuration_backup_request')
    mock_get_configuration_backup_request.return_value = response_data

    backup_incident, backupDate = get_configuration_backup_incident(
        client, last_successful_backup_date, backup_older_then_days
    )
    if backup_incident:
        expected_results[0]['occurred'] = backup_incident['occurred']

    assert backup_incident == expected_results[0]
    assert backupDate == expected_results[1]

    backup_incident, backupDate = get_configuration_backup_incident(
        client, backupDate, backup_older_then_days
    )
    assert mock_get_configuration_backup_request.call_count == 2
    assert len(backup_incident) == 0
    assert backupDate == expected_results[1]


REPOS_SPACE_EVENTS = [
    {
        'type': 'WinLocal',
        'id': '88788f9e-d8f5-4eb4-bc4f-9b3f5403bcec',
        'name': 'Default Backup Repository',
        'description': 'Created by Veeam Backup',
        'hostId': '6745a759-2205-4cd2-b172-8ec8f7e60ef8',
        'hostName': 'WIN-Q4F3IF4VR1L',
        'path': 'C:\\Backup',
        'capacityGB': 149.4,
        'freeGB': 68.9,
        'usedSpaceGB': 30.6
    }
]
REPOS_SPACE_INCIDENTS = [
    {
        'name': 'Veeam - Repository Default Backup Repository is running low on disk space. Free space: 68.9',
        'occurred': '2024-05-16T07:21:32Z',
        'rawJSON': ('{"type": "WinLocal", "id": "88788f9e-d8f5-4eb4-bc4f-9b3f5403bcec", '
                    '"name": "Default Backup Repository", "description": "Created by Veeam Backup", '
                    '"hostId": "6745a759-2205-4cd2-b172-8ec8f7e60ef8", "hostName": "WIN-Q4F3IF4VR1L", '
                    '"path": "C:\\\\Backup", "capacityGB": 149.4, "freeGB": 68.9, "usedSpaceGB": 30.6, '
                    '"details": "Created by Veeam Backup; Repository Name: Default Backup Repository; '
                    'Free Space (GB): 68.9; Hostname: WIN-Q4F3IF4VR1L", "incident_type": "Repository Capacity"}'
                    ),
        'severity': IncidentSeverity.HIGH
    }
]


@pytest.mark.parametrize(
    'existed_ids, max_events_for_fetch, free_space_less_then, response_data, expected_results',
    [
        # 1 test case: 'free_space_less_then' == 50 =>
        # we expect 0 events because our event has 69 free gb
        (
            set(), DEFAULT_FETCH, 50,
            REPOS_SPACE_EVENTS, ([], set())
        ),
        # 2 test case: 'free_space_less_then' == 200 =>
        # we expect new event because our event has 69 free gb
        (
            set(), DEFAULT_FETCH, 200,
            REPOS_SPACE_EVENTS, (REPOS_SPACE_INCIDENTS, {'88788f9e-d8f5-4eb4-bc4f-9b3f5403bcec'})
        ),
        # 3 test case: 'free_space_less_then' == 200 but we have event id in 'existed_ids' =>
        # we expect 0 events because this event already exist
        (
            {'88788f9e-d8f5-4eb4-bc4f-9b3f5403bcec'}, DEFAULT_FETCH, 200,
            REPOS_SPACE_EVENTS, ([], {'88788f9e-d8f5-4eb4-bc4f-9b3f5403bcec'})
        ),
        # 4 test case: 'max_events_for_fetch' == 0 =>
        # we expect 0 events cause we have 'max_events_for_fetch' = 0;
        (
            set(), 0, 200,
            REPOS_SPACE_EVENTS, ([], set())
        )
    ]
)
def test_get_repository_space_incidents(
    client, mocker, existed_ids, max_events_for_fetch,
    free_space_less_then, response_data, expected_results
):
    mock_search_with_paging = mocker.patch('VBRRESTAPI.search_with_paging')
    mock_search_with_paging.return_value = response_data

    free_space_incidents, repositoryIds = get_repository_space_incidents(
        client, existed_ids, max_events_for_fetch, free_space_less_then
    )
    if free_space_incidents:
        expected_results[0][0]['occurred'] = free_space_incidents[0]['occurred']

    assert free_space_incidents == expected_results[0]
    assert repositoryIds == expected_results[1]

    free_space_incidents, repositoryIds = get_repository_space_incidents(
        client, repositoryIds, max_events_for_fetch, free_space_less_then
    )
    assert mock_search_with_paging.call_count == 2
    assert len(free_space_incidents) == 0
    assert repositoryIds == expected_results[1]


@pytest.mark.parametrize(
    'last_run, max_results, errors_by_command, expected_result',
    [
        (
            {'repository_ids': [1, 2, 3]}, 10, {'error_count_in_free_space_incidents': 0},
            ({1, 2, 3}, [], set())
        ),
    ]
)
def test_fetch_repository_space_incidents(
    client, mocker, last_run, max_results, errors_by_command, expected_result
):
    mock_handle_command_with_token_refresh = mocker.patch('VBRRESTAPI.handle_command_with_token_refresh')
    mock_handle_command_with_token_refresh.return_value = ([], set())

    free_space_less_then = 200
    incidents, repository_ids = fetch_repository_space_incidents(
        client, last_run, max_results, free_space_less_then, errors_by_command
    )

    args = mock_handle_command_with_token_refresh.call_args[0]
    assert args[1]['existed_ids'] == expected_result[0]
    assert incidents == expected_result[1]
    assert repository_ids == expected_result[2]


@pytest.mark.parametrize(
    'last_run, max_results, errors_by_command, expected_result',
    [
        (
            {'repository_ids': [1, 2, 3]}, 10, {'error_count_in_free_space_incidents': 1},
            ([{'type': 'incident_on_error'}], {1, 2, 3})
        ),
    ]
)
def test_fetch_repository_space_incidents_with_exception(
    client, mocker, last_run, max_results, errors_by_command, expected_result
):
    mocker.patch('VBRRESTAPI.handle_command_with_token_refresh')
    mock_process_error = mocker.patch('VBRRESTAPI.process_error')
    mock_process_error.return_value = ({'type': 'incident_on_error'}, {'error_in_triggered_alarms': 2})
    mocker.patch.object(demisto, 'debug')

    free_space_less_then = 200
    incidents, repository_ids = fetch_repository_space_incidents(
        client, last_run, max_results, free_space_less_then, errors_by_command
    )

    mock_process_error.assert_called_once()
    assert incidents == expected_result[0]
    assert repository_ids == expected_result[1]


@pytest.mark.parametrize(
    'last_run, max_results, errors_by_command, expected_result',
    [
        (
            {'malware_ids': [1, 2, 3]}, 10, {'error_count_in_malware_incidents': 0},
            ({1, 2, 3, 4, 5}, {'post_event_ids': []}, [], set())
        ),
    ]
)
def test_fetch_malware_events(
    client, mocker, last_run, max_results, errors_by_command, expected_result
):
    mock_handle_command_with_token_refresh = mocker.patch('VBRRESTAPI.handle_command_with_token_refresh')
    mock_handle_command_with_token_refresh.return_value = ([], set(), '2024-05-24T15:42:22.198Z')
    mocker.patch.object(demisto, 'getIntegrationContext', return_value={'post_event_ids': [4, 5]})
    mock_set_integration_context = mocker.patch.object(demisto, 'setIntegrationContext')

    last_fetch = '2024-05-24T15:42:22.198Z'
    malware_incidents, malwareIds, _ = fetch_malware_events(
        client, last_run, last_fetch, max_results, errors_by_command
    )

    args = mock_handle_command_with_token_refresh.call_args[0]
    assert args[1]['existed_ids'] == expected_result[0]
    set_context_args = mock_set_integration_context.call_args[0]
    assert set_context_args[0] == expected_result[1]
    assert malware_incidents == expected_result[2]
    assert malwareIds == expected_result[3]


@pytest.mark.parametrize(
    'last_run, errors_by_command, expected_result',
    [
        (
            {'backup_date': '2024-05-24T15:42:22.198Z'},
            {'error_count_in_configuration_backup': 0},
            '2024-05-24T15:42:22.198Z'
        )
    ]
)
def test_fetch_configuration_backup_incident(
    client, mocker, last_run, errors_by_command, expected_result
):
    mock_handle_command_with_token_refresh = mocker.patch('VBRRESTAPI.handle_command_with_token_refresh')
    mock_handle_command_with_token_refresh.return_value = ({}, '2024-05-24T15:42:22.198Z')

    backup_older_then_days = 30
    fetch_configuration_backup_incident(
        client, last_run, backup_older_then_days, errors_by_command
    )

    args = mock_handle_command_with_token_refresh.call_args[0]
    assert args[1]['last_successful_backup_date'] == expected_result


FETCH_ERROR_INCIDENT = {
    'name': 'Veeam - Fetch incident error has occurred on ',
    'occurred': datetime.now().strftime(DATE_FORMAT),
    'rawJSON': '{"incident_type": "Incident Fetch Error", "details": "Sample error message"}',
    'severity': IncidentSeverity.MEDIUM
}


@pytest.mark.parametrize(
    'error_count, error_message, expected_results',
    [
        # 1 test case: first error -> 1 error_count and 0 incidents
        (0, 'Sample error message', (1, {})),
        # 2 test case: sixth error in a row -> 6 error_count and new incident
        (5, 'Sample error message', (6, FETCH_ERROR_INCIDENT)),
    ]
)
def test_process_error(error_count, error_message, expected_results):
    incident, new_error_count = process_error(error_count, error_message)
    if incident:
        expected_results[1]['occurred'] = incident['occurred']

    assert new_error_count == expected_results[0]
    assert incident == expected_results[1]


RESPONSE = [
    (MALWARE_INCIDENTS, ['b9b6d52f-d8ac-448f-ac32-5b86e07d05fa'], '2024-04-24T15:42:22.198Z'),
    (REPOS_SPACE_INCIDENTS, ['88788f9e-d8f5-4eb4-bc4f-9b3f5403bcec']),
    ([CONF_BACKUP_INCIDENT], '2024-05-13T10:00:51.018689-07:00')
]

LAST_RUN = {
    'last_fetch': '2024-04-24T15:42:22.198Z',
    'malware_ids': ['b9b6d52f-d8ac-448f-ac32-5b86e07d05fa'],
    'repository_ids': ['88788f9e-d8f5-4eb4-bc4f-9b3f5403bcec'],
    'backup_date': '2024-05-13T10:00:51.018689-07:00',
    'errors_by_command': {}
}


@pytest.mark.parametrize(
    'last_run, first_fetch_time, response_data, expected_results',
    [
        # 1 test case:
        ({}, '2024-04-23T15:42:22.198Z', RESPONSE, (LAST_RUN, 3))

    ]
)
def test_fetch_incidents(client, mocker, last_run, first_fetch_time, response_data, expected_results):
    mock_fetch_malware_events = mocker.patch('VBRRESTAPI.fetch_malware_events')
    mock_fetch_malware_events.return_value = response_data[0]

    mock_fetch_repository_space_incidents = mocker.patch('VBRRESTAPI.fetch_repository_space_incidents')
    mock_fetch_repository_space_incidents.return_value = response_data[1]

    mock_fetch_configuration_backup_incident = mocker.patch('VBRRESTAPI.fetch_configuration_backup_incident')
    mock_fetch_configuration_backup_incident.return_value = response_data[2]

    next_run, incidents = fetch_incidents(
        client, last_run, first_fetch_time, DEFAULT_FETCH, DEFAULT_FETCH, 30, 200, True, True, True
    )
    mock_fetch_malware_events.assert_called_once()
    mock_fetch_repository_space_incidents.assert_called_once()
    mock_fetch_configuration_backup_incident.assert_called_once()

    assert next_run == expected_results[0]
    assert len(incidents) == expected_results[1]


RESPONSE_DATA = {'data': [{'id': 1}, {'id': 2}, {'id': 3}, {'id': 4}, {'id': 5}]}


@pytest.mark.parametrize(
    'page_size, size_limit, response, expected_result, expected_calls',
    [
        (
            3, 0, RESPONSE_DATA,
            [{'id': 1}, {'id': 2}, {'id': 3}, {'id': 4}, {'id': 5}],
            [{'skip': 0, 'limit': 3}, {'skip': 3, 'limit': 3}]
        ),
        (
            100, 0, RESPONSE_DATA,
            [{'id': 1}, {'id': 2}, {'id': 3}, {'id': 4}, {'id': 5}],
            [{'skip': 0, 'limit': 100}]
        ),
        (
            4, 2, RESPONSE_DATA,
            [{'id': 1}, {'id': 2}],
            [{'skip': 0, 'limit': 2}]
        ),
        (
            3, 3, RESPONSE_DATA,
            [{'id': 1}, {'id': 2}, {'id': 3}],
            [{'skip': 0, 'limit': 3}]
        )
    ]
)
def test_search_with_paging(mocker, page_size, size_limit, response, expected_result, expected_calls):
    method_mock = ApiMock(response)
    args = {}
    result = search_with_paging(method_mock, args, page_size, size_limit)

    assert result == expected_result
    actual_calls = method_mock.call_args_list
    for actual_call, expected_call in zip(actual_calls, expected_calls):
        assert actual_call == expected_call

    assert method_mock.call_count == len(expected_calls)


def test_validate_filter_parameter():
    try:
        value = 128  # normal int value
        validate_filter_parameter(value)
    except Exception as e:
        pytest.fail(f'raised {e}')


@pytest.mark.parametrize(
    'value',
    [
        -1,  # negative int
        MAX_INT + 1,  # more than max_int value
    ]
)
def test_validate_filter_parameter_with_exception(value):
    with pytest.raises(ValueError):
        validate_filter_parameter(value)


@pytest.mark.parametrize('command', [
    ('test-module'),
    ('veeam-vbr-get-configuration-backup')  # all real commands
])
def test_process_command(client, mocker, command):
    mock_handle_command_with_token_refresh = mocker.patch('VBRRESTAPI.handle_command_with_token_refresh')
    try:
        process_command(command, client, datetime.now(), {}, {})
        mock_handle_command_with_token_refresh.assert_called_once()
    except Exception as e:
        pytest.fail(f'raised {e}')


@pytest.mark.parametrize('command', [
    ('test-'),
    ('vbr-get-')  # not real commands
])
def test_process_command_with_exception(client, mocker, command):
    mocker.patch('VBRRESTAPI.handle_command_with_token_refresh')
    with pytest.raises(NotImplementedError):
        process_command(command, client, datetime.now(), {}, {})


def test_handle_command_with_token_refresh_attempts(client, mocker):
    mock_getIntegrationContext = mocker.patch(
        'VBRRESTAPI.demisto.getIntegrationContext',
        side_effect=[{}, {}, {}, {}, {'token': 'valid'}]
    )  # only on 3 attempt give context
    mock_setIntegrationContext = mocker.patch('VBRRESTAPI.demisto.setIntegrationContext')
    mock_get_api_key = mocker.patch('VBRRESTAPI.get_api_key', return_value='new_api_key')
    mock_set_api_key = mocker.patch('VBRRESTAPI.set_api_key')

    mock_command = Mock()
    response = requests.models.Response()
    response.status_code = 401
    mock_command.side_effect = [
        DemistoException(message='test', res=response),
        DemistoException(message='test', res=response),
        {'res': 'success'}
    ]  # 3 attemps -> last success

    result = handle_command_with_token_refresh(mock_command, {}, client, max_attempts=3)

    assert result == {'res': 'success'}
    assert mock_getIntegrationContext.call_count == 5  # 3 calls + 2 on exception
    assert mock_get_api_key.call_count == 2
    assert mock_setIntegrationContext.call_count == 4  # 2 resets + 2 setting token
    assert mock_set_api_key.call_count == 3
    assert mock_command.call_count == 3


def test_handle_command_with_token_refresh_attempts_exception(client, mocker):
    mock_getIntegrationContext = mocker.patch(
        'VBRRESTAPI.demisto.getIntegrationContext',
        side_effect=[{}, {}, {}, {}, {}, {}]
    )
    mock_setIntegrationContext = mocker.patch('VBRRESTAPI.demisto.setIntegrationContext')
    mock_get_api_key = mocker.patch('VBRRESTAPI.get_api_key', return_value='new_api_key')
    mock_set_api_key = mocker.patch('VBRRESTAPI.set_api_key')

    mock_command = Mock()
    response = requests.models.Response()
    response.status_code = 401
    mock_command.side_effect = [
        DemistoException(message='test', res=response),
        DemistoException(message='test', res=response),
        DemistoException(message='test', res=response)
    ]  # all 3 attemps fail

    with pytest.raises(ValueError):
        handle_command_with_token_refresh(mock_command, {}, client, max_attempts=3)

    assert mock_getIntegrationContext.call_count == 6  # 3 calls + 1 on exception
    assert mock_get_api_key.call_count == 3
    assert mock_setIntegrationContext.call_count == 6  # 3 resets + 3 setting token
    assert mock_set_api_key.call_count == 3
    assert mock_command.call_count == 3


def test_handle_command_with_token_refresh(client, mocker):
    mock_getIntegrationContext = mocker.patch(
        'VBRRESTAPI.demisto.getIntegrationContext',
        side_effect=[{}, {'token': 'new_api_key'}, {}, {'token': 'new_api_key'}]
    )
    mock_setIntegrationContext = mocker.patch('VBRRESTAPI.demisto.setIntegrationContext')
    mock_get_api_key = mocker.patch('VBRRESTAPI.get_api_key', return_value='new_api_key')
    mock_set_api_key = mocker.patch('VBRRESTAPI.set_api_key')

    mock_command = Mock()
    response = requests.models.Response()
    response.status_code = 401
    mock_command.side_effect = [
        DemistoException(message='test', res=response),
        {'res': 'success'}
    ]
    result = handle_command_with_token_refresh(mock_command, {}, client, max_attempts=3)

    assert result == {'res': 'success'}

    assert mock_getIntegrationContext.call_count == 3
    assert mock_get_api_key.call_count == 2
    assert mock_setIntegrationContext.call_count == 3
    assert mock_set_api_key.call_count == 2
    assert mock_command.call_count == 2

    mock_setIntegrationContext.assert_any_call({'token': 'new_api_key'})
    mock_set_api_key.assert_any_call(client, 'new_api_key')
