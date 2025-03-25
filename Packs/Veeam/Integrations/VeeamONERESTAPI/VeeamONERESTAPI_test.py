import pytest
import json
from unittest.mock import Mock
from datetime import datetime
from CommonServerPython import *
from VeeamONERESTAPI import DATE_FORMAT, Client, FilterBuilder, Operation, \
    fetch_incidents, search_with_paging, overwrite_last_fetch_time, try_cast_to_int, process_command, \
    handle_command_with_token_refresh, convert_triggered_alarms_to_incidents, process_error, check_version, \
    fetch_converted_incidents, convert_to_list, get_triggered_alarms_command, update_token

SERVER_URL = 'https://test_url.com'
REQUEST_TIMEOUT = 120


class ApiMock:
    def __init__(self, response: dict) -> None:
        self.response = response
        self.call_count = 0
        self.call_args_list = []

    def __call__(self, **args: dict) -> dict:
        self.call_args_list.append(args)
        Offset = args.get('Offset')
        Limit = args.get('Limit')
        data = self.response['items']
        response = data[Offset:Offset + Limit]
        self.call_count += 1
        return {'items': response}


def util_load_json(path):
    with open(path, encoding='utf-8') as f:
        return json.loads(f.read())


@pytest.fixture()
def client():
    return Client(server_url=SERVER_URL, verify=None, proxy=None, headers=None, auth=None, timeout=REQUEST_TIMEOUT)


@pytest.fixture
def filter_builder():
    return FilterBuilder()


def test_add_property(filter_builder):
    filter_builder.add_property('alarmTemplateId', Operation.EQUALS, '330')
    assert len(filter_builder.items) == 1
    assert filter_builder.items[0] == {'property': 'alarmTemplateId', 'operation': 'equals', 'value': '330'}


def test_add_property_with_collation(filter_builder):
    filter_builder.add_property(
        'alarmTemplateId', Operation.EQUALS, '330', collation='ignorecase'
    )
    assert len(filter_builder.items) == 1
    assert filter_builder.items[0] == {
        'property': 'alarmTemplateId',
        'operation': 'equals',
        'value': '330',
        'collation': 'ignorecase'
    }


def test_add_node(filter_builder):
    node = FilterBuilder()
    node.add_property('triggeredTime', Operation.GREATER_THAN_OR_EQUAL, 'last_fetch_time')
    filter_builder.add_node(node)

    assert len(filter_builder.items) == 1
    assert filter_builder.items[0] == {
        'property': 'triggeredTime',
        'operation': 'greaterThanOrEqual',
        'value': 'last_fetch_time'
    }


STR_FILTER = (
    '{"operation": "and", "items": [{"property": "triggeredTime", '
    '"operation": "greaterThanOrEqual", "value": "last_fetch_time"}, '
    '{"property": "alarmTemplateId", "operation": "equals", "value": "330"}]}'
)


@pytest.mark.parametrize(
    'operation, items, expected_result',
    [
        (
            Operation.AND,
            [
                {'property': 'triggeredTime', 'operation': 'greaterThanOrEqual', 'value': 'last_fetch_time'},
                {'property': 'alarmTemplateId', 'operation': 'equals', 'value': '330'}
            ],
            STR_FILTER
        ),
        (
            None,
            [{'property': 'alarmTemplateId', 'operation': 'equals', 'value': '330'}],
            '{"property": "alarmTemplateId", "operation": "equals", "value": "330"}'
        )
    ]
)
def test_str(operation, items, expected_result):
    filter_builder = FilterBuilder(operation=operation, items=items)
    assert filter_builder.__str__() == expected_result


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
    "string, expected_result",
    [
        ("[1, 2, 3]", [1, 2, 3]),
        ("[4, 5, 6]", [4, 5, 6]),
        ("[]", [])
    ]
)
def test_convert_to_list(string, expected_result):
    assert convert_to_list(string) == expected_result


def test_convert_to_list_invalid_string():
    string = "abc"
    with pytest.raises(Exception):
        convert_to_list(string)


@pytest.mark.parametrize(
    'version, expected_result',
    [
        ('12.1.0.1', 'Exception'),
        ('12.2.0.3770', None),
        ('12.3.0', None),
        ('12.1.12.2', 'Exception'),
        ('12.2.0', None)

    ]
)
def test_check_version(version, expected_result):
    if expected_result:
        with pytest.raises(ValueError):
            check_version(version)
    else:
        check_version(version)


def test_update_token(client, mocker):
    expected_token = 'token'
    mocker.patch(
        'VeeamONERESTAPI.Client.authentication_create_token_request',
        return_value={'access_token': 'token'}
    )

    token = update_token(client, 'username', 'password')

    assert token == expected_token


@pytest.mark.parametrize(
    "response, expected_command_results",
    [
        (
            {
                'items': [
                    {'id': 1, 'name': 'Alarm 1', 'severity': 3},
                    {'id': 2, 'name': 'Alarm 2', 'severity': 2},
                    {'id': 3, 'name': 'Alarm 3', 'severity': 1}
                ]
            },
            {
                'outputs_prefix': 'Veeam.VONE.TriggeredAlarmInfoPage',
                'outputs_key_field': '',
                'outputs': [
                    {'id': 1, 'name': 'Alarm 1', 'severity': 3},
                    {'id': 2, 'name': 'Alarm 2', 'severity': 2},
                    {'id': 3, 'name': 'Alarm 3', 'severity': 1}
                ],
                'raw_response': [
                    {'id': 1, 'name': 'Alarm 1', 'severity': 3},
                    {'id': 2, 'name': 'Alarm 2', 'severity': 2},
                    {'id': 3, 'name': 'Alarm 3', 'severity': 1}
                ]
            }
        )
    ]
)
def test_get_triggered_alarms_command(client, mocker, response, expected_command_results):
    mocker.patch('VeeamONERESTAPI.Client.get_triggered_alarms_request', return_value=response)
    mocker.patch('VeeamONERESTAPI.try_cast_to_int')

    args = {}
    command_results = get_triggered_alarms_command(client, args)

    assert command_results.outputs_prefix == expected_command_results['outputs_prefix']
    assert command_results.outputs_key_field == expected_command_results['outputs_key_field']
    assert command_results.outputs == expected_command_results['outputs']
    assert command_results.raw_response == expected_command_results['raw_response']


TRIGGERED_ALARMS = util_load_json('test_data/get_triggered_alarms.json')
TRIGGERED_ALARMS_INCIDENTS = [
    {
        'name': 'Veeam - VM with no replica (Virtual Infrastructure)',
        'occurred': '2024-05-27T14:28:52.66Z',
        'rawJSON': ('{"triggeredAlarmId": 4, "name": "VM with no replica", "alarmTemplateId": 330, '
                    '"predefinedAlarmId": 331, "triggeredTime": "2024-05-27T14:28:52.66Z", "status": "Resolved", '
                    '"description": "All metrics are back to normal", "comment": "", "repeatCount": 13, "alarmAssignment": '
                    '{"objectId": 0, "objectName": "Virtual Infrastructure", "objectType": "VirtualInfrastructure"}, '
                    '"childAlarmsCount": 0, "remediation": [], "incident_type": 331}'
                    ),
        'severity': IncidentSeverity.CRITICAL
    }
]
DEFAULT_FETCH = 20


@pytest.mark.parametrize(
    'start_time, existed_ids, max_events_for_fetch, response_data, expected_results',
    [
        # 1 test case: max_events_for_fetch = DEFAULT_FETCH,  => we expect events and its ids
        (
            datetime.now(),
            set(),
            DEFAULT_FETCH,
            TRIGGERED_ALARMS,
            (TRIGGERED_ALARMS_INCIDENTS, {'4'}, {'4'})
        ),
        # 2 test case: max_events_for_fetch = 0, => we expect 0 events cause we have 'max_events_for_fetch' = 0
        (
            datetime.now(),
            set(),
            0,
            TRIGGERED_ALARMS,
            ([], set(), set())
        )
    ]
)
def test_convert_triggered_alarms_to_incidents(
    client, mocker, start_time, existed_ids, max_events_for_fetch,
    response_data, expected_results
):
    mock_search_with_paging = mocker.patch('VeeamONERESTAPI.search_with_paging')
    mock_search_with_paging.return_value = response_data

    mock_overwrite_last_fetch_time = mocker.patch('VeeamONERESTAPI.overwrite_last_fetch_time')
    mock_overwrite_last_fetch_time.return_value = start_time.strftime(DATE_FORMAT)

    incidents, alarmsIds, last_fetch_time = convert_triggered_alarms_to_incidents(
        client, start_time, existed_ids, max_events_for_fetch
    )

    assert incidents == expected_results[0]
    assert alarmsIds == expected_results[1]

    incidents, alarmsIds, last_fetch_time = convert_triggered_alarms_to_incidents(
        client, start_time, alarmsIds, max_events_for_fetch
    )

    assert mock_search_with_paging.call_count == 2
    assert len(incidents) == 0
    assert alarmsIds == expected_results[2]


@pytest.mark.parametrize(
    'last_run, last_fetch, max_results, errors_by_command, expected_result',
    [
        (
            {'alarms_ids': [1, 2, 3]}, '2022-01-01T00:00:00Z', 10, {'error_in_triggered_alarms': 0},
            ([], set(), '2022-01-01T00:00:00Z')
        ),
    ]
)
def test_fetch_converted_incidents(
    client, mocker, last_run, last_fetch, max_results, errors_by_command, expected_result
):
    mock_handle_command_with_token_refresh = mocker.patch('VeeamONERESTAPI.handle_command_with_token_refresh')
    mock_handle_command_with_token_refresh.return_value = ([], set(), '2022-01-01T00:00:00Z')

    incidents, alarms_ids, last_fetch_time = fetch_converted_incidents(
        client, last_run, last_fetch, max_results, errors_by_command
    )

    mock_handle_command_with_token_refresh.assert_called_once()
    assert incidents == expected_result[0]
    assert alarms_ids == expected_result[1]
    assert last_fetch_time == expected_result[2]


@pytest.mark.parametrize(
    'last_run, last_fetch, max_results, errors_by_command, expected_result',
    [
        (
            {'alarms_ids': [1, 2, 3]}, '2022-01-01T00:00:00Z', 10, {'error_in_triggered_alarms': 1},
            ([{'type': 'incident_on_error'}], {1, 2, 3}, '2022-01-01T00:00:00Z')
        ),
    ]
)
def test_fetch_converted_incidents_with_exception(
    client, mocker, last_run, last_fetch, max_results, errors_by_command, expected_result
):
    mocker.patch('VeeamONERESTAPI.handle_command_with_token_refresh')
    mock_process_error = mocker.patch('VeeamONERESTAPI.process_error')
    mock_process_error.return_value = ({'type': 'incident_on_error'}, {'error_in_triggered_alarms': 2})

    incidents, alarms_ids, last_fetch_time = fetch_converted_incidents(
        client, last_run, last_fetch, max_results, errors_by_command
    )

    mock_process_error.assert_called_once()
    assert incidents == expected_result[0]
    assert alarms_ids == expected_result[1]
    assert last_fetch_time == expected_result[2]


@pytest.mark.parametrize(
    'last_fetch_time, alarm, expected_result',
    [
        # 1 test case: 'last_fetch_time' = 2024-05-28T15:42:22.198Z => we expect 'last_fetch_time' remain the same
        (
            '2024-05-28T15:42:22.198Z',
            TRIGGERED_ALARMS[0],
            '2024-05-28T15:42:22.198Z'
        ),
        # 2 test case: 'last_fetch_time' = 2019-08-24T14:15:22Z => we expect 'last_fetch_time' change to the alarm 'triggeredTime'
        (
            '2019-08-24T14:15:22Z',
            TRIGGERED_ALARMS[0],
            '2024-05-27T14:28:52.66Z'
        )
    ]
)
def test_overwrite_last_fetch_time(last_fetch_time, alarm, expected_result):
    last_time = overwrite_last_fetch_time(last_fetch_time, alarm)
    assert last_time == expected_result


FETCH_ERROR_INCIDENT = {
    'name': "Veeam - Fetch incident error has occurred on ",
    'occurred': datetime.now().strftime(DATE_FORMAT),
    'rawJSON': '{"incident_type": "Incident Fetch Error", "details": "Sample error message"}',
    'severity': IncidentSeverity.MEDIUM
}


@pytest.mark.parametrize(
    'error_count, error_message,  expected_results',
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


RESPONSE = [(TRIGGERED_ALARMS_INCIDENTS, ['330'], '2024-05-27T14:28:52.66Z')]
LAST_RUN = {'last_fetch': '2024-05-27T14:28:52.66Z', 'alarms_ids': ['330'], 'errors_by_command': {}}


@pytest.mark.parametrize(
    'last_run, first_fetch_time, response_data, expected_results',
    [
        # 1 test case:
        ({}, '2024-04-24T15:42:22.198Z', RESPONSE, (LAST_RUN, 1))

    ]
)
def test_fetch_incidents(client, mocker, last_run, first_fetch_time, response_data, expected_results):
    mock_fetch_converted_incidents = mocker.patch('VeeamONERESTAPI.fetch_converted_incidents')
    mock_fetch_converted_incidents.return_value = response_data[0]

    next_run, incidents = fetch_incidents(client, last_run, first_fetch_time, DEFAULT_FETCH)
    mock_fetch_converted_incidents.assert_called_once()

    assert next_run == expected_results[0]
    assert len(incidents) == expected_results[1]


RESPONSE_DATA = {'items': [{'id': 1}, {'id': 2}, {'id': 3}, {'id': 4}, {'id': 5}]}


@pytest.mark.parametrize(
    'page_size, size_limit, response, expected_result, expected_calls',
    [
        (
            3, 0, RESPONSE_DATA,
            [{'id': 1}, {'id': 2}, {'id': 3}, {'id': 4}, {'id': 5}],
            [{'Offset': 0, 'Limit': 3}, {'Offset': 3, 'Limit': 3}]
        ),
        (
            100, 0, RESPONSE_DATA,
            [{'id': 1}, {'id': 2}, {'id': 3}, {'id': 4}, {'id': 5}],
            [{'Offset': 0, 'Limit': 100}]
        ),
        (
            4, 2, RESPONSE_DATA,
            [{'id': 1}, {'id': 2}],
            [{'Offset': 0, 'Limit': 2}]
        ),
        (
            3, 3, RESPONSE_DATA,
            [{'id': 1}, {'id': 2}, {'id': 3}],
            [{'Offset': 0, 'Limit': 3}]
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


@pytest.mark.parametrize('command', [
    ('test-module'),
    ('veeam-vone-get-triggered-alarms')  # all real commands
])
def test_process_command(client, mocker, command):
    mock_handle_command_with_token_refresh = mocker.patch('VeeamONERESTAPI.handle_command_with_token_refresh')
    try:
        process_command(command, client, datetime.now(), {}, {})
        mock_handle_command_with_token_refresh.assert_called_once()
    except Exception as e:
        pytest.fail(f'raised {e}')


@pytest.mark.parametrize('command', [
    ('test-'),
    ('vone-get-')  # not real commands
])
def test_process_command_with_exception(client, mocker, command):
    mocker.patch('VeeamONERESTAPI.handle_command_with_token_refresh')
    with pytest.raises(NotImplementedError):
        process_command(command, client, datetime.now(), {}, {})


def test_handle_command_with_token_refresh_attempts(client, mocker):
    mock_getIntegrationContext = mocker.patch(
        'VeeamONERESTAPI.demisto.getIntegrationContext',
        side_effect=[{}, {}, {}, {}, {'token': 'valid'}]
    )  # Only on 3rd attempt give context
    mock_setIntegrationContext = mocker.patch('VeeamONERESTAPI.demisto.setIntegrationContext')
    mock_get_api_key = mocker.patch('VeeamONERESTAPI.get_api_key', return_value='new_api_key')
    mock_set_api_key = mocker.patch('VeeamONERESTAPI.set_api_key')
    mocker.patch('VeeamONERESTAPI.Client.get_about_request', return_value={})
    mocker.patch('VeeamONERESTAPI.check_version')

    mock_command = Mock()
    response = requests.models.Response()
    response.status_code = 401
    mock_command.side_effect = [
        DemistoException(message='test', res=response),
        DemistoException(message='test', res=response),
        {'res': 'success'}
    ]  # 3 attempts -> last success

    result = handle_command_with_token_refresh(mock_command, {}, client, max_attempts=3)

    assert result == {'res': 'success'}
    assert mock_getIntegrationContext.call_count == 5  # 3 calls + 2 on exception
    assert mock_get_api_key.call_count == 2
    assert mock_setIntegrationContext.call_count == 4  # 2 resets + 2 setting token
    assert mock_set_api_key.call_count == 3
    assert mock_command.call_count == 3


def test_handle_command_with_token_refresh_attempts_exception(client, mocker):
    mock_getIntegrationContext = mocker.patch(
        'VeeamONERESTAPI.demisto.getIntegrationContext',
        side_effect=[{}, {}, {}, {}, {}, {}]
    )
    mock_setIntegrationContext = mocker.patch('VeeamONERESTAPI.demisto.setIntegrationContext')
    mock_get_api_key = mocker.patch('VeeamONERESTAPI.get_api_key', return_value='new_api_key')
    mock_set_api_key = mocker.patch('VeeamONERESTAPI.set_api_key')
    mocker.patch('VeeamONERESTAPI.Client.get_about_request', return_value={})
    mocker.patch('VeeamONERESTAPI.check_version')

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
        'VeeamONERESTAPI.demisto.getIntegrationContext',
        side_effect=[{}, {'token': 'new_api_key'}, {}, {'token': 'new_api_key'}]
    )
    mock_setIntegrationContext = mocker.patch('VeeamONERESTAPI.demisto.setIntegrationContext')
    mock_get_api_key = mocker.patch('VeeamONERESTAPI.get_api_key', return_value='new_api_key')
    mock_set_api_key = mocker.patch('VeeamONERESTAPI.set_api_key')
    mocker.patch('VeeamONERESTAPI.Client.get_about_request', return_value={})
    mocker.patch('VeeamONERESTAPI.check_version')

    mock_command = Mock()
    response = requests.models.Response()
    response.status_code = 401
    mock_command.side_effect = [DemistoException(message='test', res=response), {'res': 'success'}]
    result = handle_command_with_token_refresh(mock_command, {}, client, max_attempts=3)

    assert result == {'res': 'success'}

    assert mock_getIntegrationContext.call_count == 3
    assert mock_get_api_key.call_count == 2
    assert mock_setIntegrationContext.call_count == 3
    assert mock_set_api_key.call_count == 2
    assert mock_command.call_count == 2

    mock_setIntegrationContext.assert_any_call({'token': 'new_api_key'})
    mock_set_api_key.assert_any_call(client, 'new_api_key')
