import pytest
from datetime import datetime
from freezegun import freeze_time
import pytz
import copy
from Exabeam import Client, contents_append_notable_user_info, contents_user_info, get_peer_groups, \
    get_user_labels, get_watchlist, get_asset_data, get_session_info_by_id, get_rules_model_definition, \
    parse_context_table_records_list, get_notable_assets, get_notable_session_details, get_notable_sequence_details, \
    get_notable_sequence_event_types, delete_context_table_records, list_incidents, convert_all_unix_keys_to_date, \
    fetch_incidents, build_incident_response_query_params, fetch_notable_users
from test_data.response_constants import RESPONSE_PEER_GROUPS, RESPONSE_USER_LABELS, RESPONSE_WATCHLISTS, \
    RESPONSE_ASSET_DATA, RESPONSE_SESSION_INFO, RESPONSE_MODEL_DATA, RESPONSE_NOTABLE_ASSET_DATA, \
    RESPONSE_NOTABLE_SESSION_DETAILS, RESPONSE_NOTABLE_SEQUENCE_DETAILS, RESPONSE_NOTABLE_SEQUENCE_EVENTS, \
    DELETE_RECORD_RESPONSE, RESPONSE_INCIDENT_LIST
from test_data.result_constants import EXPECTED_PEER_GROUPS, EXPECTED_USER_LABELS, EXPECTED_WATCHLISTS, \
    EXPECTED_ASSET_DATA, EXPECTED_SESSION_INFO, EXPECTED_MODEL_DATA, EXPECTED_NOTABLE_ASSET_DATA, \
    EXPECTED_NOTABLE_SESSION_DETAILS, EXPECTED_NOTABLE_SEQUENCE_DETAILS, EXPECTED_NOTABLE_SEQUENCE_EVENTS, \
    EXPECTED_RESULT_AFTER_RECORD_DELETION, EXPECTED_INCIDENT_LIST
from test_data.response_incidents import INCIDENTS, EXPECTED_INCIDENTS, EXPECTED_LAST_RUN, EXPECTED_CALL_ARGS, \
    EXPECTED_LAST_RUN_FOR_LOOK_BACK, INCIDENTS_FOR_LOOK_BACK_FIRST_TIME, EXPECTED_INCIDENTS_FOR_LOOK_BACK, \
    EXPECTED_CALL_ARGS_FOR_LOOK_BACK, INCIDENTS_FOR_LOOK_BACK_SECOND_TIME
from test_data.response_users import RES_USERS


def test_contents_append_notable_user_info():
    contents = []
    user_ = {
        "username": 'my_username',
        "lastActivityType": 'malicious',
        "labels": 'bad'
    }
    user = {
        "userFullName": 'my_fullname',
        "notableSessionIds": '123',
        "highestRiskSession": 5
    }
    user_info = {
        "riskScore": 3,
        "location": 'lake wanaka',
        "employeeType": 'manager',
        "department": 'my_dept',
        "title": 'my_title'
    }
    outputs = contents_append_notable_user_info(contents, user, user_, user_info)

    expected_outputs = [{
        "UserName": 'my_username',
        "RiskScore": 3,
        "FirstSeen": None,
        "LastSeen": None,
        "LastActivity": 'malicious',
        "Labels": 'bad',
        "UserFullName": 'my_fullname',
        "Location": 'lake wanaka',
        "NotableSessionIds": '123',
        "NotableUser": True,
        "HighestRiskSession": 5,
        "EmployeeType": 'manager',
        "Department": 'my_dept',
        "Title": 'my_title'
    }]

    assert outputs == expected_outputs


def test_contents_user_info():
    user = {
        "username": 'my_user',
        "accountNames": 'my_account',
        "peerGroupFieldName": 'my_peer_group',
        "peerGroupFieldValue": 'peer51',
        "peerGroupDisplayName": 'PEER51',
        "peerGroupType": 'secret'
    }
    user_info = {
        "riskScore": 42,
        "averageRiskScore": 3,
        "lastSessionId": '123',
        "lastActivityType": 'powershell',
        'labels': 'my_label',
    }
    outputs = contents_user_info(user, user_info)

    expected_outputs = {
        'Username': 'my_user',
        'RiskScore': 42,
        'AverageRiskScore': 3,
        'LastSessionID': '123',
        'FirstSeen': None,
        'LastSeen': None,
        'LastActivityType': 'powershell',
        'Label': 'my_label',
        'AccountNames': 'my_account',
        'PeerGroupFieldName': 'my_peer_group',
        'PeerGroupFieldValue': 'peer51',
        'PeerGroupDisplayName': 'PEER51',
        'PeerGroupType': 'secret'
    }

    assert outputs == expected_outputs


@pytest.mark.parametrize('command, args, response, expected_result', [
    (get_peer_groups, {}, RESPONSE_PEER_GROUPS, EXPECTED_PEER_GROUPS),
    (get_user_labels, {}, RESPONSE_USER_LABELS, EXPECTED_USER_LABELS),
    (get_watchlist, {}, RESPONSE_WATCHLISTS, EXPECTED_WATCHLISTS),
    (get_asset_data, {'asset_name': 'dummmy'}, RESPONSE_ASSET_DATA, EXPECTED_ASSET_DATA),
    (get_session_info_by_id, {'session_id': 'dummmy'}, RESPONSE_SESSION_INFO, EXPECTED_SESSION_INFO),
    (get_rules_model_definition, {'model_name': 'dummmy'}, RESPONSE_MODEL_DATA, EXPECTED_MODEL_DATA),
    (get_notable_assets, {'limit': 1, 'time_period': '1 y'}, RESPONSE_NOTABLE_ASSET_DATA, EXPECTED_NOTABLE_ASSET_DATA),
    (get_notable_session_details, {'limit': 1}, RESPONSE_NOTABLE_SESSION_DETAILS, EXPECTED_NOTABLE_SESSION_DETAILS),
    (get_notable_sequence_details, {'limit': 1, 'page': 0}, RESPONSE_NOTABLE_SEQUENCE_DETAILS,
     EXPECTED_NOTABLE_SEQUENCE_DETAILS),
    (get_notable_sequence_event_types, {'limit': 9, 'page': 0}, RESPONSE_NOTABLE_SEQUENCE_EVENTS,
     EXPECTED_NOTABLE_SEQUENCE_EVENTS),
    (delete_context_table_records, {"records": "test_key", "context_table_name": "test_table"},
     DELETE_RECORD_RESPONSE, EXPECTED_RESULT_AFTER_RECORD_DELETION),
    (list_incidents, {'limit': 1, 'status': 'new'}, RESPONSE_INCIDENT_LIST, EXPECTED_INCIDENT_LIST)
])  # noqa: E124
def test_commands(command, args, response, expected_result, mocker):
    import requests
    requests.packages.urllib3.disable_warnings()
    mocker.patch.object(Client, '_login')
    client = Client('http://exabeam.com/api/auth/login', verify=False, username='user',
                    password='1234', proxy=False, headers={})

    mocker.patch.object(client, '_http_request', return_value=response)
    result = command(client, args)
    assert expected_result == result[1]  # entry context is found in the 2nd place in the result of the command


@pytest.mark.parametrize('records_input, fmt, is_delete, expected_result', [
    ('k1:v1,v2:,v3:v31;v32', 'key:value', False, [{'key': 'k1', 'value': ['v1']},
                                                  {'key': 'v2', 'value': []},
                                                  {'key': 'v3', 'value': ['v31', 'v32']}]),

    ('k1,k2', 'id', True, [{'id': 'k1', 'key': ''}, {'id': 'k2', 'key': ''}]),

    ('id1:k1:v1,id2:k2:,id3:k3:v31;v32', 'id:key:value', False, [{'id': 'id1', 'key': 'k1', 'value': ['v1']},
                                                                 {'id': 'id2', 'key': 'k2', 'value': []},
                                                                 {'id': 'id3', 'key': 'k3', 'value': ['v31', 'v32']}])
])  # noqa: E124
def test_parse_context_table_records_list_good_input(records_input, fmt, is_delete, expected_result):
    """
    Given:
        Valid inputs of context table records
    When:
        Running parse_context_table_records_list.
    Then:
        An equivalent records data, in the payload request format.
    """
    records_list = records_input.split(',')
    result = parse_context_table_records_list(records_list, fmt, is_delete)
    assert result == expected_result


@pytest.mark.parametrize('records_input, fmt, is_delete', [
    ('k1:v1,v2:,v3:v31;v32', 'id:key:value', False),
    ('k1:v1,k2:v2', 'id', True),
    ('id1:k1:v1,id2:k2:,id3:k3:v31;v32', 'key:value', False)
])  # noqa: E124
def test_parse_context_table_records_list_bad_input(records_input, fmt, is_delete):
    """
    Given:
        Invalid inputs of context table records
    When:
        Running parse_context_table_records_list.
    Then:
        Make sure a ValueError exception is thrown.
    """
    records_list = records_input.split(',')
    try:
        parse_context_table_records_list(records_list, fmt, is_delete)
        raise AssertionError
    except ValueError:
        assert True


def test_get_notable_session_details_command_empty_sessions(mocker):
    """
    Given:
        An empty session response.
    When:
        When calling "get_notable_session_details" method.
    Then:
        Verify the human-readable section have the proper message.
    """
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    mocked_res = {'totalCount': 0, 'sessions': [], 'users': {}, 'executiveUserFlags': {}}
    mocker.patch.object(Client, '_login', return_value=None)
    mocker.patch.object(Client, 'get_notable_session_details_request', return_value=mocked_res)

    client = Client(base_url='https://example.com', username='test_user', password='1234', verify=False, proxy=False,
                    headers={})
    human_readable, entry_context, session_details_raw_data = get_notable_session_details(client, {'limit': '1'})
    assert human_readable == 'No results found.'


@pytest.mark.parametrize(
    'args, expected_results',
    [
        (
            {
                'query': None,
                'incident_type': 'generic',
                'status': 'new',
                'priority': 'low',
                'limit': 3,
                'page_size': 25,
                'page_number': 0,
            },
            {
                'query': 'incidentType:generic AND priority:low AND status:new',
                'length': 3,
                'offset': 0,
            }
        ),
        (
            {
                'query': None,
                'incident_type': 'generic',
                'status': None,
                'priority': 'low',
                'limit': 3,
                'page_size': 25,
                'page_number': 0,
            },
            {
                'query': 'incidentType:generic AND priority:low',
                'length': 3,
                'offset': 0,
            }
        ),
        (
            {
                'query': None,
                'incident_type': None,
                'status': None,
                'priority': None,
                'limit': 3,
                'page_size': 25,
                'page_number': 0,
            },
            {
                'length': 3,
                'offset': 0,
            }
        ),
        (
            {
                'query': 'incidentType:generic OR priority:low',
                'incident_type': 'malware',
                'status': None,
                'priority': 'medium',
                'limit': 6,
                'page_size': 25,
                'page_number': 1,
            },
            {
                'query': 'incidentType:generic OR priority:low',
                'length': 6,
                'offset': 25,
            }
        ),
    ]
)
def test_build_incident_response_query_params(args, expected_results):

    results = build_incident_response_query_params(**args)

    for key in results:
        assert results[key] == expected_results[key]


@pytest.mark.parametrize(
    'incident, expected_results',
    [
        (
            {
                'id': 123,
                'baseFields': {
                    'createdAt': 1670420803000,
                    'startedDate': 1670421189876,
                    'closedDate': 1671421199904,
                    'updatedAt': 1670421199904,
                }
            },
            {
                'createdAt': '2022-12-07T13:46:43Z',
                'startedDate': '2022-12-07T13:53:09Z',
                'closedDate': '2022-12-19T03:39:59Z',
                'updatedAt': '2022-12-07T13:53:19Z',
            }
        ),
        (
            {
                'id': 123,
                'baseFields': {
                    'createdAt': 1670420803000,
                    'startedDate': 1670421189876,
                    'updatedAt': 1670421199904,
                }
            },
            {
                'createdAt': '2022-12-07T13:46:43Z',
                'startedDate': '2022-12-07T13:53:09Z',
                'updatedAt': '2022-12-07T13:53:19Z',
            }
        )
    ]
)
def test_convert_all_unix_keys_to_date(incident, expected_results):

    results = convert_all_unix_keys_to_date(incident)

    for key in expected_results:
        assert results['baseFields'][key] == expected_results[key]


@pytest.mark.parametrize(
    'params, incidents, expected_incidents, expected_last_run',
    [
        (
            {'max_fetch': 3, 'incident_type': 'generic,abnormalAuth', 'status': 'new', 'priority': 'medium'},
            INCIDENTS,
            EXPECTED_INCIDENTS,
            EXPECTED_LAST_RUN,
        )
    ]
)
def test_fetch_incdents(mocker, params, incidents, expected_incidents, expected_last_run):

    mocker.patch.object(Client, '_login', return_value=None)
    client = Client(base_url='https://example.com', username='test_user', password='1234', verify=False, proxy=False,
                    headers={})
    request_get_incidents = mocker.patch.object(client, 'get_incidents', return_value=incidents)
    mocker.patch('Exabeam.demisto.getLastRun', return_value={})
    mocker.patch('Exabeam.get_fetch_run_time_range', return_value=("2022-12-22T13:53:05.195302", "2022-12-25T13:53:05.145561"))
    results, last_run = fetch_incidents(client, params)

    for i in range(len(results)):
        assert results[i]['Name'] == expected_incidents['first_fetch'][i]['name']
        assert results[i]['occurred'] == expected_incidents['first_fetch'][i]['baseFields']['createdAt']

    assert last_run['limit'] == expected_last_run['first_fetch']['limit']
    assert last_run['time'] == expected_last_run['first_fetch']['time']
    for id_ in expected_last_run['first_fetch']['found_incident_ids']:
        assert id_ in last_run['found_incident_ids']

    assert request_get_incidents.call_args_list[0][0][0] == EXPECTED_CALL_ARGS
    mocker.patch('Exabeam.demisto.getLastRun', return_value=last_run)
    results, last_run = fetch_incidents(client, params)

    for i in range(len(results)):
        assert results[i]['Name'] == expected_incidents['second_fetch'][i]['name']
        assert results[i]['occurred'] == expected_incidents['second_fetch'][i]['baseFields']['createdAt']

    assert last_run['limit'] == expected_last_run['second_fetch']['limit']
    assert last_run['time'] == expected_last_run['second_fetch']['time']
    for id_ in expected_last_run['second_fetch']['found_incident_ids']:
        assert id_ in last_run['found_incident_ids']

    mocker.patch('Exabeam.demisto.getLastRun', return_value=last_run)
    results, last_run = fetch_incidents(client, params)

    for i in range(len(results)):
        assert results[i]['Name'] == expected_incidents['third_fetch'][i]['name']
        assert results[i]['occurred'] == expected_incidents['third_fetch'][i]['baseFields']['createdAt']

    assert last_run['limit'] == expected_last_run['third_fetch']['limit']
    assert last_run['time'] == expected_last_run['third_fetch']['time']
    for id_ in expected_last_run['third_fetch']['found_incident_ids']:
        assert id_ in last_run['found_incident_ids']


@pytest.mark.parametrize(
    'args, expected_results',
    [
        (
            {
                'username': '__token',
                'password': None,
                'api_token': 'test',
                'is_fetch': False,
            },
            "When specifying username='__token', the API Token must be provieded using in the password field"
            " please empty the other field"
        ),
        (
            {
                'username': '__token',
                'password': 'test',
                'api_token': None,
                'is_fetch': True,
            },
            'In order to use the “Fetch Incident” functionality,'
            ' the username must be provided in the “Username” parameter.\n'
            ' Please see documentation `Authentication Methods`'
        ),
        (
            {
                'username': '__token',
                'password': None,
                'api_token': None,
                'is_fetch': False,
            },
            'Please insert API Token in the password field'
            ' or see documentation `Authentication Methods` for another authentication methods'
        ),
        (
            {
                'username': None,
                'password': None,
                'api_token': None,
                'is_fetch': False,
            },
            "If an API token is not provided, it is mandatory to insert username and password."
        ),
        (
            {
                'username': None,
                'password': None,
                'api_token': 'test',
                'is_fetch': True,
            },
            'In order to use the “Fetch Incident” functionality,'
            ' the username must be provided in the “Username” parameter.\n'
            ' Please see documentation `Authentication Methods`'
        ),
        (
            {
                'username': 'test',
                'password': None,
                'api_token': None,
                'is_fetch': True,
            },
            'Please insert password or API token.'
        ),
        (
            {
                'username': 'test',
                'password': 'test',
                'api_token': 'test',
                'is_fetch': True,
            },
            'Please insert API token OR password and not both.'
        ),
    ]
)
def test_validate_authentication_params(mocker, args, expected_results):

    mocker.patch.object(Client, 'is_token_auth', return_value=True)

    try:
        Client(base_url='test',
               username=args['username'],
               password=args['password'],
               verify=False,
               proxy=False,
               headers={},
               api_key=args['api_token'],
               is_fetch=args['is_fetch'])
    except ValueError as err:
        assert str(err.args[0]) == expected_results


@pytest.mark.parametrize(
    'params, expected_incidents, expected_last_run',
    [
        (
            {'max_fetch': 3, 'incident_type': 'generic,abnormalAuth', 'status': 'new', 'priority': 'medium', 'look_back': 4},
            EXPECTED_INCIDENTS_FOR_LOOK_BACK,
            EXPECTED_LAST_RUN_FOR_LOOK_BACK,
        )
    ]
)
@freeze_time(datetime(2022, 12, 22, 10, 0, 5, tzinfo=pytz.timezone('UTC')))
def test_fetch_incidents_with_look_back(mocker, params, expected_incidents, expected_last_run):
    """
        Given:
            - A last run with an incident.
        When:
            - executing fetch_incidents with look back.
        Then:
            - Ensure that the last run time is set correctly.
            - Check that the query with look-back is set correctly.
            - Ensure that incidents are correctly filtered.
    """
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    mocker.patch.object(Client, '_login', return_value=None)
    client = Client(base_url='https://example.com',
                    username='test_user',
                    password='1234',
                    verify=False,
                    proxy=False,
                    headers={})
    request_get_incidents = mocker.patch.object(client, 'get_incidents',
                                                return_value=INCIDENTS_FOR_LOOK_BACK_FIRST_TIME)
    mocker.patch('Exabeam.demisto.getLastRun', return_value={'found_incident_ids': {
                 "SOC-402": 1671703085},  # Unix Epoch Time
        'limit': 3, 'time': '2022-12-22T09:58:05.000000'})
    try:
        results, last_run = fetch_incidents(client, params)
    except Exception:
        pass

    for i in range(len(results)):
        assert results[i]['Name'] == expected_incidents['first_fetch'][i]['name']
        assert results[i]['occurred'] == expected_incidents['first_fetch'][i]['baseFields']['createdAt']

    assert last_run['limit'] == expected_last_run['first_fetch']['limit']
    assert last_run['time'] == expected_last_run['first_fetch']['time']
    for id_ in expected_last_run['first_fetch']['found_incident_ids']:
        assert id_ in last_run['found_incident_ids']

    assert request_get_incidents.call_args_list[0][0][0] == EXPECTED_CALL_ARGS_FOR_LOOK_BACK
    mocker.patch('Exabeam.demisto.getLastRun', return_value=last_run)
    request_get_incidents = mocker.patch.object(client, 'get_incidents', return_value=INCIDENTS_FOR_LOOK_BACK_SECOND_TIME)
    try:
        results, last_run = fetch_incidents(client, params)
    except Exception:
        pass

    assert last_run['limit'] == expected_last_run['second_fetch']['limit']
    assert last_run['time'] == expected_last_run['second_fetch']['time']
    for id_ in expected_last_run['second_fetch']['found_incident_ids']:
        assert id_ in last_run['found_incident_ids']


@pytest.mark.parametrize(
    "args, last_run_obj, expected_new_incidents_count",
    [
        (
            {
                "notable_users_fetch_interval": "60",
                "notable_users_first_fetch": "3 months",
                "max_fetch_users": "50",
                "minimum_risk_score_to_fetch_users": "90",
                "type_fetch": "Exabeam Notable User",
            },
            {
                "last_run_notable_users": "2024-06-18T13:08:58.489698",
                "usernames": ["old_username_risky"],
            },
            1,
        ),
        (
            {
                "notable_users_fetch_interval": "60",
                "notable_users_first_fetch": "3 months",
                "max_fetch_users": "50",
                "minimum_risk_score_to_fetch_users": "90",
                "type_fetch": "Exabeam Notable User",
            },
            {"last_run_notable_users": "2024-06-18T13:08:58.489698"},
            2,
        ),
    ],
    ids=["with_old_username_risky", "without_old_username_risky"],
)
def test_notable_users_fetch_incdents(mocker, args, last_run_obj, expected_new_incidents_count):
    mocker.patch.object(Client, '_login', return_value=None)
    client = Client(base_url='https://example.com', username='test_user', password='1234', verify=False, proxy=False, headers={})
    copy_res = copy.deepcopy(RES_USERS)  # for separation between the tests
    mocker.patch('Exabeam.get_notable_users', return_value=(None, None, copy_res))

    incidents, last_run = fetch_notable_users(client, args, last_run_obj)

    assert len(incidents) == expected_new_incidents_count
    assert incidents[0]['Name'] == 'new_username_risky'
    actual_last_run = last_run['last_run_notable_users'].split('.')[0]  # Remove microseconds for comparison
    assert actual_last_run == datetime.now(pytz.utc).strftime('%Y-%m-%dT%H:%M:%S')


@pytest.mark.parametrize(
    "params, expected_functions_called",
    [
        (
            {
                "fetch_type": ["Exabeam Notable User", "Exabeam Incident"],
            },
            {"fetch_notable_users": 1, "fetch_exabeam_incidents": 1},
        ),
        (
            {},
            {"fetch_notable_users": 0, "fetch_exabeam_incidents": 1},
        ),
    ],
    ids=["both_notable_users_and_incidents", "default_configuration"],
)
def test_fetch_incidents(mocker, params, expected_functions_called):
    mocker.patch.object(Client, '_login', return_value=None)
    client = Client(base_url='https://example.com', username='test_user', password='1234', verify=False, proxy=False, headers={})

    fetch_notable_users = mocker.patch('Exabeam.fetch_notable_users', return_value=([], {}))
    fetch_exabeam_incidents = mocker.patch('Exabeam.fetch_exabeam_incidents', return_value=([], {}))

    fetch_incidents(client, params)
    assert fetch_notable_users.call_count == expected_functions_called.get("fetch_notable_users")
    assert fetch_exabeam_incidents.call_count == expected_functions_called.get("fetch_exabeam_incidents")
