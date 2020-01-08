from Tanium_v2 import Client
import json

BASE_URL = 'https://test.com'

parse_question_res = {
    'data': [
        {
            'from_canonical_text': 0,
            'group': {
                'and_flag': True,
                'deleted_flag': True,
                'filters': [
                    {
                        'all_times_flag': False,
                        'all_values_flag': False,
                        'delimiter': '',
                        'delimiter_index': 0,
                        'ignore_case_flag': True,
                        'max_age_seconds': 0,
                        'not_flag': False,
                        'operator': 'RegexMatch',
                        'sensor': {
                            'hash': 3409330187,
                            'id': 3,
                            'name': 'Computer Name'
                        },
                        'substring_flag': False,
                        'substring_length': 0,
                        'substring_start': 0,
                        'utf8_flag': False,
                        'value': '.*equals.*',
                        'value_type': 'String'
                    }
                ],
                'not_flag': False,
                'sub_groups': []
            },
            'question_text': 'Get Computer Name from all machines with Computer Name contains \"equals\"',
            'selects': [
                {
                    'sensor': {
                        'hash': 3409330187,
                        'name': 'Computer Name'
                    }
                }
            ],
            'sensor_references': [
                {
                    'name': 'Computer Name',
                    'real_ms_avg': 0,
                    'start_char': '4'
                },
                {
                    'name': 'Computer Name',
                    'real_ms_avg': 0,
                    'start_char': '41'
                }
            ]
        }
    ]
}

CREATE_ACTION_BY_TARGET_GROUP_RES = {
    'package_spec': {'source_id': 12345},
    'name': 'action-name via Demisto API',
    'target_group': {'name': 'target-group-name'},
    'action_group': {'id': 1},
    'expire_seconds': 360}

CREATE_ACTION_BY_HOST_RES = {
    'package_spec':
        {'source_id': 20},
    'name': 'action-name via Demisto API',
    'target_group': {
        'and_flag': True,
        'deleted_flag': True,
        'filters': [
            {'all_times_flag': False,
             'all_values_flag': False,
             'delimiter': '',
             'delimiter_index': 0,
             'ignore_case_flag': True,
             'max_age_seconds': 0,
             'not_flag': False,
             'operator': 'RegexMatch',
             'sensor': {
                 'hash': 3409330187,
                 'id': 3,
                 'name': 'Computer Name'},
             'substring_flag': False,
             'substring_length': 0,
             'substring_start': 0,
             'utf8_flag': False,
             'value': '.*equals.*',
             'value_type': 'String'}],
        'not_flag': False,
        'sub_groups': []},
    'action_group': {
        'id': 1},
    'expire_seconds': 360}

CREATE_ACTION_WITH_PARAMETERS_RES = {
    'package_spec':
        {'source_id': 12345,
         'parameters': [{
             'key': '$1',
             'value': 'true'
         }, {
             'key': '$2',
             'value': 'value'
         }, {
             'key': '$3',
             'value': 'otherValue'}]},
    'name': 'action-name via Demisto API',
    'target_group': {
        'name': 'target-group-name'},
    'action_group': {
        'id': 1},
    'expire_seconds': 360}

QUESTION_RESULTS_RAW = {
    "data": {
        "result_sets": [
            {
                "age": 0,
                "archived_question_id": 0,
                "cache_id": "3891494157",
                "columns": [
                    {
                        "hash": 3409330187,
                        "name": "Computer Name",
                        "type": 1
                    },
                    {
                        "hash": 2801942354,
                        "name": "IPv4 Address",
                        "type": 5
                    },
                    {
                        "hash": 1092986182,
                        "name": "Logged In Users",
                        "type": 1
                    },
                    {
                        "hash": 0,
                        "name": "Count",
                        "type": 3
                    }
                ],
                "estimated_total": 2,
                "mr_tested": 2,
                "rows": [
                    {
                        "cid": 2232836718,
                        "data": [
                            [
                                {
                                    "text": "host-name"
                                }
                            ],
                            [
                                {
                                    "text": "127.0.0.1"
                                }
                            ],
                            [
                                {
                                    "text": "[no results]"
                                }
                            ],
                            [
                                {
                                    "text": "1"
                                }
                            ]
                        ],
                        "id": 699534294
                    }
                ]
            }
        ]
    }
}


QUESTION_RESULTS = [{"ComputerName": "host-name", "IPv4Address": "127.0.0.1", "Count": "1"}]


def test_create_action_body_by_target_group_name(requests_mock):
    client = Client(BASE_URL, 'username', 'password', 'domain')

    requests_mock.get(BASE_URL + 'session/login', json={'data': {'session': 'SESSION-ID'}})
    requests_mock.get(BASE_URL + 'packages/by-name/package-name', json={'data': {'id': 12345, 'expire_seconds': 360}})

    body = client.build_create_action_body(False, 'action-name', '', package_name='package-name',
                                           action_group_id=1, target_group_name='target-group-name')

    body = json.dumps(body)
    res = json.dumps(CREATE_ACTION_BY_TARGET_GROUP_RES)

    assert res == body


def test_create_action_body_by_host(requests_mock):
    client = Client(BASE_URL, 'username', 'password', 'domain')

    requests_mock.get(BASE_URL + 'session/login', json={'data': {'session': 'session-id'}})
    requests_mock.get(BASE_URL + 'packages/20', json={'data': {'id': 12345, 'expire_seconds': 360}})
    requests_mock.post(BASE_URL + 'parse_question', json=parse_question_res)

    body = client.build_create_action_body(True, 'action-name', '', package_id=20, action_group_id=1, hostname='host')

    body = json.dumps(body)
    res = json.dumps(CREATE_ACTION_BY_HOST_RES)

    assert res == body


def test_create_action_body_with_parameters(requests_mock):
    client = Client(BASE_URL, 'username', 'password', 'domain')

    requests_mock.get(BASE_URL + 'session/login', json={'data': {'session': 'session-id'}})
    requests_mock.get(BASE_URL + 'packages/by-name/package-name', json={'data': {'id': 12345, 'expire_seconds': 360}})

    body = client.build_create_action_body(False, 'action-name', '$1=true;$2=value;$3=otherValue',
                                           package_name='package-name', action_group_id=1,
                                           target_group_name='target-group-name')

    body = json.dumps(body)
    res = json.dumps(CREATE_ACTION_WITH_PARAMETERS_RES)

    assert res == body


def test_parse_question_results():
    client = Client(BASE_URL, 'username', 'password', 'domain')
    results = client.parse_question_results(QUESTION_RESULTS_RAW)
    assert results == QUESTION_RESULTS
