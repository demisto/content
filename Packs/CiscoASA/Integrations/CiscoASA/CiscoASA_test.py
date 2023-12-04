
import io
import json
import pytest

from http import HTTPStatus

from CommonServerPython import CommandResults
from CiscoASA import (
    Client,
    list_network_object_group_command,
    list_local_user_group_command,
    list_local_user_command,
    list_time_range_command,
    list_security_object_group_command,
    list_user_object_command,
    write_memory_command,
    create_rule_command,
    edit_rule_command
)


MOCK_RULES_GLOBAL = {
    "kind": "collection#ExtendedACE",
    "selfLink": "https://example.com/api/access/global/rules",
    "rangeInfo": {
        "offset": 0,
        "limit": 1,
        "total": 1
    },
    "items": [
        {
            "kind": "object#ExtendedACE",
            "selfLink": "https://example.com/api/access/global/rules/1090940913",
            "permit": True,
            "sourceAddress": {
                "kind": "IPv4Address", "value": "8.8.8.8"},
            "destinationAddress": {"kind": "AnyIPAddress", "value": "any"},
            "sourceService": {
                "kind": "NetworkProtocol",
                "value": "ip"
            },
            "destinationService": {
                "kind": "NetworkProtocol",
                "value": "ip"
            },
            "active": True,
            "remarks": [],
            "ruleLogging": {
                "logInterval": 300,
                "logStatus": "Default"
            },
            "position": 1,
            "isAccessRule": True,
            "objectId": "1090940913"
        },
        {
            "kind": "object#ExtendedACE",
            "selfLink": "https://example.com/api/access/global/rules/123456789",
            "permit": True,
            "sourceAddress": {
                "kind": "IPv4Address",
                "value": "1.1.1.1"
            },
            "destinationAddress": {
                "kind": "AnyIPAddress",
                "value": "any"
            },
            "sourceService": {
                "kind": "NetworkProtocol",
                "value": "ip"
            },
            "destinationService": {
                "kind": "NetworkProtocol",
                "value": "ip"
            },
            "active": True,
            "remarks": [],
            "ruleLogging": {
                "logInterval": 300,
                "logStatus": "Default"
            },
            "position": 1,
            "isAccessRule": True,
            "objectId": "123456789"
        }
    ]
}

RULES = [
    {'Source': '8.8.8.8', 'Dest': 'any', 'IsActive': True, 'Interface': None, 'InterfaceType': None,
     'Remarks': [], 'Position': 1, 'ID': '1090940913', 'Permit': True, 'SourceService': 'ip', 'DestService': 'ip',
     'SourceKind': 'IPv4Address', 'DestKind': 'AnyIPAddress'},
    {'Source': '1.1.1.1', 'Dest': 'any', 'IsActive': True, 'Interface': None, 'InterfaceType': None,
     'Remarks': [], 'Position': 1, 'ID': '123456789', 'Permit': True, 'SourceService': 'ip', 'DestService': 'ip',
     'SourceKind': 'IPv4Address', 'DestKind': 'AnyIPAddress'}]


def test_get_all_rules(requests_mock):

    from CiscoASA import list_rules_command

    requests_mock.get("https://example.com/api/access/global/rules", json=MOCK_RULES_GLOBAL, status_code=200)

    client = Client("https://example.com", auth=("username", "password"), verify=False, proxy=False)

    args = {"interface_type": "Global"}

    command_results = list_rules_command(client, args)

    # Assert that the rules  are exported as expected (in the outputs)
    assert command_results.outputs[0].get("ID") == '1090940913'
    assert command_results.outputs[1].get("ID") == '123456789'

    empty_mock = {
        "selfLink": "https://example.com/api/access/out",
        "rangeInfo": {
            "offset": 0,
            "limit": 0,
            "total": 0
        },
        "items": []
    }
    requests_mock.get("https://example.com/api/access/global/rules", json=empty_mock, status_code=200)

    command_results = list_rules_command(client, args)

    # Assert outputs is empty when there's no rule
    assert [] == command_results.outputs


def test_rule_by_id(requests_mock):
    from CiscoASA import rule_by_id_command

    requests_mock.get("https://example.com/api/access/global/rules/123456789", json=MOCK_RULES_GLOBAL.get('items')[1],
                      status_code=200)

    client = Client("https://example.com", auth=("username", "password"), verify=False, proxy=False)

    args = {"interface_type": "Global",
            "interface_name": 'name',
            'rule_id': '123456789'
            }

    command_results = rule_by_id_command(client, args)

    # Assert that the rule is exported as expected (in the outputs)
    assert command_results.outputs[0].get("ID") == '123456789'


def test_create_rule(requests_mock):
    from CiscoASA import create_rule_command

    args = {
        'source': "any",
        'destination': "1.1.1.1",
        'permit': "True",
        'interface_type': "In",
        'remarks': "This,is,remark",
        'position': 2,
        'logging_level': "Default",
        'active': 'True'
    }

    requests_mock.post("https://example.com/api/access/global/rules", json=MOCK_RULES_GLOBAL.get('items')[1],
                       status_code=201)

    client = Client("https://example.com", auth=("username", "password"), verify=False, proxy=False)

    # Try to create a rule in In without an interface name

    with pytest.raises(ValueError):
        create_rule_command(client, args)


def test_raw_to_rules():
    from CiscoASA import raw_to_rules
    rules = raw_to_rules(MOCK_RULES_GLOBAL.get("items"))
    assert rules == RULES


BASE_URL = 'https://example.com'


@pytest.fixture()
def mock_client(requests_mock) -> Client:
    """
    Establish a mock connection to the client with a username and password.

    Returns:
        Client: Mock connection to client.
    """
    requests_mock.post(
        url=f'{BASE_URL}/api/tokenservices',
        headers={
            'X-Auth-Token': 'helloworld',
        }
    )

    return Client(
        base_url=BASE_URL,
        auth=('hello', 'world'),
    )


def load_mock_response(file_name: str) -> str | io.TextIOWrapper:
    """
    Load mock file that simulates an API response.
    Args:
        file_name (str): Name of the mock response JSON/TEXT file to return.
    Returns:
        str: Mock file content.
    """
    with open(f'test_data/{file_name}') as mock_file:
        return json.loads(mock_file.read())


@pytest.mark.parametrize(
    'list_command, file_path, outputs_prefix, endpoint_suffix, expected_outputs',
    [
        (
            list_network_object_group_command,
            'list_network_object_group.json',
            'CiscoASA.NetworkObjectGroup',
            'networkobjectgroups',
            [
                {
                    'name': 'TEST_GROUP',
                    'members': [
                        {
                            'kind': 'objectRef#NetworkObj',
                            'object_id': 'Test_Lior'
                        },
                        {
                            'kind': 'objectRef#NetworkObj',
                            'object_id': 'Test_Lior1'
                        },
                        {
                            'kind': 'objectRef#NetworkObj',
                            'object_id': 'Test_Lior2'
                        }
                    ],
                    'description': 'This is a test',
                    'object_id': 'TEST_GROUP'
                }
            ],
        ),
        (
            list_local_user_group_command,
            'list_local_user_group.json',
            'CiscoASA.LocalUserGroup',
            'localusergroups',
            [
                {
                    'name': 'TEST_GROUP',
                    'members': [
                        {
                            'kind': 'objectRef#UserObj',
                            'object_id': 'Pikachu_I_Choose_You!'
                        },
                        {
                            'kind': 'objectRef#UserObj',
                            'object_id': 'Use_thunderbolt!'
                        },
                    ],
                    'object_id': 'TEST_GROUP'
                }
            ],
        ),
        (
            list_local_user_command,
            'list_local_user.json',
            'CiscoASA.LocalUser',
            'localusers',
            [
                {
                    'name': 'I',
                    'mschap_authenticated': False,
                    'privilege_level': 15,
                    'asdm_cli_access_type': 'Full',
                    'object_id': 'I'
                },
                {
                    'name': 'Choose',
                    'mschap_authenticated': False,
                    'privilege_level': 15,
                    'asdm_cli_access_type': 'Full',
                    'object_id': 'Choose'
                },
                {
                    'name': 'You',
                    'privilege_level': 15,
                    'mschap_authenticated': False,
                    'asdm_cli_access_type': 'Full',
                    'object_id': 'You'
                }
            ],
        ),
        (
            list_time_range_command,
            'list_time_range.json',
            'CiscoASA.TimeRange',
            'timeranges',
            [
                {
                    'name': 'trUserTest',
                    'object_id': 'trUserTest',
                    'start': 'now',
                    'end': '03:47 May 14 2014',
                    'periodic': [
                        {
                            'frequency': 'Wednesday to Thursday',
                            'start_hour': 4,
                            'start_minute': 3,
                            'end_hour': 23,
                            'end_minute': 59
                        }
                    ]
                },
                {
                    'name': 'tr_periodic_test',
                    'object_id': 'tr_periodic_test',
                    'start': 'now',
                    'end': 'never',
                    'periodic': [
                        {
                            'frequency': 'weekend',
                            'start_hour': 3,
                            'start_minute': 3,
                            'end_hour': 4,
                            'end_minute': 1
                        },
                        {
                            'frequency': 'daily',
                            'start_hour': 4,
                            'start_minute': 0,
                            'end_hour': 5,
                            'end_minute': 1
                        },
                        {
                            'frequency': 'Tuesday Thursday Saturday ',
                            'start_hour': 0,
                            'start_minute': 0,
                            'end_hour': 1,
                            'end_minute': 1
                        },
                        {
                            'frequency': 'weekdays',
                            'start_hour': 12,
                            'start_minute': 0,
                            'end_hour': 13,
                            'end_minute': 1
                        }
                    ]
                }
            ],
        ),
        (
            list_security_object_group_command,
            'list_security_object_group.json',
            'CiscoASA.SecurityObjectGroup',
            'securityobjectgroups',
            [
                {
                    'name': 'oneSecurityGroup',
                    'description': 'test12',
                    'members': [
                        {
                            'kind': 'SecurityName',
                            'value': 'beep'
                        },
                        {
                            'kind': 'SecurityTag',
                            'value': 'bap'
                        }
                    ],
                    'object_id': 'oneSecurityGroup'
                },
                {
                    'name': 'secondSecurityGroup',
                    'description': 'test21',
                    'members': [
                        {
                            'kind': 'objectRef#SecurityObjGroup',
                            'object_id': 'oneSecurityGroup'
                        },
                        {
                            'kind': 'SecurityTag',
                            'value': '52'
                        }
                    ],
                    'object_id': 'secondSecurityGroup'
                }
            ],
        ),
        (
            list_user_object_command,
            'list_user_object.json',
            'CiscoASA.UserObject',
            'userobjects',
            [
                {
                    "object_id": "Squirtle",
                    "user_name": "Squirtle",
                    "local_user_object_id": "Squirtle",
                },
                {
                    "object_id": "Blastoise",
                    "user_name": "Blastoise",
                    "local_user_object_id": "Blastoise",
                }
            ],
        ),
    ]
)
def test_list_command(
    requests_mock,
    mock_client,
    list_command,
    file_path,
    outputs_prefix,
    endpoint_suffix,
    expected_outputs,
):
    """
    Scenario:
    - Test retrieving a list of objects.

    Given:
    - Nothing

    When:
    - list_network_object_group_command,
    - list_local_user_group_command,
    - list_local_user_command,
    - list_time_range_command,
    - list_security_object_group_command,
    - list_user_object_command

    Then:
    - Ensure that the CommandResults outputs is correct.
    - Ensure that the CommandResults raw_response is correct.
    - Ensure that the CommandResults outputs_key_field is correct.
    - Ensure that the CommandResults outputs_prefix is correct.
    """
    args = {'limit': 50}
    response = load_mock_response(file_path)

    requests_mock.get(
        url=f'{BASE_URL}/api/objects/{endpoint_suffix}',
        json=response
    )

    command_results: CommandResults = list_command(mock_client, args)

    assert command_results.outputs == expected_outputs
    assert json.dumps(command_results.raw_response, sort_keys=True) == json.dumps([response], sort_keys=True)
    assert command_results.outputs_key_field == 'object_id'
    assert command_results.outputs_prefix == outputs_prefix


@pytest.mark.parametrize(
    'get_command, file_path, outputs_prefix, endpoint_suffix, args, expected_outputs',
    [
        (
            list_network_object_group_command,
            'get_network_object_group.json',
            'CiscoASA.NetworkObjectGroup',
            'networkobjectgroups',
            {'object_id': 'TEST_GROUP'},
            {
                'name': 'TEST_GROUP',
                'members': [
                    {
                        'kind': 'objectRef#NetworkObj',
                        'object_id': 'Test_Lior'
                    },
                    {
                        'kind': 'objectRef#NetworkObj',
                        'object_id': 'Test_Lior1'
                    },
                    {
                        'kind': 'objectRef#NetworkObj',
                        'object_id': 'Test_Lior2'
                    }
                ],
                'description': 'This is a test',
                'object_id': 'TEST_GROUP'
            },
        ),
        (
            list_local_user_group_command,
            'get_local_user_group.json',
            'CiscoASA.LocalUserGroup',
            'localusergroups',
            {'object_id': 'TEST_GROUP'},
            {
                'name': 'TEST_GROUP',
                'members': [
                    {
                        'kind': 'objectRef#UserObj',
                        'object_id': 'Pikachu_I_Choose_You!'
                    },
                    {
                        'kind': 'objectRef#UserObj',
                        'object_id': 'Use_thunderbolt!'
                    },
                ],
                'object_id': 'TEST_GROUP'
            },
        ),
        (
            list_local_user_command,
            'get_local_user.json',
            'CiscoASA.LocalUser',
            'localusers',
            {'object_id': 'Lucario'},
            {
                'name': 'Lucario',
                'mschap_authenticated': False,
                'privilege_level': 15,
                'asdm_cli_access_type': 'Full',
                'object_id': 'Lucario'
            },
        ),
        (
            list_time_range_command,
            'get_time_range.json',
            'CiscoASA.TimeRange',
            'timeranges',
            {'object_id': 'tr_periodic_test'},
            {
                'name': 'tr_periodic_test',
                'object_id': 'tr_periodic_test',
                'start': 'now',
                'end': 'never',
                'periodic': [
                    {
                        'frequency': 'weekend',
                        'start_hour': 3,
                        'start_minute': 3,
                        'end_hour': 4,
                        'end_minute': 1
                    },
                    {
                        'frequency': 'daily',
                        'start_hour': 4,
                        'start_minute': 0,
                        'end_hour': 5,
                        'end_minute': 1
                    },
                    {
                        'frequency': 'Tuesday Thursday Saturday ',
                        'start_hour': 0,
                        'start_minute': 0,
                        'end_hour': 1,
                        'end_minute': 1
                    },
                    {
                        'frequency': 'weekdays',
                        'start_hour': 12,
                        'start_minute': 0,
                        'end_hour': 13,
                        'end_minute': 1
                    }
                ]
            },
        ),
        (
            list_security_object_group_command,
            'get_security_object_group.json',
            'CiscoASA.SecurityObjectGroup',
            'securityobjectgroups',
            {'object_id': 'oneSecurityGroup'},
            {
                'name': 'oneSecurityGroup',
                'description': 'test12',
                'members': [
                    {
                        'kind': 'SecurityName',
                        'value': 'beep'
                    },
                    {
                        'kind': 'SecurityTag',
                        'value': '71'
                    }
                ],
                'object_id': 'oneSecurityGroup'
            },
        ),
        (
            list_user_object_command,
            'get_user_object.json',
            'CiscoASA.UserObject',
            'userobjects',
            {'object_id': 'Chikorita'},
            {
                'object_id': 'Chikorita',
                'user_name': 'Chikorita',
                'local_user_object_id': 'Chikorita',
            },
        ),
    ]
)
def test_get_command(
    requests_mock,
    mock_client,
    get_command,
    file_path,
    outputs_prefix,
    endpoint_suffix,
    args,
    expected_outputs,
):
    """
    Scenario:
    - Test retrieving a single object.

    Given:
    - An object ID

    When:
    - list_network_object_group_command,
    - list_local_user_group_command,
    - list_local_user_command,
    - list_time_range_command,
    - list_security_object_group_command,
    - list_user_object_command

    Then:
    - Ensure that the CommandResults outputs is correct.
    - Ensure that the CommandResults raw_response is correct.
    - Ensure that the CommandResults outputs_key_field is correct.
    - Ensure that the CommandResults outputs_prefix is correct.
    """
    args['limit'] = 50

    response = load_mock_response(file_path)

    requests_mock.get(
        url=f'{BASE_URL}/api/objects/{endpoint_suffix}/{args["object_id"]}',
        json=response
    )

    command_results: CommandResults = get_command(mock_client, args)

    assert command_results.outputs == expected_outputs
    assert json.dumps(command_results.raw_response, sort_keys=True) == json.dumps(response, sort_keys=True)
    assert command_results.outputs_key_field == 'object_id'
    assert command_results.outputs_prefix == outputs_prefix


def test_write_memory_command(requests_mock, mock_client):
    """
    Scenario:
    - Test saving a configuration.

    Given:
    - Nothing

    When:
    - write_memory_command

    Then:
    - Ensure that the CommandResults outputs is correct.
    - Ensure that the CommandResults raw_response is correct.
    - Ensure that the CommandResults outputs_prefix is correct.
    """
    expected_outputs = {
        "response": [
            "Bulko"
        ]
    }
    mock_client._headers = {}
    response = load_mock_response('write_memory.json')

    requests_mock.post(
        url=f'{BASE_URL}/api/commands/writemem',
        json=response
    )

    command_results: CommandResults = write_memory_command(mock_client)

    assert command_results.outputs == expected_outputs
    assert json.dumps(command_results.raw_response, sort_keys=True) == json.dumps(response, sort_keys=True)
    assert command_results.outputs_prefix == 'CiscoASA.WriteMemory'


@pytest.mark.parametrize(
    'rule_id, rule_command, is_create',
    [
        ({'active': True}, create_rule_command, True),
        ({'rule_id': '1090940913', 'active': True}, edit_rule_command, False),
    ]
)
def test_rule_command(rule_id, rule_command, is_create, requests_mock, mock_client):
    """
    Scenario:
    - Test the create rule command.

    Given:
    - All the arguments needed to create a rule are filled.

    When:
    - create_rule_command

    Then:
    - Ensure that the CommandResults outputs is correct.
    - Ensure that the CommandResults raw_response is correct.
    """
    args = {
        'interface_type': 'Global',
        'permit': 'False',
        'source': '8.8.8.8',
        'source_kind': 'IPv4Address',
        'destination': 'any',
        'destination_kind': 'IPv4Address',
        'service': 'ip',
        'service_kind': 'NetworkProtocol',
        'destination_service': 'ip',
        'destination_service_kind': 'NetworkProtocol',
        'time_range': 'TEST_TIME',
        'user': 'Hello',
        'user_kind': 'UserObj',
        'source_security': 'Hello',
        'source_security_kind': 'SecurityObjGroup',
        'destination_security': 'Hello',
        'destination_security_kind': 'SecurityName',
    } | rule_id

    mock_rule_id = '1090940913'
    rule_by_id_endpoint = f'{BASE_URL}/api/access/global/rules/{mock_rule_id}'
    headers = {'Location': rule_by_id_endpoint}

    requests_mock.get(
        url=rule_by_id_endpoint,
        json=MOCK_RULES_GLOBAL['items'][0],
    )

    if is_create:
        requests_mock.post(
            url=f'{BASE_URL}/api/access/global/rules',
            headers=headers,
            status_code=HTTPStatus.CREATED,
        )
        command_results: CommandResults = create_rule_command(mock_client, args)

    else:
        requests_mock.patch(
            url=rule_by_id_endpoint,
            headers=headers,
            status_code=HTTPStatus.CREATED,
        )
        command_results: CommandResults = edit_rule_command(mock_client, args)

    expected_outputs = [
        {
            'Source': '8.8.8.8',
            'SourceService': 'ip',
            'Dest': 'any',
            'DestService': 'ip',
            'IsActive': True,
            'Interface': '',
            'InterfaceType': 'Global',
            'Remarks': [],
            'Position': 1,
            'ID': '1090940913',
            'Permit': True,
            'SourceKind': 'IPv4Address',
            'DestKind': 'AnyIPAddress',
        }
    ]

    expected_raw_response = {
        'kind': 'object#ExtendedACE',
        'selfLink': 'https://example.com/api/access/global/rules/1090940913',
        'permit': True,
        'sourceAddress': {'kind': 'IPv4Address', 'value': '8.8.8.8'},
        'destinationAddress': {'kind': 'AnyIPAddress', 'value': 'any'},
        'sourceService': {'kind': 'NetworkProtocol', 'value': 'ip'},
        'destinationService': {'kind': 'NetworkProtocol', 'value': 'ip'},
        'active': True,
        'remarks': [],
        'ruleLogging': {'logInterval': 300, 'logStatus': 'Default'},
        'position': 1,
        'isAccessRule': True,
        'objectId': '1090940913',
        'interface': '',
        'interface_type': 'Global',
    }

    assert command_results.outputs == expected_outputs
    assert command_results.raw_response == expected_raw_response
