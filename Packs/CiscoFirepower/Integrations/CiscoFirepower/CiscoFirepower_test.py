"""
Unit testing for Cisco Firepower Management Center.
"""
import json
import io
import os
from typing import Any, Union
from http import HTTPStatus
from unittest import mock
import pytest
from CommonServerPython import CommandResults
from CiscoFirepower import Client, switch_list_to_list_counter, raw_response_to_context_list, \
    raw_response_to_context_rules, raw_response_to_context_network_groups, raw_response_to_context_policy_assignment, \
    raw_response_to_context_access_policy, INTEGRATION_CONTEXT_NAME, INTRUSION_POLICY_CONTEXT, INTRUSION_RULE_CONTEXT, \
    INTRUSION_RULE_GROUP_CONTEXT, NETWORK_ANALYSIS_POLICY_CONTEXT, INTRUSION_RULE_UPLOAD_CONTEXT, \
    INTRUSION_RULE_UPLOAD_TITLE


USERNAME = 'USERNAME'
PASSWORD = 'PASSWORD'
BASE_URL = 'https://firepower'
SUFFIX = 'api/fmc_config/v1/domain/DOMAIN_UUID'
FILE_ENTRY = {
    'name': 'intrusion_rule_upload.txt',
    'path': 'test_data/intrusion_rule_upload.txt'
}
FILE_ENTRY_ERROR = {
    'name': 'intrusion_rule_upload.json',
    'path': 'test_data/intrusion_rule_upload.json'
}

INPUT_TEST_SWITCH_LIST_TO_LIST_COUNTER = [
    ({'name': 'n', 'type': 't', 'devices': [1, 2, 3]}, {'name': 'n', 'type': 't', 'devices': 3}),
    ({'name': 'n', 'type': 't', 'devices': {'new': [1, 2], 'old': [1, 2]}}, {'name': 'n', 'type': 't', 'devices': 4}),
    ({'name': 'n', 'type': 't', 'devices': {'new': 1, 'old': [1, 2]}}, {'name': 'n', 'type': 't', 'devices': 3}),
    ({'name': 'n', 'type': 't', 'devices': {'new': 'my new'}}, {'name': 'n', 'type': 't', 'devices': 1})
]

INPUT_TEST_RAW_RESPONSE_TO_CONTEXT_LIST = [
    (
        {"id": "123", "metadata": {"domain": {"id": "456"}}, "name": "home", "type": "URLCategory"},
        ['id', 'name'],
        {"ID": "123", "Name": "home"},
    ),
    (
        {
            "id": "121212",
            "links": {
                "self": "link"
            },
            "metadata": {
                "domain": {
                    "id": "123456",
                    "name": "Global",
                    "type": "Domain"
                },
                "lastUser": {
                    "id": "141414",
                    "name": "admin",
                    "type": "user"
                },
                "readOnly": {
                    "state": 'false'
                },
                "timestamp": '1575996253'
            },
            "name": "Child Abuse Content",
            "type": "URLCategory"
        },
        ['id', 'name'],
        {"ID": "121212",
         "Name": "Child Abuse Content"},
    ),
]

INPUT_TEST_RAW_RESPONSE_TO_CONTEXT_NETWORK_GROUPS = [
    (
        {
            "description": " ",
            "id": "131313",
            "links": {"self": "link"},
            "literals": [{"type": "Network", "value": "ip"}, {"type": "Host", "value": "::/0"}],
            "metadata": {
                "domain": {
                    "id": "123456",
                    "name": "Global",
                    "type": "Domain"
                },
                "lastUser": {
                    "name": "admin"
                },
                "readOnly": {
                    "reason": "SYSTEM",
                    "state": 'true'
                },
                "timestamp": '1521658703283'
            },
            "name": "any",
            "overridable": 'false',
            "type": "NetworkGroup"
        },
        {
            "Name": "any",
            "ID": "131313",
            "Overridable": 'false',
            "Description": " ",
            "Objects": [],
            "Addresses": [
                {
                    "Value": "ip",
                    "Type": "Network"
                },
                {
                    "Value": "::/0",
                    "Type": "Host"
                }
            ]
        }
    )
]

INPUT_TEST_RAW_RESPONSE_TO_CONTEXT_POLICY_ASSIGNMENT = [
    (
        {
            "id": "151515",
            "links": {"self": "link"},
            "name": "BPS-Testing",
            "policy": {
                "id": "151515",
                "name": "BPS-Testing",
                "type": "AccessPolicy"
            },
            "targets": [
                {
                    "id": "161616",
                    "keepLocalEvents": 'false',
                    "name": "FTD_10.8.49.209",
                    "type": "Device"
                }
            ],
            "type": "PolicyAssignment"
        },
        {
            "ID": "151515",
            "Name": "BPS-Testing",
            "PolicyID": "151515",
            "PolicyName": "BPS-Testing",
            "PolicyDescription": "",
            "Targets": [
                {
                    "ID": "161616",
                    "Name": "FTD_10.8.49.209",
                    "Type": "Device"
                }
            ]
        },

    )
]

INPUT_TEST_RAW_RESPONSE_TO_CONTEXT_ACCESS_POLICY = [
    (
        {
            "defaultAction": {
                "action": "BLOCK",
                "id": "171717",
                "logBegin": 'false',
                "logEnd": 'false',
                "sendEventsToFMC": 'false',
                "type": "AccessPolicyDefaultAction"
            },
            "id": "151515",
            "links": {
                "self": "linkn/123456/policy"
            },
            "metadata": {
                "domain": {
                    "id": "123456",
                    "name": "Global",
                    "type": "Domain"
                },
                "inherit": 'false'
            },
            "name": "BPS-Testing",
            "prefilterPolicySetting": {
                "id": "181818",
                "name": "Default Prefilter Policy",
                "type": "PrefilterPolicy"
            },
            "rules": {
                "links": {
                    "self": "linkn/123456/policy"
                },
                "refType": "list",
                "type": "AccessRule"
            },
            "type": "AccessPolicy"
        },
        {
            "DefaultActionID": "171717",
            "ID": "151515",
            "Name": "BPS-Testing"
        }
    )
]

INPUT_TEST_RAW_RESPONSE_TO_CONTEXT_RULS = [
    (
        {
            "action": "BLOCK",
            "destinationNetworks": {
                "literals": [
                    {
                        "type": "Host",
                        "value": "ip"
                    },
                    {
                        "type": "Host",
                        "value": "ip"
                    }
                ]
            },
            "enableSyslog": 'false',
            "enabled": 'false',
            "id": "202020",
            "links": {
                "self": "linkn/123456/policy"
            },
            "logBegin": 'false',
            "logEnd": 'false',
            "logFiles": 'false',
            "metadata": {
                "accessPolicy": {
                    "id": "212121",
                    "name": "Performance Test Policy without AMP",
                    "type": "AccessPolicy"
                },
                "category": "--Undefined--",
                "domain": {
                    "id": "123456",
                    "name": "Global",
                    "type": "Domain"
                },
                "ruleIndex": '5',
                "section": "Default",
                "timestamp": '1582462113800'
            },
            "name": "newUpdateTest",
            "sendEventsToFMC": 'false',
            "sourceNetworks": {
                "literals": [
                    {
                        "type": "Host",
                        "value": "ip1"
                    },
                    {
                        "type": "Host",
                        "value": "ip"
                    }
                ]
            },
            "type": "AccessRule",
            "urls": {
                "literals": [
                    {
                        "type": "Url",
                        "url": "url"
                    },
                    {
                        "type": "Url",
                        "url": "url"
                    }
                ]
            },
            "variableSet": {
                "id": "101010",
                "name": "Default-Set",
                "type": "VariableSet"
            },
            "vlanTags": {}
        },
        {
            'Action': 'BLOCK',
            'Applications': [],
            'Category': '--Undefined--',
            'DestinationNetworks': {'Addresses': [{'Type': 'Host', 'Value': 'ip'},
                                                  {'Type': 'Host', 'Value': 'ip'}], 'Objects': []},
            'DestinationPorts': {'Addresses': [], 'Objects': []},
            'DestinationZones': {'Objects': []},
            'Enabled': 'false',
            'ID': '202020',
            'Name': 'newUpdateTest',
            'RuleIndex': '5',
            'Section': 'Default',
            'SendEventsToFMC': 'false',
            'SourceNetworks': {
                'Addresses': [{'Type': 'Host', 'Value': 'ip1'}, {'Type': 'Host', 'Value': 'ip'}],
                'Objects': []},
            'SourcePorts': {'Addresses': [], 'Objects': []},
            'SourceSecurityGroupTags': {'Objects': []},
            'SourceZones': {'Objects': []},
            'Urls': {'Addresses': [{'URL': 'url'}, {'URL': 'url'}], 'Objects': []},
            'VlanTags': {'Numbers': [], 'Objects': []}
        }
    )
]


""" TESTS FUNCTION """


@pytest.mark.parametrize('list_input, list_output', INPUT_TEST_SWITCH_LIST_TO_LIST_COUNTER)
def test_switch_list_to_list_counter(list_input, list_output):
    result = switch_list_to_list_counter(list_input)
    assert list_output == result


@pytest.mark.parametrize('list_input, list_to_output, list_output', INPUT_TEST_RAW_RESPONSE_TO_CONTEXT_LIST)
def test_raw_response_to_context_list(list_to_output, list_input, list_output):
    result = raw_response_to_context_list(list_to_output, list_input)
    assert list_output == result


@pytest.mark.parametrize('list_input, list_output', INPUT_TEST_RAW_RESPONSE_TO_CONTEXT_NETWORK_GROUPS)
def test_raw_response_to_context_network_groups(list_input, list_output):
    result = raw_response_to_context_network_groups(list_input)
    assert list_output == result


@pytest.mark.parametrize('list_input, list_output', INPUT_TEST_RAW_RESPONSE_TO_CONTEXT_POLICY_ASSIGNMENT)
def test_raw_response_to_context_policy_assignment(list_input, list_output):
    result = raw_response_to_context_policy_assignment(list_input)
    assert list_output == result


@pytest.mark.parametrize('list_input, list_output', INPUT_TEST_RAW_RESPONSE_TO_CONTEXT_ACCESS_POLICY)
def test_raw_response_to_context_access_policy(list_input, list_output):
    result = raw_response_to_context_access_policy(list_input)
    assert list_output == result


@pytest.mark.parametrize('list_input, list_output', INPUT_TEST_RAW_RESPONSE_TO_CONTEXT_RULS)
def test_raw_response_to_context_ruls(list_input, list_output):
    result = raw_response_to_context_rules(list_input)
    assert list_output == result


''' Helper Functions '''  # pylint: disable=pointless-string-statement


def assert_output_has_no_links(outputs: Union[list[dict[str, Any]], dict[str, Any]]):
    """
    Check that there are no 'links' keys in the outputs.
    Args:
        outputs (list[dict[str, Any]] | dict[str, Any]): output to loop through.
    """
    if isinstance(outputs, dict):
        outputs = [outputs]

    for output in outputs:
        assert 'links' not in output


def assert_command_results(command_results: CommandResults, method: str, expected_output_prefix: str = ''):
    """
    Test that the command results outputs has no links in it, if it exists.
    Test the output prefix.
    Test readable output.

    Args:
        command_results (CommandResults): CommandResults created by the tested command.
        method (str): Key to the expected message within the CommandResults readable output.
        expected_output_prefix (str): Expected output prefix to be within the CommandsResults.
            Defaults to ''.
    """
    message_by_method = {
        'POST': 'Created',
        'GET': 'Fetched',
        'PUT': 'Updated',
        'DELETE': 'Deleted',
    }

    assert command_results.readable_output
    assert message_by_method[method] in command_results.readable_output

    if method != 'DELETE':
        context_prefix = '.'.join((INTEGRATION_CONTEXT_NAME, expected_output_prefix))

        assert command_results.outputs_prefix == context_prefix
        assert_output_has_no_links(command_results.outputs)  # type: ignore[arg-type] # outputs is Optional[object]


def load_mock_response(file_name: str) -> str | io.TextIOWrapper:
    """
    Load mock file that simulates an API response.
    Args:
        file_name (str): Name of the mock response JSON/TEXT file to return.
    Returns:
        str: Mock file content.
    """
    path = os.path.join('test_data', file_name)

    with io.open(path, mode='r', encoding='utf-8') as mock_file:
        if os.path.splitext(file_name)[1] == '.json':
            return json.loads(mock_file.read())

        return mock_file


@pytest.fixture()
def mock_client(requests_mock) -> Client:
    """
    Establish a connection to the client with a username and password.

    Returns:
        Client: Connection to client.
    """
    requests_mock.post(
        f'{BASE_URL}/api/fmc_platform/v1/auth/generatetoken',
        headers={
            'X-auth-access-token': 'X-auth-access-token',
            'DOMAIN_UUID': 'DOMAIN_UUID'
        }
    )

    return Client(
        base_url=BASE_URL,
        username=USERNAME,
        password=PASSWORD,
    )


def test_generate_token_error():
    """
    Scenario:
    -   Test the handling of an error while generating a token during client initialization.
    Given:
    -   A mock response object with a pre-set side effect for the raise_for_status method
    When:
    -   The Client class is initialized
    Then:
    -   Ensure that the correct exception is raised when the _http_request method is called
    """
    mock_response = mock.Mock()
    mock_response.headers = {
        'X-auth-access-token': '123456',
        'DOMAIN_UUID': 'abcdef',
    }
    mock_response.raise_for_status.side_effect = Exception('HTTP request failed')

    @mock.patch.object(Client, '_http_request', return_value=mock_response)
    def test(mock_request):
        client = Client(
            base_url=BASE_URL,
            username='test',
            password='test',
        )

        try:
            client._http_request(
                method='POST',
                url_suffix='api/test',
                resp_type='response'
            )
        except Exception as e:
            assert str(e) == 'HTTP request failed'

    test()


''' Intrusion Policy CRUD '''  # pylint: disable=pointless-string-statement


def test_create_intrusion_policy_command(requests_mock, mock_client):
    """
    Scenario:
    -   Create an intrusion policy.
    Given:
    -   name, basepolicy_id, description
    When:
    -    ciscofp-create-intrusion-policy is called.
    Then:
    -   Ensure the readable_output is correct.
    -   Ensure the outputs_prefix is correct.
    -   Ensure the outputs has no links.
    """
    args = {
        'name': 'name',
        'basepolicy_id': 'basepolicy_id',
        'description': 'description',
    }

    method = 'POST'
    mock_response = load_mock_response('intrusion_policy_response.json')

    requests_mock.request(
        method,
        f'{BASE_URL}/{SUFFIX}/policy/intrusionpolicies',
        json=mock_response,
    )

    from CiscoFirepower import create_intrusion_policy_command
    command_results = create_intrusion_policy_command(mock_client, args)

    assert_command_results(
        command_results=command_results,
        method=method,
        expected_output_prefix=INTRUSION_POLICY_CONTEXT
    )

    assert command_results.outputs[0]['name'] == mock_response['name']
    assert command_results.outputs[0]['id'] == mock_response['id']
    assert command_results.outputs[0]['description'] == mock_response['description']
    assert command_results.outputs[0]['basePolicy'] == mock_response['basePolicy']
    assert command_results.outputs[0]['metadata'] == mock_response['metadata']


@pytest.mark.parametrize(
    'args',
    (
        ({}),
        ({'limit': '6'}),
        ({'page_size': '3'}),
    )
)
def test_list_intrusion_policy_command(requests_mock, mock_client, args):
    """
    Scenario:
    -   Get an intrusion policy list.
    Given:
    -   Nothing.
    -   limit
    -   page_size
    When:
    -    ciscofp-get-intrusion-policy is called.
    Then:
    -   Ensure the readable_output is correct.
    -   Ensure the outputs_prefix is correct.
    -   Ensure the outputs has no links.
    """
    method = 'GET'
    mock_response = load_mock_response('intrusion_policy_list_response.json')

    requests_mock.request(
        method,
        f'{BASE_URL}/{SUFFIX}/policy/intrusionpolicies',
        json=mock_response,
    )

    from CiscoFirepower import list_intrusion_policy_command
    command_results = list_intrusion_policy_command(mock_client, args)

    assert_command_results(
        command_results=command_results,
        method=method,
        expected_output_prefix=INTRUSION_POLICY_CONTEXT
    )

    for output, mock_output in zip(command_results.outputs, mock_response['items']):
        assert output['name'] == mock_output['name']
        assert output['id'] == mock_output['id']
        assert output['description'] == mock_output['description']
        assert output['metadata'] == mock_output['metadata']


def test_get_intrusion_policy_command(requests_mock, mock_client):
    """
    Scenario:
    -   Get an intrusion policy.
    Given:
    -   intrusion_policy_id
    When:
    -    ciscofp-get-intrusion-policy is called.
    Then:
    -   Ensure the readable_output is correct.
    -   Ensure the outputs_prefix is correct.
    -   Ensure the outputs has no links.
    """
    args = {'intrusion_policy_id': 'intrusion_policy_id'}

    method = 'GET'
    mock_response = load_mock_response('intrusion_policy_response.json')

    requests_mock.request(
        method,
        f'{BASE_URL}/{SUFFIX}/policy/intrusionpolicies/{args["intrusion_policy_id"]}',
        json=mock_response,
    )

    from CiscoFirepower import list_intrusion_policy_command
    command_results = list_intrusion_policy_command(mock_client, args)

    assert_command_results(
        command_results=command_results,
        method=method,
        expected_output_prefix=INTRUSION_POLICY_CONTEXT
    )

    assert command_results.outputs[0]['name'] == mock_response['name']
    assert command_results.outputs[0]['id'] == mock_response['id']
    assert command_results.outputs[0]['description'] == mock_response['description']
    assert command_results.outputs[0]['metadata'] == mock_response['metadata']


def test_error_get_intrusion_policy_command(mock_client):
    """
    Scenario:
    -   Get an intrusion policy.
    Given:
    -   limit, intrusion_policy_id
    When:
    -    ciscofp-get-intrusion-policy is called.
    Then:
    -   Ensure an exception has been raised and it is correct.
    """
    args = {
        'limit': '5',
        'intrusion_policy_id': 'intrusion_policy_id',
    }

    with pytest.raises(ValueError) as ve:
        from CiscoFirepower import list_intrusion_policy_command
        list_intrusion_policy_command(mock_client, args)

        assert str(ve) == 'GET and LIST arguments can not be supported simutanlesy.'


def test_update_intrusion_policy_command(requests_mock, mock_client):
    """
    Scenario:
    -   Update an intrusion policy.
    Given:
    -   intrusion_policy_id, name, basepolicy_id, description
    When:
    -    ciscofp-update-intrusion-policy is called.
    Then:
    -   Ensure the readable_output is correct.
    -   Ensure the outputs_prefix is correct.
    -   Ensure the outputs has no links.
    """
    args = {
        'intrusion_policy_id': 'intrusion_policy_id',
        'name': 'name',
        'basepolicy_id': 'basepolicy_id',
        'description': 'description',
        'inspection_mode': 'PREVENTION'
    }

    method = 'PUT'
    mock_response = load_mock_response('intrusion_policy_response.json')

    requests_mock.request(
        method,
        f'{BASE_URL}/{SUFFIX}/policy/intrusionpolicies/{args["intrusion_policy_id"]}',
        json=mock_response,
    )

    from CiscoFirepower import update_intrusion_policy_command
    command_results = update_intrusion_policy_command(mock_client, args)

    assert_command_results(
        command_results=command_results,
        method=method,
        expected_output_prefix=INTRUSION_POLICY_CONTEXT
    )

    assert command_results.outputs[0]['name'] == mock_response['name']
    assert command_results.outputs[0]['id'] == mock_response['id']
    assert command_results.outputs[0]['description'] == mock_response['description']
    assert command_results.outputs[0]['basePolicy'] == mock_response['basePolicy']
    assert command_results.outputs[0]['metadata'] == mock_response['metadata']


def test_delete_intrusion_policy_command(requests_mock, mock_client):
    """
    Scenario:
    -   Delete an intrusion policy.
    Given:
    -   intrusion_policy_id
    When:
    -    ciscofp-delete-intrusion-policy is called.
    Then:
    -   Ensure the readable_output is correct.
    """
    args = {
        'intrusion_policy_id': 'intrusion_policy_id'
    }

    method = 'DELETE'
    mock_response = load_mock_response('intrusion_policy_response.json')

    requests_mock.request(
        method,
        f'{BASE_URL}/{SUFFIX}/policy/intrusionpolicies/{args["intrusion_policy_id"]}',
        json=mock_response,
    )

    from CiscoFirepower import delete_intrusion_policy_command
    command_results = delete_intrusion_policy_command(mock_client, args)

    assert_command_results(
        command_results=command_results,
        method=method
    )


def test_delete_intrusion_policy_error_command(requests_mock, mock_client):
    """
    Scenario:
    -   Delete an intrusion policy that doesn't exist.
    Given:
    -   intrusion_policy_id
    When:
    -    ciscofp-delete-intrusion-policy is called.
    Then:
    -   Ensure the readable_output is correct.
    """
    args = {
        'intrusion_policy_id': 'intrusion_policy_id'
    }

    method = 'DELETE'
    mock_response = load_mock_response('intrusion_policy_delete_fail.json')

    requests_mock.request(
        method,
        f'{BASE_URL}/{SUFFIX}/policy/intrusionpolicies/{args["intrusion_policy_id"]}',
        json=mock_response,
        status_code=HTTPStatus.NOT_FOUND,
    )

    from CiscoFirepower import delete_intrusion_policy_command
    command_results = delete_intrusion_policy_command(mock_client, args)

    assert command_results.readable_output == \
        f'The Intrusion Policy ID: "{args["intrusion_policy_id"]}" does not exist.'


''' Intrusion Rule CRUD '''  # pylint: disable=pointless-string-statement


def test_create_intrusion_rule_command(requests_mock, mock_client):
    """
    Scenario:
    -   Create an intrusion rule.
    Given:
    -   rule_data, rule_group_ids
    When:
    -    ciscofp-create-intrusion-rule is called.
    Then:
    -   Ensure the readable_output is correct.
    -   Ensure the outputs_prefix is correct.
    -   Ensure the outputs has no links.
    """
    args = {
        'rule_data': 'rule_data',
        'rule_group_ids': 'rule_group_id1,rule_group_id2',
    }

    method = 'POST'
    mock_response = load_mock_response('intrusion_rule_response.json')

    requests_mock.request(
        method,
        f'{BASE_URL}/{SUFFIX}/object/intrusionrules',
        json=mock_response,
    )

    from CiscoFirepower import create_intrusion_rule_command
    command_results = create_intrusion_rule_command(mock_client, args)

    assert_command_results(
        command_results=command_results,
        method=method,
        expected_output_prefix=INTRUSION_RULE_CONTEXT
    )

    assert command_results.outputs[0]['name'] == mock_response['name']
    assert command_results.outputs[0]['id'] == mock_response['id']
    assert command_results.outputs[0]['ruleData'] == mock_response['ruleData']
    assert command_results.outputs[0]['ruleGroups'] == mock_response['ruleGroups']


@pytest.mark.parametrize(
    'args',
    (
        ({'expanded_response': 'True'}),
        ({'limit': '6', 'expanded_response': 'False'}),
        ({'page_size': '3'}),
    )
)
def test_list_intrusion_rule_command(requests_mock, mock_client, args):
    """
    Scenario:
    -   Get an intrusion rule list.
    Given:
    -   expanded_response.
    -   limit, expanded_response
    -   page_size
    When:
    -    ciscofp-get-intrusion-rule is called.
    Then:
    -   Ensure the readable_output is correct.
    -   Ensure the outputs_prefix is correct.
    -   Ensure the outputs has no links.
    """
    method = 'GET'
    mock_response = load_mock_response('intrusion_rule_list_response.json')

    requests_mock.request(
        method,
        f'{BASE_URL}/{SUFFIX}/object/intrusionrules',
        json=mock_response,
    )

    from CiscoFirepower import list_intrusion_rule_command
    command_results = list_intrusion_rule_command(mock_client, args)

    assert_command_results(
        command_results=command_results,
        method=method,
        expected_output_prefix=INTRUSION_RULE_CONTEXT
    )

    for output, mock_output in zip(command_results.outputs, mock_response['items']):
        assert output['name'] == mock_output['name']
        assert output['id'] == mock_output['id']
        assert output['msg'] == mock_output['msg']
        assert output['ruleAction'] == mock_output['ruleAction']


def test_get_intrusion_rule_command(requests_mock, mock_client):
    """
    Scenario:
    -   Get an intrusion rule.
    Given:
    -   intrusion_rule_id
    When:
    -    ciscofp-get-intrusion-rule is called.
    Then:
    -   Ensure the readable_output is correct.
    -   Ensure the outputs_prefix is correct.
    -   Ensure the outputs has no links.
    """
    args = {'intrusion_rule_id': 'intrusion_rule_id'}
    method = 'GET'
    mock_response = load_mock_response('intrusion_rule_response.json')

    requests_mock.request(
        method,
        f'{BASE_URL}/{SUFFIX}/object/intrusionrules/{args["intrusion_rule_id"]}',
        json=mock_response,
    )

    from CiscoFirepower import list_intrusion_rule_command
    command_results = list_intrusion_rule_command(mock_client, args)

    assert_command_results(
        command_results=command_results,
        method=method,
        expected_output_prefix=INTRUSION_RULE_CONTEXT
    )

    assert command_results.outputs[0]['name'] == mock_response['name']
    assert command_results.outputs[0]['id'] == mock_response['id']
    assert command_results.outputs[0]['ruleData'] == mock_response['ruleData']
    assert command_results.outputs[0]['ruleGroups'] == mock_response['ruleGroups']


def test_error_get_intrusion_rule_command(mock_client):
    """
    Scenario:
    -   Get an intrusion rule.
    Given:
    -   limit, intrusion_rule_id
    When:
    -    ciscofp-get-intrusion-rule is called.
    Then:
    -   Ensure an exception has been raised and it is correct.
    """
    args = {
        'limit': '5',
        'intrusion_rule_id': 'intrusion_rule_id',
    }

    with pytest.raises(ValueError) as ve:
        from CiscoFirepower import list_intrusion_rule_command
        list_intrusion_rule_command(mock_client, args)

        assert str(ve) == 'GET and LIST arguments can not be supported simutanlesy.'


@pytest.mark.parametrize(
    'args',
    (
        {
            'intrusion_rule_id': 'intrusion_rule_id',
            'rule_data': 'rule_data',
            'rule_group_ids': 'rule_group_id1,rule_group_id2',
        },
        {
            'intrusion_rule_id': 'intrusion_rule_id',
            'rule_group_ids': 'rule_group_id1,rule_group_id2',
        },
        {
            'intrusion_rule_id': 'intrusion_rule_id',
            'rule_data': 'rule_data',
        },
    )
)
def test_update_intrusion_rule_command(requests_mock, mock_client, args):
    """
    Scenario:
    -   Update an intrusion rule.
    Given:
    -   intrusion_rule_id, rule_data, rule_group_ids
    -   intrusion_rule_id, rule_group_ids
    -   intrusion_rule_id, rule_data
    When:
    -    ciscofp-update-intrusion-rule is called.
    Then:
    -   Ensure the readable_output is correct.
    -   Ensure the outputs_prefix is correct.
    -   Ensure the outputs has no links.
    """
    method = 'PUT'
    url = f'{BASE_URL}/{SUFFIX}/object/intrusionrules/{args["intrusion_rule_id"]}'
    mock_response = load_mock_response('intrusion_rule_response.json')

    if 'rule_data' not in args or 'rule_group_ids' not in args:
        requests_mock.request(
            'GET',
            url,
            json=mock_response,
        )

    requests_mock.request(
        method,
        url,
        json=mock_response,
    )

    from CiscoFirepower import update_intrusion_rule_command
    command_results = update_intrusion_rule_command(mock_client, args)

    assert_command_results(
        command_results=command_results,
        method=method,
        expected_output_prefix=INTRUSION_RULE_CONTEXT
    )

    assert command_results.outputs[0]['name'] == mock_response['name']
    assert command_results.outputs[0]['id'] == mock_response['id']
    assert command_results.outputs[0]['ruleData'] == mock_response['ruleData']
    assert command_results.outputs[0]['ruleGroups'] == mock_response['ruleGroups']


@pytest.mark.parametrize(
    'args, expected_output',
    (
        (
            {'intrusion_rule_id': 'intrusion_rule_id'},
            'At least rule_data or rule_group_ids must be entered, if not both of them.'
        ),
        (
            {'intrusion_rule_id': 'intrusion_rule_id', 'update_strategy': 'MERGE', 'rule_data': 'rule_data'},
            'rule_group_ids must be entered when merging.'
        ),
    )
)
def test_error_update_intrusion_rule_command(mock_client, args, expected_output):
    """
    Scenario:
    -   Update an intrusion rule.
    Given:
    -   intrusion_rule_id
    -   intrusion_rule_id, update_strategy, rule_data
    When:
    -    ciscofp-update-intrusion-rule is called.
    Then:
    -   Ensure an exception is raised and it is correct.
    """
    with pytest.raises(ValueError) as ve:
        from CiscoFirepower import update_intrusion_rule_command
        update_intrusion_rule_command(mock_client, args)

        assert str(ve) == expected_output


def test_delete_intrusion_rule_command(requests_mock, mock_client):
    """
    Scenario:
    -   Delete an intrusion rule.
    Given:
    -   intrusion_rule_id
    When:
    -    ciscofp-delete-intrusion-rule is called.
    Then:
    -   Ensure the readable_output is correct.
    """
    args = {
        'intrusion_rule_id': 'intrusion_rule_id',
    }

    method = 'DELETE'
    mock_response = load_mock_response('intrusion_rule_response.json')

    requests_mock.request(
        method,
        f'{BASE_URL}/{SUFFIX}/object/intrusionrules/{args["intrusion_rule_id"]}',
        json=mock_response,
    )

    from CiscoFirepower import delete_intrusion_rule_command
    command_results = delete_intrusion_rule_command(mock_client, args)

    assert_command_results(
        command_results=command_results,
        method=method,
    )


@mock.patch('CiscoFirepower.demisto.getFilePath', lambda x: FILE_ENTRY)
def test_upload_intrusion_file_validation_command(requests_mock, mock_client):
    """
    Scenario:
    -   Upload an intrusion rule file for validation.
    -   Upload an intrusion rule file for import.
    Given:
    -   entry_id.
    -   entry_id, rule_import_mode, rule_group_ids
    When:
    -    ciscofp-upload-intrusion-rule-file is called.
    Then:
    -   Ensure the outputs_prefix is correct.
    -   Ensure the readable_output is correct.
    """
    args = {
        'entry_id': 'entry_id'
    }

    mock_response = load_mock_response('intrusion_rule_upload_validation_response.json')
    requests_mock.post(
        f'{BASE_URL}/{SUFFIX}/object/intrusionrulesupload',
        json=mock_response,
    )

    from CiscoFirepower import upload_intrusion_rule_file_command
    command_results = upload_intrusion_rule_file_command(mock_client, args)

    assert f'Validation for Intrusion Rules within: "{FILE_ENTRY["name"]}"' in command_results.readable_output
    assert mock_response['error']['messages'][0]['description'] in command_results.readable_output


@mock.patch('CiscoFirepower.demisto.getFilePath', lambda x: FILE_ENTRY)
def test_upload_intrusion_file_import_command(requests_mock, mock_client):
    """
    Scenario:
    -   Upload an intrusion rule file for import.
    Given:
    -   entry_id, rule_import_mode, rule_group_ids
    When:
    -    ciscofp-upload-intrusion-rule-file is called.
    Then:
    -   Ensure the outputs_prefix is correct.
    -   Ensure the readable_output is correct.
    """
    args = {
        'entry_id': 'entry_id',
        'rule_import_mode': 'MERGE',
        'rule_group_ids': 'rule_group_id1,rule_group_id2',
    }

    mock_response = load_mock_response('intrusion_rule_upload_import_response.json')
    requests_mock.post(
        f'{BASE_URL}/{SUFFIX}/object/intrusionrulesupload',
        json=mock_response,
    )

    from CiscoFirepower import upload_intrusion_rule_file_command
    command_results = upload_intrusion_rule_file_command(mock_client, args)

    assert command_results.outputs_prefix == '.'.join((INTEGRATION_CONTEXT_NAME, INTRUSION_RULE_UPLOAD_CONTEXT))
    assert INTRUSION_RULE_UPLOAD_TITLE in command_results.readable_output
    assert command_results.outputs[0]['summary'] == mock_response['summary']
    assert command_results.outputs[0]['ruleGroups'] == mock_response['ruleGroups']
    assert command_results.outputs[0]['files'] == mock_response['files']


@pytest.mark.parametrize(
    'args, expected_output',
    (
        (
            {
                'entry_id': 'entry_id',
                'validate_only': 'False',
                'rule_import_mode': 'MERGE',
            },
            'rule_import_mode and rule_group_ids must be inserted when validate_only is "False".'
        ),
        (
            {
                'entry_id': 'entry_id',
                'validate_only': 'False',
                'rule_group_ids': 'rule_group_ids1,rule_group_ids2',
            },
            'rule_import_mode and rule_group_ids must be inserted when validate_only is "False".'
        ),
        (
            {
                'entry_id': 'entry_id',
                'rule_import_mode': 'REPLACE',
                'rule_group_ids': 'rule_group_ids1,rule_group_ids2',
            },
            'Supported file formats are ".txt" and ".rules".'
        ),
    )
)
@mock.patch('CiscoFirepower.demisto.getFilePath', lambda x: FILE_ENTRY_ERROR)
def test_error_upload_intrusion_file_command(mock_client, args, expected_output):
    """
    Scenario:
    -   Upload an intrusion rule file for import/validation.
    Given:
    -   entry_id, validate_only, rule_import_mode
    -   entry_id, validate_only, rule_group_ids
    -   entry_id, rule_import_mode, rule_group_ids
    When:
    -    ciscofp-upload-intrusion-rule-file is called.
    Then:
    -   Ensure an exception has been raised and it is correct.
    """
    with pytest.raises(ValueError) as ve:
        from CiscoFirepower import upload_intrusion_rule_file_command
        upload_intrusion_rule_file_command(mock_client, args)

        assert str(ve) == expected_output


''' Intrusion Rule Group CRUD '''  # pylint: disable=pointless-string-statement


def test_create_intrusion_rule_group_command(requests_mock, mock_client):
    """
    Scenario:
    -   Create an intrusion rule group.
    Given:
    -   name, description
    When:
    -    ciscofp-create-intrusion-rule-group is called.
    Then:
    -   Ensure the readable_output is correct.
    -   Ensure the outputs_prefix is correct.
    -   Ensure the outputs has no links.
    """
    args = {
        'name': 'name',
        'description': 'description',
    }

    method = 'POST'
    mock_response = load_mock_response('intrusion_rule_group_response.json')

    requests_mock.request(
        method,
        f'{BASE_URL}/{SUFFIX}/object/intrusionrulegroups',
        json=mock_response,
    )

    from CiscoFirepower import create_intrusion_rule_group_command
    command_results = create_intrusion_rule_group_command(mock_client, args)

    assert_command_results(
        command_results=command_results,
        method=method,
        expected_output_prefix=INTRUSION_RULE_GROUP_CONTEXT
    )

    assert command_results.outputs[0]['name'] == mock_response['name']
    assert command_results.outputs[0]['id'] == mock_response['id']
    assert command_results.outputs[0]['description'] == mock_response['description']


@pytest.mark.parametrize(
    'args',
    (
        ({'expanded_response': 'True'}),
        ({'limit': '6', 'expanded_response': 'False'}),
        ({'page_size': '3'}),
    )
)
def test_list_intrusion_rule_group_command(requests_mock, mock_client, args):
    """
    Scenario:
    -   Get an intrusion rule group list.
    Given:
    -   expanded_response.
    -   limit, expanded_response
    -   page_size
    When:
    -    ciscofp-get-intrusion-rule-group is called.
    Then:
    -   Ensure the readable_output is correct.
    -   Ensure the outputs_prefix is correct.
    -   Ensure the outputs has no links.
    """

    method = 'GET'
    mock_response = load_mock_response('intrusion_rule_group_list_response.json')

    requests_mock.request(
        method,
        f'{BASE_URL}/{SUFFIX}/object/intrusionrulegroups',
        json=mock_response,
    )

    from CiscoFirepower import list_intrusion_rule_group_command
    command_results = list_intrusion_rule_group_command(mock_client, args)

    assert_command_results(
        command_results=command_results,
        method=method,
        expected_output_prefix=INTRUSION_RULE_GROUP_CONTEXT
    )

    for output, mock_output in zip(command_results.outputs, mock_response['items']):
        assert output['name'] == mock_output['name']
        assert output['id'] == mock_output['id']
        assert output['description'] == mock_output['description']
        assert output['childGroups'] == mock_output['childGroups']


def test_get_intrusion_rule_group_command(requests_mock, mock_client):
    """
    Scenario:
    -   Get an intrusion rule group.
    Given:
    -   rule_group_id
    When:
    -    ciscofp-get-intrusion-rule-group is called.
    Then:
    -   Ensure the readable_output is correct.
    -   Ensure the outputs_prefix is correct.
    -   Ensure the outputs has no links.
    """
    args = {'rule_group_id': 'rule_group_id'}

    method = 'GET'
    mock_response = load_mock_response('intrusion_rule_group_response.json')

    requests_mock.request(
        method,
        f'{BASE_URL}/{SUFFIX}/object/intrusionrulegroups/{args["rule_group_id"]}',
        json=mock_response,
    )

    from CiscoFirepower import list_intrusion_rule_group_command
    command_results = list_intrusion_rule_group_command(mock_client, args)

    assert_command_results(
        command_results=command_results,
        method=method,
        expected_output_prefix=INTRUSION_RULE_GROUP_CONTEXT
    )

    assert command_results.outputs[0]['name'] == mock_response['name']
    assert command_results.outputs[0]['id'] == mock_response['id']
    assert command_results.outputs[0]['description'] == mock_response['description']


def test_error_get_intrusion_rule_group_command(mock_client):
    """
    Scenario:
    -   Get an intrusion rule group.
    Given:
    -   limit, rule_group_id
    When:
    -    ciscofp-get-intrusion-rule-group is called.
    Then:
    -   Ensure an exception has been raised and it is correct.
    """
    args = {
        'limit': '5',
        'rule_group_id': 'rule_group_id',
    }

    with pytest.raises(ValueError) as ve:
        from CiscoFirepower import list_intrusion_rule_group_command
        list_intrusion_rule_group_command(mock_client, args)

        assert str(ve) == 'GET and LIST arguments can not be supported simutanlesy.'


def test_update_intrusion_rule_group_command(requests_mock, mock_client):
    """
    Scenario:
    -   Update an intrusion rule group.
    Given:
    -   rule_group_id, name, description
    When:
    -    ciscofp-update-intrusion-rule-group is called.
    Then:
    -   Ensure the readable_output is correct.
    -   Ensure the outputs_prefix is correct.
    -   Ensure the outputs has no links.
    """
    args = {
        'rule_group_id': 'rule_group_id',
        'name': 'name',
        'description': 'description',
    }

    method = 'PUT'
    mock_response = load_mock_response('intrusion_rule_group_response.json')

    requests_mock.request(
        method,
        f'{BASE_URL}/{SUFFIX}/object/intrusionrulegroups/{args["rule_group_id"]}',
        json=mock_response,
    )

    from CiscoFirepower import update_intrusion_rule_group_command
    command_results = update_intrusion_rule_group_command(mock_client, args)

    assert_command_results(
        command_results=command_results,
        method=method,
        expected_output_prefix=INTRUSION_RULE_GROUP_CONTEXT
    )

    assert command_results.outputs[0]['name'] == mock_response['name']
    assert command_results.outputs[0]['id'] == mock_response['id']
    assert command_results.outputs[0]['description'] == mock_response['description']


def test_delete_intrusion_rule_group_command(requests_mock, mock_client):
    """
    Scenario:
    -   Delete an intrusion rule group.
    Given:
    -   rule_group_id
    When:
    -    ciscofp-delete-intrusion-rule-group is called.
    Then:
    -   Ensure the readable_output is correct.
    """
    args = {
        'rule_group_id': 'rule_group_id'
    }

    method = 'DELETE'
    mock_response = load_mock_response('intrusion_rule_group_response.json')

    requests_mock.request(
        method,
        f'{BASE_URL}/{SUFFIX}/object/intrusionrulegroups/{args["rule_group_id"]}',
        json=mock_response,
    )

    from CiscoFirepower import delete_intrusion_rule_group_command
    command_results = delete_intrusion_rule_group_command(mock_client, args)

    assert_command_results(
        command_results=command_results,
        method=method,
    )


''' Network Analysis Policy CRUD '''  # pylint: disable=pointless-string-statement


def test_create_network_analysis_policy_command(requests_mock, mock_client):
    """
    Scenario:
    -   Create an network analysis policy.
    Given:
    -   name, basepolicy_id, description
    When:
    -    ciscofp-create-network-analysis-policy is called.
    Then:
    -   Ensure the readable_output is correct.
    -   Ensure the outputs_prefix is correct.
    -   Ensure the outputs has no links.
    """
    args = {
        'name': 'name',
        'basepolicy_id': 'basepolicy_id',
        'description': 'description',
    }

    method = 'POST'
    mock_response = load_mock_response('network_analysis_response.json')

    requests_mock.request(
        method,
        f'{BASE_URL}/{SUFFIX}/policy/networkanalysispolicies',
        json=mock_response,
    )

    from CiscoFirepower import create_network_analysis_policy_command
    command_results = create_network_analysis_policy_command(mock_client, args)

    assert_command_results(
        command_results=command_results,
        method=method,
        expected_output_prefix=NETWORK_ANALYSIS_POLICY_CONTEXT
    )

    assert command_results.outputs[0]['name'] == mock_response['name']
    assert command_results.outputs[0]['id'] == mock_response['id']
    assert command_results.outputs[0]['description'] == mock_response['description']
    assert command_results.outputs[0]['basePolicy'] == mock_response['basePolicy']
    assert command_results.outputs[0]['metadata'] == mock_response['metadata']


@pytest.mark.parametrize(
    'args',
    (
        ({'expanded_response': 'True'}),
        ({'limit': '6', 'expanded_response': 'False'}),
        ({'page_size': '3'}),
    )
)
def test_list_network_analysis_policy_command(requests_mock, mock_client, args):
    """
    Scenario:
    -   Create an network analysis policy list.
    -   Create an network analysis policy.
    Given:
    -   expanded_response.
    -   limit, expanded_response
    -   page_size
    -   network_analysis_policy_id
    When:
    -    ciscofp-get-network-analysis-policy is called.
    Then:
    -   Ensure the readable_output is correct.
    -   Ensure the outputs_prefix is correct.
    -   Ensure the outputs has no links.
    """
    method = 'GET'
    mock_response = load_mock_response('network_analysis_list_response.json')

    requests_mock.request(
        method,
        f'{BASE_URL}/{SUFFIX}/policy/networkanalysispolicies',
        json=mock_response,
    )

    from CiscoFirepower import list_network_analysis_policy_command
    command_results = list_network_analysis_policy_command(mock_client, args)

    assert_command_results(
        command_results=command_results,
        method=method,
        expected_output_prefix=NETWORK_ANALYSIS_POLICY_CONTEXT
    )

    for output, mock_output in zip(command_results.outputs, mock_response['items']):
        assert output['name'] == mock_output['name']
        assert output['id'] == mock_output['id']
        assert output['description'] == mock_output['description']
        assert output['metadata'] == mock_output['metadata']


def test_get_network_analysis_policy_command(requests_mock, mock_client):
    """
    Scenario:
    -   Create an network analysis policy.
    Given:
    -   network_analysis_policy_id
    When:
    -    ciscofp-get-network-analysis-policy is called.
    Then:
    -   Ensure the readable_output is correct.
    -   Ensure the outputs_prefix is correct.
    -   Ensure the outputs has no links.
    """
    args = {'network_analysis_policy_id': 'network_analysis_policy_id'}
    method = 'GET'
    mock_response = load_mock_response('network_analysis_response.json')

    requests_mock.request(
        method,
        f'{BASE_URL}/{SUFFIX}/policy/networkanalysispolicies/{args["network_analysis_policy_id"]}',
        json=mock_response,
    )

    from CiscoFirepower import list_network_analysis_policy_command
    command_results = list_network_analysis_policy_command(mock_client, args)

    assert_command_results(
        command_results=command_results,
        method=method,
        expected_output_prefix=NETWORK_ANALYSIS_POLICY_CONTEXT
    )

    assert command_results.outputs[0]['name'] == mock_response['name']
    assert command_results.outputs[0]['id'] == mock_response['id']
    assert command_results.outputs[0]['description'] == mock_response['description']
    assert command_results.outputs[0]['basePolicy'] == mock_response['basePolicy']
    assert command_results.outputs[0]['metadata'] == mock_response['metadata']


def test_error_get_network_analysis_policy_command(mock_client):
    """
    Scenario:
    -   Get an network analysis policy.
    Given:
    -   limit, network_analysis_policy_id
    When:
    -    ciscofp-get-network-analysis-policy is called.
    Then:
    -   Ensure an exception has been raised and it is correct.
    """
    args = {
        'limit': '5',
        'network_analysis_policy_id': 'network_analysis_policy_id',
    }

    with pytest.raises(ValueError) as ve:
        from CiscoFirepower import list_network_analysis_policy_command
        list_network_analysis_policy_command(mock_client, args)

        assert str(ve) == 'GET and LIST arguments can not be supported simutanlesy.'


def test_update_network_analysis_policy_command(requests_mock, mock_client):
    """
    Scenario:
    -   Update an network analysis policy.
    Given:
    -   network_analysis_policy_id, name, basepolicy_id, description
    When:
    -    ciscofp-update-network-analysis-policy is called.
    Then:
    -   Ensure the readable_output is correct.
    -   Ensure the outputs_prefix is correct.
    -   Ensure the outputs has no links.
    """
    args = {
        'network_analysis_policy_id': 'network_analysis_policy_id',
        'name': 'name',
        'basepolicy_id': 'basepolicy_id',
        'description': 'description',
        'inspection_mode': 'PREVENTION',
        'replicate_inspection_mode': 'True'
    }

    method = 'PUT'
    mock_response = load_mock_response('network_analysis_response.json')

    requests_mock.request(
        method,
        f'{BASE_URL}/{SUFFIX}/policy/networkanalysispolicies/{args["network_analysis_policy_id"]}',
        json=mock_response,
    )

    from CiscoFirepower import update_network_analysis_policy_command
    command_results = update_network_analysis_policy_command(mock_client, args)

    assert_command_results(
        command_results=command_results,
        method=method,
        expected_output_prefix=NETWORK_ANALYSIS_POLICY_CONTEXT
    )

    assert command_results.outputs[0]['name'] == mock_response['name']
    assert command_results.outputs[0]['id'] == mock_response['id']
    assert command_results.outputs[0]['description'] == mock_response['description']
    assert command_results.outputs[0]['basePolicy'] == mock_response['basePolicy']
    assert command_results.outputs[0]['metadata'] == mock_response['metadata']


def test_delete_network_analysis_policy_command(requests_mock, mock_client):
    """
    Scenario:
    -   Delete an network analysis policy.
    Given:
    -   network_analysis_policy_id
    When:
    -    ciscofp-delete-network-analysis-policy is called.
    Then:
    -   Ensure the readable_output is correct.
    """
    args = {
        'network_analysis_policy_id': 'network_analysis_policy_id'
    }

    method = 'DELETE'
    mock_response = load_mock_response('network_analysis_response.json')

    requests_mock.request(
        method,
        f'{BASE_URL}/{SUFFIX}/policy/networkanalysispolicies/{args["network_analysis_policy_id"]}',
        json=mock_response,
    )

    from CiscoFirepower import delete_network_analysis_policy_command
    command_results = delete_network_analysis_policy_command(mock_client, args)

    assert_command_results(
        command_results=command_results,
        method=method,
    )
