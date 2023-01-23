"""
Tests module for Prisma SASE integration.
"""

import json
import pytest

from PrismaSASE import Client


def load_mock_response(file_name: str) -> str:
    """
    Load mock file that simulates an API response.

    Args:
        file_name (str): Name of the mock response JSON file to return.

    Returns:
        str: Mock file content.

    """
    with open(f'test_data/{file_name}', mode='r', encoding='utf-8') as mock_file:
        return mock_file.read()


def create_mocked_client():
    return Client(base_url='http://base_url',
                  client_id='clientid',
                  client_secret='clientsecret',
                  tsg_id='tsg_id',
                  verify=False,
                  proxy=False,
                  headers={
                      'Accept': 'application/json',
                      'Content-Type': 'application/json'
                  })


@pytest.mark.parametrize(
    # Write and define the expected
    "args, default_tsg_id",
    [
        ({"name": "cid-1252366",
          "folder": "Shared",
          "position": "pre",
          "action": "allow",
          "source_hip": "any",
          "destination_hip": "any",
          "from": "trust",
          "to": "trust",
          "source": "PA-GP-Mobile-User-Pool",
          "source_user": "any",
          "service": "application-default",
          "log_setting": "Cortex Data Lake",
          "profile_setting": "best-practice",
          "tsg_id": "1234567"}, "1234567")
    ]
)
def test_create_security_rule_command(mocker, args, default_tsg_id):
    from PrismaSASE import create_security_rule_command
    mock_response = json.loads(load_mock_response('security-rule.json'))
    client = create_mocked_client()

    mocker.patch.object(client, 'get_access_token', return_value='access_token')
    mocker.patch.object(client, 'create_security_rule', return_value=mock_response)

    result = create_security_rule_command(client, args)

    assert result.outputs_prefix == 'PrismaSase.SecurityRule'
    assert result.outputs == mock_response


@pytest.mark.parametrize(
    # Write and define the expected
    "args",
    [{"folder": "Shared",
      "position": "pre",
      "tsg_id": "1234567"}
     ]
)
def test_list_security_rules_command(mocker, args):
    from PrismaSASE import list_security_rules_command
    mock_response = json.loads(load_mock_response('list-security-rules.json'))
    client = create_mocked_client()

    mocker.patch.object(client, 'get_access_token', return_value='access_token')
    mocker.patch.object(client, 'list_security_rules', return_value=mock_response)
    result = list_security_rules_command(client, args)
    assert result.outputs_prefix == 'PrismaSase.SecurityRule'
    assert result.outputs == mock_response.get('data')


@pytest.mark.parametrize(
    # Write and define the expected
    "args",
    [{"folder": "Shared",
      "position": "pre",
      "rule_id": "####385c-1c8a-42fc-94e4-####cbd148b9"}
     ]
)
def test_list_security_rules_command_with_id(mocker, args):
    from PrismaSASE import list_security_rules_command
    mock_response = json.loads(load_mock_response('security-rule.json'))
    client = create_mocked_client()

    mocker.patch.object(client, 'get_access_token', return_value='access_token')
    mocker.patch.object(client, 'get_security_rule_by_id', return_value=mock_response)
    result = list_security_rules_command(client, args)
    assert result.outputs_prefix == 'PrismaSase.SecurityRule'
    assert result.outputs == mock_response


@pytest.mark.parametrize(
    # Write and define the expected
    "args",
    [
        {"folders": "Mobile Users",
         "description": "Description",
         "tsg_id": "1234567"}
    ]
)
def test_push_candidate_config_command(mocker, requests_mock, args):
    # TODO check how to test polling
    from PrismaSASE import push_candidate_config_command
    mock_response = json.loads(load_mock_response('push-candidate-config.json'))
    requests_mock.post('http://base_url/sse/config/v1/config-versions/candidate:push', json=mock_response)
    client = create_mocked_client()

    mocker.patch.object(client, 'get_access_token', return_value='access_token')
    result = push_candidate_config_command(client, args)
    assert result.outputs_prefix == 'PrismaSase.CandidateConfig'
    assert result.outputs == mock_response


@pytest.mark.parametrize(
    # Write and define the expected
    'args, expected_result',
    [
        ({"rule_id": "####ec11-b599-4372-a0d7-####ecb8203",
          "action": "deny",
          "to": "any",
          "overwrite": False
          },
         {'action': 'deny', 'to': ['any']}),
        ({"rule_id": "####ec11-b599-4372-a0d7-####ecb8203",
          "action": "deny",
          "to": "to",
          "overwrite": True
          }, {'action': 'deny', 'to': ['to']}),
        ({"rule_id": "####ec11-b599-4372-a0d7-####ecb8203",
          "to": "to",
          "overwrite": False
          }, {'action': 'deny', 'to': ['untrust', 'to']})
    ],
)
def test_edit_security_rule_command(mocker, args, expected_result):
    from PrismaSASE import edit_security_rule_command
    mock_response = json.loads(load_mock_response('edit-security-rule.json'))
    client = create_mocked_client()

    mocker.patch.object(client, 'get_access_token', return_value='access_token')
    mocker.patch.object(client, 'get_security_rule_by_id', return_value=mock_response)
    res = mocker.patch.object(client, 'edit_security_rule')
    edit_security_rule_command(client, args)
    assert res.call_args[1]['rule']['action'] == expected_result['action']
    assert res.call_args[1]['rule']['to'] == expected_result['to']


@pytest.mark.parametrize(
    # Write and define the expected
    "args",
    [
        {"limit": "2",
         "tsg_id": "1234567"}
    ]
)
def test_list_config_jobs_command(mocker, requests_mock, args):
    # TODO add parameter for one
    from PrismaSASE import list_config_jobs_command
    mock_response = json.loads(load_mock_response('list-config-jobs.json'))
    mock_url = 'http://base_url/sse/config/v1/jobs?limit=2'

    requests_mock.get(mock_url, json=mock_response)
    client = create_mocked_client()

    mocker.patch.object(client, 'get_access_token', return_value='access_token')
    result = list_config_jobs_command(client, args)
    assert result.outputs_prefix == 'PrismaSase.ConfigJob'
    assert result.outputs == mock_response.get('data')


@pytest.mark.parametrize(
    # Write and define the expected
    "args",
    [
        {"rule_id": "####385c-1c8a-42fc-94e4-####cbd148b9",
         "tsg_id": "1234567"}
    ]
)
def test_delete_security_rule_command(mocker, args):
    from PrismaSASE import delete_security_rule_command
    mock_response = json.loads(load_mock_response('security-rule.json'))

    client = create_mocked_client()

    mocker.patch.object(client, 'get_access_token', return_value='access_token')
    mocker.patch.object(client, 'delete_security_rule', return_value=mock_response)
    result = delete_security_rule_command(client, args)
    assert 'deleted successfully' in result.readable_output
    assert '####385c-1c8a-42fc-94e4-####cbd148b9' in result.readable_output


@pytest.mark.parametrize(
    # Write and define the expected
    "args",
    [
        {"name": "TestXSOARAddress",
         "folder": "Shared",
         "description": "Test address created by xsoar",
         "ip_netmask": "1.1.1.1/24",
         "tsg_id": "1234567"}
    ]
)
def test_create_address_object_command(mocker, args):
    from PrismaSASE import create_address_object_command
    mock_response = {
        "description": "Test address created by xsoar",
        "folder": "Shared",
        "id": "####f837-379e-4c48-a967-####7a52ec14",
        "ip_netmask": "1.1.1.1/24"}
    client = create_mocked_client()

    mocker.patch.object(client, 'get_access_token', return_value='access_token')
    mocker.patch.object(client, 'create_address_object', return_value=mock_response)

    result = create_address_object_command(client, args)

    assert result.outputs_prefix == 'PrismaSase.Address'
    assert result.outputs[0]['type'] == 'ip_netmask'
    assert result.outputs[0]['address_value'] == '1.1.1.1/24'


@pytest.mark.parametrize(
    # Write and define the expected
    "args",
    [
        {"name": "TestXSOARAddress",
         "folder": "Shared",
         "description": "Test address created by xsoar changed",
         "type": "fqdn",
         "address_value": "test.com",
         "id": "####f837-379e-4c48-a967-####7a52ec14",
         "tsg_id": "1234567"}
    ]
)
def test_edit_address_object_command(mocker, args):
    from PrismaSASE import edit_address_object_command

    mock_response = {
        "description": "Test address created by xsoar changed",
        "folder": "Shared",
        "id": "####f837-379e-4c48-a967-####a52ec14",
        "ip_netmask": "1.1.1.1/24",
        "name": "TestXSOARAddress"}

    client = create_mocked_client()

    mocker.patch.object(client, 'get_access_token', return_value='access_token')
    mocker.patch.object(client, 'get_address_by_id', return_value=mock_response)
    res = mocker.patch.object(client, 'edit_address_object')

    edit_address_object_command(client, args)
    test = res.call_args[1]

    assert res.call_args[1]['address']['fqdn'] == 'test.com'


@pytest.mark.parametrize(
    # Write and define the expected
    "args",
    [
        {"id": "####f837-379e-4c48-a967-####7a52ec14",
         "tsg_id": "1234567"}
    ]
)
def test_delete_address_object_command(mocker, args):
    from PrismaSASE import delete_address_object_command
    mock_response = {
        "description": "Test address created by xsoar changed",
        "folder": "Shared",
        "id": "####f837-379e-4c48-a967-####7a52ec14",
        "ip_netmask": "1.1.1.1/24",
        "name": "TestXSOARAddress"}

    client = create_mocked_client()

    mocker.patch.object(client, 'get_access_token', return_value='access_token')
    mocker.patch.object(client, 'delete_address_object', return_value=mock_response)

    result = delete_address_object_command(client, args)

    assert 'deleted successfully' in result.readable_output
    assert '####f837-379e-4c48-a967-####7a52ec14' in result.readable_output


@pytest.mark.parametrize(
    # Write and define the expected
    "args",
    [
        {"folder": "Shared",
         "limit": "20",
         "tsg_id": "1234567"}
    ]
)
def test_list_address_objects_command(mocker, requests_mock, args):
    # TODO add one
    from PrismaSASE import list_address_objects_command
    mock_response = json.loads(load_mock_response('list-address-objects.json'))
    requests_mock.get('http://base_url/sse/config/v1/addresses?folder=Shared&limit=20', json=mock_response)
    client = create_mocked_client()

    mocker.patch.object(client, 'get_access_token', return_value='access_token')
    result = list_address_objects_command(client, args)
    assert result.outputs_prefix == 'PrismaSase.Address'
    assert result.outputs == mock_response.get('data')
