"""
Tests module for Prisma SASE integration.
"""

import json
import pytest
import CommonServerPython
from CommonServerPython import DemistoException
from PrismaSASE import Client


def load_mock_response(file_name: str) -> str:
    """
    Load mock file that simulates an API response.

    Args:
        file_name (str): Name of the mock response JSON file to return.

    Returns:
        str: Mock file content.

    """
    with open(f'test_data/{file_name}', encoding='utf-8') as mock_file:
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


def test_list_security_rules_command__when_object_not_found(mocker):
    """
    Given:
        - A security rule ID that does not exist in the API.
    When:
        - Running list-security-rules command.
    Then:
        - Ensure the command returns an error message as a human-readable output.
    """
    from PrismaSASE import list_security_rules_command
    client = create_mocked_client()
    mocker.patch.object(client, 'get_access_token', return_value='access_token')
    mocker.patch.object(client, 'list_security_rules', side_effect=DemistoException("Error in API call [404]"))
    with pytest.raises(DemistoException):
        res = list_security_rules_command(client, {"id": "1234567"})
        assert res == "The item you're searching for does not exist within the Prisma SASE API."


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
          "action": "deny",
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
    assert result.outputs['type'] == 'ip_netmask'
    assert result.outputs['address_value'] == '1.1.1.1/24'


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
def test_list_address_objects_command(mocker, args):
    from PrismaSASE import list_address_objects_command
    mock_response = json.loads(load_mock_response('list-address-objects.json'))

    client = create_mocked_client()

    mocker.patch.object(client, 'get_access_token', return_value='access_token')
    mocker.patch.object(client, 'list_address_objects', return_value=mock_response)
    result = list_address_objects_command(client, args)
    assert result.outputs_prefix == 'PrismaSase.Address'
    assert result.outputs == mock_response.get('data')


@pytest.mark.parametrize(
    # Write and define the expected
    "args",
    [
        {"object_id": "####f837-379e-4c48-a967-####a52ec14"}
    ]
)
def test_list_address_objects_command_with_id(mocker, args):
    mock_response = {
        "description": "Test address created by xsoar changed",
        "folder": "Shared",
        "id": "####f837-379e-4c48-a967-####a52ec14",
        "ip_netmask": "1.1.1.1/24",
        "name": "TestXSOARAddress"}
    from PrismaSASE import list_address_objects_command
    client = create_mocked_client()

    mocker.patch.object(client, 'get_access_token', return_value='access_token')
    mocker.patch.object(client, 'get_address_by_id', return_value=mock_response)
    result = list_address_objects_command(client, args)
    assert result.outputs_prefix == 'PrismaSase.Address'
    assert result.outputs['type'] == 'ip_netmask'
    assert result.outputs['address_value'] == '1.1.1.1/24'


def test_list_tags_command(mocker):
    from PrismaSASE import list_tags_command
    mock_response = json.loads(load_mock_response('list-tags.json'))
    client = create_mocked_client()

    mocker.patch.object(client, 'get_access_token', return_value='access_token')
    mocker.patch.object(client, 'list_tags', return_value=mock_response)
    result = list_tags_command(client, args={})
    assert result.outputs_prefix == 'PrismaSase.Tag'
    assert result.outputs == mock_response.get('data')


@pytest.mark.parametrize(
    # Write and define the expected
    "args",
    [
        {"tag_id": "id1", "color": "Blue"}
    ]
)
def test_update_tag_command(mocker, args):
    from PrismaSASE import update_tag_command
    mock_response = json.loads(load_mock_response('tag.json'))
    client = create_mocked_client()

    mocker.patch.object(client, 'get_access_token', return_value='access_token')
    mocker.patch.object(client, 'get_tag_by_id', return_value=mock_response)
    res = mocker.patch.object(client, 'update_tag')
    update_tag_command(client, args)
    assert res.call_args[1]['tag']['color'] == 'Blue'


@pytest.mark.parametrize(
    # Write and define the expected
    "args",
    [
        {"tag_id": "id1"}
    ]
)
def test_delete_tag_command(mocker, args):
    from PrismaSASE import delete_tag_command

    mock_response = json.loads(load_mock_response('tag.json'))
    client = create_mocked_client()

    mocker.patch.object(client, 'get_access_token', return_value='access_token')
    mocker.patch.object(client, 'delete_tag', return_value=mock_response)

    result = delete_tag_command(client, args)

    assert 'deleted successfully' in result.readable_output
    assert 'id1' in result.readable_output


def test_list_address_group_command(mocker):
    from PrismaSASE import list_address_group_command
    mock_response = json.loads(load_mock_response('list-address-group.json'))
    client = create_mocked_client()

    mocker.patch.object(client, 'get_access_token', return_value='access_token')
    mocker.patch.object(client, 'list_address_group', return_value=mock_response)
    result = list_address_group_command(client, args={})
    assert result.outputs_prefix == 'PrismaSase.AddressGroup'
    assert result.outputs == mock_response.get('data')


@pytest.mark.parametrize(
    # Write and define the expected
    "test_data_file, args, address_type, expected_results",
    [
        ('dynamic-address-group.json',
         {"group_id": "id1", "overwrite": True, 'dynamic_filter': 'test'},
         'dynamic',
         {'dynamic': {'filter': 'test'}}),
        ('static-address-group.json',
         {"group_id": "id1", "overwrite": False, 'static_addresses': 'test'},
         'static',
         {'static': ['test2', 'test']}),
        ('dynamic-address-group.json',
         {"group_id": "id1", "overwrite": False, 'dynamic_filter': 'and test'},
         'dynamic',
         {'dynamic': {'filter': 'Microsoft 365 and Hamuzim and test'}}),
        ('static-address-group.json',
         {"group_id": "id1", "overwrite": True, 'static_addresses': 'test'},
         'static',
         {'static': ['test']})
    ]
)
def test_update_address_group_command(mocker, test_data_file, args, address_type, expected_results):
    from PrismaSASE import update_address_group_command
    mock_response = json.loads(load_mock_response(test_data_file))
    client = create_mocked_client()

    mocker.patch.object(client, 'get_access_token', return_value='access_token')
    mocker.patch.object(client, 'get_address_group_by_id', return_value=mock_response)
    res = mocker.patch.object(client, 'update_address_group')
    update_address_group_command(client, args)
    assert res.call_args[1]['address_group'][address_type] == expected_results[address_type]


@pytest.mark.parametrize(
    # Write and define the expected
    "args",
    [
        {"group_id": "id3"}
    ]
)
def test_delete_address_group_command(mocker, args):
    from PrismaSASE import delete_address_group_command

    mock_response = json.loads(load_mock_response('dynamic-address-group.json'))
    client = create_mocked_client()

    mocker.patch.object(client, 'get_access_token', return_value='access_token')
    mocker.patch.object(client, 'delete_address_group', return_value=mock_response)

    result = delete_address_group_command(client, args)

    assert 'deleted successfully' in result.readable_output
    assert 'id3' in result.readable_output


def test_list_custom_url_category_command(mocker):
    from PrismaSASE import list_custom_url_category_command
    mock_response = json.loads(load_mock_response('list-address-group.json'))
    client = create_mocked_client()

    mocker.patch.object(client, 'get_access_token', return_value='access_token')
    mocker.patch.object(client, 'list_custom_url_category', return_value=mock_response)
    result = list_custom_url_category_command(client, args={})
    assert result.outputs_prefix == 'PrismaSase.CustomURLCategory'
    assert result.outputs == mock_response.get('data')


@pytest.mark.parametrize(
    # Write and define the expected
    "args, expected_results",
    [
        ({'id': 'id1', 'overwrite': True, 'value': 'www.test.com'},
         ['www.test.com']),
        ({'id': 'id1', 'overwrite': False, 'value': 'www.test.com'},
         ['www.google.com', 'www.test.com']),
    ]
)
def test_update_custom_url_category_command(mocker, args, expected_results):
    from PrismaSASE import update_custom_url_category_command
    mock_response = json.loads(load_mock_response('custom-url-category.json'))
    client = create_mocked_client()

    mocker.patch.object(client, 'get_access_token', return_value='access_token')
    mocker.patch.object(client, 'get_custom_url_category_by_id', return_value=mock_response)
    res = mocker.patch.object(client, 'update_custom_url_category')
    update_custom_url_category_command(client, args)
    assert res.call_args[1]['custom_url_category']['list'] == expected_results


@pytest.mark.parametrize(
    # Write and define the expected
    "args",
    [
        {"id": "id1"}
    ]
)
def test_delete_custom_url_category_command(mocker, args):
    from PrismaSASE import delete_custom_url_category_command

    mock_response = json.loads(load_mock_response('custom-url-category.json'))
    client = create_mocked_client()

    mocker.patch.object(client, 'get_access_token', return_value='access_token')
    mocker.patch.object(client, 'delete_custom_url_category', return_value=mock_response)

    result = delete_custom_url_category_command(client, args)

    assert 'deleted successfully' in result.readable_output
    assert 'id1' in result.readable_output


def test_list_external_dynamic_list_command(mocker):
    from PrismaSASE import list_external_dynamic_list_command
    mock_response = json.loads(load_mock_response('list-external-dynamic-list.json'))
    client = create_mocked_client()

    mocker.patch.object(client, 'get_access_token', return_value='access_token')
    mocker.patch.object(client, 'list_external_dynamic_list', return_value=mock_response)
    result = list_external_dynamic_list_command(client, args={})
    assert result.outputs_prefix == 'PrismaSase.ExternalDynamicList'
    assert result.outputs == mock_response.get('data')


EXPECTED_DYNAMIC_LIST = {
    "id": "1",
    "name": "ip",
    "folder": "Shared",
    "type": {
        "ip": {
            "description": "api test",
            "recurring": {
                "hourly": {}
            },
            "certificate_profile": "GP_Log_Certificate",
            "url": "www.test1.com",
            "exception_list": ["www.test.com"]
        }
    }
}


@pytest.mark.parametrize(
    # Write and define the expected
    "args, expected_results",
    [
        ({'id': '1', 'overwrite': True, 'source_url': 'www.test1.com', 'frequency': 'hourly'},
         EXPECTED_DYNAMIC_LIST
         )
    ]
)
def test_update_external_dynamic_list_command(mocker, args, expected_results):
    from PrismaSASE import update_external_dynamic_list_command
    mock_response = json.loads(load_mock_response('external-dynamic-list.json'))
    client = create_mocked_client()

    mocker.patch.object(client, 'get_access_token', return_value='access_token')
    mocker.patch.object(client, 'get_external_dynamic_list_by_id', return_value=mock_response)
    res = mocker.patch.object(client, 'update_external_dynamic_list')
    update_external_dynamic_list_command(client, args)
    assert res.call_args[1]['external_dynamic_list'] == expected_results


@pytest.mark.parametrize(
    # Write and define the expected
    "args",
    [
        {"id": "1"}
    ]
)
def test_delete_external_dynamic_list_command(mocker, args):
    from PrismaSASE import delete_external_dynamic_list_command

    mock_response = json.loads(load_mock_response('external-dynamic-list.json'))
    client = create_mocked_client()

    mocker.patch.object(client, 'get_access_token', return_value='access_token')
    mocker.patch.object(client, 'delete_external_dynamic_list', return_value=mock_response)

    result = delete_external_dynamic_list_command(client, args)

    assert 'deleted successfully' in result.readable_output
    assert '1' in result.readable_output


@pytest.mark.parametrize(
    # Write and define the expected
    "args",
    [
        {"folders": "folder1, folder2"}
    ]
)
def test_run_push_jobs_polling_command_first_poll(mocker, args):
    from PrismaSASE import run_push_jobs_polling_command
    mocker.patch.object(CommonServerPython, 'is_demisto_version_ge', return_value=True)
    client = create_mocked_client()
    mocker.patch.object(client, 'push_candidate_config')
    result = run_push_jobs_polling_command(client, args)
    assert result.scheduled_command


@pytest.mark.parametrize(
    # Write and define the expected
    "args",
    [
        {"job_id": "1", "parent_finished": False}
    ]
)
def test_run_push_jobs_polling_command_second_poll(mocker, args):
    from PrismaSASE import run_push_jobs_polling_command
    mocker.patch.object(CommonServerPython, 'is_demisto_version_ge', return_value=True)
    client = create_mocked_client()
    mock_response = json.loads(load_mock_response('get-config-jobs-by-id.json'))
    mocker.patch.object(client, 'get_config_job_by_id', return_value=mock_response)
    result = run_push_jobs_polling_command(client, args)
    assert result.scheduled_command


@pytest.mark.parametrize(
    # Write and define the expected
    "args",
    [
        {"job_id": "1", "parent_finished": True}
    ]
)
def test_run_push_jobs_polling_command_last_poll(mocker, args):
    from PrismaSASE import run_push_jobs_polling_command
    mocker.patch.object(CommonServerPython, 'is_demisto_version_ge', return_value=True)
    client = create_mocked_client()
    mock_response = json.loads(load_mock_response('list-config-jobs.json'))
    mocker.patch.object(client, 'list_config_jobs', return_value=mock_response)
    result = run_push_jobs_polling_command(client, args)
    assert not result.scheduled_command


def test_address_to_xsoar_format():
    from PrismaSASE import address_to_xsoar_format
    address_object = json.loads(load_mock_response('address-object.json'))
    address_to_xsoar_format(address_object)
    assert address_object['type'] == 'ip_netmask'
    assert address_object['address_value'] == '1.1.1.1/24'
    assert 'ip_netmask' not in address_object


def test_address_group_to_xsoar_format_static_address():
    from PrismaSASE import address_group_to_xsoar_format
    address_group = json.loads(load_mock_response('static-address-group.json'))
    address_group_to_xsoar_format(address_group)
    assert address_group['addresses'] == ['test2']
    assert 'static' not in address_group


def test_address_group_to_xsoar_format():
    from PrismaSASE import address_group_to_xsoar_format
    address_group = json.loads(load_mock_response('dynamic-address-group.json'))
    address_group_to_xsoar_format(address_group)
    assert address_group['dynamic_filter'] == "Microsoft 365 and Hamuzim"
    assert 'dynamic' not in address_group


@pytest.mark.parametrize('input, expected_output', [('external-dynamic-list.json', 'five_minute'),
                                                    ('external-dynamic-list2.json', None)])
def test_external_dynamic_list_to_xsoar_format(input, expected_output):
    """"_summary_"
    Given:
        - A json of external dynamic list
        1. the json contains frequency and exception list
        2. the json doesn't contain frequency
    When:
        - Converting the external dynamic list to xsoar format
    Then:
        - Validate the frequency and exception list
    """
    from PrismaSASE import external_dynamic_list_to_xsoar_format
    dynamic_list = json.loads(load_mock_response(input))
    external_dynamic_list_to_xsoar_format(dynamic_list)
    assert dynamic_list['type'] == 'ip'
    assert dynamic_list['source'] == 'https://www.test.com'
    assert dynamic_list['frequency'] == expected_output
    assert dynamic_list['exception_list'] == ['www.test.com']


@pytest.mark.parametrize(
    # Write and define the expected
    "args, expected_result",
    [
        ({'type': 'ip', 'source_url': 'test.com'},
         'test.com'),
        ({'type': 'predefined_url', 'predefined_url_list': 'panw-auth-portal-exclude-list'},
         'panw-auth-portal-exclude-list'),
        ({'type': 'predefined_ip', 'predefined_ip_list': 'panw-torexit-ip-list'},
         'panw-torexit-ip-list')
    ]
)
def test_get_url_according_to_type(args, expected_result):
    from PrismaSASE import get_url_according_to_type
    url = get_url_according_to_type(args)
    assert url == expected_result


@pytest.mark.parametrize(
    # Write and define the expected
    "args, expected_result",
    [
        ({'type': 'ip', 'predefined_url_list': 'test.com'},
         'Please provide the source_url'),
        ({'type': 'predefined_url', 'source_url': 'panw-auth-portal-exclude-list'},
         'Please provide the predefined_url_list'),
        ({'type': 'predefined_ip', 'source_url': 'panw-torexit-ip-list'},
         'Please provide the predefined_ip_list')
    ]
)
def test_get_url_according_to_type_raise_exception(args, expected_result):
    from PrismaSASE import get_url_according_to_type

    with pytest.raises(Exception) as e:
        get_url_according_to_type(args)

    assert expected_result in str(e.value)


@pytest.mark.parametrize(
    # Write and define the expected
    "args, expected_result",
    [
        ({'frequency': 'hourly'},
         {'hourly': {}}),
        ({'frequency': 'daily', 'frequency_hour': '00'},
         {'daily': {'at': '00'}}),
        ({'frequency': 'weekly', 'day_of_week': 'sunday', 'frequency_hour': '00'},
         {'weekly': {'day_of_week': 'sunday', 'at': '00'}}),
        ({'frequency': 'monthly', 'day_of_month': '1', 'frequency_hour': '00'},
         {'monthly': {'day_of_month': '1', 'at': '00'}})
    ]
)
def test_build_recurring_according_to_params(args, expected_result):
    from PrismaSASE import build_recurring_according_to_params

    frequency = build_recurring_according_to_params(args)
    assert frequency == expected_result


@pytest.mark.parametrize(
    # Write and define the expected
    "args, expected_result",
    [
        ({'frequency': 'daily'},
         'Please provide the frequency_hour'),
        ({'frequency': 'weekly', 'frequency_hour': '00'},
         'Please provide the day_of_week'),
        ({'frequency': 'weekly', 'day_of_week': '1'},
         'Please provide the frequency_hour'),
        ({'frequency': 'monthly', 'frequency_hour': '00'},
         'Please provide the day_of_month')
    ]
)
def test_build_recurring_according_to_params_raise_exception(args, expected_result):
    from PrismaSASE import build_recurring_according_to_params

    with pytest.raises(Exception) as e:
        build_recurring_according_to_params(args)

    assert expected_result in str(e.value)


@pytest.mark.parametrize(
    # Write and define the expected
    "args, expected_result",
    [
        ({'page': '2', 'page_size': '2'},
         {'limit': 2, 'offset': 2}),
        ({'limit': '2'},
         {'limit': 2}),
        ({},
         {'limit': 50})
    ]
)
def test_get_pagination_params(args, expected_result):
    from PrismaSASE import get_pagination_params

    pagination_params = get_pagination_params(args)
    assert pagination_params == expected_result


def test_quarantine_host(mocker):
    """"_summary_"
    Given:
        - A host_id to be added to the quarantine list
    When:
        - call to quarantine_host_command
    Then:
        - Validate the command pass as expected
    """
    from PrismaSASE import quarantine_host_command
    client = create_mocked_client()
    host_id = 'test_host'

    mocker.patch.object(client, 'get_access_token', return_value='access_token')
    mocker.patch.object(client, '_http_request', return_value={'host_id': host_id})

    result = quarantine_host_command(client, {'host_id': host_id})

    assert all(msg in result.readable_output for msg in ['Host Quarantined', host_id])


def test_build_security_rule():
    args = {"action": "allow",
            "application": "app1,app2",
            "category": "cat1,cat2",
            "description": "Test rule description",
            "destination": "dest1,dest2",
            "disabled": "no",
            "from": "zone1,zone2",
            "profile_setting": "group1,group2",
            "service": "service1,service2",
            "source": "src1,src2",
            "source_user": "user1;user2",
            "tag": "tag1,tag2",
            "to": "zone3,zone4", }
    prisma_sase_client = create_mocked_client()
    res = prisma_sase_client.build_security_rule(args)
    expected = {
        "action": "allow",
        "application": ["app1", "app2"],
        "category": ["cat1", "cat2"],
        "description": "Test rule description",
        "destination": ["dest1", "dest2"],
        "disabled": "no",
        "from": ["zone1", "zone2"],
        "profile_setting": {"group": ["group1", "group2"]},
        "service": ["service1", "service2"],
        "source": ["src1", "src2"],
        "source_user": ["user1", "user2"],
        "tag": ["tag1", "tag2"],
        "to": ["zone3", "zone4"],
    }
    assert res == expected


def test_get_cie_user(mocker):
    """
    Given:
        - A user to be retrieved.
    When:
        - Call to get_cie_user_command.
    Then:
        - Validate the command pass and the output is as expected.
    """
    from PrismaSASE import get_cie_user_command
    client = create_mocked_client()
    args = {'attributes_to_filter_by': 'Distinguished Name, Unique Identifier, Common-Name, Name, User Principal Name',
            'attributes_to_return': 'Common-Name, Unique Identifier, Manager, User Principal Name, Name, Distinguished Name',
            'domain': 'example.com', 'operator': 'Equal',
            'value_for_filter': 'CN=Test,UID=TestID,DC=example,DC=com'}
    mocked_resp = json.loads(load_mock_response('./cie_get_user.json'))

    mocker.patch.object(client, 'get_access_token', return_value='access_token')
    mocker.patch.object(client, '_http_request', return_value=mocked_resp.get('api_response'))

    result = get_cie_user_command(client, args)

    assert result.outputs == mocked_resp.get('expected_result')


def test_get_cie_user_prepare_args():
    """
    Given:
        - Args for the get_cie_user_command
    When:
        - Call to prepare_args_for_get_cie_user.
    Then:
        - Validate the parsed argument as the API expected.
    """
    from PrismaSASE import cie_user_prepare_args

    args = {'attributes_to_filter_by': 'Distinguished Name, Unique Identifier, Common-Name, Name, User Principal Name',
            'attributes_to_return': 'Common-Name, Unique Identifier, Manager, User Principal Name, Name, Distinguished Name',
            'domain': 'example.com', 'operator': 'Equal',
            'value_for_filter': 'CN=Test,UID=TestID,DC=example,DC=com'}

    expected_result = {'domain': 'example.com',
                       'attrs': ['Unique Identifier', 'Common-Name',
                                 'Distinguished Name', 'User Principal Name', 'Name',
                                 'Manager'], 'name': {
                           'attrNameOR': ['Distinguished Name', 'Unique Identifier',
                                          'Common-Name', 'Name', 'User Principal Name'],
                           'attrValue': 'CN=Test,UID=TestID,DC=example,DC=com', 'match': 'equal'}, 'useNormalizedAttrs': 'True'}
    res = cie_user_prepare_args(args)
    for key, value in res.items():
        if isinstance(value, list):
            value.sort()
            expected_result.get(key).sort()
        assert value == expected_result.get(key)
