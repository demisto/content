import json
import io
import pytest
from F5Silverline import get_ip_objects_list_command, add_ip_objects_command, delete_ip_objects_command, Client


def create_client(base_url: str, verify: bool, headers: dict, proxy: bool):
    return Client(base_url=base_url, verify=verify, proxy=proxy, headers=headers)


def util_load_json(path):
    with io.open(path, mode='r', encoding='utf-8') as f:
        return json.loads(f.read())


IP_ADDRESSES_TO_ADD = [
    ({'list_type': 'denylist', 'cidr_range': '1.2.3.4'},
     'IP objects wehre added successfully into the denylist\n| IP |\n| - |\n| 1.2.3.4/32 |'),
    ({'list_type': 'allowlist', 'cidr_range': '1.2.3.4', 'note': "test"},
     "IP objects wehre added successfully into the allowlist\n| IP |\n| - |\n| 1.2.3.4/32 |"),
    ({'list_type': 'allowlist', 'cidr_range': '1.2.3.4,1.2.3.4/23', 'note': "test"},
     "IP objects wehre added successfully into the allowlist\n| IP |\n| - |\n| 1.2.3.4/32 |\n| 1.2.3.4/23 |"),
]

IP_ADDRESSES_TO_DELETE = [
    ({'list_type': 'denylist', 'object_id': '850f7418-2ac9'},
     "IP object with ID: 850f7418-2ac9 deleted successfully from the denylist list. \n", True),
    ({'list_type': 'allowlist', 'object_id': '850f7418-2ac9', 'note': "test"},
     "IP object with ID: 850f7418-2ac9 deleted successfully from the allowlist list. \n", True),
    ({'list_type': 'allowlist', 'object_id': '850f7418-2ac9', 'note': "test"},
     "", False),
]

IP_OBJECT_GET_LIST = [({'list_type': 'denylist', 'object_id': ['id1']}, 'ip_object_list_by_id.json'),
                      ({'list_type': 'denylist'}, 'ip_object_list_no_id.json'),
                      ({'list_type': 'denylist', 'page_number': '1', 'page_size': '1'}, 'ip_object_list_no_id.json'),
                      ({'list_type': 'denylist', 'page_number': '1', 'page_size': '1',
                        'object_id': ['id1']}, 'ip_object_list_by_id.json')]


@pytest.mark.parametrize('args,expected_output', IP_ADDRESSES_TO_ADD)
def test_add_ip_objects_command(mocker, args, expected_output):
    """
    Given:
        - Got IP address of a new IP object to add to a list_type.

    When:
        - After asked for f5-silverline-ip-object-add command.

    Then:
        - Validating that the object was created successfully.
        - Validating the returned human readable.
    """
    mocker.patch.object(Client, "request_ip_objects")
    return_results_mock = mocker.patch('F5Silverline.return_results')
    client = create_client(base_url='https://portal.f5silverline.com/api/v1/ip_lists', verify=False, headers={},
                           proxy=False)
    add_ip_objects_command(client, args)
    assert return_results_mock.call_args[0][0].readable_output == expected_output


@pytest.mark.parametrize('args,expected_output, is_object_exist', IP_ADDRESSES_TO_DELETE)
def test_delete_ip_objects_command(mocker, args, expected_output, is_object_exist):
    """
    Given:
        - Got id of an IP object to delete from a list_type.

    When:
        - After asked for f5-silverline-ip-object-delete command.

    Then:
        - Validating that the object was deleted successfully.
        - Validating the returned human readable.
    """
    import F5Silverline
    mocker.patch.object(Client, "request_ip_objects")
    mocker.patch.object(F5Silverline, "is_object_id_exist", return_value=is_object_exist)
    client = create_client(base_url='https://portal.f5silverline.com/api/v1/ip_lists', verify=False, headers={},
                           proxy=False)
    result = delete_ip_objects_command(client, args)
    if not is_object_exist:
        assert not expected_output
    else:
        assert result.readable_output == expected_output


@pytest.mark.parametrize('args, response_json', IP_OBJECT_GET_LIST)
def test_get_ip_objects_list_command(mocker, args, response_json):
    """
    Given:
        - Got list_type in order to get the data from.

    When:
        - After asked for f5-silverline-ip-object-list command

    Then:
        - Validating that the list returned successfully to the right context path.
        - If the user gave unique ids, validating that they returned as expected.
    """
    client = create_client(base_url='https://portal.f5silverline.com/api/v1/ip_lists', verify=False, headers={},
                           proxy=False)
    response = util_load_json(f"test_data/{response_json}")
    mocker.patch.object(Client, "request_ip_objects", return_value=response)
    results = get_ip_objects_list_command(client, args)

    assert results.outputs_prefix == "F5Silverline"
    assert results.outputs_key_field == "id"
    assert [results.outputs['IPObjectList'][0].get('id')] == args.get('object_id', ['id1'])
    assert results.outputs['IPObjectList'][0].get('attributes') == {'ip': '1.2.3.4', 'mask': '32', 'duration': 0,
                                                                    'expires_at': 'None',
                                                                    'list_target': 'proxy'}
    assert results.outputs['IPObjectList'][0].get('links') == {
        'self': 'https://portal.f5silverline.com/api/v1/ip_lists/denylist/ip_objects/id1?list_target=proxy'}
