import json
import io

import pytest
from F5_Silverline import get_ip_objects_list_command, add_ip_objects_command, delete_ip_objects_command, Client


def create_client(base_url: str, verify: bool, headers: dict, proxy: bool):
    return Client(base_url=base_url, verify=verify, proxy=proxy, headers=headers)


IP_ADDRESSES_TO_ADD = [
    ({'list_type': 'denylist', 'IP': '1.2.3.4'}, "IP object with IP address: 1.2.3.4 created successfully."),
    ({'list_type': 'allowlist', 'IP': '1.2.3.4', 'note': "test"},
     "IP object with IP address: 1.2.3.4 created successfully."),
]

IP_ADDRESSES_TO_DELETE = [
    ({'list_type': 'denylist', 'object_id': '850f7418-2ac9'}, "IP object with ID: 850f7418-2ac9 deleted successfully."),
    ({'list_type': 'allowlist', 'object_id': '850f7418-2ac9', 'note': "test"},
     "IP object with ID: 850f7418-2ac9 deleted successfully."),
]


@pytest.mark.parametrize('args,expected_output', IP_ADDRESSES_TO_ADD)
def test_add_ip_objects_command(mocker, args, expected_output):
    mocker.patch.object(Client, "request_ip_objects")
    client = create_client(base_url='https://portal.f5silverline.com/api/v1/ip_lists', verify=False, headers={},
                           proxy=False)
    result = add_ip_objects_command(client, args)
    assert result.readable_output == expected_output


@pytest.mark.parametrize('args,expected_output', IP_ADDRESSES_TO_DELETE)
def test_delete_ip_objects_command(mocker, args, expected_output):
    mocker.patch.object(Client, "request_ip_objects")
    client = create_client(base_url='https://portal.f5silverline.com/api/v1/ip_lists', verify=False, headers={},
                           proxy=False)
    result = delete_ip_objects_command(client, args)
    assert result.readable_output == expected_output


def util_load_json(path):
    with io.open(path, mode='r', encoding='utf-8') as f:
        return json.loads(f.read())
