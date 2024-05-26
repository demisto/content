"""Base Integration for Cortex XSOAR - Unit Tests file

Pytest Unit Tests: all funcion names must start with "test_"

More details: https://xsoar.pan.dev/docs/integrations/unit-testing

MAKE SURE YOU REVIEW/REPLACE ALL THE COMMENTS MARKED AS "TODO"

You must add at least a Unit Test function for every XSOAR command
you are implementing with your integration
"""

import json

from Packs.ThalesCipherTrustManager.Integrations.ThalesCipherTrustManager.ThalesCipherTrustManager import CommandArguments

MOCKER_HTTP_METHOD = 'ThalesCipherTrustManager.CipherTrustClient._http_request'

def util_load_json(path):
    with open(path, encoding='utf-8') as f:
        return json.loads(f.read())


import pytest
from unittest.mock import patch
from CommonServerPython import CommandResults, tableToMarkdown

#todo: test pagination?
GROUPS_LIST_TEST_ARGS = [
    {
        CommandArguments.GROUP_NAME: 'Admins',
        CommandArguments.USER_ID: '123',
        CommandArguments.CONNECTION: 'conn1',
        CommandArguments.CLIENT_ID: '456',
        CommandArguments.LIMIT: '10',
        CommandArguments.PAGE: '1',
        CommandArguments.PAGE_SIZE: '10'
    },
    {
        CommandArguments.GROUP_NAME: 'Users',
        CommandArguments.LIMIT: '5'
    },
    {
        CommandArguments.PAGE: '2',
        CommandArguments.PAGE_SIZE: '5'
    }
]


@pytest.mark.parametrize('args', GROUPS_LIST_TEST_ARGS)
@patch(MOCKER_HTTP_METHOD)
@patch('CommonServerPython.tableToMarkdown')
def test_group_list_command(mock_get_group_list, args):
    from ThalesCipherTrustManager import CipherTrustClient, group_list_command
    mock_get_group_list.return_value = util_load_json('test_data/group_list.json')

    client = CipherTrustClient(username='user', password='pass', base_url='https://example.com', verify=False, proxy=False)

    result = group_list_command(client, args)

    assert isinstance(result, CommandResults)
    assert result.outputs_prefix == 'CipherTrust.Group'
    assert result.outputs == mock_get_group_list.return_value
    assert result.raw_response == mock_get_group_list.return_value
    assert result.readable_output == 'groups'


def test_group_create_command():
    pass


def test_group_delete_command():
    pass


def test_group_update_command():
    pass


def test_user_to_group_add_command():
    pass


def test_user_to_group_remove_command():
    pass


def test_users_list_command():
    pass


def test_user_create_command():
    pass


def test_user_update_command():
    pass


def test_user_delete_command():
    pass


def test_user_password_change_command():
    pass


def test_local_ca_create_command():
    pass


def test_local_ca_list_command():
    pass


def test_local_ca_update_command():
    pass


def test_local_ca_delete_command():
    pass


def test_local_ca_self_sign_command():
    pass


def test_local_ca_install_command():
    pass


def test_certificate_issue_command():
    pass


def test_certificate_list_command():
    pass


def test_local_certificate_delete_command():
    pass


def test_certificate_revoke_command():
    pass


def test_certificate_resume_command():
    pass


def test_external_certificate_upload_command():
    pass


def test_external_certificate_delete_command():
    pass


def test_external_certificate_update_command():
    pass


def test_external_certificate_list_command():
    pass
