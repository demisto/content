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

''' CONSTANTS '''

CONTEXT_OUTPUT_PREFIX = "CipherTrust."
GROUP_CONTEXT_OUTPUT_PREFIX = f"{CONTEXT_OUTPUT_PREFIX}Group"
USERS_CONTEXT_OUTPUT_PREFIX = f"{CONTEXT_OUTPUT_PREFIX}Users"
LOCAL_CA_CONTEXT_OUTPUT_PREFIX = f"{CONTEXT_OUTPUT_PREFIX}LocalCA"
CA_SELF_SIGN_CONTEXT_OUTPUT_PREFIX = f"{CONTEXT_OUTPUT_PREFIX}CASelfSign"
CA_INSTALL_CONTEXT_OUTPUT_PREFIX = f"{CONTEXT_OUTPUT_PREFIX}CAInstall"
CA_CERTIFICATE_CONTEXT_OUTPUT_PREFIX = f"{CONTEXT_OUTPUT_PREFIX}CACertificate"
EXTERNAL_CERTIFICATE_CONTEXT_OUTPUT_PREFIX = f"{CONTEXT_OUTPUT_PREFIX}ExternalCertificate"

class CommandArguments:
    PAGE = 'page'
    PAGE_SIZE = 'page_size'
    LIMIT = 'limit'
    GROUP_NAME = 'group_name'
    USER_ID = 'user_id'
    CONNECTION = 'connection'
    CLIENT_ID = 'client_id'
    NAME = 'name'
    DESCRIPTION = 'description'
    FORCE = 'force'
    USERNAME = 'username'
    EMAIL = 'email'
    GROUPS = 'groups'
    EXCLUDE_GROUPS = 'exclude_groups'
    AUTH_DOMAIN_NAME = 'auth_domain_name'
    ACCOUNT_EXPIRED = 'account_expired'
    ALLOWED_AUTH_METHODS = 'allowed_auth_methods'
    ALLOWED_CLIENT_TYPES = 'allowed_client_types'
    PASSWORD_POLICY = 'password_policy'
    RETURN_GROUPS = 'return_groups'
    CERTIFICATE_SUBJECT_DN = 'certificate_subject_dn'
    EXPIRES_AT = 'expires_at'
    IS_DOMAIN_USER = 'is_domain_user'
    PREVENT_UI_LOGIN = 'prevent_ui_login'
    PASSWORD_CHANGE_REQUIRED = 'password_change_required'
    PASSWORD = 'password'
    FAILED_LOGINS_COUNT = 'failed_logins_count'
    NEW_PASSWORD = 'new_password'
    AUTH_DOMAIN = 'auth_domain'
    CN = 'cn'
    ALGORITHM = 'algorithm'
    COPY_FROM_CA = 'copy_from_ca'
    DNS_NAMES = 'dns_names'
    IP = 'ip'
    NAME_FIELDS_RAW_JSON = 'name_fields_raw_json'
    NAME_FIELDS_JSON_ENTRY_ID = 'name_fields_json_entry_id'
    SIZE = 'size'
    SUBJECT = 'subject'
    LOCAL_CA_ID = 'local_ca_id'
    CHAINED = 'chained'
    ISSUER = 'issuer'
    STATE = 'state'
    CERT = 'cert'
    ALLOW_CLIENT_AUTHENTICATION = 'allow_client_authentication'
    ALLOW_USER_AUTHENTICATION = 'allow_user_authentication'
    DURATION = 'duration'
    NOT_AFTER = 'not_after'
    NOT_BEFORE = 'not_before'
    PARENT_ID = 'partent_id'
    CA_ID = 'ca_id'
    CSR = 'csr'
    PURPOSE = 'purpose'
    ID = 'id'
    CERT_ID = 'cert_id'
    REASON = 'reason'
    PARENT = 'parent'
    EXTERNAL_CA_ID = 'external_ca_id'
    SERIAL_NUMBER = 'serial_number'


'''
Mock Data
'''

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
def test_group_list_command(mock_get_group_list, args):
    from ThalesCipherTrustManager import CipherTrustClient, group_list_command
    mock_get_group_list.return_value = util_load_json('test_data/group_list.json')

    client = CipherTrustClient(username='user', password='pass', base_url='https://example.com', verify=False, proxy=False)

    result = group_list_command(client, args)

    assert isinstance(result, CommandResults)
    assert result.outputs_prefix == GROUP_CONTEXT_OUTPUT_PREFIX
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
