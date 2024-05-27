import json

MOCKER_HTTP_METHOD = 'ThalesCipherTrustManager.CipherTrustClient._http_request'
MOCK_USERNAME = 'user'
MOCK_PASSWORD = 'password123'
MOCK_SERVER_URL = 'https://example.com'


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
    {},  # No arguments
    {CommandArguments.GROUP_NAME: 'group1'},  # Only GROUP_NAME
    {CommandArguments.USER_ID: 'user1'},  # Only USER_ID
    {CommandArguments.CONNECTION: 'connection1'},  # Only CONNECTION
    {CommandArguments.CLIENT_ID: 'client1'},  # Only CLIENT_ID
    {
        CommandArguments.GROUP_NAME: 'group2',
        CommandArguments.USER_ID: 'user2'
    },  # Combination of GROUP_NAME and USER_ID
    {
        CommandArguments.CONNECTION: 'connection2',
        CommandArguments.CLIENT_ID: 'client2'
    },  # Combination of CONNECTION and CLIENT_ID
    {
        CommandArguments.GROUP_NAME: 'group3',
        CommandArguments.USER_ID: 'user3',
        CommandArguments.CONNECTION: 'connection3',
        CommandArguments.CLIENT_ID: 'client3'
    }  # All arguments
]

GROUP_CREATE_TEST_ARGS = [
    {
        CommandArguments.NAME: 'group1',
    },
    {
        CommandArguments.NAME: 'group2',
        CommandArguments.DESCRIPTION: 'description2'
    }
]
GROUP_DELETE_TEST_ARGS = [
    {CommandArguments.GROUP_NAME: 'group1'},
    {CommandArguments.GROUP_NAME: 'group2', CommandArguments.FORCE: 'true'}
]
GROUP_UPDATE_TEST_ARGS = [
    {
        CommandArguments.GROUP_NAME: 'group1',
        CommandArguments.DESCRIPTION: 'description1_updated'
    }
]
USER_TO_GROUP_ADD_TEST_ARGS = []
USER_TO_GROUP_REMOVE_TEST_ARGS = []
USERS_LIST_TEST_ARGS = []
USER_CREATE_TEST_ARGS = []
USER_UPDATE_TEST_ARGS = []
USER_DELETE_TEST_ARGS = []
USER_PASSWORD_CHANGE_TEST_ARGS = []
LOCAL_CA_CREATE_TEST_ARGS = []
LOCAL_CA_LIST_TEST_ARGS = []
LOCAL_CA_UPDATE_TEST_ARGS = []
LOCAL_CA_DELETE_TEST_ARGS = []
LOCAL_CA_SELF_SIGN_TEST_ARGS = []
LOCAL_CA_INSTALL_TEST_ARGS = []
CERTIFICATE_ISSUE_TEST_ARGS = []
CERTIFICATE_LIST_TEST_ARGS = []
LOCAL_CERTIFICATE_DELETE_TEST_ARGS = []
CERTIFICATE_REVOKE_TEST_ARGS = []
CERTIFICATE_RESUME_TEST_ARGS = []
EXTERNAL_CERTIFICATE_UPLOAD_TEST_ARGS = []
EXTERNAL_CERTIFICATE_DELETE_TEST_ARGS = []
EXTERNAL_CERTIFICATE_UPDATE_TEST_ARGS = []
EXTERNAL_CERTIFICATE_LIST_TEST_ARGS = []

''' HELPER FUNCTIONS TESTS'''


@pytest.mark.parametrize('limit, page, page_size, expected_skip, expected_limit',
                         [('100', '2', '25', 25, 25), ('200', None, None, 0, 200), (None, '2', '30', 30, 30),
                          (None, '2', None, 50, 50), (None, '3', None, 100, 50)])
def test_derive_skip_and_limit_for_pagination(limit, page, page_size, expected_skip, expected_limit):
    from ThalesCipherTrustManager import derive_skip_and_limit_for_pagination
    assert derive_skip_and_limit_for_pagination(limit, page, page_size) == (expected_skip, expected_limit)


@pytest.mark.parametrize('limit, page, page_size',
                         [(None, '1', '101'), (None, 'invalid', '30'), ('invalid', None, None)])
def test_derive_skip_and_limit_for_pagination_invalid_input(limit, page, page_size):
    from ThalesCipherTrustManager import derive_skip_and_limit_for_pagination
    with pytest.raises(ValueError):
        derive_skip_and_limit_for_pagination(limit, page, page_size)


@pytest.mark.parametrize('expires_at_arg, expected_output',
                         [("", ""), ("2023-05-26T15:30:00", "2023-05-26T15:30:00.000000Z"), (None, None)])
def test_add_expires_at_param(expires_at_arg, expected_output):
    from ThalesCipherTrustManager import add_expires_at_param
    request_data = {}
    add_expires_at_param(request_data, expires_at_arg)
    assert request_data['expires_at'] == expected_output


def test_add_expires_at_param_invalid_input():
    from ThalesCipherTrustManager import add_expires_at_param
    with pytest.raises(ValueError):
        request_data = {}
        add_expires_at_param(request_data, "invalid-datetime")
        assert request_data['expires_at'] is None


''' COMMAND FUNCTIONS TESTS '''


@pytest.mark.parametrize('args', GROUPS_LIST_TEST_ARGS)
@patch(MOCKER_HTTP_METHOD)
def test_group_list_command(mock_get_group_list, args):
    from ThalesCipherTrustManager import CipherTrustClient, group_list_command
    mock_get_group_list.return_value = util_load_json('test_data/mock_group_list_response.json')

    client = CipherTrustClient(username=MOCK_USERNAME, password=MOCK_PASSWORD, server_url=MOCK_SERVER_URL, verify=False,
                               proxy=False)

    result = group_list_command(client, args)

    assert isinstance(result, CommandResults)
    assert result.outputs_prefix == GROUP_CONTEXT_OUTPUT_PREFIX
    assert result.outputs == mock_get_group_list.return_value
    assert result.raw_response == mock_get_group_list.return_value


@pytest.mark.parametrize('args', GROUP_CREATE_TEST_ARGS)
@patch(MOCKER_HTTP_METHOD)
def test_group_create_command(mock_create_group, args):
    from ThalesCipherTrustManager import CipherTrustClient, group_create_command
    mock_create_group.return_value = util_load_json('test_data/mock_group_create_response.json')

    client = CipherTrustClient(username=MOCK_USERNAME, password=MOCK_PASSWORD, server_url=MOCK_SERVER_URL, verify=False,
                               proxy=False)

    result = group_create_command(client, args)

    assert isinstance(result, CommandResults)
    assert result.outputs_prefix == GROUP_CONTEXT_OUTPUT_PREFIX
    assert result.outputs == mock_create_group.return_value
    assert result.raw_response == mock_create_group.return_value


@pytest.mark.parametrize('args', GROUP_DELETE_TEST_ARGS)
@patch(MOCKER_HTTP_METHOD)
def test_group_delete_command(mock_delete_group, args):
    from ThalesCipherTrustManager import CipherTrustClient, group_delete_command
    mock_delete_group.return_value = util_load_json('test_data/mock_group_delete_response.json')

    client = CipherTrustClient(username=MOCK_USERNAME, password=MOCK_PASSWORD, server_url=MOCK_SERVER_URL, verify=False,
                               proxy=False)

    result = group_delete_command(client, args)

    assert isinstance(result, CommandResults)
    assert result.outputs_prefix is None
    assert result.outputs == mock_delete_group.return_value
    assert result.raw_response == mock_delete_group.return_value
    assert result.readable_output == f'{args.get(CommandArguments.GROUP_NAME)} has been deleted successfully!'


@pytest.mark.parametrize('args', GROUP_UPDATE_TEST_ARGS)
@patch(MOCKER_HTTP_METHOD)
def test_group_update_command(mock_update_group, args):
    from ThalesCipherTrustManager import CipherTrustClient, group_create_command
    mock_update_group.return_value = util_load_json('test_data/mock_group_update_response.json')

    client = CipherTrustClient(username=MOCK_USERNAME, password=MOCK_PASSWORD, server_url=MOCK_SERVER_URL, verify=False,
                               proxy=False)

    result = group_create_command(client, args)

    assert isinstance(result, CommandResults)
    assert result.outputs_prefix == GROUP_CONTEXT_OUTPUT_PREFIX
    assert result.outputs == mock_update_group.return_value
    assert result.raw_response == mock_update_group.return_value


@pytest.mark.parametrize('args', USER_TO_GROUP_ADD_TEST_ARGS)
@patch(MOCKER_HTTP_METHOD)
def test_user_to_group_add_command(mock_add_user_to_group, args):
    from ThalesCipherTrustManager import CipherTrustClient, user_to_group_add_command
    mock_add_user_to_group.return_value = util_load_json('test_data/mock_user_to_group_add_response.json')

    client = CipherTrustClient(username=MOCK_USERNAME, password=MOCK_PASSWORD, server_url=MOCK_SERVER_URL, verify=False,
                               proxy=False)

    result = user_to_group_add_command(client, args)

    assert isinstance(result, CommandResults)
    assert result.outputs_prefix == GROUP_CONTEXT_OUTPUT_PREFIX
    assert result.outputs == mock_add_user_to_group.return_value
    assert result.raw_response == mock_add_user_to_group.return_value


@pytest.mark.parametrize('args', USER_TO_GROUP_REMOVE_TEST_ARGS)
@patch(MOCKER_HTTP_METHOD)
def test_user_to_group_remove_command(mock_remove_user_from_group, args):
    from ThalesCipherTrustManager import CipherTrustClient, user_to_group_remove_command
    mock_remove_user_from_group.return_value = util_load_json('test_data/mock_user_to_group_remove_response.json')

    client = CipherTrustClient(username=MOCK_USERNAME, password=MOCK_PASSWORD, server_url=MOCK_SERVER_URL, verify=False,
                               proxy=False)

    result = user_to_group_remove_command(client, args)

    assert isinstance(result, CommandResults)
    assert result.outputs_prefix is None
    assert result.outputs == mock_remove_user_from_group.return_value
    assert result.raw_response == mock_remove_user_from_group.return_value
    assert result.readable_output == f'{args[CommandArguments.USER_ID]} has been deleted successfully from {args[CommandArguments.GROUP_NAME]}'


@pytest.mark.parametrize('args', USERS_LIST_TEST_ARGS)
@patch(MOCKER_HTTP_METHOD)
def test_users_list_command(mock_get_users_list, args):
    from ThalesCipherTrustManager import CipherTrustClient, users_list_command
    mock_get_users_list.return_value = util_load_json('test_data/mock_users_list_response.json')

    client = CipherTrustClient(username=MOCK_USERNAME, password=MOCK_PASSWORD, server_url=MOCK_SERVER_URL, verify=False,
                               proxy=False)

    result = users_list_command(client, args)

    assert isinstance(result, CommandResults)
    assert result.outputs_prefix == USERS_CONTEXT_OUTPUT_PREFIX
    assert result.outputs == mock_get_users_list.return_value
    assert result.raw_response == mock_get_users_list.return_value


@patch(MOCKER_HTTP_METHOD)
def test_users_list_command_id_provided(mock_get_user):
    from ThalesCipherTrustManager import CipherTrustClient, users_list_command
    mock_get_user.return_value = util_load_json('test_data/mock_users_list_id_provided_response.json')

    client = CipherTrustClient(username=MOCK_USERNAME, password=MOCK_PASSWORD, server_url=MOCK_SERVER_URL, verify=False,
                               proxy=False)
    #todo: pass user_id
    args = {}

    result = users_list_command(client, args)

    assert isinstance(result, CommandResults)
    assert result.outputs_prefix == USERS_CONTEXT_OUTPUT_PREFIX
    assert result.outputs == {'resources': [mock_get_user.return_value]}
    assert result.raw_response == mock_get_user.return_value


@pytest.mark.parametrize('args', USER_CREATE_TEST_ARGS)
@patch(MOCKER_HTTP_METHOD)
def test_user_create_command(mock_create_user, args):
    from ThalesCipherTrustManager import CipherTrustClient, user_create_command
    mock_create_user.return_value = util_load_json('test_data/mock_user_create_response.json')

    client = CipherTrustClient(username=MOCK_USERNAME, password=MOCK_PASSWORD, server_url=MOCK_SERVER_URL, verify=False,
                               proxy=False)

    result = user_create_command(client, args)

    assert isinstance(result, CommandResults)
    assert result.outputs_prefix == USERS_CONTEXT_OUTPUT_PREFIX
    assert result.outputs == mock_create_user.return_value
    assert result.raw_response == mock_create_user.return_value


@pytest.mark.parametrize('args', USER_UPDATE_TEST_ARGS)
@patch(MOCKER_HTTP_METHOD)
def test_user_update_command(mock_update_user, args):
    from ThalesCipherTrustManager import CipherTrustClient, user_update_command
    mock_update_user.return_value = util_load_json('test_data/mock_user_update_response.json')

    client = CipherTrustClient(username=MOCK_USERNAME, password=MOCK_PASSWORD, server_url=MOCK_SERVER_URL, verify=False,
                               proxy=False)

    result = user_update_command(client, args)

    assert isinstance(result, CommandResults)
    assert result.outputs_prefix == USERS_CONTEXT_OUTPUT_PREFIX
    assert result.outputs == mock_update_user.return_value
    assert result.raw_response == mock_update_user.return_value


@pytest.mark.parametrize('args', USER_DELETE_TEST_ARGS)
@patch(MOCKER_HTTP_METHOD)
def test_user_delete_command(mock_delete_user, args):
    from ThalesCipherTrustManager import CipherTrustClient, user_delete_command
    mock_delete_user.return_value = util_load_json('test_data/mock_user_delete_response.json')

    client = CipherTrustClient(username=MOCK_USERNAME, password=MOCK_PASSWORD, server_url=MOCK_SERVER_URL, verify=False,
                               proxy=False)

    result = user_delete_command(client, args)

    assert isinstance(result, CommandResults)
    assert result.outputs_prefix is None
    assert result.outputs == mock_delete_user.return_value
    assert result.raw_response == mock_delete_user.return_value
    assert result.readable_output == f'{args[CommandArguments.USER_ID]} has been deleted successfully!'


@pytest.mark.parametrize('args', USER_PASSWORD_CHANGE_TEST_ARGS)
@patch(MOCKER_HTTP_METHOD)
def test_user_password_change_command(mock_change_current_user_password, args):
    from ThalesCipherTrustManager import CipherTrustClient, user_password_change_command
    mock_change_current_user_password.return_value = util_load_json('test_data/mock_user_password_change_response.json')

    client = CipherTrustClient(username=MOCK_USERNAME, password=MOCK_PASSWORD, server_url=MOCK_SERVER_URL, verify=False,
                               proxy=False)

    result = user_password_change_command(client, args)

    assert isinstance(result, CommandResults)
    assert result.outputs_prefix is None
    assert result.outputs == mock_change_current_user_password.return_value
    assert result.raw_response == mock_change_current_user_password.return_value
    assert result.readable_output == f'Password has been changed successfully for {args[CommandArguments.USERNAME]}!'


@pytest.mark.parametrize('args', LOCAL_CA_CREATE_TEST_ARGS)
@patch(MOCKER_HTTP_METHOD)
def test_local_ca_create_command(mock_create_local_ca, args):
    from ThalesCipherTrustManager import CipherTrustClient, local_ca_create_command
    mock_create_local_ca.return_value = util_load_json('test_data/mock_local_ca_create_response.json')

    client = CipherTrustClient(username=MOCK_USERNAME, password=MOCK_PASSWORD, server_url=MOCK_SERVER_URL, verify=False,
                               proxy=False)

    result = local_ca_create_command(client, args)

    assert isinstance(result, CommandResults)
    assert result.outputs_prefix == LOCAL_CA_CONTEXT_OUTPUT_PREFIX
    assert result.outputs == mock_create_local_ca.return_value
    assert result.raw_response == mock_create_local_ca.return_value


@pytest.mark.parametrize('args', LOCAL_CA_LIST_TEST_ARGS)
@patch(MOCKER_HTTP_METHOD)
def test_local_ca_list_command(mock_get_local_ca_list, args):
    from ThalesCipherTrustManager import CipherTrustClient, local_ca_list_command
    mock_get_local_ca_list.return_value = util_load_json('test_data/mock_local_ca_list_response.json')

    client = CipherTrustClient(username=MOCK_USERNAME, password=MOCK_PASSWORD, server_url=MOCK_SERVER_URL, verify=False,
                               proxy=False)

    result = local_ca_list_command(client, args)

    assert isinstance(result, CommandResults)
    assert result.outputs_prefix == LOCAL_CA_CONTEXT_OUTPUT_PREFIX
    assert result.outputs == mock_get_local_ca_list.return_value
    assert result.raw_response == mock_get_local_ca_list.return_value


@patch(MOCKER_HTTP_METHOD)
def test_local_ca_list_command_id_provided(mock_get_local_ca):
    from ThalesCipherTrustManager import CipherTrustClient, local_ca_list_command
    mock_get_local_ca.return_value = util_load_json('test_data/mock_local_ca_list_id_provided_response.json')

    client = CipherTrustClient(username=MOCK_USERNAME, password=MOCK_PASSWORD, server_url=MOCK_SERVER_URL, verify=False,
                               proxy=False)
    # todo: pass id
    args = {}
    result = local_ca_list_command(client, args)

    assert isinstance(result, CommandResults)
    assert result.outputs_prefix == LOCAL_CA_CONTEXT_OUTPUT_PREFIX
    assert result.outputs == {'resources': [mock_get_local_ca.return_value]}
    assert result.raw_response == mock_get_local_ca.return_value


@pytest.mark.parametrize('args', LOCAL_CA_UPDATE_TEST_ARGS)
@patch(MOCKER_HTTP_METHOD)
def test_local_ca_update_command(mock_update_local_ca, args):
    from ThalesCipherTrustManager import CipherTrustClient, local_ca_update_command
    mock_update_local_ca.return_value = util_load_json('test_data/mock_local_ca_update_response.json')

    client = CipherTrustClient(username=MOCK_USERNAME, password=MOCK_PASSWORD, server_url=MOCK_SERVER_URL, verify=False,
                               proxy=False)

    result = local_ca_update_command(client, args)

    assert isinstance(result, CommandResults)
    assert result.outputs_prefix == LOCAL_CA_CONTEXT_OUTPUT_PREFIX
    assert result.outputs == mock_update_local_ca.return_value
    assert result.raw_response == mock_update_local_ca.return_value


@pytest.mark.parametrize('args', LOCAL_CA_DELETE_TEST_ARGS)
@patch(MOCKER_HTTP_METHOD)
def test_local_ca_delete_command(mock_delete_local_ca, args):
    from ThalesCipherTrustManager import CipherTrustClient, local_ca_delete_command
    mock_delete_local_ca.return_value = util_load_json('test_data/mock_local_ca_delete_response.json')

    client = CipherTrustClient(username=MOCK_USERNAME, password=MOCK_PASSWORD, server_url=MOCK_SERVER_URL, verify=False,
                               proxy=False)

    result = local_ca_delete_command(client, args)

    assert isinstance(result, CommandResults)
    assert result.outputs_prefix is None
    assert result.outputs == mock_delete_local_ca.return_value
    assert result.raw_response == mock_delete_local_ca.return_value
    assert result.readable_output == f'{args[CommandArguments.LOCAL_CA_ID]} has been deleted successfully!'


@pytest.mark.parametrize('args', LOCAL_CA_SELF_SIGN_TEST_ARGS)
@patch(MOCKER_HTTP_METHOD)
def test_local_ca_self_sign_command(mock_self_sign_local_ca, args):
    from ThalesCipherTrustManager import CipherTrustClient, local_ca_self_sign_command
    mock_self_sign_local_ca.return_value = util_load_json('test_data/mock_local_ca_self_sign_response.json')

    client = CipherTrustClient(username=MOCK_USERNAME, password=MOCK_PASSWORD, server_url=MOCK_SERVER_URL, verify=False,
                               proxy=False)

    result = local_ca_self_sign_command(client, args)

    assert isinstance(result, CommandResults)
    assert result.outputs_prefix == CA_SELF_SIGN_CONTEXT_OUTPUT_PREFIX
    assert result.outputs == mock_self_sign_local_ca.return_value
    assert result.raw_response == mock_self_sign_local_ca.return_value


@pytest.mark.parametrize('args', LOCAL_CA_INSTALL_TEST_ARGS)
@patch(MOCKER_HTTP_METHOD)
def test_local_ca_install_command(mock_install_local_ca, args):
    from ThalesCipherTrustManager import CipherTrustClient, local_ca_install_command
    mock_install_local_ca.return_value = util_load_json('test_data/mock_local_ca_install_response.json')

    client = CipherTrustClient(username=MOCK_USERNAME, password=MOCK_PASSWORD, server_url=MOCK_SERVER_URL, verify=False,
                               proxy=False)

    result = local_ca_install_command(client, args)

    assert isinstance(result, CommandResults)
    assert result.outputs_prefix == CA_INSTALL_CONTEXT_OUTPUT_PREFIX
    assert result.outputs == mock_install_local_ca.return_value
    assert result.raw_response == mock_install_local_ca.return_value


@pytest.mark.parametrize('args', CERTIFICATE_ISSUE_TEST_ARGS)
@patch(MOCKER_HTTP_METHOD)
def test_certificate_issue_command(mock_issue_certificate, args):
    from ThalesCipherTrustManager import CipherTrustClient, certificate_issue_command
    mock_issue_certificate.return_value = util_load_json('test_data/mock_certificate_issue_response.json')

    client = CipherTrustClient(username=MOCK_USERNAME, password=MOCK_PASSWORD, server_url=MOCK_SERVER_URL, verify=False,
                               proxy=False)

    result = certificate_issue_command(client, args)

    assert isinstance(result, CommandResults)
    assert result.outputs_prefix == CA_CERTIFICATE_CONTEXT_OUTPUT_PREFIX
    assert result.outputs == mock_issue_certificate.return_value
    assert result.raw_response == mock_issue_certificate.return_value


@pytest.mark.parametrize('args', CERTIFICATE_LIST_TEST_ARGS)
@patch(MOCKER_HTTP_METHOD)
def test_certificate_list_command(mock_get_certificates_list, args):
    from ThalesCipherTrustManager import CipherTrustClient, certificate_list_command
    mock_get_certificates_list.return_value = util_load_json('test_data/mock_certificate_list_response.json')

    client = CipherTrustClient(username=MOCK_USERNAME, password=MOCK_PASSWORD, server_url=MOCK_SERVER_URL, verify=False,
                               proxy=False)

    result = certificate_list_command(client, args)

    assert isinstance(result, CommandResults)
    assert result.outputs_prefix == CA_CERTIFICATE_CONTEXT_OUTPUT_PREFIX
    assert result.outputs == mock_get_certificates_list.return_value
    assert result.raw_response == mock_get_certificates_list.return_value


@pytest.mark.parametrize('args', LOCAL_CERTIFICATE_DELETE_TEST_ARGS)
@patch(MOCKER_HTTP_METHOD)
def test_local_certificate_delete_command(mock_delete_certificate, args):
    from ThalesCipherTrustManager import CipherTrustClient, local_certificate_delete_command
    mock_delete_certificate.return_value = util_load_json('test_data/mock_local_certificate_delete_response.json')

    client = CipherTrustClient(username=MOCK_USERNAME, password=MOCK_PASSWORD, server_url=MOCK_SERVER_URL, verify=False,
                               proxy=False)

    result = local_certificate_delete_command(client, args)

    assert isinstance(result, CommandResults)
    assert result.outputs_prefix is None
    assert result.outputs == mock_delete_certificate.return_value
    assert result.raw_response == mock_delete_certificate.return_value
    assert result.readable_output == f'{args[CommandArguments.LOCAL_CA_ID]} has been deleted successfully!'


@pytest.mark.parametrize('args', CERTIFICATE_REVOKE_TEST_ARGS)
@patch(MOCKER_HTTP_METHOD)
def test_certificate_revoke_command(mock_revoke_certificate, args):
    from ThalesCipherTrustManager import CipherTrustClient, certificate_revoke_command
    mock_revoke_certificate.return_value = util_load_json('test_data/mock_certificate_revoke_response.json')

    client = CipherTrustClient(username=MOCK_USERNAME, password=MOCK_PASSWORD, server_url=MOCK_SERVER_URL, verify=False,
                               proxy=False)

    result = certificate_revoke_command(client, args)

    assert isinstance(result, CommandResults)
    assert result.outputs_prefix is None
    assert result.outputs == mock_revoke_certificate.return_value
    assert result.raw_response == mock_revoke_certificate.return_value
    assert result.readable_output == f'{args[CommandArguments.CERT_ID]} has been revoked'


@pytest.mark.parametrize('args', CERTIFICATE_RESUME_TEST_ARGS)
@patch(MOCKER_HTTP_METHOD)
def test_certificate_resume_command(mock_resume_certificate, args):
    from ThalesCipherTrustManager import CipherTrustClient, certificate_resume_command
    mock_resume_certificate.return_value = util_load_json('test_data/mock_certificate_resume_response.json')

    client = CipherTrustClient(username=MOCK_USERNAME, password=MOCK_PASSWORD, server_url=MOCK_SERVER_URL, verify=False,
                               proxy=False)

    result = certificate_resume_command(client, args)

    assert isinstance(result, CommandResults)
    assert result.outputs_prefix is None
    assert result.outputs == mock_resume_certificate.return_value
    assert result.raw_response == mock_resume_certificate.return_value
    assert result.readable_output == f'{args[CommandArguments.CERT_ID]} has been resumed'


@pytest.mark.parametrize('args', EXTERNAL_CERTIFICATE_UPLOAD_TEST_ARGS)
@patch(MOCKER_HTTP_METHOD)
def test_external_certificate_upload_command(mock_upload_external_certificate, args):
    from ThalesCipherTrustManager import CipherTrustClient, external_certificate_upload_command
    mock_upload_external_certificate.return_value = util_load_json('test_data/mock_external_certificate_upload_response.json')

    client = CipherTrustClient(username=MOCK_USERNAME, password=MOCK_PASSWORD, server_url=MOCK_SERVER_URL, verify=False,
                               proxy=False)

    result = external_certificate_upload_command(client, args)

    assert isinstance(result, CommandResults)
    assert result.outputs_prefix == EXTERNAL_CERTIFICATE_CONTEXT_OUTPUT_PREFIX
    assert result.outputs == mock_upload_external_certificate.return_value
    assert result.raw_response == mock_upload_external_certificate.return_value


@pytest.mark.parametrize('args', EXTERNAL_CERTIFICATE_DELETE_TEST_ARGS)
@patch(MOCKER_HTTP_METHOD)
def test_external_certificate_delete_command(mock_delete_external_certificate, args):
    from ThalesCipherTrustManager import CipherTrustClient, external_certificate_delete_command
    mock_delete_external_certificate.return_value = util_load_json('test_data/mock_external_certificate_delete_response.json')

    client = CipherTrustClient(username=MOCK_USERNAME, password=MOCK_PASSWORD, server_url=MOCK_SERVER_URL, verify=False,
                               proxy=False)

    result = external_certificate_delete_command(client, args)

    assert isinstance(result, CommandResults)
    assert result.outputs_prefix is None
    assert result.outputs == mock_delete_external_certificate.return_value
    assert result.raw_response == mock_delete_external_certificate.return_value
    assert result.readable_output == f'{args[CommandArguments.EXTERNAL_CA_ID]} has been deleted successfully!'


@pytest.mark.parametrize('args', EXTERNAL_CERTIFICATE_UPDATE_TEST_ARGS)
@patch(MOCKER_HTTP_METHOD)
def test_external_certificate_update_command(mock_update_external_certificate, args):
    from ThalesCipherTrustManager import CipherTrustClient, external_certificate_update_command
    mock_update_external_certificate.return_value = util_load_json('test_data/mock_external_certificate_update_response.json')

    client = CipherTrustClient(username=MOCK_USERNAME, password=MOCK_PASSWORD, server_url=MOCK_SERVER_URL, verify=False,
                               proxy=False)

    result = external_certificate_update_command(client, args)

    assert isinstance(result, CommandResults)
    assert result.outputs_prefix == EXTERNAL_CERTIFICATE_CONTEXT_OUTPUT_PREFIX
    assert result.outputs == mock_update_external_certificate.return_value
    assert result.raw_response == mock_update_external_certificate.return_value


@pytest.mark.parametrize('args', EXTERNAL_CERTIFICATE_UPDATE_TEST_ARGS)
@patch(MOCKER_HTTP_METHOD)
def test_external_certificate_list_command(mock_get_external_certificates_list, args):
    from ThalesCipherTrustManager import CipherTrustClient, external_certificate_list_command
    mock_get_external_certificates_list.return_value = util_load_json(
        'test_data/mock_external_certificate_list_response.json.json')

    client = CipherTrustClient(username=MOCK_USERNAME, password=MOCK_PASSWORD, server_url=MOCK_SERVER_URL, verify=False,
                               proxy=False)

    result = external_certificate_list_command(client, args)

    assert isinstance(result, CommandResults)
    assert result.outputs_prefix == EXTERNAL_CERTIFICATE_CONTEXT_OUTPUT_PREFIX
    assert result.outputs == mock_get_external_certificates_list.return_value
    assert result.raw_response == mock_get_external_certificates_list.return_value
