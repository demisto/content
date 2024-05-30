import json

MOCKER_HTTP_METHOD = 'ThalesCipherTrustManager.CipherTrustClient._http_request'
MOCKER_CREATE_AUTH_TOKEN = f"ThalesCipherTrustManager.CipherTrustClient.create_auth_token"
MOCKER_LOAD_CONTENT_FROM_FILE = 'ThalesCipherTrustManager.load_content_from_file'
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
    CERT_ENTRY_ID = 'cert_entry_id'
    NEW_GROUP_NAME = 'new_group_name'


'''
Mock Data 
'''

GROUPS_LIST_TEST_ARGS = [
    {},
    {CommandArguments.GROUP_NAME: 'group1'},
    {CommandArguments.USER_ID: 'user1'},
    {CommandArguments.CONNECTION: 'connection1'},
    {CommandArguments.CLIENT_ID: 'client1'},
    {
        CommandArguments.GROUP_NAME: 'group2',
        CommandArguments.USER_ID: 'user2'
    },
    {
        CommandArguments.CONNECTION: 'connection2',
        CommandArguments.CLIENT_ID: 'client2'
    },
    {
        CommandArguments.GROUP_NAME: 'group3',
        CommandArguments.USER_ID: 'user3',
        CommandArguments.CONNECTION: 'connection3',
        CommandArguments.CLIENT_ID: 'client3'
    },
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
USER_TO_GROUP_ADD_TEST_ARGS = [
    {
        CommandArguments.GROUP_NAME: 'group1',
        CommandArguments.USER_ID: 'user1'
    }
]
USER_TO_GROUP_REMOVE_TEST_ARGS = [
    {
        CommandArguments.GROUP_NAME: 'group1',
        CommandArguments.USER_ID: 'user1'
    },
]

USERS_LIST_TEST_ARGS = [
    {
        CommandArguments.NAME: "John Doe",
        CommandArguments.USERNAME: "johndoe",
        CommandArguments.EMAIL: "john.doe@example.com",
        CommandArguments.GROUPS: "group1,group2",
        CommandArguments.EXCLUDE_GROUPS: "group3",
        CommandArguments.AUTH_DOMAIN_NAME: "example_domain",
        CommandArguments.ACCOUNT_EXPIRED: "true",
        CommandArguments.ALLOWED_AUTH_METHODS: "password",
        CommandArguments.ALLOWED_CLIENT_TYPES: "confidential",
        CommandArguments.PASSWORD_POLICY: "example_policy",
        CommandArguments.RETURN_GROUPS: "true"
    },
]
USER_CREATE_TEST_ARGS = [
    {
        "name": "Test User",
        "user_id": "root|12345678-1234-1234-1234-123456789012",
        "username": "testuser",
        "password": "TestPassword!123",
        "email": "testuser@example.com",
        "allowed_auth_methods": "password",
        "allowed_client_types": "unregistered,public,confidential",
        "certificate_subject_dn": "CN=Test User,OU=Test Unit,O=Test Organization,L=Test City,ST=Test State,C=Test Country",
        "connection": "local_account",
        "expires_at": "2025-01-01T00:00:00.000Z",
        "is_domain_user": "false",
        "prevent_ui_login": "false",
        "password_change_required": "false",
        "password_policy": "default_policy"
    },
    {
        "name": "Domain User",
        "username": "domainuser",
        "email": "domainuser@example.com",
        "allowed_auth_methods": "password_with_user_certificate",
        "allowed_client_types": "public,confidential",
        "certificate_subject_dn": "CN=Domain User,OU=Domain Unit,O=Domain Organization,L=Domain City,ST=Domain State,C=Domain "
                                  "Country",
        "connection": "domain_account",
        "is_domain_user": "true",
        "prevent_ui_login": "true",
        "password_change_required": "true",
        "password_policy": "strict_policy"
    },
    {
        "name": "Cert Auth User",
        "username": "certauthuser",
        "email": "certauthuser@example.com",
        "allowed_auth_methods": "user_certificate",
        "allowed_client_types": "unregistered",
        "certificate_subject_dn": "CN=Cert Auth User,OU=Cert Unit,O=Cert Organization,L=Cert City,ST=Cert State,C=Cert Country",
        "enable_cert_auth": "true",
        "password_policy": "cert_policy"
    },
    {
        "name": "Expiring User",
        "username": "expiringuser",
        "email": "expiringuser@example.com",
        "allowed_auth_methods": "password",
        "allowed_client_types": "unregistered,public,confidential",
        "expires_at": "tomorrow",
        "prevent_ui_login": "false",
        "password_change_required": "false",
        "password_policy": "default_policy"
    },
    {
        "name": "Empty Expiration User",
        "username": "emptyexpirationuser",
        "email": "emptyexpirationuser@example.com",
        "allowed_auth_methods": "password",
        "allowed_client_types": "unregistered,public,confidential",
        "expires_at": "empty",
        "prevent_ui_login": "false",
        "password_change_required": "false",
        "password_policy": "default_policy"
    },
    {
        "name": "Empty Auth Methods User",
        "username": "noauthmethodsuser",
        "email": "noauthmethodsuser@example.com",
        "allowed_auth_methods": "empty",
        "allowed_client_types": "unregistered,public,confidential",
        "prevent_ui_login": "false",
        "password_change_required": "false",
        "password_policy": "default_policy"
    },
]

USER_UPDATE_TEST_ARGS = [
    {
        CommandArguments.NAME: "John Doe",
        CommandArguments.USER_ID: "local|f4k3-u51d-1234",
        CommandArguments.USERNAME: "johndoe",
        CommandArguments.PASSWORD: "password123",
        CommandArguments.EMAIL: "john.doe@example.com",
        CommandArguments.PASSWORD_CHANGE_REQUIRED: "true",
        CommandArguments.ALLOWED_AUTH_METHODS: "password,user_certificate",
        CommandArguments.ALLOWED_CLIENT_TYPES: "public,confidential",
        CommandArguments.CERTIFICATE_SUBJECT_DN: "CN=John Doe,OU=Example,O=Example Corp,C=US",
        CommandArguments.EXPIRES_AT: "2025-12-31T23:59:59Z",
        CommandArguments.FAILED_LOGINS_COUNT: 0,
        CommandArguments.PREVENT_UI_LOGIN: "true",
        CommandArguments.PASSWORD_POLICY: "complex"
    }
    ,
    {
        CommandArguments.USER_ID: "local|f4k3-u51d-1234",
    },
    {
        CommandArguments.USER_ID: "local|f4k3-u51d-1234",
        CommandArguments.EXPIRES_AT: "tomorrow",
    },
    {
        CommandArguments.USER_ID: "local|f4k3-u51d-1234",
        CommandArguments.EXPIRES_AT: "empty",
        CommandArguments.ALLOWED_AUTH_METHODS: "empty",
        CommandArguments.ALLOWED_CLIENT_TYPES: "empty"

    },

]
USER_DELETE_TEST_ARGS = [
    {CommandArguments.USER_ID: 'user1'},
]
USER_PASSWORD_CHANGE_TEST_ARGS = [
    {
        CommandArguments.USERNAME: 'user1',
        CommandArguments.PASSWORD: 'old_password',
        CommandArguments.NEW_PASSWORD: 'new_password',
        CommandArguments.AUTH_DOMAIN: 'local_account'
    },
]

LOCAL_CA_CREATE_TEST_ARGS = [

    {
        CommandArguments.CN: "test.localca2",
    },
    {
        CommandArguments.CN: "example.localca",
        CommandArguments.ALGORITHM: "RSA",
        CommandArguments.COPY_FROM_CA: "abcd1234-ab12-cd34-ef56-abcdef123456",
        CommandArguments.DNS_NAMES: "example.com,example.org",
        CommandArguments.EMAIL: "admin@example.com,contact@example.org",
        CommandArguments.IP: "192.168.1.1,10.0.0.1",
        CommandArguments.NAME: "example-localca",
        CommandArguments.NAME_FIELDS_RAW_JSON: '[{"O": "ExampleOrg", "OU": "IT", "C": "US", "ST": "CA", "L": "San Francisco"}, {"OU": "ExampleOrg Inc."}]',
        CommandArguments.SIZE: "2048"
    },
]

FAKE_CERT = "-----BEGIN CERTIFICATE REQUEST-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAfafaeeefakakefeekafaeaa\nfeakfafeefaafakfafeakffakeeafffkafeafeekaffakeefaakfefaefaefakfaffka\nfaeffakeeffeakafakefeaefeffaafkekaeffkaeffafakfaefffaeefffaeffakekafa\nfeakfeafakefafeaefakeffafakeefaffakefkeffaeakeffaeakffaeakffaefakffa\n-----END CERTIFICATE REQUEST-----\n",
FAKE_SUBJECT = "/C=FA/ST=Fk/L=FakeCity/O=FakeOrg/OU=FakeUnit/OU=FakeGroup/CN=fake.example.com"

LOCAL_CA_LIST_TEST_ARGS = [
    {},
    {"subject": FAKE_SUBJECT, "limit": 10, "page": 1, "state": "active", "cert": FAKE_CERT, "issuer": FAKE_SUBJECT},

]
LOCAL_CA_UPDATE_TEST_ARGS = [
    {CommandArguments.LOCAL_CA_ID: "123e4567-e89b-12d3-a456-426614174000"},
    {
        CommandArguments.LOCAL_CA_ID: "123e4567-e89b-12d3-a456-426614174000",
        CommandArguments.ALLOW_CLIENT_AUTHENTICATION: "true",
        CommandArguments.ALLOW_USER_AUTHENTICATION: "true"
    },
]
LOCAL_CA_DELETE_TEST_ARGS = [
    {CommandArguments.LOCAL_CA_ID: "123e4567-e89b-12d3-a456-426614174000"},
]
LOCAL_CA_SELF_SIGN_TEST_ARGS = [
    ({'local_ca_id': '123e4567-e89b-12d3-a456-426614174000', 'not_after': '2024-12-31T23:59:59Z'}),

    ({'local_ca_id': '123e4567-e89b-12d3-a456-426614174000', 'duration': '365'}),

    ({'local_ca_id': '123e4567-e89b-12d3-a456-426614174000', 'not_after': '2024-12-31T23:59:59Z', 'duration': '365'}),

    ({'local_ca_id': '123e4567-e89b-12d3-a456-426614174000', 'not_before': '2023-01-01T00:00:00Z',
      'not_after': '2024-01-01T00:00:00Z'}),

    ({'local_ca_id': '123e4567-e89b-12d3-a456-426614174000', 'duration': '365', 'not_before': '2023-01-01T00:00:00Z',
      'not_after': 'two weeks'})
]

LOCAL_CA_SELF_SIGN_TEST_MISSING_ARGS = [
    ({'local_ca_id': '123e4567-e89b-12d3-a456-426614174000'}),
    ({'local_ca_id': '123e4567-e89b-12d3-a456-426614174000', 'not_before': '2023-01-01T00:00:00Z'}),
]
LOCAL_CA_INSTALL_TEST_ARGS = [
    {
        CommandArguments.LOCAL_CA_ID: "123e4567-e89-b12d3-a456-426614174000",
        CommandArguments.CERT_ENTRY_ID: "123e4567-e89-b12d3-a456-426614174000",
        CommandArguments.PARENT_ID: "123e4567-e89-b12d3-a456-426614174000",
    }
]
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


@pytest.mark.parametrize('param_name, argument_value, expected_output',
                         [("test_date", "empty", ""),
                          ("test_date", "2023-05-26T15:30:00", "2023-05-26T15:30:00.000000Z"),
                          ("test_date", None, None)])
def test_add_empty_date_param(param_name, argument_value, expected_output):
    from ThalesCipherTrustManager import add_empty_date_param
    request_data = {}
    add_empty_date_param(request_data, argument_value, param_name)
    assert request_data.get(param_name) == expected_output


def test_add_empty_date_param_invalid_input():
    from ThalesCipherTrustManager import add_empty_date_param
    with pytest.raises(ValueError):
        request_data = {}
        add_empty_date_param(request_data, "invalid-datetime", "test_date")
    with pytest.raises(KeyError):
        assert request_data['test_date'] is None


@pytest.mark.parametrize('param_name, argument_value, expected_output',
                         [("test_list", "empty", []),
                          ("test_list", "item1,item2,item3", ["item1", "item2", "item3"]),
                          ("test_list", "", []),
                          ("test_list", None, None)])
def test_add_empty_list_param(param_name, argument_value, expected_output):
    from ThalesCipherTrustManager import add_empty_list_param
    request_data = {}
    add_empty_list_param(request_data, argument_value, param_name)
    assert request_data.get(param_name) == expected_output


def test_add_empty_list_param_no_value():
    from ThalesCipherTrustManager import add_empty_list_param
    with pytest.raises(KeyError):
        request_data = {}
        add_empty_list_param(request_data, None, "test_list")
        assert request_data['test_list'] is None


@pytest.mark.parametrize('request_data, argument_value, flag_name, expected_login_flags', [
    ({}, "some_value", "flag1", {"flag1": "some_value"}),
    ({'login_flags': {'existing_flag': 'existing_value'}}, "new_value", "new_flag",
     {'existing_flag': 'existing_value', 'new_flag': 'new_value'}),
    ({}, None, "flag1", None),
    ({'login_flags': {}}, "some_value", "flag1", {"flag1": "some_value"})
])
def test_add_login_flags(request_data, argument_value, flag_name, expected_login_flags):
    from ThalesCipherTrustManager import add_login_flags
    add_login_flags(request_data, argument_value, flag_name)
    assert request_data.get('login_flags') == expected_login_flags


#todo: test file loads?

''' COMMAND FUNCTIONS TESTS '''


@pytest.fixture(autouse=True)
def patch_create_auth_token(monkeypatch):
    def mock_create_auth_token(*args, **kwargs):
        return util_load_json('test_data/mock_create_auth_token_response.json')

    monkeypatch.setattr(MOCKER_CREATE_AUTH_TOKEN, mock_create_auth_token)


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
    mock_delete_group.return_value = None

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
    from ThalesCipherTrustManager import CipherTrustClient, group_update_command
    mock_update_group.return_value = util_load_json('test_data/mock_group_update_response.json')

    client = CipherTrustClient(username=MOCK_USERNAME, password=MOCK_PASSWORD, server_url=MOCK_SERVER_URL, verify=False,
                               proxy=False)

    result = group_update_command(client, args)

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
    mock_remove_user_from_group.return_value = None

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
    args = {CommandArguments.USER_ID: 'user1'}

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
    mock_delete_user.return_value = None

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
    mock_change_current_user_password.return_value = None

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
    args = {"local_ca_id": "123e4567-e89b-12d3-a456-426614174000", "chained": "true"}
    result = local_ca_list_command(client, args)

    assert isinstance(result, CommandResults)
    assert result.outputs_prefix == LOCAL_CA_CONTEXT_OUTPUT_PREFIX
    assert result.outputs == {'resources': [mock_get_local_ca.return_value]}
    assert result.raw_response == mock_get_local_ca.return_value

    args = {"chained": "true"}
    with pytest.raises(ValueError):
        local_ca_list_command(client, args)


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
    mock_delete_local_ca.return_value = None

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


@pytest.mark.parametrize('args', LOCAL_CA_SELF_SIGN_TEST_MISSING_ARGS)
@patch(MOCKER_HTTP_METHOD)
def test_local_ca_self_sign_command_missing_arguments(mock_self_sign_local_ca, args):
    from ThalesCipherTrustManager import CipherTrustClient, local_ca_self_sign_command
    mock_self_sign_local_ca.return_value = util_load_json('test_data/mock_local_ca_self_sign_response.json')

    client = CipherTrustClient(username=MOCK_USERNAME, password=MOCK_PASSWORD, server_url=MOCK_SERVER_URL, verify=False,
                               proxy=False)

    with pytest.raises(ValueError):
        result = local_ca_self_sign_command(client, args)


@pytest.mark.parametrize('args', LOCAL_CA_INSTALL_TEST_ARGS)
@patch(MOCKER_LOAD_CONTENT_FROM_FILE)
@patch(MOCKER_HTTP_METHOD)
def test_local_ca_install_command(mock_install_local_ca, mock_load_content_from_file, args):
    from ThalesCipherTrustManager import CipherTrustClient, local_ca_install_command
    mock_install_local_ca.return_value = util_load_json('test_data/mock_local_ca_install_response.json')
    mock_load_content_from_file.return_value = FAKE_CERT

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
