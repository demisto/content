from CommonServerPython import CommandResults
from unittest.mock import patch
import pytest
import json

MOCKER_HTTP_METHOD = 'ThalesCipherTrustManager.CipherTrustClient._http_request'
MOCKER_CREATE_AUTH_TOKEN = "ThalesCipherTrustManager.CipherTrustClient.create_auth_token"
MOCKER_LOAD_CONTENT_FROM_FILE = 'ThalesCipherTrustManager.load_content_from_file'
MOCKER_RETURN_FILE_RESULT = 'ThalesCipherTrustManager.fileResult'
MOCKER_RETURN_PASSWORD_PROTECTED_ZIP_FILE_RESULT = 'ThalesCipherTrustManager.return_password_protected_zip_file_result'
MOCK_USERNAME = 'user'
MOCK_PASSWORD = 'password123'
MOCK_SERVER_URL = 'https://example.com'


def util_load_json(path):
    with open(path, encoding='utf-8') as f:
        return json.loads(f.read())


def remove_keys_from_dict(d, keys):
    copy_d = d.copy()
    for key in keys:
        copy_d.pop(key, '')
    return copy_d


''' CONSTANTS '''

CONTEXT_OUTPUT_PREFIX = "CipherTrust."
GROUP_CONTEXT_OUTPUT_PREFIX = f"{CONTEXT_OUTPUT_PREFIX}Group"
USERS_CONTEXT_OUTPUT_PREFIX = f"{CONTEXT_OUTPUT_PREFIX}Users"
LOCAL_CA_CONTEXT_OUTPUT_PREFIX = f"{CONTEXT_OUTPUT_PREFIX}LocalCA"
CA_SELF_SIGN_CONTEXT_OUTPUT_PREFIX = f"{CONTEXT_OUTPUT_PREFIX}CASelfSign"
CA_INSTALL_CONTEXT_OUTPUT_PREFIX = f"{CONTEXT_OUTPUT_PREFIX}CAInstall"
CA_CERTIFICATE_CONTEXT_OUTPUT_PREFIX = f"{CONTEXT_OUTPUT_PREFIX}CACertificate"
EXTERNAL_CA_CONTEXT_OUTPUT_PREFIX = f"{CONTEXT_OUTPUT_PREFIX}ExternalCA"
CSR_CONTEXT_OUTPUT_PREFIX = f"{CONTEXT_OUTPUT_PREFIX}CSR"

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
CSR_ENTRY_ID = 'csr_entry_id'
EXTERNAL_CERT_ID = 'external_cert_id'
ENCRYPTION_ALGO = 'encryption_algo'
KEY_SIZE = 'key_size'
PRIVATE_KEY_BYTES = 'private_key_bytes'
ENCRYPTION_PASSWORD = 'encryption_password'
PRIVATE_KEY_FILE_PASSWORD = 'private_key_file_password'

'''
Mock Data
'''

GROUPS_LIST_TEST_ARGS = [
    {},
    {GROUP_NAME: 'group1'},
    {USER_ID: 'user1'},
    {CONNECTION: 'connection1'},
    {CLIENT_ID: 'client1'},
    {
        GROUP_NAME: 'group2',
        USER_ID: 'user2'
    },
    {
        CONNECTION: 'connection2',
        CLIENT_ID: 'client2'
    },
    {
        GROUP_NAME: 'group3',
        USER_ID: 'user3',
        CONNECTION: 'connection3',
        CLIENT_ID: 'client3'
    },
]

GROUP_CREATE_TEST_ARGS = [
    {
        NAME: 'group1',
    },
    {
        NAME: 'group2',
        DESCRIPTION: 'description2'
    }
]
GROUP_DELETE_TEST_ARGS = [
    {GROUP_NAME: 'group1'},
    {GROUP_NAME: 'group2', FORCE: 'true'}
]
GROUP_UPDATE_TEST_ARGS = [
    {
        GROUP_NAME: 'group1',
        DESCRIPTION: 'description1_updated'
    }
]
USER_TO_GROUP_ADD_TEST_ARGS = [
    {
        GROUP_NAME: 'group1',
        USER_ID: 'user1'
    }
]
USER_TO_GROUP_REMOVE_TEST_ARGS = [
    {
        GROUP_NAME: 'group1',
        USER_ID: 'user1'
    },
]

USERS_LIST_TEST_ARGS = [
    {
        NAME: "John Doe",
        USERNAME: "johndoe",
        EMAIL: "john.doe@example.com",
        GROUPS: "group1,group2",
        EXCLUDE_GROUPS: "group3",
        AUTH_DOMAIN_NAME: "example_domain",
        ACCOUNT_EXPIRED: "true",
        ALLOWED_AUTH_METHODS: "password",
        ALLOWED_CLIENT_TYPES: "confidential",
        PASSWORD_POLICY: "example_policy",
        RETURN_GROUPS: "true"
    },
]
USER_CREATE_TEST_ARGS = [
    {
        NAME: "Test User",
        USER_ID: "root|12345678-1234-1234-1234-123456789012",
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
        "expires_at": "never",
        "prevent_ui_login": "false",
        "password_change_required": "false",
        "password_policy": "default_policy"
    },
    {
        "name": "Empty Auth Methods User",
        "username": "noauthmethodsuser",
        "email": "noauthmethodsuser@example.com",
        "allowed_auth_methods": "none",
        "allowed_client_types": "unregistered,public,confidential",
        "prevent_ui_login": "false",
        "password_change_required": "false",
        "password_policy": "default_policy"
    },
]

USER_UPDATE_TEST_ARGS = [
    {
        NAME: "John Doe",
        USER_ID: "local|f4k3-u51d-1234",
        USERNAME: "johndoe",
        PASSWORD: "password123",
        EMAIL: "john.doe@example.com",
        PASSWORD_CHANGE_REQUIRED: "true",
        ALLOWED_AUTH_METHODS: "password,user_certificate",
        ALLOWED_CLIENT_TYPES: "public,confidential",
        CERTIFICATE_SUBJECT_DN: "CN=John Doe,OU=Example,O=Example Corp,C=US",
        EXPIRES_AT: "2025-12-31T23:59:59Z",
        FAILED_LOGINS_COUNT: 0,
        PREVENT_UI_LOGIN: "true",
        PASSWORD_POLICY: "complex"
    },
    {
        USER_ID: "local|f4k3-u51d-1234",
    },
    {
        USER_ID: "local|f4k3-u51d-1234",
        EXPIRES_AT: "tomorrow",
    },
    {
        USER_ID: "local|f4k3-u51d-1234",
        EXPIRES_AT: "never",
        ALLOWED_AUTH_METHODS: "none",
        ALLOWED_CLIENT_TYPES: "none"

    },

]
USER_DELETE_TEST_ARGS = [
    {USER_ID: 'user1'},
]
USER_PASSWORD_CHANGE_TEST_ARGS = [
    {
        USERNAME: 'user1',
        PASSWORD: 'old_password',
        NEW_PASSWORD: 'new_password',
        AUTH_DOMAIN: 'local_account'
    },
]

LOCAL_CA_CREATE_TEST_ARGS = [

    {
        CN: "test.localca2",
    },
    {
        CN: "example.localca",
        ALGORITHM: "RSA",
        COPY_FROM_CA: "abcd1234-ab12-cd34-ef56-abcdef123456",
        DNS_NAMES: "example.com,example.org",
        EMAIL: "admin@example.com,contact@example.org",
        IP: "192.168.1.1,10.0.0.1",
        NAME: "example-localca",
        NAME_FIELDS_RAW_JSON: '[{"O": "ExampleOrg", "OU": "IT", "C": "US", "ST": "CA", "L": "San Francisco"}, '
                              '{"OU": "ExampleOrg Inc."}]',
        SIZE: "2048"
    },
]
FAKE_CERT = ("-----BEGIN CERTIFICATE-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAfafaeeefakakefeekafaeaa"
             "\nfeakfafeefaafakfafeakffakeeafffkafeafeekaffakeefaakfefaefaefakfaffka"
             "\nfaeffakeeffeakafakefeaefeffaafkekaeffkaeffafakfaefffaeefffaeffakekafa"
             "\nfeakfeafakefafeaefakeffafakeefaffakefkeffaeakeffaeakffaeakffaefakffa\n------END CERTIFICATE-----\n")

FAKE_CSR = ("-----BEGIN CERTIFICATE REQUEST-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAfafaeeefakakefeekafaeaa"
            "\nfeakfafeefaafakfafeakffakeeafffkafeafeekaffakeefaakfefaefaefakfaffka"
            "\nfaeffakeeffeakafakefeaefeffaafkekaeffkaeffafakfaefffaeefffaeffakekafa"
            "\nfeakfeafakefafeaefakeffafakeefaffakefkeffaeakeffaeakffaeakffaefakffa\n-----END CERTIFICATE REQUEST-----\n"),
FAKE_SUBJECT = "/C=FA/ST=Fk/L=FakeCity/O=FakeOrg/OU=FakeUnit/OU=FakeGroup/CN=fake.example.com"

LOCAL_CA_LIST_TEST_ARGS = [
    {},
    {"subject": FAKE_SUBJECT, "limit": 10, "page": 1, "state": "active", "cert": FAKE_CERT, "issuer": FAKE_SUBJECT},

]
LOCAL_CA_UPDATE_TEST_ARGS = [
    {LOCAL_CA_ID: "1localca-23e4567-e89b-12d3-a456-426614174000"},
    {
        LOCAL_CA_ID: "localca-123e4567-e89b-12d3-a456-426614174000",
        ALLOW_CLIENT_AUTHENTICATION: "true",
        ALLOW_USER_AUTHENTICATION: "true"
    },
]
LOCAL_CA_DELETE_TEST_ARGS = [
    {LOCAL_CA_ID: "localca-123e4567-e89b-12d3-a456-426614174000"},
]
LOCAL_CA_SELF_SIGN_TEST_ARGS = [
    ({LOCAL_CA_ID: 'localca-123e4567-e89b-12d3-a456-426614174000', 'not_after': '2024-12-31T23:59:59Z'}),

    ({LOCAL_CA_ID: 'localca-123e4567-e89b-12d3-a456-426614174000', 'duration': '365'}),

    ({LOCAL_CA_ID: 'localca-123e4567-e89b-12d3-a456-426614174000', 'not_after': '2024-12-31T23:59:59Z',
      'duration':
          '365'}),

    ({LOCAL_CA_ID: 'localca-123e4567-e89b-12d3-a456-426614174000', 'not_before': '2023-01-01T00:00:00Z',
      'not_after': '2024-01-01T00:00:00Z'}),

    ({LOCAL_CA_ID: '123e4567-e89b-12d3-a456-426614174000', 'duration': '365', 'not_before': '2023-01-01T00:00'
                                                                                            ':00Z',
      'not_after': 'two weeks'})
]

LOCAL_CA_SELF_SIGN_TEST_MISSING_ARGS = [
    ({LOCAL_CA_ID: 'localca-123e4567-e89b-12d3-a456-426614174000'}),
    ({LOCAL_CA_ID: 'localca-123e4567-e89b-12d3-a456-426614174000', 'not_before': '2023-01-01T00:00:00Z'}),
]
LOCAL_CA_INSTALL_TEST_ARGS = [
    {
        LOCAL_CA_ID: "localca-123e4567-e89-b12d3-a456-426614174000",
        CERT_ENTRY_ID: "123e4567-e89-b12d3-a456-426614174000",
        PARENT_ID: "123e4567-e89-b12d3-a456-426614174000",
    }
]
CERTIFICATE_ISSUE_TEST_ARGS = [
    {
        # Test Case 1: All arguments provided, including both NOT_BEFORE and NOT_AFTER
        CA_ID: "localca-ca12345",
        CSR_ENTRY_ID: "csr12345",
        PURPOSE: "test",
        DURATION: 365,
        NAME: "Test Certificate 1",
        NOT_BEFORE: "2024-06-01T12:34:56Z",
        NOT_AFTER: "2025-06-02T12:34:56Z"
    },
    {
        # Test Case 2: NOT_BEFORE provided, but NOT_AFTER is missing
        CA_ID: "localca-ca67890",
        CSR_ENTRY_ID: "csr67890",
        PURPOSE: "test",
        DURATION: 180,
        NAME: "Test Certificate 2",
        NOT_BEFORE: "2024-06-01T12:34:56Z"
    },
    {
        # Test Case 3: Only DURATION is provided, neither NOT_BEFORE nor NOT_AFTER
        CA_ID: "localca-ca54321",
        CSR_ENTRY_ID: "csr54321",
        PURPOSE: "production",
        DURATION: 90,
        NAME: "Test Certificate 3"
    },
    {
        # Test Case 4: NOT_AFTER provided, but NOT_BEFORE is missing
        CA_ID: "localca-ca09876",
        CSR_ENTRY_ID: "csr09876",
        PURPOSE: "development",
        NAME: "Test Certificate 4",
        NOT_AFTER: "2025-06-02T12:34:56Z",
    }
]

CERTIFICATE_LIST_TEST_ARGS = [
    {CA_ID: "localca-123e456-12d3-a456-426614174000"},
    {CA_ID: "localca-123e456-12d3-a456-426614174000",
     SUBJECT: "CN=Test User,OU=Test Unit,O=Test Organization,L=Test City,ST=Test State,C=Test Country",
     ISSUER: "CN=Test CA,OU=Test Unit,O=Test Organization,L=Test City,ST=Test State,C=Test Country",
     CERT: FAKE_CERT,
     ID: "123e456-12d3-a456-426614174000",
     PAGE: 0,
     PAGE_SIZE: 10,
     LIMIT: 10},
]
LOCAL_CERTIFICATE_DELETE_TEST_ARGS = [
    {
        CA_ID: "localca-b765018b-0a64-419f-b537-c30863aa4002",
        LOCAL_CA_ID: "123e4567-e89b-12d3-a456-426614174000",
    }
]
CERTIFICATE_REVOKE_TEST_ARGS = [
    {CA_ID: "localca-b765018b-0a64-419f-b537-c30863aa4002",
     CERT_ID: "123e4567-e89b-12d3-a456-426614174000",
     REASON: "certificateHold"}
]
CERTIFICATE_RESUME_TEST_ARGS = [{
    CA_ID: "localca-b765018b-0a64-419f-b537-c30863aa4002",
    CERT_ID: "123e4567-e89b-12d3-a456-426614174000",
}]
EXTERNAL_CA_UPLOAD_TEST_ARGS = [
    {
        CERT_ENTRY_ID: "123e4567-e89-b12d3-a456-426614174000",
        NAME: "Test Certificate",
        PARENT: "URI-REFERENCE",

    }
]
EXTERNAL_CA_DELETE_TEST_ARGS = [
    {EXTERNAL_CA_ID: "123e456"}
]
EXTERNAL_CA_UPDATE_TEST_ARGS = [
    {EXTERNAL_CA_ID: "123e4567-e89b-12d3-a456-426614174000",
     ALLOW_CLIENT_AUTHENTICATION: "false",
     ALLOW_USER_AUTHENTICATION: "true"}
]
EXTERNAL_CA_LIST_TEST_ARGS = [
    {},
    {SUBJECT: "CN=Test User,OU=Test Unit,O=Test Organization,L=Test City,ST=Test State,C=Test Country",
     ISSUER: "CN=Test CA,OU=Test Unit,O=Test Organization,L=Test City,ST=Test State,C=Test Country",
     SERIAL_NUMBER: "0",
     CERT: FAKE_CERT,
     PAGE: 0,
     PAGE_SIZE: 10,
     LIMIT: 10},
]

CSR_GENERATE_TEST_ARGS = [
    {CN: "test.example.com", PRIVATE_KEY_FILE_PASSWORD: '123'},

]

''' HELPER FUNCTIONS TESTS'''


@pytest.mark.parametrize('limit, page, page_size, expected_skip, expected_limit',
                         [('100', '2', '25', 25, 25), ('200', None, None, 0, 200), (None, '2', '30', 30, 30),
                          (None, '2', None, 50, 50), (None, '3', None, 100, 50)])
def test_derive_skip_and_limit_for_pagination(limit, page, page_size, expected_skip, expected_limit):
    from ThalesCipherTrustManager import derive_skip_and_limit_for_pagination
    assert derive_skip_and_limit_for_pagination(limit, page, page_size) == (expected_skip, expected_limit)


@pytest.mark.parametrize('limit, page, page_size',
                         [(None, '1', '2001'), (None, 'invalid', '30'), ('invalid', None, None)])
def test_derive_skip_and_limit_for_pagination_invalid_input(limit, page, page_size):
    from ThalesCipherTrustManager import derive_skip_and_limit_for_pagination
    with pytest.raises(ValueError):
        derive_skip_and_limit_for_pagination(limit, page, page_size)


@pytest.mark.parametrize('param_name, argument_value, expected_output',
                         [("test_date", "never", ""),
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
                         [("test_list", "none", []),
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


@pytest.mark.parametrize('request_data, argument_value, expected_login_flags', [
    ({}, True, {"prevent_ui_login": True}),
    ({}, False, {"prevent_ui_login": False}),
    ({}, None, None),
])
def test_add_login_flags(request_data, argument_value, expected_login_flags):
    from ThalesCipherTrustManager import add_prevent_ui_login
    add_prevent_ui_login(request_data, argument_value)
    assert request_data.get('login_flags') == expected_login_flags


''' COMMAND FUNCTIONS TESTS '''


@pytest.fixture(autouse=True)
def patch_create_auth_token(monkeypatch):
    def mock_create_auth_token(*args, **kwargs):
        return util_load_json('test_data/mock_create_auth_token_response.json')

    def empty_func(*args, **kwargs):
        return None

    monkeypatch.setattr(MOCKER_CREATE_AUTH_TOKEN, mock_create_auth_token)
    monkeypatch.setattr(MOCKER_RETURN_FILE_RESULT, empty_func)
    monkeypatch.setattr(MOCKER_RETURN_PASSWORD_PROTECTED_ZIP_FILE_RESULT, empty_func)


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
    assert result.outputs == mock_get_group_list.return_value.get('resources')
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
    assert result.readable_output == f'{args.get(GROUP_NAME)} has been deleted successfully!'


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
    assert result.readable_output == (f'{args[USER_ID]} has been deleted successfully from'
                                      f' {args[GROUP_NAME]}')


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
    assert result.outputs == mock_get_users_list.return_value.get('resources')
    assert result.raw_response == mock_get_users_list.return_value


@patch(MOCKER_HTTP_METHOD)
def test_users_list_command_id_provided(mock_get_user):
    from ThalesCipherTrustManager import CipherTrustClient, users_list_command
    mock_get_user.return_value = util_load_json('test_data/mock_users_list_id_provided_response.json')

    client = CipherTrustClient(username=MOCK_USERNAME, password=MOCK_PASSWORD, server_url=MOCK_SERVER_URL, verify=False,
                               proxy=False)
    args = {USER_ID: 'user1'}

    result = users_list_command(client, args)

    assert isinstance(result, CommandResults)
    assert result.outputs_prefix == USERS_CONTEXT_OUTPUT_PREFIX
    assert result.outputs == mock_get_user.return_value
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
    assert result.readable_output == f'{args[USER_ID]} has been deleted successfully!'


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
    assert result.readable_output == f'Password has been changed successfully for {args[USERNAME]}!'


@pytest.mark.parametrize('args', LOCAL_CA_CREATE_TEST_ARGS)
@patch(MOCKER_HTTP_METHOD)
def test_local_ca_create_command(mock_create_local_ca, args):
    from ThalesCipherTrustManager import CipherTrustClient, local_ca_create_command
    mock_create_local_ca.return_value = util_load_json('test_data/mock_local_ca_create_response.json')
    mock_outputs = remove_keys_from_dict(mock_create_local_ca.return_value, ['csr'])

    client = CipherTrustClient(username=MOCK_USERNAME, password=MOCK_PASSWORD, server_url=MOCK_SERVER_URL, verify=False,
                               proxy=False)

    result = local_ca_create_command(client, args)

    assert isinstance(result, CommandResults)
    assert result.outputs_prefix == LOCAL_CA_CONTEXT_OUTPUT_PREFIX
    assert result.outputs == mock_outputs
    assert result.raw_response == mock_create_local_ca.return_value


@pytest.mark.parametrize('args', LOCAL_CA_LIST_TEST_ARGS)
@patch(MOCKER_HTTP_METHOD)
def test_local_ca_list_command(mock_get_local_ca_list, args):
    from ThalesCipherTrustManager import CipherTrustClient, local_ca_list_command
    mock_get_local_ca_list.return_value = util_load_json('test_data/mock_local_ca_list_response.json')
    mock_outputs = [remove_keys_from_dict(output, ['csr', 'cert']) for output in
                    mock_get_local_ca_list.return_value.get('resources')]

    client = CipherTrustClient(username=MOCK_USERNAME, password=MOCK_PASSWORD, server_url=MOCK_SERVER_URL, verify=False,
                               proxy=False)

    result = local_ca_list_command(client, args)

    assert isinstance(result, CommandResults)
    assert result.outputs_prefix == LOCAL_CA_CONTEXT_OUTPUT_PREFIX
    assert result.outputs == mock_outputs
    assert result.raw_response == mock_get_local_ca_list.return_value


@patch(MOCKER_HTTP_METHOD)
def test_local_ca_list_command_id_provided(mock_get_local_ca):
    from ThalesCipherTrustManager import CipherTrustClient, local_ca_list_command
    mock_get_local_ca.return_value = util_load_json('test_data/mock_local_ca_list_id_provided_response.json')
    mock_outputs = remove_keys_from_dict(mock_get_local_ca.return_value, ['csr', 'cert'])
    client = CipherTrustClient(username=MOCK_USERNAME, password=MOCK_PASSWORD, server_url=MOCK_SERVER_URL, verify=False,
                               proxy=False)
    args = {"local_ca_id": "123e4567-e89b-12d3-a456-426614174000", "chained": "true"}
    result = local_ca_list_command(client, args)

    assert isinstance(result, CommandResults)
    assert result.outputs_prefix == LOCAL_CA_CONTEXT_OUTPUT_PREFIX
    assert result.outputs == [mock_outputs]
    assert result.raw_response == mock_get_local_ca.return_value

    args = {"chained": "true"}
    with pytest.raises(ValueError):
        local_ca_list_command(client, args)


@pytest.mark.parametrize('args', LOCAL_CA_UPDATE_TEST_ARGS)
@patch(MOCKER_HTTP_METHOD)
def test_local_ca_update_command(mock_update_local_ca, args):
    from ThalesCipherTrustManager import CipherTrustClient, local_ca_update_command
    mock_update_local_ca.return_value = util_load_json('test_data/mock_local_ca_update_response.json')
    mock_outputs = remove_keys_from_dict(mock_update_local_ca.return_value, ['csr', 'cert'])
    client = CipherTrustClient(username=MOCK_USERNAME, password=MOCK_PASSWORD, server_url=MOCK_SERVER_URL, verify=False,
                               proxy=False)

    result = local_ca_update_command(client, args)

    assert isinstance(result, CommandResults)
    assert result.outputs_prefix == LOCAL_CA_CONTEXT_OUTPUT_PREFIX
    assert result.outputs == mock_outputs
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
    assert result.readable_output == f'{args[LOCAL_CA_ID]} has been deleted successfully!'


@pytest.mark.parametrize('args', LOCAL_CA_SELF_SIGN_TEST_ARGS)
@patch(MOCKER_HTTP_METHOD)
def test_local_ca_self_sign_command(mock_self_sign_local_ca, args):
    from ThalesCipherTrustManager import CipherTrustClient, local_ca_self_sign_command
    mock_self_sign_local_ca.return_value = util_load_json('test_data/mock_local_ca_self_sign_response.json')
    mock_outputs = remove_keys_from_dict(mock_self_sign_local_ca.return_value, ['csr', 'cert'])
    client = CipherTrustClient(username=MOCK_USERNAME, password=MOCK_PASSWORD, server_url=MOCK_SERVER_URL, verify=False,
                               proxy=False)

    result = local_ca_self_sign_command(client, args)

    assert isinstance(result, CommandResults)
    assert result.outputs_prefix == CA_SELF_SIGN_CONTEXT_OUTPUT_PREFIX
    assert result.outputs == mock_outputs
    assert result.raw_response == mock_self_sign_local_ca.return_value


@pytest.mark.parametrize('args', LOCAL_CA_SELF_SIGN_TEST_MISSING_ARGS)
@patch(MOCKER_HTTP_METHOD)
def test_local_ca_self_sign_command_missing_arguments(mock_self_sign_local_ca, args):
    from ThalesCipherTrustManager import CipherTrustClient, local_ca_self_sign_command
    mock_self_sign_local_ca.return_value = util_load_json('test_data/mock_local_ca_self_sign_response.json')

    client = CipherTrustClient(username=MOCK_USERNAME, password=MOCK_PASSWORD, server_url=MOCK_SERVER_URL, verify=False,
                               proxy=False)

    with pytest.raises(ValueError):
        local_ca_self_sign_command(client, args)


@pytest.mark.parametrize('args', LOCAL_CA_INSTALL_TEST_ARGS)
@patch(MOCKER_LOAD_CONTENT_FROM_FILE)
@patch(MOCKER_HTTP_METHOD)
def test_local_ca_install_command(mock_install_local_ca, mock_load_content_from_file, args):
    from ThalesCipherTrustManager import CipherTrustClient, local_ca_install_command
    mock_install_local_ca.return_value = util_load_json('test_data/mock_local_ca_install_response.json')
    mock_load_content_from_file.return_value = FAKE_CERT
    mock_outputs = remove_keys_from_dict(mock_install_local_ca.return_value, ['csr', 'cert'])

    client = CipherTrustClient(username=MOCK_USERNAME, password=MOCK_PASSWORD, server_url=MOCK_SERVER_URL, verify=False,
                               proxy=False)

    result = local_ca_install_command(client, args)

    assert isinstance(result, CommandResults)
    assert result.outputs_prefix == CA_INSTALL_CONTEXT_OUTPUT_PREFIX
    assert result.outputs == mock_outputs
    assert result.raw_response == mock_install_local_ca.return_value


@pytest.mark.parametrize('args', CERTIFICATE_ISSUE_TEST_ARGS)
@patch(MOCKER_HTTP_METHOD)
@patch(MOCKER_LOAD_CONTENT_FROM_FILE)
def test_certificate_issue_command(mock_load_content_from_file, mock_issue_certificate, args):
    from ThalesCipherTrustManager import CipherTrustClient, certificate_issue_command
    mock_issue_certificate.return_value = util_load_json('test_data/mock_certificate_issue_response.json')
    mock_load_content_from_file.return_value = FAKE_CSR
    mock_outputs = remove_keys_from_dict(mock_issue_certificate.return_value, ['cert'])

    client = CipherTrustClient(username=MOCK_USERNAME, password=MOCK_PASSWORD, server_url=MOCK_SERVER_URL, verify=False,
                               proxy=False)

    result = certificate_issue_command(client, args)

    assert isinstance(result, CommandResults)
    assert result.outputs_prefix == CA_CERTIFICATE_CONTEXT_OUTPUT_PREFIX
    assert result.outputs == mock_outputs
    assert result.raw_response == mock_issue_certificate.return_value


@patch(MOCKER_HTTP_METHOD)
@patch(MOCKER_LOAD_CONTENT_FROM_FILE)
def test_certificate_issue_command_missing_args(mock_load_content_from_file, mock_issue_certificate):
    from ThalesCipherTrustManager import CipherTrustClient, certificate_issue_command
    mock_issue_certificate.return_value = util_load_json('test_data/mock_certificate_issue_response.json')
    mock_load_content_from_file.return_value = FAKE_CSR
    client = CipherTrustClient(username=MOCK_USERNAME, password=MOCK_PASSWORD, server_url=MOCK_SERVER_URL, verify=False,
                               proxy=False)
    args = {CA_ID: "ca12345", CSR_ENTRY_ID: "csr12345", PURPOSE: "test"}
    with pytest.raises(ValueError):
        certificate_issue_command(client, args)


@pytest.mark.parametrize('args', CERTIFICATE_LIST_TEST_ARGS)
@patch(MOCKER_HTTP_METHOD)
def test_certificate_list_command(mock_get_certificates_list, args):
    from ThalesCipherTrustManager import CipherTrustClient, certificate_list_command
    mock_get_certificates_list.return_value = util_load_json('test_data/mock_certificate_list_response.json')
    mock_outputs = [remove_keys_from_dict(output, ['csr', 'cert']) for output in
                    mock_get_certificates_list.return_value.get('resources')]
    client = CipherTrustClient(username=MOCK_USERNAME, password=MOCK_PASSWORD, server_url=MOCK_SERVER_URL, verify=False,
                               proxy=False)

    result = certificate_list_command(client, args)

    assert isinstance(result, CommandResults)
    assert result.outputs_prefix == CA_CERTIFICATE_CONTEXT_OUTPUT_PREFIX
    assert result.outputs == mock_outputs
    assert result.raw_response == mock_get_certificates_list.return_value


@pytest.mark.parametrize('args', LOCAL_CERTIFICATE_DELETE_TEST_ARGS)
@patch(MOCKER_HTTP_METHOD)
def test_local_certificate_delete_command(mock_delete_certificate, args):
    from ThalesCipherTrustManager import CipherTrustClient, local_certificate_delete_command
    mock_delete_certificate.return_value = None

    client = CipherTrustClient(username=MOCK_USERNAME, password=MOCK_PASSWORD, server_url=MOCK_SERVER_URL, verify=False,
                               proxy=False)

    result = local_certificate_delete_command(client, args)

    assert isinstance(result, CommandResults)
    assert result.outputs_prefix is None
    assert result.outputs == mock_delete_certificate.return_value
    assert result.raw_response == mock_delete_certificate.return_value
    assert result.readable_output == f'{args[LOCAL_CA_ID]} has been deleted successfully!'


@pytest.mark.parametrize('args', CERTIFICATE_REVOKE_TEST_ARGS)
@patch(MOCKER_HTTP_METHOD)
def test_certificate_revoke_command(mock_revoke_certificate, args):
    from ThalesCipherTrustManager import CipherTrustClient, certificate_revoke_command
    mock_revoke_certificate.return_value = util_load_json('test_data/mock_certificate_revoke_response.json')
    mock_outputs = remove_keys_from_dict(mock_revoke_certificate.return_value, ['cert'])
    client = CipherTrustClient(username=MOCK_USERNAME, password=MOCK_PASSWORD, server_url=MOCK_SERVER_URL, verify=False,
                               proxy=False)

    result = certificate_revoke_command(client, args)

    assert isinstance(result, CommandResults)
    assert result.outputs_prefix == CA_CERTIFICATE_CONTEXT_OUTPUT_PREFIX
    assert result.outputs == mock_outputs
    assert result.raw_response == mock_revoke_certificate.return_value
    assert result.readable_output == f'{args[CERT_ID]} has been revoked'


@pytest.mark.parametrize('args', CERTIFICATE_RESUME_TEST_ARGS)
@patch(MOCKER_HTTP_METHOD)
def test_certificate_resume_command(mock_resume_certificate, args):
    from ThalesCipherTrustManager import CipherTrustClient, certificate_resume_command
    mock_resume_certificate.return_value = util_load_json('test_data/mock_certificate_resume_response.json')
    mock_outputs = remove_keys_from_dict(mock_resume_certificate.return_value, ['cert'])

    client = CipherTrustClient(username=MOCK_USERNAME, password=MOCK_PASSWORD, server_url=MOCK_SERVER_URL, verify=False,
                               proxy=False)

    result = certificate_resume_command(client, args)

    assert isinstance(result, CommandResults)
    assert result.outputs_prefix == CA_CERTIFICATE_CONTEXT_OUTPUT_PREFIX
    assert result.outputs == mock_outputs
    assert result.raw_response == mock_resume_certificate.return_value
    assert result.readable_output == f'{args[CERT_ID]} has been resumed'


@pytest.mark.parametrize('args', EXTERNAL_CA_UPLOAD_TEST_ARGS)
@patch(MOCKER_HTTP_METHOD)
@patch(MOCKER_LOAD_CONTENT_FROM_FILE)
def test_external_ca_upload_command(mock_load_content_from_file, mock_upload_external_ca, args):
    from ThalesCipherTrustManager import CipherTrustClient, external_ca_upload_command
    mock_upload_external_ca.return_value = util_load_json('test_data/mock_external_ca_upload_response.json')
    mock_outputs = remove_keys_from_dict(mock_upload_external_ca.return_value, ['cert'])
    mock_load_content_from_file.return_value = FAKE_CERT

    client = CipherTrustClient(username=MOCK_USERNAME, password=MOCK_PASSWORD, server_url=MOCK_SERVER_URL, verify=False,
                               proxy=False)

    result = external_ca_upload_command(client, args)

    assert isinstance(result, CommandResults)
    assert result.outputs_prefix == EXTERNAL_CA_CONTEXT_OUTPUT_PREFIX
    assert result.outputs == mock_outputs
    assert result.raw_response == mock_upload_external_ca.return_value


@pytest.mark.parametrize('args', EXTERNAL_CA_DELETE_TEST_ARGS)
@patch(MOCKER_HTTP_METHOD)
def test_external_ca_delete_command(mock_delete_external_ca, args):
    from ThalesCipherTrustManager import CipherTrustClient, external_ca_delete_command
    mock_delete_external_ca.return_value = None

    client = CipherTrustClient(username=MOCK_USERNAME, password=MOCK_PASSWORD, server_url=MOCK_SERVER_URL, verify=False,
                               proxy=False)

    result = external_ca_delete_command(client, args)

    assert isinstance(result, CommandResults)
    assert result.outputs_prefix is None
    assert result.outputs == mock_delete_external_ca.return_value
    assert result.raw_response == mock_delete_external_ca.return_value
    assert result.readable_output == f'{args[EXTERNAL_CA_ID]} has been deleted successfully!'


@pytest.mark.parametrize('args', EXTERNAL_CA_UPDATE_TEST_ARGS)
@patch(MOCKER_HTTP_METHOD)
def test_external_ca_update_command(mock_update_external_ca, args):
    from ThalesCipherTrustManager import CipherTrustClient, external_ca_update_command
    mock_update_external_ca.return_value = util_load_json('test_data/mock_external_ca_update_response.json')
    mock_outputs = remove_keys_from_dict(mock_update_external_ca.return_value, ['cert'])

    client = CipherTrustClient(username=MOCK_USERNAME, password=MOCK_PASSWORD, server_url=MOCK_SERVER_URL, verify=False,
                               proxy=False)

    result = external_ca_update_command(client, args)

    assert isinstance(result, CommandResults)
    assert result.outputs_prefix == EXTERNAL_CA_CONTEXT_OUTPUT_PREFIX
    assert result.outputs == mock_outputs
    assert result.raw_response == mock_update_external_ca.return_value


@pytest.mark.parametrize('args', EXTERNAL_CA_LIST_TEST_ARGS)
@patch(MOCKER_HTTP_METHOD)
def test_external_ca_list_command(mock_get_external_ca_list, args):
    from ThalesCipherTrustManager import CipherTrustClient, external_ca_list_command
    mock_get_external_ca_list.return_value = util_load_json(
        'test_data/mock_external_ca_list_response.json')
    mock_outputs = [remove_keys_from_dict(output, ['cert']) for output in mock_get_external_ca_list.return_value.get('resources')]

    client = CipherTrustClient(username=MOCK_USERNAME, password=MOCK_PASSWORD, server_url=MOCK_SERVER_URL, verify=False,
                               proxy=False)

    result = external_ca_list_command(client, args)

    assert isinstance(result, CommandResults)
    assert result.outputs_prefix == EXTERNAL_CA_CONTEXT_OUTPUT_PREFIX
    assert result.outputs == mock_outputs
    assert result.raw_response == mock_get_external_ca_list.return_value


@pytest.mark.parametrize('args', CSR_GENERATE_TEST_ARGS)
@patch(MOCKER_HTTP_METHOD)
def test_csr_generate_command(mock_create_csr, args):
    from ThalesCipherTrustManager import CipherTrustClient, csr_generate_command

    mock_create_csr.return_value = util_load_json('test_data/mock_csr_generate_response.json')
    client = CipherTrustClient(username=MOCK_USERNAME, password=MOCK_PASSWORD, server_url=MOCK_SERVER_URL, verify=False,
                               proxy=False)
    result = csr_generate_command(client, args)
    assert isinstance(result, CommandResults)
    assert result.outputs_prefix == CSR_CONTEXT_OUTPUT_PREFIX
    assert result.outputs is None
    assert result.raw_response is None
    assert result.readable_output == f'CSR and its corresponding private key have been generated successfully for {args.get(CN)}.'
