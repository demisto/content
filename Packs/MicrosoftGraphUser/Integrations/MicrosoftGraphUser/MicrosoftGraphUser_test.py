
users_list_mock = [
    {
        'id': '08779ba7-f3ed-4344-b9d7-98b9911ea8a8',
        'displayName': 'Test User',
        'jobTitle': "Magician",
        'mobilePhone': None,
        'mail': None
    },
    {
        'id': '670edadc-0197-45b0-90e6-ee061e25ab73',
        'displayName': 'Test1',
        'jobTitle': 'TESTER',
        'mobilePhone': '050505050',
        'mail': None,
        "@removed": {
            "reason": "changed"
        }
    }
]

expected_outputs = [
    {
        'ID': '08779ba7-f3ed-4344-b9d7-98b9911ea8a8',
        'DisplayName': 'Test User',
        'JobTitle': "Magician",
        'MobilePhone': None,
        'Mail': None
    },
    {
        'ID': '670edadc-0197-45b0-90e6-ee061e25ab73',
        'DisplayName': 'Test1',
        'JobTitle': 'TESTER',
        'MobilePhone': '050505050',
        'Mail': None,
        'Status': 'deleted'
    }
]


def test_camel_case_to_readable():
    from MicrosoftGraphUser import camel_case_to_readable
    assert camel_case_to_readable('id') == 'ID'
    assert camel_case_to_readable('createdDateTime') == 'Created Date Time'


def test_parse_outputs():
    from MicrosoftGraphUser import parse_outputs
    _, parsed_outputs = parse_outputs(users_list_mock)
    assert parsed_outputs == expected_outputs


def test_get_user_command_404_response(mocker):
    """
    Given:
        - The get_user_command
    When:
        - The returned response is a 404 - not found error.
    Then:
        - Validate that the error is handled and that the human readable indicates an error.
    """
    from MicrosoftGraphUser import MsGraphClient, get_user_command
    from MicrosoftApiModule import MicrosoftClient, BaseClient
    from requests.models import Response

    client = MsGraphClient('tenant_id', 'auth_id', 'enc_key', 'app_name', 'base_url', 'verify', 'proxy',
                           'self_deployed', 'redirect_uri', 'auth_code', True)
    error_404 = Response()
    error_404._content = b'{"error": {"code": "Request_ResourceNotFound", "message": "Resource ' \
                         b'"NotExistingUser does not exist."}}'
    error_404.status_code = 404
    mocker.patch.object(BaseClient, '_http_request', return_value=error_404)
    mocker.patch.object(MicrosoftClient, 'get_access_token')
    hr, _, _ = get_user_command(client, {'user': 'NotExistingUser'})  # client.get_user('user', 'properties')
    assert 'User NotExistingUser was not found' in hr


def test_get_user_command_url_saved_chars(mocker):
    """
    Given:
        - The get_user_command
    When:
        - The returned response is a 404 - not found error.
    Then:
        - Validate that the error is handled and that the human readable indicates an error.
    """
    from MicrosoftGraphUser import MsGraphClient, get_user_command
    from MicrosoftApiModule import MicrosoftClient, BaseClient

    user_name = "dbot^"
    client = MsGraphClient('tenant_id', 'auth_id', 'enc_key', 'app_name', 'http://base_url', 'verify', 'proxy',
                           'self_deployed', 'redirect_uri', 'auth_code', False)
    http_mock = mocker.patch.object(BaseClient, '_http_request')
    mocker.patch.object(MicrosoftClient, 'get_access_token')
    hr, _, _ = get_user_command(client, {'user': user_name})
    assert 'users/dbot%5E' == http_mock.call_args[1]["url_suffix"]


def test_get_unsupported_chars_in_user():
    """
    Given:
        - User with unsupported characters
    When:
        - Calling get_unsupported_chars_in_user
    Then:
        - Validate special characters were extracted
    """
    from MicrosoftGraphUser import get_unsupported_chars_in_user
    invalid_chars = '%&*+/=?`{|}'
    invalid_user = f'demi{invalid_chars}sto'

    assert len(get_unsupported_chars_in_user(invalid_user).difference(set(invalid_chars))) == 0


def test_suppress_errors(mocker):

    from MicrosoftGraphUser import unblock_user_command, disable_user_account_command, \
        update_user_command, change_password_user_command, delete_user_command, \
        get_direct_reports_command, get_manager_command, assign_manager_command, \
        revoke_user_session_command, MsGraphClient
    from MicrosoftApiModule import NotFoundError

    TEST_SUPPRESS_ERRORS = [
        {'fun': unblock_user_command, 'mock_fun': 'unblock_user',
         'mock_value': NotFoundError('123456789'), 'args': {'user': '123456789'},
         'expected_result': '#### User -> 123456789 does not exist'},
        {'fun': disable_user_account_command, 'mock_fun': 'disable_user_account_session',
         'mock_value': NotFoundError('123456789'), 'args': {'user': '123456789'},
         'expected_result': '#### User -> 123456789 does not exist'},
        {'fun': update_user_command, 'mock_fun': 'update_user',
         'mock_value': NotFoundError('123456789'), 'args': {'user': '123456789'},
         'expected_result': '#### User -> 123456789 does not exist'},
        {'fun': change_password_user_command, 'mock_fun': 'password_change_user',
         'mock_value': NotFoundError('123456789'), 'args': {'user': '123456789'},
         'expected_result': '#### User -> 123456789 does not exist'},
        {'fun': delete_user_command, 'mock_fun': 'delete_user',
         'mock_value': NotFoundError('123456789'), 'args': {'user': '123456789'},
         'expected_result': '#### User -> 123456789 does not exist'},
        {'fun': get_direct_reports_command, 'mock_fun': 'get_direct_reports',
         'mock_value': NotFoundError('123456789'), 'args': {'user': '123456789'},
         'expected_result': '#### User -> 123456789 does not exist'},
        {'fun': get_manager_command, 'mock_fun': 'get_manager',
         'mock_value': NotFoundError('123456789'), 'args': {'user': '123456789'},
         'expected_result': '#### User -> 123456789 does not exist'},
        {'fun': assign_manager_command, 'mock_fun': 'assign_manager',
         'mock_value': NotFoundError('123456789'), 'args': {'user': '123456789'},
         'expected_result': '#### User -> 123456789 does not exist'},
        {'fun': assign_manager_command, 'mock_fun': 'assign_manager',
         'mock_value': NotFoundError('123456789'), 'args': {'manager': '123456789'},
         'expected_result': '#### Manager -> 123456789 does not exist'},
        {'fun': revoke_user_session_command, 'mock_fun': 'revoke_user_session',
         'mock_value': NotFoundError('123456789'), 'args': {'user': '123456789'},
         'expected_result': '#### User -> 123456789 does not exist'}
    ]

    client = MsGraphClient(base_url='https://graph.microsoft.com/v1.0', tenant_id='tenant-id',
                           auth_id='auth_and_token_url', enc_key='enc_key', app_name='ms-graph-groups',
                           verify='use_ssl', proxy='proxies', self_deployed='self_deployed', handle_error=True,
                           auth_code='', redirect_uri='')
    for test in TEST_SUPPRESS_ERRORS:
        mocker.patch.object(client, test['mock_fun'], side_effect=test['mock_value'])
        results, _, _ = test['fun'](client, test['args'])
        assert results == test['expected_result']
