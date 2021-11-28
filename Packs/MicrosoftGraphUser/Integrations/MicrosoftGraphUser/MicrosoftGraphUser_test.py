
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
                           'self_deployed', 'redirect_uri', 'auth_code')
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
                           'self_deployed', 'redirect_uri', 'auth_code')
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
