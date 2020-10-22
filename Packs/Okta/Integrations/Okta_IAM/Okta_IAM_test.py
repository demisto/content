import demistomock as demisto
from requests import Response, Session
from Okta_IAM import Client, get_user_command  # , create_user_command, update_user_command, enable_user_command
from CommonServerPython import IAMErrors, IAMUserProfile

''' ARGUMENTS '''

USER_ARGS = {
    'user-profile': {
        'email': 'testdemisto2@paloaltonetworks.com'
    }
}


''' OUTPUTS '''

GET_USER_OUTPUT__EXISTING_USER = {
    "id": "mock_id",
    "status": "PROVISIONED",
    "profile": {
        "firstName": "mock_first_name",
        "lastName": "mock_last_name",
        "login": "testdemisto2@paloaltonetworks.com",
        "email": "testdemisto2@paloaltonetworks.com"
    }
}


def test_exception_response_text_parsing_when_ok_code_is_invalid(self, requests_mock):
    from CommonServerPython import DemistoException
    reason = 'Bad Request'
    text_response = '{"error": "additional text"}'
    requests_mock.get('https://test.com/api/v1/',
                      status_code=400,
                      reason=reason,
                      text=text_response)
    try:
        self.client._http_request('get', 'event', resp_type='text', ok_codes=(200,))
    except DemistoException as e:
        assert e.res.get('error') == 'additional text'


GET_USER_REQUEST__BAD_RESPONSE = Response()
GET_USER_REQUEST__BAD_RESPONSE.status_code = 500
GET_USER_REQUEST__BAD_RESPONSE. = {
    'errorCode': 'mock_error_code',
    'errorSummary': 'mock_error_summary',
    'errorCauses': [
        'reason_1', 'reason_2'
    ]
}


def mock_client():
    client = Client(
        base_url='https://test.com',
        verify=False,
        token='test',
        proxy=False
    )
    return client


def get_outputs_from_user_profile(user_profile):
    entry_context = user_profile.to_entry()
    outputs = entry_context.get('Contents')
    return outputs


def test_get_user_command__existing_user(mocker):
    """
    Given:
        - An Okta IAM client object
        - A user-profile argument that contains an email of an existing user in Okta
    When:
        - Calling function get_user_command
    Then:
        - Ensure the resulted User Profile object holds the correct user details
    """
    client = mock_client()
    args = USER_ARGS

    mocker.patch.object(demisto, 'command', return_value='get-user')
    mocker.patch.object(client, 'get_user', return_value=GET_USER_OUTPUT__EXISTING_USER)
    mocker.patch.object(IAMUserProfile, 'update_with_app_data', return_value={})

    user_profile = get_user_command(client, args, 'mocked_mapper_in')
    outputs = get_outputs_from_user_profile(user_profile)

    assert outputs.get('action') == 'get'
    assert outputs.get('success') is True
    assert outputs.get('active') is True
    assert outputs.get('id') == 'mock_id'
    assert outputs.get('username') == 'testdemisto2@paloaltonetworks.com'
    assert outputs.get('details', {}).get('profile', {}).get('firstName') == 'mock_first_name'
    assert outputs.get('details', {}).get('profile', {}).get('lastName') == 'mock_last_name'


def test_get_user_command__non_existing_user(mocker):
    """
    Given:
        - An Okta IAM client object
        - A user-profile argument that contains an email of a non-existing user in Okta
    When:
        - Calling function get_user_command
    Then:
        - Ensure the resulted User Profile object holds information about an unsuccessful result.
    """
    client = mock_client()
    args = USER_ARGS

    mocker.patch.object(demisto, 'command', return_value='get-user')
    mocker.patch.object(client, 'get_user', return_value=None)

    user_profile = get_user_command(client, args, 'mocked_mapper_in')
    outputs = get_outputs_from_user_profile(user_profile)

    assert outputs.get('action') == 'get'
    assert outputs.get('success') is False
    assert outputs.get('errorCode') == IAMErrors.USER_DOES_NOT_EXIST[0]
    assert outputs.get('errorMessage') == IAMErrors.USER_DOES_NOT_EXIST[1]


def test_get_user_command__bad_response(mocker):
    """
    Given:
        - An Okta IAM client object
        - A user-profile argument that contains an email of a non-existing user in Okta
    When:
        - Calling function get_user_command
        - A bad response (500) is returned from Okta's API
    Then:
        - Ensure the resulted User Profile object holds information about the bad response.
    """
    client = mock_client()
    args = USER_ARGS

    mocker.patch.object(demisto, 'command', return_value='get-user')
    mocker.patch.object(Session, 'request', return_value=GET_USER_REQUEST__BAD_RESPONSE)

    user_profile = get_user_command(client, args, 'mocked_mapper_in')
    outputs = get_outputs_from_user_profile(user_profile)

    assert outputs.get('action') == 'get'
    assert outputs.get('success') is False
    assert outputs.get('errorCode') == 'mock_error_code'
    assert outputs.get('errorMessage') == 'mock_error_summary. Reason:\n1. reason_1\n2.reason_2'
