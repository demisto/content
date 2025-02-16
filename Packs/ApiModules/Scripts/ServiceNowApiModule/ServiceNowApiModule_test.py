from ServiceNowApiModule import *
import demistomock as demisto

PARAMS = {
    'insecure': False,
    'credentials': {
        'identifier': 'user1',
        'password:': '12345'
    },
    'proxy': False,
    'client_id': 'client_id',
    'client_secret': 'client_secret',
    'use_oauth': True,
}


# Unit tests for OAuth authorization
def test_get_access_token(mocker):
    """Unit test
    Given
    A client using OAuth authorization
    - (a) Integration context with a valid access token.
    - (b) Integration context with an expired access token.
    - (c) Empty integration context (mocks the case that the user didn't run the login command first).
    When
    - Calling the get_access_token function while using OAuth 2.0 authorization.
    Then
    - (a) Validate that the previous access token is returned, since it is still valid.
    - (b) Validate that a new access token is returned, as the previous one expired.
    - (c) Validate that an error is raised, asking the user to first run the login command.
    """
    valid_access_token = {
        'access_token': 'previous_token',
        'refresh_token': 'refresh_token',
        'expiry_time': 1
    }
    expired_access_token = {
        'access_token': 'previous_token',
        'refresh_token': 'refresh_token',
        'expiry_time': -1
    }

    from requests.models import Response
    new_token_response = Response()
    new_token_response._content = b'{"access_token": "new_token", "refresh_token": "refresh_token", "expires_in": 1}'
    new_token_response.status_code = 200

    mocker.patch('ServiceNowApiModule.date_to_timestamp', return_value=0)
    client = ServiceNowClient(credentials=PARAMS.get('credentials', {}), use_oauth=True,
                              client_id=PARAMS.get('client_id', ''), client_secret=PARAMS.get('client_secret', ''),
                              url=PARAMS.get('url', ''), verify=PARAMS.get('insecure', False),
                              proxy=PARAMS.get('proxy', False), headers=PARAMS.get('headers', ''))

    # Validate the previous access token is returned, as it is still valid
    mocker.patch.object(demisto, 'getIntegrationContext', return_value=valid_access_token)
    assert client.get_access_token() == 'previous_token'

    # Validate that a new access token is returned when the previous has expired
    mocker.patch.object(demisto, 'getIntegrationContext', return_value=expired_access_token)
    mocker.patch.object(BaseClient, '_http_request', return_value=new_token_response)
    assert client.get_access_token() == 'new_token'

    # Validate that an error is returned in case the user didn't run the login command first
    mocker.patch.object(demisto, 'getIntegrationContext', return_value={})
    try:
        client.get_access_token()
    except Exception as e:
        assert 'Could not create an access token' in e.args[0]


def test_get_jwt_access_token(mocker):
    """Unit test
    Given
    A client using JWT OAuth authorization
    - (a) Integration context with a valid access token.
    - (b) Integration context with an expired access token.
    - (c) Empty integration context (mocks the case that the user didn't run the login command first).
    When
    - Calling the get_jwt_token function while using OAuth 2.0 authorization.
    Then
    - (a) Validate that the previous access token is returned, since it is still valid.
    - (b) Validate that a new access token is returned, as the previous one expired.
    - (c) Validate that an error is raised, asking the user to first run the login command.
    """
    valid_access_token = { 'jwt':{
            'access_token': 'previous_token',
            'expiry_time': 1
        }
        
    }
    expired_access_token = { 'jwt':{
            'access_token': 'previous_token',
            'expiry_time': -1
    }
    }
    params = {
        'insecure': False,
        'credentials': {
            'identifier': 'user1',
            'password:': '12345'
        },
        'proxy': False,
        'client_id': 'client_id',
        'client_secret': 'client_secret',
        'use_oauth': False,
        'credentials_jwt': {'identifier': '1111111', 'password': 'password'},
        'jwt_sub': 'dummy@example.com',
        'use_jwt_outh': True,
        "jwt_credentials":
        {'identifier': '22222222222',
         'password': """-----BEGIN PRIVATE KEY-----
            sertificate_example=
    -----END PRIVATE KEY-----"""}
    }

    from requests.models import Response
    new_token_response = Response()
    new_token_response._content = b'{"access_token": "new_token", "expires_in": 1}'
    new_token_response.status_code = 200

    mocker.patch('ServiceNowApiModule.date_to_timestamp', return_value=0)
    client = ServiceNowClient(
        credentials=params.get('credentials', {}),
        use_jwt=params.get('use_jwt', True),
        client_id=params.get('client_id', ''),
        client_secret=params.get('client_secret', ''),
        url=params.get('url', ''),
        verify=params.get('verify', False),
        proxy=params.get('proxy', False),
        headers=params.get('headers', ''),
        jwt_key_id=params.get('jwt_key_id', ''),
        jwt_key=params.get('jwt_private_key', ''),
        jwt_sub=params.get('jwt_sub', '')
    )

    # Validate the previous access token is returned, as it is still valid
    mocker.patch.object(demisto, 'getIntegrationContext', return_value=valid_access_token)
    assert client.get_jwt_token() == 'previous_token'

    # Validate that a new access token is returned when the previous has expired
    mocker.patch.object(demisto, 'getIntegrationContext', return_value=expired_access_token)
    mocker.patch.object(jwt,'encode', return_value= 'jwt_token')
    mocker.patch.object(BaseClient, '_http_request', return_value=new_token_response)
    mocker.patch('CommonServerPython.replace_spaces_in_credential', return_value=params['jwt_credentials']['password'])
    assert client.get_jwt_token() == 'new_token'

    # Validate that an error is returned in case the user didn't run the login command first
    mocker.patch.object(demisto, 'getIntegrationContext', return_value={})
    mocker.patch.object(jwt,'encode', return_value= 'jwt_token')


def test_separate_client_id_and_refresh_token():
    """Unit test
    Given
    - Integration parameters and a client_id parameter which contains a '@' characters that separates between the 'real'
      client id and the refresh token.
    When
    - Calling the ServiceNowClient constructor while using OAuth 2.0 authorization.
    Then
    - Verify that the client_id field of the client contains only the 'real' client id.
    """
    client_id_with_strudel = 'client_id@refresh_token'
    client = ServiceNowClient(credentials=PARAMS.get('credentials', {}), use_oauth=True,
                              client_id=client_id_with_strudel, client_secret=PARAMS.get('client_secret', ''),
                              url=PARAMS.get('url', ''), verify=PARAMS.get('insecure', False),
                              proxy=PARAMS.get('proxy', False), headers=PARAMS.get('headers', ''))
    assert client.client_id == 'client_id'
