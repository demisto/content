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
    'use_oauth': True
}


def test_get_access_token(mocker):
    """Unit test
    Given
    - Integration context with/without valid/expired access token.
    When
    - Calling the get_access_token function.
    Then
    - Validate that an valid access token is returned if one exist, else that a new one is created.
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
    create_new_token_response = {
        'access_token': 'new_token',
        'refresh_token': 'refresh_token',
        'expires_in': 1
    }

    mocker.patch('ServiceNowApiModule.date_to_timestamp', return_value=0)
    client = ServiceNowClient(credentials=PARAMS.get('credentials', {}), use_oauth=PARAMS.get('use_oauth', False),
                              client_id=PARAMS.get('client_id', ''), client_secret=PARAMS.get('client_secret', ''),
                              url=PARAMS.get('url', ''), verify=PARAMS.get('insecure', False),
                              proxy=PARAMS.get('proxy', False), headers=PARAMS.get('headers', ''))

    # Validate the previous access token is returned, as it is still valid
    mocker.patch.object(demisto, 'getIntegrationContext', return_value=valid_access_token)
    assert client.get_access_token() == 'previous_token'

    # Validate that a new access token is returned when the previous has expired
    mocker.patch.object(demisto, 'getIntegrationContext', return_value=expired_access_token)
    mocker.patch.object(client, 'http_request', return_value=create_new_token_response)
    assert client.get_access_token() == 'new_token'

    # Validate that an error is returned in case the user didn't run `!servicenow-login` first
    mocker.patch.object(demisto, 'getIntegrationContext', return_value={})
    try:
        client.get_access_token()
    except Exception as e:
        assert 'Could not create an access token' in e.args[0]
