import pytest

OAUTH1 = {
    'url': 'example.com',
    'consumerKey': 'example_key',
    'accessToken': 'example_token',
    'privateKey': 'example_private_key',
    'username': ''
}

PAT = {'url': 'example.com', 'username': '', 'accessToken': 'example_token'}

BASIC = {'url': 'example.com', 'username': 'example_user', 'APItoken': 'example_token'}
OAUTH2 = {'url': 'example.com', 'client_id': 'id', "client_secret": 'secret', 'auth_code': 'code', 'redirect_uri': 'uri'}
AUTH_CASES = [
    (OAUTH1, {}, {'Content-Type': 'application/json', 'X-Atlassian-Token': 'nocheck'}),
    (OAUTH1, {'X-Atlassian-Token': 'nocheck'}, {'Content-Type': 'application/json', 'X-Atlassian-Token': 'nocheck'}),
    (PAT, {}, {'Content-Type': 'application/json', 'Authorization': 'Bearer example_token', "Accept": "application/json"}),
    (PAT, {'X-Atlassian-Token': 'nocheck'}, {'Content-Type': 'application/json', 'X-Atlassian-Token': 'nocheck',
                                             'Authorization': 'Bearer example_token', "Accept": "application/json"}),
    (BASIC, {}, {'Content-Type': 'application/json'}),
    (BASIC, {'X-Atlassian-Token': 'nocheck'}, {'Content-Type': 'application/json', 'X-Atlassian-Token': 'nocheck'}),
    (OAUTH2, {}, {'Content-Type': 'application/json', 'Authorization': 'Bearer example_token', "Accept": "application/json"}),
]


@pytest.mark.parametrize('params, custom_headers, expected_headers', AUTH_CASES)
def test_http_request(mocker, params, custom_headers, expected_headers):
    """
       Given:
           - Case OAuth authentication: The user is using the default headers for a command
           - Case OAuth authentication: The user is using custom headers for a command
           - Case PAT authentication: The user is using the default headers for a command
           - Case PAT authentication: The user is using custom headers for a command
           - Case BASIC authentication: The user is using the default headers for a command
           - Case BASIC authentication: The user is using custom headers for a command

       When
           - Running any command, trying to make a request to Jira while using specific authentication.
       Then
           - Ensure the authentication headers are correct when using custom headers
           - Ensure the authentication headers are correct when using default headers
       """
    import AtlassianApiModule
    import requests

    class ResponseDummy():
        def __init__(self):
            self.ok = 1
    client = AtlassianApiModule.AtlassianClient(base_url=params.get('url'), access_token=params.get('accessToken'),
                                                api_token=params.get('APItoken'), username=params.get('username'),
                                                password=params.get('password'), consumer_key=params.get('consumerKey'),
                                                private_key=params.get('privateKey'),
                                                headers={'Content-Type': 'application/json'},
                                                client_id=params.get('client_id'),
                                                client_secret=params.get('client_secret'),
                                                auth_code=params.get('auth_code'),
                                                redirect_uri=params.get('redirect_uri'))

    req_mock = mocker.patch.object(requests, 'request', return_value=ResponseDummy())

    mocker.patch.object(client, 'get_access_token', return_value='example_token')
    client.http_request(method='get', headers=custom_headers, full_url=params.get('url'))
    assert expected_headers == req_mock.call_args[1]['headers']
