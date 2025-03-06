import freezegun
from requests import Response
from MicrosoftApiModule import *
import demistomock as demisto
import pytest
import datetime

TOKEN = 'dummy_token'
TENANT = 'dummy_tenant'
REFRESH_TOKEN = 'dummy_refresh'
AUTH_ID = 'dummy_auth_id'
ENC_KEY = 'dummy_enc_key'
TOKEN_URL = 'mock://dummy_url'
APP_NAME = 'ms-graph-mail-listener'
BASE_URL = 'https://graph.microsoft.com/v1.0/'
OK_CODES = (200, 201, 202)

CLIENT_ID = 'dummy_client'
CLIENT_SECRET = 'dummy_secret'
APP_URL = 'https://login.microsoftonline.com/dummy_tenant/oauth2/v2.0/token'
SCOPE = 'https://graph.microsoft.com/.default'
RESOURCE = 'https://defender.windows.com/shtak'
RESOURCES = ['https://resource1.com', 'https://resource2.com']
FREEZE_STR_DATE = "1970-01-01 00:00:00"


def oproxy_client_tenant():
    tenant_id = TENANT
    auth_id = f'{AUTH_ID}@{TOKEN_URL}'
    enc_key = ENC_KEY
    app_name = APP_NAME
    base_url = BASE_URL
    ok_codes = OK_CODES

    return MicrosoftClient(self_deployed=False, auth_id=auth_id, enc_key=enc_key, app_name=app_name,
                           tenant_id=tenant_id, base_url=base_url, verify=True, proxy=False, ok_codes=ok_codes)


def oproxy_client_multi_resource():
    tenant_id = TENANT
    auth_id = f'{AUTH_ID}@{TOKEN_URL}'
    enc_key = ENC_KEY
    app_name = APP_NAME
    base_url = BASE_URL
    ok_codes = OK_CODES

    return MicrosoftClient(self_deployed=False, auth_id=auth_id, enc_key=enc_key, app_name=app_name,
                           tenant_id=tenant_id, base_url=base_url, verify=True, proxy=False,
                           ok_codes=ok_codes, multi_resource=True,
                           resources=['https://resource1.com', 'https://resource2.com'])


def oproxy_client_refresh():
    refresh_token = REFRESH_TOKEN  # represents the refresh token from the integration context
    auth_id = f'{AUTH_ID}@{TOKEN_URL}'
    enc_key = ENC_KEY
    app_name = APP_NAME
    base_url = BASE_URL
    ok_codes = OK_CODES

    return MicrosoftClient(self_deployed=False, auth_id=auth_id, enc_key=enc_key, app_name=app_name,
                           refresh_token=refresh_token, base_url=base_url, verify=True, proxy=False, ok_codes=ok_codes,
                           )


def self_deployed_client():
    tenant_id = TENANT
    client_id = CLIENT_ID
    client_secret = CLIENT_SECRET
    base_url = BASE_URL
    resource = RESOURCE
    ok_codes = OK_CODES

    return MicrosoftClient(self_deployed=True, tenant_id=tenant_id, auth_id=client_id, enc_key=client_secret,
                           resource=resource, base_url=base_url, verify=True, proxy=False, ok_codes=ok_codes)


def self_deployed_client_multi_resource():
    tenant_id = TENANT
    client_id = CLIENT_ID
    client_secret = CLIENT_SECRET
    base_url = BASE_URL
    resources = RESOURCES
    ok_codes = OK_CODES

    return MicrosoftClient(self_deployed=True, tenant_id=tenant_id, auth_id=client_id, enc_key=client_secret,
                           resources=resources, multi_resource=True, base_url=base_url, verify=True, proxy=False,
                           ok_codes=ok_codes)


def retry_on_rate_limit_client(retry_on_rate_limit: bool):
    tenant_id = TENANT
    client_id = CLIENT_ID
    client_secret = CLIENT_SECRET
    base_url = BASE_URL
    resource = RESOURCE
    ok_codes = OK_CODES

    return MicrosoftClient(self_deployed=True, tenant_id=tenant_id, auth_id=client_id, enc_key=client_secret,
                           resource=resource, base_url=base_url, verify=True, proxy=False, ok_codes=ok_codes,
                           retry_on_rate_limit=retry_on_rate_limit)


@pytest.mark.parametrize('error_content, status_code, expected_response', [
    (b'{"error":{"code":"code","message":"message"}}', 401, 'code: message'),
    (b'{"error": "invalid_grant", "error_description": "AADSTS700082: The refresh token has expired due to inactivity.'
     b'\\u00a0The token was issued on 2023-02-06T12:26:14.6448497Z and was inactive for 90.00:00:00.'
     b'\\r\\nTrace ID: test\\r\\nCorrelation ID: test\\r\\nTimestamp: 2023-07-02 06:40:26Z", '
     b'"error_codes": [700082], "timestamp": "2023-07-02 06:40:26Z", "trace_id": "test", "correlation_id": "test",'
     b' "error_uri": "https://login.microsoftonline.com/error?code=700082"}', 400,
     'invalid_grant. \nThe refresh token has expired due to inactivity.\xa0The token was issued on 2023-02-06T12:26:14.6448497Z '
     'and was inactive for 90.00:00:00.\nYou can run the ***command_prefix-auth-reset*** command to '
     'reset the authentication process.'),
    (b'{"error": "invalid_resource", "error_description": "AADSTS500011: The resource principal named '
     b'https://security.microsoft.us was not found in the tenant named x Inc.. This can happen if the '
     b'application has not been installed by the administrator of the tenant or consented to by any user '
     b'in the tenant. You might have sent your authentication request to the wrong tenant. '
     b'Trace ID: test Correlation ID: test '
     b'Timestamp: 2025-02-26 14:27:01Z", "error_codes": [500011], "timestamp": "2025-02-26 14:27:01Z", '
     b'"trace_id": "test", "correlation_id": "test", "error_uri": "https://login.microsoftonline.us/error?code=500011"}', 400,
     'invalid_resource. \nThe resource principal named https://security.microsoft.us was not found in the tenant named x Inc.. '
     'This can happen if the application has not been installed by the administrator of the tenant or consented '
     'to by any user in the tenant. You might have sent your authentication request to the wrong tenant.')])
def test_error_parser(mocker, error_content, status_code, expected_response):
    """
    Given:
        - The error_content, status_code, and expected_response for testing the error_parser function.
    When:
        - The error_parser function is called with the given error_content and status_code.
    Then:
        - Assert that the response from the error_parser matches the expected_response.
    """
    mocker.patch.object(demisto, 'error')
    client = self_deployed_client()
    err = Response()
    err.status_code = status_code
    err._content = error_content
    response = client.error_parser(err)
    assert response == expected_response


def test_raise_authentication_error(mocker):
    """
    Given:
        - The error_content, status_code, and expected_response for testing the _raise_authentication_error function.
    When:
        - The _raise_authentication_error function is called with the given error_content and status_code.
    Then:
        - Assert that the response from the _raise_authentication_error matches the expected_response.
    """
    mocker.patch.object(demisto, 'error')
    client = oproxy_client_tenant()
    err = Response()
    err.status_code = 401
    error_content_str = "Error: failed to get access token with err: " \
                        "{\"error\":\"invalid_grant\",\"error_description\":\"AADSTS700003: Device object was not found in the " \
                        "tenant 'test' directory.\\r\\nTrace ID: test\\r\\nCorrelation ID: test\\r\\n" \
                        "Timestamp: 2023-07-20 12:03:53Z\",\"error_codes\":[700003],\"timestamp\":\"2023-07-20 12:03:53Z\"," \
                        "\"trace_id\":\"test\",\"correlation_id\":\"test\"," \
                        "\"error_uri\":\"https://login.microsoftonline.com/error?code=700003\",\"suberror\":" \
                        "\"device_authentication_failed\",\"claims\":\"{\\\"access_token\\\":{\\\"capolids\\\":" \
                        "{\\\"essential\\\":true,\\\"values\\\":[\\\"test\\\"]}}}\"}"
    err._content = error_content_str.encode('utf-8')
    err.reason = "test reason"
    expected_msg = "Error in Microsoft authorization. Status: 401, body: invalid_grant. \nDevice object was not found in " \
                   "the tenant 'test' directory."
    with pytest.raises(Exception, match=expected_msg):
        client._raise_authentication_error(err)


def test_page_not_found_error(mocker):
    """
    Given:
        - The http_request command for making MS API calls.
    When:
        - The response returned is a 404 response.
    Then:
        - Validate that the exception is handled in the http_request function of MicrosoftClient.
    """
    error_404 = Response()
    error_404._content = b'{"error": {"code": "Request_ResourceNotFound", "message": "Resource ' \
                         b'"NotExistingUser does not exist."}}'
    error_404.status_code = 404
    client = self_deployed_client()
    mocker.patch.object(BaseClient, '_http_request', return_value=error_404)
    mocker.patch.object(client, 'get_access_token')

    with pytest.raises(NotFoundError):
        client.http_request()


def test_epoch_seconds(mocker):
    mocker.patch.object(MicrosoftClient, '_get_utcnow', return_value=datetime.datetime(2019, 12, 24, 14, 12, 0, 586636))
    mocker.patch.object(MicrosoftClient, '_get_utc_from_timestamp', return_value=datetime.datetime(1970, 1, 1, 0, 0))
    integer = MicrosoftClient.epoch_seconds()
    assert integer == 1577196720


@pytest.mark.parametrize('client, tokens, context', [(oproxy_client_refresh(), (TOKEN, 3600, REFRESH_TOKEN),
                                                      {'access_token': TOKEN,
                                                       'valid_until': 3605,
                                                       'current_refresh_token': REFRESH_TOKEN}),
                                                     (oproxy_client_tenant(), (TOKEN, 3600, ''),
                                                      {'access_token': TOKEN,
                                                       'valid_until': 3605,
                                                       'current_refresh_token': ''}),
                                                     (self_deployed_client(),
                                                      (TOKEN, 3600, REFRESH_TOKEN),
                                                      {'access_token': TOKEN,
                                                       'valid_until': 3605,
                                                       'current_refresh_token': REFRESH_TOKEN})])
def test_get_access_token_no_context(mocker, client, tokens, context):
    mocker.patch.object(demisto, 'getIntegrationContext', return_value={})
    mocker.patch.object(demisto, 'setIntegrationContext')

    mocker.patch.object(client, '_oproxy_authorize', return_value=tokens)
    mocker.patch.object(client, '_get_self_deployed_token', return_value=tokens)
    mocker.patch.object(client, 'epoch_seconds', return_value=10)

    # Arrange
    token = client.get_access_token()

    integration_context = demisto.setIntegrationContext.call_args[0][0]

    # Assert
    assert token == TOKEN
    assert integration_context == context


@pytest.mark.parametrize('client, tokens, context', [(oproxy_client_refresh(),
                                                      (TOKEN, 3600, REFRESH_TOKEN),
                                                      {'access_token': TOKEN,
                                                       'valid_until': 3605,
                                                       'current_refresh_token': REFRESH_TOKEN}),
                                                     (oproxy_client_tenant(), (TOKEN, 3600, ''),
                                                      {'access_token': TOKEN,
                                                       'valid_until': 3605,
                                                       'current_refresh_token': REFRESH_TOKEN}),
                                                     (self_deployed_client(), (TOKEN, 3600, REFRESH_TOKEN),
                                                      {'access_token': TOKEN,
                                                       'valid_until': 3605,
                                                       'current_refresh_token': REFRESH_TOKEN})])
def test_get_access_token_with_context_valid(mocker, client, tokens, context):
    # Set
    mocker.patch.object(demisto, 'getIntegrationContext', return_value=context)
    mocker.patch.object(demisto, 'setIntegrationContext')

    mocker.patch.object(client, '_oproxy_authorize', return_value=tokens)
    mocker.patch.object(client, '_get_self_deployed_token', return_value=tokens)
    mocker.patch.object(client, 'epoch_seconds', return_value=3600)

    # Arrange
    token = client.get_access_token()

    set_context_count = demisto.setIntegrationContext.call_count
    auth_call_oproxy = client._oproxy_authorize.call_count
    auth_call_self_deployed = client._get_self_deployed_token.call_count

    # Assert
    assert set_context_count == 0
    assert auth_call_oproxy == 0
    assert auth_call_self_deployed == 0
    assert token == TOKEN


@pytest.mark.parametrize('client, tokens, context_invalid, context_valid',
                         [(oproxy_client_refresh(),
                           (TOKEN, 3600, REFRESH_TOKEN),
                           {'access_token': TOKEN,
                            'valid_until': 3605,
                            'current_refresh_token': REFRESH_TOKEN},
                           {'access_token': TOKEN,
                            'valid_until': 8595,
                            'current_refresh_token': REFRESH_TOKEN}),
                          (oproxy_client_tenant(),
                           (TOKEN, 3600, ''),
                           {'access_token': TOKEN,
                            'valid_until': 3605,
                            'current_refresh_token': REFRESH_TOKEN},
                           {'access_token': TOKEN,
                            'valid_until': 8595,
                            'current_refresh_token': ''}),
                          (self_deployed_client(),
                           (TOKEN, 3600, ''),
                           {'access_token': TOKEN,
                            'valid_until': 3605,
                            'current_refresh_token': ''},
                           {'access_token': TOKEN,
                            'valid_until': 8595,
                            'current_refresh_token': ''})])
def test_get_access_token_with_context_invalid(mocker, client, tokens, context_invalid, context_valid):
    # Set
    mocker.patch.object(demisto, 'getIntegrationContext', return_value=context_invalid)
    mocker.patch.object(demisto, 'setIntegrationContext')

    mocker.patch.object(client, '_oproxy_authorize', return_value=tokens)
    mocker.patch.object(client, '_get_self_deployed_token', return_value=tokens)
    mocker.patch.object(client, 'epoch_seconds', side_effect=[4000, 5000])

    # Arrange
    token = client.get_access_token()

    integration_context = demisto.setIntegrationContext.call_args[0][0]

    # Assert
    assert token == TOKEN
    assert integration_context == context_valid


@pytest.mark.parametrize('client, enc_content, tokens, res', [(oproxy_client_tenant(), TENANT,
                                                               {'access_token': TOKEN, 'expires_in': 3600},
                                                               (TOKEN, 3600, '')),
                                                              (oproxy_client_refresh(), REFRESH_TOKEN,
                                                               {'access_token': TOKEN,
                                                                'expires_in': 3600,
                                                                'refresh_token': REFRESH_TOKEN},
                                                               (TOKEN, 3600, REFRESH_TOKEN))])
def test_oproxy_request(mocker, requests_mock, client, enc_content, tokens, res):
    def get_encrypted(content, key):
        return content + key

    # Set
    body = {
        'app_name': APP_NAME,
        'registration_id': AUTH_ID,
        'encrypted_token': enc_content + ENC_KEY,
        'scope': None,
        'resource': ''
    }
    mocker.patch.object(client, '_add_info_headers')
    mocker.patch.object(client, 'get_encrypted', side_effect=get_encrypted)
    requests_mock.post(
        TOKEN_URL,
        json=tokens)

    # Arrange
    req_res = client._oproxy_authorize()
    req_body = requests_mock._adapter.last_request.json()
    assert req_body == body
    assert req_res == res


def test_self_deployed_request(requests_mock):
    import urllib
    # Set
    client = self_deployed_client()

    body = {
        'client_id': CLIENT_ID,
        'client_secret': CLIENT_SECRET,
        'grant_type': 'client_credentials',
        'scope': SCOPE,
        'resource': RESOURCE
    }

    requests_mock.post(
        APP_URL,
        json={'access_token': TOKEN, 'expires_in': '3600'})

    # Arrange
    req_res = client._get_self_deployed_token()
    req_body = requests_mock._adapter.last_request._request.body
    assert req_body == urllib.parse.urlencode(body)
    assert req_res == (TOKEN, 3600, '')


def test_oproxy_use_resource(mocker):
    """
    Given:
        multi_resource client
    When
        When configuration is oproxy authentication type and multi resource
    Then
        Verify post request is using resource value
    """
    resource = 'https://resource2.com'
    client = oproxy_client_multi_resource()
    context = {"access_token": TOKEN}

    mocked_post = mocker.patch('requests.post', json=context, status_code=200, ok=True)
    mocker.patch.object(client, 'get_encrypted', return_value='encrypt')

    client._oproxy_authorize(resource)
    assert resource == mocked_post.call_args_list[0][1]['json']['resource']


@pytest.mark.parametrize('resource', ['https://resource1.com', 'https://resource2.com'])
def test_self_deployed_multi_resource(requests_mock, resource):
    """
    Given:
        multi_resource client.
    When
        When configuration is client credentials authentication type and multi resource.
    Then
        Verify access token for each resource.
    """
    client = self_deployed_client_multi_resource()
    requests_mock.post(
        APP_URL,
        json={'access_token': TOKEN, 'expires_in': '3600'})

    req_res = client._get_self_deployed_token()
    assert req_res == ('', 3600, '')
    assert client.resource_to_access_token[resource] == TOKEN


@pytest.mark.parametrize('azure_cloud_name', ['com', 'gcc', 'gcc-high', 'dod', 'de', 'cn'])
def test_national_endpoints(mocker, azure_cloud_name):
    """
    Given:
        self-deployed client
    When:
        Configuring the client with different national endpoints
    Then:
        Verify that the token_retrieval_url and the scope are set correctly
    """
    tenant_id = TENANT
    auth_id = f'{AUTH_ID}@{TOKEN_URL}'
    enc_key = ENC_KEY
    app_name = APP_NAME
    ok_codes = OK_CODES
    azure_cloud = AZURE_CLOUDS[azure_cloud_name]
    client = MicrosoftClient(self_deployed=True, auth_id=auth_id, enc_key=enc_key, app_name=app_name,
                             tenant_id=tenant_id, verify=True, proxy=False, ok_codes=ok_codes,
                             azure_cloud=azure_cloud)

    assert client.azure_ad_endpoint == TOKEN_RETRIEVAL_ENDPOINTS[client.azure_cloud.abbreviation]
    assert client.scope == f'{GRAPH_ENDPOINTS[client.azure_cloud.abbreviation]}/.default'


def test_retry_on_rate_limit(requests_mock, mocker):
    """
    Given:
        self-deployed client with retry_on_rate_limit=True
    When:
        Response from http request is 429 rate limit
    Then:
        Verify that a ScheduledCommand is returend with relevant details
    """
    client = retry_on_rate_limit_client(True)
    requests_mock.post(
        APP_URL,
        json={'access_token': TOKEN, 'expires_in': '3600'})

    requests_mock.get(
        'https://graph.microsoft.com/v1.0/test_id',
        status_code=429,
        json={'content': "Rate limit reached!"}
    )

    mocker.patch('CommonServerPython.is_demisto_version_ge', return_value=True)
    mocker.patch('MicrosoftApiModule.is_demisto_version_ge', return_value=True)
    mocker.patch.object(demisto, 'command', return_value='testing_command')
    mocker.patch.object(demisto, 'results')
    mocker.patch.object(sys, 'exit')
    mocker.patch.object(demisto, 'callingContext', {'context': {'ExecutedCommands': [{'moduleBrand': 'msgraph'}]}})

    client.http_request(method='GET', url_suffix='test_id')
    retry_results: ScheduledCommand = demisto.results.call_args[0][0]
    assert retry_results.get('PollingCommand') == 'testing_command'
    assert retry_results.get('PollingArgs') == {'ran_once_flag': True}

    metric_results = demisto.results.call_args_list[0][0][0]
    assert metric_results.get('Contents') == 'Metrics reported successfully.'
    assert metric_results.get('APIExecutionMetrics') == [{'Type': 'QuotaError', 'APICallsCount': 1}]


def test_fail_on_retry_on_rate_limit(requests_mock, mocker):
    """
    Given:
        client with retry_on_rate_limit=True and where 'first_run_flag' set to True in args
    When:
        Response from http request is 429 rate limit
    Then:
        Return Error as we  already retried rerunning the command
    """
    client = retry_on_rate_limit_client(True)
    requests_mock.post(
        APP_URL,
        json={'access_token': TOKEN, 'expires_in': '3600'})

    requests_mock.get(
        'https://graph.microsoft.com/v1.0/test_id',
        status_code=429,
        json={'content': "Rate limit reached!"}
    )

    mocker.patch('CommonServerPython.is_demisto_version_ge', return_value=True)
    mocker.patch('MicrosoftApiModule.is_demisto_version_ge', return_value=True)
    mocker.patch.object(demisto, 'command', return_value='testing_command')
    mocker.patch.object(demisto, 'args', return_value={'ran_once_flag': True})
    mocker.patch.object(demisto, 'results')
    mocker.patch.object(sys, 'exit')
    mocker.patch.object(demisto, 'callingContext', {'context': {'ExecutedCommands': [{'moduleBrand': 'msgraph'}]}})

    with pytest.raises(DemistoException, match=r'Rate limit reached!'):
        client.http_request(method='GET', url_suffix='test_id')


def test_rate_limit_when_retry_is_false(requests_mock):
    """
    Given:
        self-deployed client with retry_on_rate_limit=False
    When:
        Response from http request is 429 rate limit
    Then:
        Verify that a regular error is returned and not a ScheduledCommand
    """
    client = retry_on_rate_limit_client(False)
    requests_mock.post(
        APP_URL,
        json={'access_token': TOKEN, 'expires_in': '3600'})

    requests_mock.get(
        'https://graph.microsoft.com/v1.0/test_id',
        status_code=429,
        json={'content': "Rate limit reached!"}
    )

    with pytest.raises(DemistoException, match="Error in API call \[429\]"):
        client.http_request(method='GET', url_suffix='test_id')


@pytest.mark.parametrize('response, result', [
    (200, [{'Type': 'Successful', 'APICallsCount': 1}]),
    (429, [{'Type': 'QuotaError', 'APICallsCount': 1}]),
    (500, [{'Type': 'GeneralError', 'APICallsCount': 1}])
])
def test_create_api_metrics(mocker, response, result):
    """
    Test create_api_metrics function, make sure metrics are reported according to the response
    """
    mocker.patch.object(demisto, 'results')
    mocker.patch('CommonServerPython.is_demisto_version_ge', return_value=True)
    mocker.patch('MicrosoftApiModule.is_demisto_version_ge', return_value=True)
    mocker.patch.object(demisto, 'callingContext', {'context': {'ExecutedCommands': [{'moduleBrand': 'msgraph'}]}})
    MicrosoftClient.create_api_metrics(response)

    metric_results = demisto.results.call_args_list[0][0][0]
    assert metric_results.get('Contents') == 'Metrics reported successfully.'
    assert metric_results.get('APIExecutionMetrics') == result


def test_general_error_metrics(requests_mock, mocker):
    "When we activate the retry mechanism, and we recieve a general error, it's metric should be recorded"
    client = retry_on_rate_limit_client(True)
    requests_mock.post(
        APP_URL,
        json={'access_token': TOKEN, 'expires_in': '3600'})

    requests_mock.get(
        'https://graph.microsoft.com/v1.0/test_id',
        status_code=500,
        json={'content': "General Error!"}
    )

    mocker.patch('CommonServerPython.is_demisto_version_ge', return_value=True)
    mocker.patch('MicrosoftApiModule.is_demisto_version_ge', return_value=True)
    mocker.patch.object(demisto, 'command', return_value='testing_command')
    mocker.patch.object(demisto, 'results')

    with pytest.raises(DemistoException):
        client.http_request(method='GET', url_suffix='test_id')
    metric_results = demisto.results.call_args_list[0][0][0]
    assert metric_results.get('Contents') == 'Metrics reported successfully.'
    assert metric_results.get('APIExecutionMetrics') == [{'Type': 'GeneralError', 'APICallsCount': 1}]


@pytest.mark.parametrize(argnames='client_id', argvalues=['test_client_id', None])
def test_get_token_managed_identities(requests_mock, mocker, client_id):
    """
    Given:
        managed identity client id or None
    When:
        get access token
    Then:
        Verify that the result are as expected
    """
    test_token = 'test_token'
    import MicrosoftApiModule

    mock_token = {'access_token': test_token, 'expires_in': '86400'}

    get_mock = requests_mock.get(MANAGED_IDENTITIES_TOKEN_URL, json=mock_token)
    mocker.patch.object(MicrosoftApiModule, 'get_integration_context', return_value={})

    client = self_deployed_client()
    client.managed_identities_resource_uri = Resources.graph
    client.managed_identities_client_id = client_id or MANAGED_IDENTITIES_SYSTEM_ASSIGNED

    assert test_token == client.get_access_token()
    qs = get_mock.last_request.qs
    assert qs['resource'] == [Resources.graph]
    assert client_id and qs['client_id'] == [client_id] or 'client_id' not in qs


def test_get_token_managed_identities__error(requests_mock, mocker):
    """
    Given:
        managed identity client id
    When:
        get access token
    Then:
        Verify that the result are as expected
    """

    import MicrosoftApiModule

    mock_token = {'error_description': 'test_error_description'}
    requests_mock.get(MANAGED_IDENTITIES_TOKEN_URL, json=mock_token)
    mocker.patch.object(MicrosoftApiModule, 'return_error', side_effect=Exception())
    mocker.patch.object(MicrosoftApiModule, 'get_integration_context', return_value={})

    client = self_deployed_client()
    client.managed_identities_client_id = 'test_client_id'
    client.managed_identities_resource_uri = Resources.graph

    with pytest.raises(Exception):
        client.get_access_token()

    err_message = 'Error in Microsoft authorization with Azure Managed Identities'
    assert err_message in MicrosoftApiModule.return_error.call_args[0][0]


args = {'test': 'test_arg_value'}
params = {'test': 'test_param_value', 'test_unique': 'test_arg2_value'}


def test_get_from_args_or_params__when_the_key_exists_in_args_and_params():
    """
    Given:
        args and params with the same key in both
    When:
        get value from args or params is called
    Then:
        Verify that the result are as expected = the value from args is returned
    """

    assert get_from_args_or_params(args, params, 'test') == 'test_arg_value'


def test_get_from_args_or_params__when_the_key_exists_only_in_params():
    """
    Given:
        args and params with the requested key exist only in params
    When:
        get value from args or params is called
    Then:
        Verify that the result are as expected = the value from params
    """
    assert get_from_args_or_params(args, params, 'test_unique') == 'test_arg2_value'


def test_get_from_args_or_params__when_the_key_dose_not_exists():
    """
    Given:
        args and params
    When:
        get value from args or params is called with a key that dose not exist
    Then:
        Verify that the correct error message is raising
    """
    with pytest.raises(Exception) as e:
        get_from_args_or_params(args, params, 'mock')
    assert e.value.args[0] == "No mock was provided. Please provide a mock either in the instance \
configuration or as a command argument."


def test_azure_tag_formatter__with_valid_input():
    """
    Given:
        A valid json as a string
    When:
        azure_tag_formatter is called
    Then:
        Verify that the result are as expected
    """
    assert azure_tag_formatter('{"key":"value"}') == "tagName eq 'key' and tagValue eq 'value'"


def test_azure_tag_formatter__with_invalid_input():
    """
    Given:
        A invalid json as a string
    When:
        azure_tag_formatter is called
    Then:
        Verify that the correct error message is raising
    """
    with pytest.raises(Exception) as e:
        azure_tag_formatter('{"key:value"}')
    assert e.value.args[0] == 'Invalid tag format, please use the following format: \'{"key_name":"value_name"}\''


def test_reset_auth(mocker):
    """
        Given:
            -
        When:
            - Calling function reset_auth.
        Then:
            - Ensure the output are as expected.
    """
    from MicrosoftApiModule import reset_auth

    expected_output = 'Authorization was reset successfully. Please regenerate the credentials, ' \
                      'and then click **Test** to validate the credentials and connection.'

    mocker.patch.object(demisto, 'getIntegrationContext', return_value={"test"})
    mocker.patch.object(demisto, 'setIntegrationContext')

    result = reset_auth()

    assert result.readable_output == expected_output
    assert demisto.getIntegrationContext.call_count == 1
    assert demisto.setIntegrationContext.call_count == 1
    assert demisto.setIntegrationContext.call_args[0][0] == {}
    assert result


def test_generate_login_url():
    """
    Given:
        - Self-deployed are true and auth code are the auth flow
    When:
        - Calling function generate_login_url
     Then:
        - Ensure the generated url are as expected.
    """
    from MicrosoftApiModule import generate_login_url

    client = self_deployed_client()

    result = generate_login_url(client)

    expected_url = f'[login URL](https://login.microsoftonline.com/{TENANT}/oauth2/v2.0/authorize?' \
                   f'response_type=code&scope=offline_access%20https://graph.microsoft.com/.default' \
                   f'&client_id={CLIENT_ID}&redirect_uri=https://localhost/myapp)'
    assert expected_url in result.readable_output, "Login URL is incorrect"


@pytest.mark.parametrize('params, expected_resource_manager, expected_active_directory, expected_microsoft_graph_resource_id', [
    ({'azure_cloud': 'Germany'}, 'https://management.microsoftazure.de',
     'https://login.microsoftonline.de', 'https://graph.microsoft.de'),
    ({'azure_cloud': 'Custom', 'server_url': 'mock_url'}, 'mock_url',
     'https://login.microsoftonline.com', 'https://graph.microsoft.com/'),
    ({'azure_ad_endpoint': 'mock_endpoint'}, 'https://management.azure.com/', 'mock_endpoint',
     'https://graph.microsoft.com/'),
    ({'url': 'mock_url'}, 'https://management.azure.com/', 'https://login.microsoftonline.com', 'mock_url'),
    ({}, 'https://management.azure.com/', 'https://login.microsoftonline.com', 'https://graph.microsoft.com/')
])
def test_get_azure_cloud(params, expected_resource_manager, expected_active_directory, expected_microsoft_graph_resource_id):
    """
    Given:
        - params with different azure_cloud values
        case 1: azure_cloud = Germany
        case 2: azure_cloud = Custom and server_url
        case 3: azure_cloud = None. azure_ad_endpoint in params
        case 4: azure_cloud = None. url in params
        case 5 : params is empty
    When:
        - Calling function get_azure_cloud
    Then:
        - Ensure the generated url are as expected.
    """
    from MicrosoftApiModule import get_azure_cloud
    assert get_azure_cloud(params=params, integration_name='test').endpoints.resource_manager == expected_resource_manager
    assert get_azure_cloud(params=params, integration_name='test').endpoints.active_directory == expected_active_directory
    assert get_azure_cloud(
        params=params, integration_name='test').endpoints.microsoft_graph_resource_id == expected_microsoft_graph_resource_id


@freezegun.freeze_time(FREEZE_STR_DATE)
def test_should_delay_true():
    """
    Given:
        - Mocked context with later next request time than the current time.
    When:
        - Calling the function should_delay_request.
     Then:
        - Ensure the function return the expected value.
    """
    from MicrosoftApiModule import should_delay_request
    from datetime import datetime

    mocked_next_request_time = datetime.strptime(FREEZE_STR_DATE, '%Y-%m-%d %H:%M:%S').timestamp() + 1.0
    excepted_error = f"The request will be delayed until {datetime.fromtimestamp(mocked_next_request_time)}"
    with pytest.raises(Exception) as e:
        should_delay_request(mocked_next_request_time)
    assert str(e.value) == excepted_error


@freezegun.freeze_time(FREEZE_STR_DATE)
def test_should_delay_false():
    """
    Given:
        - Mocked context with next request time equal to the current time.
    When:
        - Calling the function should_delay_request.
     Then:
        - Ensure the function return with no error.
    """
    from MicrosoftApiModule import should_delay_request
    from datetime import datetime

    mocked_next_request_time = datetime.strptime(FREEZE_STR_DATE, '%Y-%m-%d %H:%M:%S').timestamp()
    should_delay_request(mocked_next_request_time)


@freezegun.freeze_time(FREEZE_STR_DATE)
@pytest.mark.parametrize('mocked_next_request_time,excepted', [(2, 4.0), (3, 8.0), (6, 64.0)])
def test_calculate_next_request_time(mocked_next_request_time, excepted):
    """
    Given:
        - Mocked context with next request time equal to the current time.
    When:
        - Calling the function should_delay_request.
     Then:
        - Ensure the function return with no error.
    """
    from MicrosoftApiModule import calculate_next_request_time
    assert calculate_next_request_time(mocked_next_request_time) == excepted


@freezegun.freeze_time(FREEZE_STR_DATE)
@pytest.mark.parametrize('mocked_delay_request_counter,excepted',
                         [({'delay_request_counter': 5}, {'next_request_time': 32.0, 'delay_request_counter': 6}),
                          ({'delay_request_counter': 6}, {'next_request_time': 64.0, 'delay_request_counter': 7}),
                          ({'delay_request_counter': 7}, {'next_request_time': 64.0, 'delay_request_counter': 7})])
def test_oproxy_authorize_retry_mechanism(mocker, capfd, mocked_delay_request_counter, excepted):
    """
    Given:
        - Mocked context with next request time equal to the current time.
    When:
        - Calling the _oproxy_authorize function.
     Then:
        - Ensure the function return with no error and the context has been set with the right values.
    """
    from datetime import datetime
    # pytest raises a warning when there is error in the stderr, this is a workaround to disable it
    with capfd.disabled():
        client = oproxy_client_refresh()
        error = Response()
        error.status_code = 400
        error.reason = "Bad Request"
        mocked_next_request_time = {'next_request_time': datetime.strptime(FREEZE_STR_DATE, '%Y-%m-%d %H:%M:%S').timestamp()}

        mocked_context = mocked_next_request_time | mocked_delay_request_counter
        mocker.patch.object(demisto, 'getIntegrationContext', return_value=mocked_context)
        mocker.patch.object(client, '_oproxy_authorize_build_request', return_value=error)
        res = mocker.patch.object(demisto, 'setIntegrationContext')

        with pytest.raises(Exception):
            client._oproxy_authorize()
        assert res.call_args[0][0] == excepted
