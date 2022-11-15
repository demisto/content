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
    refresh_token = REFRESH_TOKEN
    auth_id = f'{AUTH_ID}@{TOKEN_URL}'
    enc_key = ENC_KEY
    app_name = APP_NAME
    base_url = BASE_URL
    ok_codes = OK_CODES

    return MicrosoftClient(self_deployed=False, auth_id=auth_id, enc_key=enc_key, app_name=app_name,
                           refresh_token=refresh_token, base_url=base_url, verify=True, proxy=False, ok_codes=ok_codes)


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


def test_error_parser(mocker):
    mocker.patch.object(demisto, 'error')
    err = Response()
    err.status_code = 401
    err._content = b'{"error":{"code":"code","message":"message"}}'
    response = MicrosoftClient.error_parser(err)
    assert response == 'code: message'


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

    try:
        client.http_request()
    except Exception as e:  # Validate that a `NotFoundError` was raised
        assert type(e).__name__ == 'NotFoundError'


def test_epoch_seconds(mocker):
    mocker.patch.object(MicrosoftClient, '_get_utcnow', return_value=datetime.datetime(2019, 12, 24, 14, 12, 0, 586636))
    mocker.patch.object(MicrosoftClient, '_get_utcfromtimestamp', return_value=datetime.datetime(1970, 1, 1, 0, 0))
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


@pytest.mark.parametrize('endpoint', ['com', 'gcc-high', 'dod', 'de', 'cn'])
def test_national_endpoints(mocker, endpoint):
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
    base_url = BASE_URL
    ok_codes = OK_CODES
    client = MicrosoftClient(self_deployed=True, auth_id=auth_id, enc_key=enc_key, app_name=app_name,
                             tenant_id=tenant_id, base_url=base_url, verify=True, proxy=False, ok_codes=ok_codes,
                             endpoint=endpoint)

    assert client.azure_ad_endpoint == TOKEN_RETRIEVAL_ENDPOINTS[endpoint]
    assert client.scope == f'{GRAPH_ENDPOINTS[endpoint]}/.default'


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

    try:
        client.http_request(method='GET', url_suffix='test_id')
        assert False
    except DemistoException as err:
        assert 'Rate limit reached!' in err.args[0]['content']


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

    try:
        client.http_request(method='GET', url_suffix='test_id')
        assert False
    except DemistoException as err:
        assert 'Error in API call [429]' in err.args[0]


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

    client = retry_on_rate_limit_client(True)
    client.create_api_metrics(response)

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

    try:
        client.http_request(method='GET', url_suffix='test_id')
        assert False
    except DemistoException:
        metric_results = demisto.results.call_args_list[0][0][0]
        assert metric_results.get('Contents') == 'Metrics reported successfully.'
        assert metric_results.get('APIExecutionMetrics') == [{'Type': 'GeneralError', 'APICallsCount': 1}]
