import json

import pytest

from GSuiteApiModule import DemistoException, COMMON_MESSAGES, GSuiteClient

with open('test_data/service_account_json.txt') as f:
    TEST_JSON = f.read()

PROXY_METHOD_NAME = 'GSuiteApiModule.handle_proxy'

CREDENTIAL_SUBJECT = 'test@org.com'

MOCKER_HTTP_METHOD = 'GSuiteApiModule.GSuiteClient.http_request'


@pytest.fixture
def gsuite_client():
    headers = {
        'Content-Type': 'application/json'
    }
    return GSuiteClient(GSuiteClient.safe_load_non_strict_json(TEST_JSON), base_url='https://www.googleapis.com/',
                        verify=False, proxy=False, headers=headers)


def test_safe_load_non_strict_json():
    """
    Scenario: Dictionary should be prepared from json string.

    Given:
    - json as string.

    When:
    - Preparing dictionary from string.

    Then:
    - Ensure valid json should be loaded successfully.
    """
    excepted_json = json.loads(TEST_JSON, strict=False)
    assert GSuiteClient.safe_load_non_strict_json(TEST_JSON) == excepted_json


def test_safe_load_non_strict_json_parse_error():
    """
    Scenario: Failed to load json when invalid json string is given.

    Given:
    - Empty json string.

    When:
    - Preparing dictionary from string.

    Then:
    - Ensure Exception is raised with proper error message.
    """

    with pytest.raises(ValueError, match=COMMON_MESSAGES['JSON_PARSE_ERROR']):
        GSuiteClient.safe_load_non_strict_json('Invalid json')


def test_safe_load_non_strict_json_empty():
    """
    Scenario: Returns {}(blank) dictionary when empty json string is given.

    Given:
    - Invalid json as string.

    When:
    - Preparing dictionary from string.

    Then:
    - Ensure {}(blank) dictionary should be returned.
    """

    assert GSuiteClient.safe_load_non_strict_json('') == {}


def test_validate_and_extract_response(mocker):
    """
    Scenario: Parse response when status code is 200 or 204.

    Given:
    - Tuple containing response object and content.

    When:
    - Validating and loading json from response.

    Then:
    - Ensure content json should be parsed successfully.
    """
    from GSuiteApiModule import httplib2, demisto
    mocker.patch.object(demisto, 'debug')
    response = httplib2.Response({'status': 200})
    expected_content = {'response': {}}
    assert GSuiteClient.validate_and_extract_response((response, b'{"response": {}}')) == expected_content


def test_validate_and_extract_response_error(mocker):
    """
    Scenario: Should raise exception when status code is not 200 or 204.

    Given:
    - Tuple containing response object and content.

    When:
    - Validating and loading json from response.

    Then:
    - Ensure the Demisto exception should be raised respective to status code.
    """
    from GSuiteApiModule import httplib2, demisto
    mocker.patch.object(demisto, 'debug')
    response = httplib2.Response({'status': 400})

    with pytest.raises(DemistoException, match=COMMON_MESSAGES['BAD_REQUEST_ERROR'].format('BAD REQUEST')):
        GSuiteClient.validate_and_extract_response((response, b'{"error": {"message":"BAD REQUEST"}}'))

    response = httplib2.Response({'status': 509})

    with pytest.raises(DemistoException, match=COMMON_MESSAGES['UNKNOWN_ERROR'].format(509, 'error')):
        GSuiteClient.validate_and_extract_response((response, b'{"error": {"message":"error"}}'))


def test_get_http_client(mocker):
    """
    Scenario: Should return http client object with configured proxy, verify and timeout parameters.

    Given:
    - proxy: Boolean indicates whether to use proxy or not.
    - verify: Boolean indicates whether to use ssl certification.
    - timeout: Timeout value for request.

    When:
    - Initializing httplib2.Http object when proxy, timeout and verify parameters provided.

    Then:
    - Ensure configured Http() object should be return.
    """
    from GSuiteApiModule import httplib2

    mocker.patch(PROXY_METHOD_NAME, return_value={'https': 'http url'})

    http = GSuiteClient.get_http_client(proxy=True, verify=False, timeout=60)
    assert isinstance(http, httplib2.Http)
    assert http.disable_ssl_certificate_validation is True
    assert http.timeout == 60


def test_get_http_client_prefix_https_addition(mocker):
    """
    Scenario: Should return Http object with proxy configured with prefix https.

    Given:
    - proxy: Boolean indicates whether to use proxy or not.
    - verify: Boolean indicates whether to use ssl certification.
    - timeout: Timeout value for request.

    When:
    - Initializing httplib2.Http object when proxy, timeout and verify parameters provided.

    Then:
    - Ensure prefix https should be added before given https proxy value.
    """
    from GSuiteApiModule import httplib2

    mocker.patch(PROXY_METHOD_NAME, return_value={'https': 'demisto:admin@0.0.0.0:3128'})

    http = GSuiteClient.get_http_client(proxy=True, verify=True)
    assert isinstance(http, httplib2.Http)
    assert http.proxy_info.proxy_host == '0.0.0.0'
    assert http.proxy_info.proxy_port == 3128
    assert http.proxy_info.proxy_user == 'demisto'
    assert http.proxy_info.proxy_pass == 'admin'


def test_set_authorized_http(gsuite_client):
    """
    Scenario: Initialize AuthorizedHttp with given subject, scopes and timeout.

    Given:
    - scopes: List of scopes needed to make request.
    - subject: To link subject with credentials.
    - timeout: Timeout value for request.

    When:
    - Initializing AuthorizedHttp with the parameters provided.

    Then:
    - Ensure AuthorizedHttp is returned with configuration.
    """
    from GSuiteApiModule import AuthorizedHttp
    gsuite_client.set_authorized_http(scopes=['scope1', 'scope2'], subject=CREDENTIAL_SUBJECT)
    assert isinstance(gsuite_client.authorized_http, AuthorizedHttp)


def test_http_request(mocker, gsuite_client):
    """
    Scenario: Request to API call should give response.

    Given:
    - url_suffix: url_suffix of url.
    - params: Parameters to pass in request url.
    - method: Method to use while making http request.
    - body: Request body.

    When:
    - Initializing AuthorizedHttp with the parameters provided.

    Then:
    - Ensure AuthorizedHttp is returned with configuration.
    """
    from GSuiteApiModule import httplib2, AuthorizedHttp

    content = '{"items": {}}'
    response = httplib2.Response({'status': 200, 'content': content})

    mocker.patch.object(AuthorizedHttp, 'request', return_value=(response, content))

    gsuite_client.set_authorized_http(scopes=['scope1', 'scope2'], subject=CREDENTIAL_SUBJECT)
    expected_response = gsuite_client.http_request(url_suffix='url_suffix', params={'userId': 'abc'}, )

    assert expected_response == {'items': {}}


def test_http_request_http_error(mocker, gsuite_client):
    """
    Scenario: Proxy setup is invalid, Request to API call should give respective message for proxy error.

    Given:
    - url_suffix: url_suffix of url.
    - params: Parameters to pass in request url.

    When:
    - Initializing AuthorizedHttp with the parameters provided.

    Then:
    - Ensure Demisto exception is raised with respective proxy error.
    """
    from GSuiteApiModule import httplib2, AuthorizedHttp

    gsuite_client.set_authorized_http(scopes=['scope1', 'scope2'], subject=CREDENTIAL_SUBJECT)

    # Proxy Error
    mocker.patch.object(AuthorizedHttp, 'request', side_effect=httplib2.socks.HTTPError((407, b'proxy error')))
    with pytest.raises(DemistoException):
        gsuite_client.http_request(url_suffix='url_suffix', params={'userId': 'abc'})

    # HTTP Error
    mocker.patch.object(AuthorizedHttp, 'request', side_effect=httplib2.socks.HTTPError((409, b'HTTP error')))
    with pytest.raises(DemistoException):
        gsuite_client.http_request(url_suffix='url_suffix', params={'userId': 'abc'})

    # HTTP Error no tuple
    mocker.patch.object(AuthorizedHttp, 'request', side_effect=httplib2.socks.HTTPError('HTTP error'))
    with pytest.raises(DemistoException):
        gsuite_client.http_request(url_suffix='url_suffix', params={'userId': 'abc'})


def test_http_request_timeout_error(mocker, gsuite_client):
    """
    Scenario: url is invalid, Request to API call should give respective message for connection timeout.

    Given:
    - url_suffix: url_suffix of url.
    - params: Parameters to pass in request url.

    When:
    - Initializing AuthorizedHttp with the parameters provided.

    Then:
    - Ensure Demisto exception is raised with respective connection timeout error.
    """
    from GSuiteApiModule import AuthorizedHttp

    gsuite_client.set_authorized_http(scopes=['scope1', 'scope2'], subject=CREDENTIAL_SUBJECT)

    mocker.patch.object(AuthorizedHttp, 'request', side_effect=TimeoutError('timeout error'))

    with pytest.raises(DemistoException, match=COMMON_MESSAGES['TIMEOUT_ERROR'].format('timeout error')):
        gsuite_client.http_request(url_suffix='url_suffix', params={'userId': 'abc'})


def test_http_request_transport_error(mocker, gsuite_client):
    """
    Scenario: url is invalid, Request to API call should give respective message for transport error.

    Given:
    - url_suffix: url_suffix of url.
    - params: Parameters to pass in request url.

    When:
    - Initializing AuthorizedHttp with the parameters provided.

    Then:
    - Ensure Demisto exception is raised with respective transport error.
    """
    from GSuiteApiModule import AuthorizedHttp, exceptions

    gsuite_client.set_authorized_http(scopes=['scope1', 'scope2'], subject=CREDENTIAL_SUBJECT)

    mocker.patch.object(AuthorizedHttp, 'request', side_effect=exceptions.TransportError('proxyerror'))

    with pytest.raises(DemistoException, match=COMMON_MESSAGES['PROXY_ERROR']):
        gsuite_client.http_request(url_suffix='url_suffix', params={'userId': 'abc'})

    mocker.patch.object(AuthorizedHttp, 'request', side_effect=exceptions.TransportError('new error'))
    with pytest.raises(DemistoException, match=COMMON_MESSAGES['TRANSPORT_ERROR'].format('new error')):
        gsuite_client.http_request(url_suffix='url_suffix', params={'userId': 'abc'})


def test_http_request_refresh_error(mocker, gsuite_client):
    """
    Scenario: Failed to generate/refresh token, Request to API call should give respective message.

    Given:
    - url_suffix: url_suffix of url.
    - params: Parameters to pass in request url.

    When:
    - Initializing AuthorizedHttp with the parameters provided.

    Then:
    - Ensure Demisto exception is raised with respective refresh error message.
    """
    from GSuiteApiModule import AuthorizedHttp, exceptions

    gsuite_client.set_authorized_http(scopes=['scope1', 'scope2'], subject=CREDENTIAL_SUBJECT)
    mocker.patch.object(AuthorizedHttp, 'request', side_effect=exceptions.RefreshError(
        "invalid_request: Invalid impersonation & quot; sub & quot; field."))

    with pytest.raises(DemistoException, match=COMMON_MESSAGES['REFRESH_ERROR'].format(
            "invalid_request: Invalid impersonation & quot; sub & quot; field.")):
        gsuite_client.http_request(url_suffix='url_suffix', params={'userId': 'abc'})


def test_http_request_error(mocker, gsuite_client):
    """
    Scenario: Some unknown error occurred during request to API call should give respective message.

    Given:
    - url_suffix: url_suffix of url.
    - params: Parameters to pass in request url.

    When:
    - Initializing AuthorizedHttp with the parameters provided.

    Then:
    - Ensure Demisto exception is raised with respective error.
    """
    from GSuiteApiModule import AuthorizedHttp

    gsuite_client.set_authorized_http(scopes=['scope1', 'scope2'], subject=CREDENTIAL_SUBJECT)

    mocker.patch.object(AuthorizedHttp, 'request', side_effect=Exception('error'))

    with pytest.raises(DemistoException, match='error'):
        gsuite_client.http_request(url_suffix='url_suffix', params={'userId': 'abc'})


def test_strip_dict():
    """
    Scenario: Call to test-module should return 'ok' if API call succeeds.

    Given:
    - A dictionary with entries having whitespaces and empty values

    When:
    - Calling strip_dict() method.

    Then:
    - Ensure returned dictionary has stripped values and entries with empty values are removed.
    """
    sample_input = {"key1": "  VALUE_1 ", "key2": ""}
    sample_output = {"key1": "VALUE_1"}
    assert GSuiteClient.strip_dict(sample_input) == sample_output
