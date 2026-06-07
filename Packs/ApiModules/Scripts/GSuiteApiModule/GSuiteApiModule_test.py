import json

import pytest
from GSuiteApiModule import COMMON_MESSAGES, DemistoException, GSuiteClient

with open("test_data/service_account_json.txt") as f:
    TEST_JSON = f.read()

PROXY_METHOD_NAME = "GSuiteApiModule.handle_proxy"

CREDENTIAL_SUBJECT = "test@org.com"

MOCKER_HTTP_METHOD = "GSuiteApiModule.GSuiteClient.http_request"


@pytest.fixture
def gsuite_client():
    headers = {"Content-Type": "application/json"}
    return GSuiteClient(
        GSuiteClient.safe_load_non_strict_json(TEST_JSON),
        base_url="https://www.googleapis.com/",
        verify=False,
        proxy=False,
        headers=headers,
    )


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

    with pytest.raises(ValueError, match=COMMON_MESSAGES["JSON_PARSE_ERROR"]):
        GSuiteClient.safe_load_non_strict_json("Invalid json")


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

    assert GSuiteClient.safe_load_non_strict_json("") == {}


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
    from GSuiteApiModule import demisto, httplib2

    mocker.patch.object(demisto, "debug")
    response = httplib2.Response({"status": 200})
    expected_content = {"response": {}}
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
    from GSuiteApiModule import demisto, httplib2

    mocker.patch.object(demisto, "debug")
    response = httplib2.Response({"status": 400})

    with pytest.raises(DemistoException, match=COMMON_MESSAGES["BAD_REQUEST_ERROR"].format("BAD REQUEST")):
        GSuiteClient.validate_and_extract_response((response, b'{"error": {"message":"BAD REQUEST"}}'))

    response = httplib2.Response({"status": 509})

    with pytest.raises(DemistoException, match=COMMON_MESSAGES["UNKNOWN_ERROR"].format(509, "error")):
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

    mocker.patch(PROXY_METHOD_NAME, return_value={"https": "http url"})

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

    mocker.patch(PROXY_METHOD_NAME, return_value={"https": "demisto:admin@0.0.0.0:3128"})

    http = GSuiteClient.get_http_client(proxy=True, verify=True)
    assert isinstance(http, httplib2.Http)
    assert http.proxy_info.proxy_host == "0.0.0.0"
    assert http.proxy_info.proxy_port == 3128
    assert http.proxy_info.proxy_user == "demisto"
    assert http.proxy_info.proxy_pass == "admin"


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

    gsuite_client.set_authorized_http(scopes=["scope1", "scope2"], subject=CREDENTIAL_SUBJECT)
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
    from GSuiteApiModule import AuthorizedHttp, httplib2

    content = '{"items": {}}'
    response = httplib2.Response({"status": 200, "content": content})

    mocker.patch.object(AuthorizedHttp, "request", return_value=(response, content))

    gsuite_client.set_authorized_http(scopes=["scope1", "scope2"], subject=CREDENTIAL_SUBJECT)
    expected_response = gsuite_client.http_request(
        url_suffix="url_suffix",
        params={"userId": "abc"},
    )

    assert expected_response == {"items": {}}


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
    from GSuiteApiModule import AuthorizedHttp, httplib2

    gsuite_client.set_authorized_http(scopes=["scope1", "scope2"], subject=CREDENTIAL_SUBJECT)

    # Proxy Error
    mocker.patch.object(AuthorizedHttp, "request", side_effect=httplib2.socks.HTTPError((407, b"proxy error")))
    with pytest.raises(DemistoException):
        gsuite_client.http_request(url_suffix="url_suffix", params={"userId": "abc"})

    # HTTP Error
    mocker.patch.object(AuthorizedHttp, "request", side_effect=httplib2.socks.HTTPError((409, b"HTTP error")))
    with pytest.raises(DemistoException):
        gsuite_client.http_request(url_suffix="url_suffix", params={"userId": "abc"})

    # HTTP Error no tuple
    mocker.patch.object(AuthorizedHttp, "request", side_effect=httplib2.socks.HTTPError("HTTP error"))
    with pytest.raises(DemistoException):
        gsuite_client.http_request(url_suffix="url_suffix", params={"userId": "abc"})


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

    gsuite_client.set_authorized_http(scopes=["scope1", "scope2"], subject=CREDENTIAL_SUBJECT)

    mocker.patch.object(AuthorizedHttp, "request", side_effect=TimeoutError("timeout error"))

    with pytest.raises(DemistoException, match=COMMON_MESSAGES["TIMEOUT_ERROR"].format("timeout error")):
        gsuite_client.http_request(url_suffix="url_suffix", params={"userId": "abc"})


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

    gsuite_client.set_authorized_http(scopes=["scope1", "scope2"], subject=CREDENTIAL_SUBJECT)

    mocker.patch.object(AuthorizedHttp, "request", side_effect=exceptions.TransportError("proxyerror"))

    with pytest.raises(DemistoException, match=COMMON_MESSAGES["PROXY_ERROR"]):
        gsuite_client.http_request(url_suffix="url_suffix", params={"userId": "abc"})

    mocker.patch.object(AuthorizedHttp, "request", side_effect=exceptions.TransportError("new error"))
    with pytest.raises(DemistoException, match=COMMON_MESSAGES["TRANSPORT_ERROR"].format("new error")):
        gsuite_client.http_request(url_suffix="url_suffix", params={"userId": "abc"})


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

    gsuite_client.set_authorized_http(scopes=["scope1", "scope2"], subject=CREDENTIAL_SUBJECT)
    mocker.patch.object(
        AuthorizedHttp,
        "request",
        side_effect=exceptions.RefreshError("invalid_request: Invalid impersonation & quot; sub & quot; field."),
    )

    with pytest.raises(
        DemistoException,
        match=COMMON_MESSAGES["REFRESH_ERROR"].format("invalid_request: Invalid impersonation & quot; sub & quot; field."),
    ):
        gsuite_client.http_request(url_suffix="url_suffix", params={"userId": "abc"})


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

    gsuite_client.set_authorized_http(scopes=["scope1", "scope2"], subject=CREDENTIAL_SUBJECT)

    mocker.patch.object(AuthorizedHttp, "request", side_effect=Exception("error"))

    with pytest.raises(DemistoException, match="error"):
        gsuite_client.http_request(url_suffix="url_suffix", params={"userId": "abc"})


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


def test_maybe_apply_ucp_credentials_noop_when_ucp_disabled(mocker, gsuite_client):
    """
    Scenario: UCP is not active, so request-time injection is a no-op and the
    params-built credentials are left untouched.

    Given:
    - should_use_ucp_auth() returns False.

    When:
    - _maybe_apply_ucp_credentials() is called.

    Then:
    - Ensure UCP credentials are never fetched and the existing credentials are unchanged.
    """
    import GSuiteApiModule

    mocker.patch.object(GSuiteApiModule, "should_use_ucp_auth", return_value=False)
    get_ucp_credentials = mocker.patch.object(GSuiteApiModule, "get_ucp_credentials")
    original_credentials = gsuite_client.credentials

    gsuite_client._maybe_apply_ucp_credentials()

    get_ucp_credentials.assert_not_called()
    assert gsuite_client.credentials is original_credentials


def test_maybe_apply_ucp_credentials_overwrites_from_ucp(mocker, gsuite_client):
    """
    Scenario: When UCP is active, the credential used for the request is overwritten
    from the UCP functions (the service-account JSON in api_key.key).

    Given:
    - should_use_ucp_auth() returns True.
    - get_ucp_credentials() returns the APIKey UCP shape with the JSON under api_key.key.

    When:
    - _maybe_apply_ucp_credentials() is called.

    Then:
    - Ensure from_service_account_info is called with the UCP-supplied dict, proving the
      API key flows from the UCP functions into the client at request-build time.
    """
    import GSuiteApiModule
    from GSuiteApiModule import service_account

    mocker.patch.object(GSuiteApiModule, "should_use_ucp_auth", return_value=True)
    mocker.patch.object(
        GSuiteApiModule,
        "get_ucp_credentials",
        return_value={"type": "api_key", "api_key": {"key": TEST_JSON}},
    )
    from_info = mocker.patch.object(service_account.Credentials, "from_service_account_info")

    gsuite_client._maybe_apply_ucp_credentials()

    from_info.assert_called_once_with(info=json.loads(TEST_JSON, strict=False))


def test_maybe_apply_ucp_credentials_missing_key_raises(mocker, gsuite_client):
    """
    Scenario: UCP is active but no service-account JSON is present in the credentials.

    Given:
    - should_use_ucp_auth() returns True.
    - get_ucp_credentials() returns an empty/incomplete credential dict.

    When:
    - _maybe_apply_ucp_credentials() is called.

    Then:
    - Ensure a UcpException is raised (the request must not proceed without a credential).
    """
    import GSuiteApiModule
    from GSuiteApiModule import UcpException

    mocker.patch.object(GSuiteApiModule, "should_use_ucp_auth", return_value=True)
    mocker.patch.object(GSuiteApiModule, "get_ucp_credentials", return_value={"type": "api_key", "api_key": {}})
    mocker.patch.object(GSuiteApiModule.demisto, "error")

    with pytest.raises(UcpException):
        gsuite_client._maybe_apply_ucp_credentials()


def test_init_defers_credential_failure_under_ucp(mocker):
    """
    Scenario: Under UCP the service-account JSON is absent from params at construction
    time, so __init__ must not hard-fail — the credential is injected at request time.

    Given:
    - should_use_ucp_auth() returns True.
    - The client is constructed with an EMPTY dict (UCP-stripped params).

    When:
    - GSuiteClient.__init__ runs.

    Then:
    - Ensure no exception is raised and credentials stay None until request-time injection.
    """
    import GSuiteApiModule

    mocker.patch.object(GSuiteApiModule, "should_use_ucp_auth", return_value=True)

    client = GSuiteClient({}, proxy=False, verify=False)

    assert client.credentials is None


def test_init_raises_on_bad_credentials_when_ucp_disabled(mocker):
    """
    Scenario: Without UCP, an empty/unparsable service-account dict is a real config error.

    Given:
    - should_use_ucp_auth() returns False.

    When:
    - GSuiteClient.__init__ runs with an empty dict.

    Then:
    - Ensure ValueError(JSON_PARSE_ERROR) is raised (legacy behavior is unchanged).
    """
    import GSuiteApiModule

    mocker.patch.object(GSuiteApiModule, "should_use_ucp_auth", return_value=False)

    with pytest.raises(ValueError, match=COMMON_MESSAGES["JSON_PARSE_ERROR"]):
        GSuiteClient({}, proxy=False, verify=False)
