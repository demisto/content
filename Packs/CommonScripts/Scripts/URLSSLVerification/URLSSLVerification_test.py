import pytest
from pytest_mock import MockerFixture
import demistomock as demisto
from URLSSLVerification import arg_to_list_with_regex, mark_http_as_suspicious,main
import requests
from requests.exceptions import SSLError, RequestException

@pytest.mark.parametrize("arg, expected_result", [("false", False), ("true", True), (None, True)])
def test_is_http_should_be_suspicious(arg, expected_result):
    assert mark_http_as_suspicious(arg) == expected_result


@pytest.mark.parametrize(
    "arg, expected_result",
    [
        (None, []),
        (["some_url"], ["some_url"]),
        ('["some_url"]', ["some_url"]),
        ("https://some_url.com", ["https://some_url.com"]),
    ],
)
def test_arg_to_list_with_regex(arg, expected_result):
    assert arg_to_list_with_regex(arg) == expected_result


def create_response(url, status_code = 200, history = []):
    resp = requests.Response()
    resp.status_code = status_code
    resp.url = url
    resp.history = history
    return resp


def fake_requests_get(url, timeout, allow_redirects=True, verify=True):
    """
    This helper function simulates HTTP requests with no real URL.
    It fabricates response objects that include status codes, URL redirection history, and header-like information.

    Args:
        url (str): The target URL.
        timeout (int or float): Maximum time in seconds to wait for the response.
        allow_redirects (bool, optional): Whether to follow redirects. Defaults to True.
        verify (bool, optional): Whether to enforce SSL certificate verification. Defaults to True.

    Raises:
        SSLError: If SSL certificate verification fails.

    Returns:
        requests.Response: A simulated HTTP response including status, final URL, and redirect history.

    """
    if url == "https_no_certificate" and verify:
        raise SSLError("SSL certificate error")
    
    elif url == "http" or url == "https_certificate":
        return create_response(url=url)
    
    elif url == "http_to_https_certificate":
        first_response = create_response(url="http_to_https_certificate", status_code=301)
        if allow_redirects:
            return create_response(url="https_certificate", history=[first_response])
        else:
            return first_response
    elif url == "http_to_http" and allow_redirects:
        first_response = create_response(url="http_to_http", status_code=301)
        if allow_redirects:
            return create_response(url="http", history=[first_response])
        else:
            return first_response
        
    else:
        raise RequestException

    
@pytest.mark.parametrize(
    "arg, expected_result",
    [
        # Set_http_as_suspicious = True
        ({"url":"http","set_http_as_suspicious":"true"}, {"Verified":False, "Score":2}),
        ({"url":"https_certificate","set_http_as_suspicious":"true"}, {"Verified":True, "Score":"Unknown"}),
        # Set_http_as_suspicious = False
        ({"url":"http_to_https_certificate","set_http_as_suspicious":"false"}, {"Verified":True, "Score":"Unknown"}),
        ({"url":"http","set_http_as_suspicious":"false"}, {"Verified":False, "Score":2}),
        ({"url":"https_certificate","set_http_as_suspicious":"false"}, {"Verified":True, "Score":"Unknown"}),
        ({"url":"https_no_certificate","set_http_as_suspicious":"false"}, {"Verified":False, "Score":2}),
    ],
)
def test_main(arg, expected_result, mocker: MockerFixture):
    # Mock demisto.args()
    mocker.patch.object(
        demisto,
        "args",
        return_value=arg,
    )
     # Mock return_results
    mock_return_results = mocker.patch("URLSSLVerification.return_results")
    mocker.patch("URLSSLVerification.requests.get", side_effect=fake_requests_get)
    
    # Call the main function
    main()
    
    # Assert that return_results was called with the correct arguments
    mock_return_results.assert_called_once()
    
    result = mock_return_results.call_args[0][0]
    
    for url in result.outputs["URL"]:
        assert url["Verified"] == expected_result["Verified"]
    
    for d_bot in result.outputs["DBotScore"]:
        assert d_bot["Score"] == expected_result["Score"]