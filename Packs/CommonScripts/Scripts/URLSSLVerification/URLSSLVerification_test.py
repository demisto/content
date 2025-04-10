import pytest
from pytest_mock import MockerFixture
import demistomock as demisto
from URLSSLVerification import arg_to_list_with_regex, mark_http_as_suspicious,main,verify_ssl_certificate
import requests

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
        ("this is a test",["this is a test"])
    ],
)
def test_arg_to_list_with_regex(arg, expected_result):
    assert arg_to_list_with_regex(arg) == expected_result
    
@pytest.mark.parametrize(
    "arg, expected_results",
    [
        # Set_http_as_suspicious = True
        ({"url":"http://neverssl.com",
          "set_http_as_suspicious":"true"},              [{"Verified":False,
                                                           "Score":2,
                                                           "Indicator":"http://neverssl.com"}]),
        ({"url":"https://www.google.com",
          "set_http_as_suspicious":"true"},              [{"Verified":True,
                                                           "Score":0,
                                                           "Indicator":"https://www.google.com"}]),
        
        # Set_http_as_suspicious = False
        ({"url":"http://expired.badssl.com",
          "set_http_as_suspicious":"false"},             [{"Verified":False,
                                                           "Score":2,
                                                           "Indicator":"http://expired.badssl.com"}]),
        ({"url":"http://neverssl.com",
          "set_http_as_suspicious":"false"},             [{"Verified":False,
                                                           "Score":2,
                                                           "Indicator":"http://neverssl.com"}]),
        ({"url":"https://www.google.com",
          "set_http_as_suspicious":"false"},             [{"Verified":True,
                                                           "Score":0,
                                                           "Indicator":"https://www.google.com"}]),
        ({"url":"https://expired.badssl.com",
          "set_http_as_suspicious":"false"},             [{"Verified":False,
                                                           "Score":2,
                                                           "Indicator":"https://expired.badssl.com"}]),
        ({"url":"http://httpbin.org/redirect/1",
          "set_http_as_suspicious":"false"},             [{"Verified":False,
                                                           "Score":2,
                                                           "Indicator":"http://httpbin.org/redirect/1"}]),
        ({"url":"invalid_url",
          "set_http_as_suspicious":"false"},              [{"Verified":False,
                                                            "Score":2,
                                                            "Indicator":"invalid_url"}]),
        
        # Test Multiple url
        ({"url":["invalid_url","http://httpbin.org/redirect/1"],
          "set_http_as_suspicious":"false"},
                                                          [{"Verified":False,
                                                            "Score":2,
                                                            "Indicator":"invalid_url"},
                                                           {"Verified":False,
                                                            "Score":2,
                                                            "Indicator":"http://httpbin.org/redirect/1"},
                                                           ]),
    ],
)
def test_main(arg, expected_results, mocker: MockerFixture):
    """
    Given:
        Requests.get work as mentioned above.
    When:
        main function is called.
    Then:
        The function should return the appropriate message.
    """
    # Mock demisto.args()
    mocker.patch.object(
        demisto,
        "args",
        return_value=arg,
    )
     # Mock return_results
    mock_return_results = mocker.patch("URLSSLVerification.return_results")
    
    # Call the main function
    main()
    
    # Assert that return_results was called with the correct arguments
    mock_return_results.assert_called_once()
    
    result = mock_return_results.call_args[0][0]
    
    for url in result.outputs["URL"]:
        assert url["Verified"] == [ret["Verified"] for ret in expected_results if ret["Indicator"] == url["Data"]][0]
    
    for d_bot in result.outputs["DBotScore"]:
        assert d_bot["Score"] == [ret["Score"] for ret in expected_results if ret["Indicator"] == d_bot["Indicator"]][0]
        
@pytest.mark.parametrize("url, description_result",[
    ("https://expired.badssl.com","SSL Certificate verification failed"),
    ("invalid_url","Failed to establish a new connection with the URL"),
])
def test_verify_ssl_certificate(url, description_result, mocker: MockerFixture):
    """
    Given:
        Requests.get work as mentioned above.
    When:
        verify_ssl_certificate is called.
    Then:
        The function should return the appropriate message.
    """
    
    result = verify_ssl_certificate(url)
    assert result
    assert result["Description"] == description_result
    