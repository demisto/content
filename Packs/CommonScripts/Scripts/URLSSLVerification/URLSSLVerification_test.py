import pytest
from pytest_mock import MockerFixture
import demistomock as demisto
from URLSSLVerification import arg_to_list_with_regex, mark_http_as_suspicious,main


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
    
    
@pytest.mark.parametrize(
    "arg, expected_result",
    [
        # Set_http_as_suspicous = True
        ({"url":"http://neverssl.com","set_http_as_suspicious":"true"}, {"Verified":False, "Score":2}),
        ({"url":"https://google.com","set_http_as_suspicious":"true"}, {"Verified":True, "Score":"Unknown"}),
        # Set_http_as_suspicous = False
        ({"url":"http://wikipedia.org","set_http_as_suspicious":"false"}, {"Verified":True, "Score":"Unknown"}),
        ({"url":"http://neverssl.com","set_http_as_suspicious":"false"}, {"Verified":False, "Score":2}),
        ({"url":"https://google.com","set_http_as_suspicious":"false"}, {"Verified":True, "Score":"Unknown"}),
        ({"url":"https://expired.badssl.com","set_http_as_suspicious":"false"}, {"Verified":False, "Score":2}),
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
    
    # Call the main function
    main()
    
    # Assert that return_results was called with the correct arguments
    mock_return_results.assert_called_once()
    
    result = mock_return_results.call_args[0][0]
    
    for url in result.outputs["URL"]:
        assert url["Verified"] == expected_result["Verified"]
    
    for d_bot in result.outputs["DBotScore"]:
        assert d_bot["Score"] == expected_result["Score"]