import json
from requests.models import Response
import pytest
from Tavily import TavilyExtractClient, extarct_command


@pytest.fixture
def tavily_extract_client():
    return TavilyExtractClient(api_key="test-api-key")


def test_extract_success(mocker, tavily_extract_client):
    """
    Sanity test for success extract
    """
    response = Response()
    response.status_code = 200
    response._content = json.dumps({
        "results": [
            {
                "url": "https://example.com",
                "raw_content": "Example content from the web page."
            }
        ]
    }).encode("utf-8")

    http_request = mocker.patch.object(tavily_extract_client, "_http_request", return_value=response)

    url = "https://example.com"
    result = tavily_extract_client.extract(url)

    assert "results" in result
    assert result["results"][0]["url"] == "https://example.com"
    assert "raw_content" in result["results"][0]
    http_request.assert_called_once()


def test_extract_failure(mocker, tavily_extract_client):
    """
    Sanity test for failure extract
    """
    response = Response()
    response.status_code = 400
    response._content = b"Bad Request"

    http_request = mocker.patch.object(tavily_extract_client, "_http_request", return_value=response)

    url = "https://bad-url.com"

    with pytest.raises(Exception) as excinfo:
        tavily_extract_client.extract(url)

    assert "Request failed" in str(excinfo.value)
    http_request.assert_called_once()


def test_extarct_command(mocker, tavily_extract_client):
    """
    Given:
        - A client
        - An url for check
    When:
        - Executing the extarct_command function
    Then:
        - Ensure the command results contains two outputs (URL and Content)
        - Ensure the first dictionary for the first given url contains the two keys: URL and Content and correct values
    """
    response = Response()
    response.status_code = 200
    response._content = json.dumps({
        "results": [
            {
                "url": "https://example.com",
                "raw_content": "Example content from the web page."
            }
        ]
    }).encode("utf-8")

    mocker.patch.object(tavily_extract_client, "_http_request", return_value=response)

    command_results = extarct_command(client=tavily_extract_client, args={"url": "https://example.com"})

    assert len(command_results.outputs) == 2
    assert isinstance(command_results.outputs, dict)
    assert len(command_results.outputs.keys()) == 2
    assert command_results.outputs["URL"] == "https://example.com"
    assert command_results.outputs["Content"] == "Example content from the web page."
