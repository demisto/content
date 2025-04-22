import pytest
from unittest.mock import patch, MagicMock
from Tavily import TavilyExtractClient, extarct_command


@pytest.fixture
def client():
    return TavilyExtractClient(api_key="test-api-key")


@patch("Tavily.requests.post")
def test_extract_success(mock_post, client):
    """
    Sanity test for success extract
    """
    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.json.return_value = {
        "results": [
            {
                "url": "https://example.com",
                "raw_content": "Example content from the web page."
            }
        ]
    }
    mock_post.return_value = mock_response

    urls = ["https://example.com"]
    result = client.extract(urls)

    assert "results" in result
    assert result["results"][0]["url"] == "https://example.com"
    assert "raw_content" in result["results"][0]
    mock_post.assert_called_once()


@patch("Tavily.requests.post")
def test_extract_failure(mock_post, client):
    """
    Sanity test for failure extract
    """
    mock_response = MagicMock()
    mock_response.status_code = 400
    mock_response.text = "Bad Request"
    mock_post.return_value = mock_response

    urls = ["https://bad-url.com"]

    with pytest.raises(Exception) as excinfo:
        client.extract(urls)

    assert "Request failed" in str(excinfo.value)
    mock_post.assert_called_once()


@patch("Tavily.requests.post")
def test_extarct_command(mock_post, client):
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
    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.json.return_value = {
        "results": [
            {
                "url": "https://example.com",
                "raw_content": "Example content from the web page."
            }
        ]
    }
    mock_post.return_value = mock_response
    args = {"url": "https://example.com"}
    command_results = extarct_command(client, args)

    assert len(command_results.outputs) == 2
    assert isinstance(command_results.outputs, dict)
    assert len(command_results.outputs.keys()) == 2
    assert command_results.outputs["URL"] == "https://example.com"
    assert command_results.outputs["Content"] == "Example content from the web page."

