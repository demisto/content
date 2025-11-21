import json
import pytest
from unshortenMe import Client, unshorten_url_command, test_module
from CommonServerPython import DemistoException

SERVER_URL = "https://unshorten.me/api/v2"


def util_load_json(path):
    with open(path, encoding="utf-8") as f:
        return json.loads(f.read())


@pytest.fixture()
def client():
    """Provides a client instance for tests."""
    return Client(base_url=SERVER_URL, proxy=False, verify=False, headers={"Authorization": "Token test_token"})


def test_unshorten_url_command_success(client, mocker):
    """
    GIVEN:
        - A valid short URL.
    WHEN:
        - The unshorten_url_command is called.
        - The API returns a successful response.
    THEN:
        - Ensure the CommandResults object contains the correct, unshortened URL.
    """
    # Arrange: Load mock data and mock the underlying http_request method
    mock_response = util_load_json("test_data/success_response.json")
    mocker.patch.object(Client, "_http_request", return_value=mock_response)

    # Act: Call the command function
    result = unshorten_url_command(client, "https://bit.ly/3DKWm5t")

    # Assert: Check the outputs (accessing the first item in the list)
    assert result.outputs_prefix == "unshortenMe"
    assert result.outputs[0]["success"] is True
    assert result.outputs[0]["unshortened_url"] == "https://www.youtube.com/"
    assert "unshorten.me results" in result.readable_output  # Check for table title


def test_unshorten_url_command_api_failure(client, mocker):
    """
    GIVEN:
        - A URL that causes an API error.
    WHEN:
        - The unshorten_url_command is called.
        - The API returns a response with "success": false.
    THEN:
        - Ensure a DemistoException is raised with the correct error message.
    """
    # Arrange
    mock_response = util_load_json("test_data/failure_response.json")
    mocker.patch.object(Client, "_http_request", return_value=mock_response)

    # Act / Assert
    with pytest.raises(DemistoException, match="unshorten.me API error: URL is not valid"):
        unshorten_url_command(client, "https://example.com/some-bad-link")


def test_unshorten_url_command_invalid_input(client):
    """
    GIVEN:
        - An improperly formatted URL string (missing http/https).
    WHEN:
        - The unshorten_url_command is called.
    THEN:
        - Ensure a ValueError is raised before any API call is made.
    """
    # Act / Assert
    with pytest.raises(ValueError, match="Input is not a valid URL format"):
        unshorten_url_command(client, "example.com")


def test_test_module_command(client, mocker):
    """
    GIVEN:
        - A client instance.
    WHEN:
        - The test_module command is called.
    THEN:
        - Ensure the function makes a request and returns 'ok' on success.
    """
    # Arrange: Mock the request method to simulate a successful API call
    mocker.patch.object(Client, "unshorten_request")

    # Act
    result = test_module(client)

    # Assert
    assert result == "ok"


def test_test_module_failure(client, mocker):
    """
    GIVEN:
        - The client is configured to throw an error.
    WHEN:
        - The test_module is called.
    THEN:
        - Ensure it catches the exception and returns an error message.
    """
    # Arrange
    mocker.patch.object(client, "unshorten_request", side_effect=DemistoException("API call failed"))

    # Act: Call the command
    result = test_module(client)

    # Assert
    assert "Error: API call failed" in result


def test_main_unknown_command(mocker):
    """
    GIVEN:
        - An unknown command is provided.
    WHEN:
        - The main function is called.
    THEN:
        - Ensure the NotImplementedError is caught and return_error is called.
    """
    # Arrange: Mock the demisto object to simulate an unknown command
    mocker.patch("unshortenMe.demisto.command", return_value="some-unknown-command")
    mocker.patch("unshortenMe.demisto.params", return_value={"credentials": {"password": "test"}})
    mocker.patch("unshortenMe.demisto.args", return_value={})
    return_error_mock = mocker.patch("unshortenMe.return_error")
    mocker.patch("unshortenMe.demisto.error")  # <-- ADD THIS LINE

    # Act: Call the main function
    from unshortenMe import main

    main()

    # Assert: Ensure return_error was called with the correct message
    return_error_mock.assert_called_once()
    call_args, _ = return_error_mock.call_args
    assert "Command some-unknown-command is not implemented" in call_args[0]
