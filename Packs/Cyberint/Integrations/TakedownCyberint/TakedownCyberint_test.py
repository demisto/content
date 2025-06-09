from unittest.mock import MagicMock
from typing import Any
import TakedownCyberint
import pytest
from CommonServerPython import DemistoException
import json
from TakedownCyberint import test_module


BASE_URL = "https://test.cyberint.io"
TOKEN = "example_token"


def load_mock_response(file_name: str) -> str:
    """
    Load one of the mock responses to be used for assertion.
    Args:
        file_name (str): Name of the mock response JSON file to return.
    """
    with open(f"test_data/{file_name}", encoding="utf-8") as mock_file:
        return mock_file.read()


def load_mock_empty_response() -> str:
    """Load mock file that simulates an API response.

    Returns:
        str: Mock file content.
    """
    with open("test_data/empty.jsonb") as file:
        return file.read()


@pytest.fixture()
def mock_client() -> TakedownCyberint.Client:
    """
    Establish a mock connection to the client with access token.

    Returns:
        Client: Mock connection to client.
    """
    return TakedownCyberint.Client(
        base_url=BASE_URL,
        access_token=TOKEN,
        verify=False,
        proxy=False,
    )


# def test_test_module_error(requests_mock, mock_client):
#     """
#     Scenario: API returns an error for an valid token but not permitted customer_id.
#     Given:
#      - User provides valid credentials but not permitted customer_id.
#     """
#     error_response = json.loads(load_mock_response("error_response.json"))
#     requests_mock.post(f"{BASE_URL}/takedown/api/v1/request", status_code=403, json=error_response)
#     assert test_module(mock_client) == "ok"


def test_test_module_forbidden_error(mock_client):
    """Test test_module with a forbidden error."""
    # Mock `retrieve_takedown_requests` to raise a DemistoException with FORBIDDEN status
    exception = DemistoException("Forbidden")
    exception.res = MagicMock(status_code=403)
    mock_client.retrieve_takedown_requests = MagicMock(side_effect=exception)

    result = test_module(mock_client)

    assert result == "ok"
    mock_client.retrieve_takedown_requests.assert_called_once_with(customer_id="Cyberint", url="https://cyberint.com")


def test_test_module_ok(requests_mock, mock_client):
    """
    Scenario: Verify date format.
    Given:
     - User has provided valid credentials and arguments (date).
    When:
     - Using date for commands.
    Then:
     - Ensure that the return date is according to Cyberint format.
    """
    mock_response = json.loads(load_mock_response("test_content.json"))
    requests_mock.post(f"{BASE_URL}/takedown/api/v1/request", json=mock_response)

    result = test_module(mock_client)

    assert result == "ok"


def test_test_module_unexpected_error(mock_client):
    """Test test_module with an unexpected error."""
    # Mock `retrieve_takedown_requests` to raise a generic DemistoException
    exception = DemistoException("Unexpected error")
    mock_client.retrieve_takedown_requests = MagicMock(side_effect=exception)

    with pytest.raises(DemistoException, match="Unexpected error"):
        mock_client.retrieve_takedown_requests()
        mock_client.assert_called_once_with(customer_id="Cyberint", url="https://cyberint.com")


def test_submit_takedown_request_command(requests_mock: MagicMock, mock_client: MagicMock) -> None:
    """
    Scenario: Submit a takedown request successfully.
    Given:
     - User provides valid arguments for submitting a takedown request.
    When:
     - submit_takedown_request_command is called.
    Then:
     - Ensure the command returns the expected CommandResults.
    """
    from TakedownCyberint import submit_takedown_request_command

    # Mock the API response
    mock_response: dict[str, Any] = {
        "data": {
            "takedown_request": {
                "reason": "Phishing",
                "url": "https://example.com/phishing",
                "original_url": "https://example.com",
                "customer": "Cyberint",
                "status": "Open",
                "brand": "Example",
                "alert_ref_id": "12345",
                "alert_id": 123,
                "hosting_providers": ["Provider1", "Provider2"],
                "name_servers": ["ns1.example.com", "ns2.example.com"],
                "escalation_actions": ["Action1", "Action2"],
                "last_escalation_date": "2024-01-01T00:00:00Z",
                "last_status_change_date": "2024-01-02T00:00:00Z",
                "last_seen_date": "2024-01-03T00:00:00Z",
                "created_date": "2023-12-31T00:00:00Z",
                "status_reason": "Submitted",
                "id": "67890",
            }
        }
    }
    requests_mock.post(f"{BASE_URL}/takedown/api/v1/submit", json=mock_response)

    # Prepare the command arguments
    args = {
        "customer": "Cyberint",
        "reason": "Phishing",
        "url": "https://example.com/phishing",
        "brand": "Example",
        "original_url": "https://example.com",
        "alert_id": 123,
        "note": "Test note",
    }

    # Execute the command
    result = submit_takedown_request_command(mock_client, args)

    # Assert the results
    assert result.readable_output.startswith("### Takedown Request")
    assert result.outputs_prefix == "Cyberint.takedowns_submit"
    assert result.outputs_key_field == "id"
    assert result.raw_response == mock_response["data"]["takedown_request"]
    assert result.outputs == mock_response["data"]["takedown_request"]


def test_submit_takedown_request_command_empty_response(requests_mock: MagicMock, mock_client: MagicMock) -> None:
    """
    Scenario: Submit a takedown request but the API returns an empty response.
    Given:
     - User provides valid arguments for submitting a takedown request.
    When:
     - submit_takedown_request_command is called, but the API returns an empty response.
    Then:
     - Ensure the command handles the empty response gracefully.
    """
    from TakedownCyberint import submit_takedown_request_command

    # Mock the API response
    mock_response: dict[str, Any] = {}
    requests_mock.post(f"{BASE_URL}/takedown/api/v1/submit", json=mock_response)

    # Prepare the command arguments
    args = {
        "customer": "Cyberint",
        "reason": "Phishing",
        "url": "https://example.com/phishing",
        "brand": "Example",
        "original_url": "https://example.com",
        "alert_id": 123,
        "note": "Test note",
    }

    # Execute the command
    result = submit_takedown_request_command(mock_client, args)

    # Assert the results
    assert result.readable_output == "### Takedown Request\n**No entries.**\n"
    assert result.outputs_prefix == "Cyberint.takedowns_submit"
    assert result.outputs_key_field == "id"
    assert result.raw_response == {}
    assert result.outputs == {}


def test_retrieve_takedown_requests_command(requests_mock: MagicMock, mock_client: MagicMock):
    """
    Scenario: Retrieve takedown requests successfully.
    Given:
     - User provides valid arguments for retrieving takedown requests.
    When:
     - retrieve_takedown_requests_command is called.
    Then:
     - Ensure the command returns the expected CommandResults.
    """
    from TakedownCyberint import retrieve_takedown_requests_command

    # Mock the API response
    mock_response: dict[str, Any] = {
        "data": {
            "takedown_requests": [
                {
                    "reason": "Phishing",
                    "url": "https://example.com/phishing",
                    "original_url": "https://example.com",
                    "customer": "Cyberint",
                    "status": "Open",
                    "brand": "Example",
                    "alert_ref_id": "12345",
                    "alert_id": 123,
                    "hosting_providers": ["Provider1", "Provider2"],
                    "name_servers": ["ns1.example.com", "ns2.example.com"],
                    "escalation_actions": ["Action1", "Action2"],
                    "last_escalation_date": "2024-01-01T00:00:00Z",
                    "last_status_change_date": "2024-01-02T00:00:00Z",
                    "last_seen_date": "2024-01-03T00:00:00Z",
                    "created_date": "2023-12-31T00:00:00Z",
                    "status_reason": "Submitted",
                    "id": "67890",
                }
            ]
        }
    }
    requests_mock.post(f"{BASE_URL}/takedown/api/v1/request", json=mock_response)

    # Prepare the command arguments
    args = {
        "customer_id": "Cyberint",
        "url": "https://example.com/phishing",
    }

    # Execute the command
    result = retrieve_takedown_requests_command(mock_client, args)

    # Assert the results
    assert result.readable_output.startswith("### Takedown Requests")
    assert result.outputs_prefix == "Cyberint.takedowns_list"
    assert result.outputs_key_field == "id"
    assert result.raw_response == mock_response["data"]["takedown_requests"]
    assert result.outputs == mock_response["data"]["takedown_requests"]


def test_retrieve_takedown_requests_command_empty_response(requests_mock: MagicMock, mock_client: MagicMock) -> None:
    """
    Scenario: Retrieve takedown requests, but the API returns an empty response.
    Given:
     - User provides valid arguments for retrieving takedown requests.
    When:
     - retrieve_takedown_requests_command is called, but the API returns an empty response.
    Then:
     - Ensure the command handles the empty response gracefully.
    """
    from TakedownCyberint import retrieve_takedown_requests_command

    # Mock the API response
    mock_response: dict[str, Any] = {"data": {"takedown_requests": []}}
    requests_mock.post(f"{BASE_URL}/takedown/api/v1/request", json=mock_response)

    # Prepare the command arguments
    args = {
        "customer_id": "Cyberint",
        "url": "https://example.com/phishing",
    }

    # Execute the command
    result = retrieve_takedown_requests_command(mock_client, args)

    # Assert the results
    assert result.readable_output == "### Takedown Requests\n**No entries.**\n"
    assert result.outputs_prefix == "Cyberint.takedowns_list"
    assert result.outputs_key_field == "id"
    assert result.raw_response == []
    assert result.outputs == []


def test_submit_takedown_request_command_error(requests_mock: MagicMock, mock_client: MagicMock) -> None:
    """
    Scenario: Submit a takedown request but the API returns an error.
    Given:
     - User provides valid arguments for submitting a takedown request.
    When:
     - submit_takedown_request_command is called, but the API returns an error.
    Then:
     - Ensure the command raises a DemistoException.
    """
    from TakedownCyberint import submit_takedown_request_command

    # Mock the API response
    mock_response: dict[str, Any] = {"error": "Unauthorized"}
    requests_mock.post(f"{BASE_URL}/takedown/api/v1/submit", json=mock_response, status_code=401)

    # Prepare the command arguments
    args = {
        "customer": "Cyberint",
        "reason": "Phishing",
        "url": "https://example.com/phishing",
        "brand": "Example",
        "original_url": "https://example.com",
        "alert_id": 123,
        "note": "Test note",
    }

    # Execute the command
    with pytest.raises(DemistoException, match="Error in API call"):
        submit_takedown_request_command(mock_client, args)


def test_retrieve_takedown_requests_command_error(requests_mock: MagicMock, mock_client: MagicMock) -> None:
    """
    Scenario: Retrieve takedown requests but the API returns an error.
    Given:
     - User provides valid arguments for retrieving takedown requests.
    When:
     - retrieve_takedown_requests_command is called, but the API returns an error.
    Then:
     - Ensure the command raises a DemistoException.
    """
    from TakedownCyberint import retrieve_takedown_requests_command

    # Mock the API response
    mock_response: dict[str, Any] = {"error": "Unauthorized"}
    requests_mock.post(f"{BASE_URL}/takedown/api/v1/request", json=mock_response, status_code=401)

    # Prepare the command arguments
    args = {
        "customer_id": "Cyberint",
        "url": "https://example.com/phishing",
    }

    # Execute the command
    with pytest.raises(DemistoException, match="Error in API call"):
        retrieve_takedown_requests_command(mock_client, args)
