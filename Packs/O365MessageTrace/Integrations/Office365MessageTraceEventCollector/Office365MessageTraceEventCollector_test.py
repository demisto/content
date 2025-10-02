"""Office365MessageTraceEventCollector - Unit Tests file

Pytest Unit Tests for Office365MessageTraceEventCollector integration
"""

from datetime import datetime, timedelta, timezone
import json
import os
import pytest
from unittest.mock import patch, MagicMock

import demistomock as demisto


def util_load_json(path):
    with open(path, encoding="utf-8") as f:
        return json.loads(f.read())


# Load test data from fixtures
def load_test_data(filename):
    test_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "test_data")
    with open(os.path.join(test_dir, filename), encoding="utf-8") as f:
        return json.loads(f.read())


# Mock data for testing
MOCK_ACCESS_TOKEN = "test_access_token"
MOCK_TRACE_RESPONSE = load_test_data("message_trace_response.json")
MOCK_TRACE_RESPONSE_WITH_NEXTLINK = load_test_data("message_trace_response_with_nextlink.json")
MOCK_TRACE_DETAIL_RESPONSE = load_test_data("message_trace_detail_response.json")

MOCK_TOKEN_RESPONSE = {
    "access_token": MOCK_ACCESS_TOKEN,
    "expires_in": "3600",
    "token_type": "Bearer"
}


@patch("Office365MessageTraceEventCollector.demisto")
def test_test_module(mock_demisto):
    """Test the test_module function"""
    from Office365MessageTraceEventCollector import test_module, Client

    # Mock client test_connection method to return True
    client = MagicMock()
    client.test_connection.return_value = True
    
    result = test_module(client)
    assert result == "ok"
    
    # Test failure case
    client.test_connection.return_value = False
    result = test_module(client)
    assert "Test failed" in result

    # Test exception case
    client.test_connection.side_effect = Exception("Connection error")
    result = test_module(client)
    assert "Test failed: Connection error" in result


@patch("Office365MessageTraceEventCollector.Client._http_request")
def test_request_access_token(mock_http_request):
    """Test the _request_access_token method"""
    from Office365MessageTraceEventCollector import Client, OFFICE365_LOGIN_URL
    
    # Setup
    mock_http_request.return_value = MOCK_TOKEN_RESPONSE
    client = Client(
        url="https://test.com",
        tenant_id="tenant123",
        client_id="client123",
        client_secret="secret123"
    )
    
    # Test
    token = client._request_access_token()
    
    # Assert
    assert token == MOCK_ACCESS_TOKEN
    mock_http_request.assert_called_once()
    args, kwargs = mock_http_request.call_args
    assert kwargs['method'] == 'POST'
    assert kwargs['full_url'] == f"{OFFICE365_LOGIN_URL}/tenant123/oauth2/token"
    assert "client_secret" in kwargs['data']


@patch("Office365MessageTraceEventCollector.jwt")
@patch("Office365MessageTraceEventCollector.Client._http_request")
def test_request_access_token_certificate_based(mock_http_request, mock_jwt):
    """Test the _request_access_token method with certificate-based authentication"""
    from Office365MessageTraceEventCollector import Client, OFFICE365_LOGIN_URL
    
    # Setup
    mock_http_request.return_value = MOCK_TOKEN_RESPONSE
    mock_jwt.encode.return_value = "mocked_jwt_token"
    
    client = Client(
        url="https://test.com",
        tenant_id="tenant123",
        client_id="client123",
        client_secret="",
        certificate_thumbprint="ABCDEF1234567890",
        private_key="-----BEGIN PRIVATE KEY-----\nMockPrivateKey\n-----END PRIVATE KEY-----"
    )
    
    # Test
    token = client._request_access_token()
    
    # Assert
    assert token == MOCK_ACCESS_TOKEN
    mock_http_request.assert_called_once()
    args, kwargs = mock_http_request.call_args
    assert kwargs['method'] == 'POST'
    assert kwargs['full_url'] == f"{OFFICE365_LOGIN_URL}/tenant123/oauth2/token"
    assert "client_assertion" in kwargs['data']
    assert kwargs['data']['client_assertion'] == "mocked_jwt_token"


@patch("Office365MessageTraceEventCollector.time")
@patch("Office365MessageTraceEventCollector.Client._request_access_token")
def test_get_access_token_caching(mock_request_access_token, mock_time):
    """Test that the _get_access_token method properly caches tokens"""
    from Office365MessageTraceEventCollector import Client
    
    # Setup
    client = Client(
        url="https://test.com",
        tenant_id="tenant123",
        client_id="client123",
        client_secret="secret123"
    )
    
    mock_request_access_token.return_value = "test_token"
    
    # Test 1: First call should request a new token
    mock_time.time.return_value = 100  # Current time
    token1 = client._get_access_token()
    
    assert token1 == "test_token"
    assert mock_request_access_token.call_count == 1
    
    # Test 2: Second call with token still valid should use cached token
    mock_time.time.return_value = 200  # Still before expiry
    client.token_expires_at = 1000  # Token expires far in the future
    
    token2 = client._get_access_token()
    assert token2 == "test_token"
    assert mock_request_access_token.call_count == 1  # Still only called once
    
    # Test 3: Call after token expired should request new token
    mock_time.time.return_value = 2000  # After expiry
    
    token3 = client._get_access_token()
    assert token3 == "test_token"
    assert mock_request_access_token.call_count == 2  # Called again


@patch("Office365MessageTraceEventCollector.jwt")
def test_create_client_assertion(mock_jwt):
    """Test the _create_client_assertion method"""
    from Office365MessageTraceEventCollector import Client
    import time
    
    # Setup
    client = Client(
        url="https://test.com",
        tenant_id="tenant123",
        client_id="client123",
        client_secret="",
        certificate_thumbprint="ABCDEF1234567890",
        private_key="-----BEGIN PRIVATE KEY-----\nMockPrivateKey\n-----END PRIVATE KEY-----"
    )
    
    mock_jwt.encode.return_value = "mocked_jwt_token"
    
    # Test
    assertion = client._create_client_assertion("https://test-audience.com")
    
    # Assert
    assert assertion == "mocked_jwt_token"
    mock_jwt.encode.assert_called_once()
    args, kwargs = mock_jwt.encode.call_args
    
    # Check the JWT payload
    payload = args[0]
    assert payload["iss"] == "client123"
    assert payload["sub"] == "client123"
    assert payload["aud"] == "https://test-audience.com"
    
    # Check JWT headers
    headers = kwargs["headers"]
    assert headers["alg"] == "RS256"
    assert headers["x5t"] == "ABCDEF1234567890"


@patch("Office365MessageTraceEventCollector.jwt", None)
def test_create_client_assertion_missing_jwt():
    """Test the _create_client_assertion method when JWT module is not available"""
    from Office365MessageTraceEventCollector import Client
    
    # Setup
    client = Client(
        url="https://test.com",
        tenant_id="tenant123",
        client_id="client123",
        client_secret="",
        certificate_thumbprint="ABCDEF1234567890",
        private_key="-----BEGIN PRIVATE KEY-----\nMockPrivateKey\n-----END PRIVATE KEY-----"
    )
    
    # Test - should raise an error when JWT is not available
    with pytest.raises(ValueError) as excinfo:
        client._create_client_assertion("https://test-audience.com")
    
    assert "PyJWT library is required" in str(excinfo.value)


def test_create_client_assertion_missing_private_key():
    """Test the _create_client_assertion method when private key is missing"""
    from Office365MessageTraceEventCollector import Client
    
    # Setup
    client = Client(
        url="https://test.com",
        tenant_id="tenant123",
        client_id="client123",
        client_secret="",
        certificate_thumbprint="ABCDEF1234567890",
        private_key=None
    )
    
    # Test - should raise an error when private key is missing
    with pytest.raises(ValueError) as excinfo:
        client._create_client_assertion("https://test-audience.com")
    
    assert "Private key is required" in str(excinfo.value)


@patch("Office365MessageTraceEventCollector.Client._get_access_token")
@patch("Office365MessageTraceEventCollector.Client._http_request")
def test_make_authenticated_request(mock_http_request, mock_get_access_token):
    """Test the _make_authenticated_request method"""
    from Office365MessageTraceEventCollector import Client
    
    # Setup
    client = Client(
        url="https://test.com",
        tenant_id="tenant123",
        client_id="client123",
        client_secret="secret123"
    )
    
    mock_get_access_token.return_value = "test_access_token"
    mock_http_request.return_value = {"result": "success"}
    
    # Test
    result = client._make_authenticated_request("GET", "/test-endpoint", params={"param": "value"})
    
    # Assert
    assert result == {"result": "success"}
    mock_get_access_token.assert_called_once()
    mock_http_request.assert_called_once()
    
    args, kwargs = mock_http_request.call_args
    assert kwargs['method'] == 'GET'
    assert kwargs['url_suffix'] == '/test-endpoint'
    assert kwargs['params'] == {"param": "value"}
    assert kwargs['headers']['Authorization'] == "Bearer test_access_token"
    assert kwargs['headers']['Accept'] == "application/json"


@patch("Office365MessageTraceEventCollector.Client._make_authenticated_request")
def test_get_message_trace(mock_make_request):
    """Test the get_message_trace method"""
    from Office365MessageTraceEventCollector import Client
    
    # Setup
    mock_make_request.return_value = MOCK_TRACE_RESPONSE
    client = Client(
        url="https://test.com",
        tenant_id="tenant123",
        client_id="client123",
        client_secret="secret123"
    )
    
    # Test with all parameters
    result = client.get_message_trace(
        start_date="2023-07-01T00:00:00Z",
        end_date="2023-07-02T00:00:00Z",
        sender_address="sender@example.com",
        recipient_address="recipient@example.com",
        message_trace_id="123456-78901-abcdef",
        status="Delivered"
    )
    
    # Assert
    assert result == MOCK_TRACE_RESPONSE
    mock_make_request.assert_called_once()
    args, kwargs = mock_make_request.call_args
    assert kwargs['method'] == 'GET'
    assert kwargs['url_suffix'] == '/MessageTrace'
    assert "$filter" in kwargs['params']
    assert "SenderAddress eq 'sender@example.com'" in kwargs['params']['$filter']


@patch("Office365MessageTraceEventCollector.Client.get_message_trace")
def test_office365_message_trace_list_paging(mock_get_message_trace):
    """Test the office365_message_trace_list_paging function"""
    from Office365MessageTraceEventCollector import Client, office365_message_trace_list_paging
    
    # Setup
    client = Client(
        url="https://test.com",
        tenant_id="tenant123",
        client_id="client123",
        client_secret="secret123"
    )
    
    # Test with a single page of results
    mock_get_message_trace.return_value = MOCK_TRACE_RESPONSE
    results = office365_message_trace_list_paging(
        client=client,
        start_date="2023-07-01T00:00:00Z",
        end_date="2023-07-02T00:00:00Z"
    )
    
    # Assert
    assert len(results) == 2
    assert results[0]["MessageId"] == "<ABC123@contoso.com>"
    assert results[1]["MessageId"] == "<ABC124@contoso.com>"
    
    # Test with pagination (multiple pages)
    mock_get_message_trace.side_effect = [
        MOCK_TRACE_RESPONSE_WITH_NEXTLINK,  # First call returns nextLink
        MOCK_TRACE_RESPONSE  # Second call returns more results
    ]
    results = office365_message_trace_list_paging(
        client=client,
        start_date="2023-07-01T00:00:00Z",
        end_date="2023-07-02T00:00:00Z"
    )
    
    # Assert
    assert len(results) == 3  # 1 from first page + 2 from second page
    assert mock_get_message_trace.call_count == 2


def test_parse_message_trace_date_range():
    """Test the parse_message_trace_date_range function"""
    from Office365MessageTraceEventCollector import parse_message_trace_date_range
    
    # Test with hours
    start, end = parse_message_trace_date_range("24 hours")
    now = datetime.now(timezone.utc)
    expected_start = (now - timedelta(hours=24)).strftime("%Y-%m-%dT%H:%M:%SZ")
    assert start[:16] == expected_start[:16]  # Compare only up to minutes to avoid second differences
    
    # Test with days
    start, end = parse_message_trace_date_range("7 days")
    expected_start = (now - timedelta(days=7)).strftime("%Y-%m-%dT%H:%M:%SZ")
    assert start[:16] == expected_start[:16]
    
    # Test default (48 hours)
    start, end = parse_message_trace_date_range()
    expected_start = (now - timedelta(hours=48)).strftime("%Y-%m-%dT%H:%M:%SZ")
    assert start[:16] == expected_start[:16]


def test_format_message_trace_results():
    """Test the format_message_trace_results function"""
    from Office365MessageTraceEventCollector import format_message_trace_results
    
    # Test normal formatting
    formatted = format_message_trace_results(MOCK_TRACE_RESPONSE["value"])
    assert len(formatted) == 2
    assert formatted[0]["MessageId"] == "<ABC123@contoso.com>"
    assert formatted[0]["Received"] == "2023-07-01T12:00:00Z"
    
    # Test formatting for dataset (XSIAM)
    formatted = format_message_trace_results(MOCK_TRACE_RESPONSE["value"], for_dataset=True)
    assert "_time" in formatted[0]
    assert "Received" not in formatted[0]
    assert formatted[0]["_time"] == "2023-07-01T12:00:00Z"


@patch("Office365MessageTraceEventCollector.office365_message_trace_list_paging")
@patch("Office365MessageTraceEventCollector.tableToMarkdown")
def test_office365_message_trace_list_command(mock_table_to_markdown, mock_list_paging):
    """Test the office365_message_trace_list_command function"""
    from Office365MessageTraceEventCollector import Client, office365_message_trace_list_command
    
    # Setup
    client = Client(
        url="https://test.com",
        tenant_id="tenant123",
        client_id="client123",
        client_secret="secret123"
    )
    mock_list_paging.return_value = MOCK_TRACE_RESPONSE["value"]
    mock_table_to_markdown.return_value = "Markdown Table"
    
    # Test with all parameters
    args = {
        "start_date": "2023-07-01T00:00:00Z",
        "end_date": "2023-07-02T00:00:00Z",
        "sender_address": "sender@example.com",
        "recipient_address": "recipient@example.com",
        "message_trace_id": "123456-78901-abcdef",
        "status": "Delivered",
        "top": "100"
    }
    result = office365_message_trace_list_command(client, args)
    
    # Assert
    assert result.outputs_prefix == 'Office365.MessageTrace'
    assert result.outputs_key_field == 'MessageId'
    assert isinstance(result.outputs, list)
    assert len(result.outputs) == 2
    
    # Test with only date_range
    args = {
        "date_range": "48 hours"
    }
    result = office365_message_trace_list_command(client, args)
    assert result.outputs_prefix == 'Office365.MessageTrace'


@patch("Office365MessageTraceEventCollector.office365_message_trace_list_paging")
def test_get_events(mock_list_paging):
    """Test the get_events function"""
    from Office365MessageTraceEventCollector import Client, get_events
    
    # Setup
    client = Client(
        url="https://test.com",
        tenant_id="tenant123",
        client_id="client123",
        client_secret="secret123"
    )
    mock_list_paging.return_value = MOCK_TRACE_RESPONSE["value"]
    
    # Test
    events, new_timestamp, new_id = get_events(
        client=client,
        last_timestamp="2023-07-01T00:00:00Z",
        last_id="<previousid@example.com>",
        limit=100
    )
    
    # Assert
    assert len(events) == 2
    assert events[0]["MessageTraceId"] == "123456-78901-abcdef"
    assert "_time" in events[0]
    assert events[0]["_time"] == "2023-07-01T12:00:00Z"
    assert new_timestamp != "2023-07-01T00:00:00Z"  # Should be updated
    assert new_id == "<ABC123@contoso.com>"


@patch("Office365MessageTraceEventCollector.get_events")
@patch("Office365MessageTraceEventCollector.send_events_to_xsiam")
@patch("Office365MessageTraceEventCollector.demisto")
def test_office365_message_trace_fetch_events_command(mock_demisto, mock_send_events, mock_get_events):
    """Test the office365_message_trace_fetch_events_command function"""
    from Office365MessageTraceEventCollector import Client, office365_message_trace_fetch_events_command
    
    # Setup
    client = Client(
        url="https://test.com",
        tenant_id="tenant123",
        client_id="client123",
        client_secret="secret123"
    )
    
    mock_demisto.params.return_value = {
        "limit": "100",
        "first_fetch": "1 day ago"
    }
    mock_demisto.getLastRun.return_value = {
        "last_timestamp": "2023-07-01T00:00:00Z",
        "last_id": "<previousid@example.com>"
    }
    
    mock_get_events.return_value = (
        MOCK_TRACE_RESPONSE["value"],
        "2023-07-01T12:00:01Z",  # New timestamp
        "<ABC123@contoso.com>"   # New ID
    )
    
    # Test
    office365_message_trace_fetch_events_command(client)
    
    # Assert
    mock_get_events.assert_called_once_with(
        client=client,
        last_timestamp="2023-07-01T00:00:00Z",
        last_id="<previousid@example.com>",
        limit=100
    )
    mock_send_events.assert_called_once_with(MOCK_TRACE_RESPONSE["value"], "microsoft", "messagetrace")
    mock_demisto.setLastRun.assert_called_once_with({
        "last_timestamp": "2023-07-01T12:00:01Z",
        "last_id": "<ABC123@contoso.com>"
    })


@patch("Office365MessageTraceEventCollector.Client")
@patch("Office365MessageTraceEventCollector.demisto")
def test_main_test_module(mock_demisto, mock_client_class):
    """Test the main function with test-module command"""
    from Office365MessageTraceEventCollector import main
    
    # Setup
    mock_demisto.command.return_value = "test-module"
    mock_demisto.params.return_value = {
        "tenant_id": "tenant123",
        "client_id": "client123",
        "client_secret": "secret123",
        "url": "https://test.com",
        "insecure": "false",
        "proxy": "false"
    }
    
    mock_client_instance = MagicMock()
    mock_client_class.return_value = mock_client_instance
    
    # Mock test_module function indirectly
    mock_client_instance.test_connection.return_value = True
    
    # Test
    main()
    
    # Assert
    mock_demisto.results.assert_called_once_with("ok")


@patch("Office365MessageTraceEventCollector.Client")
@patch("Office365MessageTraceEventCollector.demisto")
@patch("Office365MessageTraceEventCollector.office365_message_trace_list_command")
def test_main_get_events(mock_list_command, mock_demisto, mock_client_class):
    """Test the main function with office365-mt-get-events command"""
    from Office365MessageTraceEventCollector import main
    
    # Setup
    mock_demisto.command.return_value = "office365-mt-get-events"
    mock_demisto.params.return_value = {
        "tenant_id": "tenant123",
        "client_id": "client123",
        "client_secret": "secret123",
        "url": "https://test.com",
        "insecure": "false",
        "proxy": "false"
    }
    mock_demisto.args.return_value = {
        "start_date": "2023-07-01T00:00:00Z"
    }
    
    mock_client_instance = MagicMock()
    mock_client_class.return_value = mock_client_instance
    
    # Mock command result
    command_result = MagicMock()
    mock_list_command.return_value = command_result
    
    # Test
    main()
    
    # Assert
    mock_list_command.assert_called_once_with(mock_client_instance, {"start_date": "2023-07-01T00:00:00Z"})
    mock_demisto.results.assert_called_once_with(command_result)


@patch("Office365MessageTraceEventCollector.Client")
@patch("Office365MessageTraceEventCollector.demisto")
@patch("Office365MessageTraceEventCollector.office365_message_trace_fetch_events_command")
def test_main_fetch_events(mock_fetch_command, mock_demisto, mock_client_class):
    """Test the main function with fetch-events command"""
    from Office365MessageTraceEventCollector import main
    
    # Setup
    mock_demisto.command.return_value = "fetch-events"
    mock_demisto.params.return_value = {
        "tenant_id": "tenant123",
        "client_id": "client123",
        "client_secret": "secret123",
        "url": "https://test.com",
        "insecure": "false",
        "proxy": "false"
    }
    
    mock_client_instance = MagicMock()
    mock_client_class.return_value = mock_client_instance
    
    # Test
    main()
    
    # Assert
    mock_fetch_command.assert_called_once_with(mock_client_instance)


@patch("Office365MessageTraceEventCollector.Client")
@patch("Office365MessageTraceEventCollector.demisto")
def test_main_invalid_command(mock_demisto, mock_client_class):
    """Test the main function with an invalid command"""
    from Office365MessageTraceEventCollector import main
    
    # Setup
    mock_demisto.command.return_value = "invalid-command"
    mock_demisto.params.return_value = {
        "tenant_id": "tenant123",
        "client_id": "client123",
        "client_secret": "secret123",
        "url": "https://test.com",
        "insecure": "false",
        "proxy": "false"
    }
    
    # Test
    main()
    
    # Assert
    mock_demisto.error.assert_called_once()
    args = mock_demisto.error.call_args[0][0]
    assert "Failed to execute" in args
    assert "NotImplementedError" in args


def test_client_get_message_trace_detail():
    """Test the get_message_trace_detail method"""
    from Office365MessageTraceEventCollector import Client
    
    # Setup
    client = Client(
        url="https://test.com",
        tenant_id="tenant123",
        client_id="client123",
        client_secret="secret123"
    )
    
    # Mock _make_authenticated_request method
    client._make_authenticated_request = MagicMock(return_value=MOCK_TRACE_DETAIL_RESPONSE)
    
    # Test
    result = client.get_message_trace_detail(
        message_trace_id="123456-78901-abcdef",
        recipient_address="recipient@example.com",
        sender_address="sender@example.com",
        start_date="2023-07-01T00:00:00Z",
        end_date="2023-07-02T00:00:00Z"
    )
    
    # Assert
    assert result == MOCK_TRACE_DETAIL_RESPONSE
    client._make_authenticated_request.assert_called_once()
    args, kwargs = client._make_authenticated_request.call_args
    assert kwargs['method'] == 'GET'
    assert kwargs['url_suffix'] == '/MessageTraceDetail'
    assert "$filter" in kwargs['params']
    assert "MessageTraceId eq guid'123456-78901-abcdef'" in kwargs['params']['$filter']
