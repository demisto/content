"""Office365MessageTraceEventCollector - Unit Tests

Pytest Unit Tests for Office365MessageTraceEventCollector integration
"""

import json
from unittest.mock import patch


TENANT_ID = "test-tenant-id"
TENANT_URL = "https://test.com"
CLIENT_ID = "client123"
CLIENT_SECRET = "secret123"


def util_load_json(path):
    with open(path, encoding="utf-8") as f:
        return json.loads(f.read())


@patch("Office365MessageTraceEventCollector.Client._http_request")
def test_test_module(mock_http_request):
    """Test test_module function"""
    from Office365MessageTraceEventCollector import Client, test_module

    # Mock response data
    mock_response = {"value": []}

    mock_http_request.return_value = mock_response

    client = Client(url=TENANT_URL, tenant_id=TENANT_ID, client_id=CLIENT_ID, client_secret=CLIENT_SECRET, verify=False)

    response = test_module(client)

    # Assertions
    assert response == "ok"


@patch("Office365MessageTraceEventCollector.Client._http_request")
def test_get_message_trace_response(mock_http_request):
    """Test get_message_trace returns proper API response"""
    from Office365MessageTraceEventCollector import Client

    # Mock response data
    mock_response = util_load_json("./test_data/message_trace_response.json")

    mock_http_request.return_value = mock_response

    client = Client(
        url=TENANT_URL,
        tenant_id=TENANT_ID,
        client_id=CLIENT_ID,
        client_secret=CLIENT_SECRET,
        verify=False,
    )

    # Mock _get_access_token to avoid actual token request
    with patch.object(client, "_get_access_token", return_value="test_token"):
        result = client.get_message_trace(
            start_date="2023-07-01T00:00:00Z",
            end_date="2023-07-02T00:00:00Z",
            sender_address="sender@example.com",
        )

    # Assertions
    assert result == mock_response
    assert len(result["value"]) == 2
    assert result["value"][0]["MessageId"] == "<ABC123@contoso.com>"


@patch("Office365MessageTraceEventCollector.send_events_to_xsiam")
@patch("Office365MessageTraceEventCollector.Client._http_request")
@patch("Office365MessageTraceEventCollector.demisto")
def test_fetch_events_command(mock_demisto, mock_http_request, mock_send_events):
    """Test fetch_events_command function"""
    from Office365MessageTraceEventCollector import Client, office365_message_trace_fetch_events_command

    # Mock response data
    mock_response = util_load_json("./test_data/message_trace_fetch_response.json")

    mock_http_request.return_value = mock_response
    mock_demisto.params.return_value = {"first_fetch": "1 day ago", "processing_delay": "0"}
    mock_demisto.getLastRun.return_value = {}
    mock_demisto.getIntegrationContext.return_value = {}

    client = Client(url=TENANT_URL, tenant_id=TENANT_ID, client_id=CLIENT_ID, client_secret=CLIENT_SECRET, verify=False)

    # Mock _get_access_token to avoid actual token request
    with patch.object(client, "_get_access_token", return_value="test_token"):
        office365_message_trace_fetch_events_command(client)

    # Assertions
    assert mock_demisto.setLastRun.called
    assert mock_demisto.debug.called
    assert mock_send_events.called


def test_parse_message_trace_date_range_with_last_run():
    """Test parse_message_trace_date_range with processing delay"""
    from Office365MessageTraceEventCollector import parse_message_trace_date_range

    first_fetch = "3 days ago"
    processing_delay = 0

    start_time, end_time = parse_message_trace_date_range(first_fetch, processing_delay)

    # Should calculate 3 days in the past
    assert start_time is not None
    assert end_time is not None
    # Verify both are in ISO format
    assert "T" in start_time
    assert "T" in end_time


def test_parse_message_trace_date_range_no_last_run():
    """Test parse_message_trace_date_range without last_run_time (first fetch)"""
    from Office365MessageTraceEventCollector import parse_message_trace_date_range

    first_fetch = "2 days ago"
    processing_delay = 0

    start_time, end_time = parse_message_trace_date_range(first_fetch, processing_delay)

    # Should parse first_fetch time - result is in %Y-%m-%dT%H:%M:%SZ format
    # Verify format is correct
    assert start_time is not None
    assert end_time is not None
    assert "T" in start_time
    assert "Z" in start_time
    assert "T" in end_time
    assert "Z" in end_time


def test_parse_message_trace_date_range_invalid_first_fetch():
    """Test parse_message_trace_date_range with invalid first_fetch defaults to 5 minutes ago"""
    from Office365MessageTraceEventCollector import parse_message_trace_date_range
    import pytest

    first_fetch = "completely-invalid"
    processing_delay = 0

    with pytest.raises(ValueError) as exc_info:
        parse_message_trace_date_range(first_fetch, processing_delay)

    assert f"Unable to parse date range: {first_fetch}" in str(exc_info.value)


def test_format_message_trace_results_with_time_field():
    """Test format_message_trace_results with Received field"""
    from Office365MessageTraceEventCollector import format_message_trace_results

    events = util_load_json("./test_data/format_message_trace_results.json")

    formatted = format_message_trace_results(events)

    assert len(formatted) == 2
    assert formatted[0]["Received"] == "2023-09-15T10:00:00Z"
    assert formatted[1]["Received"] == "2023-09-15T11:00:00Z"
    assert formatted[0]["MessageId"] == "<event-1@example.com>"
    assert formatted[1]["MessageId"] == "<event-2@example.com>"


def test_format_message_trace_results_for_dataset():
    """Test format_message_trace_results for XSIAM dataset"""
    from Office365MessageTraceEventCollector import format_message_trace_results

    events = util_load_json("./test_data/format_message_trace_results.json")

    formatted = format_message_trace_results(events, for_dataset=True)

    assert len(formatted) == 2
    assert "_time" in formatted[0]
    assert formatted[0]["_time"] == "2023-09-15T10:00:00Z"
    assert "Received" not in formatted[0]


def test_format_message_trace_results_empty_list():
    """Test format_message_trace_results with empty list"""
    from Office365MessageTraceEventCollector import format_message_trace_results

    events = []

    formatted = format_message_trace_results(events)

    assert formatted == []


def test_format_message_trace_results_missing_timestamp():
    """Test format_message_trace_results with events that may have missing fields"""
    from Office365MessageTraceEventCollector import format_message_trace_results

    events = util_load_json("./test_data/format_message_trace_results_missing_fields.json")

    formatted = format_message_trace_results(events)

    # Should include all events - function doesn't skip based on timestamps
    assert len(formatted) == 3
    assert formatted[0]["MessageId"] == "<event-1@example.com>"
    assert formatted[0]["Size"] == 0
    assert formatted[1]["MessageId"] == "<event-2@example.com>"
    assert formatted[1]["Received"] == ""  # Missing field returns empty string
    assert formatted[2]["MessageId"] == "<event-3@example.com>"


def test_format_message_trace_results_preserves_original_fields():
    """Test format_message_trace_results preserves all original event fields"""
    from Office365MessageTraceEventCollector import format_message_trace_results

    events = util_load_json("./test_data/format_message_trace_results_preserve_fields.json")

    formatted = format_message_trace_results(events)

    assert len(formatted) == 1
    assert formatted[0]["Received"] == "2023-09-15T10:00:00Z"
    assert formatted[0]["MessageId"] == "<event-1@example.com>"
    assert formatted[0]["Subject"] == "Test event"
    assert formatted[0]["Status"] == "Delivered"
    assert formatted[0]["SenderAddress"] == "sender@example.com"
    assert formatted[0]["RecipientAddress"] == "recipient@example.com"
    # Note: function only formats known fields, so CustomField won't be in output
    assert "CustomField" not in formatted[0]


@patch("Office365MessageTraceEventCollector.Client._http_request")
def test_get_events_command(mock_http_request):
    """Test get_events_command function"""
    from Office365MessageTraceEventCollector import Client, get_events

    # Mock response data
    mock_response = util_load_json("./test_data/message_trace_get_events_response.json")

    mock_http_request.return_value = mock_response

    client = Client(url=TENANT_URL, tenant_id=TENANT_ID, client_id=CLIENT_ID, client_secret=CLIENT_SECRET, verify=False)

    # Mock _get_access_token to avoid actual token request
    with patch.object(client, "_get_access_token", return_value="test_token"):
        events, new_timestamp = get_events(client=client, last_timestamp="2023-09-15T00:00:00Z", processing_delay=0)

    # Assertions
    assert len(events) == 1
    assert events[0]["MessageTraceId"] == "123456-78901-abcdef"
    assert "_time" in events[0]
    assert events[0]["_time"] == "2023-07-01T12:00:00Z"
    assert new_timestamp is not None


@patch("Office365MessageTraceEventCollector.Client._http_request")
@patch("Office365MessageTraceEventCollector.demisto")
def test_office365_message_trace_list_command(mock_demisto, mock_http_request):
    """Test office365_message_trace_list_command function"""
    from Office365MessageTraceEventCollector import Client, office365_message_trace_list_command

    # Mock response data
    mock_response = util_load_json("./test_data/message_trace_list_response.json")
    mock_http_request.return_value = mock_response

    client = Client(url=TENANT_URL, tenant_id=TENANT_ID, client_id=CLIENT_ID, client_secret=CLIENT_SECRET, verify=False)

    # Mock _get_access_token to avoid actual token request
    with patch.object(client, "_get_access_token", return_value="test_token"):
        args = {"start_date": "2023-07-01T00:00:00Z", "end_date": "2023-07-02T00:00:00Z", "limit": "100"}
        result = office365_message_trace_list_command(client, args)

    # Assertions
    assert result.outputs_prefix == "Office365.MessageTrace"
    assert result.outputs_key_field == "MessageId"
    assert isinstance(result.outputs, list)
    assert len(result.outputs) == 1
    assert result.outputs[0]["MessageId"] == "<ABC123@contoso.com>"
