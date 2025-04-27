from CiscoAppDynamics import Client, fetch_events, get_max_event_time, create_empty_last_run
import pytest
from datetime import datetime, timedelta, UTC




@pytest.fixture
def client(mocker):
    client = Client(
        base_url="some-url",
        client_id="id",
        client_secret="secret",
        application_id="app",
        max_audit_fetch=2,
        max_healthrule_fetch=2,
        verify=False,
        proxy=False,
    )
    mocker.patch.object(client, "_http_request")
    return client

def test_create_access_token(client:Client):
    mock_response = {"access_token": "fake-token", "expires_in": 600}
    client._http_request.return_value = mock_response

    client.create_access_token()

    assert client.token == "fake-token"
    assert client.token_expiry > datetime.now(UTC)
    
@pytest.mark.parametrize("token, expiry_offset_minutes, should_create_new", [
    (None, None, True),              # No token at all --> should create new
    ("valid-token", 10, False),       # Valid token (expiry in 10 minutes) --> should reuse
    ("expired-token", -1, True),      # Expired token (expiry 1 minute ago) --> should create new
])
def test_get_valid_token(client, mocker, token, expiry_offset_minutes, should_create_new):
    
    client.token = token
    if expiry_offset_minutes is not None:
        client.token_expiry = datetime.now(UTC) + timedelta(minutes=expiry_offset_minutes)
    else:
        client.token_expiry = None

    mock_create = mocker.patch.object(client, 'create_access_token', return_value="new-token")

    result_token = client._get_valid_token()

    if should_create_new:
        mock_create.assert_called_once()
        assert result_token == "new-token"
    else:
        mock_create.assert_not_called()
        assert result_token == token
    

@pytest.mark.parametrize("api_response, expected_count", [
    ([  # More than max_audit_fetch
        {"timeStamp": 1700000000000},
        {"timeStamp": 1700000001000},
        {"timeStamp": 1700000002000},
        {"timeStamp": 1700000003000},
    ], 2),
    ([  # Less than max_audit_fetch
        {"timeStamp": 1700000004000},
    ], 1),
    ([  # Empty list
    ], 0),
])
def test_get_audit_logs_various_cases(client, mocker, api_response, expected_count):
    """Test get_audit_logs with different API responses."""
    
    # Mock _authorized_request to return the api_response
    mocker.patch.object(client, '_authorized_request', return_value=api_response)

    # Define start and end times
    start = datetime.now(UTC) - timedelta(hours=1)
    end = datetime.now(UTC)

    # Call the function
    events = client.get_audit_logs(start, end)

    # Assertions
    assert isinstance(events, list)
    assert len(events) == expected_count
    if expected_count > 0:
        assert all("timeStamp" in ev for ev in events)
    

@pytest.mark.parametrize("api_response, expected_count", [
    ([  # More than max_healthrule_fetch
        {"detectedTimeInMillis": 1700000000000},
        {"detectedTimeInMillis": 1700000001000},
        {"detectedTimeInMillis": 1700000002000},
        {"detectedTimeInMillis": 1700000003000},
    ], 2),
    ([  # Less than max_healthrule_fetch
        {"detectedTimeInMillis": 1700000004000},
    ], 1),
    ([  # Empty list
    ], 0),
])
def test_get_health_events_various_cases(client, mocker, api_response, expected_count):
    """Test get_health_events with different API responses."""

    # Mock _authorized_request to return a different batch each call
    mocker.patch.object(client, '_authorized_request', return_value=api_response)

    start = datetime.now(UTC) - timedelta(hours=1)
    end = datetime.now(UTC)

    # Call the function
    events = client.get_health_events(start, end)

    # Assertions
    assert isinstance(events, list)
    assert len(events) == expected_count
    if expected_count > 0:
        assert all("detectedTimeInMillis" in ev for ev in events)
    
def test_fetch_events(client):
    now = datetime.now(UTC)
    last_run = {
        "Audit": now - timedelta(minutes=5),
        "Healthrule Violations Events": now - timedelta(minutes=5)
    }

    mock_audit = [{"timeStamp": int(now.timestamp() * 1000)}]
    mock_health = [{"detectedTimeInMillis": int(now.timestamp() * 1000)}]

    client.get_audit_logs = lambda start, end: mock_audit
    client.get_health_events = lambda start, end: mock_health

    events, next_run = fetch_events(client, last_run, ["Audit", "Healthrule Violations Events"])

    assert len(events) == 2
    assert next_run["Audit"] is not None
    assert next_run["Healthrule Violations Events"] is not None
    

def test_get_max_event_time():
    now = datetime.now(UTC)
    events = [
        {"detectedTimeInMillis": int(now.timestamp() * 1000)},
        {"detectedTimeInMillis": int((now.timestamp() - 1) * 1000)},
        {"detectedTimeInMillis": int((now.timestamp() - 2) * 1000)},
    ]

    result = get_max_event_time(events, "Healthrule Violations Events", now)

    expected_max = int(now.timestamp() * 1000)
    expected_datetime = datetime.fromtimestamp(expected_max / 1000, tz=UTC)

    assert isinstance(result, datetime)
    assert result == expected_datetime
    
def test_create_empty_last_run():
    now = datetime.now(UTC)
    last_run = create_empty_last_run(now)

    assert "Audit" in last_run
    assert "Healthrule Violations Events" in last_run
    assert last_run["Audit"] == now
    assert last_run["Healthrule Violations Events"] == now