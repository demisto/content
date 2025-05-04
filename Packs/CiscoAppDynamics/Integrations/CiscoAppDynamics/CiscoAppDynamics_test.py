import CiscoAppDynamics
import pytest
import demistomock as demisto
from datetime import datetime, timedelta, UTC
from CiscoAppDynamics import (
    Client,
    fetch_events,
    get_max_event_time,
    create_empty_last_run,
    main,
    AUDIT,
    HEALTH_EVENT,
    DATE_FORMAT
)


@pytest.fixture
def client(mocker):
    """
    Fixture to create a Client instance with patched _http_request.
    Returns a client with default fetch limits for audit and health events.
    """
    client = Client(
        base_url="https://example.com",
        client_id="id",
        client_secret="secret",
        application_id="app",
        max_audit_fetch=3,
        max_healthrule_fetch=3,
        verify=False,
        proxy=False,
    )
    mocker.patch.object(client, "_http_request")
    return client

def test_create_access_token(client:Client):
    """
    Given
        - A patched _http_request that returns a valid OAuth response.
    When
        - create_access_token is called.
    Then
        - client.token is set to the returned access_token.
        - client.token_expiry is set to a future datetime.
    """
    mock_response = {"access_token": "fake-token",
                     "expires_in": 600}
    client._http_request.return_value = mock_response

    client.create_access_token()

    assert client.token == "fake-token"
    assert client.token_expiry > datetime.now(UTC)
    
    
    
@pytest.mark.parametrize("token, expiry_offset_minutes, should_create_new", [
    (None, None, True),
    ("valid-token", 10, False),
    ("expired-token", -1, True),
])
def test_get_valid_token(client, mocker, token, expiry_offset_minutes, should_create_new):
    """
    Given
        - Various token and expiry setups.
    When
        - _get_valid_token is called.
    Then
        - Returns new token if missing or expired.
        - Returns existing token if still valid.
    """
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
        


def test_error_creating_token(requests_mock, mocker):
    """
    Given
      - The auth (token) endpoint returns 401 Unauthorized.
    When
      - the user runs `!test-module`.
    Then
      - main() should catch that and invoke return_error with the 401 message.
    """
    mocker.patch.object(CiscoAppDynamics.demisto, 'command', return_value='test-module')
    mocker.patch.object(CiscoAppDynamics.demisto, 'params', return_value={
        'url': 'https://example.com',
    })

    return_error_mock = mocker.patch('CiscoAppDynamics.return_error')

    auth_url = 'https://example.com/controller/api/oauth/access_token'
    requests_mock.post(auth_url, status_code=401, json={'message': 'Unauthorized'})

    main()

    return_error_mock.assert_called_once()

    

@pytest.mark.parametrize("api_response, expected_count", [
    ([  # More than max_audit_fetch
        {"timeStamp": 1700000000000},
        {"timeStamp": 1700000001000},
        {"timeStamp": 1700000002000},
        {"timeStamp": 1700000003000},
    ], 3),
    ([  # Less than max_audit_fetch
        {"timeStamp": 1700000004000},
    ], 1),
    ([  # Empty list
    ], 0),
])
def test_get_audit_logs_various_cases(client, mocker, api_response, expected_count):
    """
    Given
        - get_audit_logs returns different sized lists via _authorized_request.
        Case:
        1. API return more then the max_audit_fetch.
        2. API return less then the max_audit_fetch.
        3. API return no logs.
    When
        - get_audit_logs is called.
    Then
        - Returns at most max_audit_fetch events.
    """
    mocker.patch.object(client, '_authorized_request', return_value=api_response)

    start = datetime.now(UTC) - timedelta(hours=1)
    end = datetime.now(UTC)

    events = client.get_audit_logs(start, end)
    assert len(events) == expected_count




@pytest.mark.parametrize("start_delta_hours, expected_start_delta", [
    (12, 12),       # Within 24h, unchanged
    (24, 24),       # Exactly 24h, unchanged
    (30, 24),       # More than 24h, clamped to 24
])
def test_get_audit_logs_respects_24h_limit(client,start_delta_hours, expected_start_delta, mocker):
    """
    Given
        - The start time is more/less/equal than 24 hours before the end time.
    When
        - get_audit_logs is called.
    Then
        - The start time is clamped to maximum 24 hours before the end time.
        - The API call to _authorized_request uses the corrected time window.
    """
    end_dt = datetime(2025, 5, 4, 12, 0, 0, tzinfo=UTC)
    original_start_dt = end_dt - timedelta(hours=start_delta_hours)
    expected_start_dt = end_dt - timedelta(hours=expected_start_delta)

    mocker.patch.object(client, "_authorized_request", return_value=[{"dummy": "event"}])

    client.get_audit_logs(original_start_dt, end_dt)

   # Assert
    expected_params = {
        "startTime": expected_start_dt.strftime(DATE_FORMAT)[:-3] + 'Z',
        "endTime": end_dt.strftime(DATE_FORMAT)[:-3] + 'Z'
    }

    client._authorized_request.assert_called_once_with(
        url_suffix="/controller/ControllerAuditHistory",
        params=expected_params
    )


@pytest.mark.parametrize("api_response, expected_count", [
    ([  # More than max_healthrule_fetch
        {"detectedTimeInMillis": 1700000000000},
        {"detectedTimeInMillis": 1700000001000},
        {"detectedTimeInMillis": 1700000002000},
        {"detectedTimeInMillis": 1700000003000},
    ], 3),
    ([  # Less than max_healthrule_fetch
        {"detectedTimeInMillis": 1700000004000},
    ], 1),
    ([  # Empty list
    ], 0),
])

def test_get_health_events_various_cases(client, mocker, api_response, expected_count):
    """
    Given
        - get_health_events returns different sized lists via _authorized_request.
        Case:
        1. API return more then the max_healthrule_fetch.
        2. API return less then the max_healthrule_fetch.
        3. API return no logs.
    When
        - get_health_events is invoked with start and end datetimes.
    Then
        - Returns at most max_healthrule_fetch events.
    """
    mocker.patch.object(client, '_authorized_request', return_value=api_response)

    start = datetime.now(UTC) - timedelta(hours=1)
    end = datetime.now(UTC)

    events = client.get_health_events(start, end)

    assert len(events) == expected_count



def test_get_health_events_multi_calls(client, mocker):
    """
    Given
        - get_health_events returns HEALTH_RULE_API_LIMIT events via _authorized_request every time.
    When
        - We need to fetch multi time using the API because more events than the the API can return
        happened and less then the total we made.
    Then
        - Returns max_healthrule_fetch events.
        - Call _authorized_request twice.
    """
    mocker.patch.object(CiscoAppDynamics, 'HEALTH_RULE_API_LIMIT', 2)
    api_response = [{"detectedTimeInMillis": 1700000000000},
                    {"detectedTimeInMillis": 1700000001000}]
    mocker.patch.object(client, '_authorized_request', return_value=api_response)

    start = datetime.now(UTC) - timedelta(hours=1)
    end = datetime.now(UTC)

    events = client.get_health_events(start, end)

    assert client._authorized_request.call_count == 2
    assert len(events) == 3
    
def test_fetch_events(client, mocker):
    """
    Given
        - Combined audit and health event lists from client.
    When
        - fetch_events is called with last_run timestamps.
    Then
        - Merges and enriches events correctly.
        - next_run dict has new high-water marks.
    """
    now = datetime.now(UTC)
    last_run = {
        "Audit": now - timedelta(minutes=5),
        "Healthrule Violations Events": now - timedelta(minutes=5)
    }

    audit_return = [{"timeStamp": int(now.timestamp() * 1000)}]
    health_return = [{"detectedTimeInMillis": int(now.timestamp() * 1000)}]
    mocker.patch.object(client, 'get_audit_logs', return_value=audit_return)
    mocker.patch.object(client, 'get_health_events', return_value=health_return)


    events, next_run = fetch_events(client, last_run, ["Audit", "Healthrule Violations Events"])

    assert len(events) == 2
    assert next_run["Audit"] is not None
    assert next_run["Healthrule Violations Events"] is not None
    

def test_get_max_event_time():
    """
    Given
        - A list of events with detectedTimeInMillis values.
    When
        - get_max_event_time is called.
    Then
        - Returns the correct datetime of the max timestamp.
    """
    now = datetime.now(UTC)
    events = [
        {"detectedTimeInMillis": int(now.timestamp() * 1000)},
        {"detectedTimeInMillis": int((now.timestamp() - 1) * 1000)},
        {"detectedTimeInMillis": int((now.timestamp() - 2) * 1000)},
    ]

    result = get_max_event_time(events, "Healthrule Violations Events")

    expected_max = int(now.timestamp() * 1000)
    expected_datetime = datetime.fromtimestamp(expected_max / 1000, tz=UTC)

    assert isinstance(result, datetime)
    assert result == expected_datetime
    
def test_create_empty_last_run():
    """
    Given
        - A current datetime.
    When
        - create_empty_last_run is called.
    Then
        - Both AUDIT and HEALTH_EVENT keys map to that datetime.
    """
    now = datetime.now(UTC)
    last_run = create_empty_last_run(now)
    start_time = now + timedelta(minutes=-1)
    assert "Audit" in last_run
    assert "Healthrule Violations Events" in last_run
    assert last_run["Audit"] == start_time
    assert last_run["Healthrule Violations Events"] == start_time
    



@pytest.mark.parametrize("type_to_fetch, excepted_url", [
    (AUDIT, 'https://example.com/controller/ControllerAuditHistory'),
    (HEALTH_EVENT, 'https://example.com/controller/rest/applications/app_id/problems/healthrule-violations'),
])
def test_error_audit_logs_main(type_to_fetch, excepted_url, requests_mock, mocker):
    """
    Given
      - OAuth token endpoint returns 200 with a valid token.
      - Audit‐history endpoint returns HTTP 500.
    When
      - main() is invoked with command 'fetch-events'.
    Then
      - return_error is called once with the 500 error text.
    """
    mocker.patch.object(demisto, 'command', return_value='fetch-events')
    mocker.patch.object(demisto, 'params', return_value={
        'url': 'https://example.com',
        'application_id': 'app_id',
        'events_type_to_fetch': [type_to_fetch],
    })
    mocker.patch.object(demisto, 'getLastRun', return_value={})

    return_error_mock = mocker.patch("CiscoAppDynamics.return_error")

    
    fake_token = {"access_token": "fake-token",
                  "expires_in": 600}
    
    mocker.patch.object(Client, '_get_valid_token',return_value=fake_token)

    requests_mock.get(excepted_url,
                      status_code=500,
                      text='Internal Server Error')

    main()
    
    return_error_mock.assert_called_once()
    assert "Internal Server Error" in return_error_mock.call_args[0][0]
