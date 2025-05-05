import pytest

from GoogleApigeeEventCollector import (
    Client,
    fetch_events,
    get_events_command,
)


def mock_client(mocker):
    client = Client(base_url='https://test.com', verify=False, proxy=False, org_name='org', username='user',
                    password='password', zone='zone')
    mocker.patch.object(Client, 'get_access_token', return_value={'access_token': 'access_token'})
    mocker.patch.object(Client, 'generate_data_with_username', return_value={'grant_type': 'password', 'username': 'user',
                                                                         'password': 'password',})
    mocker.patch.object(Client, 'generate_data_with_refresh_token', return_value={'grant_type': 'refresh_token',
                                                                                 'refresh_token': 'valid'})
    mocker.patch.object(Client, '_http_request', return_value={'access_token': 'access_token', 'expires_in': 3600,
                                                               'refresh_token': 'refresh_token'})
    return client


def test_get_events_command(requests_mock, mocker):
    """
    Tests google-apigee-get-events command function.
    Checks the output of the command function with the expected output.
    """
    client = mock_client(mocker)
    mock_response = {
        'auditRecord': [generate_mocked_event(13), generate_mocked_event(15)],
        'total_count': 2,
    }
    args = {
        'from_date': 3,
        'limit': 2,
    }
    requests_mock.get(f'https://test.com/v1/audits/organizations/{client.org_name}', json=mock_response)
    events, _ = get_events_command(client, args)

    assert len(events) == mock_response.get('total_count')
    assert events == mock_response.get('auditRecord')


def generate_mocked_event(event_time: int):
    return {
        'operation': 'OPER',
        'requestUri': 'some/uri',
        'responseCode': '200',
        'timeStamp': event_time,
        'user': 'user'
    }


@pytest.mark.parametrize(
    'scenario, last_fetch, limit, events_amount, events_per_time, new_events_amount, last_event_time, events_size',
    [
        (
            'get all events between the timespan',  # scenario
            1,  # last_fetch
            7,  # limit
            0,  # events_amount
            [9, 9, 8, 7, 6, 5, 2],  # events_per_time,
            2,  # new_events_amount
            9,  # last_event_time
            7,  # events_size
        ),
        (
            'get all events between the timespan and limit > fetched_events',  # scenario
            1,  # last_fetch
            10,  # limit
            0,  # events_amount
            [9, 9, 8, 7, 6, 5, 2],  # events_per_time,
            0,  # new_events_amount
            9,  # last_event_time
            7,  # events_size
        ),
        (
            'testing starting from a timestamp where we already have existing events in the last fetch',  # scenario
            2,  # last_fetch
            3,  # limit
            3,  # events_amount
            [55, 8, 7, 2, 2, 2],  # events_per_time
            1,  # new_events_amount
            55,  # last_event_time
            3,  # events_size
        ),
        (
            'all events were already fetched',  # scenario
            9,  # last_fetch
            3,  # limit
            3,  # events_amount
            [9, 9, 9],  # events_per_time
            0,  # new_events_amount
            0,  # last_event_time
            0,  # events_size
        ),
        (
            'fetch more than limit',  # scenario
            1,  # last_fetch
            3,  # limit
            0,  # events_amount
            [9, 8, 7, 6, 5, 2],  # events_per_time
            1,  # new_events_amount
            6,  # last_event_time
            3,  # events_size
        ),
        (
            'fetch multiple events at the same time',  # scenario
            1,  # last_fetch
            5,  # limit
            0,  # events_amount
            [8, 8, 8, 8, 5, 2],  # events_per_time
            3,  # new_events_amount
            8,  # last_event_time
            5,  # events_size
        ),
        (
            'there is no logs',  # scenario
            1,  # last_fetch
            5,  # limit
            0,  # events_amount
            [],  # events_per_time
            0,  # new_events_amount
            0,  # last_event_time
            0,  # events_size
        ),
    ]
)
def test_fetch_events(mocker, scenario, last_fetch, limit, events_amount, events_per_time, new_events_amount,
                      last_event_time, events_size):
    """
    Tests fetch-events command function.
    Checks the output of the command function with the expected output.
    """
    def mock_get_logs(from_date, to_time):
        events = [generate_mocked_event(event_time) for event_time in events_per_time]
        return {
            'auditRecord': events,
            'total_count': len(events),
        }

    mocked_client = mocker.Mock()
    mocked_client.get_logs.side_effect = mock_get_logs
    mocked_client.max_fetch = limit

    last_run = {'last_fetch_events_amount': events_amount, 'last_fetch_timestamp': last_fetch}
    next_run, events = fetch_events(
        client=mocked_client,
        last_run=last_run,
        limit=limit
    )

    assert len(events) == events_size
    assert next_run.get(
        'last_fetch_events_amount') == new_events_amount, f'{scenario} - set last run does not match expected value'
    if events:
        assert events[0].get('timeStamp') == last_event_time
        assert events[-1].get('timeStamp') >= last_fetch


def test_test_module(requests_mock, mocker):
    """
    Tests test-module command function.
    Checks the output of the command function with the expected output.
    """
    from GoogleApigeeEventCollector import test_module
    client = mock_client(mocker)
    requests_mock.get(f'https://test.com/v1/audits/organizations/{client.org_name}', json={})
    res = test_module(client)

    assert res == 'ok'


@pytest.mark.parametrize(
    'scenario, token_initiate_time, token_expiration_seconds, current_time, result',
    [
        (
            'valid token',  # scenario
            120,  # token_initiate_time
            400,  # token_expiration_seconds
            140,  # current_time
            True  # result
        ),
        (
            'invalid token',  # scenario
            120,  # token_initiate_time
            100,  # token_expiration_seconds
            300,  # current_time
            False  # result
        ),
    ]
)
def test_is_token_valid(mocker, scenario, token_initiate_time, token_expiration_seconds, current_time, result):
    is_token_valid = Client.is_token_valid(token_initiate_time, token_expiration_seconds, current_time)
    assert is_token_valid == result, f'{scenario} - does not match expected value'

def test_get_token_with_username(mocker):
    """
    Given:
        - A mock client configured with username and password credentials.
    When:
        - Calling `get_token_request` to retrieve an access token.
    Then:
        - Ensure the HTTP request is made with the correct method, URL, headers, and body.
        - Verify the returned access_token, expires_in, and refresh_token values.
    """
    client = mock_client(mocker)
    spy_http = mocker.spy(Client, '_http_request')
    access_token, expires_in, refresh_token = client.get_token_request()
    assert access_token == 'access_token'
    assert expires_in == 3600
    assert refresh_token == 'refresh_token'
    args = spy_http.call_args
    assert args[0] == ('POST',)
    assert args[1] == {'full_url': 'https://zone.login.apigee.com/oauth/token',
                       'url_suffix': '/oauth/token',
                       'data': {'grant_type': 'password', 'username': 'user', 'password': 'password'},
                       'headers': {'Content-Type': 'application/x-www-form-urlencoded;charset=utf-8',
                                   'Accept': 'application/json;charset=utf-8',
                                   'Authorization': 'Basic ZWRnZWNsaTplZGdlY2xpc2VjcmV0'}}
    
def test_get_token_with_valid_refresh_token(mocker):
    """
    Given:
        - A mock client configured to use a refresh token.
    When:
        - Calling `get_token_request` with a valid refresh token.
    Then:
        - Ensure the HTTP request is sent as a POST to the correct URL.
        - Confirm the payload includes the proper grant type and refresh token.
        - Verify the expected access_token, expires_in, and refresh_token are returned.
    """
    client = mock_client(mocker)
    spy_http = mocker.spy(Client, '_http_request')
    access_token, expires_in, refresh_token = client.get_token_request(refresh_token = 'token')
    assert access_token == 'access_token'
    assert expires_in == 3600
    assert refresh_token == 'refresh_token'
    
    args = spy_http.call_args
    assert args[0] == ('POST',)
    assert args[1] == {'full_url': 'https://zone.login.apigee.com/oauth/token',
                       'url_suffix': '/oauth/token',
                       'data': {'grant_type': 'refresh_token', 'refresh_token': 'valid'},
                       'headers': {'Content-Type': 'application/x-www-form-urlencoded;charset=utf-8',
                                   'Accept': 'application/json;charset=utf-8',
                                   'Authorization': 'Basic ZWRnZWNsaTplZGdlY2xpc2VjcmV0'}}

def test_get_token_with_invalid_refresh_token(mocker):
    """
    Given:
        - A mock client configured to use a refresh token.
    When:
        - Calling `get_token_request` with an invalid refresh token that triggers an exception.
    Then:
        - The client should retry the request using the password grant type.
        - Ensure the first HTTP request uses the refresh token grant type with the correct payload.
        - Ensure the second HTTP request uses the password grant type with the correct credentials.
        - Verify that the final response includes the expected access_token, expires_in, and refresh_token.
    """
    client = mock_client(mocker)
    http_mock = mocker.patch.object(Client, '_http_request', side_effect=[Exception('Invalid refresh token'),
                                                                          {'access_token': 'access_token', 'expires_in': 3600,
                                                                           'refresh_token': 'refresh_token'}])
    access_token, expires_in, refresh_token = client.get_token_request(refresh_token='invalid')
    
    assert http_mock.call_count == 2
    first_call = http_mock.call_args_list[0]
    second_call = http_mock.call_args_list[1]
    
    # Inspecting the first call
    assert first_call[0] == ('POST',)
    assert first_call[1]['data']['grant_type'] == 'refresh_token'
    assert first_call[1]['data']['refresh_token'] == 'valid'

    # Inspecting the second call
    assert second_call[0] == ('POST',)
    assert second_call[1]['data']['grant_type'] == 'password'
    assert second_call[1]['data']['username'] == 'user'
    assert second_call[1]['data']['password'] == 'password'
    
    assert access_token == 'access_token'
    assert expires_in == 3600
    assert refresh_token == 'refresh_token'