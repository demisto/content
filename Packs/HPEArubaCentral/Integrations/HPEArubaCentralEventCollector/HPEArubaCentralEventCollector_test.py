from HPEArubaCentralEventCollector import main, Client
import pytest
import demistomock as demisto
from CommonServerPython import date_to_timestamp
from freezegun import freeze_time
import json

VENDOR = 'aruba'
PRODUCT = 'central'
DATE_FORMAT = '%Y-%m-%dT%H:%M:%S'
BASE_URL = 'https://server_url'
CLIENT_ID = 'test client id'
CLIENT_SECRET = 'test client secret'
USER_NAME = 'test username'
USER_PASSWORD = 'test password'
CUSTOMER_ID = 'test customer id'
TEST_TOKEN = 'testaccesstoken'
TEST_REFRESH_TOKEN = 'testrefreshtoken'
FROM_DATE = '2024-09-11T03:21:33'
FROM_TIME = int(date_to_timestamp(FROM_DATE, DATE_FORMAT) / 1000)
CSRF_TOKEN = 'testcsrftoken'
SESSION_ID = 'testsessionid'
AUTH_CODE = 'testauthcode'
FETCH_DATE = '2024-09-12T03:21:33'
FETCH_TIME = int(date_to_timestamp(FETCH_DATE, DATE_FORMAT) / 1000)
FETCH_LIMIT = 10


def util_load_json(path):
    with open(path, encoding='utf-8') as f:
        return json.loads(f.read())


def mock_instance_params(mocker, fetch_networking: bool = False):
    """
    Helper function to mock the instance parameters.

    Args:
        mocker: pytest mocker object
        fetch_networking (bool): Instance fetch_networking parameter
    """
    mocker.patch.object(demisto, 'params', return_value={
        'url': BASE_URL,
        'credentials': {
            'identifier': CLIENT_ID,
            'password': CLIENT_SECRET,
        },
        'user': {
            'identifier': USER_NAME,
            'password': USER_PASSWORD,
        },
        'customer_id': {
            'password': CUSTOMER_ID,
        },
        'fetch_networking_events': fetch_networking,
        'max_audit_events_per_fetch': FETCH_LIMIT,
        'max_networking_events_per_fetch': FETCH_LIMIT,
        'proxy': False,
        'verify': False,
    })


@freeze_time(FETCH_DATE)
@pytest.mark.parametrize('fetch_networking', [True, False])
def test_fetch_events_command(mocker, requests_mock, fetch_networking):
    """
    Given:
    - Instance params

    When:
    - Running fetch-events command

    Then:
    - Ensure events are fetched and sent to XSIAM as expected
    """
    audit_response_mock = util_load_json('test_data/mock_audit_response.json')
    networking_response_mock = util_load_json('test_data/mock_networking_response.json')
    requests_mock.get(f'{BASE_URL}/auditlogs/v1/events',
                      request_headers={'authorization': f'Bearer {TEST_TOKEN}'},
                      json=audit_response_mock)
    requests_mock.get(f'{BASE_URL}/monitoring/v2/events',
                      request_headers={'authorization': f'Bearer {TEST_TOKEN}'},
                      json=networking_response_mock)

    mocker.patch.object(demisto, 'command', return_value='fetch-events')
    mocker.patch.object(demisto, 'getLastRun', return_value={
        'last_audit_ts': FROM_TIME,
        'last_networking_ts': FROM_TIME,
    })
    mock_instance_params(mocker, fetch_networking=fetch_networking)
    mocker.patch('HPEArubaCentralEventCollector.get_integration_context', return_value={
        'access_token': TEST_TOKEN,
        'expiry_time': FETCH_TIME + 1})

    send_events_to_xsiam_mock = mocker.patch('HPEArubaCentralEventCollector.send_events_to_xsiam', return_value={})

    main()

    audit_response_mock['events'].reverse()
    expected_events = audit_response_mock['events'] if not fetch_networking else (audit_response_mock['events']
                                                                                  + networking_response_mock['events'])
    send_events_to_xsiam_mock.assert_called_once_with(expected_events,
                                                      vendor=VENDOR,
                                                      product=PRODUCT)


@freeze_time(FETCH_DATE)
def test_get_access_token(mocker, requests_mock):
    """
    Given:
    - A request to get an access token

    When:
    - No valid access token exists in the integration context

    Then:
    - Obtain a new access token by following the OAuth2 authorization code grant flow
    """
    mocker.patch.object(demisto, 'getIntegrationContext', return_value={})

    # Mock login request
    def match_login_request(request):
        return (request.qs.get('client_id')[0] == CLIENT_ID
                and request.json() == {
                    "username": USER_NAME,
                    "password": USER_PASSWORD,
        })
    requests_mock.post(f'{BASE_URL}/oauth2/authorize/central/api/login', additional_matcher=match_login_request,
                       cookies={'csrftoken': CSRF_TOKEN, 'session': SESSION_ID})

    # Mock auth code request
    def match_auth_code_request(request):
        return (request.qs.get('client_id')[0] == CLIENT_ID
                and request.qs.get('response_type')[0] == 'code'
                and request.json() == {'customer_id': CUSTOMER_ID
                                       })
    requests_mock.post(f'{BASE_URL}/oauth2/authorize/central/api', additional_matcher=match_auth_code_request,
                       request_headers={
                           'Content-Type': 'application/json',
                           'Cookie': f'session={SESSION_ID}',
                           'X-CSRF-TOKEN': CSRF_TOKEN,
                       },
                       json={'auth_code': AUTH_CODE})

    # Mock token request
    def match_token_request(request):
        return (request.json() == {
            'client_id': CLIENT_ID,
            'client_secret': CLIENT_SECRET,
            'grant_type': 'authorization_code',
            'code': AUTH_CODE,
        })
    requests_mock.post(f'{BASE_URL}/oauth2/token', additional_matcher=match_token_request,
                       json={
                           'refresh_token': TEST_REFRESH_TOKEN,
                           'token_type': 'bearer',
                           'access_token': TEST_TOKEN,
                           'expires_in': 7200,
                       })

    mocked_set_integration_context = mocker.patch('HPEArubaCentralEventCollector.set_integration_context')

    client = Client(
        base_url=BASE_URL,
        client_id=CLIENT_ID,
        client_secret=CLIENT_SECRET,
        user_name=USER_NAME,
        user_password=USER_PASSWORD,
        customer_id=CUSTOMER_ID,
    )

    assert client.get_access_token() == TEST_TOKEN

    mocked_set_integration_context.assert_called_once_with({
        'access_token': TEST_TOKEN,
        'expiry_time': FETCH_TIME + 7200,
        'refresh_token': TEST_REFRESH_TOKEN,
    })


@freeze_time(FETCH_DATE)
def test_refresh_access_token(mocker, requests_mock):
    """
    Given:
    - A request to get an access token

    When:
    - There is an expired access token in the context

    Then:
    - Refresh the access token using the refresh token
    """
    # Return an expired token from the context
    mocker.patch('HPEArubaCentralEventCollector.get_integration_context',
                 return_value={
                     'access_token': TEST_TOKEN,
                     'expiry_time': FETCH_TIME - 1,
                     'refresh_token': TEST_REFRESH_TOKEN,
                 })

    # Mock refresh request
    new_token = f'refreshed_{TEST_TOKEN}'
    new_refresh_token = f'refreshed_{TEST_REFRESH_TOKEN}'

    def match_refresh_request(request):
        expected_params = {
            'client_id': [CLIENT_ID],
            'client_secret': [CLIENT_SECRET],
            'grant_type': ['refresh_token'],
            'refresh_token': [TEST_REFRESH_TOKEN],
        }
        return request.qs == expected_params

    requests_mock.post(f'{BASE_URL}/oauth2/token', additional_matcher=match_refresh_request,
                       json={
                           'refresh_token': new_refresh_token,
                           'token_type': 'bearer',
                           'access_token': new_token,
                           'expires_in': 7200,
                       })

    mocked_set_integration_context = mocker.patch('HPEArubaCentralEventCollector.set_integration_context')

    client = Client(
        base_url=BASE_URL,
        client_id=CLIENT_ID,
        client_secret=CLIENT_SECRET,
        user_name=USER_NAME,
        user_password=USER_PASSWORD,
        customer_id=CUSTOMER_ID,
    )

    assert client.get_access_token() == new_token

    mocked_set_integration_context.assert_called_once_with({
        'access_token': new_token,
        'expiry_time': FETCH_TIME + 7200,
        'refresh_token': new_refresh_token,
    })


@freeze_time(FETCH_DATE)
def test_fetch_with_duplicates(mocker, requests_mock):
    """
    Given:
    - fetch events command

    When:
    - Some events with the same starting timestamp were previously fetched

    Then:
    - Fetched events are returned without the previously fetched ones
    """
    fetch_networking = True
    full_audit_response = util_load_json('test_data/mock_audit_response.json')
    full_networking_response = util_load_json('test_data/mock_networking_response.json')

    mocker.patch.object(demisto, 'command', return_value='fetch-events')
    mock_instance_params(mocker, fetch_networking=fetch_networking)
    mocker.patch('HPEArubaCentralEventCollector.get_integration_context', return_value={
        'access_token': TEST_TOKEN,
        'expiry_time': FETCH_TIME + 1})

    # Mock first fetch to get some of the events
    first_audit_response = full_audit_response.copy()
    first_audit_response['events'] = first_audit_response['events'][-2:]
    first_networking_response = full_networking_response.copy()
    first_networking_response['events'] = first_networking_response['events'][:2]

    requests_mock.get(f'{BASE_URL}/auditlogs/v1/events',
                      request_headers={'authorization': f'Bearer {TEST_TOKEN}'},
                      json=first_audit_response)
    requests_mock.get(f'{BASE_URL}/monitoring/v2/events',
                      request_headers={'authorization': f'Bearer {TEST_TOKEN}'},
                      json=first_networking_response)

    mocker.patch.object(demisto, 'getLastRun', return_value={})
    set_last_run_mock = mocker.patch.object(demisto, 'setLastRun')
    send_events_to_xsiam_mock = mocker.patch('HPEArubaCentralEventCollector.send_events_to_xsiam', return_value={})

    main()

    expected_audit_events = list(reversed(first_audit_response['events']))
    expected_networking_events = first_networking_response['events']
    send_events_to_xsiam_mock.assert_called_once_with(expected_audit_events + expected_networking_events,
                                                      vendor=VENDOR,
                                                      product=PRODUCT)

    # Mock next fetch to get all of the events, including the previously fetched
    requests_mock.get(f'{BASE_URL}/auditlogs/v1/events',
                      request_headers={'authorization': f'Bearer {TEST_TOKEN}'},
                      json=full_audit_response)
    requests_mock.get(f'{BASE_URL}/monitoring/v2/events',
                      request_headers={'authorization': f'Bearer {TEST_TOKEN}'},
                      json=full_networking_response)

    mocker.patch.object(demisto, 'getLastRun', return_value=set_last_run_mock.call_args[0][0])
    send_events_to_xsiam_mock = mocker.patch('HPEArubaCentralEventCollector.send_events_to_xsiam', return_value={})

    main()

    expected_audit_events = list(reversed(full_audit_response['events'][:-2]))
    expected_networking_events = full_networking_response['events'][2:]
    send_events_to_xsiam_mock.assert_called_once_with(expected_audit_events + expected_networking_events,
                                                      vendor=VENDOR,
                                                      product=PRODUCT)


@pytest.mark.parametrize('should_fail', [True, False])
def test_test_module(mocker, should_fail):
    """
    Given:
    - test module command

    When:
    - Pressing test button

    Then:
    - Test module passed
    """
    mocker.patch.object(demisto, 'command', return_value='test-module')
    mock_instance_params(mocker)

    if should_fail:
        mocker.patch('HPEArubaCentralEventCollector.fetch_events',
                     side_effect=Exception('401 - Unauthorized access, authentication required'))
    else:
        mocker.patch('HPEArubaCentralEventCollector.fetch_events', return_value=({}, [], []))

    if should_fail:
        return_error_mock = mocker.patch('HPEArubaCentralEventCollector.return_error')
        main()
        return_error_mock.assert_called()

    else:
        return_results_mock = mocker.patch('HPEArubaCentralEventCollector.return_results')
        main()
        return_results_mock.assert_called_once_with('ok')


@freeze_time(FETCH_DATE)
@pytest.mark.parametrize('fetch_networking, should_push_events', [(True, True), (False, False), (True, False), (False, True)])
def test_get_events_command(mocker, requests_mock, fetch_networking, should_push_events):
    """
    Given:
    - Instance params and command args

    When:
    - Running the get events command

    Then:
    - Events are fetched and HR is returned. Events are pushed to XSIAM if should_push_events is true.
    """
    audit_response_mock = util_load_json('test_data/mock_audit_response.json')
    networking_response_mock = util_load_json('test_data/mock_networking_response.json')
    requests_mock.get(f'{BASE_URL}/auditlogs/v1/events',
                      request_headers={'authorization': f'Bearer {TEST_TOKEN}'},
                      json=audit_response_mock)
    requests_mock.get(f'{BASE_URL}/monitoring/v2/events',
                      request_headers={'authorization': f'Bearer {TEST_TOKEN}'},
                      json=networking_response_mock)
    mocker.patch.object(demisto, 'command', return_value='aruba-central-get-events')
    mock_instance_params(mocker, fetch_networking=fetch_networking)
    mocker.patch.object(demisto, 'args', return_value={
        'should_push_events': should_push_events,
        'limit': FETCH_LIMIT,
        'from_date': FROM_DATE,
    })
    mocker.patch('HPEArubaCentralEventCollector.get_integration_context', return_value={
        'access_token': TEST_TOKEN,
        'expiry_time': FETCH_TIME + 1})

    send_events_to_xsiam_mock = mocker.patch('HPEArubaCentralEventCollector.send_events_to_xsiam', return_value={})
    return_results_mock = mocker.patch('HPEArubaCentralEventCollector.return_results')

    main()

    return_results_mock.assert_called()
    if fetch_networking:
        assert len(return_results_mock.call_args.args[0]) == 2
    else:
        assert len(return_results_mock.call_args.args[0]) == 1

    if should_push_events:
        audit_response_mock['events'].reverse()
        expected_events = audit_response_mock['events'] if not fetch_networking else (audit_response_mock['events']
                                                                                      + networking_response_mock['events'])
        send_events_to_xsiam_mock.assert_called_once_with(expected_events,
                                                          vendor=VENDOR,
                                                          product=PRODUCT)
    else:
        send_events_to_xsiam_mock.assert_not_called()
