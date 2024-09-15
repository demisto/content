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
CSRF_TOKEN = 'testcsrftoken'
SESSION_ID = 'testsessionid'
AUTH_CODE = 'testauthcode'
FETCH_TIME = int(date_to_timestamp(FROM_DATE, DATE_FORMAT) / 1000)
FETCH_LIMIT = 10


def util_load_json(path):
    with open(path, encoding='utf-8') as f:
        return json.loads(f.read())


def mock_instance_params(mocker, fetch_networking: bool = False):
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


@freeze_time(FROM_DATE)
@pytest.mark.parametrize('fetch_networking', [True, False])
def test_fetch_events_command(mocker, requests_mock, fetch_networking):
    """
    Given:
    - fetch events command

    When:
    - Running fetch-events command

    Then:
    - Ensure number of events fetched, and next run fields
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
    mocker.patch.object(demisto, 'getLastRun', return_value={})
    mock_instance_params(mocker, fetch_networking=fetch_networking)
    mocker.patch('HPEArubaCentralEventCollector.get_integration_context', return_value={
        'access_token': TEST_TOKEN,
        'expiry_time': FETCH_TIME + 1})

    send_events_to_xsiam_mock = mocker.patch('HPEArubaCentralEventCollector.send_events_to_xsiam', return_value={})

    main()

    audit_response_mock['events'].reverse()
    send_events_to_xsiam_mock.assert_any_call(audit_response_mock['events'],
                                              vendor=VENDOR,
                                              product=PRODUCT)
    if fetch_networking:
        send_events_to_xsiam_mock.assert_any_call(networking_response_mock['events'],
                                                  vendor=VENDOR,
                                                  product=f'{PRODUCT}_network_events')


@freeze_time(FROM_DATE)
def test_get_access_token(mocker, requests_mock):

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

    setContextMock = mocker.patch('HPEArubaCentralEventCollector.set_integration_context')

    client = Client(
        base_url=BASE_URL,
        client_id=CLIENT_ID,
        client_secret=CLIENT_SECRET,
        user_name=USER_NAME,
        user_password=USER_PASSWORD,
        customer_id=CUSTOMER_ID,
    )

    assert client.get_access_token() == TEST_TOKEN

    setContextMock.assert_called_once_with({
        'access_token': TEST_TOKEN,
        'expiry_time': FETCH_TIME + 7200,
        'refresh_token': TEST_REFRESH_TOKEN,
    })


@pytest.mark.skip()
def test_refresh_access_token():
    return


@pytest.mark.skip()
def test_fetch_with_duplicates():
    return


@pytest.mark.parametrize('should_fail', [True, False])
def test_test_module(mocker, should_fail):
    """
    Given:
    - test module command (fetches detections)

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


@freeze_time(FROM_DATE)
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
        send_events_to_xsiam_mock.assert_any_call(audit_response_mock['events'],
                                                  vendor=VENDOR,
                                                  product=PRODUCT)
        if fetch_networking:
            send_events_to_xsiam_mock.assert_any_call(networking_response_mock['events'],
                                                      vendor=VENDOR,
                                                      product=f'{PRODUCT}_network_events')
    else:
        send_events_to_xsiam_mock.assert_not_called()
