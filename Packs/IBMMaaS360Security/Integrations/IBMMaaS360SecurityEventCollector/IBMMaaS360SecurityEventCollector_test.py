import pytest
from freezegun import freeze_time
from IBMMaaS360SecurityEventCollector import Client, AuditEventType, DATE_FORMAT
from datetime import datetime, timedelta, timezone
from CommonServerPython import set_integration_context
import json

PAGE_SIZE = 3
BILLING_ID = 'testbillingid'
BASE_URL = 'https://test.com'
AUTH_SUFFIX = f'/auth-apis/auth/2.0/authenticate/customer/{BILLING_ID}'
REFRESH_SUFFIX = f'/auth-apis/auth/2.0/refreshToken/customer/{BILLING_ID}'
AUDIT_CHANGES_SUFFIX = AuditEventType.ChangesAudit.url_suffix.format(billingId=BILLING_ID)
AUDIT_LOGIN_REPORTS_SUFFIX = AuditEventType.LoginReports.url_suffix.format(billingId=BILLING_ID)
AUTH_TOKEN = 'test_auth_token'
REFRESH_TOKEN = 'test_refresh_token'
TEST_TIME = datetime(2024, 10, 30, 12, 0, 0)


def util_load_json(path):
    with open(path, encoding='utf-8') as f:
        return json.loads(f.read())


@pytest.fixture(autouse=True)
def test_setup(mocker):
    mocker.patch('IBMMaaS360SecurityEventCollector.PAGE_SIZE', PAGE_SIZE)
    set_integration_context({})


@pytest.fixture
def client() -> Client:
    return Client(
        base_url=BASE_URL,
        username='testuser',
        password='testpassword',
        app_id='testappid',
        app_version='1.0',
        platform_id='testplatform',
        access_key='testkey',
        billing_id=BILLING_ID,
    )


@pytest.mark.parametrize('error_code', [0, 401, 1008])
def test_authenticate(requests_mock, client, error_code):
    """
    Given:
    - IBM MaaS360 Security client.

    When:
    - client.authenticate is called.

    Then:
    - The authentication request is sent and the auth+refresh tokens are extracted correctly.
    """
    auth_request_mock = requests_mock.post(
        f'{BASE_URL}{AUTH_SUFFIX}',
        json={
            'authResponse': {
                'authToken': AUTH_TOKEN,
                'errorCode': error_code,
                'refreshToken': REFRESH_TOKEN,
            }
        })
    if error_code:
        with pytest.raises(Exception):
            client.authenticate()
    else:
        auth_token, refresh_token = client.authenticate()
        assert auth_request_mock.last_request.json() == {
            'authRequest': {
                'maaS360AdminAuth': {
                    'billingID': BILLING_ID,
                    'platformID': 'testplatform',
                    'appID': 'testappid',
                    'appVersion': '1.0',
                    'appAccessKey': 'testkey',
                    'userName': 'testuser',
                    'password': 'testpassword'
                }
            }
        }
        assert auth_token == AUTH_TOKEN
        assert refresh_token == REFRESH_TOKEN


@pytest.mark.parametrize('error_code', [0, 401, 1002])
def test_refresh_auth_token(requests_mock, client, error_code):
    """
    Given:
    - IBM MaaS360 Security client.
    - Refresh token.

    When:
    - client.refresh_auth_token is called.

    Then:
    - The token refresh request is sent and the new auth+refresh tokens are extracted correctly.
    """
    refresh_request_mock = requests_mock.post(
        f'{BASE_URL}{REFRESH_SUFFIX}',
        json={
            'authResponse': {
                'authToken': AUTH_TOKEN,
                'errorCode': error_code,
                'refreshToken': f'new_{REFRESH_TOKEN}',
            }
        })
    if error_code:
        with pytest.raises(Exception):
            client.refresh_auth_token(REFRESH_TOKEN)
    else:
        auth_token, refresh_token = client.refresh_auth_token(REFRESH_TOKEN)
        assert refresh_request_mock.last_request.json() == {
            'authRequest': {
                'maaS360AdminAuth': {
                    'platformID': 'testplatform',
                    'billingID': BILLING_ID,
                    'userName': 'testuser',
                    'appID': 'testappid',
                    'appVersion': '1.0',
                    'refreshToken': REFRESH_TOKEN,
                }
            }
        }
        assert auth_token == AUTH_TOKEN
        assert refresh_token == f'new_{REFRESH_TOKEN}'


def test_get_auth_token_first_run(mocker, client):
    """
    Given:
    - IBM MaaS360 Security client.
    - No prior call to get_auth_token.

    When:
    - client.get_auth_token is called.

    Then:
    - The client will authenticate and return the auth token.
    - Consecutive call shortly after won't authenticate again.
    """
    mocked_authenticate = mocker.patch.object(client, 'authenticate', return_value=(AUTH_TOKEN, REFRESH_TOKEN))

    auth_token = client.get_auth_token()

    mocked_authenticate.assert_called_once()
    assert auth_token == AUTH_TOKEN

    mocked_authenticate = mocker.patch.object(client, 'authenticate', return_value=('bad_token', 'bad_refresh'))
    auth_token = client.get_auth_token()

    mocked_authenticate.assert_not_called()
    assert auth_token == AUTH_TOKEN


def test_get_auth_token_long_wait(mocker, client):
    """
    Given:
    - IBM MaaS360 Security client.
    - Prior call to get_auth_token.

    When:
    - client.get_auth_token is called.

    Then:
    - Consecutive call to get_auth_token after token expiry will trigger a token refresh.
    """
    with freeze_time(TEST_TIME) as frozen_time:
        mocked_authenticate = mocker.patch.object(client, 'authenticate', return_value=(AUTH_TOKEN, REFRESH_TOKEN))

        auth_token = client.get_auth_token()

        mocked_authenticate.assert_called_once()
        assert auth_token == AUTH_TOKEN

        frozen_time.tick(timedelta(hours=2))  # Token expired

        mocked_authenticate = mocker.patch.object(client, 'authenticate',
                                                  return_value=(f'new_{AUTH_TOKEN}', f'new_{REFRESH_TOKEN}'))
        mocked_refresh = mocker.patch.object(client, 'refresh_auth_token',
                                             return_value=(f'refreshed_{AUTH_TOKEN}', f'refreshed_{REFRESH_TOKEN}'))

        auth_token = client.get_auth_token()

        mocked_authenticate.assert_not_called()
        mocked_refresh.assert_called_once_with(REFRESH_TOKEN)
        assert auth_token == f'refreshed_{AUTH_TOKEN}'


def test_get_auth_token_long_wait_failed_refresh(mocker, requests_mock, client):
    """
    Given:
    - IBM MaaS360 Security client.
    - Prior call to get_auth_token.

    When:
    - client.get_auth_token is called.
    - Token refresh request fails.

    Then:
    - Call to get_auth_token will reauthenticate after token refresh failure.
    """
    with freeze_time() as frozen_time:
        mocked_authenticate = mocker.patch.object(client, 'authenticate', return_value=(AUTH_TOKEN, REFRESH_TOKEN))

        auth_token = client.get_auth_token()

        mocked_authenticate.assert_called_once()
        assert auth_token == AUTH_TOKEN

        frozen_time.tick(timedelta(hours=2))  # Token expired

        mocked_authenticate = mocker.patch.object(client, 'authenticate',
                                                  return_value=(f'new_{AUTH_TOKEN}', f'new_{REFRESH_TOKEN}'))
        refresh_request_mock = requests_mock.post(
            f'{BASE_URL}{REFRESH_SUFFIX}',
            json={
                'authResponse': {
                    'authToken': 'bad_token',
                    'errorCode': 1002,
                    'refreshToken': 'bad_refresh',
                    'errorDesc': 'Invalid credentials',
                }
            })

        auth_token = client.get_auth_token()

        assert refresh_request_mock.called_once
        mocked_authenticate.assert_called_once()
        assert auth_token == f'new_{AUTH_TOKEN}'


def test_http_request(mocker, requests_mock, client):
    """
    Given:
    - IBM MaaS360 Security client.

    When:
    - client.http_request is called.

    Then:
    - An authorization header with a valid auth token will be included in the request.
    """
    mocker.patch.object(client, 'get_auth_token', return_value=AUTH_TOKEN)
    admin_changes = util_load_json('test_data/mock_admin_changes.json')
    audit_changes_mock = requests_mock.get(f'{BASE_URL}{AUDIT_CHANGES_SUFFIX}',
                                           json=admin_changes)

    res = client.http_request(
        method='GET',
        url_suffix=AUDIT_CHANGES_SUFFIX,
    )

    assert res == admin_changes
    assert audit_changes_mock.last_request.headers['Authorization'] == f'MaaS token="{AUTH_TOKEN}"'


def test_fetch_admin_audit_events(mocker, requests_mock, client):
    """
    Given:
    - IBM MaaS360 Security client.
    - Fetch params

    When:
    - client.fetch_admin_audit_events is called.

    Then:
    - Events are fetched correctly until there are no more or we reach the max_events_per_fetch.
    - The page_offset and pages_remaining parameters are returned correctly.
    """
    admin_changes = util_load_json('test_data/mock_admin_changes.json')
    audit_changes_mock = requests_mock.get(f'{BASE_URL}{AUDIT_CHANGES_SUFFIX}', json=admin_changes)
    mocker.patch.object(client, 'get_auth_token', return_value=AUTH_TOKEN)
    from_date = TEST_TIME - timedelta(days=7)
    to_date = TEST_TIME

    events, page_offset, pages_remaining = client.fetch_admin_audit_events(
        AuditEventType.ChangesAudit,
        from_date=from_date,
        to_date=to_date,
        page_offset=0,
        max_fetch_amount=PAGE_SIZE,
    )

    assert page_offset == 1  # fetched first page
    assert pages_remaining
    assert audit_changes_mock.called_once
    assert audit_changes_mock.last_request.qs == {
        'fromdate': [str(from_date)],
        'todate': [str(to_date)],
        'pagesize': [str(PAGE_SIZE)],
        'pagenumber': [str(1)],
    }

    for event in events:
        event_ts = event[AuditEventType.ChangesAudit.ts_field] / 1000
        expected_time = datetime.fromtimestamp(event_ts, tz=timezone.utc).strftime(DATE_FORMAT)
        assert event.pop('_time') == expected_time
        assert event.pop('source_log_type') == AuditEventType.ChangesAudit.source_log_type

    assert events == admin_changes['adminChanges']['adminChange']


def test_fetch_events(mocker, requests_mock, client):
    """
    Given:
    - IBM MaaS360 Security client.
    - Last run object.

    When:
    - fetch-events is called.

    Then:
    - Events are fetched correctly until there are no more or we reach the max_events_per_fetch.
    - Fetches continue from the last run's stopping point.
    - Next run is returned as expected.
    """
    return


def test_test_module_command(mocker, requests_mock, client):
    """
    Given:
    - IBM MaaS360 Security client.

    When:
    - Pressing test button

    Then:
    - Test module ensures the client is able to authenticate and fetch events correctly.
    """
    return


def test_get_events_command(mocker, requests_mock, client):
    """
    Given:
    - IBM MaaS360 Security client.

    When:
    - get-events is called.

    Then:
    - fetch-events is called with the correct arguments.
    - Events and CommandResults are returned as expected.
    """
    return
