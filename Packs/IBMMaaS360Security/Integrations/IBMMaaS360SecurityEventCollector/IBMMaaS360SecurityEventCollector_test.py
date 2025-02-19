from math import ceil
import pytest
from freezegun import freeze_time
from IBMMaaS360SecurityEventCollector import Client, AuditEventType, DATE_FORMAT
from datetime import datetime, timedelta
from dateutil import tz
from CommonServerPython import set_integration_context, date_to_timestamp
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


admin_changes = util_load_json('test_data/mock_admin_changes.json')
login_reports = util_load_json('test_data/mock_login_events.json')


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


@pytest.fixture
def admin_changes_request(requests_mock):
    def mock_admin_changes_resp(request, context):
        if request.headers.get('Authorization') != f'MaaS token="{AUTH_TOKEN}"':
            context.status_code = 401
            return {'adminChanges': {
                "errorCode": 1009,
                "errorDesc": "Token invalid"
            }}
        page_number = int(request.qs.get('pagenumber', [0])[0])
        if page_number - 1 < len(admin_changes):
            return admin_changes[page_number - 1]
        else:
            return {'adminChanges': {
                'count': 0,
                'pageNumber': page_number,
                'pageSize': PAGE_SIZE,
            }}

    return requests_mock.get(f'{BASE_URL}{AUDIT_CHANGES_SUFFIX}',
                             json=mock_admin_changes_resp)


@pytest.fixture
def login_reports_request(requests_mock):
    def mock_login_reports_resp(request, context):
        if request.headers.get('Authorization') != f'MaaS token="{AUTH_TOKEN}"':
            return {'adminChanges': {
                "errorCode": 1009,
                "errorDesc": "Token invalid"
            }}
        page_number = int(request.qs.get('pagenumber', [0])[0])
        if page_number - 1 < len(login_reports):
            return login_reports[page_number - 1]
        else:
            return {'loginEvents': {
                'count': 0,
                'pageNumber': page_number,
                'pageSize': PAGE_SIZE,
            }}

    return requests_mock.get(f'{BASE_URL}{AUDIT_LOGIN_REPORTS_SUFFIX}',
                             json=mock_login_reports_resp)


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
    admin_changes = util_load_json('test_data/mock_admin_changes.json')[0]
    audit_changes_mock = requests_mock.get(f'{BASE_URL}{AUDIT_CHANGES_SUFFIX}',
                                           json=admin_changes)

    res = client.http_request(
        method='GET',
        url_suffix=AUDIT_CHANGES_SUFFIX,
    )

    assert res == admin_changes
    assert audit_changes_mock.last_request.headers['Authorization'] == f'MaaS token="{AUTH_TOKEN}"'


@pytest.mark.parametrize('pages_to_fetch', [1, 2, 3])
def test_fetch_admin_audit_events(mocker, client, admin_changes_request, pages_to_fetch):
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
    mocker.patch.object(client, 'get_auth_token', return_value=AUTH_TOKEN)
    from_date = TEST_TIME - timedelta(days=7)
    to_date = TEST_TIME

    events, page_offset, pages_remaining = client.fetch_admin_audit_events(
        AuditEventType.ChangesAudit,
        from_date=from_date,
        to_date=to_date,
        page_offset=0,
        max_fetch_amount=pages_to_fetch * PAGE_SIZE,
    )

    assert page_offset == pages_to_fetch
    assert pages_remaining if pages_to_fetch < len(admin_changes) else not pages_remaining
    assert admin_changes_request.call_count == pages_to_fetch
    assert admin_changes_request.last_request.qs == {
        'fromdate': [str(from_date)],
        'todate': [str(to_date)],
        'pagesize': [str(PAGE_SIZE)],
        'pagenumber': [str(pages_to_fetch)],
    }

    for event in events:
        event_ts = event[AuditEventType.ChangesAudit.ts_field] / 1000
        expected_time = datetime.fromtimestamp(event_ts, tz=tz.UTC).strftime(DATE_FORMAT)
        assert event.pop('_time') == expected_time
        assert event.pop('source_log_type') == AuditEventType.ChangesAudit.source_log_type

    expected_events = [event for page in admin_changes[:pages_to_fetch] for event in page['adminChanges']['adminChange']]
    assert events == expected_events


@pytest.mark.parametrize('max_pages_to_fetch', [1, 2, 3])
def test_fetch_events(mocker, client, admin_changes_request, login_reports_request, max_pages_to_fetch):
    """
    Given:
    - IBM MaaS360 Security client.
    - Last run object.

    When:
    - fetch-events is called multiple times.

    Then:
    - Events are fetched correctly until there are no more or we reach the max_pages_to_fetch.
    - Fetches continue from the previous fetch stopping point.
    - Pagination is done correctly, fetching consecutive pages as expected.
    """
    from IBMMaaS360SecurityEventCollector import fetch_events

    mocker.patch.object(client, 'get_auth_token', return_value=AUTH_TOKEN)

    last_run = {}
    first_fetch_time = date_to_timestamp(TEST_TIME - timedelta(days=7))
    max_events_per_fetch = {
        AuditEventType.ChangesAudit: PAGE_SIZE,
        AuditEventType.LoginReports: PAGE_SIZE,
    }

    for i in range(max_pages_to_fetch):
        last_run, events = fetch_events(
            client=client,
            last_run=last_run,
            first_fetch_time=first_fetch_time,
            max_events_per_fetch=max_events_per_fetch,
        )

        expected_admin_changes = []
        expected_login_reports = []
        if i < len(admin_changes):
            assert admin_changes_request.call_count == i + 1
            expected_admin_changes = admin_changes[i]['adminChanges']['adminChange']

        if i < len(login_reports):
            assert login_reports_request.call_count == i + 1
            expected_login_reports = login_reports[i]['loginEvents']['loginEvent']

        assert len(events) == len(expected_admin_changes) + len(expected_login_reports)

        for event in events:
            event_time = event.pop('_time')
            log_type = event.pop('source_log_type')
            if log_type == AuditEventType.ChangesAudit.source_log_type:
                assert event in expected_admin_changes
                event_ts = event[AuditEventType.ChangesAudit.ts_field] / 1000
            else:
                assert event in expected_login_reports
                event_ts = event[AuditEventType.LoginReports.ts_field] / 1000

            expected_time = datetime.fromtimestamp(event_ts, tz=tz.UTC).strftime(DATE_FORMAT)
            assert event_time == expected_time


def test_test_module_command_success(requests_mock, client, admin_changes_request, login_reports_request):
    """
    Given:
    - IBM MaaS360 Security client.
    - Valid credentials.

    When:
    - Pressing test button

    Then:
    - The test module succeeds in authenticating and fetching data and returns 'ok'.
    """
    from IBMMaaS360SecurityEventCollector import test_module

    first_fetch_time = date_to_timestamp(TEST_TIME - timedelta(days=7))
    auth_request_mock = requests_mock.post(
        f'{BASE_URL}{AUTH_SUFFIX}',
        json={
            'authResponse': {
                'authToken': AUTH_TOKEN,
                'errorCode': 0,
                'refreshToken': REFRESH_TOKEN,
            }
        })

    res = test_module(client, {}, first_fetch_time)

    assert auth_request_mock.called_once
    assert admin_changes_request.called_once
    assert login_reports_request.called_once
    assert res == 'ok'


def test_test_module_command_failure(requests_mock, client):
    """
    Given:
    - IBM MaaS360 Security client.
    - Bad credentials.

    When:
    - Pressing test button

    Then:
    - The test module fails with some error message.
    """
    from IBMMaaS360SecurityEventCollector import test_module

    first_fetch_time = date_to_timestamp(TEST_TIME - timedelta(days=7))
    auth_request_mock = requests_mock.post(
        f'{BASE_URL}{AUTH_SUFFIX}',
        json={
            'authResponse': {
                'errorCode': 1002,
                'errorDesc': 'Invalid Credentials',
            }
        })

    res = test_module(client, {}, first_fetch_time)

    assert auth_request_mock.called_once
    assert res != 'ok'


@pytest.mark.parametrize('limit', [1, 2, 3, 6, 11])
def test_get_events_command(mocker, client, admin_changes_request, login_reports_request, limit):
    """
    Given:
    - IBM MaaS360 Security client.

    When:
    - get-events is called.

    Then:
    - Events are returned as expected.
    """
    from IBMMaaS360SecurityEventCollector import get_events

    mocker.patch.object(client, 'get_auth_token', return_value=AUTH_TOKEN)

    args = {'limit': limit}

    events, _results = get_events(
        client=client,
        args=args,
    )

    expected_admin_changes = [event for page in admin_changes for event in page['adminChanges']['adminChange']][:limit]
    expected_login_len = limit - len(expected_admin_changes)
    expected_login_reports = [event for page in login_reports for event in page['loginEvents']['loginEvent']][:expected_login_len]

    assert admin_changes_request.call_count == ceil(len(expected_admin_changes) / PAGE_SIZE)
    assert login_reports_request.call_count == ceil(len(expected_login_reports) / PAGE_SIZE)
    assert len(events) == len(expected_admin_changes) + len(expected_login_reports) == limit

    for event in events:
        event_time = event.pop('_time')
        log_type = event.pop('source_log_type')
        if log_type == AuditEventType.ChangesAudit.source_log_type:
            assert event in expected_admin_changes
            event_ts = event[AuditEventType.ChangesAudit.ts_field] / 1000
        else:
            assert event in expected_login_reports
            event_ts = event[AuditEventType.LoginReports.ts_field] / 1000

        expected_time = datetime.fromtimestamp(event_ts, tz=tz.UTC).strftime(DATE_FORMAT)
        assert event_time == expected_time
