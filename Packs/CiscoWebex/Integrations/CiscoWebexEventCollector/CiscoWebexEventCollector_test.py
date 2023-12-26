import json
import datetime
import pytest
import requests_mock
from freezegun import freeze_time

""" UTILS """


def util_load_json(path: str) -> dict:
    with open(path) as f:
        return json.load(f)


def util_load_text(path: str) -> str:
    with open(path) as f:
        return f.read()


def mock_get_access_token():
    return {
        "access_token": "123456",
        "expires_in": 1111,
        "refresh_token": "123456",
        "refresh_token_expires_in": 2222,
    }


def mock_get_integration_context():
    expires_in = (datetime.datetime.utcnow() + datetime.timedelta(weeks=3)).isoformat()
    return {
        "admin": {
            "access_token": "123456",
            "access_token_expires_in": expires_in,
            "refresh_token": "123456",
            "refresh_token_expires_in": expires_in,
        },
        "compliance_officer": {
            "access_token": "123456",
            "access_token_expires_in": expires_in,
            "refresh_token": "123456",
            "refresh_token_expires_in": expires_in,
        },
    }


def mocked_admin_client():
    from CiscoWebexEventCollector import AdminClient

    class MockAdminClient(AdminClient):
        def get_access_token(self):
            return ''

    return MockAdminClient(
        'https://url.com',
        False,
        False,
        '1',
        '1',
        'https://redirect.com',
        'admin_scope',
        '1',
    )


def mocked_compliance_officer_client():
    from CiscoWebexEventCollector import ComplianceOfficerClient

    class MockComplianceOfficerClient(ComplianceOfficerClient):
        def get_access_token(self):
            return ''

    return MockComplianceOfficerClient(
        'https://url.com',
        False,
        False,
        '1',
        '1',
        'https://redirect.com',
        'co_scope',
    )


""" TEST HELPER FUNCTION """


@freeze_time("2023-12-20 13:40:00 UTC")
def test_create_last_run():
    """
        Given:
            - A list of set_ids.
        When:
            - create_last_run function is running.
        Then:
            - Validates that the function works as expected.
    """
    from CiscoWebexEventCollector import create_last_run

    expected_result = {
        'admin_audits': {'since_datetime': '2023-12-13T13:40:00.000Z', 'next_url': ''},
        'security_audits': {'since_datetime': '2023-12-13T13:40:00.000Z', 'next_url': ''},
        'compliance_officer_events': {'since_datetime': '2023-12-13T13:40:00.000Z', 'next_url': ''},
    }

    assert create_last_run() == expected_result


@freeze_time("2023-12-20 13:40:00 UTC")
def test_date_time_to_iso_format():
    """
        Given:
            - A datetime object with freeze time set to '2023-12-20 13:40:00'.
        When:
            - date_time_to_iso_format function is running.
        Then:
            - Validates that the function works as expected.
    """
    from CiscoWebexEventCollector import date_time_to_iso_format
    assert date_time_to_iso_format(datetime.datetime.utcnow()) == '2023-12-20T13:40:00.000Z'


def test_add_fields_to_events():
    """
        Given:
            - lists of events
                1. Admin Audit Events.
                2. Admin Audit Events.
                3. Events.
        When:
            - add_fields_to_events function is running.
        Then:
            - Validates that the function works as expected.
    """
    from CiscoWebexEventCollector import add_fields_to_events, COMMAND_FUNCTION_TO_EVENT_TYPE

    admin_audits = util_load_json('test_data/admin_audits.json').get('items')
    security_audits = util_load_json('test_data/security_audits.json').get('items')
    compliance_officer_events = util_load_json('test_data/events.json').get('items')

    assert not any(key in admin_audits[0] for key in ('_time', 'source_log_type'))
    assert not any(key in security_audits[0] for key in ('_time', 'source_log_type'))
    assert not any(key in compliance_officer_events[0] for key in ('_time', 'source_log_type'))

    add_fields_to_events(admin_audits, 'Admin Audit Events')
    add_fields_to_events(security_audits, 'Security Audit Events')
    add_fields_to_events(compliance_officer_events, 'Events')

    assert admin_audits[0]['_time'] == admin_audits[0]['created']
    assert admin_audits[0]['source_log_type'] == COMMAND_FUNCTION_TO_EVENT_TYPE.get('get_admin_audits')
    assert security_audits[0]['_time'] == security_audits[0]['created']
    assert security_audits[0]['source_log_type'] == COMMAND_FUNCTION_TO_EVENT_TYPE.get('get_security_audits')
    assert compliance_officer_events[0]['_time'] == compliance_officer_events[0]['created']
    assert compliance_officer_events[0]['source_log_type'] == COMMAND_FUNCTION_TO_EVENT_TYPE.get('get_compliance_officer_events')


def test_increase_datetime_for_next_fetch():
    """
        Given:
            - A list of events
        When:
            - increase_datetime_for_next_fetch function is running.
        Then:
            - Validates that the function works as expected.
    """
    from CiscoWebexEventCollector import increase_datetime_for_next_fetch
    events = util_load_json('test_data/events.json').get('items')
    assert increase_datetime_for_next_fetch(events) == '2023-12-04T07:40:06.691Z'


""" TEST COMMAND FUNCTION """


@pytest.mark.parametrize('client, expected_url', [
    (mocked_admin_client(),
     'https://webexapis.com/v1/authorize?response_type=code&scope=admin_scope&client_id=1&redirect_uri=https%3A%2F%2Fredirect.com'),
    (mocked_compliance_officer_client(),
     'https://webexapis.com/v1/authorize?response_type=code&scope=co_scope&client_id=1&redirect_uri=https%3A%2F%2Fredirect.com'),
])
def test_oauth_start(client, expected_url):
    from CiscoWebexEventCollector import oauth_start
    results = oauth_start(client)
    assert expected_url in results.readable_output


@pytest.mark.parametrize('client', [mocked_admin_client(), mocked_compliance_officer_client()])
def test_oauth_complete(client):
    from CiscoWebexEventCollector import oauth_complete

    with requests_mock.Mocker() as m:
        m.post('https://url.com/access_token?grant_type=authorization_code&code=123456&client_id=1&client_secret=1&redirect_uri=https%3A%2F%2Fredirect.com', json=mock_get_access_token())
        results = oauth_complete(client, {'code': '123456'})

    assert 'Logged in successfully.' in results.readable_output


@pytest.mark.parametrize('client', [mocked_admin_client(), mocked_compliance_officer_client()])
def test_oauth_test(client):
    from CiscoWebexEventCollector import oauth_test

    with requests_mock.Mocker() as m:
        m.get('https://url.com/adminAudit/events', text=util_load_text('test_data/admin_audits.json'))
        m.get('https://url.com/events', text=util_load_text('test_data/events.json'))
        result = oauth_test(client)

    assert result == 'ok'


@pytest.mark.parametrize('command_function, args', [
    (mocked_admin_client().get_admin_audits, {}),
    (mocked_admin_client().get_security_audits, {}),
    (mocked_compliance_officer_client().get_compliance_officer_events, {}),
])
def test_get_events_command(command_function, args):
    """
        Given:
            - A list of set_ids and a date form where to fetch with a CyberArkEPM (mock) client.
        When:
            - get_events_command function is running.
                1. with event type `admin_audits`
                2. with event type `policy_audits`
                3. with event type `detailed_events`
        Then:
            - Validates that the function works as expected.
    """
    from CiscoWebexEventCollector import get_events_command, COMMAND_FUNCTION_TO_EVENT_TYPE

    with requests_mock.Mocker() as m:
        m.get('https://url.com/adminAudit/events', text=util_load_text('test_data/admin_audits.json'))
        m.get('https://url.com/admin/securityAudit/events', text=util_load_text('test_data/security_audits.json'))
        m.get('https://url.com/events', text=util_load_text('test_data/events.json'))
        command_results, events = get_events_command(command_function, args)

    assert len(events) > 0
    assert COMMAND_FUNCTION_TO_EVENT_TYPE.get(command_function.__name__) in command_results.readable_output


@freeze_time("2023-12-20 13:40:00 UTC")
def test_fetch_events():
    """
        Given:
            - A cyberArk client.
        When:
            - fetch-events command is running.
        Then:
            - Validates that the function works as expected.
    """
    from CiscoWebexEventCollector import create_last_run, fetch_events

    with requests_mock.Mocker() as m:
        m.get('https://url.com/adminAudit/events?orgId=1&from=2023-12-13T13%3A40%3A00.000Z&to=2023-12-20T13%3A40%3A00.000Z&max=1',
              text=util_load_text('test_data/admin_audits.json'),
              headers={'Link': '<https://url.com/adminAudit/events?nexturl=true>; rel="next"'})
        m.get('https://url.com/admin/securityAudit/events?orgId=1&startTime=2023-12-13T13%3A40%3A00.000Z&endTime=2023-12-20T13%3A40%3A00.000Z&max=1',
              text=util_load_text('test_data/security_audits.json'),
              headers={'Link': '<https://url.com/securityAudit/events?nexturl=true>; rel="next"'})
        m.get('https://url.com/events?from=2023-12-13T13%3A40%3A00.000Z&to=2023-12-20T13%3A40%3A00.000Z&max=1',
              text=util_load_text('test_data/events.json'),
              headers={'Link': '<https://url.com/events?nexturl=true>; rel="next"'})
        events, next_run = fetch_events(mocked_admin_client(), mocked_compliance_officer_client(), create_last_run(), max_fetch=1)

    assert len(events) > 0
    assert next_run == {
        'admin_audits': {'since_datetime': '2023-11-02T09:33:26.409Z', 'next_url': 'https://url.com/adminAudit/events?nexturl=true'},
        'security_audits': {'since_datetime': '2023-12-19T06:47:38.174Z', 'next_url': 'https://url.com/securityAudit/events?nexturl=true'},
        'compliance_officer_events': {'since_datetime': '2023-12-04T07:40:06.691Z', 'next_url': 'https://url.com/events?nexturl=true'}
    }

    with requests_mock.Mocker() as m:
        m.get('https://url.com/adminAudit/events?nexturl=true', text=util_load_text('test_data/no_events.json'))
        m.get('https://url.com/securityAudit/events?nexturl=true', text=util_load_text('test_data/no_events.json'))
        m.get('https://url.com/events?nexturl=true', text=util_load_text('test_data/no_events.json'))

        events, next_run = fetch_events(mocked_admin_client(), mocked_compliance_officer_client(), next_run, max_fetch=1)

    assert len(events) == 0
    assert next_run == {
        'admin_audits': {'since_datetime': '2023-11-02T09:33:26.409Z', 'next_url': ''},
        'security_audits': {'since_datetime': '2023-12-19T06:47:38.174Z', 'next_url': ''},
        'compliance_officer_events': {'since_datetime': '2023-12-04T07:40:06.691Z', 'next_url': ''}
    }
