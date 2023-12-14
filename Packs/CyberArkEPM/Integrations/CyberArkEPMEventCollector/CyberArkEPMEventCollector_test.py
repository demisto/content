import json
from unittest.mock import Mock
import pytest
from freezegun import freeze_time
from CyberArkEPMEventCollector import *


""" UTILS """


def util_load_json(path: str) -> dict:
    with open(path) as f:
        return json.load(f)


# Mocking Client class for testing HTTP requests
def mocked_client():
    return Client(
        'https://url.com',
        'test',
        '123456',
        '1',
    )


""" TEST HELPER FUNCTION """


@freeze_time('2023-12-01 03:20:00')
def test_create_last_run():
    set_ids = ['123', '456']
    from_date = '2023-01-01T00:00:00Z'
    result = create_last_run(set_ids, from_date)
    expected_result = {
        '123': {'admin_audits': {'from_date': from_date}, 'policy_audits': {'from_date': from_date, 'next_cursor': 'start'}, 'detailed_events': {'from_date': from_date, 'next_cursor': 'start'}},
        '456': {'admin_audits': {'from_date': from_date}, 'policy_audits': {'from_date': from_date, 'next_cursor': 'start'}, 'detailed_events': {'from_date': from_date, 'next_cursor': 'start'}}
    }
    assert result == expected_result


def test_prepare_datetime():
    from_date = '2023-01-01T00:00:00'
    assert prepare_datetime(datetime.strptime(from_date, '%Y-%m-%dT%H:%M:%S')) == '2023-01-01T00:00:00.000Z'
    assert prepare_datetime(from_date) == '2023-01-01T00:00:00.000Z'
    assert prepare_datetime(from_date, increase=True) == '2023-01-01T00:00:00.001Z'


def test_add_fields_to_events():
    policy_audits = util_load_json('test_data/policy_audits.json').get('events')
    admin_audits = util_load_json('test_data/admin_audits.json').get('AdminAudits')
    events = util_load_json('test_data/events.json').get('events')

    assert not any(key in policy_audits[0] for key in ('_time', 'eventTypeXsiam'))
    assert not any(key in admin_audits[0] for key in ('_time', 'eventTypeXsiam'))
    assert not any(key in events[0] for key in ('_time', 'eventTypeXsiam'))

    add_fields_to_events(policy_audits, 'arrivalTime', 'policy_audits')
    add_fields_to_events(admin_audits, 'EventTime', 'admin_audits')
    add_fields_to_events(events, 'arrivalTime', 'detailed_events')

    assert policy_audits[0]['_time'] == policy_audits[0]['arrivalTime']
    assert policy_audits[0]['eventTypeXsiam'] == XSIAM_EVENT_TYPE.get('policy_audits')
    assert admin_audits[0]['_time'] == admin_audits[0]['EventTime']
    assert admin_audits[0]['eventTypeXsiam'] == XSIAM_EVENT_TYPE.get('admin_audits')
    assert events[0]['_time'] == events[0]['arrivalTime']
    assert events[0]['eventTypeXsiam'] == XSIAM_EVENT_TYPE.get('detailed_events')


def test_get_set_ids_by_set_names(mocker, requests_mock):
    mocker.patch('CyberArkEPMEventCollector.get_integration_context', return_value={})
    requests_mock.post('https://url.com/EPM/API/Auth/EPM/Logon', json={'ManagerURL': 'https://manage.com', 'Authorization': '123456'})
    requests_mock.get('https://url.com/sets', json=[{'Id': 'id1', 'Name': 'set_name1'}, {'Id': 'id2', 'Name': 'set_name2'}])

    client = mocked_client()
    ids = get_set_ids_by_set_names(client, ['set_name1', 'set_name2'])

    assert ids == ['id1', 'id2']


def test_get_policy_audits():
    ...


def test_get_admin_audits():
    ...


def test_get_detailed_events():
    ...


""" TEST COMMAND FUNCTION """


def test_fetch_events(mocked_client):
    last_run = {'123': {'policy_audits': '2022-01-01T00:00:00Z'}}
    max_fetch = 5
    with patch('your_script.demisto.getLastRun', return_value=last_run):
        events, next_run = fetch_events(mocked_client, last_run, max_fetch)
        assert len(events) == 0  # Mocked client will return empty events
        assert next_run == {'123': {'policy_audits': '2022-01-01T00:00:00Z'}}  # No events fetched, next_run remains the same

