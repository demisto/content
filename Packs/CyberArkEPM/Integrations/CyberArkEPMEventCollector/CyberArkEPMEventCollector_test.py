from unittest.mock import Mock
import pytest
from freezegun import freeze_time
from CyberArkEPMEventCollector import *


""" UTILS """


def util_load_json(path: str) -> dict:
    with open(path) as f:
        return json.load(f)


# Mocking Client class for testing HTTP requests
@pytest.fixture
def mocked_client():
    return Mock(spec=Client)


""" TEST HELPER FUNCTION """


@freeze_time('2023-12-01 03:20:00')
def test_create_last_run():
    set_ids = ['123', '456']
    from_date = '2023-01-01T00:00:00Z'
    result = create_last_run(set_ids, from_date)
    expected_result = {
        '123': {'policy_audits': from_date, 'admin_audits': from_date, 'detailed_events': from_date},
        '456': {'policy_audits': from_date, 'admin_audits': from_date, 'detailed_events': from_date}
    }
    assert result == expected_result


def test_prepare_datetime():
    from_date = '2023-01-01T00:00:00'
    assert prepare_datetime(datetime.strptime(from_date, '%Y-%m-%dT%H:%M:%S')) == '2023-01-01T00:00:00.000Z'
    assert prepare_datetime(from_date) == '2023-01-01T00:00:00.000Z'
    assert prepare_datetime(from_date, increase=True) == '2023-01-01T00:00:00.001Z'


def test_prepare_next_run():
    from_date = '2023-01-01T00:00:00Z'
    last_run = {
        '123': {'policy_audits': from_date, 'admin_audits': from_date, 'detailed_events': from_date},
        '456': {'policy_audits': from_date, 'admin_audits': from_date, 'detailed_events': from_date}
    }
    next_run = {}
    expected_next_run = {
        '123': {'policy_audits': '2023-12-11T13:09:56.056Z', 'admin_audits': "2023-12-12T07:45:27.141Z", 'detailed_events': "2023-12-12T06:59:18.141Z"},
        '456': {'policy_audits': '2023-12-11T13:09:56.056Z', 'admin_audits': "2023-12-12T07:45:27.141Z", 'detailed_events': "2023-12-12T06:59:18.141Z"}
    }
    set_ids = ['123', '456']
    policy_audits = util_load_json('test_data/policy_audits.json').get('events')
    admin_audits = util_load_json('test_data/admin_audits.json').get('AdminAudits')
    events = util_load_json('test_data/events.json').get('events')

    for set_id in set_ids:
        prepare_next_run(last_run, next_run, set_id, policy_audits, 'policy_audits')
        prepare_next_run(last_run, next_run, set_id, admin_audits, 'admin_audits')
        prepare_next_run(last_run, next_run, set_id, events, 'detailed_events')

    assert next_run == expected_next_run


def test_add_fields_to_events():
    ...


def test_get_set_ids_by_set_names():
    ...


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

