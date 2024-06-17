import json
import datetime
import pytest

""" UTILS """


def util_load_json(path: str) -> dict:
    with open(path) as f:
        return json.load(f)


def mocked_client(requests_mock):
    from CyberArkEPMEventCollector import Client
    mock_response_sets = {'Sets': [{'Id': 'id1', 'Name': 'set_name1'}, {'Id': 'id2', 'Name': 'set_name2'}]}
    mock_response_admin_audits = util_load_json('test_data/admin_audits.json')
    mock_response_policy_audits = util_load_json('test_data/policy_audits.json')
    mock_response_events = util_load_json('test_data/events.json')
    mock_response_no_more_events = util_load_json('test_data/no_more_events.json')

    requests_mock.post('https://url.com/EPM/API/Auth/EPM/Logon', json={'ManagerURL': 'https://mock.com', 'Authorization': '123'})
    requests_mock.get('https://mock.com/EPM/API/Sets', json=mock_response_sets)
    requests_mock.get('https://mock.com/EPM/API/Sets/id1/AdminAudit?dateFrom=2023-01-01T00:00:00Z&limit=10',
                      json=mock_response_admin_audits)
    requests_mock.get('https://mock.com/EPM/API/Sets/id2/AdminAudit?dateFrom=2023-01-01T00:00:00Z&limit=10',
                      json=mock_response_admin_audits)
    requests_mock.get('https://mock.com/EPM/API/Sets/id1/AdminAudit?dateFrom=2023-12-12T07:45:27.141Z&limit=10',
                      json=mock_response_admin_audits)
    requests_mock.get('https://mock.com/EPM/API/Sets/id2/AdminAudit?dateFrom=2023-12-12T07:45:27.141Z&limit=10',
                      json=mock_response_admin_audits)
    requests_mock.post('https://mock.com/EPM/API/Sets/id1/policyaudits/search?nextCursor=start&limit=10',
                       json=mock_response_policy_audits)
    requests_mock.post('https://mock.com/EPM/API/Sets/id1/policyaudits/search?nextCursor=1700097106000&limit=10',
                       json=mock_response_no_more_events)
    requests_mock.post('https://mock.com/EPM/API/Sets/id2/policyaudits/search?nextCursor=start&limit=10',
                       json=mock_response_policy_audits)
    requests_mock.post('https://mock.com/EPM/API/Sets/id2/policyaudits/search?nextCursor=1700097106000&limit=10',
                       json=mock_response_no_more_events)
    requests_mock.post('https://mock.com/EPM/API/Sets/id1/Events/Search?nextCursor=start&limit=10', json=mock_response_events)
    requests_mock.post('https://mock.com/EPM/API/Sets/id1/Events/Search?nextCursor=1702360757618&limit=10',
                       json=mock_response_no_more_events)
    requests_mock.post('https://mock.com/EPM/API/Sets/id2/Events/Search?nextCursor=start&limit=10', json=mock_response_events)
    requests_mock.post('https://mock.com/EPM/API/Sets/id2/Events/Search?nextCursor=1702360757618&limit=10',
                       json=mock_response_no_more_events)

    return Client(
        'https://url.com',
        'test',
        '123456',
        '1',
        policy_audits_event_type=['a', 'b', 'c']
    )


""" TEST HELPER FUNCTION """


def test_create_last_run():
    """
        Given:
            - A list of set_ids.

        When:
            - create_last_run function is running.

        Then:
            - Validates that the function works as expected.
    """
    from CyberArkEPMEventCollector import create_last_run

    set_ids = ['123', '456']
    from_date = '2023-01-01T00:00:00Z'
    expected_result = {
        '123': {
            'admin_audits': {'from_date': from_date},
            'policy_audits': {'from_date': from_date, 'next_cursor': 'start'},
            'detailed_events': {'from_date': from_date, 'next_cursor': 'start'},
        },
        '456': {
            'admin_audits': {'from_date': from_date},
            'policy_audits': {'from_date': from_date, 'next_cursor': 'start'},
            'detailed_events': {'from_date': from_date, 'next_cursor': 'start'},
        }
    }

    assert create_last_run(set_ids, from_date) == expected_result


@pytest.mark.parametrize(
    'date_time, increase, expected_date_time',
    [
        ('2023-01-01T00:00:00', False, '2023-01-01T00:00:00.000Z'),
        (datetime.datetime.strptime('2023-01-01T00:00:00', '%Y-%m-%dT%H:%M:%S'), False, '2023-01-01T00:00:00.000Z'),
        ('2023-01-01T00:00:00', True, '2023-01-01T00:00:00.001Z'),
    ]
)
def test_prepare_datetime(date_time, increase, expected_date_time):
    """
        Given:
            - A datetime presentation
                1. in str
                2. in datetime object

        When:
            - prepare_datetime function is running.
                1. with increase set to false.
                2. with increase set to true.

        Then:
            - Validates that the function works as expected.
    """
    from CyberArkEPMEventCollector import prepare_datetime
    assert prepare_datetime(date_time, increase) == expected_date_time


def test_add_fields_to_events():
    """
        Given:
            - lists of events
                1. admin audits.
                2. policy audits.
                3. events.

        When:
            - add_fields_to_events function is running.

        Then:
            - Validates that the function works as expected.
    """
    from CyberArkEPMEventCollector import add_fields_to_events, XSIAM_EVENT_TYPE

    policy_audits = util_load_json('test_data/policy_audits.json').get('events')
    admin_audits = util_load_json('test_data/admin_audits.json').get('AdminAudits')
    events = util_load_json('test_data/events.json').get('events')

    assert not any(key in policy_audits[0] for key in ('_time', 'source_log_type'))
    assert not any(key in admin_audits[0] for key in ('_time', 'source_log_type'))
    assert not any(key in events[0] for key in ('_time', 'source_log_type'))

    add_fields_to_events(policy_audits, 'arrivalTime', 'policy_audits')
    add_fields_to_events(admin_audits, 'EventTime', 'admin_audits')
    add_fields_to_events(events, 'arrivalTime', 'detailed_events')

    assert policy_audits[0]['_time'] == policy_audits[0]['arrivalTime']
    assert policy_audits[0]['source_log_type'] == XSIAM_EVENT_TYPE.get('policy_audits')
    assert admin_audits[0]['_time'] == admin_audits[0]['EventTime']
    assert admin_audits[0]['source_log_type'] == XSIAM_EVENT_TYPE.get('admin_audits')
    assert events[0]['_time'] == events[0]['arrivalTime']
    assert events[0]['source_log_type'] == XSIAM_EVENT_TYPE.get('detailed_events')


def test_get_set_ids_by_set_names(mocker, requests_mock):
    """
        Given:
            - A list of set_names.

        When:
            - get_set_ids_by_set_names function is running.

        Then:
            - Validates that the function works as expected.
    """
    from CyberArkEPMEventCollector import get_set_ids_by_set_names
    mocker.patch('CyberArkEPMEventCollector.get_integration_context', return_value={})

    set_names = ['set_name1', 'set_name2']
    client = mocked_client(requests_mock)

    assert get_set_ids_by_set_names(client, set_names) == ['id1', 'id2']


""" TEST COMMAND FUNCTION """


@pytest.mark.parametrize('event_type', ['admin_audits', 'policy_audits', 'detailed_events'])
def test_get_events_command(requests_mock, event_type):
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
    from CyberArkEPMEventCollector import create_last_run, get_events_command
    from CommonServerPython import string_to_table_header

    client = mocked_client(requests_mock)
    last_run_per_id = create_last_run(['id1', 'id2'], '2023-01-01T00:00:00Z')

    events, command_results = get_events_command(client, event_type, last_run_per_id, 10)

    assert len(events) == 6
    assert string_to_table_header(event_type) in command_results.readable_output


def test_fetch_events(requests_mock):
    """
        Given:
            - A cyberArk client.

        When:
            - fetch-events command is running.

        Then:
            - Validates that the function works as expected.
    """
    from CyberArkEPMEventCollector import create_last_run, fetch_events
    last_run = create_last_run(['id1', 'id2'], '2023-01-01T00:00:00Z')
    events, next_run = fetch_events(mocked_client(requests_mock), last_run, 10, True)

    assert len(events) == 18
    assert next_run['id1'] == next_run['id2'] == {
        'admin_audits': {'from_date': '2023-12-12T07:45:27.141Z'},
        'detailed_events': {'from_date': '2023-12-12T06:59:18.141Z', 'next_cursor': 'start'},
        'policy_audits': {'from_date': '2023-12-11T13:09:56.056Z', 'next_cursor': 'start'}
    }
