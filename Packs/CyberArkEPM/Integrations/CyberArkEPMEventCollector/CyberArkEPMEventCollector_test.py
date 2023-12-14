import json
from freezegun import freeze_time
from CyberArkEPMEventCollector import *


""" UTILS """


def util_load_json(path: str) -> dict:
    with open(path) as f:
        return json.load(f)


def mocked_client(requests_mock):
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

    client = mocked_client(requests_mock)
    ids = get_set_ids_by_set_names(client, ['set_name1', 'set_name2'])

    assert ids == ['id1', 'id2']


""" TEST COMMAND FUNCTION """


def test_get_admin_audits_command(requests_mock):
    client = mocked_client(requests_mock)
    last_run_per_id = create_last_run(['id1', 'id2'], '2023-01-01T00:00:00Z')

    events, _ = get_admin_audits_command(client, last_run_per_id, {'limit': 10})

    assert len(events) == 6


def test_get_policy_command(requests_mock):
    client = mocked_client(requests_mock)
    last_run_per_id = create_last_run(['id1', 'id2'], '2023-01-01T00:00:00Z')

    events, _ = get_policy_audits_command(client, last_run_per_id, {'limit': 10})

    assert len(events) == 6


def test_get_detailed_events_command(requests_mock):
    client = mocked_client(requests_mock)
    last_run_per_id = create_last_run(['id1', 'id2'], '2023-01-01T00:00:00Z')

    events, _ = get_detailed_events_command(client, last_run_per_id, {'limit': 10})

    assert len(events) == 6


def test_fetch_events(requests_mock):
    last_run = create_last_run(['id1', 'id2'], '2023-01-01T00:00:00Z')
    events, next_run = fetch_events(mocked_client(requests_mock), last_run, 10)

    assert len(events) == 18
    assert next_run['id1'] == next_run['id1'] == {
        'admin_audits': {'from_date': '2023-12-12T07:45:27.141Z'},
        'detailed_events': {'from_date': '2023-12-12T06:59:18.141Z', 'next_cursor': 'start'},
        'policy_audits': {'from_date': '2023-12-11T13:09:56.056Z', 'next_cursor': 'start'}
    }

    fetch_events(mocked_client(requests_mock), next_run, 10)

    assert len(events) == 18
    assert next_run['id1'] == next_run['id1'] == {
        'admin_audits': {'from_date': '2023-12-12T07:45:27.141Z'},
        'detailed_events': {'from_date': '2023-12-12T06:59:18.141Z', 'next_cursor': 'start'},
        'policy_audits': {'from_date': '2023-12-11T13:09:56.056Z', 'next_cursor': 'start'}
    }
