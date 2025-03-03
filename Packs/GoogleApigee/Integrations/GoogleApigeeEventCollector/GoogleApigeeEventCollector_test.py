import pytest

from GoogleApigeeEventCollector import (
    Client,
    fetch_events,
    get_events
)


def mock_client():
    return Client(base_url='https://test.com', verify=False, proxy=False, org_name='org', username='user',
                  password='password', zone='zone')


def test_get_events(requests_mock, mocker):
    """Tests get-events command function.

    Checks the output of the command function with the expected output.
    """
    client = mock_client()
    mock_response = {
        'auditRecord': [generate_mocked_event(13), generate_mocked_event(15)],
        'total_count': 2,
    }
    args = {
        'from_date': 3,
        'limit': 2,
    }
    mocker.patch.object(Client, 'get_access_token', return_value={'access_token': 'access_token'})
    requests_mock.get(f'https://test.com/v1/audits/organizations/{client.org_name}', json=mock_response)
    events, _ = get_events(client, args)

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

    def mock_get_events(from_date, to_time):
        events = [generate_mocked_event(event_time) for event_time in events_per_time]
        return {
            'auditRecord': events,
            'total_count': len(events),
        }

    mocked_client = mocker.Mock()
    mocked_client.get_logs.side_effect = mock_get_events
    mocked_client.max_fetch = limit

    last_run = {'events_amount': events_amount, 'last_fetch': last_fetch}
    next_run, events = fetch_events(
        client=mocked_client,
        last_run=last_run,
    )

    assert len(events) == events_size
    assert next_run.get('events_amount') == new_events_amount, f'{scenario} - set last run does not match expected value'
    if events:
        assert events[0].get('timeStamp') == last_event_time
        assert events[-1].get('timeStamp') >= last_fetch
