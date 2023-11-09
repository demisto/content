from OktaEventCollector import Client, remove_duplicates, get_last_run, get_events_command, main
import pytest
from unittest.mock import MagicMock
from freezegun import freeze_time
import demistomock as demisto

id1_pub = [[{'uuid': 'a5b57ec5feaa', 'published': '2022-04-17T12:32:36.667'}]]
id2_pub = [{'uuid': 'a5b57ec5febb', 'published': '2022-04-17T12:32:36.667'}]
id3_pub = [{'uuid': 'a5b57ec5fecc', 'published': '2022-04-17T12:32:36.667'}]
id4_pub = [{'uuid': 'a5b57ec5fedd', 'published': '2022-04-17T12:32:36.667'}]

id1 = {'uuid': 'a5b57ec5febb'}
id2 = {'uuid': 'a5b57ec5fecc'}
id3 = {'uuid': 'a12f3c5d77f3'}
id4 = {'uuid': 'a12f3c5dxxxx'}


@pytest.fixture
def dummy_client(mocker):
    """
    A dummy client fixture for testing.
    """
    events = [id1_pub, id2_pub, id3_pub, id4_pub]

    client = Client('base_url', 'api_key')
    mocker.patch.object(client, 'get_events', side_effect=events)
    return client


@pytest.mark.parametrize("events,ids,result", [
    ([id1, id2, id3], ['a12f3c5d77f3'], [id1, id2]),
    ([id1, id2, id3], ['a12f3c5dxxxx'], [id1, id2, id3]),
    ([id1], ['a5b57ec5febb'], []),
    ([{'uuid': 0}, {'uuid': 1}, {'uuid': 2}, {'uuid': 3}, {'uuid': 4}, {'uuid': 5}, {'uuid': 6}, {'uuid': 7},
      {'uuid': 8}, {'uuid': 9}], [0, 4, 7, 9],
     [{'uuid': 1}, {'uuid': 2}, {'uuid': 3}, {'uuid': 5}, {'uuid': 6}, {'uuid': 8}])])
def test_remove_duplicates(events, ids, result):
    assert remove_duplicates(events, ids) == result


@pytest.mark.parametrize("events,last_run_after,result", [
    ([{'published': '2022-04-17T12:31:36.667',
       'uuid': '1d0844b6-3148-11ec-9027-a5b57ec5faaa'},
      {'published': '2022-04-17T12:32:36.667',
       'uuid': '1d0844b6-3148-11ec-9027-a5b57ec5fbbb'},
      {'published': '2022-04-17T12:33:36.667',
       'uuid': '1d0844b6-3148-11ec-9027-a5b57ec5fccc'}],
     '2022-04-17T11:30:00.000',
     {'after': '2022-04-17T12:33:36.667000', 'ids': ['1d0844b6-3148-11ec-9027-a5b57ec5fccc']}),
    ([{'published': '2022-04-17T12:31:36.667',
       'uuid': '1d0844b6-3148-11ec-9027-a5b57ec5faaa'},
      {'published': '2022-04-17T12:32:36.667',
       'uuid': '1d0844b6-3148-11ec-9027-a5b57ec5fbbb'},
      {'published': '2022-04-17T12:32:36.667',
       'uuid': '1d0844b6-3148-11ec-9027-a5b57ec5fccc'}],
     '2022-04-17T11:30:00.000',
     {'after': '2022-04-17T12:32:36.667000',
      'ids': ['1d0844b6-3148-11ec-9027-a5b57ec5fccc',
              '1d0844b6-3148-11ec-9027-a5b57ec5fbbb']}),
    ([],
     '2022-04-17T12:31:36.667',
     {'after': '2022-04-17T12:31:36.667000', 'ids': []})])
def test_get_last_run(events, last_run_after, result):
    assert get_last_run(events, last_run_after) == result


def test_get_events_success(dummy_client, mocker):
    mock_remove_duplicates = MagicMock()
    mock_remove_duplicates.return_value = [{'id': 1,
                                            'published': '2022-04-17T12:32:36.667'}]
    mocker.patch('OktaEventCollector.remove_duplicates', mock_remove_duplicates)
    mocker.patch.object(dummy_client, 'get_events', side_effect=id1_pub)
    events, epoch = get_events_command(dummy_client, 1, 'since', ['id1'])
    assert len(events) == 1
    assert epoch == 0


def test_get_events_no_events(dummy_client, mocker):
    mocker.patch.object(dummy_client, 'get_events', return_value=None)
    events, epoch = get_events_command(dummy_client, 1, 'since')
    assert len(events) == 0
    assert epoch == 0


@freeze_time('2022-04-17T12:32:36.667Z')
def test_429_too_many_requests(mocker, requests_mock):

    mock_events = [
        {
            'uuid': 1,
            'published': '2022-04-17T14:00:00.000Z'
        },
        {
            'uuid': 2,
            'published': '2022-04-17T14:00:01.000Z'
        },
        {
            'uuid': 3,
            'published': '2022-04-17T14:00:02.000Z'
        },
        {
            'uuid': 4,
            'published': '2022-04-17T14:00:03.000Z'
        }
    ]
    requests_mock.get(
        'https://testurl.com/api/v1/logs?since=2022-04-17T12%3A32%3A36.667000%2B00%3A00&sortOrder=ASCENDING&limit=5',
        json=mock_events)
    requests_mock.get('https://testurl.com/api/v1/logs?since=2022-04-17T14%3A00%3A03.000Z&sortOrder=ASCENDING&limit=5',
                      status_code=429,
                      reason='Too many requests',
                      headers={
                          'x-rate-limit-remaining': '0',
                          'x-rate-limit-reset': '1698343702',
                      })

    mocker.patch.object(demisto, 'command', return_value='fetch-events')
    mocker.patch.object(demisto, 'getLastRun', return_value={})
    mocker.patch.object(demisto, 'params', return_value={
        'url': 'https://testurl.com',
        'api_key': {
            'password': 'TESTAPIKEY'
        },
        'limit': 5,
        'after': '2022-04-17T12:32:36.667Z',
        'proxy': False,
        'verify': False
    })
    send_events_to_xsiam_mock = mocker.patch('OktaEventCollector.send_events_to_xsiam', return_value={})

    main()

    send_events_to_xsiam_mock.assert_called_once_with(mock_events, vendor='okta', product='okta')
