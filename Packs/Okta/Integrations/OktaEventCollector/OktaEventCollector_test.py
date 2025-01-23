from unittest.mock import MagicMock
import dateutil.parser._parser
import pytest
from freezegun import freeze_time
from OktaEventCollector import Client, DemistoException, fetch_events, get_events_command, get_last_run, main, remove_duplicates
import requests_mock
import demistomock as demisto


class MockResponse:
    def __init__(self, data=None, text='', status_code=200, links={}):
        self.data = data
        self.text = str(data) if data else text
        self.status_code = status_code
        self.links = links


id1_pub = '[{"uuid": "a5b57ec5feaa", "published": "2022-04-17T12:32:36.667"}]'
id2_pub = [{'uuid': 'a5b57ec5febb', 'published': '2022-04-17T12:32:36.667'}]
id3_pub = [{'uuid': 'a5b57ec5fecc', 'published': '2022-04-17T12:32:36.667'}]
id4_pub = [{'uuid': 'a5b57ec5fedd', 'published': '2022-04-17T12:32:36.667'}]
empty_response = '[]'

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
     {'after': '2022-04-17T12:33:36.667000', 'ids': ['1d0844b6-3148-11ec-9027-a5b57ec5fccc'], 'next_link': ''}),
    ([{'published': '2022-04-17T12:31:36.667',
       'uuid': '1d0844b6-3148-11ec-9027-a5b57ec5faaa'},
      {'published': '2022-04-17T12:32:36.667',
       'uuid': '1d0844b6-3148-11ec-9027-a5b57ec5fbbb'},
      {'published': '2022-04-17T12:32:36.667',
       'uuid': '1d0844b6-3148-11ec-9027-a5b57ec5fccc'}],
     '2022-04-17T11:30:00.000',
     {'after': '2022-04-17T12:32:36.667000',
      'ids': ['1d0844b6-3148-11ec-9027-a5b57ec5fccc',
              '1d0844b6-3148-11ec-9027-a5b57ec5fbbb'], 'next_link': ''}),
    ([],
     '2022-04-17T12:31:36.667',
     {'after': '2022-04-17T12:31:36.667000', 'ids': [], 'next_link': ''})
])
def test_get_last_run(events, last_run_after, result):
    assert get_last_run(events, last_run_after, next_link='') == result


def test_get_last_run_with_different_format():
    events = [{'published': '2022-04-17T12:31:36',
               'uuid': '1d0844b6-3148-11ec-9027-a5b57ec5faaa'},
              {'published': '2022-04-17T12:32:36',
               'uuid': '1d0844b6-3148-11ec-9027-a5b57ec5fbbb'},
              {'published': '2022-04-17T12:33:36',
               'uuid': '1d0844b6-3148-11ec-9027-a5b57ec5fccc'}]
    last_run_after = '2022-04-17T11:30:00'
    expected_result = {'after': '2022-04-17T12:33:36', 'ids': ['1d0844b6-3148-11ec-9027-a5b57ec5fccc'], 'next_link': ''}
    assert get_last_run(events, last_run_after, next_link='') == expected_result


def test_get_last_run_invalid_date_format():
    events = [{'published': '2022-04-17T12:31:36',
               'uuid': '1d0844b6-3148-11ec-9027-a5b57ec5faaa'},
              {'published': '2022-04-17T12:32:36',
               'uuid': '1d0844b6-3148-11ec-9027-a5b57ec5fbbb'},
              {'published': 'xxxyyyzzz',
               'uuid': '1d0844b6-3148-11ec-9027-a5b57ec5fccc'}]
    last_run_after = '2022-04-17T11:30:00'
    with pytest.raises(dateutil.parser._parser.ParserError):
        get_last_run(events, last_run_after, next_link='')


def test_get_events_success(dummy_client, mocker):
    mock_remove_duplicates = MagicMock()
    mock_remove_duplicates.return_value = [{'id': 1,
                                            'published': '2022-04-17T12:32:36.667'}]
    mocker.patch('OktaEventCollector.remove_duplicates', mock_remove_duplicates)
    mocker.patch.object(dummy_client, 'get_events', side_effect=[MockResponse(text=id1_pub)])
    events, epoch, _ = get_events_command(dummy_client, 1, 'since', ['id1'])
    assert len(events) == 1
    assert epoch == 0


def test_get_events_with_next_link_success(dummy_client, mocker):
    mock_remove_duplicates = MagicMock()
    mock_remove_duplicates.return_value = [{'id': 1,
                                            'published': '2022-04-17T12:32:36.667'}]
    mocker.patch('OktaEventCollector.remove_duplicates', mock_remove_duplicates)
    mocker.patch.object(dummy_client, 'get_events', side_effect=[
                        MockResponse(text=id1_pub, links={'next': {'url': 'next_link'}})])
    events, epoch, next_link = get_events_command(dummy_client, 1, 'since', ['id1'], next_link='next_link')
    assert len(events) == 1
    assert epoch == 0
    assert next_link == 'next_link'


def test_get_events_no_events(dummy_client, mocker):
    mocker.patch.object(dummy_client, 'get_events', side_effect=[MockResponse(text=empty_response)])
    events, epoch, _ = get_events_command(dummy_client, 1, 'since')
    assert len(events) == 0
    assert epoch == 0


def test_get_events_429_error_failure(dummy_client, mocker):
    mock_remove_duplicates = MagicMock()
    mock_remove_duplicates.return_value = [{'id': 1,
                                            'published': '2022-04-17T12:32:36.667'}]
    mocker.patch('OktaEventCollector.remove_duplicates', mock_remove_duplicates)
    mocker.patch.object(dummy_client, 'get_events', side_effect=[DemistoException('exception')])
    with pytest.raises(DemistoException):
        get_events_command(dummy_client, 1, 'since', ['id1'])


def test_get_events_general_failure(dummy_client, mocker):
    mock_remove_duplicates = MagicMock()
    mock_remove_duplicates.return_value = [{'id': 1,
                                            'published': '2022-04-17T12:32:36.667'}]
    mocker.patch('OktaEventCollector.remove_duplicates', mock_remove_duplicates)
    mocker.patch.object(dummy_client, 'get_events', side_effect=BaseException())
    with pytest.raises(BaseException):
        get_events_command(dummy_client, 1, 'since', ['id1'])


def test_fetch_event(dummy_client, mocker):
    response = {
        'events': [{'id': 1, 'published': '2022-04-17T12:32:36.667'}],
        'epoch_time_to_continue_fetch': 0,
        'next_link': 'next_link'
    }
    mocker.patch('OktaEventCollector.get_events_command', side_effect=[
                 ([], 1, response['next_link']),
                 (response['events'], response['epoch_time_to_continue_fetch'], response['next_link']),
                 ])
    events, next_link = fetch_events(dummy_client, 0, 1, '')
    assert events == [{'id': 1, 'published': '2022-04-17T12:32:36.667'}]
    assert next_link == 'next_link'


@freeze_time('2022-04-17T12:32:36.667Z')
def test_429_too_many_requests(mocker):

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

    with requests_mock.Mocker() as m:
        m.get(
            'https://testurl.com/api/v1/logs?since=2022-04-17T12%3A32%3A36.667000%2B00%3A00&sortOrder=ASCENDING&limit=5',
            json=mock_events)
        m.get('https://testurl.com/api/v1/logs?since=2022-04-17T14%3A00%3A03.000Z&sortOrder=ASCENDING&limit=5',
              status_code=429,
              reason='Too many requests',
              headers={
                  'x-rate-limit-remaining': '0',
                  'x-rate-limit-reset': '1698343702',
              })

        main()

    send_events_to_xsiam_mock.assert_called_once_with(mock_events, vendor='okta', product='okta')


@freeze_time('2022-04-17T12:32:36.667Z')
@pytest.mark.parametrize("address, command", [
    ('https://testurl.com/api/v1/logs?sortOrder=ASCENDING&since=2022-04-16T12%3A32%3A36.667000&limit=5', 'okta-get-events'),
    ('https://testurl.com/api/v1/logs?sortOrder=ASCENDING&since=2022-04-17T11%3A32%3A36.667000&limit=5', 'test-module')
])
def test_okta_get_events(mocker, address, command):

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
    mocker.patch.object(demisto, 'command', return_value=command)
    mocker.patch.object(demisto, 'getLastRun', return_value={})
    mocker.patch.object(demisto, 'args', return_value={
        'from_date': '1 day',
        'should_push_events': True,
    })
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
    with requests_mock.Mocker() as m:
        m.get(
            address,
            json=mock_events)
        main()

    if command == 'test-module':
        send_events_to_xsiam_mock.assert_not_called()
    else:
        send_events_to_xsiam_mock.assert_called_once_with(mock_events, vendor='okta', product='okta')
