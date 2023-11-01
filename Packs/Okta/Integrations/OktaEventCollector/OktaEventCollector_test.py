from OktaEventCollector import ReqParams, Client, Request, GetEvents, Method, main
import pytest
from freezegun import freeze_time
import demistomock as demisto

req_params = ReqParams(since='', sortOrder='ASCENDING', limit='5')
request = Request(method=Method.GET, url='https://testurl.com', headers={}, params=req_params)
client = Client(request)
get_events = GetEvents(client)
id1 = {'uuid': 'a5b57ec5febb'}
id2 = {'uuid': 'a5b57ec5fecc'}
id3 = {'uuid': 'a12f3c5d77f3'}
id4 = {'uuid': 'a12f3c5dxxxx'}


class MockResponse:
    def __init__(self, data):
        self.data = data

    def json(self):
        return self.data


@pytest.mark.parametrize("events,ids,result", [
    ([id1, id2, id3], ['a12f3c5d77f3'], [id1, id2]),
    ([id1, id2, id3], ['a12f3c5dxxxx'], [id1, id2, id3]),
    ([], ['a12f3c5d77f3'], []),
    ([{'uuid': 0}, {'uuid': 1}, {'uuid': 2}, {'uuid': 3}, {'uuid': 4}, {'uuid': 5}, {'uuid': 6}, {'uuid': 7},
      {'uuid': 8}, {'uuid': 9}], [0, 4, 7, 9],
     [{'uuid': 1}, {'uuid': 2}, {'uuid': 3}, {'uuid': 5}, {'uuid': 6}, {'uuid': 8}])])
def test_remove_duplicates(events, ids, result):
    assert get_events.remove_duplicates(events, ids) == result


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
    assert get_events.get_last_run(events, last_run_after) == result


@pytest.mark.parametrize("time", ['2022-04-17T12:32:36.667)'])
def test_set_since_value(time):
    req_params.set_since_value(time)
    assert req_params.since == time


def test_make_api_call(mocker):
    mock_res = MockResponse([{1}, {1}, {1}, {1}, {1}])
    mocker.patch.object(client, 'call', return_value=mock_res)
    assert get_events.make_api_call() == [{1}, {1}, {1}, {1}, {1}]
    mock_res.data = [{1}, {1}, {1}, {1}, {1}, {1}, {1}, {1}, {1}, {1}]
    assert get_events.make_api_call() == [{1}, {1}, {1}, {1}, {1}, {1}, {1}, {1}, {1}, {1}]


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
    requests_mock.get('https://testurl.com/api/v1/logs?since=2022-04-17T14%3A00%3A03.000Z&sortOrder=ASCENDING&limit=1',
                      status_code=429,
                      reason='Too many requests',
                      headers={
                          'x-rate-limit-remaining': '0',
                          'x-rate-limit-reset': '1698343702'
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
