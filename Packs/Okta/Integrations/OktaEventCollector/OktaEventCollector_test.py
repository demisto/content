from OktaEventCollector import ReqParams, Client, Request, GetEvents, Method
import pytest

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


@pytest.mark.parametrize("events,result", [
    ([{'published': '2022-04-17T12:31:36.667',
       'uuid': '1d0844b6-3148-11ec-9027-a5b57ec5faaa'},
      {'published': '2022-04-17T12:32:36.667',
       'uuid': '1d0844b6-3148-11ec-9027-a5b57ec5fbbb'},
      {'published': '2022-04-17T12:33:36.667',
       'uuid': '1d0844b6-3148-11ec-9027-a5b57ec5fccc'}],
     {'after': '2022-04-17T12:33:36.667000', 'ids': ['1d0844b6-3148-11ec-9027-a5b57ec5fccc']}),
    ([{'published': '2022-04-17T12:31:36.667',
       'uuid': '1d0844b6-3148-11ec-9027-a5b57ec5faaa'},
      {'published': '2022-04-17T12:32:36.667',
       'uuid': '1d0844b6-3148-11ec-9027-a5b57ec5fbbb'},
      {'published': '2022-04-17T12:32:36.667',
       'uuid': '1d0844b6-3148-11ec-9027-a5b57ec5fccc'}], {'after': '2022-04-17T12:32:36.667000',
                                                          'ids': ['1d0844b6-3148-11ec-9027-a5b57ec5fccc',
                                                                  '1d0844b6-3148-11ec-9027-a5b57ec5fbbb']})])
def test_get_last_run(events, result):
    assert get_events.get_last_run(events) == result


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
