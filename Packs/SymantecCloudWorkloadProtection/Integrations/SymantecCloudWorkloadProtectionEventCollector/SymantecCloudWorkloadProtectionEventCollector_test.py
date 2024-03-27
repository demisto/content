from CommonServerPython import *


def load_json(filename: str):
    with open(f'test_data/{filename}.json') as f:
        return json.load(f)


EVENTS = load_json('events')


def mock_request_func(data: dict) -> dict:
    def _mock_request_func(pageSize, pageNumber, startDate, endDate, order) -> dict:
        start_from = pageSize * pageNumber
        res = filter((lambda x: startDate <= x['time'] < endDate), EVENTS)  # type: ignore
        res = sorted(res, key=lambda x: x['time'], reverse={'ASCENDING': False}[order])  # type: ignore
        res = res[start_from:start_from + pageSize]
        return {'result': res, 'total': len(res)}
    return _mock_request_func(**data)


def test_pagination_fetch():

    import SymantecCloudWorkloadProtectionEventCollector as scp

    scp.API_LIMIT = 3
    client = scp.Client(None)
    client.max_fetch = 10  # len(EVENTS)

    last_date = '2022-01-01T00:00:00.00Z'

    result = client._pagination_fetch(mock_request_func, last_date)

    assert result == EVENTS[:10]


def test_manage_duplicates():

    from SymantecCloudWorkloadProtectionEventCollector import Client

    objects, last_run = Client(None)._manage_duplicates(EVENTS, [0, 1, 2])

    assert objects == EVENTS[3:]
    assert last_run['last_date'] == '2023-01-08T00:00:00.00Z'
    assert last_run['last_synchronous_ids'] == [19]
