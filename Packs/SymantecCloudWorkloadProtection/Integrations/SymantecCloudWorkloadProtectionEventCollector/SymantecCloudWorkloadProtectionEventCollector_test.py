from CommonServerPython import *
import pytest


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

    assert result == EVENTS[10:]
