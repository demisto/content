import pytest
import io
import json
from CommonServerPython import *

from ReliaQuestGreyMatterDRPIncidents import \
    HttpRequestHandler, get_triage_item_events


class MockResponse:
    def __init__(self, data, status_code):
        self.data = data
        self.text = str(data)
        self.status_code = status_code


def util_load_json(path):
    with io.open(path, mode='r', encoding='utf-8') as f:
        return json.loads(f.read())


def util_load_response(path):
    with io.open(path, mode='r', encoding='utf-8') as f:
        return MockResponse(f.read(), 200)


DS_BASE_URL = 'https://portal-digitalshadows.com'
SECRETE_KEY = 'Zb9HEBwDg86TN1KNprHjkfipXmEDMb0gSCassK5T3ZfxsAbcgKVmAIXF7oZ6ItlZZbXO6idTHE67IM007EwQ4uN3'
ACCESS_KEY = 'DSAKJBFK'


def test_get_triage_item_events(request_mock):
    mock_response = util_load_json("test_data/get_triage_item_events.json")
    request_mock.get('/v1/triage-item-events', json=mock_response)
    client = HttpRequestHandler(DS_BASE_URL, '100000', ACCESS_KEY, SECRETE_KEY)
    response = get_triage_item_events(client)
    assert response != None
