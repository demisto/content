import json
from importlib import import_module
from test_data.feed_data import RESPONSE_DATA
from FeedORKL import Client, fetch_indicator_command

FeedORKL = import_module('FeedORKL')
main = FeedORKL.main


def util_load_json(path):
    with open(path, encoding='utf-8') as f:
        return json.loads(f.read())


def test_fetch_integration(requests_mock):
    requests_mock.get('https://orkl.eu/api/v1/library/entries?order_by=file_creation_date&limit=1&offset=0&order=desc',
                      json=RESPONSE_DATA)

    client = Client(verify=False)
    params = {
        'feedTags': 'Test Tag',
        'tlp_color': 'RED',
        'limit': 1,
        'createRelationships': 'true',
        'feedReliability': 'C - Fairly reliable'
    }

    indicators = fetch_indicator_command(
        client,
        params.get('feedTags'),
        params.get('tlp_color'),
        params.get('limit'),
        params.get('createRelationships'),
        params.get('feedReliability')
    )

    assert len(indicators) == 47

    for indicator in indicators:
        if indicator.get('value') == 'ALPHVM':
            assert indicator.get('source') == 'ORKL Feed'
            break
