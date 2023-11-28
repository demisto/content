import json
from importlib import import_module
from test_data.feed_data import RESPONSE_DATA
from FeedORKL import Client, fetch_indicator_command, get_reports_command

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


def test_get_reports_command(requests_mock):
    requests_mock.get('https://orkl.eu/api/v1/library/entries?order_by=created_at&limit=1&offset=0&order=desc',
                      json=RESPONSE_DATA)

    expected_human_readable = (
        "### ORKL Reports\n"
        "|Created At|Report Name|Source|References|Threat Actors|\n"
        "|---|---|---|---|---|\n"
        "| 2023-11-18T02:07:23.236896Z | Scattered Spider | Malpedia | "
        "https://www.cisa.gov/sites/default/files/2023-11/aa23-320a_scattered_spider.pdf | "
        "ETDA:ALPHV,<br>ETDA:Muddled Libra,<br>ETDA:Lead,<br>MITRE:Scattered Spider,<br>"
        "MISPGALAXY:Scattered Spider,<br>ETDA:Scattered Spider,<br>Secureworks:GOLD HARVEST |\n"
    )

    client = Client(verify=False)
    params = {
        'feedTags': 'Test Tag',
        'tlp_color': 'RED',
        'limit': 1,
        'createRelationships': 'true',
        'feedReliability': 'C - Fairly reliable'
    }
    reports = get_reports_command(client=client, limit=params.get('limit'), order_by='created_at', order='desc')
    assert reports.readable_output == expected_human_readable
