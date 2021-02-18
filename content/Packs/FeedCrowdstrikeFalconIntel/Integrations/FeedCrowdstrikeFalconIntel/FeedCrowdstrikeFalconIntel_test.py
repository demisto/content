import pytest
import json
from FeedCrowdstrikeFalconIntel import Client


def get_fetch_data():
    with open('./test_data.json', 'r') as f:
        return json.loads(f.read())


indicators = get_fetch_data()


@pytest.mark.parametrize(
    "params, actors_filter, expected",
    [
        ({}, '', '/intel/combined/actors/v1'),
        ({}, 'blabla', '/intel/combined/actors/v1blabla'),
        ('last_modified_date%3A%3E{relevant_time}', 'blabla',
         '/intel/combined/actors/v1blabla%2Blast_modified_date%3A%3E{relevant_time}'),
        ('last_modified_date%3A%3E{relevant_time}', '',
         '/intel/combined/actors/v1?filter=last_modified_date%3A%3E{relevant_time}')
    ]
)
def test_build_url_suffix(params, actors_filter, expected):
    res = Client.build_url_suffix(Client, params, actors_filter)
    assert res == expected


def test_create_indicators_from_response():
    res = Client.create_indicators_from_response(Client, indicators["list_data_cs"], {}, 'AMBER')
    assert res == indicators["expected_list"]
