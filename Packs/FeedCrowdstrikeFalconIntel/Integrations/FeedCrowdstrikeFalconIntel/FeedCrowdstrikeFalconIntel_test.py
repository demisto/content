import pytest
from FeedCrowdstrikeFalconIntel import Client

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
