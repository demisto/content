import pytest
from freezegun import freeze_time
from SplunkPy_v2 import build_search_query, get_default_earliest_time


data_test_build_search_query = [
    ('', 'search '),
    ('test', 'search test'),
    ('search', 'search'),
    ('Search', 'Search'),
    ('|', '|'),
    ('test search', 'search test search'),
    ('test Search', 'search test Search'),
    ('test |', 'search test |')
]


@pytest.mark.parametrize('query, expected_query', data_test_build_search_query)
def test_build_search_query(query, expected_query):
    output = build_search_query(query)
    assert output == expected_query, f'build_search_query({query})\n\treturns: {output}\n\tinstead: {expected_query}'


@freeze_time("2020-03-26T00:00:00")
def test_get_default_earliest_time():
    expected_output = '2020-03-19T00:00:00'
    output = get_default_earliest_time()
    assert output == expected_output, f'get_default_earliest_time()\n\treturns: {output}\n\tinstead: {expected_output}'
