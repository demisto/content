from FireEyeHelix import build_search_groupby_result
from test_data.constants import EXPECTED_AGGREGATIONS_SINGLE_RESULT, SEARCH_AGGREGATIONS_SINGLE, \
    EXPECTED_AGGREGATIONS_MULTI_RESULT, SEARCH_AGGREGATIONS_MULTI


def test_build_search_groupby_result():
    separator = '|%$,$%|'
    assert build_search_groupby_result(SEARCH_AGGREGATIONS_SINGLE, separator) == EXPECTED_AGGREGATIONS_SINGLE_RESULT
    assert build_search_groupby_result(SEARCH_AGGREGATIONS_MULTI, separator) == EXPECTED_AGGREGATIONS_MULTI_RESULT
