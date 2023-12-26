import GetIndicatorDBotScoreFromCache
import demistomock as demisto


def prepare_mocks(mocker, values, cache):
    def mock_search_iocs_results(values: list[str], cache: list[str]) -> dict:
        values_lower = [v.lower() for v in values]
        res = [{
            "value": v,
            "indicator_type": "IP",
            "score": 0,
            "expirationStatus": "inactive",
        } for v in cache if v.lower() in values_lower]
        return {"iocs": res}

    value = ",".join(values)
    mocker.patch.object(demisto, "args", return_value={"value": value})
    mocker.patch.object(demisto, "searchIndicators", return_value=mock_search_iocs_results(values, cache))
    mocker.patch.object(GetIndicatorDBotScoreFromCache, "return_results")


def test_all_inputs_exist_in_cache(mocker):
    """
    Given:
        A list of values, all of them exist in XSOAR cache.
    When:
        Running GetIndicatorDBotScoreFromCache script.
    Then:
        Ensure all of them are returned.
    """
    values = ["1.1.1.1", "1.1.1.1", "2.2.2.2"]
    cache = {"1.1.1.1", "2.2.2.2"}
    expected_found = {"1.1.1.1", "2.2.2.2"}
    prepare_mocks(mocker, values, cache)

    GetIndicatorDBotScoreFromCache.main()
    return_results_calls = GetIndicatorDBotScoreFromCache.return_results.call_args_list

    indicators_results = return_results_calls[0][0][0]["Contents"]
    assert {i["Indicator"] for i in indicators_results} == expected_found


def test_some_inputs_exist_in_cache_and_one_doesnt(mocker):
    """
    Given:
        A list of values:
        - Two of them (1.1.1.1 and 2.2.2.2) exist in the cache
        - One input (1.1.1.1) is duplicated.
        - One input (3.3.3.3) is not in cache.
    When:
        Running GetIndicatorDBotScoreFromCache script.
    Then:
        - Ensure the existing inputs are returned without duplicates.
        - Ensure the single non-existing input is returned as not found.
    """
    values = ["1.1.1.1", "1.1.1.1", "2.2.2.2", "3.3.3.3"]
    cache = {"1.1.1.1", "2.2.2.2"}
    expected_found = {"1.1.1.1", "2.2.2.2"}
    expected_not_found = {"3.3.3.3"}
    prepare_mocks(mocker, values, cache)

    GetIndicatorDBotScoreFromCache.main()
    return_results_calls = GetIndicatorDBotScoreFromCache.return_results.call_args_list

    indicators_results = return_results_calls[0][0][0]["Contents"]
    assert {i["Indicator"] for i in indicators_results} == expected_found

    not_found_results = return_results_calls[1][0][0]
    assert all(i in not_found_results for i in expected_not_found)


def test_some_inputs_exist_in_cache_and_multiple_dont(mocker):
    """
    Given:
        A list of values:
        - Two of them (1.1.1.1, 2.2.2.2) exist in the cache
        - Two inputs (3.3.3.3, 4.4.4.4) are not in cache.
    When:
        Running GetIndicatorDBotScoreFromCache script.
    Then:
        - Ensure the two existing inputs are returned without duplicates.
        - Ensure the two non-existing inputs are returned as not found.
    """
    values = ["1.1.1.1", "2.2.2.2", "3.3.3.3", "4.4.4.4"]
    cache = {"1.1.1.1", "2.2.2.2"}
    expected_found = {"1.1.1.1", "2.2.2.2"}
    expected_not_found = {"3.3.3.3", "4.4.4.4"}
    prepare_mocks(mocker, values, cache)

    GetIndicatorDBotScoreFromCache.main()
    return_results_calls = GetIndicatorDBotScoreFromCache.return_results.call_args_list

    indicators_results = return_results_calls[0][0][0]["Contents"]
    assert {i["Indicator"] for i in indicators_results} == expected_found

    not_found_results = return_results_calls[1][0][0]["Contents"]
    assert all(i in not_found_results for i in expected_not_found)


def test_no_inputs_in_cache(mocker):
    """
    Given:
        A list of values, non of them is in the cache.
        The input consists of a single duplicated input (3.3.3.3)
    When:
        Running GetIndicatorDBotScoreFromCache script.
    Then:
        Ensure the two non-existing inputs are returned as not found.
    """
    values = ["3.3.3.3", "3.3.3.3"]
    cache = {"1.1.1.1", "2.2.2.2"}
    expected_not_found = {"3.3.3.3"}
    prepare_mocks(mocker, values, cache)

    GetIndicatorDBotScoreFromCache.main()
    return_results_calls = GetIndicatorDBotScoreFromCache.return_results.call_args_list

    not_found_results = return_results_calls[0][0][0]
    assert all(i in not_found_results for i in expected_not_found)


def test_multiple_iocs_with_same_value_but_different_casing(mocker):
    """
    Given:
        A single indicator value (Test.com).
    When:
        Running GetIndicatorDBotScoreFromCache script.
    Then:
        Ensure all IOCs with the same value but different casing are returned.
    """
    values = ["Test.com"]
    cache = {"test.com", "TEST.com", "should_not_return_this"}
    expected_found = {"test.com", "TEST.com"}
    prepare_mocks(mocker, values, cache)

    GetIndicatorDBotScoreFromCache.main()
    return_results_calls = GetIndicatorDBotScoreFromCache.return_results.call_args_list

    indicators_results = return_results_calls[0][0][0]["Contents"]
    assert {i["Indicator"] for i in indicators_results} == expected_found


def test_query_values(mocker):
    """
    Given:
        An array of indicator value (Test~.com, Test2~.com).
    When:
        Running GetIndicatorDBotScoreFromCache script.
    Then:
        Ensure all values in the query to demisto.searchIndicators has \".
    """
    mocker.patch.object(demisto, "args", return_value={"value": "Test~.com, Test2~.com"})
    mocker.patch.object(demisto, "searchIndicators")
    GetIndicatorDBotScoreFromCache.main()
    args_list = demisto.searchIndicators.call_args_list
    call_query = args_list[0][1]['query']
    assert call_query in [
        'value:("test2~.com" "test~.com")',
        'value:("test~.com" "test2~.com")',
    ]
