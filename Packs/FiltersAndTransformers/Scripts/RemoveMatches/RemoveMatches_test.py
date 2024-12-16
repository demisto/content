from RemoveMatches import filter_items
import pytest


@pytest.mark.parametrize("filter_list, values, ignore_case, match_exact, output",
                         [(['ValueA', 'ValueB'], ['ValueA', 'ValueB', 'ValueC'], True, True, ['ValueC']),
                          (['valueA', 'ValueB'], ['ValueA', 'ValueB', 'ValueC'], False, True, ['ValueA', 'ValueC']),
                          (['Value(A|B)'], ['ValueA', 'ValueB', 'ValueC'], True, False, ['ValueC']),
                          (['value(A|B)'], ['ValueA', 'ValueB', 'ValueC'], False, False, ['ValueA', 'ValueB', 'ValueC'])])
def test_filter_items(filter_list: list[str], values: list, ignore_case: bool, match_exact: bool, output: list):
    result = filter_items(values, filter_list=filter_list, ignore_case=ignore_case, match_exact=match_exact)
    assert result == output
