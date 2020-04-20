import pytest
from typing import Optional, List


@pytest.mark.parametrize(argnames="grid_keys, grid_headers, expected",
                         argvalues=[
                             (
                                     "testName1, testName2, testName3",
                                     "gridTestName1, gridTestName2, gridTestName3",
                                     ["Grid test name1", "Grid test name2", "Grid test name3"]
                             ),
                             (
                                     "testName1, testName2, testName3",
                                     "",
                                     ["Test name1", "Test name2", "Test name3"]
                             ),
                             (
                                     "testName1, test_name2, testName3",
                                     "",
                                     ["Test name1", "Test name2", "Test name3"]
                             )
                         ])
def test_get_table_columns(grid_keys: str, grid_headers: Optional[str], expected: List[str]):
    from SetGridField import get_table_columns
    assert expected == get_table_columns(grid_headers=grid_headers,
                                         grid_keys=grid_keys)


@pytest.mark.parametrize(argnames="entry_context, context_keys, grid_keys, expected",
                         argvalues=[
                             (
                                     {'a': {'b': {'c': 1}}}, "a.b", "c", [1]
                             ),
                             (
                                     {'a': {'b': [{'c': 1}, {'c': 2}]}}, "a.b", "c", [1, 2]
                             ),
                             (
                                     {'a': {'b': [{'c': 1}, {'c': 2}]}}, "a", "c", []
                             ),
                             (
                                     {'a': {'b': [{'c': 1}, {'d': 2}]}}, "a.b, a.b", "c, d", [[1], [2]]
                             ),
                             (
                                     {}, "a.b, a.b", "c, d", []
                             ),
                         ])
def test_get_data_from_entry_context(mocker, entry_context, context_keys: str, grid_keys: str, expected: List):
    import SetGridField
    from numpy import array as np_array
    mocker.patch('SetGridField.demisto.context')
    SetGridField.demisto.context.return_value = entry_context
    assert np_array(expected).all() == SetGridField.get_data_from_entry_context(context_keys=context_keys,
                                                                                grid_keys=grid_keys).all()
