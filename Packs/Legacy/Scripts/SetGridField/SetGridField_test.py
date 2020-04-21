import pytest
from typing import Optional, List, Dict
import numpy as np


@pytest.mark.parametrize(argnames="sort_by, columns, exp_columns, exp_exception",
                         argvalues=[
                             ('header1', 'header1,header2', ['header1', 'header2'], False),
                             ('header3', 'header1,header2', ['header1', 'header2'], True),
                             ('header1', '', ['header1', 'header2'], True)
                         ])
def test_get_current_table(mocker, sort_by: Optional[str], columns: str, exp_columns: List[str], exp_exception: bool):
    from SetGridField import get_current_table
    mock = mocker.patch('SetGridField.demisto.incidents')
    if exp_exception:
        with pytest.raises(ValueError):
            get_current_table(grid_id='mygrid',
                              sort_by=sort_by,
                              columns=columns)
    else:
        assert mock, exp_columns == get_current_table(grid_id='mygrid',
                                                      sort_by=sort_by,
                                                      columns=columns)


@pytest.mark.parametrize(argnames='obj_dict, keys, exp_dict',
                         argvalues=[
                             ({'a': 1, 'b': 2}, ['a'], {'a': 1}),
                             ({'b': 2, 'a': 1}, ['a', 'b'], {'a': 1, 'b': 2}),
                             ({'b': 2}, ['a', 'b'], {'a': '', 'b': 2})
                         ])
def test_populate_dict(obj_dict: Dict[str, str], keys: List[str], exp_dict: Dict[str, str]):
    from SetGridField import populate_dict
    assert exp_dict == populate_dict(obj_dict=obj_dict, keys=keys)


@pytest.mark.parametrize(argnames='data, exp_data',
                         argvalues=[
                             (np.array([['a'], ['b', 'c']]), np.array([['a', ''], ['b', 'c']])),
                             (np.array([['a', 'b'], ['c']]), np.array([['a', 'b'], ['c', '']]))
                         ])
def test_numpy_fillna(data: np.ndarray, exp_data: np.ndarray):
    from SetGridField import numpy_fillna
    assert exp_data.tolist() == numpy_fillna(data=data).astype(np.str).tolist()


@pytest.mark.parametrize(argnames="entry_context, context_paths, row_correlation, expected",
                         argvalues=[
                             (
                                     {'a': {'b': {'c': 1}}}, "a.b.c", True, [{'c': 1}]
                             ),
                             (
                                     {'a': {'b': [{'c': 1}, {'c': 2}]}}, "a.b.c", True, [{'c': 1}, {'c': 2}]
                             ),
                             (
                                     {'a': {'b': [{'c': 1}, {'d': 2}]}}, "a.b.c, a.b.d", True, [{'c': 1, 'd': ''},
                                                                                                {'c': '', 'd': 2}]
                             ),
                             (
                                     {}, "a.b, a.b", "c, d", []
                             ),
                         ])
def test_get_data_from_entry_context(mocker, entry_context, context_paths: str, row_correlation: bool, expected: List):
    import SetGridField
    from numpy import array as np_array
    mocker.patch('SetGridField.demisto.context')
    SetGridField.demisto.context.return_value = entry_context
    assert expected == SetGridField.get_data_from_entry_context(context_paths=context_paths,
                                                                row_correlation=row_correlation)
