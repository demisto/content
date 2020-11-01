import pytest
from typing import List


@pytest.mark.parametrize(argnames="phrase, norm_phrase",
                         argvalues=[("TestPhrase", "testphrase"),
                                    ("Test_phrase", "testphrase"),
                                    ("test_phrase", "testphrase")])
def test_normalized_string(phrase: str, norm_phrase: str):
    from SetGridField import normalized_string
    assert norm_phrase == normalized_string(phrase)


@pytest.mark.parametrize(argnames="before_dict, keys, max_keys, after_dict",
                         argvalues=[
                             ({'a': 1, 'b': 2}, ['a'], None, {'a': 1}),
                             ({'a': 1, 'b': 2}, ['*'], 1, {'a': 1}),
                             ({'a': 1, 'b': 2}, ['*'], 2, {'a': 1, 'b': 2})
                         ])
def test_filter_the_dict(before_dict: dict, keys: dict, max_keys: int, after_dict: dict):
    from SetGridField import filter_dict
    assert after_dict == filter_dict(dict_obj=before_dict,
                                     keys=keys,
                                     max_keys=max_keys)


@pytest.mark.parametrize(argnames="entry_context, keys, raise_exception, unpack_nested",
                         argvalues=[
                             ([{'a': 'val', 'b': 'val'}], ['a', 'b'], False, False),
                             ([{'a': [], 'b': 'val'}], ['a', 'b'], True, False),
                             ([{'a': [], 'b': 'val'}], ['b'], False, False),
                             (['a', 'b', 1, False], ['b'], False, False),
                             (['a', 'b', 1, False, []], ['*'], True, False),
                         ])
def test_validate_entry_context(entry_context: dict, keys: list, raise_exception: bool, unpack_nested: bool):
    from SetGridField import validate_entry_context
    if raise_exception:
        with pytest.raises(ValueError):
            validate_entry_context(entry_context=entry_context,
                                   keys=keys,
                                   unpack_nested_elements=unpack_nested)
    else:
        validate_entry_context(entry_context=entry_context,
                               keys=keys,
                               unpack_nested_elements=unpack_nested)


@pytest.mark.parametrize(argnames="keys, columns, dt_response_json, expected_json, unpack_nested",
                         argvalues=[
                             (["name", "value"], ["col1", "col2"], "context_entry_list.json", "expected_list_grid.json",
                              False),
                             (["*"], ["col1", "col2"], "context_entry_dict.json", "expected_dict_grid.json", False),
                             (["*"], ["col1"], "context_entry_list_of_values.json", "expected_list_of_values_grid.json",
                              False),
                             (["*"], ["col1", "col2"], "context_entry_dict_with_elements.json",
                              "expected_dict_with_elements_grid.json", True),
                             (["firstname", "lastname", "email"], ["Fname", "Lname", "Email"],
                              "context_single_dict_with_keys.json", "expected_single_dict_with_keys_grid.json", False),
                             (["firstname", "lastname", "email"], ["Fname", "Lname", "Email"],
                              "context_entry_list_of_dicts.json", "expected_list_of_dicts_grid.json", False)
                         ])
def test_build_grid(datadir, mocker, keys: list, columns: list, dt_response_json: str, expected_json: str,
                    unpack_nested: bool):
    import SetGridField
    import json
    import pandas as pd

    mocker.patch.object(SetGridField, 'demisto')
    SetGridField.demisto.dt.return_value = json.load(open(datadir[dt_response_json]))
    expected_grid = json.load(open(datadir[expected_json]))
    assert pd.DataFrame(expected_grid).to_dict() == SetGridField.build_grid(
        context_path=mocker.MagicMock(), keys=keys, columns=columns, unpack_nested_elements=unpack_nested
    ).to_dict()


@pytest.mark.parametrize(argnames="keys, columns, unpack_nested_elements, dt_response_path, expected_results_path",
                         argvalues=[
                             (["name", "value"], ["col1", "col2"], False, 'context_entry_list_missing_key.json',
                              'expected_list_grid_none_value.json')
                         ])
def test_build_grid_command(datadir, mocker, keys: List[str], columns: List[str], unpack_nested_elements: bool,
                            dt_response_path: str, expected_results_path: str):
    import json
    import SetGridField
    mocker.patch.object(SetGridField, 'get_current_table', return_value=[])
    mocker.patch.object(SetGridField, 'demisto')
    SetGridField.demisto.dt.return_value = json.load(open(datadir[dt_response_path]))
    results = SetGridField.build_grid_command(grid_id='test', context_path=mocker.MagicMock(), keys=keys,
                                              columns=columns, overwrite=True, sort_by=None,
                                              unpack_nested_elements=unpack_nested_elements)
    expected_results = json.load(open(datadir[expected_results_path]))
    assert json.dumps(results) == json.dumps(expected_results)
