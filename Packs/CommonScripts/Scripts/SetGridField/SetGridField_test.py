import json
import pytest


def util_load_json(path):
    path = f'./test_data/{path}'
    with open(path, encoding='utf-8') as f:
        return json.loads(f.read())


@pytest.mark.parametrize(argnames="phrase, norm_phrase",
                         argvalues=[("TestPhrase", "testphrase"),
                                    ("Test_phrase", "testphrase"),
                                    ("test_phrase", "testphrase")])
def test_normalized_string(phrase: str, norm_phrase: str):
    from SetGridField import normalized_string
    assert norm_phrase == normalized_string(phrase)


@pytest.mark.parametrize(
    argnames="before_dict, keys, max_keys, after_dict",
    argvalues=[
        ({'a': 1, 'b': 2}, ['a'], None, {'a': 1}),
        ({'a': 1, 'b': 2}, ['*'], 1, {'a': 1}),
        ({'a': 1, 'b': 2}, ['*'], 2, {'a': 1, 'b': 2}),
        ({'a': 1, 'b': [1, 2, 3]}, ['a'], None, {'a': 1}),
    ])
def test_filter_the_dict(before_dict: dict, keys: dict, max_keys: int, after_dict: dict):
    from SetGridField import filter_dict
    assert after_dict == filter_dict(dict_obj=before_dict,
                                     keys=keys,
                                     max_keys=max_keys)


@pytest.mark.parametrize(argnames="entry_context, raise_exception, unpack_nested",
                         argvalues=[
                             ([{'a': 'val', 'b': 'val'}], False, False),
                             ([{'a': [], 'b': 'val'}], False, False),
                             ([{'a': [], 'b': 'val'}], False, False),
                             (['a', 'b', 1, False], False, False),
                             (['a', 'b', 1, False, [{}, 'a']], True, False),
                         ])
def test_validate_entry_context(capfd, entry_context: dict, raise_exception: bool, unpack_nested: bool):
    from SetGridField import validate_entry_context
    if raise_exception:
        # disabling the stdout check cause along with the exception, we write additional data to the log.
        with pytest.raises(ValueError), capfd.disabled():
            validate_entry_context(context_path='Path',
                                   entry_context=entry_context,
                                   unpack_nested_elements=unpack_nested)
    else:
        validate_entry_context(context_path='Path',
                               entry_context=entry_context,
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
                              "context_entry_list_of_dicts.json", "expected_list_of_dicts_grid.json", False),
                             (["firstname", "lastname", "email", "phones"], ["Fname", "Lname", "Email", "Phones"],
                              "context_entry_list_of_dicts_complex.json", "expected_list_of_dicts_complex.json", False)
                         ])
def test_build_grid(mocker, keys: list, columns: list, dt_response_json: str, expected_json: str,
                    unpack_nested: bool):
    """Unit test
    Given
    - script args
    - a file
    When
    - build_grid command
    Then
    - Validate that the grid was created with the correct column names
    """
    import SetGridField
    import pandas as pd

    mocker.patch.object(SetGridField, 'demisto')
    SetGridField.demisto.dt.return_value = util_load_json(dt_response_json)
    expected_grid = util_load_json(expected_json)

    assert pd.DataFrame(expected_grid).to_dict() == SetGridField.build_grid(
        context_path=mocker.MagicMock(), keys=keys, columns=columns, unpack_nested_elements=unpack_nested, keys_from_nested=["*"]
    ).to_dict()


very_long_column_name = 11 * "column_name_OF_LEN_264__"


@pytest.mark.parametrize(argnames="keys, columns, unpack_nested_elements, dt_response_path, expected_results_path",
                         argvalues=[
                             (["name", "value"], ["col!@#$%^&*()ע_1", very_long_column_name], False,
                              'context_entry_list_missing_key.json',
                              'expected_list_grid_none_value.json')
                         ])
def test_build_grid_command(mocker, keys: list[str], columns: list[str], unpack_nested_elements: bool,
                            dt_response_path: str, expected_results_path: str):
    """Unit test
    Given
    - script args
    - a file
    When
    - build_grid_command command
    Then
    - Validate that the grid was created with the correct column names
    """
    import json
    import SetGridField
    mocker.patch.object(SetGridField, 'get_current_table', return_value=[])
    mocker.patch.object(SetGridField, 'demisto')
    SetGridField.demisto.dt.return_value = util_load_json(dt_response_path)

    results = SetGridField.build_grid_command(grid_id='test', context_path=mocker.MagicMock(), keys=keys,
                                              columns=columns, overwrite=True, sort_by=None,
                                              unpack_nested_elements=unpack_nested_elements, keys_from_nested=["*"])

    expected_results = util_load_json(expected_results_path)
    assert json.dumps(results) == json.dumps(expected_results)


@pytest.mark.parametrize(argnames="keys, columns, unpack_nested_elements, dt_response_path, expected_results_path",
                         argvalues=[
                             (["firstname", "lastname", "email"], ["fname", "lname", "email"], False,
                              'context_entry_list_of_dicts_non_sorted.json', 'expected_entry_list_of_dicts_sorted.json')
                         ])
def test_build_grid_command_with_sort_by(mocker, keys: list[str], columns: list[str],
                                         unpack_nested_elements: bool, dt_response_path: str,
                                         expected_results_path: str):
    """Unit test
    Given
    - script args, including sort_by
    - a file
    When
    - build_grid_command command
    Then
    - Validate that the grid was created with the correct column names and sorted correctly
    """
    import json
    import SetGridField
    mocker.patch.object(SetGridField, 'get_current_table', return_value=[])
    mocker.patch.object(SetGridField, 'demisto')

    SetGridField.demisto.dt.return_value = util_load_json(dt_response_path)

    results = SetGridField.build_grid_command(grid_id='test', context_path=mocker.MagicMock(), keys=keys,
                                              columns=columns, overwrite=True, sort_by=['fname'],
                                              unpack_nested_elements=unpack_nested_elements, keys_from_nested=["*"])

    expected_results = util_load_json(expected_results_path)
    assert json.dumps(results) == json.dumps(expected_results)


@pytest.mark.parametrize(argnames="keys, columns, unpack_nested_elements, dt_response_path, expected_results_path",
                         argvalues=[
                             (["col1", "col2"], ["col1", "col2"], False,
                              'context_entry_list_of_dicts_non_sorted_multi.json',
                              'expected_entry_list_of_dicts_sorted_multi.json')
                         ])
def test_build_grid_command_with_multi_sort_by(mocker, keys: list[str], columns: list[str],
                                               unpack_nested_elements: bool, dt_response_path: str,
                                               expected_results_path: str):
    """Unit test
    Given
    - script args, including multi sort_by cols
    - a file
    When
    - build_grid_command command
    Then
    - Validate that the grid was created with the correct column names and sorted correctly
    """
    import json
    import SetGridField
    mocker.patch.object(SetGridField, 'get_current_table', return_value=[])
    mocker.patch.object(SetGridField, 'demisto')

    SetGridField.demisto.dt.return_value = util_load_json(dt_response_path)
    results = SetGridField.build_grid_command(grid_id='test', context_path=mocker.MagicMock(), keys=keys,
                                              columns=columns, overwrite=True, sort_by=['col1', 'col2'],
                                              unpack_nested_elements=unpack_nested_elements, keys_from_nested=["*"])

    expected_results = util_load_json(expected_results_path)
    assert json.dumps(results) == json.dumps(expected_results)
