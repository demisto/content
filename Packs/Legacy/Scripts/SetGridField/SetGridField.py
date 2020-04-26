# STD Libaries
from typing import Optional, Union, List, Dict, Tuple, Any
# 3-rd party libaries
import numpy as np
import pandas as pd
from jsonpath_ng import parse
import phrases_case
# Local packages
import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *


def normalized_string(phrase: str) -> str:
    return phrases_case.camel(phrase).replace("'", "").lower()

def get_current_table(grid_id: str, sort_by: Optional[str], columns: Optional[str], context_paths: str) -> \
        Tuple[List[Dict[Any, Any]], Any]:
    """ Get current grid data

    Data retreived:
        1. Column names.
        2. Current grid data.
    Validate:
        1. Correct number of context paths.
        2. Sort_by is a name of a column.
        3. Grid ID.
        4. Columns exists.

     Args:
        grid_id(str): Normalized Grid ID (Machine name in `Settings -> Advanced -> Fields -> Field property` or in Incident
                      Context Data.
        sort_by(str): The static name of the column to sort the table rows by.
        columns(str): Comma separated list of columns names, Should be defined if grid is empty otherwise the automation
                      detect it automatically.
        context_paths(str): Context path to build the Table from, If the Table is row correlated, The path until the last
                            key should be the same for all paths, In addition the number of the given paths should be the
                            same as the columns number in the original grid, because the grid column is immutable.

     Returns:
        list: Current grid as dict in following structure - [{'col1': 'val1'},{'col2': 'val2'},{'col3': 'val3'},
              {'col4': 'val4'}].
        list: Table columns name.
     """
    # Get current Grid data
    current_table: Optional[List[dict]] = demisto.incidents()[0].get("CustomFields", {}).get(grid_id)
    if not current_table:
        raise ValueError(f"The grid id isn't valid: {grid_id}")
    # Validate columns number the same as context paths - If no data initiated skip validation, but check if columns specified
    columns_list = [normalized_string(phrase) for phrase in argToList(columns)]
    if len(columns_list) == len(argToList(context_paths)):
        raise ValueError("Columns not specified correctly!")
    # Validate sort is valide col
    if sort_by and sort_by not in columns:
        raise ValueError(f'sort_by: {sort_by} is not columns: {columns}')

    return current_table, columns


def populate_dict(obj_dict: Dict[str, str], keys: List[str]) -> Dict[str, str]:
    """ Populate dict with missing keys if not exists using empty string - used for saving on row correlation.

    Args:
        obj_dict: dict to validate.
        keys: keys to validate

    Returns:
        dict: Full dictionary.

    Examples:
        >>> populate_dict(obj_dict={'a': 1, 'b': 2}, keys=['a', 'b', 'c'])
        {'a': 1, 'b': 2, 'c': ''}
    """
    obj_dict_keys = list(obj_dict.keys())
    # Remove unwanted keys
    for key in obj_dict_keys:
        if key not in keys:
            obj_dict.pop(key)
    # Add missing keys
    for key in keys:
        if key not in obj_dict_keys:
            obj_dict[key] = ''
    # Orgenize keys
    new_obj_dict = {}
    for key in keys:
        new_obj_dict[key] = obj_dict[key]

    return new_obj_dict


def numpy_fillna(data: np.ndarray) -> np.ndarray:
    """ Fill missing rows with empty strings in order to complete to full table size (if row isn't in full length complete, it
        will complete to full size.

    Args:
        data(np.ndarray): data to evaluate and complete.

    Returns:
        np.ndarray: Filled table.
    """
    # Get lengths of each row of data
    lens = np.array([len(i) for i in data])
    # Mask of valid places in each row
    mask = np.arange(lens.max()) < lens[:, None]
    # Setup output array and put elements from data into masked positions
    out = np.zeros(mask.shape, dtype=data.dtype)
    out[mask] = np.concatenate(data)
    out[out == 0] = ''

    return out


def get_data_from_entry_context(context_paths: str, row_correlation: bool) -> Union[np.ndarray, list]:
    """ Build ndarray from Entry context.

     Args:
        context_paths(str): Context path to build the Table from, If the Table is row correlated, The path until the last
                            key should be the same for all paths, In addition the number of the given paths should be the
                            same as the columns number in the original grid, because the grid column is immutable.
        row_correlation(bool): True if the rows correlated (represent an object/item), else False.
     Returns:
         np.ndarray || list : table built from Entry Context.
     """
    context_paths_list: List[str] = argToList(context_paths)
    if row_correlation:
        # Get and validate Data when rows correlated
        correlated_keys = []
        absolute_path = ''
        # Vaidation of path in the same item/object
        for context_path in context_paths_list:
            splited_path = context_path.split('.')
            if splited_path:
                current_absolute_path = '..'.join(splited_path[:-1])
                if absolute_path:
                    if absolute_path != current_absolute_path:
                        raise ValueError(
                            f'Unable to correlate rows due to keys not in the same context path {current_absolute_path}')
                else:
                    absolute_path = current_absolute_path
                correlated_keys.append(splited_path[-1])
            else:
                raise ValueError(f'Unable to correlate rows due to not valid context path {context_path}')
        # Search for requested data
        jsonpath_expression = parse(f'{absolute_path}.[*]')
        data = [populate_dict(obj_dict=item.value, keys=correlated_keys) for item in jsonpath_expression.find(demisto.context())]

        return data
    else:
        # Get Data when rows not correlated
        data = []
        for context_path in context_paths_list:
            jsonpath_expression = parse(context_path.replace('.', '.[*].'))
            data.append(np.array([item.value for item in jsonpath_expression.find(demisto.context())]))

        return numpy_fillna(np.array(data))


def build_table(data: Union[List[Dict[Any, Any]], Any], columns: List[str], sort_by: Optional[str],
                overwrite: bool, current_table: List[Dict[Any, Any]]) -> List[Dict[Any, Any]]:
    """ Build updated table

    Args:
        data(np.ndarray || list): Data to add to the grid.
        columns(list): Columns name.
        sort_by(str): The static name of the column to sort the table rows by.
        overwrite(bool): True if to overwrite current grid, False in order to append data.
        current_table: Current grid/table data.

    Returns:
        list: updated to table.
    """
    # Create new Table
    demisto.results(str(data))
    if isinstance(data[0], dict):
        table = pd.DataFrame.from_dict(data=data)
        table.columns = columns
    elif isinstance(data[0], np.ndarray):
        table = pd.DataFrame(data=data.T,  # type: ignore
                             columns=columns)
    else:
        raise ValueError('No valid values')
    # Sort table if mentioned
    if sort_by:
        demisto.results(table)
        table.sort_values(by=sort_by)
    # Change to Grid form
    table = table.to_dict('records')
    # Overwrite data if specified
    if not overwrite:
        table.append(current_table)

    return table


def build_grid_command(grid_id: str, context_paths: str, sort_by: Optional[str], row_correlation: bool, overwrite: bool,
                       columns: Optional[str]) -> List[Dict[str, str]]:
    """ Build Table as dictionary for populate grid in incident layout.

    The required table structure to populate in the incident is as follow:
    [{'col1': 'val1', 'col2': 'val2'}, {'col1': 'val3', 'col2': 'val4'}] which represent:
    | col1 | col2 |
    | ---- | ---- |
    | val1 | val2 |
    | val3 | val4 |

    Args:
        grid_id(str): Normalized Grid ID (Machine name in `Settings -> Advanced -> Fields -> Field property` or in Incident
                      Context Data.
        context_paths(str): Context path to build the Table from, If the Table is row correlated, The path until the last
                            key should be the same for all paths, In addition the number of the given paths should be the
                            same as the columns number in the original grid, because the grid column is immutable.
        sort_by(str): The static name of the column to sort the table rows by.
        row_correlation(bool): True if the rows correlated (represent an object/item), else False.
        overwrite(bool): True if to overwrite current grid, False in order to append data.
        columns(str): Comma separated list of columns names, Should be defined if grid is empty otherwise the automation
                      detect it automatically.

    Returns:
        dict: Table dictianary as shown above in explaination.
    """
    current_table, columns = get_current_table(grid_id=grid_id,
                                               sort_by=sort_by,
                                               columns=columns,
                                               context_paths=context_paths)
    data = get_data_from_entry_context(context_paths=context_paths,
                                       row_correlation=row_correlation)
    table = build_table(data=data,
                        columns=columns,
                        sort_by=sort_by,
                        overwrite=overwrite,
                        current_table=current_table)

    return table


def main():
    try:
        # Normalize grid id from any form to connected lower words, e.g. my_word/myWord -> myword
        grid_id = normalized_string(demisto.getArg('grid_id'))
        # Build updated table
        table = build_grid_command(grid_id=grid_id,
                                   context_paths=demisto.getArg('context_paths'),
                                   row_correlation=False if demisto.getArg('row_correlation') == 'false' else True,
                                   sort_by=demisto.getArg('sort_by'),
                                   overwrite=False if demisto.getArg('overwrite') == 'false' else True,
                                   columns=demisto.getArg('columns'))
        # Execute automation 'setIncident` which change the Context data in the incident
        demisto.executeCommand("setIncident",
                               {
                                   'customFields':
                                       {
                                           grid_id: table
                                       }
                               })
    except Exception as e:
        return_error(f'Failed to execute setGridField. Error: {str(e)}')


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
