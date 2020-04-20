from typing import Optional, NoReturn, Union, List, Dict

import numpy as np
import pandas as pd
from jsonpath_ng import parse, jsonpath
import phrases_case

import demistomock as demisto
from CommonServerPython import *  # noqa: E402 lgtm [py/polluting-import]
from CommonServerUserPython import *  # noqa: E402 lgtm [py/polluting-import]


def get_table_columns(context_paths: str, headers: Optional[str], sort: Optional[str]) -> List[str]:
    """ Decide on column in table.

        If grid headers choose it else use grid keys and normalize strings by: CamelCase, SnakeCase, Capitalized

     Args:
        context_paths: Path to item to collext the keys from (e.g. Key1.Key2: [])
        headers: optinal headers for the girid.

     Returns:
         list: string representing the columns
     """
    columns: List[str] = argToList(context_paths.split('.')[-1]) if not headers else argToList(headers)
    columns = [phrases_case.space(header).capitalize() for header in columns]

    sort_by = ''
    if sort:
        sort_by = phrases_case.space(sort.split('.')[-1]).capitalize()

    return columns, sort_by


def get_data_from_entry_context(context_paths: str, row_correlated: bool, columns: List[str]) -> np.ndarray:
    """ Get data from Entry context

     Args:
         context_paths: Path to item to collext the keys from (e.g. Key1.Key2: [])
         row_correlated: True if the rows correlated, if a row has meaning for example representing object propertied.

     Returns:
         list: Data to DataFrame
     """
    context_paths_list: List[str] = argToList(context_paths)
    if row_correlated:
        correlated_keys = []
        absolute_path = ''
        for context_path in context_paths_list:
            splited_path = context_path.split('.')
            if splited_path:
                current_absolute_path = '.[*].'.join(splited_path[:-1])
                if absolute_path:
                    if absolute_path != current_absolute_path:
                        raise ValueError(
                            f'Unable to correlate rows due to keys not in the same context path {current_absolute_path}')
                else:
                    absolute_path = current_absolute_path
                correlated_keys.append(splited_path[-1])
            else:
                raise ValueError(f'Unable to correlate rows due to not valid context path {context_path}')

        jsonpath_expression_str = f'{absolute_path}.[*]'
        jsonpath_expression = parse(jsonpath_expression_str)

        return [populate_dict(item.value, correlated_keys) for item in jsonpath_expression.find(demisto.context())]
    else:
        data = []
        for context_path in context_paths_list:
            jsonpath_expression_str = context_path.replace('.', '.[*].')
            jsonpath_expression = parse(jsonpath_expression_str)
            data.append(np.array([item.value for item in jsonpath_expression.find(demisto.context())]))

        return numpy_fillna(np.array(data))


def populate_dict(obj_dict: Dict[str, str], correlated_keys: List[str]):
    obj_dict_keys = obj_dict.keys()
    for key in correlated_keys:
        if key not in obj_dict_keys:
            obj_dict[key] = ""
    return obj_dict


def numpy_fillna(data):
    # Get lengths of each row of data
    lens = np.array([len(i) for i in data])

    # Mask of valid places in each row
    mask = np.arange(lens.max()) < lens[:, None]

    # Setup output array and put elements from data into masked positions
    out = np.zeros(mask.shape, dtype=data.dtype)
    out[mask] = np.concatenate(data)
    out[out == 0] = ''

    return out


def build_table(data, columns, sort_by):
    if isinstance(data[0], dict):
        table = pd.DataFrame.from_dict(data=data)
        table.columns = columns
    elif isinstance(data[0], np.ndarray):
        table = pd.DataFrame(data=data.T,
                             columns=columns)
    else:
        raise ValueError('No valid values')

    if sort_by:
        table.sort_values(by=sort_by)

    return table


def build_grid_command(context_paths: str, row_correlated: bool, headers: Optional[str], sort: Optional[str]) -> str:
    """ Build markdown grid by user input.

    Args:
        context_paths: Path to item to collext the keys from (e.g. Key1.Key2: []).
        row_correlated: True if the rows correlated, if a row has meaning for example representing object propertied.
        headers: optinal headers for the girid.
        sort: The entry context path to sort the rows by.

    Returns:
        str: Markdown table
    """
    columns, sort_by = get_table_columns(context_paths=context_paths,
                                         headers=headers,
                                         sort=sort)
    data = get_data_from_entry_context(context_paths=context_paths,
                                       row_correlated=row_correlated,
                                       columns=columns)
    table = build_table(data=data,
                        columns=columns,
                        sort_by=sort_by)

    return table.to_markdown()


def main() -> Union[NoReturn, str]:
    try:
        markdown = build_grid_command(context_paths=demisto.getArg('context_paths'),
                                      headers=demisto.getArg('headers'),
                                      row_correlated=(False if demisto.getArg('correlated_row') == 'false' else True),
                                      sort=demisto.getArg('sort'))
        demisto.results(markdown)
    except Exception as ex:
        return_error(f'Failed to execute setGridField. Error: {str(ex)}')


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
