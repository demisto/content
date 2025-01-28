import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
# STD Libraries
from typing import Any
# 3-rd party libraries
import pandas as pd
import phrases_case
# Local packages
from CommonServerUserPython import *


def get_error_message(grid_id: str) -> str:
    """ Gets error message.

    Args:
        grid_id: The grid ID.

    Returns:
        str: The error message.
    """
    return f"The following grid id was not found: {grid_id}. Make sure you entered the correct " \
           f"incident type with the \"Machine name\" as it appears in the incident field editor in " \
           f"Settings->Advanced ->Fields (Incident). Also make sure that this value appears in the " \
           f"incident Context Data under incident - if not then consult with PANW support team."


def normalized_string(phrase: str) -> str:
    """ Normalize a string to flatcase (to match `cli name`).

    Args:
        phrase: Phrase to normalize.

    Returns:
        str: Normalized phrase.

    Examples:
        >>> normalized_string("TestWord")
        "testword"
        >>> normalized_string("hello_world")
        "helloworld"
    """
    return phrases_case.camel(phrase).replace("'", "").lower()


def normalized_column_name(phrase: str) -> str:
    """ Normalize columns or Grid to connected word in lowercase, to match the logic of stripToClumnName() from
        the client's `strings.js` and the server logic.

    Args:
        phrase: Phrase to normalize.

    Returns:
        str: Normalized phrase.

    Examples:
        >>> normalized_string("Test Word!@#$%^&*()-=+")
        "testword"
        >>> normalized_string("hello🦦_world@")
        "hello_world"
    """
    return re.sub(r'[^a-zA-Z\d_]', '', phrase).lower()


def filter_dict(dict_obj: dict[Any, Any], keys: list[str], max_keys: int | None = None) -> dict[Any, Any]:
    """ Filter keys from Dictionary:
            1. Will only save keys which specified in keys parameters.
            2. If key in index 0 is "*", will save all keys until max_keys (as much as Grid can include).

    Args:
        dict_obj: Dictionary to filter keys from.
        keys: Keys to save.
        max_keys: Max keys to save in case of keys[0] = "*"

    Returns:
        dict: Filtered dict.
    """
    # Iterate over all the items in dictionary
    if keys[0] != "*":
        # create empty dict of given headers
        new_dict = {key: None for key in keys}
        for (key, value) in dict_obj.items():
            # Check if item satisfies the given condition then add to new dict
            if value not in ('', None) and key in keys:
                new_dict[key] = value

    else:
        if max_keys:
            new_dict = dict(list(dict_obj.items())[:max_keys])
        else:
            new_dict = dict_obj

    return new_dict


def entry_dicts_to_string(dict_obj: dict[Any, Any], keys_to_choose: list[str]):
    """

    Args:
        dict_obj: context entry to iterate on
        keys_to_choose: specific keys to filter from the nested dictionaries

    Returns:
        string contains all selected values from the nested dictionary of the context entry.
    """
    new_dict = {key: '' for key in dict_obj}
    for (key, value) in dict_obj.items():
        if isinstance(value, dict):
            value = filter_dict(value, keys_to_choose)
            new_dict[key] = "\n".join(f'{dict_key}: {dict_value}' for dict_key, dict_value in value.items())
        elif isinstance(value, list):
            array_to_join = []
            for list_value in value:
                if isinstance(list_value, dict):
                    list_value = filter_dict(list_value, keys_to_choose)
                    array_to_join.append("\n".join(f'{dict_key}: {dict_value}' for dict_key, dict_value in list_value.items()))
                else:
                    array_to_join.append(f"\n{list_value}")
            final_value = "\n\n".join(array_to_join)
            new_dict[key] = final_value
        else:
            new_dict[key] = value

    return new_dict


def unpack_all_data_from_dict(entry_context: dict[Any, Any], keys: list[str], columns: list[str]):
    """ Unpacks lists and dicts to flatten the object for the grid.

    Args:
        entry_context: Dictionary to unpack.
        keys: Keys to save.
        columns: Grid columns name.

    Returns:
        list: Unpacked data.
    """
    unpacked_data = []  # type: List

    filtered_dict = filter_dict(entry_context, keys)

    def recursively_unpack_data(item_to_unpack: dict[Any, Any], path: str):
        for key, value in item_to_unpack.items():
            if isinstance(value, dict):
                recursively_unpack_data(filter_dict(value, keys), path + '.' + key)
            elif isinstance(value, list):
                for item in value:
                    if isinstance(item, dict):
                        recursively_unpack_data(filter_dict(item, keys), path + '.' + key)
                    else:
                        unpacked_data.append(
                            {
                                columns[0]: key,
                                columns[1]: item if isinstance(item, str | int | float | bool) else ""
                            }
                        )
            else:
                unpacked_data.append(
                    {
                        columns[0]: key,
                        columns[1]: value if isinstance(value, str | int | float | bool) else ""
                    }
                )

    recursively_unpack_data(filtered_dict, '')

    return unpacked_data


@logger
def get_current_table(grid_id: str) -> pd.DataFrame:
    """ Get current Data from the grid

    Args:
        grid_id: Grid ID to retrieve data from.

    Returns:
        DataFrame: Existing grid data.
    """
    # Note: in XSIAM empty grid fields doe not exist in the context.
    # in XSOAR the fields exist with empty values.
    incident = demisto.incident()
    custom_fields = incident.get("CustomFields", {}) or {}
    if (not is_xsiam_or_xsoar_saas()) and grid_id not in custom_fields:
        raise ValueError(get_error_message(grid_id))
    current_table: list[dict] | None = custom_fields.get(grid_id)
    return pd.DataFrame(current_table) if current_table else pd.DataFrame()


@logger
def validate_entry_context(context_path: str, entry_context: Any, unpack_nested_elements: bool):
    """ Validate entry context structure is valid, should be:
        - For unpack_nested_elements==False:
            1. List[Dict[str, Any]]
            2. List[str/bool/int/float]
            3. Dict[str, str/bool/int/float] - for developer it will be in first index of a list.
        - For unpack_nested_elements==True:
            1. Dict[str, Any]

    Args:
        context_path: Path of entry context
        entry_context: Entry context to validate
        unpack_nested_elements: True for unpacking nested elements, False otherwise.

    Raises:
        ValueError: If structure is not valid.
        data_type (str): The type of information in the context path.
    """
    if unpack_nested_elements:
        if not isinstance(entry_context, dict):
            raise ValueError(
                'When the unpack_nested_elements argument is set to True, the context object for the path should be '
                'of type dict.')
        else:
            return None

    if not isinstance(entry_context, list | dict):
        raise ValueError(
            f'The context object {context_path} should be of type dict or list.\n'
            f'Received type: {type(entry_context)}')

    data_type = 'dict'

    if isinstance(entry_context, dict):
        return data_type

    has_seen_dict = False
    for index, item in enumerate(entry_context):
        if not isinstance(item, dict):
            if has_seen_dict:
                raise ValueError(
                    f'The context object in index {index} - {item} is of invalid type ({type(item)}).\n'
                    f'The object {context_path} should contain only dict type values.')
            else:
                break

        has_seen_dict = True

    if not has_seen_dict:
        data_type = 'list'
        for index, item in enumerate(entry_context):
            if not isinstance(item, str | int | float | bool):
                raise ValueError(
                    f'The context path {context_path} should contain a list of simple values '
                    f'(string, number, boolean)\n'
                    f'received item in index {index} of type {type(item)}:\n{item}')

    return data_type


def build_grid(context_path: str, keys: list[str], columns: list[str], unpack_nested_elements: bool,
               keys_from_nested: list[str]) -> pd.DataFrame:
    """ Build new DateFrame from current context retrieved by DT.
        There are 3 cases:
            1. DT returns dict - In this case we will insert it in the table as key, value in each row.
            2. DT returns list - In this case each entry in the list will represent a row.
            3. DT return unknown obj (str..) - return empty list.

    Args:
        context_path: DT context path.
        keys: Keys to be included
        columns: Grid columns name.
        unpack_nested_elements: True for unpacking nested elements, False otherwise.
        keys_from_nested: Keys to extract from nested dictionaries.

    Returns:
        pd.DataFrame: New Table include data from Entry Context
    """
    # Retrieve entry context data
    entry_context_data = demisto.dt(demisto.context(), context_path)
    # Validate entry context structure
    data_type = validate_entry_context(context_path, entry_context_data, unpack_nested_elements)

    demisto.debug('context object is valid. starting to build the grid.')
    # Building new Grid
    if unpack_nested_elements:

        # Handle entry context as dict, with unpacking of nested elements
        table = pd.DataFrame(unpack_all_data_from_dict(entry_context_data, keys, columns))
        table = table.rename(columns=dict(zip(table.columns, columns)))
    elif data_type == 'list':
        # Handle entry context as list of value
        table = pd.DataFrame(entry_context_data)
        table = table.rename(columns=dict(zip(table.columns, columns)))
    elif isinstance(entry_context_data, list):
        # Handle entry context as list of dicts
        entry_context_data = [entry_dicts_to_string(dict_obj=filter_dict(item, keys, len(columns)),
                                                    keys_to_choose=keys_from_nested)
                              for item in entry_context_data]
        table = pd.DataFrame(entry_context_data)
        table = table.rename(columns=dict(zip(table.columns, columns)))
    elif isinstance(entry_context_data, dict):
        # Handle entry context key-value
        # If the keys arg is * it means we don't know which keys we have in the context - Will create key-value table.
        entry_context_data = entry_dicts_to_string(dict_obj=filter_dict(entry_context_data, keys),
                                                   keys_to_choose=keys_from_nested)
        if keys == ['*']:
            entry_context_data = entry_context_data.items()
            table = pd.DataFrame(entry_context_data, columns=columns[:2])
        else:
            entry_context_data = entry_context_data
            table = pd.DataFrame([entry_context_data])
            table = table.rename(columns=dict(zip(table.columns, columns)))

    else:
        table = []

    return table


@logger
def build_grid_command(grid_id: str, context_path: str, keys: list[str], columns: list[str], overwrite: bool,
                       sort_by: list[str], unpack_nested_elements: bool, keys_from_nested: list[str]) \
        -> list[dict[Any, Any]]:
    """ Build Grid in one of the 3 options:
            1. Context_path contains list of dicts where values are of primitive types (str, int, float, bool),
                e.g. [{'a': 1, 'b': 2}, {'a': 1, 'b': 2}]
            2. Context_path contains dict (key value pairs), e.g. {'a': 1, 'b': 2}
            3. Context_path contains dict where values can be non-primitive types,
            e.g. {'a': 1, 'b': [1, 2, 3], 'c': {'1': 1, '2': 2}}

        Warnings:
            1. The automation can't validate that the columns name correct.

        Args:
            grid_id: Grid ID to modify.
            context_path: Entry context path to collect the values from.
            keys: Keys to be included in the table, If specified "*" will retrieve all availble keys.
            columns: Name of the columns in the must be equal.
            overwrite: True if to overwrite existing data else False.
            sort_by: Name(s) of the columns to sort by.
            unpack_nested_elements: True for unpacking nested elements, False otherwise.
            keys_from_nested: Keys to extract from nested dictionaries.

        Returns:
            list: Table representation for the Grid.
    """
    # Assert columns match keys
    if keys[0] != '*' and (len(columns) != len(keys)):
        raise DemistoException(f'The number of keys: {len(keys)} should match the number of columns: {len(columns)}.')
    # Get old Data
    old_table = get_current_table(grid_id=grid_id)
    # Change columns to all lower case (underscores allowed).
    columns = [normalized_column_name(phrase) for phrase in columns]
    # Create new Table from the given context path.
    new_table: pd.DataFrame = build_grid(context_path=context_path,
                                         keys=keys,
                                         columns=columns,
                                         unpack_nested_elements=unpack_nested_elements,
                                         keys_from_nested=keys_from_nested)

    # Merge tables if not specified to overwrite.
    if not overwrite:
        new_table = pd.concat([new_table, old_table])

    # Sort by column name if specified, support multi columns sort
    if sort_by and set(sort_by) <= set(new_table.columns):
        new_table = new_table.sort_values(by=sort_by)

    # filter empty values in the generated table
    filtered_table = []
    for record in new_table.to_dict(orient='records'):
        filtered_table.append({k: v for k, v in record.items() if pd.notnull(v)})

    return filtered_table


def main():  # pragma: no cover
    args = demisto.args()
    try:
        # Normalize grid id from any form to connected lower words, e.g. my_word/myWord -> myword
        grid_id = normalized_string(args.get('grid_id'))

        context_path = args.get('context_path')
        # Build updated table
        table = build_grid_command(grid_id=grid_id,
                                   context_path=context_path,
                                   keys=argToList(args.get('keys')),
                                   overwrite=argToBoolean(args.get('overwrite')),
                                   columns=argToList(args.get('columns')),
                                   sort_by=argToList(args.get('sort_by')),
                                   unpack_nested_elements=argToBoolean(args.get('unpack_nested_elements')),
                                   keys_from_nested=argToList(args.get('keys_from_nested'))
                                   )
        # Execute automation 'setIncident` which change the Context data in the incident
        res_set = demisto.executeCommand("setIncident", {
            'customFields': {
                grid_id: table,
            },
        })
        # we want to check if the incident was succefully updated
        # we execute command and not using `demisto.incident()` because we want to get the updated incident and context
        res = demisto.executeCommand("getIncidents", {"id": demisto.incident().get("id")})
        custom_fields: dict = {}
        for entry in res:
            if entry['Contents']:
                data = entry["Contents"]["data"]
                custom_fields = data[0].get("CustomFields", {}) if data else {}
        # in the debugger, there is an addition of the "_grid" suffix to the grid_id.
        if is_xsiam_or_xsoar_saas() and table and grid_id not in custom_fields and f"{grid_id}_grid" not in custom_fields:
            raise ValueError(get_error_message(grid_id))
        if is_error(res_set):
            demisto.error(f'failed to execute "setIncident" with table: {table}.')
            return_results(res_set)
        elif is_error(res):
            demisto.error('failed to execute "getIncidents".')
            return_results(res)
        else:
            return_results(f'Set grid {grid_id} using {context_path} successfully.')

    except Exception as exc:
        return_error(f'Failed to execute setGridField. Error: {str(exc)}', error=traceback.format_exc())


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
