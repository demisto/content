import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401


def parse_rows(rows: str) -> list[list[str]]:
    """
    Parse the rows input as a string and convert it into a list of lists.

    Args:
        rows (str): A string representation of a list of lists.

    Returns:
        list[list[str]]: A list of lists representing the rows.

    Raises:
        Exception: If the format is invalid or parsing fails.
    """
    if not (rows.startswith('[') and rows.endswith(']')):
        raise ValueError("Invalid format: rows should be a list of lists e.g., [[1,2],[3,4]]")

    rows = rows.replace('], [', '],[')
    rows = rows.strip('[]')
    row_list_strs = rows.split('],[')
    row_list: list[list[str]] = []
    for row_str in row_list_strs:
        row_str = row_str.strip('[]')
        row = row_str.split(',')
        processed_row = [element.strip().strip('"').strip("'") for element in row]
        row_list.append(processed_row)
    return row_list


def get_existing_grid_records(indicator_value: str, grid_field: str) -> list[dict[str, str | None]]:
    """
    Retrieve the existing grid field records from the indicator.

    Args:
        indicator_value (str): The value of the indicator.
        grid_field (str): The name of the grid field.

    Returns:
        list[dict[str, str | None]]: The existing grid field records.

    Raises:
        Exception: If the indicator or grid field is not found or if any errors occur.
    """
    search_result = demisto.executeCommand('findIndicators', {'value': indicator_value})
    if isError(search_result):
        return_error(f'Failed to find indicator {indicator_value}. Error: {get_error(search_result)}')

    indicators = search_result[0]['Contents']
    if not indicators:
        return_error(f'No indicator found with value {indicator_value}.')

    indicator = indicators[0]
    existing_grid_records = indicator.get('CustomFields', {}).get(grid_field, [])
    if not isinstance(existing_grid_records, list):
        existing_grid_records = []

    return existing_grid_records


def main() -> None:
    """
    Main function to update an indicator's grid field with provided row data.

    The data can either be provided as a dictionary or as a list of lists.
    Headers for the table must be provided using the 'headers' argument.
    Keys for the extraction from context dictionaries can be provided using the 'keys_from_context' argument.
    When the 'append' argument is set to True, the new content is appended to the existing grid content.

    Raises:
        Exception: If required arguments are not provided, or if any validations fail.
    """
    raw_input_data = demisto.args().get('input', {})
    headers: list[str] = demisto.args().get('headers', '').split(',')
    indicator_value: str = demisto.args().get('indicator', '')
    grid_field: str = demisto.args().get('grid_field', '')
    keys_from_context: str = demisto.args().get('keys_from_context', '')
    append: bool = demisto.args().get('append', 'false').lower() == 'true'

    if not raw_input_data:
        return_error('You must provide the "input" argument.')

    # Check if the input data is a dict or list of dicts
    if isinstance(raw_input_data, dict):
        raw_input_data = [raw_input_data]  # Convert single dictionary to list of dictionaries

    if isinstance(raw_input_data, list) and all(isinstance(item, dict) for item in raw_input_data):
        # Process dictionary input
        if keys_from_context:
            keys = keys_from_context.split(',')
            rows: list[list[str]] = [[row.get(key, '') for key in keys[:len(headers)]] for row in raw_input_data]
            demisto.debug(f'{rows}')
        else:
            # Ensure input dictionary keys match headers
            for row in raw_input_data:
                if set(row.keys()) != set(headers):
                    return_error('Input dictionary keys must match headers when context keys are not provided.')

            rows = [[row.get(header, '') for header in headers] for row in raw_input_data]

        demisto.debug('Changed the data into list format')

    else:
        # Process as list of lists string
        demisto.debug(f'Trying to parse rows - {raw_input_data}')
        try:
            rows = parse_rows(str(raw_input_data))
            if not isinstance(rows, list) or not all(isinstance(row, list) for row in rows):
                return_error('Rows must be a list of lists.')
        except Exception as e:
            return_error(
                f'Invalid format for rows input. Expected format: [[1,2],[3,4]] or a valid dictionary structure. Error: {str(e)}')

    # Validate that headers are a list of strings
    if not all(isinstance(header, str) for header in headers):
        return_error('All headers must be strings.')

    # Validate rows length matches headers length
    for row in rows:
        if len(row) != len(headers):
            return_error('Each row must have the same number of elements as there are headers.')

    # Prepare the new rows data in the format expected by the grid field
    new_grid_records: list[dict[str, str | None]] = []
    for row in rows:
        # Handle empty cells by setting them to None or an empty string
        record = {header: (value if value != '' else None) for header, value in zip(headers, row)}
        new_grid_records.append(record)

    if append:
        # Append new records to existing ones
        grid_records = get_existing_grid_records(indicator_value, grid_field) + new_grid_records

    else:
        # Overwrite the grid field with new records
        grid_records = new_grid_records

    # Update the indicator with the grid field using its value
    set_indicator_result = demisto.executeCommand('setIndicator', {
        'value': indicator_value,
        grid_field: grid_records
    })

    if isError(set_indicator_result):
        if get_error(set_indicator_result) == 'setIndicator must contain at least one field to set (7)':
            return_error(f'Indicator {indicator_value} has no grid field called {grid_field}.')
        else:
            return_error(f'Failed to set grid field for indicator {indicator_value}. Error: {get_error(set_indicator_result)}')
    else:
        demisto.results(f'Successfully updated indicator {indicator_value} grid field {grid_field}.')


if __name__ in ['__main__', '__builtin__', 'builtins']:
    main()
