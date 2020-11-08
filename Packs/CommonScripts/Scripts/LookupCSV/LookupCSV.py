"""
Given a CSV file in the War Room by entry ID, searches based on column and value.
If the column is not present, simply parse the CSV into a list of lists or list of dicts (if header row supplied).
"""
from CommonServerPython import *
import csv


def search_dicts(k, v, data):
    """
    Search a list of dicts by key
    """
    match = []
    for row in data:
        if k in row:
            if v == row[k]:
                match.append(row)

    if len(match) == 1:
        # If we only get one result: return just it as a dictr
        return match[0]
    else:
        return match


def search_lists(k, v, data):
    """
    Search a list of lists by index
    """
    match = []

    k = int(k)
    for row in data:
        row_values = list(row.values())
        if row_values[k] == v:
            match.append(row)

    if len(match) == 1:
        # If we only get one result: return just it.
        return match[0]
    else:
        return match


def main():
    d_args = demisto.args()

    entry_id = d_args['entryID'] if 'entryID' in d_args else None
    header_row = d_args['header_row'] if 'header_row' in d_args else None
    search_column = d_args['column'] if 'column' in d_args else None

    search_value: str = d_args['value'] if 'value' in d_args else None

    add_row = d_args['add_header_row'] if 'add_header_row' in d_args else None

    res = demisto.getFilePath(entry_id)
    if not res:
        return_error("Entry {} not found".format(entry_id))

    file_path = res['path']
    file_name = res['name']
    if not file_name.lower().endswith('.csv'):
        return_error(
            '"{}" is not in csv format. Please ensure the file is in correct format and has a ".csv" extension'.format(
                file_name))

    csv_data: list = []
    with open(file_path, mode='r') as csv_file:
        if header_row:
            csv_reader = csv.DictReader(csv_file)
            for line in csv_reader:
                csv_data.append(line)
        elif add_row:
            headers = add_row.split(',')
            csv_reader = csv.DictReader(csv_file, fieldnames=headers)
            for line in csv_reader:
                csv_data.append(line)
                if len(line) != len(add_row.split(",")):
                    return_error(
                        "Added row via add_header_row has invalid length.")

        else:
            csv_reader = csv.DictReader(csv_file, fieldnames=[])
            for line in csv_reader:
                line_values = list(line.values())

                if line_values:
                    csv_data.append(line_values[0])

    # If we're searching the CSV
    if search_column:
        if header_row:
            csv_data = search_dicts(search_column, search_value, csv_data)
        else:
            # Lists are 0-indexed but this makes it more human readable (column 0 is column 1)
            try:
                search_column = int(search_column) - 1
            except ValueError:
                return_error(
                    "CSV column spec must be integer if header_row not supplied (got {})".format(search_column))
            csv_data = search_lists(search_column, search_value, csv_data)

    output = {
        'LookupCSV': {
            'FoundResult': True if csv_data and search_column else False,
            'Result': csv_data if csv_data else None,
            'SearchValue': '' if not search_value else search_value
        }
    }

    demisto.results({
        "Type": entryTypes["note"],
        "ContentsFormat": formats["json"],
        "Contents": csv_data,
        "EntryContext": output
    })


if __name__ in ('__builtin__', 'builtins'):
    main()
