"""
Given a CSV file in the war room by entry ID, searches based on column and value.

If column is not present, simply parse the CSV into a list of lists or list of dicts (if header row supplied)
"""
from CommonServerPython import *


def search_dicts(k, v, data):
    """
    Search a list of dicts by key
    """
    for row in data:
        if k in row:
            if v == row[k]:
                return row

def search_lists(k, v, data):
    """
    Search a list of lists by index
    """
    k = int(k)
    for row in data:
        if row[k] == v:
            return row

def main():
    d_args = demisto.args()

    entry_id = d_args['entryID'] if 'entryID' in d_args else None
    header_row = d_args['header_row'] if 'header_row' in d_args else None
    search_column = d_args['column'] if 'column' in d_args else None

    search_value = d_args['value'] if 'value' in d_args else None


    res = demisto.getFilePath(entry_id)
    if not res:
        return_error("Entry {} not found".format(entry_id))

    file_path = res['path']
    file_name = res['name']
    if not file_name.lower().endswith('.csv'):
        return_error(
            '"{}" is not in csv format. Please ensure the file is in correct format and has a ".csv" extension'.format(
                file_name))

    csv_data = []
    with open(file_path) as f:
        lines = f.read().splitlines()

        if header_row:
            headers = lines[0]
            headers = headers.split(",")
            lines = lines[1:]

        for line in lines:
            d = {}
            row = line.split(",")
            if header_row:
                for i, h in enumerate(headers):
                    d[h] = row[i]
                csv_data.append(d)
            else:
                csv_data.append(row)

    # If we're searching the CSV
    if search_column:
        if header_row:
            csv_data = search_dicts(search_column, search_value, csv_data)
        else:
            # Lists are 0-indexed but this makes it more human readable (column 0 is column 1)
            try:
                search_column = int(search_column) - 1
            except ValueError:
                return_error("CSV column spec must be integer if header_row not supplied (got {})".format(search_column))
            csv_data = search_lists(search_column, search_value, csv_data)

    output = {
        'LookupCSV.result': csv_data
    }
    demisto.results({
        "Type": entryTypes["note"],
        "ContentsFormat": formats["json"],
        "Contents": csv_data,
        "EntryContext": output
    })


if __name__ in ('__builtin__', 'builtins'):
    main()