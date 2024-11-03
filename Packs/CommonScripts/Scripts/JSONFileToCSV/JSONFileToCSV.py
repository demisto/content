import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *
import json
import io
import csv


def json_to_csv(data, delimiter):
    result = io.StringIO()
    csv_data = csv.writer(result, delimiter=delimiter)
    csv_headers = list(data[0].keys())
    csv_headers.sort()
    csv_data.writerow(csv_headers)

    for d in data:
        val_lst = [d[key] for key in csv_headers]
        csv_data.writerow(val_lst)

    return result.getvalue().strip()


def main(entry_id, out_filename, delimiter):
    if isinstance(entry_id, list):
        entry_id = entry_id[0]

    file_info = {}

    try:
        file_info = demisto.getFilePath(entry_id)

    except Exception as e:
        return_error(f"Failed to get the file path for entry: {entry_id} the error message was {str(e)}")

    file_path = file_info.get("path")

    # Open file and read data
    with open(file_path) as f:  # type: ignore
        dict_list = json.load(f)

    csv_string = json_to_csv(dict_list, delimiter)

    # Output CSV as a file to war-room
    demisto.results(fileResult(out_filename, csv_string))


if __name__ in ["__builtin__", "builtins", "__main__"]:
    args = demisto.args()
    main(args.get("entryid"), args.get("filename"), args.get("delimiter", ","))
