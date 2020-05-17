import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *
import json
import io
import csv


def json_to_csv(data, delimiter):
    si = io.BytesIO()
    cw = csv.writer(si, delimiter=delimiter)
    csv_headers = list(data[0].keys())
    csv_headers.sort()
    cw.writerow(csv_headers)

    for d in data:
        val_lst = [d[key] for key in csv_headers]
        cw.writerow(val_lst)

    return si.getvalue().strip("\r\n")


def main(entry_id, out_filename, delimiter):
    if isinstance(entry_id, list):
        entry_id = entry_id[0]

    file_info = {}  # type: dict
    try:
        file_info = demisto.getFilePath(entry_id)
    except Exception as e:
        return_error('Failed to get the file path for entry: {} the error message was {}'.format(entry_id, str(e)))

    file_path = file_info['path']

    # open file and read data
    with open(file_path, 'r') as f:
        dict_list = json.load(f)

    csv_out = json_to_csv(dict_list, delimiter)

    # output cvs as a file to war-room
    demisto.results(fileResult(out_filename, csv_out.encode("utf-8")))


if __name__ in ('__builtin__', 'builtins'):
    args = demisto.args()
    main(args['entryid'], args['filename'], args.get('delimiter', ',').encode("utf-8"))
