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
    cw.writerow(csv_headers)

    for d in data:
        val_lst = [d[key] for key in csv_headers]
        cw.writerow(val_lst)

    return si.getvalue().strip("\r\n")


def main(entry_id, out_filename, delimiter):
    if isinstance(entry_id, list):
        entry_id = entry_id[0]

    res = demisto.executeCommand('getFilePath', {'id': entry_id})

    # Check to see if valid file entry id was provided as input
    if res[0]['Type'] == entryTypes['error']:
        return_error('Failed to get the file path for entry: {} the error message was {}'.format(
            entry_id,
            res[0]['Contents'])
        )

    file_path = res[0]['Contents']['path']

    # open file and read data
    with open(file_path, 'r') as f:
        data = f.read()

    dictlist = json.loads(data)

    csv_out = json_to_csv(dictlist, delimiter)

    # output cvs as a file to war-room
    demisto.results(fileResult(out_filename, csv_out.encode("utf-8")))


if __name__ in ('__builtin__', 'builtins'):
    args = demisto.args()
    main(args['entryid'], args['filename'], args.get('delimiter', ',').encode("utf-8"))
