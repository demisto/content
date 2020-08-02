import demistomock as demisto
from CommonServerPython import *

import io
import csv
import sys


def main():
    entry_id = demisto.args()['entryid']
    if isinstance(entry_id, list):
        entry_id = entry_id[0]

    json_ent = demisto.executeCommand('getEntry', {'id': entry_id})

    dictlist = json_ent[0]['Contents']

    csv_final = json_to_csv(dictlist)

    if 'filename' in demisto.args():
        # output cvs to file in warroom
        demisto.results(fileResult(demisto.args()['filename'], csv_final.encode("utf-8")))
    else:
        # output cvs to warrrom
        demisto.results(csv_final.encode("utf-8"))


def json_to_csv(data):
    """
    takes a list of dictionaries and parsing them into csv.
    json should be only list which contains dictionaries.

    json:
        [
            {
                "dn": "DC=demisto,DC=int",
                "provider": "activedir"
            },
            {
                "dn": "CN=Users,DC=demisto,DC=int",
                "provider": "activedir"
            }
        ]

    csv:
        "dn", "provider"
        "DC=demisto,DC=int" , "activedir"
        "CN=Users,DC=demisto, DC=int" ,"activedir"
    """
    si = io.BytesIO()
    cw = csv.writer(si)
    try:
        keys = list(data[0].iterkeys())
    except KeyError:
        print("The given JSON is not an iterable list.")
        sys.exit(0)

    cw.writerow(keys)
    for d in data:
        val_lst = []
        for k in keys:
            val_lst.append(d[k])
        cw.writerow(val_lst)
    return si.getvalue().strip('\r\n')


if __name__ == "__builtin__" or __name__ == "builtins":
    main()
