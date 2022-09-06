import demistomock as demisto
from CommonServerPython import *

import io
import csv


def main():
    args = demisto.args()
    entry_id = args.get("entryid")

    if isinstance(entry_id, list):
        entry_id = entry_id[0]

    dictlist = demisto.executeCommand("getEntry", {"id": entry_id})[0]["Contents"]
    csv_final = json_to_csv(dictlist)

    if "filename" in args:
        # Send CSV as file in War Room
        demisto.results(fileResult(args.get("filename"), csv_final))

    else:
        # Send CSV to War Room
        demisto.results(csv_final)


def json_to_csv(data: list):
    """
    Takes a list of dictionaries and parses them into CSV format.
    JSON should be only a list that contains dictionaries.

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
    result = io.StringIO()
    csv_data = csv.writer(result)

    if not (isinstance(data, list) and data):
        raise DemistoException("Input JSON data is invalid.")

    keys = list(data[0].keys())
    csv_data.writerow(keys)

    for d in data:
        val_lst = []
        for k in keys:
            val_lst.append(d[k])

        csv_data.writerow(val_lst)

    return result.getvalue().strip()


if __name__ in ["__builtin__", "builtins", "__main__"]:
    main()
