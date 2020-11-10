import collections
import random
from typing import Counter

import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401


def parse_data(list_content):
    datesOnlyList = []

    for full_date in list_content:
        date_only = full_date.split(" ")[0]
        datesOnlyList.append(date_only)

    lists_data: List = []
    if list_content != ['']:
        list_collections: Counter = collections.Counter(datesOnlyList)
        top_lists = list_collections.most_common(10)
        lists_number = len(top_lists)
        list_number = 0

        while list_number < lists_number:
            for list_element in top_lists:
                random_number = random.randint(0, 16777215)
                hex_number = str(hex(random_number))  # convert to hexadecimal
                color = '#' + hex_number[2:]  # remove 0x and prepend '#'

                listW_widget_data = {
                    "data": [
                        list_element[1]
                    ],
                    "name": str(list_element[0]),
                    "color": color
                }

                lists_data.append(listW_widget_data)
                list_number += 1

        return lists_data


def main():
    list_data = demisto.executeCommand("getList", {"listName": "XSOAR Health - Failed Incidents Dates"})
    list_content = list_data[0].get('Contents', '').split(",")

    if list_content != ['']:
        data = parse_data(list_content)
    else:
        data = [{
            "data": [
                0
            ],
            "name": "2020-01-01",
            "color": "#00CD33"
        }]

    demisto.results(json.dumps(data))


if __name__ in ["__main__", "builtin", "builtins"]:
    main()
