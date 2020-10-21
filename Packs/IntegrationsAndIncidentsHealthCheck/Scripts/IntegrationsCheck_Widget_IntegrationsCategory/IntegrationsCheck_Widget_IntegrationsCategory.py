import collections
import random
from typing import Counter

import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401


def parse_data(list_content):
    lists_data = []

    list_collections: Counter = collections.Counter(list_content)
    top_lists = list_collections.most_common(10)
    lists_number = len(top_lists)
    list_number = 0

    while list_number < lists_number:
        for list_element in top_lists:
            random_number = random.randint(0, 16777215)
            hex_number = str(hex(random_number))  # convert to hexadecimal
            color = '#' + hex_number[2:]  # remove 0x and prepend '#'

            list_widget_data = {
                "data": [
                    list_element[1]
                ],
                "name": str(list_element[0]),
                "color": color
            }

            lists_data.append(list_widget_data)
            list_number += 1

    return lists_data


def main():
    list_data = demisto.executeCommand("getList", {"listName": "XSOAR Health - Failed Integrations Category"})
    list_content = list_data[0].get('Contents', '').split(",")

    if list_content != ['']:
        data = parse_data(list_content)

    else:
        data = [{
            "data": [
                0
            ],
            "name": "N\A",
            "color": "#00CD33"
        }]

    demisto.results(json.dumps(data))


if __name__ in ["__main__", "builtin", "builtins"]:
    main()
