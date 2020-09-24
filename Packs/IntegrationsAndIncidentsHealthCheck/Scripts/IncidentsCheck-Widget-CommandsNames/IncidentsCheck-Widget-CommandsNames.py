import collections
import random

import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

lists_data = []
incident = demisto.incidents()

list_data = demisto.executeCommand("getList", {"listName": "XSOAR Health - Failed Incident Commands"})
list_content = list_data[0].get('Contents').split(",")

if list_content != ['']:
    list_collections = collections.Counter(list_content)
    top_lists = list_collections.most_common(10)
    lists_number = len(top_lists)
    list_number = 0

    while list_number < lists_number:
        for list_element in top_lists:
            random_number = random.randint(0, 16777215)
            hex_number = str(hex(random_number))  # convert to hexadecimal
            color = '#' + hex_number[2:]  # remove 0x and prepend '#'

            lis_widget_data = {
                "data": [
                    list_element[1]
                ],
                "name": str(list_element[0]),
                "color": color
            }

            lists_data.append(lis_widget_data)
            list_number += 1

    demisto.results(json.dumps(list_data))

else:
    data = {
        {
            "data": [
                0
            ],
            "name": "N\\A",
            "color": "#00CD33"
        },

    }
    demisto.results(json.dumps(data))
