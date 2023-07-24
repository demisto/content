import collections
import random
from collections import Counter
import demistomock as demisto
from CommonServerPython import *


def parse_data(list_content):
    lists_data = []

    list_collections: Counter = collections.Counter(list_content)
    top_lists = list_collections.most_common(10)

    for list_element in top_lists:
        random_number = random.randint(0, 16777215)
        hex_number = str(hex(random_number))  # convert to hexadecimal
        color = f'#{hex_number[2:].zfill(6)}'  # remove 0x and prepend '#'
        list_widget_data = {
            "data": [
                list_element[1]
            ],
            "groups": None,
            "name": str(list_element[0]),
            "label": str(list_element[0]),
            "color": color
        }
        lists_data.append(list_widget_data)

    return {
        "Type": 17,
        "ContentsFormat": "pie",
        "Contents": {
            "stats":
                lists_data,
            "params": {
                "layout": "horizontal"
            }
        }
    }


def main():
    data = demisto.context().get('ExtractedIndicators')
    data = argToList(data)
    if data:
        list_content = []
        for item in data:
            for key, values in item.items():
                list_content.extend([key] * len(values))

        if list_content:
            data = parse_data(list_content)

    else:
        data = {
            "Type": 17,
            "ContentsFormat": "bar",
            "Contents": {
                "stats": [
                    {
                        "data": [
                            0
                        ],
                        "groups": None,
                        "name": "N/A",
                        "label": "N/A",
                        "color": "rgb(255, 23, 68)"
                    },
                ],
                "params": {
                    "layout": "horizontal"
                }
            }
        }

    return_results(data)


if __name__ in ["__main__", "builtin", "builtins"]:
    main()
