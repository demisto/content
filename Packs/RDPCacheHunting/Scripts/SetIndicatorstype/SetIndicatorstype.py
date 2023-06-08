import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
import collections
import random
from typing import Counter


def parse_data(list_content):
    lists_data = []

    list_collections: Counter = collections.Counter(list_content)
    top_lists = list_collections.most_common(10)

    for i in range(len(top_lists)):
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
    demisto.incidents()
    Indicator_type = demisto.executeCommand("getList", {"listName": "indicatorsTypes"})
    list_content = Indicator_type[0].get('Contents', '').split(",")

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
