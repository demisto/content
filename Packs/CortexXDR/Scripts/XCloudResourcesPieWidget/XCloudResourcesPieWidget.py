import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
import collections
import random
from typing import Counter


def parse_data(resources_name):
    resources_name_data = []

    resources_collections: Counter = collections.Counter(resources_name)
    top_resources = resources_collections.most_common(5)

    for resource in top_resources:
        random_number = random.randint(0, 16777215)
        hex_number = str(hex(random_number))  # convert to hexadecimal
        color = f'#{hex_number[2:].zfill(6)}'  # remove 0x and prepend '#'

        resource_widget_data = {
            "data": [
                resource[1]
            ],
            "groups": None,
            "name": str(resource[0]),
            "label": str(resource[0]),
            "color": color
        }

        resources_name_data.append(resource_widget_data)

    return {
        "Type": 17,
        "ContentsFormat": "pie",
        "Contents": {
            "stats":
                resources_name_data,
            "params": {
                "layout": "horizontal"
            }
        }
    }


def main():
    incident = demisto.incidents()
    resources_name = incident[0].get('CustomFields', {}).get('cloudresourcelist', "0")
    if resources_name:
        data = parse_data(resources_name)

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
