import collections
import random
from typing import Counter

import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401


def parse_data(instances_category):
    instances_category_data = []

    instances_collections: Counter = collections.Counter(instances_category)
    top_instances = instances_collections.most_common(10)

    for instance in top_instances:
        random_number = random.randint(0, 16777215)
        hex_number = str(hex(random_number))  # convert to hexadecimal
        color = '#' + hex_number[2:]  # remove 0x and prepend '#'

        instance_widget_data = {
            "data": [
                instance[1]
            ],
            "groups": None,
            "name": str(instance[0]),
            "label": str(instance[0]),
            "color": color
        }

        instances_category_data.append(instance_widget_data)

    return {
        "Type": 17,
        "ContentsFormat": "pie",
        "Contents": {
            "stats":
                instances_category_data,
            "params": {
                "layout": "horizontal"
            }
        }
    }


def main():
    incident = demisto.incidents()
    instances_category = incident[0].get('CustomFields', {}).get('integrationsfailedcategories', "0")

    if instances_category:
        data = parse_data(instances_category)

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
                        "name": "N\A",
                        "label": "N\A",
                        "color": "rgb(255, 23, 68)"
                    },
                ],
                "params": {
                    "layout": "horizontal"
                }
            }
        }

    demisto.results(data)


if __name__ in ["__main__", "builtin", "builtins"]:
    main()
