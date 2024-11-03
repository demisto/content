import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
import collections
import random
from collections import Counter


def parse_data(regions_name):
    regions_name_data = []

    regions_collections: Counter = collections.Counter(regions_name)
    top_regions = regions_collections.most_common(5)

    for region in top_regions:
        random_number = random.randint(0, 16777215)
        hex_number = str(hex(random_number))  # convert to hexadecimal
        color = f'#{hex_number[2:].zfill(6)}'  # remove 0x and prepend '#'

        region_widget_data = {
            "data": [
                region[1]
            ],
            "groups": None,
            "name": str(region[0]),
            "label": str(region[0]),
            "color": color
        }

        regions_name_data.append(region_widget_data)

    return {
        "Type": 17,
        "ContentsFormat": "pie",
        "Contents": {
            "stats":
                regions_name_data,
            "params": {
                "layout": "horizontal"
            }
        }
    }


def main():
    incident = demisto.incidents()
    regions_name = incident[0].get('CustomFields', {}).get('cloudregionlist', "0")
    if regions_name:
        data = parse_data(regions_name)

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
