import collections
import random

import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

incident = demisto.incidents()
instancesCategory = incident[0].get('CustomFields', {}).get('integrationsfailedcategories', "0")
instancesCategoryData = []
if instancesCategory:
    instancescollections = collections.Counter(instancesCategory)
    topInstances = instancescollections.most_common(10)
    for instance in topInstances:
        random_number = random.randint(0, 16777215)
        hex_number = str(hex(random_number))  # convert to hexadecimal
        color = '#' + hex_number[2:]  # remove 0x and prepend '#'
        instanceWidgetData = {
            "data": [
                instance[1]
            ],
            "groups": None,
            "name": str(instance[0]),
            "label": str(instance[0]),
            "color": color
        }
        instancesCategoryData.append(instanceWidgetData)
    data = {
        "Type": 17,
        "ContentsFormat": "pie",
        "Contents": {
            "stats":
                instancesCategoryData,
            "params": {
                "layout": "horizontal"
            }
        }
    }
    demisto.results(data)

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
