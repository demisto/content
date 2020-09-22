import collections
import random

import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

incident = demisto.incidents()
playbookNames = incident[0].get('CustomFields', {}).get('playbooknameswithfailedtasks', 0)
playbooksData = []
if playbookNames:
    playbookscollections = collections.Counter(playbookNames)
    topPlaybooks = playbookscollections.most_common(10)
    playbooksnumber = len(topPlaybooks)
    playbooknumber = 0
    playbookTrue = True
    while playbooknumber < playbooksnumber:
        for topPlaybook in topPlaybooks:
            random_number = random.randint(0, 16777215)
            hex_number = str(hex(random_number))  # convert to hexadecimal
            color = '#' + hex_number[2:]  # remove 0x and prepend '#'
            playbookWidgetData = {
                "data": [
                    topPlaybook[1]
                ],
                "groups": None,
                "name": str(topPlaybook[0]),
                "label": str(topPlaybook[0]),
                "color": color
            }
            playbooksData.append(playbookWidgetData)
            playbooknumber = playbooknumber + 1
    data = {
        "Type": 17,
        "ContentsFormat": "bar",
        "Contents": {
            "stats":
            playbooksData,
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
