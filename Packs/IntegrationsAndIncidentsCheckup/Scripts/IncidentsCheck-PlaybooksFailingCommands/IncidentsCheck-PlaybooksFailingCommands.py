import collections
import random
from typing import Counter

import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

incident = demisto.incidents()
failedCommands = incident[0].get('CustomFields', {}).get('playbooksfailedcommands', 0)
commandsData = []

if failedCommands:
    commandsscollections: Counter = collections.Counter(failedCommands)
    topCommands = commandsscollections.most_common(10)
    commands_count = len(topCommands)
    commandnumber = 0
    playbookTrue = True
    while commandnumber < commands_count:
        for command in topCommands:
            random_number = random.randint(0, 16777215)
            hex_number = str(hex(random_number))  # convert to hexadecimal
            color = '#' + hex_number[2:]  # remove 0x and prepend '#'
            commandWidgetData = {
                "data": [
                    command[1]
                ],
                "groups": None,
                "name": str(command[0]),
                "label": str(command[0]),
                "color": color
            }
            commandsData.append(commandWidgetData)
            commandnumber = commandnumber + 1
    data = {
        "Type": 17,
        "ContentsFormat": "pie",
        "Contents": {
            "stats":
            commandsData,
                "params": {
                    "layout": "vertical"
                }
        }
    }
    demisto.results(data)
else:
    data = {
        "Type": 17,
        "ContentsFormat": "pie",
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
                "layout": "vertical"
            }
        }
    }
    demisto.results(data)
