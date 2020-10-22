import collections
import random
from typing import Counter

import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401


def parse_data(failed_commands):
    commands_data = []

    commands_collections: Counter = collections.Counter(failed_commands)
    top_commands = commands_collections.most_common(10)
    commands_count = len(top_commands)
    command_number = 0

    while command_number < commands_count:
        for command in top_commands:
            random_number = random.randint(0, 16777215)
            hex_number = str(hex(random_number))  # convert to hexadecimal
            color = '#' + hex_number[2:]  # remove 0x and prepend '#'

            command_widget_data = {
                "data": [
                    command[1]
                ],
                "groups": None,
                "name": str(command[0]),
                "label": str(command[0]),
                "color": color
            }

            commands_data.append(command_widget_data)
            command_number += 1

    return {
        "Type": 17,
        "ContentsFormat": "pie",
        "Contents": {
            "stats":
                commands_data,
            "params": {
                "layout": "vertical"
            }
        }
    }


def main():
    incident = demisto.incidents()

    failed_commands = incident[0].get('CustomFields', {}).get('playbooksfailedcommands')
    if failed_commands:
        data = parse_data(failed_commands)

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


if __name__ in ["__main__", "builtin", "builtins"]:
    main()
