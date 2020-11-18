import collections
import random
from typing import Counter

import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401


def parse_data(playbook_names):
    playbooks_data = []

    if playbook_names:
        playbooks_collections: Counter = collections.Counter(playbook_names)
        top_playbooks = playbooks_collections.most_common(10)
        playbooks_number = len(top_playbooks)
        playbook_number = 0

        while playbook_number < playbooks_number:
            for topPlaybook in top_playbooks:
                random_number = random.randint(0, 16777215)
                hex_number = str(hex(random_number))  # convert to hexadecimal
                color = '#' + hex_number[2:]  # remove 0x and prepend '#'

                playbook_widget_data = {
                    "data": [
                        topPlaybook[1]
                    ],
                    "groups": None,
                    "name": str(topPlaybook[0]),
                    "label": str(topPlaybook[0]),
                    "color": color
                }

                playbooks_data.append(playbook_widget_data)
                playbook_number += 1

        return {
            "Type": 17,
            "ContentsFormat": "bar",
            "Contents": {
                "stats":
                    playbooks_data,
                "params": {
                    "layout": "horizontal"
                }
            }
        }


def main():
    incident = demisto.incidents()

    playbook_names = incident[0].get('CustomFields', {}).get('playbooknameswithfailedtasks')
    if playbook_names:
        data = parse_data(playbook_names)

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
