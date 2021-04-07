import demistomock as demisto
from CommonServerPython import *

import traceback
from typing import Any, Dict


def extract_list_of_events_from_indicator(indicator_data: Dict[str, Any]) -> Dict[str, Any]:
    list_of_events = indicator_data.get("CustomFields", {}).get('chronicleassetsummary', [])
    number_of_events = {'GENERIC_EVENT': 0, 'NETWORK_HTTP': 0, 'NETWORK_CONNECTION': 0, 'USER_LOGIN': 0, 'OTHERS': 0}
    for event in list_of_events:
        if event.get('eventtype') in number_of_events:
            number_of_events[event.get('eventtype')] += 1
        else:
            number_of_events['OTHERS'] += 1
    return create_pie(number_of_events)


def create_pie(number_of_events: Dict[str, int]) -> Dict[str, Any]:
    data = {
        "Type": 17,
        "ContentsFormat": "pie",
        "Contents": {
            "stats": [
                {
                    "data": [number_of_events.get('GENERIC_EVENT')],
                    "groups": None,
                    "name": "Generic Event",
                    "label": "Generic Event",
                    "color": "green"
                },
                {
                    "data": [number_of_events.get('NETWORK_HTTP')],
                    "groups": None,
                    "name": "Network HTTP",
                    "label": "Network HTTP",
                    "color": "red"
                },
                {
                    "data": [number_of_events.get('NETWORK_CONNECTION')],
                    "groups": None,
                    "name": "Network Connection",
                    "label": "Network Connection",
                    "color": "blue"
                },
                {
                    "data": [number_of_events.get('USER_LOGIN')],
                    "groups": None,
                    "name": "User Login",
                    "label": "User Login",
                    "color": "orange"
                },
                {
                    "data": [number_of_events.get('OTHERS')],
                    "groups": None,
                    "name": "Others",
                    "label": "Others",
                    "color": "grey"
                }
            ],
            "params": {"layout": "vertical"}
        },
    }
    return data


def main() -> None:
    try:
        indicator_data = demisto.args().get("indicator")
        demisto.results(extract_list_of_events_from_indicator(indicator_data))
    except Exception as e:
        demisto.error(traceback.format_exc())
        return_error(f'Could not load widget:\n{e}')


# python2 uses __builtin__ python3 uses builtins
if __name__ == "__builtin__" or __name__ == "builtins":
    main()
