import json

import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401


def main():
    try:
        incident = demisto.incident()
        events = incident.get('CustomFields', {}).get('events', {})

        if not events:
            return CommandResults()

        if isinstance(events, list):
            events_arr = []
            for event in events:
                events_arr.append(json.loads(event))
            markdown = tableToMarkdown("Offense Events", events_arr, headers=events_arr[0].keys())
        else:
            markdown = tableToMarkdown("Offense Events", json.loads(events))

        return {'ContentsFormat': formats['markdown'], 'Type': entryTypes['note'], 'Contents': markdown}
    except Exception as exp:
        return_error('could not parse QRadar events', error=exp)


if __name__ in ('__main__', '__builtin__', 'builtins'):
    return_results(main())
