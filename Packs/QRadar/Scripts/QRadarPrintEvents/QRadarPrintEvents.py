import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
import json


MAX_EVENTS = 10


def main():
    try:
        incident = demisto.incident()
        events = incident.get('CustomFields', {}).get('events', {})
        if not events:
            return CommandResults()
        title = f'Offense Events (Showing first {MAX_EVENTS})'
        if isinstance(events, list):
            events_arr = []
            for event in events:
                events_arr.append(json.loads(event))
            markdown = tableToMarkdown(title, events_arr[:MAX_EVENTS], headers=events_arr[0].keys())
        else:
            markdown = tableToMarkdown(title, json.loads(events)[:MAX_EVENTS])

        return CommandResults(readable_output=markdown)
    except Exception as exp:
        return_error('could not parse QRadar events', error=exp)


if __name__ in ('__main__', '__builtin__', 'builtins'):
    return_results(main())
