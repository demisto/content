import json

import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

incident = demisto.incidents()
events = incident[0].get('CustomFields', {}).get('events', {})
if events:
    if isinstance(events, list):
        events_arr = []
        for event in events:
            events_arr.append(json.loads(event))
        markdown = tableToMarkdown("Events From The Offense", events_arr, headers=events_arr[0].keys())
    else:
        markdown = tableToMarkdown("Events From The Offense", json.loads(events))
    demisto.results([{'ContentsFormat': formats['markdown'], 'Type': entryTypes['note'], 'Contents': markdown}])
else:
    demisto.results('')
