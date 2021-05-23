import json

import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401


def main():
    incident = demisto.incident()
    custom_fields = incident.get('CustomFields', {})
    identity_results_str = custom_fields.get('identitytable', {})
    identity_results = json.loads(identity_results_str)

    if not identity_results:
        return CommandResults()

    if isinstance(identity_results, list):
        events_arr = []
        for event in identity_results:
            events_arr.append(event)
        markdown = tableToMarkdown("", events_arr, headers=events_arr[0].keys())

    else:
        markdown = tableToMarkdown("", identity_results)

    return {'ContentsFormat': formats['markdown'], 'Type': entryTypes['note'], 'Contents': markdown}


if __name__ in ('__main__', '__builtin__', 'builtins'):
    try:
        return_results(main())
    except Exception as e:
        return_error('Got an error while parsing Splunk events', error=e)
