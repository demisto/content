import json

import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401


def main():
    incident = demisto.incident()
    custom_fields = incident.get('CustomFields', {})
    asset_results_str = custom_fields.get('assettable', {})
    asset_results = json.loads(asset_results_str)

    if not asset_results:
        return CommandResults()

    if isinstance(asset_results, list):
        events_arr = []
        for event in asset_results:
            events_arr.append(event)
        markdown = tableToMarkdown("", events_arr, headers=events_arr[0].keys())

    else:
        markdown = tableToMarkdown("", asset_results)

    return {'ContentsFormat': formats['markdown'], 'Type': entryTypes['note'], 'Contents': markdown}


if __name__ in ('__main__', '__builtin__', 'builtins'):
    try:
        return_results(main())
    except Exception as e:
        return_error('Got an error while parsing Splunk events', error=e)
