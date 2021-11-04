import json

import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401


def main():
    incident = demisto.incident()
    if not incident:
        raise ValueError("Error - demisto.incident() expected to return current incident "
                         "from context but returned None")
    custom_fields = incident.get('CustomFields', {})
    asset_results_str = custom_fields.get('assettable', {})
    is_successful = custom_fields.get('successfulassetenrichment', '')
    if is_successful == 'false':
        return CommandResults(readable_output='Asset enrichment failed.')

    asset_results = json.loads(asset_results_str)

    if not asset_results:
        return CommandResults(readable_output='No assets were found in the notable')

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
        return_error(f'Got an error while parsing Splunk events: {e}', error=e)
