import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401


def main():
    drilldown_results = []
    incident = demisto.incident()
    if not incident:
        raise ValueError("Error - demisto.incident() expected to return current incident "
                         "from context but returned None")

    labels = incident.get('labels', [])
    for label in labels:
        if label.get('type') == 'successful_drilldown_enrichment':
            is_successful = label.get('value')
            if is_successful == 'false':
                return CommandResults(readable_output='Drilldown enrichment failed.')
        if label.get('type') == 'Drilldown':
            try:
                drilldown_results = json.loads(label.get('value', []))
            except Exception as e:
                raise ValueError(f'Drilldown is not in a valid JSON structure:\n{e}')

    if not drilldown_results:
        return CommandResults(readable_output='Drilldown was not configured for notable.')

    if isinstance(drilldown_results, list):
        events_arr = []
        for event in drilldown_results:
            events_arr.append(event)
        markdown = tableToMarkdown("", events_arr, headers=events_arr[0].keys())
    else:
        markdown = tableToMarkdown("", drilldown_results)

    return {'ContentsFormat': formats['markdown'], 'Type': entryTypes['note'], 'Contents': markdown}


if __name__ in ('__main__', '__builtin__', 'builtins'):
    try:
        return_results(main())
    except Exception as e:
        return_error(f'Got an error while parsing Splunk events: {e}', error=e)
