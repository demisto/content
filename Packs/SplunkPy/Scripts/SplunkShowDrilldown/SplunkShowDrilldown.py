import json


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
            drilldown_results = json.loads(label.get('value', []))

    if not drilldown_results:
        return CommandResults(readable_output='Drilldown was not configured for notable.')
    markdown = tableToMarkdown("", drilldown_results, headers=drilldown_results[0].keys())

    return {'ContentsFormat': formats['markdown'], 'Type': entryTypes['note'], 'Contents': markdown}


if __name__ in ('__main__', '__builtin__', 'builtins'):
    try:
        return_results(main())
    except Exception as e:
        return_error(f'Got an error while parsing Splunk events: {e}', error=e)

register_module_line('SplunkShowDrilldown', 'end', __line__())
