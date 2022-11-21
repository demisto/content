import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

import json


def main():
    identity_results = []
    incident = demisto.incident()
    if not incident:
        raise ValueError("Error - demisto.incident() expected to return current incident "
                         "from context but returned None")
    labels = incident.get('labels', [])

    for label in labels:
        if label.get('type') == 'successful_identity_enrichment':
            is_successful = label.get('value')
            if is_successful == 'false':
                return CommandResults(readable_output='Identity enrichment failed.')
        if label.get('type') == 'Identity':
            identity_results = json.loads(label.get('value', []))

    if not identity_results:
        return CommandResults(readable_output='No identities were found in the notable')
    markdown = tableToMarkdown("", identity_results, headers=identity_results[0].keys())

    return {'ContentsFormat': formats['markdown'], 'Type': entryTypes['note'], 'Contents': markdown}


if __name__ in ('__main__', '__builtin__', 'builtins'):
    try:
        return_results(main())
    except Exception as e:
        return_error(f'Got an error while parsing Splunk events: {e}', error=e)
