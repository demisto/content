import demistomock as demisto
from CommonServerPython import *

from typing import Any, Dict
import traceback
import json


def get_source_hr(source) -> Dict[str, Any]:
    return {
        'Category/Description': source.get('Category', ''),
        'Confidence': source.get('IntRawConfidenceScore', 0),
        'Normalized Confidence': source.get('NormalizedConfidenceScore', ''),
        'Severity': source.get('RawSeverity', '')
    }


def main() -> None:
    try:
        incident_details = demisto.incidents()[0].get('details', '')
        try:
            incident_details = json.loads(incident_details)
        except Exception:
            demisto.log("Error while loading investigation data from incident details.")

        sources_hr = ''
        sources = incident_details.get('Sources', {})
        for source in sources:
            sources_hr += tableToMarkdown('{}'.format(source.get('Source')), get_source_hr(source),
                                          ['Category/Description', 'Confidence', 'Normalized Confidence', 'Severity'])
        result = {
            'Type': entryTypes['note'],
            'Contents': '',
            'ContentsFormat': '',
            'ReadableContentsFormat': formats['markdown'],
            'HumanReadable': sources_hr
        }
        demisto.results(result)
    except Exception as e:
        demisto.error(traceback.format_exc())
        return_error(f'Could not load widget:\n{e}')


# python2 uses __builtin__ python3 uses builtins
if __name__ == '__builtin__' or __name__ == 'builtins':
    main()
