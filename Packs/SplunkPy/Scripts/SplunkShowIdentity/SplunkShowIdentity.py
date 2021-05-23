import json

import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401


def main():
    try:
        incident = demisto.incident()
        custom_fields = incident.get('CustomFields', {})
        try:
            identity_results_str = custom_fields.get('identitytable', {})
            identity_results = json.loads(drilldown_results_str)
        except Exception as err:
            print(f'json error: {str(err)}')

        if not identity_results:
            return CommandResults()

        if isinstance(identity_results, list):
            events_arr = []
            for event in identity_results:
                try:
                    events_arr.append(event)
                except Exception as e:
                    return_error('json error: ', error=e)
            markdown = tableToMarkdown("", events_arr, headers=events_arr[0].keys())
        else:
            markdown = tableToMarkdown("", identity_results)

        return {'ContentsFormat': formats['markdown'], 'Type': entryTypes['note'], 'Contents': markdown}
    except Exception as exp:
        return_error('could not parse Splunk events', error=exp)


if __name__ in ('__main__', '__builtin__', 'builtins'):
    return_results(main())
