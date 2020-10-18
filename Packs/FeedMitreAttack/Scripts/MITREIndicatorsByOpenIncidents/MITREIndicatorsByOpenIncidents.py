import demistomock as demisto
from CommonServerPython import *
import traceback


def main():
    try:
        from_date = demisto.args().get('from', '')
        to_date = demisto.args().get('to', '')
        query = 'type:"MITRE ATT&CK" and investigationsCount:>0'
        res = demisto.searchIndicators(query=query, fromDate=from_date, toDate=to_date)

        indicators = []
        for ind in res.get('iocs', []):
            indicators.append({
                'Value': dict_safe_get(ind, ['value']),
                'Name': dict_safe_get(ind, ['CustomFields', 'mitrename']),
                'Phase Name': dict_safe_get(ind, ['CustomFields', 'mitrekillchainphases', 0, 'phase_name']),
                'Description': dict_safe_get(ind, ['CustomFields', 'mitredescription']),

            })

        incidents_table = tableToMarkdown('MITRE ATT&CK techniques by related Incidents', indicators,
                                          headers=['Value', 'Name', 'Phase Name', 'Description'])

        return_outputs(incidents_table)
    except Exception:
        demisto.error(traceback.format_exc())  # print the traceback
        return_error(f'Failed to execute MITREIndicatorsByOpenIncidents script. Error: {traceback.format_exc()}')


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
