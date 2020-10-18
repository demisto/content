import demistomock as demisto
from CommonServerPython import *
import traceback


def get_query(from_date, to_date):
    query = 'type:"MITRE ATT&CK" and investigationsCount:>0 and '

    if from_date:
        query += f"timeline.date:>={from_date} "
    if to_date:
        query += f"timeline.date:<={to_date}"
    return query


def main():
    try:
        from_date = demisto.args().get('from', '')
        to_date = demisto.args().get('to', '')
        query = get_query(from_date, to_date)
        res = demisto.searchIndicators(query=query)

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
