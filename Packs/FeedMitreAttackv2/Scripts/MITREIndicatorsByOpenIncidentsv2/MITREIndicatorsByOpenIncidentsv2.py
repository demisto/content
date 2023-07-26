import demistomock as demisto
from CommonServerPython import *
import traceback


def main():
    try:
        from_date = demisto.args().get('from', '')
        to_date = demisto.args().get('to', '')
        query = 'type:"Attack Pattern" and investigationsCount:>0 and -incident.type:"MITRE ATT&CK CoA"'
        search_indicators = IndicatorsSearcher()

        res = search_indicators.search_indicators_by_version(query=query, from_date=from_date, to_date=to_date)

        indicators = []
        iocs = res.get('iocs') if res.get('iocs') is not None else []
        for ind in iocs:
            indicators.append({
                'Value': dict_safe_get(ind, ['value']),
                'Name': dict_safe_get(ind, ['CustomFields', 'mitreid']),
                'Phase Name': dict_safe_get(ind, ['CustomFields', 'killchainphases']),
                'Description': dict_safe_get(ind, ['CustomFields', 'description']),

            })

        incidents_table = tableToMarkdown('MITRE ATT&CK techniques by related Incidents', indicators,
                                          headers=['Value', 'Name', 'Phase Name', 'Description'])

        return_outputs(incidents_table)
    except Exception:
        demisto.error(traceback.format_exc())  # print the traceback
        return_error(f'Failed to execute MITREIndicatorsByOpenIncidents script. Error: {traceback.format_exc()}')


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
