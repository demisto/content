import traceback
from typing import List
from operator import itemgetter

import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *


def get_investigations(raw_output):
    investigations = {}
    for db in raw_output[0].get('Contents'):
        buckets = db.get('buckets')
        for entry in buckets.keys():
            if entry.startswith('investigations-'):
                investigations[entry] = buckets.get(entry)

    return investigations


def parse_investigations_to_table(investigations):
    data: List = []
    widget_table = {"total": len(investigations)}
    for investigation in investigations.keys():
        size = investigations[investigation].get('leafSize').split(' ')
        if float(size[0]) >= 1.0 and size[1] == 'MB':
            data.append({
                "IncidentID": investigation.split('-')[1],
                "Size": investigations[investigation].get('leafSize'),
                "AmountOfEntries": investigations[investigation].get('keyN')
            })

    widget_table['data'] = sorted(data, key=itemgetter('Size'), reverse=True)

    return widget_table


def main():
    try:
        raw_output = demisto.executeCommand('getDBStatistics', args={})
        investigations = get_investigations(raw_output)
        demisto.results(parse_investigations_to_table(investigations))
    except Exception:
        demisto.error(traceback.format_exc())  # print the traceback
        return_error(f'Failed to execute LargestInvestigationsWidget. Error: {traceback.format_exc()}')


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
