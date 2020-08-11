import traceback
from typing import List
from operator import itemgetter
from dateutil.parser import parse

import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *


def get_investigations(raw_output, investigations):
    for db in raw_output[0].get('Contents'):
        buckets = db.get('buckets')
        for entry in buckets.keys():
            if entry.startswith('investigations-'):
                investigations[entry] = buckets.get(entry)


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

    widget_table['data'] = sorted(data, key=itemgetter('Size'), reverse=True)  # type: ignore

    return widget_table

def

def get_month_database_names():
    db_names = []
    from_date = parse(demisto.args().get('fromDate'))
    to_date = parse(demisto.args().get('toDate'))
    current_month = datetime.now().strftime('%m')
    current_year = datetime.now().strftime('%Y')
    return current_month + current_year


def main():
    try:
        investigations = {}
        for db_name in get_month_database_names():
            raw_output = demisto.executeCommand('getDBStatistics', args={"filter": db_name})
            get_investigations(raw_output, investigations)
        demisto.results(parse_investigations_to_table(investigations))
    except Exception:
        demisto.error(traceback.format_exc())  # print the traceback
        return_error(f'Failed to execute LargestInvestigationsWidget. Error: {traceback.format_exc()}')


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
