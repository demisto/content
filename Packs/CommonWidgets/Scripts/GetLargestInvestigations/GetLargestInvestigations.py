import traceback
from typing import List, Dict
from operator import itemgetter
from dateutil.parser import parse
from dateutil.relativedelta import relativedelta

import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *


def get_investigations(raw_output, investigations):
    for db in raw_output:
        buckets = db.get('buckets')
        for entry in buckets.keys():
            if entry.startswith('investigations-'):
                investigations[entry] = buckets.get(entry)
                investigations[entry].update({"Date": db.get('dbName')})


def parse_investigations_to_table(investigations):
    data: List = []
    widget_table = {"total": len(investigations)}
    for investigation in investigations.keys():
        size = investigations[investigation].get('leafSize').split(' ')
        if float(size[0]) >= 1.0 and size[1] == 'MB':
            db_name = investigations[investigation].get('Date')
            data.append({
                "IncidentID": investigation.split('-')[1],
                "Size": investigations[investigation].get('leafSize'),
                "AmountOfEntries": investigations[investigation].get('keyN'),
                "Date": db_name[:2] + "-" + db_name[2:]
            })

    widget_table['data'] = sorted(data, key=itemgetter('Size'), reverse=True)  # type: ignore

    return widget_table


def get_month_db_from_date(date):
    month = date.strftime('%m')
    year = date.strftime('%Y')
    return month + year


def get_time_object(timestring):
    if timestring is None or timestring == '':
        return datetime.now()

    date_object = parse(timestring)
    if date_object.year == 1:
        return datetime.now()
    else:
        return date_object


def get_month_database_names():
    db_names = set()
    to_date = get_time_object(demisto.args().get('to'))
    from_date = get_time_object(demisto.args().get('from'))
    current = from_date
    while current.timestamp() < to_date.timestamp():
        db_names.add(get_month_db_from_date(current))
        current = current + relativedelta(months=1)

    db_names.add(get_month_db_from_date(to_date))
    return db_names


def main():
    try:
        investigations: Dict = {}
        for db_name in get_month_database_names():
            raw_output = demisto.executeCommand('getDBStatistics', args={"filter": db_name})
            get_investigations(raw_output[0].get('Contents', {}), investigations)
        demisto.results(parse_investigations_to_table(investigations))
    except Exception:
        demisto.error(traceback.format_exc())  # print the traceback
        return_error(f'Failed to execute GetLargestInvestigations. Error: {traceback.format_exc()}')


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
