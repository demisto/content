import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *

import traceback
from typing import List, Dict
from operator import itemgetter
from dateutil.parser import parse
from dateutil.relativedelta import relativedelta


def get_investigations(raw_output, investigations):
    # in case getDBStatistics fails to fetch information it will return a message like so:
    # `Failed getting DB stats with filter [102020], minBytes [1000000]` - in this case there are no incidents to report
    if isinstance(raw_output, str):
        return
    for db in raw_output:
        buckets = db.get('buckets')
        for entry in buckets.keys():
            if entry.startswith('investigations-'):
                investigations[entry] = buckets.get(entry)
                investigations[entry].update({"Date": db.get('dbName')})


def parse_investigations_to_table(investigations, is_table_result):
    data: List = []
    widget_table = {"total": len(investigations)}
    urls = demisto.demistoUrls()
    server_url = urls.get('server', '')
    for investigation in investigations.keys():
        full_size = investigations[investigation].get('leafSize').split(' ')
        db_name = investigations[investigation].get('Date')
        size = float(full_size[0])
        if size >= 1.0 and full_size[1] == 'MB':
            if db_name.isdigit():
                inv_id = investigation.split('-')[1]
                inv_link = f"[{inv_id}]({os.path.join(server_url, '#', 'incident', inv_id)})"
                date = db_name[:2] + "-" + db_name[2:]
            else:
                inv_id = "-".join(investigation.split('-')[1:])
                inv_link = f"[playground]({os.path.join(server_url, '#', 'WarRoom', 'playground')})"
                date = ""
            inv_link = inv_id if is_table_result else inv_link
            data.append({
                "IncidentID": inv_link,
                "Size(MB)": int(size) if size == int(size) else size,
                "AmountOfEntries": investigations[investigation].get('keyN'),
                "Date": date
            })

    widget_table['data'] = sorted(data, key=itemgetter('Size(MB)'), reverse=True)  # type: ignore

    return widget_table


def get_month_db_from_date(date):
    month = date.strftime('%m')
    year = date.strftime('%Y')
    return month + year


def get_time_object(timestring, empty_res_as_now=True):
    empty_res = datetime.now() if empty_res_as_now else None
    if timestring is None or timestring == '':
        return empty_res

    date_object = parse(timestring)
    if date_object.year == 1:
        return empty_res
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
        args: Dict = demisto.args()
        from_date = args.get('from')
        is_table_result = args.get('table_result') == 'true'
        if not get_time_object(from_date, empty_res_as_now=False):
            raw_output = demisto.executeCommand('getDBStatistics', args={})
            get_investigations(raw_output[0].get('Contents', {}), investigations)
        else:
            for db_name in get_month_database_names():
                raw_output = demisto.executeCommand('getDBStatistics', args={"filter": db_name})
                get_investigations(raw_output[0].get('Contents', {}), investigations)
        result = parse_investigations_to_table(investigations, is_table_result)
        if not is_table_result:
            # change result to MD
            result = tableToMarkdown('Largest Incidents by Storage Size', result.get("data"),
                                     headers=["IncidentID", "Size(MB)", "AmountOfEntries", "Date"])
        demisto.results(result)
    except Exception:
        demisto.error(traceback.format_exc())  # print the traceback
        return_error(f'Failed to execute GetLargestInvestigations. Error: {traceback.format_exc()}')


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
