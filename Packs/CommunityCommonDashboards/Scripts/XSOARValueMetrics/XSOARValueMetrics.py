import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401


import csv
import pandas as pd
from datetime import datetime
from calendar import monthrange
from collections import defaultdict

MAXINC = 2000
XDEBUG = True
MONTHS_ABBR = [datetime.strptime(str(month), '%m').strftime('%b') for month in range(1, 13)]

SEVERITY = {
    'unknown': 0,
    'information': 0.5,
    'low': 1,
    'medium': 2,
    'high': 3,
    'critical': 4
}

STATUS = {
    'pending': 0,
    'active': 1,
    'done': 2,
    'archive': 3
}


def LogMessage(message: str) -> str:
    if XDEBUG:
        timestr = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        return f"{timestr} | {message}\n"
    return ""


def IncidentRecord(inc: dict, slatimers: list, windowstart: str, windowend: str, computeduration: str) -> dict:
    if computeduration == "yes":
        deltatime = ToDatetime(str(inc.get('closed'))) - ToDatetime(str(inc.get('created')))
        duration = int(deltatime.total_seconds())
    else:
        duration = int(inc.get('openDuration', 0))
    record = {
        'type': inc.get('type'),
        'status': inc.get('status'),
        'created': inc.get('created'),
        'occurred': inc.get('occurred'),
        'duration': duration,
        'contime': "-1",
        'dettime': "-1",
        'remtime': "-1",
        'asstime': "-1",
        'tritime': "-1",
        'UserWindow': "-1"
    }

    for timer in slatimers:
        record[timer] = "-1"
    fields = ['containmentsla', 'detectionsla', 'remediationsla', 'timetoassignment', 'triagesla']
    timers = ['contime', 'dettime', 'remtime', 'asstime', 'tritime', 'UserWindow']

    if inc.get('status') == STATUS['done'] and isinstance(inc.get('CustomFields'), dict):
        for field, timer in zip(fields, timers):
            if field in inc['CustomFields'] and inc['CustomFields'][field]['runStatus'] == "ended":
                record[timer] = inc['CustomFields'][field]['totalDuration']

        for timer in slatimers:
            if timer in inc['CustomFields'] and inc['CustomFields'][timer]['runStatus'] == "ended":
                record[timer] = inc['CustomFields'][timer]['totalDuration']

        if (windowstart != "" and windowend != "" and windowstart in inc['CustomFields'] and windowend in inc['CustomFields']
            and inc['CustomFields'][windowstart]['runStatus'] == "ended" and
                    inc['CustomFields'][windowend]['runStatus'] == "ended"):
                winduration = ToDatetime(inc['CustomFields'][windowend]['endDate']) - \
                    ToDatetime(inc['CustomFields'][windowstart]['startDate'])
                record['UserWindow'] = winduration.total_seconds()

    return record


def TopTwenty(incsumm: dict) -> list:
    sorted_inc = dict(sorted(incsumm.items(), key=lambda item: len(item[1]), reverse=True))
    removeKeys = list(sorted_inc.keys())[20:]
    return removeKeys


def MonthlyIncidents(removeKeys, monthly: dict) -> dict:
    for key in removeKeys:
        if key in monthly:
            del monthly[key]
    return monthly


def BuildWindows(start_date_str, end_date_str):
    # Convert the input strings to datetime objects
    start_date = datetime.strptime(start_date_str, '%Y-%m-%d')
    end_date = datetime.strptime(end_date_str, '%Y-%m-%d')
    result_dates = []
    current_date = start_date

    # Increment the window and store the first and last dates until reaching the end date
    while current_date <= end_date:
        # Get the first day of the current month
        day = 1  # initializing the parameter
        if current_date != start_date:
            start = current_date
        else:
            start = start_date
            day = start_date.day

        # Get the last day of the current window
        if current_date.year == end_date.year and current_date.month == end_date.month and current_date.day == end_date.day:
            last = end_date
        # Set the window to the next day, or last day of the month
        else:
            _, lastday = monthrange(current_date.year, current_date.month)
            day += 1
            # check to ensure did not step past the end of the month
            if current_date.year == end_date.year and current_date.month == end_date.month and day >= end_date.day:
                day = end_date.day
            elif day >= lastday:
                day = lastday
            last = current_date.replace(day=day)

        # Create the start, end date tuples for each window traversed
        result_dates.append((start.strftime('%Y-%m-%d'), last.strftime('%Y-%m-%d')))

        # Step to the next day of the window
        year = current_date.year
        month = current_date.month
        _, lastday = monthrange(year, month)
        day += 1
        if day > lastday:
            if month == 12:
                year += 1
            month = month % 12 + 1
            day = 1
        current_date = current_date.replace(year=year, month=month, day=day)

    return result_dates


def ToDatetime(date: str):
    # 2023-12-02T23:20:47Z' or 2023-12-02T23:20:47.000Z' for pre python 3.11 and XSOAR 8 timestamps
    if date.endswith("Z"):
        isodate = date.split(".", 1)[0].replace("Z", "", 1) + "+00:00"
        return datetime.fromisoformat(isodate)
    else:
        count = date.count('-')
        if count == 2:
            return datetime.strptime(date.rsplit('.', 1)[0], "%Y-%m-%dT%H:%M:%S")
        else:
            date, tz_offset = date.rsplit('-', 1)
            return datetime.fromisoformat(f"{date.rsplit('.', 1)[0]}-{tz_offset}")


def CloseMetrics(monthly_data: dict, records: list) -> str:
    # Process each record and count the closed incidents by month and 'type'
    for record in records:
        month = ToDatetime(record['created']).strftime('%b')
        if record['type'] not in monthly_data[month]:
            monthly_data[month][record['type']] = 0
        if record['status'] == STATUS['done']:
            monthly_data[month][record['type']] += 1
    return BuildCsv("Type", monthly_data)


def CountMetrics(counts: dict, records: list) -> str:
    # Process each record and store the incident count by month and 'type'
    for record in records:
        month = ToDatetime(record['created']).strftime('%b')
        if record['type'] not in counts[month]:
            counts[month][record['type']] = 0
        counts[month][record['type']] += 1
    return BuildCsv("Type", counts)


def DurationMetrics(records: list) -> str:
    # Create a dictionary to hold the monthly data for each 'type'
    monthly_data: dict = defaultdict(lambda: defaultdict(list))
    averages: dict = {month: {} for month in MONTHS_ABBR}

    # Process each record and aggregate the 'duration' data by month and 'type'
    for record in records:
        month = ToDatetime(record['created']).strftime('%b')
        monthly_data[record['type']][month].append(record['duration'])

    # Calculate the average for each 'type' field for each month
    for inctype, months in monthly_data.items():
        for month, durations in months.items():
            averages[month][inctype] = int(sum(durations) / len(durations))
    return BuildCsv("Type", averages)


def SlaMetrics(records: list, slatimers: list) -> str:
    # Initialize a dictionary to hold the aggregated metrics by month
    fieldnames = ['contime', 'dettime', 'remtime', 'asstime', 'tritime', 'UserWindow']
    fieldnames.extend(slatimers)
    monthly_data: dict = {key: {month: [] for month in MONTHS_ABBR} for key in fieldnames}
    averages: dict = {month: {} for month in MONTHS_ABBR}

    for record in records:
        month = ToDatetime(record['created']).strftime('%b')
        for field in fieldnames:
            if field in record and record[field] != -1:
                monthly_data[field][month].append(int(record[field]))

    for field, months in monthly_data.items():
        for month, metrics in months.items():
            length = len(metrics)
            total = 0
            for m in metrics:
                if m == -1:
                    length -= 1
                else:
                    total += m
            if length > 0:
                averages[month][field] = total / length
            else:
                averages[month][field] = 0

    return BuildCsv("Metric", averages)


def BuildCsv(key: str, data: dict) -> str:
    df = pd.DataFrame(data).fillna(0).astype(int)
    df[key] = df.index
    df = df.set_index(key)
    csv_data_string = df.to_csv()
    return csv_data_string


def SplitRecords(records: list) -> tuple[list, list]:
    curyear = ""
    thisyear: list = []
    lastyear: list = []

    for r in records:
        year = r['created'].split("-")[0]
        if curyear == "":
            curyear = year
        if curyear == year:
            lastyear.append(r)
        else:
            thisyear.append(r)

    return lastyear, thisyear


def GenerateTables(startday: str, endday: str, records: list, slatimers: list) -> tuple[str, dict, str, dict]:
    json_met: dict = {}
    json_met2: dict = {}
    json_met['YEAR'] = startday.split("-")[0]
    json_met2['YEAR'] = endday.split("-")[0]
    m = ""
    m2 = ""

    twoyears = json_met['YEAR'] != json_met2['YEAR']
    if twoyears:
        records, records2 = SplitRecords(records)

    monthly: dict = {month: {} for month in MONTHS_ABBR}
    metrics = CountMetrics(monthly, records)
    json_met['Incidents'] = CsvToJson(metrics)
    m = metrics + "\n"

    if twoyears:
        monthly = {month: {} for month in MONTHS_ABBR}
        metrics2 = CountMetrics(monthly, records2)
        json_met2['Incidents'] = CsvToJson(metrics2)
        m2 = metrics2 + "\n"

    monthly: dict = {month: {} for month in MONTHS_ABBR}
    metrics = CloseMetrics(monthly, records)
    json_met['Closed Incidents'] = CsvToJson(metrics)
    m += metrics + "\n"

    if twoyears:
        monthly = {month: {} for month in MONTHS_ABBR}
        metrics2 = CloseMetrics(monthly, records2)
        json_met2['Closed Incidents'] = CsvToJson(metrics2)
        m2 += metrics2 + "\n"

    metrics = DurationMetrics(records)
    json_met['Incident Open Duration'] = CsvToJson(metrics)
    m += metrics + "\n"

    if twoyears:
        metrics2 = DurationMetrics(records2)
        json_met2['Incident Open Duration'] = CsvToJson(metrics2)
        m2 += metrics2 + "\n"

    metrics = SlaMetrics(records, slatimers)
    json_met['SLA Metrics'] = CsvToJson(metrics)
    m += metrics

    if twoyears:
        metrics2 = SlaMetrics(records2, slatimers)
        json_met2['SLA Metrics'] = CsvToJson(metrics2)
        m2 += metrics2

    return m, json_met, m2, json_met2


def GetIncSmallWindow(w, page: int, curday: int, curhour: int, filters: dict, userquery: str):
    if userquery == "":
        query = {'page': page, 'size': MAXINC, 'fromdate': f"{w[curday]}T{curhour-4:02d}:00:00",
                 'todate': f"{w[curday]}T{curhour-1:02d}:59:59"}
        query.update(filters)
    else:
        userquery += f" occurred:>={w[curday]}T{curhour-4:02d}:00:00 and occurred:<={w[curday]}T{curhour-1:02d}:59:59"
        query = {'page': page, 'size': MAXINC, 'query': userquery}
    return execute_command("getIncidents", query, extract_contents=False)


def GetIncLargeWindow(w, page: int, filters: dict, userquery: str):
    if userquery == "":
        query = {'page': page, 'size': MAXINC, 'fromdate': f"{w[0]}T00:00:00", 'todate': f"{w[1]}T23:59:59"}
        query.update(filters)
    else:
        userquery += f" occurred:>={w[0]}T00:00:00 and occurred:<={w[1]}T23:59:59"
        query = {'page': page, 'size': MAXINC, 'query': userquery}
    return execute_command("getIncidents", query, extract_contents=False)


def ProcessResponse(w, response, monthly, period, inccount, slatimers, windowstart, windowend, computeduration):
    curmonth = w[0]
    if curmonth not in monthly:
        monthly[curmonth] = {}

    for inc in response[0]['Contents']['data']:
        rec = IncidentRecord(inc, slatimers, windowstart, windowend, computeduration)
        inccount += 1
        inctype = rec['type']

        if inctype not in monthly[curmonth]:
            monthly[curmonth][inctype] = []
        monthly[curmonth][inctype].append(rec)

        if inctype not in period:
            period[inctype] = []
        period[inctype].append(rec)
    return inccount, monthly, period


def ValidArgs(args: dict) -> bool:
    array_args = ['status', 'notstatus', 'severity', 'owner', 'type']
    return all(key in array_args for key, value in args.items())


def ValidFilter(fil: list) -> bool:
    if len(fil) != 2:
        return False
    k, v = fil
    filter_mappings: dict = {'status': STATUS, 'notstatus': STATUS, 'severity': SEVERITY}
    if k in filter_mappings:
        return v in filter_mappings[k]
    elif k in ['owner', 'type']:
        return True
    return False


def BuildFilters(filters: list) -> dict:
    filtargs: dict = {}
    if len(filters) == 0:
        return filtargs
    filter_mappings: dict = {'status': STATUS, 'notstatus': STATUS, 'severity': SEVERITY}

    for f in filters:
        newfil = [item.strip() for item in f.split("=")]
        if not ValidFilter(newfil):
            continue
        key, val = newfil
        newval = filter_mappings.get(key, {}).get(val, val)
        if key == 'severity':
            filtargs['level'] = newval
        else:
            filtargs[key] = newval
    return filtargs


def CsvToJson(csv_text: str) -> dict:
    lines = csv_text.strip("\n").split('\n')
    reader = csv.reader(lines)
    data = list(reader)
    header = data[0]  # Month labels
    series = [row[0] for row in data[1:]]  # Series labels
    json_data = {}

    for i, row in enumerate(data[1:]):
        series_data = {}
        for j, cell in enumerate(row[1:]):
            month = header[j + 1]
            series_data[month] = cell
        json_data[series[i]] = series_data

    return json_data


def RollYearList(thisyearlist: str, lastyearlist: str, curmetrics: dict):
    existing_metrics = LoadJsonList(thisyearlist)
    if 'YEAR' in existing_metrics and existing_metrics['YEAR'] != curmetrics['YEAR']:
        SaveJsonList(lastyearlist, existing_metrics)
        existing_metrics = {}
    SaveJsonList(thisyearlist, existing_metrics)


def UpdateMetricsList(listname: str, curmetrics: dict, mode: str):
    existing_metrics = LoadJsonList(listname)

    for key, val in curmetrics.items():
        if key in existing_metrics and key != 'YEAR':
            if key not in ['SLA Metrics', 'Incident Open Duration']:
                existing_metrics[key] = UpdateDict(existing_metrics[key], val, mode)
            else:
                existing_metrics[key] = UpdateDict(existing_metrics[key], val, "initialize")
        else:
            existing_metrics[key] = val

    SaveJsonList(listname, existing_metrics)


def UpdateDict(existing_dict: dict, new_dict: dict, mode: str) -> dict:
    for newkey, newvalue in new_dict.items():
        if newkey in existing_dict:
            for sub_key, sub_value in newvalue.items():
                if sub_key in existing_dict[newkey]:
                    if mode == "increment":
                        existing_dict[newkey][sub_key] = str(int(existing_dict[newkey][sub_key]) + int(sub_value))
                    elif mode == "initialize":
                        existing_dict[newkey][sub_key] = sub_value
                else:
                    existing_dict[newkey][sub_key] = sub_value
        else:
            existing_dict[newkey] = newvalue

    return existing_dict


def LoadJsonList(list_name: str) -> dict:
    results = demisto.executeCommand("getList", {'listName': list_name})[0]['Contents']
    if "Item not found" not in results:
        return json.loads(results)
    return {}


def SaveJsonList(list_name: str, json_data: dict):
    res = demisto.executeCommand('core-api-post', {
        "uri": '/lists/save',
        "body": {
            'name': list_name,
            'data': json.dumps(json_data),
            'type': "json"
        }
    })[0]['Contents']
    # If error, existing list, so set the list contents
    if "Script failed to run" in res:
        demisto.executeCommand("setList", {
            'listName': list_name,
            'listData': json.dumps(json_data)
        })


def NormalDate(date_str: str, first_day=True) -> str:
    if len(date_str.split("-")) == 3:
        return date_str
    year, month = map(int, date_str.split('-'))
    if first_day:
        return f"{year}-{month:02d}-01"
    else:
        _, last_day = monthrange(year, month)
        return f"{year}-{month:02d}-{last_day:02d}"


def FoundIncidents(res: List):
    if res and isinstance(res, list) and isinstance(res[0].get('Contents'), dict):
        if 'data' not in res[0]['Contents']:
            raise DemistoException(res[0].get('Contents'))
        elif res[0]['Contents']['data'] is None:
            return False
        return True
    return None


def main():
    try:
        XLOG = "\n"
        XLOG += LogMessage("Starting Incident Search")
        inccount = 0
        page = 0
        period: dict = {}
        monthly: dict = {}
        arguments = demisto.args()
        firstday = NormalDate(arguments['firstday'])
        lastday = NormalDate(arguments['lastday'], first_day=False)
        esflag = arguments['esflag']
        thisyear_list = arguments['thisyearlist']
        lastyear_list = arguments['lastyearlist']
        windowstart = arguments.get('windowstart', "")
        windowend = arguments.get('windowend', "")
        computeduration = arguments.get('computeduration', "no")
        mode = arguments['mode']
        query = arguments.get("query", "")
        filters = BuildFilters([item.strip().lower() for item in arguments.get('filters', "").split(",")])
        timers = arguments.get('slatimers')
        if timers:
            slatimers = [item.strip().lower() for item in timers.split(",")]
        else:
            slatimers = []
        windows = BuildWindows(firstday, lastday)

        for w in windows:
            XLOG += LogMessage(f"Start Two Day Window: {w[0]} | End: {w[1]} | {inccount}, {page}")
            page = 0

            while True:
                if esflag == "false":
                    response: List = GetIncLargeWindow(w, page, filters, query)
                    if not FoundIncidents(response):
                        break
                    inccount, monthly, period = ProcessResponse(w, response, monthly, period, inccount,
                                                                slatimers, windowstart, windowend, computeduration)
                    page += 1
                # Switch to 4 hour window if the ES flag is set since it thows error next page if
                # 10000 or more incidents were found even while paging through a smaller size page
                else:
                    curday = 0
                    curhour = 4
                    page = 0

                    # Process all the 4 hour windows in the two days
                    while True:
                        response = GetIncSmallWindow(w, page, curday, curhour, filters, query)
                        if FoundIncidents(response):
                            inccount, monthly, period = ProcessResponse(w, response, monthly, period, inccount,
                                                                        slatimers, windowstart, windowend, computeduration)
                            page += 1
                        # If no incidents found, step to the next 4 hour window
                        else:
                            curhour += 4
                            page = 0
                            # Are we done with the current day
                            if curhour > 24:
                                curhour = 4
                                # If on the second day of two day window, reset and start a new 2 day window
                                if curday == 1:
                                    curday = 0
                                    break
                                # On the first day of the 2 day window, step to the second day
                                else:  # noqa: RET508
                                    curday = 1

        XLOG += LogMessage(f"Total Found Incident Count {inccount}")
        # Limit the results to the top twenty incident types
        removeKeys = TopTwenty(period)
        for k, m in monthly.items():
            monthly[k] = MonthlyIncidents(removeKeys, m)

        # Create the list of records from the collected values
        records = []
        for m in monthly.values():
            for r in m.values():
                records.extend(r)

        XLOG += LogMessage(f"Top Twenty Incident Count: {len(records)}")
        metrics, json_metrics, metrics2, json_metrics2 = GenerateTables(firstday, lastday, records, slatimers)
        if mode != "noupdate":
            if mode != "initialize":
                RollYearList(thisyear_list, lastyear_list, json_metrics)
            if "Incidents" not in json_metrics2:
                UpdateMetricsList(thisyear_list, json_metrics, mode)
            else:
                UpdateMetricsList(lastyear_list, json_metrics, mode)
                UpdateMetricsList(thisyear_list, json_metrics2, mode)

        return_results(fileResult("xsoar_value_metrics.csv", metrics))
        if "Incidents" in json_metrics2:
            return_results(fileResult("xsoar_value_metrics2.csv", metrics2))
        return_results(XLOG)

    except Exception as ex:
        demisto.error(traceback.format_exc())
        return_error(f"XSOARValueMetrics: Exception failed to execute. Error: {str(ex)}\n{XLOG}\n")


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
