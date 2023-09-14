import demistomock as demisto
from CommonServerPython import *

""" IMPORTS """
import base64
import json
import time
import devodsconnector as ds
import concurrent.futures
import tempfile
import urllib.parse
import re
import os
from datetime import datetime
from devo.sender import Lookup, SenderConfigSSL, Sender
from devodsconnector import error_checking
from functools import partial


""" GLOBAL VARS """
ALLOW_INSECURE = demisto.params().get("insecure", False)
READER_ENDPOINT = demisto.params().get("reader_endpoint", None)
READER_OAUTH_TOKEN = demisto.params().get("reader_oauth_token", None)
WRITER_RELAY = demisto.params().get("writer_relay", None)
WRITER_CREDENTIALS = demisto.params().get("writer_credentials", None)
LINQ_LINK_BASE = demisto.params().get("linq_link_base", "https://us.devo.com/welcome")
FETCH_INCIDENTS_FILTER = demisto.params().get("fetch_incidents_filters", None)
FETCH_INCIDENTS_LIMIT = demisto.params().get("fetch_incidents_limit") or 50
FETCH_INCIDENTS_LOOKBACK_SECONDS = demisto.params().get("fetch_incidents_lookback_seconds") or 3600
# Deprecated: this parameter is never used
FETCH_INCIDENTS_DEDUPE = demisto.params().get("fetch_incidents_deduplication", None)
FETCH_INCIDENTS_WINDOW = demisto.params().get("fetch_incidents_window")
TIMEOUT = demisto.params().get("timeout", "60")
PORT = arg_to_number(demisto.params().get("port", "443") or "443")
ITEMS_PER_PAGE = 50
HEALTHCHECK_WRITER_RECORD = [{"hello": "world", "from": "demisto-integration"}]
HEALTHCHECK_WRITER_TABLE = "test.keep.free"
RANGE_PATTERN = re.compile("^[0-9]+ [a-zA-Z]+")
TIMESTAMP_PATTERN = re.compile("^[0-9]+")
TIMESTAMP_PATTERN_MILLI = re.compile("^[0-9]+.[0-9]+")
COUNT_SINGLE_TABLE = 0
COUNT_MULTI_TABLE = 0
COUNT_ALERTS = 0
USER_ALERT_TABLE = demisto.params().get("table_name", None)
USER_PREFIX = demisto.params().get("prefix", None)
INCIDENTS_FETCH_INTERVAL = demisto.params().get("incidentFetchInterval", 1) * 60
DEFAULT_ALERT_TABLE = "siem.logtrust.alert.info"
ALERTS_QUERY = """
from
    {table_name}
select
    eventdate,
    {user_prefix}alertHost,
    {user_prefix}domain,
    {user_prefix}priority,
    {user_prefix}context,
    {user_prefix}category,
    {user_prefix}status,
    {user_prefix}alertId,
    {user_prefix}srcIp,
    {user_prefix}srcPort,
    {user_prefix}srcHost,
    {user_prefix}dstIp,
    {user_prefix}dstPort,
    {user_prefix}dstHost,
    {user_prefix}application,
    {user_prefix}engine,
    {user_prefix}extraData
"""

HEALTHCHECK_QUERY = """
from
    test.keep.free
select
    *
"""

SEVERITY_LEVELS_MAP = {
    "1": 0.5,
    "2": 1,
    "3": 2,
    "4": 3,
    "5": 4,
    "informational": 0.5,
    "low": 1,
    "medium": 2,
    "high": 3,
    "critical": 4,
}

""" HELPER FUNCTIONS """


def alert_to_incident(alert, user_prefix):
    alert_severity = float(1)
    context = f"{user_prefix}context"
    alert_id = f"{user_prefix}alertId"
    extra_data = f"{user_prefix}extraData"
    event_date = "eventdate"
    alert_name = alert[context].split(".")[-1]
    alert_description = None
    alert_details = str(alert[alert_id])
    alert_occurred = demisto_ISO(float(alert[event_date]) / 1000)
    alert_labels = []
    try:
        if "alertPriority" in alert[extra_data]:
            priority = alert[extra_data].get("alertPriority")
            if (
                priority
                and priority != "null"
                and priority.lower() in SEVERITY_LEVELS_MAP
            ):
                alert_severity = SEVERITY_LEVELS_MAP[priority.lower()]

        if "alertName" in alert[extra_data]:
            name = alert[extra_data].get("alertName")
            if name and name != "null":
                alert_name = name

        if "alertDescription" in alert[extra_data]:
            description = alert[extra_data].get("alertDescription")
            if description and description != "null":
                alert_description = description

    except KeyError:
        demisto.debug(
            "Couldn't get alertPriority, alertName, and/or alertDescription, will take default values"
        )

    new_alert: dict = {"devo.metadata.alert": {}}
    for key in alert:
        if key == extra_data:
            continue
        new_alert["devo.metadata.alert"][key] = alert[key]
        alert_labels.append(
            {"type": f"devo.metadata.alert.{key}", "value": str(alert[key])}
        )
    for key in alert[extra_data]:
        new_alert[key] = alert[extra_data][key]
        alert_labels.append({"type": f"{key}", "value": str(alert[extra_data][key])})

    incident = {
        "name": alert_name,
        "severity": alert_severity,
        "details": alert_details,
        "description": alert_description,
        "occurred": alert_occurred,
        "labels": alert_labels,
        "rawJSON": json.dumps(new_alert),
    }

    return incident


# Monkey patching for backwards compatibility


def get_types(self, linq_query, start, ts_format):
    type_map = self._make_type_map(ts_format)
    stop = self._to_unix(start)
    start = stop - 1

    response = self._query(
        linq_query, start=start, stop=stop, mode="json/compact", limit=1
    )

    try:
        data = json.loads(response)
        error_checking.check_status(data)
    except ValueError:
        raise Exception("API V2 response error")

    col_data = data["object"]["m"]
    type_dict = {c: type_map[v["type"]] for c, v in col_data.items()}

    return type_dict


def build_link(query, start_ts_milli, end_ts_milli, mode="queryApp", linq_base=None):
    myb64str = base64.b64encode(

        json.dumps(
            {
                "query": query,
                "mode": mode,
                "dates": {"from": start_ts_milli, "to": end_ts_milli},
            }
        ).encode("ascii")

    ).decode()

    if linq_base:
        url = f"{linq_base}/#/vapps/app.custom.queryApp_dev?&targetQuery={myb64str}"
    else:
        url = (
            f"{LINQ_LINK_BASE}/#/vapps/app.custom.queryApp_dev?&targetQuery={myb64str}"
        )

    return url


def check_configuration():
    # Check all settings related if set
    # Basic functionality of integration
    list(
        ds.Reader(
            oauth_token=READER_OAUTH_TOKEN,
            end_point=READER_ENDPOINT,
            verify=not ALLOW_INSECURE,
        ).query(
            HEALTHCHECK_QUERY,
            start=int(time.time() - 1),
            stop=int(time.time()),
            output="dict",
        )
    )

    if WRITER_RELAY and WRITER_CREDENTIALS:
        creds = get_writer_creds()
        Sender(
            SenderConfigSSL(
                address=(WRITER_RELAY, PORT),
                key=creds["key"].name,
                cert=creds["crt"].name,
                chain=creds["chain"].name,
            )
        ).send(tag=HEALTHCHECK_WRITER_TABLE, msg=f"{HEALTHCHECK_WRITER_RECORD}")

    if FETCH_INCIDENTS_FILTER:
        alert_filters = check_type(FETCH_INCIDENTS_FILTER, dict)

        assert "type" in alert_filters, 'Missing key: "type" in fetch_incidents_filters'
        assert alert_filters["type"] in ["AND", "OR"], 'Unsupported value in fetch_incidents_filters.type'

        filters = check_type(alert_filters.get("filters"), list)
        assert filters, 'Missing key: "filters" in fetch_incidents_filters'

        for filt in filters:
            assert "key" in filt, 'Missing key: "key" in fetch_incidents_filters.filters configuration'
            assert filt["key"], 'Empty value for "key" in fetch_incidents_filters.filters configuration'

            assert "operator" in filt, 'Missing key: "operator" in fetch_incidents_filters.filters configuration'
            assert filt["operator"] in ["=", "!=", "/=", ">", "<", ">=", "<=", "and", "or",
                                        "->"], 'Unsupported operator in fetch_incidents_filters.filters configuration'

            assert "value" in filt, 'Missing key: "value" in fetch_incidents_filters.filters configuration'
            assert filt["value"], 'Empty value for "value" in fetch_incidents_filters.filters configuration'

    # Deprecated: this parameter is never used
    if FETCH_INCIDENTS_DEDUPE:
        dedupe_conf = check_type(FETCH_INCIDENTS_DEDUPE, dict)
        assert (isinstance(dedupe_conf["cooldown"], int | float)), "Invalid fetch_incidents_deduplication configuration"

    return True


def check_type(input, tar_type):
    if (
        tar_type == list
        and isinstance(input, str)
        and input.startswith("[")
        and input.endswith("]")
    ):
        input = input.replace("[", "").replace("]", "").replace("'", "")
        input = input.split(",")

    if isinstance(input, str):
        input = json.loads(input)
        if not isinstance(input, tar_type):
            raise ValueError(
                f"tables to query should either be a json string of a {tar_type} or a {tar_type} input"
            )
    elif isinstance(input, tar_type):
        pass
    else:
        raise ValueError(
            f"tables to query should either be a json string of a {tar_type} or a {tar_type} input"
        )
    return input


# Converts epoch (miliseconds) to ISO string
def demisto_ISO(s_epoch):
    if s_epoch >= 0:
        return datetime.utcfromtimestamp(s_epoch).strftime("%Y-%m-%dT%H:%M:%S.%fZ")
    return s_epoch


# We will assume timestamp_from and timestamp_to will be the same format or to will be None
def get_time_range(timestamp_from, timestamp_to):
    if isinstance(timestamp_from, int) or isinstance(timestamp_from, float):
        t_from = timestamp_from
        t_to = time.time() if timestamp_to is None else timestamp_to
    elif isinstance(timestamp_from, str):
        if re.fullmatch(RANGE_PATTERN, timestamp_from):
            t_range = parse_date_range(timestamp_from)
            t_from = t_range[0].timestamp()
            t_to = t_range[1].timestamp()
        elif re.fullmatch(TIMESTAMP_PATTERN, timestamp_from) or re.fullmatch(
            TIMESTAMP_PATTERN_MILLI, timestamp_from
        ):
            t_from = float(timestamp_from)
            t_to = time.time() if timestamp_to is None else float(timestamp_to)
        else:
            t_from = date_to_timestamp(timestamp_from) / 1000
            t_to = time.time() if timestamp_to is None else date_to_timestamp(timestamp_to) / 1000
    elif isinstance(timestamp_from, datetime):
        t_from = timestamp_from.timestamp()
        t_to = time.time() if timestamp_to is None else timestamp_to.timestamp()

    return (t_from, t_to)


def get_writer_creds():
    if WRITER_RELAY is None:
        raise ValueError("writer_relay is not set in your Devo Integration")

    if WRITER_CREDENTIALS is None:
        raise ValueError("writer_credentials are not set in your Devo Integration")

    write_credentials = check_type(WRITER_CREDENTIALS, dict)
    assert (
        "key" in write_credentials
    ), 'Required key: "key" is not present in writer credentials'
    assert (
        "crt" in write_credentials
    ), 'Required key: "crt" is not present in writer credentials'
    assert (
        "chain" in write_credentials
    ), 'Required key: "chain" is not present in writer credentials'

    # Limitation in Devo DS Connector SDK. Currently require filepaths for credentials.
    # Will accept file-handler type objects in the future.
    key_tmp = tempfile.NamedTemporaryFile(mode="w")
    crt_tmp = tempfile.NamedTemporaryFile(mode="w")
    chain_tmp = tempfile.NamedTemporaryFile(mode="w")

    key_tmp.write(write_credentials["key"])
    crt_tmp.write(write_credentials["crt"])
    chain_tmp.write(write_credentials["chain"])

    key_tmp.flush()
    crt_tmp.flush()
    chain_tmp.flush()

    creds = {"key": key_tmp, "crt": crt_tmp, "chain": chain_tmp}

    return creds


def parallel_query_helper(sub_query, append_list, timestamp_from, timestamp_to):
    append_list.extend(
        list(
            ds.Reader(
                oauth_token=READER_OAUTH_TOKEN,
                end_point=READER_ENDPOINT,
                verify=not ALLOW_INSECURE,
            ).query(
                sub_query,
                start=float(timestamp_from),
                stop=float(timestamp_to),
                output="dict",
                ts_format="iso",
            )
        )
    )


""" FUNCTIONS """


def fetch_incidents():
    demisto.debug(f"ts: {time.time()} | func: fetch_incidents | msg: begin fetch incidents")
    last_run = demisto.getLastRun()
    demisto.debug(f"ts: {time.time()} | func: fetch_incidents | msg: last_run = {last_run}")
    user_prefix = f"{USER_PREFIX}_" if USER_PREFIX else ""
    user_alert_table = USER_ALERT_TABLE if USER_ALERT_TABLE else DEFAULT_ALERT_TABLE
    alert_query = ALERTS_QUERY.format(
        table_name=user_alert_table, user_prefix=user_prefix
    )
    to_time = time.time()
    from_time = 0.0
    alert_id = f"{user_prefix}alertId"
    cur_events: list = []
    final_events: list = []
    new_last_run: dict = {}

    if int(FETCH_INCIDENTS_LIMIT) < 10 or int(FETCH_INCIDENTS_LIMIT) > 100:
        raise ValueError(
            "Fetch incidents limit should be greater than or equal to 10 and smaller than or equal to 100"
        )

    if FETCH_INCIDENTS_FILTER:
        alert_filters = check_type(FETCH_INCIDENTS_FILTER, dict)

        if alert_filters["type"] == "AND":
            filter_string = " , ".join(
                [
                    f'{user_prefix}{filt["key"]} {filt["operator"]} "{urllib.parse.quote(filt["value"])}"'
                    for filt in alert_filters["filters"]
                ]
            )
        elif alert_filters["type"] == "OR":
            filter_string = " or ".join(
                [
                    f'{user_prefix}{filt["key"]} {filt["operator"]} "{urllib.parse.quote(filt["value"])}"'
                    for filt in alert_filters["filters"]
                ]
            )

        alert_query = f"{alert_query} where {filter_string}"

    alert_query = f"{alert_query} limit {FETCH_INCIDENTS_LIMIT}"

    if FETCH_INCIDENTS_WINDOW:
        # Use the configured window for from_time if FETCH_INCIDENTS_WINDOW is set
        from_time = to_time - float(FETCH_INCIDENTS_WINDOW)
    elif "from_time" in last_run:
        # If FETCH_INCIDENTS_WINDOW is not set and it is incremental pull
        from_time = float(last_run["from_time"])
        new_last_run["from_time"] = from_time
    else:
        # If FETCH_INCIDENTS_WINDOW is not set and if it is initial pull
        from_time = to_time - float(FETCH_INCIDENTS_LOOKBACK_SECONDS)
        new_last_run["from_time"] = from_time

    demisto.debug(f"ts: {time.time()} | func: fetch_incidents | msg: alerts_query = {alert_query}")
    demisto.debug(f"ts: {time.time()} | func: fetch_incidents | msg: start = {from_time} , stop = {to_time}")

    # execute the query and get the events
    # reverse the list so that the most recent event timestamp event is taken when de-duping if needed.
    events = list(
        ds.Reader(
            oauth_token=READER_OAUTH_TOKEN,
            end_point=READER_ENDPOINT,
            verify=not ALLOW_INSECURE,
            timeout=int(TIMEOUT),
        ).query(
            alert_query,
            start=float(from_time),
            stop=float(to_time),
            output="dict",
            ts_format="timestamp",
        )
    )

    extra_data = f"{user_prefix}extraData"
    event_date = "eventdate"

    # convert the events to demisto incident
    incidents = []

    demisto.debug(f"ts: {time.time()} | func: fetch_incidents | msg: number of alerts returned {len(events)}")

    # de duplicate events between two consecutive fetches
    if "last_fetch_events" in last_run:
        # Retrieve the alert Ids that is stored in the dictionary
        last_events_ids = []
        for record in last_run.get("last_fetch_events"):
            for key in record:
                last_events_ids.append(key)
        demisto.debug(f"List of event ids fetched in last poll: {last_events_ids}")
        for event in events:
            if event[alert_id] not in last_events_ids:
                final_events.append(event)
    else:
        final_events = events

    demisto.debug(f"ts: {time.time()} | func: fetch_incidents | msg: number of final_events {len(final_events)}")

    # Store in a list alert_id and timestamp of the alerts. [{alert_id:timestamp},{alert_id:timestamp}]
    for event in final_events:
        if not isinstance(event[extra_data], dict):
            event[extra_data] = json.loads(event[extra_data])
        for ed in event[extra_data]:
            if event[extra_data][ed] and isinstance(event[extra_data][ed], str):
                event[extra_data][ed] = urllib.parse.unquote_plus(event[extra_data][ed])
        cur_events.append({event[alert_id]: event[event_date] / 1000})
        inc = alert_to_incident(event, user_prefix)
        incidents.append(inc)

    # Combine the previously stored alert list with newly fetched alerts
    if last_run.get("last_fetch_events"):
        for record in last_run.get("last_fetch_events"):
            demisto.debug(record)
            cur_events.append(record)
    demisto.debug(cur_events)
    # update new_last_run and add the event_date of the last event fetched
    if len(final_events) > 0:
        new_last_run["from_time"] = max(event[event_date] for event in final_events) / 1000
    else:
        # set the to_time to current to_time, if no data recieved
        new_last_run["from_time"] = to_time

    from_previous_poll: list = []

    # Before completing the run removing the expired alerts in a list based on the timestamp
    for record in cur_events:
        for timestamp in record.values():
            if (timestamp > from_time):
                from_previous_poll.append(record)

    new_last_run["last_fetch_events"] = from_previous_poll

    demisto.setLastRun(new_last_run)

    demisto.debug(f"ts: {time.time()} | func: fetch_incidents | msg: last_run_set = {new_last_run}")
    demisto.debug(f"ts: {time.time()} | func: fetch_incidents | msg: number of incidents generated {len(incidents)}")

    # this command will create incidents in Demisto
    demisto.incidents(incidents)

    return incidents


def run_query_command(offset, items):
    to_query = demisto.args()["query"]
    timestamp_from = demisto.args()["from"]
    timestamp_to = demisto.args().get("to", None)
    write_context = demisto.args()["writeToContext"].lower()
    query_timeout = int(demisto.args().get("queryTimeout", TIMEOUT))
    linq_base = demisto.args().get("linqLinkBase", None)
    time_range = get_time_range(timestamp_from, timestamp_to)
    to_query = f"{to_query} offset {offset} limit {items}"
    results = list(
        ds.Reader(
            oauth_token=READER_OAUTH_TOKEN,
            end_point=READER_ENDPOINT,
            verify=not ALLOW_INSECURE,
            timeout=query_timeout,
        ).query(
            to_query,
            start=float(time_range[0]),
            stop=float(time_range[1]),
            output="dict",
            ts_format="iso",
        )
    )
    global COUNT_SINGLE_TABLE
    COUNT_SINGLE_TABLE = len(results)
    querylink = {
        "DevoTableLink": build_link(
            to_query,
            int(1000 * float(time_range[0])),
            int(1000 * float(time_range[1])),
            linq_base=linq_base,
        )
    }

    entry = {
        "Type": entryTypes["note"],
        "Contents": results,
        "ContentsFormat": formats["json"],
        "ReadableContentsFormat": formats["markdown"],
    }
    entry_linq = {
        "Type": entryTypes["note"],
        "Contents": querylink,
        "ContentsFormat": formats["json"],
        "ReadableContentsFormat": formats["markdown"],
    }

    if len(results) == 0:
        entry["HumanReadable"] = "No results found"
        entry["Devo.QueryResults"] = None
        entry["Devo.QueryLink"] = querylink
        return entry
    headers = list(results[0].keys())

    md = tableToMarkdown("Devo query results", results, headers)
    entry["HumanReadable"] = md

    md_linq = tableToMarkdown(
        "Link to Devo Query",
        {"DevoTableLink": f'[Devo Direct Link]({querylink["DevoTableLink"]})'},
    )
    entry_linq["HumanReadable"] = md_linq

    if write_context == "true":
        entry["EntryContext"] = {"Devo.QueryResults": createContext(results)}
        entry_linq["EntryContext"] = {"Devo.QueryLink": createContext(querylink)}
    return [entry, entry_linq]


def get_alerts_command(offset, items):
    timestamp_from = demisto.args()["from"]
    timestamp_to = demisto.args().get("to", None)
    alert_filters = demisto.args().get("filters", None)
    write_context = demisto.args()["writeToContext"].lower()
    query_timeout = int(demisto.args().get("queryTimeout", TIMEOUT))
    linq_base = demisto.args().get("linqLinkBase", None)
    user_alert_table = demisto.args().get("table_name", None)
    user_prefix = demisto.args().get("prefix", "")
    user_alert_table = user_alert_table if user_alert_table else DEFAULT_ALERT_TABLE
    if user_prefix:
        user_prefix = f"{user_prefix}_"
    alert_query = ALERTS_QUERY.format(
        table_name=user_alert_table, user_prefix=user_prefix
    )

    query = f"{alert_query} offset {offset} limit {items}"
    time_range = get_time_range(timestamp_from, timestamp_to)

    if alert_filters:
        alert_filters = check_type(alert_filters, dict)
        if alert_filters["type"] == "AND":
            filter_string = ", ".join(
                [
                    f'{filt["key"]} {filt["operator"]} "{urllib.parse.quote(filt["value"])}"'
                    for filt in alert_filters["filters"]
                ]
            )
        elif alert_filters["type"] == "OR":
            filter_string = " or ".join(
                [
                    f'{filt["key"]} {filt["operator"]} "{urllib.parse.quote(filt["value"])}"'
                    for filt in alert_filters["filters"]
                ]
            )
        alert_query = f"{alert_query} where {filter_string}"

    results = list(
        ds.Reader(
            oauth_token=READER_OAUTH_TOKEN,
            end_point=READER_ENDPOINT,
            verify=not ALLOW_INSECURE,
            timeout=query_timeout,
        ).query(
            query,
            start=float(time_range[0]),
            stop=float(time_range[1]),
            output="dict",
            ts_format="iso",
        )
    )

    global COUNT_ALERTS
    COUNT_ALERTS = len(results)

    querylink = {
        "DevoTableLink": build_link(
            alert_query,
            int(1000 * float(time_range[0])),
            int(1000 * float(time_range[1])),
            linq_base=linq_base,
        )
    }

    extra_data = f"{user_prefix}extraData"

    for res in results:
        if not isinstance(res[extra_data], dict):
            res[extra_data] = json.loads(res[extra_data])

        for ed in res[extra_data]:
            res[extra_data][ed] = urllib.parse.unquote_plus(res[extra_data][ed])

    entry = {
        "Type": entryTypes["note"],
        "Contents": results,
        "ContentsFormat": formats["json"],
        "ReadableContentsFormat": formats["markdown"],
    }
    entry_linq = {
        "Type": entryTypes["note"],
        "Contents": querylink,
        "ContentsFormat": formats["json"],
        "ReadableContentsFormat": formats["markdown"],
    }

    if len(results) == 0:
        entry["HumanReadable"] = "No results found"
        entry["Devo.AlertsResults"] = None
        entry_linq["Devo.QueryLink"] = querylink
        return entry

    headers = list(results[0].keys())

    md = tableToMarkdown("Devo query results", results, headers)
    entry["HumanReadable"] = md

    md_linq = tableToMarkdown(
        "Link to Devo Query",
        {"DevoTableLink": f'[Devo Direct Link]({querylink["DevoTableLink"]})'},
    )
    entry_linq["HumanReadable"] = md_linq

    if write_context == "true":
        entry["EntryContext"] = {"Devo.AlertsResults": createContext(results)}
        entry_linq["EntryContext"] = {"Devo.QueryLink": createContext(querylink)}

    # raise Exception("on line 530")
    return [entry, entry_linq]


def multi_table_query_command(offset, items):
    tables_to_query = check_type(demisto.args()["tables"], list)
    search_token = demisto.args()["searchToken"]
    timestamp_from = demisto.args()["from"]
    timestamp_to = demisto.args().get("to", None)
    write_context = demisto.args()["writeToContext"].lower()
    query_timeout = int(demisto.args().get("queryTimeout", TIMEOUT))
    global COUNT_MULTI_TABLE
    time_range = get_time_range(timestamp_from, timestamp_to)

    futures = []
    all_results: List[dict] = []
    sub_queries = []

    ds_read = ds.Reader(
        oauth_token=READER_OAUTH_TOKEN,
        end_point=READER_ENDPOINT,
        verify=not ALLOW_INSECURE,
        timeout=query_timeout,
    )
    ds_read.get_types = partial(get_types, ds_read)

    for table in tables_to_query:
        fields = ds_read.get_types(f"from {table} select *", "now", "iso").keys()
        clauses = [
            f'( isnotnull({field}) and str({field})->"' + search_token + '")'
            for field in fields
        ]
        sub_queries.append(
            "from "
            + table
            + " where"
            + " or ".join(clauses)
            + " select *"
            + " offset "
            + str(offset)
            + " limit "
            + str(items)
        )

    with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
        for q in sub_queries:
            futures.append(
                executor.submit(
                    parallel_query_helper, q, all_results, time_range[0], time_range[1]
                )
            )

    concurrent.futures.wait(futures)

    entry = {
        "Type": entryTypes["note"],
        "Contents": all_results,
        "ContentsFormat": formats["json"],
        "ReadableContentsFormat": formats["markdown"],
    }

    COUNT_MULTI_TABLE = len(all_results)
    if len(all_results) == 0:
        entry["HumanReadable"] = "No results found"
        return entry

    headers: set = set().union(*(r.keys() for r in all_results))

    md = tableToMarkdown("Devo query results", all_results, headers)
    entry["HumanReadable"] = md

    if write_context == "true":
        entry["EntryContext"] = {"Devo.MultiResults": createContext(all_results)}
    return entry


def write_to_table_command():
    table_name = demisto.args()["tableName"]
    records = check_type(demisto.args()["records"], list)
    linq_base = demisto.args().get("linqLinkBase", None)

    creds = get_writer_creds()
    linq = f"from {table_name}"

    sender = Sender(
        SenderConfigSSL(
            address=(WRITER_RELAY, PORT),
            key=creds["key"].name,
            cert=creds["crt"].name,
            chain=creds["chain"].name,
        )
    )

    for r in records:
        try:
            sender.send(tag=table_name, msg=json.dumps(r))
        except TypeError:
            sender.send(tag=table_name, msg=f"{r}")

    querylink = {
        "DevoTableLink": build_link(
            linq,
            int(1000 * time.time()) - 3600000,
            int(1000 * time.time()),
            linq_base=linq_base,
        )
    }

    entry = {
        "Type": entryTypes["note"],
        "Contents": {"recordsWritten": records},
        "ContentsFormat": formats["json"],
        "ReadableContentsFormat": formats["markdown"],
        "EntryContext": {"Devo.RecordsWritten": records, "Devo.LinqQuery": linq},
    }
    entry_linq = {
        "Type": entryTypes["note"],
        "Contents": querylink,
        "ContentsFormat": formats["json"],
        "ReadableContentsFormat": formats["markdown"],
        "EntryContext": {"Devo.QueryLink": createContext(querylink)},
    }
    headers: list = []
    resultRecords: list = []
    innerDict: dict = {}
    for obj in records:
        record = json.loads(obj)
        currKey = list(record.keys())
        currValue = list(record.values())

        headers.extend(currKey)

        innerDict.update(dict(zip(currKey, currValue)))  # Create a dictionary using zip
    resultRecords.append(innerDict)  # Append the dictionary to the list

    demisto.debug("final array :")
    demisto.debug(resultRecords)

    md = tableToMarkdown("Entries to load into Devo", resultRecords, headers)
    entry["HumanReadable"] = md

    md_linq = tableToMarkdown(
        "Link to Devo Query",
        {"DevoTableLink": f'[Devo Direct Link]({querylink["DevoTableLink"]})'},
    )
    entry_linq["HumanReadable"] = md_linq

    return [entry, entry_linq]


def write_to_lookup_table_command():
    lookup_table_name = demisto.args()["lookupTableName"]
    headers = check_type(demisto.args()["headers"], list)
    records = check_type(demisto.args()["records"], list)

    creds = get_writer_creds()

    engine_config = SenderConfigSSL(
        address=(WRITER_RELAY, PORT),
        key=creds["key"].name,
        cert=creds["crt"].name,
        chain=creds["chain"].name,
    )

    try:
        con = Sender(config=engine_config, timeout=60)

        lookup = Lookup(name=lookup_table_name, historic_tag=None, con=con)
        # Order sensitive list
        pHeaders = json.dumps(headers)

        lookup.send_control("START", pHeaders, "INC")

        for r in records:
            lookup.send_data_line(key_index=0, fields=r["values"])

        lookup.send_control("END", pHeaders, "INC")
    finally:
        con.flush_buffer()
        con.socket.shutdown(0)

    entry = {
        "Type": entryTypes["note"],
        "Contents": {"recordsWritten": records},
        "ContentsFormat": formats["json"],
        "ReadableContentsFormat": formats["markdown"],
        "EntryContext": {"Devo.RecordsWritten": records},
    }

    md = tableToMarkdown("Entries to load into Devo", records)
    entry["HumanReadable"] = md

    return [entry]


def main():
    """EXECUTION CODE"""
    try:
        if ALLOW_INSECURE:
            os.environ["CURL_CA_BUNDLE"] = ""
            os.environ["PYTHONWARNINGS"] = "ignore:Unverified HTTPS request"
        handle_proxy()
        if demisto.command() == "test-module":
            check_configuration()
            demisto.results("ok")
        elif demisto.command() == "fetch-incidents":
            fetch_incidents()
        elif demisto.command() == "devo-run-query":
            from_date = int(demisto.args().get("from"))
            to_date = int(demisto.args().get("to"))
            current_time = int(time.time())

            if from_date > current_time or to_date > current_time:
                raise ValueError("Date should not be greature then current time")
            OFFSET = 0
            items_per_page = int(demisto.args().get("items_per_page", ITEMS_PER_PAGE))

            if items_per_page <= 0:
                raise ValueError("items_per_page should be a positive non-zero value.")
            total = 0
            demisto.results(run_query_command(OFFSET, items_per_page))
            total = total + COUNT_SINGLE_TABLE
            while items_per_page == COUNT_SINGLE_TABLE:
                OFFSET = OFFSET + items_per_page
                total = total + COUNT_SINGLE_TABLE
                demisto.results(run_query_command(OFFSET, items_per_page))
        elif demisto.command() == "devo-get-alerts":
            from_date = int(demisto.args().get("from"))
            to_date = int(demisto.args().get("to"))
            current_time = int(time.time())

            if from_date > current_time or to_date > current_time:
                raise ValueError("Date should not be greature then current time")
            OFFSET = 0
            items_per_page = int(demisto.args().get("items_per_page", ITEMS_PER_PAGE))
            if items_per_page <= 0:
                raise ValueError("items_per_page should be a positive non-zero value.")
            total = 0
            demisto.results(get_alerts_command(OFFSET, items_per_page))
            total = total + COUNT_ALERTS
            while items_per_page == COUNT_ALERTS:
                OFFSET = OFFSET + items_per_page
                total = total + COUNT_ALERTS
                demisto.results(get_alerts_command(OFFSET, items_per_page))
        elif demisto.command() == "devo-multi-table-query":
            OFFSET = 0
            items_per_page = int(demisto.args().get("items_per_page", ITEMS_PER_PAGE))
            if items_per_page <= 0:
                raise ValueError("items_per_page should be a positive non-zero value.")
            total = 0
            demisto.results(multi_table_query_command(OFFSET, items_per_page))
            total = total + COUNT_MULTI_TABLE
            while items_per_page * 2 == COUNT_MULTI_TABLE:
                OFFSET = OFFSET + items_per_page
                total = total + COUNT_MULTI_TABLE
                demisto.results(multi_table_query_command(OFFSET, items_per_page))
        elif demisto.command() == "devo-write-to-table":
            demisto.results(write_to_table_command())
        elif demisto.command() == "devo-write-to-lookup-table":
            demisto.results(write_to_lookup_table_command())
    except Exception as e:
        return_error(
            f"Failed to execute command {demisto.command()}. Error: {str(e)}."
        )


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
