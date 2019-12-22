import demistomock as demisto
from CommonServerPython import *
''' IMPORTS '''
import base64
import json
import time
import devodsconnector as ds
import concurrent.futures
import tempfile
import urllib.parse
from datetime import datetime
from devo.sender import Lookup, SenderConfigSSL, Sender
from typing import List, Dict, Set

''' GLOBAL VARS '''
READER_ENDPOINT = demisto.params().get('reader_endpoint', None)
READER_OAUTH_TOKEN = demisto.params().get('reader_oauth_token', None)
WRITER_RELAY = demisto.params().get('writer_relay', None)
WRITER_CREDENTIALS = demisto.params().get('writer_credentials', None)
LINQ_LINK_BASE = demisto.params().get('linq_link_base', "https://us.devo.com/welcome")
FETCH_INCIDENTS_FILTER = demisto.params().get('fetch_incidents_filters', None)
FETCH_INCIDENTS_DEDUPE = demisto.params().get('fetch_incidents_deduplication', None)
HEALTHCHECK_WRITER_RECORD = [{'hello': 'world', 'from': 'demisto-integration'}]
HEALTHCHECK_WRITER_TABLE = 'test.keep.free'
ALERTS_QUERY = '''
from
    siem.logtrust.alert.info
select
    eventdate,
    alertHost,
    domain,
    priority,
    context,
    category,
    status,
    alertId,
    srcIp,
    srcPort,
    srcHost,
    dstIp,
    dstPort,
    dstHost,
    application,
    engine,
    extraData
'''
HEALTHCHECK_QUERY = '''
from
    test.keep.free
select
    *
'''
SEVERITY_LEVELS_MAP = {
    '1': 0.5,
    '2': 1,
    '3': 2,
    '4': 3,
    '5': 4,
    'informational': 0.5,
    'low': 1,
    'medium': 2,
    'high': 3,
    'critical': 4
}


''' HELPER FUNCTIONS '''


def alert_to_incident(alert):
    alert_severity = float(1)
    alert_name = alert['context'].split('.')[-1]
    alert_description = None
    alert_occurred = demisto_ISO(float(alert['eventdate']))
    alert_labels = []

    if demisto.get(alert['extraData'], 'alertPriority'):
        alert_severity = SEVERITY_LEVELS_MAP[str(alert['extraData']['alertPriority']).lower()]

    if demisto.get(alert['extraData'], 'alertName'):
        alert_name = alert['extraData']['alertName']

    if demisto.get(alert['extraData'], 'alertDescription'):
        alert_description = alert['extraData']['alertDescription']

    new_alert: Dict = {
        'devo.metadata.alert': {}
    }
    for key in alert:
        if key == 'extraData':
            continue
        new_alert['devo.metadata.alert'][key] = alert[key]
        alert_labels.append({'type': f'devo.metadata.alert.{key}', 'value': str(alert[key])})

    for key in alert['extraData']:
        new_alert[key] = alert['extraData'][key]
        alert_labels.append({'type': f'{key}', 'value': str(alert['extraData'][key])})

    incident = {
        'name': alert_name,
        'severity': alert_severity,
        'details': alert_description,
        'occurred': alert_occurred,
        'labels': alert_labels,
        'rawJSON': json.dumps(new_alert)
    }

    return incident


def build_link(query, start_ts_milli, end_ts_milli, mode='queryApp'):
    myb64str = base64.b64encode((json.dumps({
        'query': query,
        'mode': mode,
        'dates': {
            'from': start_ts_milli,
            'to': end_ts_milli
        }
    }).encode('ascii'))).decode()
    url = LINQ_LINK_BASE + f"#/verticalApp?path=apps/custom/queryApp_dev&targetQuery={myb64str}"
    return url


def check_credentials():
    list(ds.Reader(oauth_token=READER_OAUTH_TOKEN, end_point=READER_ENDPOINT)
         .query(HEALTHCHECK_QUERY, start=int(time.time() - 1), stop=int(time.time()), output='dict'))

    if WRITER_RELAY and WRITER_CREDENTIALS:
        creds = get_writer_creds()
        ds.Writer(key=creds['key'].name, crt=creds['crt'].name, chain=creds['chain'].name, relay=WRITER_RELAY)\
            .load(HEALTHCHECK_WRITER_RECORD, HEALTHCHECK_WRITER_TABLE, historical=False)

    return True


def check_type(input, tar_type):
    if isinstance(input, str):
        input = json.loads(input)
        if not isinstance(input, tar_type):
            raise ValueError(f'tables to query should either be a json string of a {tar_type} or a {tar_type} input')
    elif isinstance(input, tar_type):
        pass
    else:
        raise ValueError(f'tables to query should either be a json string of a {tar_type} or a {tar_type} input')
    return input


# Converts epoch (miliseconds) to ISO string
def demisto_ISO(s_epoch):
    if s_epoch >= 0:
        return datetime.utcfromtimestamp(s_epoch).strftime("%Y-%m-%dT%H:%M:%S.%fZ")
    return s_epoch


def get_writer_creds():
    if WRITER_RELAY is None:
        raise ValueError('writer_relay is not set in your Devo Integration')

    if WRITER_CREDENTIALS is None:
        raise ValueError('writer_credentials are not set in your Devo Integration')

    write_credentials = check_type(WRITER_CREDENTIALS, dict)

    # Limitation in Devo DS Connector SDK. Currently require filepaths for credentials.
    # Will accept file-handler type objects in the future.
    key_tmp = tempfile.NamedTemporaryFile(mode='w')
    crt_tmp = tempfile.NamedTemporaryFile(mode='w')
    chain_tmp = tempfile.NamedTemporaryFile(mode='w')

    key_tmp.write(write_credentials['key'])
    crt_tmp.write(write_credentials['crt'])
    chain_tmp.write(write_credentials['chain'])

    key_tmp.flush()
    crt_tmp.flush()
    chain_tmp.flush()

    creds = {
        'key': key_tmp,
        'crt': crt_tmp,
        'chain': chain_tmp
    }

    return creds


def parallel_query_helper(sub_query, append_list, timestamp_from, timestamp_to):
    append_list.extend(list(ds.Reader(oauth_token=READER_OAUTH_TOKEN, end_point=READER_ENDPOINT)
                       .query(sub_query, start=float(timestamp_from), stop=float(timestamp_to),
                       output='dict', ts_format='iso')))


''' FUNCTIONS '''


def fetch_incidents():
    last_run = demisto.getLastRun()
    alert_query = ALERTS_QUERY
    to_time = time.time()
    dedupe_config = None
    alerts_list: Dict = {}
    new_last_run: Dict = {
        'from_time': to_time
    }

    if FETCH_INCIDENTS_FILTER:
        alert_filters = check_type(FETCH_INCIDENTS_FILTER, dict)

        if alert_filters['type'] == 'AND':
            filter_string = ' , '.join([f'{filt["key"]} {filt["operator"]} "{urllib.parse.quote(filt["value"])}"'
                                       for filt in alert_filters['filters']])
        elif alert_filters['type'] == 'OR':
            filter_string = ' or '.join([f'{filt["key"]} {filt["operator"]} "{urllib.parse.quote(filt["value"])}"'
                                        for filt in alert_filters['filters']])

        alert_query = f'{alert_query} where {filter_string}'

    from_time = to_time - 3600
    if 'from_time' in last_run:
        from_time = float(last_run['from_time'])

    if FETCH_INCIDENTS_DEDUPE:
        dedupe_config = check_type(FETCH_INCIDENTS_DEDUPE, dict)
        if 'alerts_list' in last_run:
            alerts_list = last_run['alerts_list']
        alerts_list = {k: v for k, v in alerts_list.items() if alerts_list[k] >= (to_time - float(dedupe_config['cooldown']))}

    # execute the query and get the events
    # reverse the list so that the most recent event timestamp event is taken when de-duping if needed.
    events = list(ds.Reader(oauth_token=READER_OAUTH_TOKEN, end_point=READER_ENDPOINT)
                    .query(alert_query, start=float(from_time), stop=float(to_time),
                           output='dict', ts_format='timestamp'))[::-1]

    deduped_events: List[Dict] = []
    if FETCH_INCIDENTS_DEDUPE:
        # Expire out of rolling time window events
        for event in events:
            if any(de['context'] == event['context'] for de in deduped_events):
                continue
            if event['context'] in alerts_list:
                continue
            deduped_events.append(event)
            alerts_list[event['context']] = event['eventdate']

        events = deduped_events
        new_last_run['alerts_list'] = alerts_list

    # convert the events to demisto incident
    incidents = []

    for event in events:
        event['extraData'] = json.loads(event['extraData'])
        for ed in event['extraData']:
            event['extraData'][ed] = urllib.parse.unquote_plus(event['extraData'][ed])
        inc = alert_to_incident(event)
        incidents.append(inc)

    demisto.setLastRun(new_last_run)

    # this command will create incidents in Demisto
    demisto.incidents(incidents)

    return incidents


def run_query_command():
    to_query = demisto.args()['query']
    timestamp_from = demisto.args()['from']
    timestamp_to = demisto.args().get('to', time.time())
    write_context = demisto.args()['writeToContext'].lower()

    results = list(ds.Reader(oauth_token=READER_OAUTH_TOKEN, end_point=READER_ENDPOINT)
                   .query(to_query, start=float(timestamp_from), stop=float(timestamp_to),
                   output='dict', ts_format='iso'))

    querylink = {'DevoTableLink': build_link(to_query, int(1000 * float(timestamp_from)), int(1000 * float(timestamp_to)))}

    entry = {
        'Type': entryTypes['note'],
        'Contents': results,
        'ContentsFormat': formats['json'],
        'ReadableContentsFormat': formats['markdown']
    }
    entry_linq = {
        'Type': entryTypes['note'],
        'Contents': querylink,
        'ContentsFormat': formats['json'],
        'ReadableContentsFormat': formats['markdown']
    }

    if len(results) == 0:
        entry['HumanReadable'] = 'No results found'
        entry['Devo.QueryResults'] = None
        entry['Devo.QueryLink'] = querylink
        return entry
    headers = list(results[0].keys())

    md = tableToMarkdown('Devo query results', results, headers)
    entry['HumanReadable'] = md

    md_linq = tableToMarkdown('Link to Devo Query', {'DevoTableLink': f'[Devo Direct Link]({querylink["DevoTableLink"]})'})
    entry_linq['HumanReadable'] = md_linq

    if write_context == 'true':
        entry['EntryContext'] = {
            'Devo.QueryResults': createContext(results)
        }
        entry_linq['EntryContext'] = {
            'Devo.QueryLink': createContext(querylink)
        }
    return [entry, entry_linq]


def get_alerts_command():
    timestamp_from = demisto.args()['from']
    timestamp_to = demisto.args().get('to', time.time())
    alert_filters = demisto.args().get('filters', None)
    write_context = demisto.args()['writeToContext'].lower()
    alert_query = ALERTS_QUERY

    if alert_filters:
        alert_filters = check_type(alert_filters, dict)
        if alert_filters['type'] == 'AND':
            filter_string = ', '\
                .join([f'{filt["key"]} {filt["operator"]} "{urllib.parse.quote(filt["value"])}"'
                      for filt in alert_filters['filters']])
        elif alert_filters['type'] == 'OR':
            filter_string = ' or '\
                .join([f'{filt["key"]} {filt["operator"]} "{urllib.parse.quote(filt["value"])}"'
                      for filt in alert_filters['filters']])
        alert_query = f'{alert_query} where {filter_string}'

    results = list(ds.Reader(oauth_token=READER_OAUTH_TOKEN, end_point=READER_ENDPOINT)
                   .query(alert_query, start=float(timestamp_from), stop=float(timestamp_to),
                   output='dict', ts_format='iso'))

    querylink = {'DevoTableLink': build_link(alert_query, int(1000 * float(timestamp_from)), int(1000 * float(timestamp_to)))}

    for res in results:
        res['extraData'] = json.loads(res['extraData'])
        for ed in res['extraData']:
            res['extraData'][ed] = urllib.parse.unquote_plus(res['extraData'][ed])

    entry = {
        'Type': entryTypes['note'],
        'Contents': results,
        'ContentsFormat': formats['json'],
        'ReadableContentsFormat': formats['markdown']
    }
    entry_linq = {
        'Type': entryTypes['note'],
        'Contents': querylink,
        'ContentsFormat': formats['json'],
        'ReadableContentsFormat': formats['markdown']
    }

    if len(results) == 0:
        entry['HumanReadable'] = 'No results found'
        entry['Devo.AlertsResults'] = None
        entry_linq['Devo.QueryLink'] = querylink
        return entry

    headers = list(results[0].keys())

    md = tableToMarkdown('Devo query results', results, headers)
    entry['HumanReadable'] = md

    md_linq = tableToMarkdown('Link to Devo Query', {'DevoTableLink': f'[Devo Direct Link]({querylink["DevoTableLink"]})'})
    entry_linq['HumanReadable'] = md_linq

    if write_context == 'true':
        entry['EntryContext'] = {
            'Devo.AlertsResults': createContext(results)
        }
        entry_linq['EntryContext'] = {
            'Devo.QueryLink': createContext(querylink)
        }

    return [entry, entry_linq]


def multi_table_query_command():
    tables_to_query = check_type(demisto.args()['tables'], list)
    search_token = demisto.args()['searchToken']
    timestamp_from = demisto.args()['from']
    timestamp_to = demisto.args().get('to', time.time())
    write_context = demisto.args()['writeToContext'].lower()

    futures = []
    all_results: List[Dict] = []
    sub_queries = []

    for table in tables_to_query:
        fields = ds.Reader(oauth_token=READER_OAUTH_TOKEN, end_point=READER_ENDPOINT)\
            ._get_types(f'from {table} select *', 'now', 'iso').keys()
        clauses = [f"( isnotnull({field}) and str({field})->\"" + search_token + "\")" for field in fields]
        sub_queries.append("from " + table + " where" + " or ".join(clauses) + " select *")

    with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
        for q in sub_queries:
            futures.append(executor.submit(parallel_query_helper, q, all_results, timestamp_from, timestamp_to))

    done, pending = concurrent.futures.wait(futures)

    entry = {
        'Type': entryTypes['note'],
        'Contents': all_results,
        'ContentsFormat': formats['json'],
        'ReadableContentsFormat': formats['markdown']
    }

    if len(all_results) == 0:
        entry['HumanReadable'] = 'No results found'
        return entry

    headers: Set = set().union(*(r.keys() for r in all_results))

    md = tableToMarkdown('Devo query results', all_results, headers)
    entry['HumanReadable'] = md

    if write_context == 'true':
        entry['EntryContext'] = {
            'Devo.MultiResults': createContext(all_results)
        }

    return entry


def write_to_table_command():
    table_name = demisto.args()['tableName']
    records = check_type(demisto.args()['records'], list)

    creds = get_writer_creds()

    linq = ds.Writer(key=creds['key'].name, crt=creds['crt'].name, chain=creds['chain'].name, relay=WRITER_RELAY)\
        .load(records, table_name, historical=False, linq_func=(lambda x: x))

    querylink = {'DevoTableLink': build_link(linq, int(1000 * time.time()) - 3600000, int(1000 * time.time()))}

    entry = {
        'Type': entryTypes['note'],
        'Contents': {'recordsWritten': len(records)},
        'ContentsFormat': formats['json'],
        'ReadableContentsFormat': formats['markdown'],
        'EntryContext': {
            'Devo.RecordsWritten': len(records),
            'Devo.LinqQuery': linq
        }
    }
    entry_linq = {
        'Type': entryTypes['note'],
        'Contents': querylink,
        'ContentsFormat': formats['json'],
        'ReadableContentsFormat': formats['markdown'],
        'EntryContext': {
            'Devo.QueryLink': createContext(querylink)
        }
    }
    md = tableToMarkdown('Entries to load into Devo', records)
    entry['HumanReadable'] = md

    md_linq = tableToMarkdown('Link to Devo Query', {'DevoTableLink': f'[Devo Direct Link]({querylink["DevoTableLink"]})'})
    entry_linq['HumanReadable'] = md_linq

    return [entry, entry_linq]


def write_to_lookup_table_command():
    lookup_table_name = demisto.args()['lookupTableName']
    headers = check_type(demisto.args()['headers'], list)
    records = check_type(demisto.args()['records'], list)

    creds = get_writer_creds()

    engine_config = SenderConfigSSL(address=(WRITER_RELAY, 443),
                                    key=creds['key'].name,
                                    cert=creds['crt'].name,
                                    chain=creds['chain'].name)

    con = Sender(config=engine_config, timeout=60)

    lookup = Lookup(name=lookup_table_name,
                    historic_tag=None,
                    con=con)
    # Order sensitive list
    pHeaders = json.dumps(headers)

    lookup.send_control('START', pHeaders, 'INC')

    for r in records:
        lookup.send_data_line(key=r['key'], fields=r['values'])

    lookup.send_control('END', pHeaders, 'INC')

    con.flush_buffer()
    con.socket.shutdown(0)

    entry = {
        'Type': entryTypes['note'],
        'Contents': {'recordsWritten': len(records)},
        'ContentsFormat': formats['json'],
        'ReadableContentsFormat': formats['markdown'],
        'EntryContext': {
            'Devo.RecordsWritten': len(records)
        }
    }

    md = tableToMarkdown('Entries to load into Devo', records)
    entry['HumanReadable'] = md

    return [entry]


''' EXECUTION CODE '''
try:
    handle_proxy()
    if demisto.command() == 'test-module':
        check_credentials()
        demisto.results('ok')
    elif demisto.command() == 'fetch-incidents':
        fetch_incidents()
    elif demisto.command() == 'devo-run-query':
        demisto.results(run_query_command())
    elif demisto.command() == 'devo-get-alerts':
        demisto.results(get_alerts_command())
    elif demisto.command() == 'devo-multi-table-query':
        demisto.results(multi_table_query_command())
    elif demisto.command() == 'devo-write-to-table':
        demisto.results(write_to_table_command())
    elif demisto.command() == 'devo-write-to-lookup-table':
        demisto.results(write_to_lookup_table_command())

except Exception as e:
    return_error('Failed to execute command {}. Error: {}'.format(demisto.command(), str(e)))
