from CommonServerPython import *

''' IMPORTS '''

import requests
import json
import time
import ast

requests.packages.urllib3.disable_warnings()


class Client(BaseClient):
    def http_request(self, method, path, data=None):
        response = self._http_request(
            method,
            url_suffix=path,
            resp_type="json",
            json_data=data
        )
        return response

    def http_get_request(self, path):
        return self.http_request('GET', path)

    def http_post_request(self, path, data):
        return self.http_request('POST', path, data)


''' CONSTANTS '''
DATE_FORMAT = '%Y-%m-%dT%H:%M:%SZ'

''' GLOBAL_VARIABLES '''
FETCH_TIME_FROM = demisto.params().get('fetchTime', '7 days').strip()
RISK_FROM = demisto.params().get('riskFrom', None)
FETCH_ALSO_N2OS_INCIDENTS = demisto.params().get('fecthAlsoIncidents', False)
INTEGRATION_NAME = 'Nozomi Networks'
QUERY_PATH = '/api/open/query/do?query='
QUERY_ALERTS_PATH = '/api/open/query/do?query=alerts'
QUERY_ASSETS_PATH = '/api/open/query/do?query=assets | sort id'
JOB_STATUS_MAX_RETRY = 5
DEFAULT_HEAD_ALERTS = 20
DEFAULT_HEAD_ASSETS = 50
DEFAULT_HEAD_QUERY = 500
MAX_ITEMS_FINDABLE_BY_A_COMMAND = 1000
MAX_ASSETS_FINDABLE_BY_A_COMMAND = 1000
DEFAULT_ASSETS_FINDABLE_BY_A_COMMAND = 500

CLIENT = Client(
    base_url=demisto.params().get('endpoint'),
    verify=not demisto.params().get('insecure', True),
    ok_codes=(200, 201, 202, 204),
    headers={'accept': "application/json"},
    auth=(demisto.params().get('username'), demisto.params().get('password')),
    proxy=demisto.params().get('proxy', False))


'''HELPER FUNCTIONS'''


def parse_incident(i):
    return {
        'name': i['name'],
        'occurred': datetime.fromtimestamp(i['time']/1000).strftime(DATE_FORMAT),
        'severity': parse_severity(i),
        'rawJSON': json.dumps(clean_null_terms(i))
    }


def clean_null_terms(d):
    clean = {}
    for key, value in d.items():
        if isinstance(value, dict):
            nested = clean_null_terms(value)
            if len(nested.keys()) > 0:
                clean[key] = nested
        elif value is not None:
            clean[key] = value
    return clean


def parse_severity(item):
    result = int(float(item['risk']) / 2)
    if result < 1:
        return 1
    return result - 1 if result > 4 else result


def ids_from_incidents(incidents_array):
    return [incident['id'] for incident in incidents_array]


def better_than_time_filter(st):
    t = ''
    if st:
        t = f' | where time > {st}'
    return t


def equal_than_time_filter(st):
    t = ''
    if st:
        t = f' | where time == {st}'
    return t


def better_than_id_filter(id):
    res = ''
    if id:
        res = f' | where id > {id}'
    return res


def start_time(last_run):
    fetch_time_default, _ = parse_date_range(FETCH_TIME_FROM, date_format=DATE_FORMAT, to_timestamp=True)
    if has_last_run(last_run):
        time_from_last_run = f'{last_run.get("last_fetch", fetch_time_default)}'
        result = f'{fetch_time_default}' if time_from_last_run == '0' else f'{time_from_last_run}'
    else:
        result = f'{fetch_time_default}'
    return result


def has_last_run(lr):
    return lr is not None and 'last_fetch' in lr


def incidents_better_than_time(st, head, risk, also_n2os_incidents, client):
    return client.http_get_request(
        f'{QUERY_ALERTS_PATH} | sort time asc | sort id asc{better_than_time_filter(st)}{risk_filter(risk)}{also_n2os_incidents_filter(also_n2os_incidents)} | head {head}'
    )['result']


def incidents_equal_than_time(st, risk, also_n2os_incidents, client):
    return client.http_get_request(
        f'{QUERY_ALERTS_PATH} | sort time asc | sort id asc{equal_than_time_filter(st)}{risk_filter(risk)}{also_n2os_incidents_filter(also_n2os_incidents)}'
    )['result']


def also_n2os_incidents_filter(also_n2os_incidents):
    if also_n2os_incidents:
        return ''
    else:
        return ' | where is_incident == false'


def risk_filter(risk):
    return f' | where risk >= {int(risk)}' if risk else ''


def incidents_better_than_id(incidents_to_filter, the_id):
    return [incident for incident in incidents_to_filter if incident['id'] > the_id]


def incidents_equal_time_better_id(st, last_id, risk, also_n2os_incidents, client):
    if last_id:
        return incidents_better_than_id(
            incidents_equal_than_time(st, risk, also_n2os_incidents, client),
            last_id)
    else:
        return []


def incidents(st, last_id, last_run, risk, also_n2os_incidents, client, head=DEFAULT_HEAD_ALERTS):
    def get_incident_name(i):
        return i['name']

    ibtt = incidents_better_than_time(st, head, risk, also_n2os_incidents, client)

    lft = last_fetched_time(ibtt, last_run)
    lfid = last_fetched_id(ibtt, last_run)

    incidents_merged = incidents_equal_time_better_id(st, last_id, risk, also_n2os_incidents, client) + ibtt

    parsed_incidents = [parse_incident(i) for i in incidents_merged]
    parsed_incidents.sort(key=get_incident_name)

    return \
        parsed_incidents, \
        lft, \
        lfid


def last_fetched_time(inc, last_run):
    return inc[-1]['time'] if len(inc) > 0 else last_run.get("last_fetch", 0)


def last_fetched_id(inc, last_run):
    return inc[-1]['id'] if len(inc) > 0 else last_run.get("last_id", None)


def last_asset_id(response):
    return response[-1]['id'] if len(response) > 0 else ''


def wait_for_job_result(job_id, operation, client):
    job_status = None
    count = 0

    try:
        while job_status != 'SUCCESS' and JOB_STATUS_MAX_RETRY >= count:
            time.sleep(2)
            count = count + 1
            job_status = client.http_get_request(
                f'/api/open/alerts/{operation}/status/{job_id}'
            )['result']['status']
    except Exception as e:
        LOG(f'nozomi: wait_for_job_result got an error, not able to retrieve job status with id {job_id}, error {e}')
        return False

    return job_status == 'SUCCESS'


def ack_unack_alerts(ids, status, client):
    data = []
    for id in ids:
        data.append({'id': id, 'ack': status})
    response = client.http_post_request('/api/open/alerts/ack', {'data': data})
    return wait_for_job_result(response["result"]["id"], 'ack', client)


def ack_alerts(ids, client):
    return ack_unack_alerts(ids, True, client)


def unack_alerts(ids, client):
    return ack_unack_alerts(ids, False, client)


def is_acked(id, client=CLIENT):
    return alert_by_id(id, client)['result'][0]['status'] == 'ack'


def alert_by_id(id, client):
    return client.http_get_request(
        f'{QUERY_ALERTS_PATH} | select id status | where id == {id}'
    )


def nozomi_alerts_ids_from_demisto_incidents(demisto_incidents):
    return ids_from_incidents([json.loads(incident['rawJSON']) for incident in demisto_incidents])


def ids_from_args(args):
    return [i.strip() for i in ast.literal_eval(args.get('ids', []))]


def close_alerts(args, close_action, client=CLIENT):
    readable_close_action = "closed_as_security" if close_action == "delete_rules" else "closed_as_change"
    human_readable = f'Command changes the status of alerts passed as "{readable_close_action}" in Nozomi Networks platform.'
    extracted_ids = ids_from_args(args)

    response = client.http_post_request(
        '/api/open/alerts/close',
        {"ids": extracted_ids, "close_action": close_action})

    result = 'SUCCESS' if wait_for_job_result(response['result']['id'], 'close', client) else 'FAIL'

    return {
        'outputs': result,
        'outputs_prefix': 'Nozomi.Ids',
        'outputs_key_field': '',
        'readable_output': human_readable
    }


def context_entry(value):
    return {
        "Nozomi": value
    }


def is_closed_as_security(id, client):
    return is_alert_status_as(id, 'closed_as_security', client)


def is_closed_as_a_change(id, client):
    return is_alert_status_as(id, 'closed_as_change', client)


def is_alert_status_as(id, expected_status, client):
    return alert_by_id(id, client)['result'][0]['status'] == expected_status


def has_last_id(lr):
    return lr is not None and 'last_id' in lr


def get_last_id(last_run):
    result = None
    if has_last_id(last_run):
        result = f'{last_run.get("last_id", 0)}'
    return result


def filter_from_args(args):
    if args and args.get('filter', '') != '':
        filter = args.get('filter', '')
        if '| where' in filter:
            return filter
        else:
            return f" | where {filter}"
    else:
        return ''


def assets_limit_from_args(args):
    if args:
        limit = int(args.get('limit', DEFAULT_ASSETS_FINDABLE_BY_A_COMMAND))
        if limit > MAX_ASSETS_FINDABLE_BY_A_COMMAND:
            return MAX_ASSETS_FINDABLE_BY_A_COMMAND
        else:
            return limit
    else:
        return DEFAULT_ASSETS_FINDABLE_BY_A_COMMAND


def nodes_confirmed_filter(only_nodes_confirmed):
    if only_nodes_confirmed and only_nodes_confirmed == 'True':
        return ' | where mac_address:info.likelihood_level == confirmed'
    else:
        return ''


def humanize_api_error(error):
    if '401' in error:
        return 'Authentication error, check your username and password'
    else:
        return error


''' MAIN_FUNCTION '''


def fetch_incidents(
        st=start_time(demisto.getLastRun()),
        client=CLIENT,
        last_run=demisto.getLastRun(),
        last_id=get_last_id(demisto.getLastRun()),
        risk=RISK_FROM,
        fetch_also_n2os_incidents=FETCH_ALSO_N2OS_INCIDENTS
):
    demisto_incidents, last_fetch, last_id_returned = incidents(st, last_id, last_run, risk, fetch_also_n2os_incidents, client)

    ack_alerts(nozomi_alerts_ids_from_demisto_incidents(demisto_incidents), client)

    demisto.setLastRun({'last_fetch': last_fetch, 'last_id': last_id_returned})
    demisto.incidents(demisto_incidents)
    return demisto_incidents, last_fetch


def is_alive(client=CLIENT):
    error = None
    try:
        client.http_get_request(f'{QUERY_ALERTS_PATH} | count')
    except Exception as e:
        error = e.args[0]

    return humanize_api_error(error) if error else 'ok'


def close_incidents_as_change(args, client=CLIENT):
    return close_alerts(args, 'learn_rules', client)


def close_incidents_as_security(args, client=CLIENT):
    return close_alerts(args, 'delete_rules', client)


def query(args, client=CLIENT):
    title = f'{INTEGRATION_NAME} - Results for Query'
    response = client.http_get_request(
        f'{QUERY_PATH}{args.get("query", "")} | head {DEFAULT_HEAD_QUERY}')

    if 'error' in response and response['error']:
        return {
            'outputs': response['error'],
            'outputs_prefix': 'Nozomi.Error',
            'outputs_key_field': '',
            'readable_output': response['error']
    }

    result = response['result']
    human_readable = tableToMarkdown(t=result, name=title, removeNull=True)

    return {
        'outputs': result,
        'outputs_prefix': 'Nozomi.Result',
        'outputs_key_field': '',
        'readable_output': human_readable
    }


def find_assets(args, head=DEFAULT_HEAD_ASSETS, client=CLIENT):
    title = f'{INTEGRATION_NAME} - Results for Find Assets'
    limit = assets_limit_from_args(args)
    result = []  # type: List[dict]
    last_id = None
    are_there_assets_to_request = True

    if head > limit:
        head = limit

    while limit > len(result) and are_there_assets_to_request:
        raw_response = client.http_get_request(
            f'{QUERY_ASSETS_PATH}{filter_from_args(args)}{better_than_id_filter(last_id)} | head {head}')
        last_id = last_asset_id(raw_response['result'])
        are_there_assets_to_request = head == len(raw_response['result'])
        result = result + raw_response['result']

    if not result:
        return {
            'outputs': [],
            'outputs_prefix': 'Nozomi.Asset',
            'outputs_key_field': 'id',
            'readable_output': f'{INTEGRATION_NAME} - No assets found'
        }

    human_readable = tableToMarkdown(
        t=result,
        name=title,
        removeNull=True,
        headers=['id', 'name', 'ip', 'mac_address', 'level firmware_version', 'os vendor', 'type']
    )
    return {
        'outputs': result,
        'outputs_prefix': 'Nozomi.Asset',
        'outputs_key_field': 'id',
        'readable_output': human_readable
    }


def find_ip_by_mac(args, client=CLIENT):
    mac = args.get("mac", "")
    only_nodes_confirmed = args.get("only_nodes_confirmed", True)
    result_error = None
    result = []  # type: List[str]

    response = client.http_get_request(
        f'{QUERY_PATH}nodes | select ip mac_address | where mac_address == {mac}{nodes_confirmed_filter(only_nodes_confirmed)}')

    if len(response["result"]) == 0:
        human_readable = f'{INTEGRATION_NAME} - Results for the Ip from Mac Search not found ip for mac address: {mac}'
        result_error = "Ip not found"
        prefix = 'Nozomi.Error'
    else:
        ips = [node['ip'] for node in response["result"]]
        human_readable = f'{INTEGRATION_NAME} - Results for the Ip from Mac Search is {ips}'
        result = ips
        prefix = 'Nozomi.Ips'

    return {
        'outputs': result_error if result_error else result,
        'outputs_prefix': prefix,
        'outputs_key_field': '',
        'readable_output': human_readable
    }


''' EXECUTION '''

LOG('nozomi: invoked command %s' % (demisto.command(),))


try:
    if demisto.command() == 'fetch-incidents':
        fetch_incidents()
    elif demisto.command() == 'test-module':
        demisto.results(is_alive())
    elif demisto.command() == 'nozomi-close-incidents-as-change':
        return_results(CommandResults(**close_incidents_as_change(demisto.args())))
    elif demisto.command() == 'nozomi-close-incidents-as-security':
        return_results(CommandResults(**close_incidents_as_security(demisto.args())))
    elif demisto.command() == 'nozomi-find-assets':
        return_results(CommandResults(**find_assets(demisto.args())))
    elif demisto.command() == 'nozomi-query':
        return_results(CommandResults(**query(demisto.args())))
    elif demisto.command() == 'nozomi-find-ip-by-mac':
        return_results(CommandResults(**find_ip_by_mac(demisto.args())))
except Exception as e:
    LOG(f'nozomi: got an error {e}')
    LOG.print_log()
    return_error(e)
