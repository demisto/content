from datetime import timezone
from typing import Dict, List

from CommonServerPython import *

''' IMPORTS '''

import requests
import json

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


''' GLOBAL_VARIABLES '''
INTEGRATION_NAME = 'Nozomi Networks'
QUERY_PATH = '/api/open/query/do?query='
QUERY_ALERTS_PATH = '/api/open/query/do?query=alerts'
QUERY_ASSETS_PATH = '/api/open/query/do?query=assets | sort id'
JOB_STATUS_MAX_RETRY = 5
DEFAULT_HEAD_ALERTS = 20
DEFAULT_HEAD_ASSETS = 50
DEFAULT_HEAD_QUERY = 500
MAX_ASSETS_FINDABLE_BY_A_COMMAND = 100
DEFAULT_ASSETS_FINDABLE_BY_A_COMMAND = 50


'''HELPER FUNCTIONS'''


def get_client():
    return Client(
        base_url=demisto.params().get('endpoint'),
        verify=not demisto.params().get('insecure', True),
        ok_codes=(200, 201, 202, 204),
        headers={'accept': "application/json"},
        auth=(demisto.params().get("credentials", {}).get('identifier', ''),
              demisto.params().get("credentials", {}).get('password', '')),
        proxy=demisto.params().get('proxy', False))


def parse_incident(i):
    return {
        'name': f"{i['name']}_{i['id']}",
        'occurred': datetime.fromtimestamp(i['time'] / 1000, timezone.utc).isoformat(),
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


def start_time(last_run, fetch_time_from='7 days'):
    fetch_time_default, _ = parse_date_range(fetch_time_from, date_format='%Y-%m-%dT%H:%M:%SZ', to_timestamp=True)
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
        f'{QUERY_ALERTS_PATH} | sort time asc | sort id asc{better_than_time_filter(st)}'
        f'{risk_filter(risk)}{also_n2os_incidents_filter(also_n2os_incidents)} | head {head}'
    )['result']


def incidents_equal_than_time(st, risk, also_n2os_incidents, client):
    return client.http_get_request(
        f'{QUERY_ALERTS_PATH} | sort time asc | sort id asc{equal_than_time_filter(st)}'
        f'{risk_filter(risk)}{also_n2os_incidents_filter(also_n2os_incidents)}'
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


def ack_unack_alerts(ids, status, client):
    data = []
    for id in ids:
        data.append({'id': id, 'ack': status})
    response = client.http_post_request('/api/open/alerts/ack', {'data': data})
    return response["result"]["id"]


def ack_alerts(ids, client):
    return ack_unack_alerts(ids, True, client)


def nozomi_alerts_ids_from_demisto_incidents(demisto_incidents):
    return ids_from_incidents([json.loads(incident['rawJSON']) for incident in demisto_incidents])


def close_alerts(args, close_action, client):
    readable_close_action = "closed_as_security" if close_action == "delete_rules" else "closed_as_change"
    extracted_ids = argToList(args.get('ids'))
    human_readable = f'Command changes the status of the following alerts: {extracted_ids} ' \
        f'passed as "{readable_close_action}" in Nozomi Networks platform.'

    client.http_post_request(
        '/api/open/alerts/close',
        {"ids": extracted_ids, "close_action": close_action})

    return {
        'readable_output': human_readable,
        'outputs_prefix': None,
        'outputs_key_field': None,
        'outputs': None
    }


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
        client,
        st=None,
        last_run=None,
        last_id=None,
        risk=None,
        fetch_also_n2os_incidents=None,
        test_mode=False
):
    st = st or start_time(demisto.getLastRun(), demisto.params().get('fetchTime', '7 days').strip())
    last_run = last_run or demisto.getLastRun()
    last_id = last_id or get_last_id(demisto.getLastRun())
    risk = risk or demisto.params().get('riskFrom', None)
    fetch_also_n2os_incidents = fetch_also_n2os_incidents or demisto.params().get('fecthAlsoIncidents', False)

    demisto_incidents, last_fetch, last_id_returned = \
        incidents(st, last_id, last_run, risk, fetch_also_n2os_incidents, client)

    if not test_mode:
        demisto.setLastRun({'last_fetch': last_fetch, 'last_id': last_id_returned})
        ack_alerts(nozomi_alerts_ids_from_demisto_incidents(demisto_incidents), client)
        demisto.incidents(demisto_incidents)

    return demisto_incidents, last_fetch


def is_alive(client):
    error = None
    try:
        client.http_get_request(f'{QUERY_ALERTS_PATH} | count')
    except Exception as e:
        error = e.args[0]

    return humanize_api_error(error) if error else 'ok'


def close_incidents_as_change(args, client):
    return close_alerts(args, 'learn_rules', client)


def close_incidents_as_security(args, client):
    return close_alerts(args, 'delete_rules', client)


def query(args, client):
    title = f'{INTEGRATION_NAME} - Results for Query'
    response = client.http_get_request(
        f'{QUERY_PATH}{args.get("query", "")} | head {DEFAULT_HEAD_QUERY}')

    if 'error' in response and response['error']:
        return {
            'outputs_key_field': None,
            'outputs': None,
            'outputs_prefix': None,
            'readable_output': response['error']
        }

    result = response['result']
    human_readable = tableToMarkdown(t=result, name=title, removeNull=True)

    return {
        'outputs': result,
        'outputs_prefix': 'Nozomi.Query.Result',
        'outputs_key_field': '',
        'readable_output': human_readable
    }


def find_assets(args, client, head=DEFAULT_HEAD_ASSETS):
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


def find_ip_by_mac(args, client):
    mac = args.get("mac", "")
    only_nodes_confirmed = args.get("only_nodes_confirmed", True)
    result_error = False
    result = {}  # type: Dict

    response = client.http_get_request(
        f'{QUERY_PATH}nodes | select ip mac_address | where mac_address == {mac}{nodes_confirmed_filter(only_nodes_confirmed)}')

    if len(response["result"]) == 0:
        human_readable = f'{INTEGRATION_NAME} - No IP results were found for mac address: {mac}'
        result_error = True
        prefix = None
    else:
        ips = [node['ip'] for node in response["result"]]
        human_readable = f'{INTEGRATION_NAME} - Results for the Ip from Mac Search is {ips}'
        result = {
            'ips': ips,
            'mac': mac
        }
        prefix = 'Nozomi.IpByMac'

    return {
        'outputs': None if result_error else result,
        'outputs_prefix': prefix,
        'outputs_key_field': None,
        'readable_output': human_readable
    }


''' EXECUTION '''


def main():
    try:
        client = get_client()
        if demisto.command() == 'fetch-incidents':
            fetch_incidents(client)
        elif demisto.command() == 'test-module':
            if demisto.params().get('isFetch'):
                fetch_incidents(client, test_mode=True)
                demisto.results('ok')
            else:
                demisto.results(is_alive(client))
        elif demisto.command() == 'nozomi-close-incidents-as-change':
            return_results(CommandResults(**close_incidents_as_change(demisto.args(), client)))
        elif demisto.command() == 'nozomi-close-incidents-as-security':
            return_results(CommandResults(**close_incidents_as_security(demisto.args(), client)))
        elif demisto.command() == 'nozomi-find-assets':
            return_results(CommandResults(**find_assets(demisto.args(), client)))
        elif demisto.command() == 'nozomi-query':
            return_results(CommandResults(**query(demisto.args(), client)))
        elif demisto.command() == 'nozomi-find-ip-by-mac':
            return_results(CommandResults(**find_ip_by_mac(demisto.args(), client)))
    except Exception as e:
        demisto.error(f'nozomi: got an error {e}')
        return_error(str(e))


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
