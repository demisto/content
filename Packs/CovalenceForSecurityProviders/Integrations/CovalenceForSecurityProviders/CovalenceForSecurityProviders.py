import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
import os
import requests
import json
import traceback
import dateparser
from datetime import datetime, timedelta
from bs4 import BeautifulSoup

DATE_FORMAT = '%Y-%m-%dT%H:%M:%S'
HOST = demisto.params().get('host')
BROKER = argToBoolean(demisto.params().get('broker', False))
USERNAME = demisto.params().get('credentials')['identifier']
PASSWORD = demisto.params().get('credentials')['password']
VERIFY_SSL = demisto.params().get('verify_ssl')
TIMEOUT = int(demisto.params().get('timeout'))
FIRST_RUN_TIME_RANGE = int(demisto.params().get('first_run_time_range').strip())
FETCH_LIMIT = int(demisto.params().get('fetch_limit'))
PROXY = demisto.params().get('proxy')
if not demisto.params().get('proxy', False):
    del os.environ['HTTP_PROXY']
    del os.environ['HTTPS_PROXY']
    del os.environ['http_proxy']
    del os.environ['https_proxy']


def find_covs(client_name):

    url = f'https://{HOST}/index'
    r = requests.get(url, verify=VERIFY_SSL)
    covs = []

    soup = BeautifulSoup(r.text, 'html.parser')
    for link in soup.find_all('a'):
        if client_name == link.contents[0]:
            href = link.get('href', '')
            if href:
                covs.append(href.split('/index/', 1)[-1])

    return covs


def build_host(host):
    host = host.rstrip('/')
    if not host.startswith('https:') and not host.startswith('http:'):
        host = 'https://' + host
    if host.startswith('https:') and not host.endswith('/CovalenceWebUI/services'):
        host += '/CovalenceWebUI/services'
    elif not host.endswith('/services'):
        host += '/services'

    return host


def login(host=HOST, cov_id=None, username=USERNAME, password=PASSWORD, verify_ssl=VERIFY_SSL):

    if not username:
        raise Exception('Username must be supplied')

    if not password:
        raise Exception('Password must be supplied')

    if not host:
        raise Exception('Host must be supplied')

    host = build_host(host)

    if not verify_ssl:
        #  Disable the warnings if we're not verifying ssl
        import urllib3
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    s = requests.Session()
    if BROKER and cov_id:
        url = f'https://{HOST}/index/{cov_id}'
        s.get(url, verify=verify_ssl)
    p = {'username': username, 'password': password}
    r = s.post(host + '/rest/login', data=p, verify=verify_ssl)

    if r.status_code != 200:
        raise Exception("Failed to login to %s - %d" % (host, r.status_code))

    if not s.cookies:
        raise Exception("Failed to retrieve cookie")

    return s


def send_request(method, api_endpoint, target_org=None, host=HOST, headers=None, params=None, data=None, json=None):
    cov_ids = []
    BROKER = argToBoolean(demisto.params().get('broker', False))
    if BROKER:
        if target_org:
            cov_ids = find_covs(target_org)
            if not cov_ids:
                raise ValueError(f'Unknown organization {target_org}')
        else:
            raise ValueError('Target organization is required in broker mode')
    else:
        cov_ids.append(None)

    result = []
    for cov_id in cov_ids:
        s = login(cov_id=cov_id)

        host = build_host(host)
        url = f'{host}{api_endpoint}'

        req = requests.Request(method, url, headers=headers, params=params, data=data, json=json)
        prepped = s.prepare_request(req)

        try:
            resp = s.send(prepped,
                          stream=None,
                          verify=VERIFY_SSL,
                          proxies=PROXY,
                          cert=None,
                          timeout=TIMEOUT
                          )
            resp.raise_for_status()
        except Exception:
            return_error('Error in API call [%d] - %s' % (resp.status_code, resp.reason))
        else:
            # when having several covs
            # merging each response from each covs into one
            if isinstance(resp.json(), dict):
                result.append(resp.json())
            elif isinstance(resp.json(), list):
                result = result + resp.json()
            else:
                result.append(resp.json())
    return result


def fetch_incidents(last_run, first_run_time_range):
    target_orgs = []
    if BROKER:
        orgs = list_org()
        for org in orgs:
            target_orgs.append(org['org_name'])
    else:
        target_orgs.append(None)

    next_run = {}
    incidents = []
    for target_org in target_orgs:
        if target_org:
            last_fetch = last_run.get(f'{target_org}_last_fetch', None)
            last_alert_id = last_run.get(f'{target_org}_last_alert_id', None)
        else:
            last_fetch = last_run.get('last_fetch', None)
            last_alert_id = last_run.get('last_alert_id', None)
        alert_time_max = datetime.utcnow()

        if last_fetch is None:
            alert_time_min = alert_time_max - timedelta(days=first_run_time_range)
        else:
            alert_time_min = dateparser.parse(last_fetch)  # type: ignore
        assert alert_time_min is not None

        cov_alerts = list_alerts(target_org=target_org,
                                 max_count=FETCH_LIMIT,
                                 alert_time_min=alert_time_min.strftime(DATE_FORMAT),
                                 alert_time_max=alert_time_max.strftime(DATE_FORMAT),
                                 details='true')

        latest_created_time = alert_time_min
        for a in cov_alerts:
            if a['id'] != last_alert_id:
                created_time = datetime.utcfromtimestamp(a.get('createdTime', 0))
                created_time_str = created_time.strftime(DATE_FORMAT)

                if BROKER:
                    incident_name = f'''[{target_org}] [{a.get('type', 'No alert type')}] {a.get('analystTitle', 'No title')}'''
                else:
                    incident_name = f'''[{a.get('type', 'No alert type')}] {a.get('analystTitle', 'No title')}'''
                incident: Dict[str, Any] = {
                    'name': incident_name,
                    'occured': created_time_str,
                    'rawJSON': json.dumps(a)
                }
                if a.get('severity', None):
                    #  XSOAR mapping
                    #  Unknown: 0
                    #  Informational: 0.5
                    #  Low: 1
                    #  Medium: 2
                    #  High: 3
                    #  Critical: 4
                    severity_from_portal = a['severity']
                    if severity_from_portal == 'Informational':
                        incident['severity'] = 0.5
                    elif severity_from_portal == 'Warning':
                        incident['severity'] = 1
                    elif severity_from_portal == 'Low':
                        incident['severity'] = 1
                    elif severity_from_portal == 'Medium':
                        incident['severity'] = 2
                    elif severity_from_portal == 'High':
                        incident['severity'] = 3
                    elif severity_from_portal == 'Critical':
                        incident['severity'] = 4
                else:
                    incident['severity'] = 0
                if a.get('analystDescription', None):
                    incident['details'] = a['analystDescription']
                incidents.append(incident)

                if created_time > latest_created_time:
                    latest_created_time = created_time
                    last_alert_id = a['id']

        if BROKER:
            next_run[f'{target_org}_last_fetch'] = latest_created_time.strftime(DATE_FORMAT)
            next_run[f'{target_org}_last_alert_id'] = last_alert_id
        else:
            next_run['last_fetch'] = latest_created_time.strftime(DATE_FORMAT)
            next_run['last_alert_id'] = last_alert_id

    return next_run, incidents


def list_alerts(target_org=None, max_count=None, initial_index=None, alert_type=None,
                alert_time_min=None, alert_time_max=None, advanced_filter=None, details=None):

    if target_org is None:
        target_org = demisto.args().get('target_org', None)
    if max_count is None:
        max_count = demisto.args().get('max_count', 1000)
    if initial_index is None:
        initial_index = demisto.args().get('initial_index', None)
    if alert_type is None:
        alert_type = demisto.args().get('alert_type', None)
    if alert_time_min is None:
        alert_time_min = demisto.args().get('alert_time_min', None)
    if alert_time_max is None:
        alert_time_max = demisto.args().get('alert_time_max', None)
    if advanced_filter is None:
        advanced_filter = demisto.args().get('advanced_filter', None)

    params = {}
    if max_count:
        params['maxCount'] = max_count
    if initial_index:
        params['initialIndex'] = initial_index
    if alert_type:
        params['alertType'] = alert_type
    if alert_time_min:
        params['alertTimeMin'] = alert_time_min
    if alert_time_max:
        params['alertTimeMax'] = alert_time_max
    if advanced_filter:
        params['advancedFilter'] = advanced_filter

    r = send_request('GET', '/rest/v1/alerts', target_org=target_org, params=params)

    if details is None:
        details = argToBoolean(demisto.args().get('details', 'false'))
    keys = ['acknowledgedStatus',
            'analystDescription',
            'analystTitle',
            'destIp',
            'sourceIp',
            'subType',
            'title',
            'type']

    if not details:
        filtered_r = []
        # returning only data in keys
        for doc in r:
            s = {k: doc[k] for k in keys}
            filtered_r.append(s)
        return filtered_r
    else:
        return r


def get_health():
    if BROKER:
        # must do health check on all cov
        health_check_resp = []
        orgs = list_org()
        for org in orgs:
            health_check_resp.append(
                send_request('GET', '/rest/v1/health', target_org=org['org_name'])
            )
        # "logical and" accross all health checks
        return all(health_check_resp)
    else:
        return send_request('GET', '/rest/v1/health')


def list_sensors():
    target_org = demisto.args().get('target_org', None)

    r = send_request('GET', '/rest/v1/sensors', target_org=target_org)

    details = argToBoolean(demisto.args().get('details', 'false'))
    keys = ['isAuthorized',
            'isNetflowGenerator',
            'name']

    if not details:
        filtered_r = []
        # returning only data in keys
        for doc in r:
            s = {k: doc[k] for k in keys}
            filtered_r.append(s)
        return filtered_r
    else:
        for s in r:
            del s['lastActive']
        return r


def get_sensor():
    target_org = demisto.args().get('target_org', None)
    sensor_id = demisto.args().get('sensor_id')

    r = send_request('GET', f'/rest/v1/sensors/{sensor_id}', target_org=target_org)
    for sensor in r:
        del sensor['lastActive']
    return r


def connections_summary_by_ip():
    target_org = demisto.args().get('target_org', None)
    max_count = demisto.args().get('max_count', 100)
    initial_index = demisto.args().get('initial_index', None)
    source_ip = demisto.args().get('source_ip', None)
    start_time = demisto.args().get('start_time', None)
    end_time = demisto.args().get('end_time', None)
    clients_only = bool(demisto.args().get('clients_only', False))
    internal_only = bool(demisto.args().get('internal_only', False))
    advanced_filter = demisto.args().get('advanced_filter', None)

    params = {}
    if max_count:
        params['maxCount'] = max_count
    if initial_index:
        params['initialIndex'] = initial_index
    if source_ip:
        params['sourceIp'] = source_ip
    if start_time:
        params['startTime'] = start_time
    if end_time:
        params['endTime'] = end_time
    if clients_only:
        params['clientsOnly'] = clients_only
    if internal_only:
        params['internalOnly'] = internal_only
    if advanced_filter:
        params['advancedFilter'] = advanced_filter

    r = send_request('GET', '/rest/v1/connections/ipsummary', target_org=target_org, params=params)

    details = argToBoolean(demisto.args().get('details', 'false'))
    keys = ['averageDuration',
            'bytesIn',
            'bytesOut',
            'clientServerRelationship',
            'destinationIpAddress',
            'dstDomainName',
            'serverPorts',
            'sourceDomainName',
            'sourceIpAddress']

    if not details:
        filtered_r = []
        # returning only data in keys
        for doc in r:
            s = {k: doc[k] for k in keys}
            filtered_r.append(s)
        return filtered_r
    else:
        return r


def connections_summary_by_port():
    target_org = demisto.args().get('target_org', None)
    max_count = demisto.args().get('max_count', 100)
    initial_index = demisto.args().get('initial_index', None)
    source_ip = demisto.args().get('source_ip', None)
    start_time = demisto.args().get('start_time', None)
    end_time = demisto.args().get('end_time', None)
    clients_only = bool(demisto.args().get('clients_only', False))
    internal_only = bool(demisto.args().get('internal_only', False))
    advanced_filter = demisto.args().get('advanced_filter', None)

    params = {}
    if max_count:
        params['maxCount'] = max_count
    if initial_index:
        params['initialIndex'] = initial_index
    if source_ip:
        params['sourceIp'] = source_ip
    if start_time:
        params['startTime'] = start_time
    if end_time:
        params['endTime'] = end_time
    if clients_only:
        params['clientsOnly'] = clients_only
    if internal_only:
        params['internalOnly'] = internal_only
    if advanced_filter:
        params['advancedFilter'] = advanced_filter

    r = send_request('GET', '/rest/v1/connections/portsummary', target_org=target_org, params=params)

    details = argToBoolean(demisto.args().get('details', 'false'))
    keys = ['averageDuration',
            'bytesIn',
            'bytesOut',
            'destinationIpAddress',
            'dstDomainName',
            'serverPort',
            'sourceDomainName',
            'sourceIpAddress']

    if not details:
        filtered_r = []
        # returning only data in keys
        for doc in r:
            s = {k: doc[k] for k in keys}
            filtered_r.append(s)
        return filtered_r
    else:
        return r


def list_dns_resolutions():
    target_org = demisto.args().get('target_org', None)
    max_count = demisto.args().get('max_count', 100)
    initial_index = demisto.args().get('initial_index', None)
    request_time_after = demisto.args().get('request_time_after', None)
    request_time_before = demisto.args().get('request_time_before', None)
    domain_name = demisto.args().get('domain_name', None)
    resolved_ip = demisto.args().get('resolved_ip', None)
    request_origin_ip = demisto.args().get('request_origin_ip', None)
    nameserver_ip = demisto.args().get('nameserver_ip', None)
    advanced_filter = demisto.args().get('advanced_filter', None)

    params = {}
    if max_count:
        params['maxCount'] = max_count
    if initial_index:
        params['initialIndex'] = initial_index
    if request_time_after:
        params['requestTimeAfter'] = request_time_after
    if request_time_before:
        params['requestTimeBefore'] = request_time_before
    if domain_name:
        params['domainName'] = domain_name
    if resolved_ip:
        params['resolvedIp'] = resolved_ip
    if request_origin_ip:
        params['requestOriginIp'] = request_origin_ip
    if nameserver_ip:
        params['nameserverIp'] = nameserver_ip
    if advanced_filter:
        params['advancedFilter'] = advanced_filter

    r = send_request('GET', '/rest/v1/dns/resolutions', target_org=target_org, params=params)

    details = argToBoolean(demisto.args().get('details', 'false'))
    keys = ['domainName',
            'requestOriginIp',
            'requestTime',
            'resolvedIp']

    if not details:
        filtered_r = []
        # returning only data in keys
        for doc in r:
            s = {k: doc[k] for k in keys}
            filtered_r.append(s)
        return filtered_r
    else:
        return r


def list_internal_networks():
    target_org = demisto.args().get('target_org', None)
    return send_request('GET', '/rest/v1/internal_networks', target_org=target_org)


def set_internal_networks():
    if BROKER:
        ValueError(f'{demisto.command()} is not available in broker mode')
    target_org = demisto.args().get('target_org', None)
    cidr = demisto.args().get('cidr', None)
    notes = demisto.args().get('notes', None)

    networks = []
    networks.append(
        {
            'cidr': cidr,
            'notes': notes
        }
    )

    send_request('PUT', '/rest/v1/internal_networks', target_org=target_org, json=networks)

    return cidr, notes


def list_endpoint_agents():
    target_org = demisto.args().get('target_org', None)
    advanced_filter = demisto.args().get('advanced_filter', None)

    params = {}
    if advanced_filter:
        params['advancedFilter'] = advanced_filter

    r = send_request('GET', '/rest/v2/endpoint/agent/agents', target_org=target_org, params=params)

    details = argToBoolean(demisto.args().get('details', 'false'))
    keys = ['hardwareVendor',
            'hostName',
            'ipAddress',
            'isConnected',
            'lastSessionUser',
            'operatingSystem',
            'serialNumber']

    if not details:
        filtered_r = []
        # returning only data in keys
        for doc in r:
            s = {k: doc[k] for k in keys}
            filtered_r.append(s)
        return filtered_r
    else:
        return r


def find_endpoint_by_user():
    target_org = demisto.args().get('target_org', None)
    user = demisto.args().get('user', None)

    params = {}
    params['advancedFilter'] = f'lastSessionUser={user}'
    return send_request('GET', '/rest/v2/endpoint/agent/agents', target_org=target_org, params=params)


def find_endpoint_by_uuid():
    target_org = demisto.args().get('target_org', None)
    uuid = demisto.args().get('uuid', None)

    params = {}
    params['advancedFilter'] = f'agentUuid={uuid}'
    return send_request('GET', '/rest/v2/endpoint/agent/agents', target_org=target_org, params=params)


def search_endpoint_process():
    target_org = demisto.args().get('target_org', None)
    name = demisto.args().get('name', None)
    advanced_filter = demisto.args().get('advanced_filter', None)

    params = {}
    if name:
        params['name'] = name
    if advanced_filter:
        params['advancedFilter'] = advanced_filter

    r = send_request('GET', '/rest/v2/endpoint/process/search', target_org=target_org, params=params)

    details = argToBoolean(demisto.args().get('details', 'false'))
    keys = ['commandLine',
            'firstSeenTime',
            'lastSeenTime',
            'processPath',
            'username']

    if not details:
        filtered_r = []
        # returning only data in keys
        for doc in r:
            s = {k: doc[k] for k in keys}
            filtered_r.append(s)
        return filtered_r
    else:
        return r


def search_endpoint_installed_software():
    target_org = demisto.args().get('target_org', None)
    name = demisto.args().get('name', None)
    version = demisto.args().get('version', None)
    advanced_filter = demisto.args().get('advanced_filter', None)

    params = {}
    if name:
        params['name'] = name
    if version:
        params['version'] = version
    if advanced_filter:
        params['advancedFilter'] = advanced_filter

    r = send_request('GET', '/rest/v2/endpoint/software/search', target_org=target_org, params=params)

    details = argToBoolean(demisto.args().get('details', 'false'))
    keys = ['installTimestamp',
            'name',
            'uninstallTimestamp',
            'vendor',
            'version']

    if not details:
        filtered_r = []
        # returning only data in keys
        for doc in r:
            s = {k: doc[k] for k in keys}
            filtered_r.append(s)
        return filtered_r
    else:
        return r


def list_org():
    if not BROKER:
        ValueError(f'{demisto.command()} is only available in broker mode')

    url = f'https://{HOST}/index'
    r = requests.get(url, verify=VERIFY_SSL)
    org_names: list[dict] = []

    soup = BeautifulSoup(r.text, 'html.parser')
    for link in soup.find_all('a'):
        org_name = link.contents[0]
        if org_name and org_name not in [i['org_name'] for i in org_names]:
            org_names.append({'org_name': org_name})

    return org_names


def main():
    demisto.info(f'{demisto.command()} is called')
    try:
        if demisto.command() == 'test-module':
            if get_health():
                return_results('ok')
            else:
                return_results('nok')

        elif demisto.command() == 'fetch-incidents':
            next_run, incidents = fetch_incidents(
                last_run=demisto.getLastRun(),
                first_run_time_range=FIRST_RUN_TIME_RANGE)

            demisto.setLastRun(next_run)
            demisto.incidents(incidents)

        elif demisto.command() == 'cov-secpr-list-alerts':
            r = list_alerts()
            if r:
                readable_output = tableToMarkdown('Alerts', r, removeNull=True, headerTransform=string_to_table_header)
            else:
                readable_output = 'No alerts found'

            results = CommandResults(
                outputs_prefix='Covalence.Alert',
                outputs_key_field='id',
                outputs=r,
                readable_output=readable_output
            )
            return_results(results)

        elif demisto.command() == 'cov-secpr-list-sensors':
            r = list_sensors()
            if r:
                readable_output = tableToMarkdown('Sensors', r, removeNull=True, headerTransform=string_to_table_header)
            else:
                readable_output = 'No sensors found'

            results = CommandResults(
                outputs_prefix='Covalence.Sensors',
                outputs_key_field='id',
                outputs=r,
                readable_output=readable_output
            )
            return_results(results)

        elif demisto.command() == 'cov-secpr-get-sensor':
            r = get_sensor()
            if r:
                readable_output = tableToMarkdown('Sensor', r, removeNull=True, headerTransform=string_to_table_header)
            else:
                readable_output = 'None sensor found'

            results = CommandResults(
                outputs_prefix='Covalence.Sensor',
                outputs_key_field='id',
                outputs=r,
                readable_output=readable_output
            )
            return_results(results)

        elif demisto.command() == 'cov-secpr-connections-summary-ip':
            r = connections_summary_by_ip()
            if r:
                readable_output = tableToMarkdown('Connections', r, removeNull=True, headerTransform=string_to_table_header)
            else:
                readable_output = 'No connections found'

            results = CommandResults(
                outputs_prefix='Covalence.Connections',
                outputs_key_field='id',
                outputs=r,
                readable_output=readable_output
            )
            return_results(results)

        elif demisto.command() == 'cov-secpr-connections-summary-port':
            r = connections_summary_by_port()
            if r:
                readable_output = tableToMarkdown('Connections', r, removeNull=True, headerTransform=string_to_table_header)
            else:
                readable_output = 'No connections found'

            results = CommandResults(
                outputs_prefix='Covalence.Connections',
                outputs_key_field='id',
                outputs=r,
                readable_output=readable_output
            )
            return_results(results)

        elif demisto.command() == 'cov-secpr-list-dns-resolutions':
            r = list_dns_resolutions()
            if r:
                readable_output = tableToMarkdown('DNS Resolutions', r, removeNull=True, headerTransform=string_to_table_header)
            else:
                readable_output = 'No DNS resolutions found'

            results = CommandResults(
                outputs_prefix='Covalence.DNSResolutions',
                outputs_key_field='id',
                outputs=r,
                readable_output=readable_output
            )
            return_results(results)

        elif demisto.command() == 'cov-secpr-list-internal-networks':
            r = list_internal_networks()
            if r:
                readable_output = tableToMarkdown('Internal Networks', r, removeNull=True, headerTransform=string_to_table_header)
            else:
                readable_output = 'No internal networks found'

            results = CommandResults(
                outputs_prefix='Covalence.InternalNetworks',
                outputs_key_field='cidr',
                outputs=r,
                readable_output=readable_output
            )
            return_results(results)

        elif demisto.command() == 'cov-secpr-set-internal-networks':
            r = set_internal_networks()

            cidr = r[0]
            notes = r[1]

            readable_output = f'Internal network set as {cidr} with notes "{notes}"'

            results = CommandResults(
                outputs_prefix='Covalence.InternalNetworks',
                outputs_key_field='cidr',
                outputs=r,
                readable_output=readable_output
            )
            return_results(results)

        elif demisto.command() == 'cov-secpr-list-endpoint-agents':
            r = list_endpoint_agents()
            if r:
                readable_output = tableToMarkdown('Endpoint Agents', r, removeNull=True, headerTransform=string_to_table_header)
            else:
                readable_output = 'No endpoint agents found'

            results = CommandResults(
                outputs_prefix='Covalence.EndpointAgents',
                outputs_key_field='agentUuid',
                outputs=r,
                readable_output=readable_output
            )
            return_results(results)

        elif demisto.command() == 'cov-secpr-find-endpoint-agents-by-user':
            r = find_endpoint_by_user()
            if r:
                readable_output = tableToMarkdown('Endpoint Agents', r, removeNull=True, headerTransform=string_to_table_header)
            else:
                readable_output = 'No endpoint agents found'

            results = CommandResults(
                outputs_prefix='Covalence.EndpointAgents',
                outputs_key_field='agentUuid',
                outputs=r,
                readable_output=readable_output
            )
            return_results(results)

        elif demisto.command() == 'cov-secpr-find-endpoint-agents-by-uuid':
            r = find_endpoint_by_uuid()
            if r:
                readable_output = tableToMarkdown('Endpoint Agents', r, removeNull=True, headerTransform=string_to_table_header)
            else:
                readable_output = 'No endpoint agents found'

            results = CommandResults(
                outputs_prefix='Covalence.EndpointAgents',
                outputs_key_field='agentUuid',
                outputs=r,
                readable_output=readable_output
            )
            return_results(results)

        elif demisto.command() == 'cov-secpr-search-endpoint-process':
            r = search_endpoint_process()
            if r:
                readable_output = tableToMarkdown('Endpoint Process', r, removeNull=True, headerTransform=string_to_table_header)
            else:
                readable_output = 'No endpoint process found'

            results = CommandResults(
                outputs_prefix='Covalence.EndpointProcess',
                outputs_key_field='id',
                outputs=r,
                readable_output=readable_output
            )
            return_results(results)

        elif demisto.command() == 'cov-secpr-search-endpoint-installed-software':
            r = search_endpoint_installed_software()
            if r:
                readable_output = tableToMarkdown('Endpoint Software', r, removeNull=True, headerTransform=string_to_table_header)
            else:
                readable_output = 'No endpoint software found'

            results = CommandResults(
                outputs_prefix='Covalence.EndpointSoftware',
                outputs_key_field='id',
                outputs=r,
                readable_output=readable_output
            )
            return_results(results)

        elif demisto.command() == 'cov-secpr-list-organizations':
            r = list_org()
            if r:
                readable_output = tableToMarkdown('Organizations', r, removeNull=True, headerTransform=string_to_table_header)
            else:
                readable_output = 'No organizations found'

            results = CommandResults(
                outputs_prefix='Covalence.EndpointSoftware',
                outputs_key_field='id',
                outputs=r,
                readable_output=readable_output
            )
            return_results(results)

        else:
            msg = f'Unknown command {demisto.command()}'
            demisto.error(msg)
    except Exception as e:
        demisto.error(traceback.format_exc())
        return_error(f'Failed to execute {demisto.command()} command. Error: {str(e)}\n{traceback.format_exc()}')


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
