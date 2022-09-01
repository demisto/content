from CommonServerPython import *

# IMPORTS #
import json
import requests
import urllib3
from typing import Dict, List, Union

# Disable insecure warnings
urllib3.disable_warnings()

# CONSTANTS #
MAX_FETCH_SIZE = 50
DATE_FORMAT = "%Y-%m-%dT%H%M"  # 2019-09-01T1012
PARAMS_KEYS = {
    "threat_score": "t_score",
    "threat_score_gte": "t_score_gte",
    "certainty_score": "c_score",
    "certainty_score_gte": "c_score_gte",
    "destination_port": "dst_port"
}


# HELPER FUNCTIONS #
def create_incident_from_detection(detection: dict):
    """
    converts a detection object to an Incident object
    """
    labels = []
    for key, value in detection.items():
        labels.append({'type': key, 'value': json.dumps(value)})

        return {
            "name": f'Detection from Vectra with ID: {detection.get("id")}',
            "labels": labels,
            "rawJSON": json.dumps(detection)
        }


def calc_pages(total_count: int, this_count: int):
    """
    preforms ciel operation to find the total number of pages
    """
    return -(-total_count // this_count)  # minus minus so the floor will become ceiling


def max_timestamp(timestamp1: str, timestamp2: str) -> str:
    """
    returns the older timestamp
    """
    date1 = parse_date_string(timestamp1, date_format=DATE_FORMAT)
    date2 = parse_date_string(timestamp2, date_format=DATE_FORMAT)

    return timestamp1 if date1 > date2 else timestamp2


def update_vectra_params(kwargs: dict) -> dict:
    """
    updates keys to match Vectra's syntax
    """
    return {PARAMS_KEYS.get(key, key): value for key, value in kwargs.items()}


class Client:
    def __init__(self, vectra_url: str, api_token: str, verify: bool, proxy: dict, fetch_size: int,
                 first_fetch: str, t_score_gte: int, c_score_gte: int, state: str):
        """
        :param vectra_url: IP or hostname of Vectra brain (ex https://www.example.com) - required
        :param api_token: API token for authentication when using API v2*
        :param verify: Boolean, controls whether we verify the server's TLS certificate
        :param proxy: Dictionary mapping protocol to the URL of the proxy.
        :param fetch_size: Max number of incidents to fetch in each cycle
        :param first_fetch: Fetch only Detections newer than this date
        :param c_score_gte: Fetch only Detections with greater/equal Certainty score
        :param t_score_gte: Fetch only Detections with greater/equal Threat score
        :param state: Fetch only Detections with matching State (e.g., active, inactive, ignored)
        """
        self.state = state
        self.t_score_gte = t_score_gte
        self.c_score_gte = c_score_gte
        self.fetch_size = fetch_size
        self.headers = {'Authorization': f'Token {api_token}'}
        self.base_url = vectra_url + '/api/v2.1/'
        self.verify = verify
        self.proxies = proxy
        self.first_fetch = first_fetch

    def http_request(self, method='GET', url_suffix='', params=None, data=None) -> Dict:
        """
        Generic HTTP request to Vectra API.

        :param method: Request's method e.g., 'GET', 'POST', 'PATCH'
        :param url_suffix: The URL's suffix, usually indicates the API command
        :param params: Command parameters
        :param data: Other data to send the request with
        :return: .json() of the response if exists
        """
        full_url = self.base_url + url_suffix
        try:
            res = requests.request(
                method=method,
                url=full_url,
                headers=self.headers,
                params=params,
                data=data,
                verify=self.verify,
                proxies=self.proxies,
            )
        except requests.exceptions.ConnectTimeout:
            raise Exception('Connection Timeout Error - potential reasons might be that the Server URL parameter is'
                            ' incorrect or that the Server is not accessible from your host.')

        except requests.exceptions.SSLError:
            raise Exception('SSL Certificate Verification Failed \nTry selecting \'Trust any certificate\'')

        except requests.exceptions.ConnectionError:
            raise Exception(f'Failed to connect to - {self.base_url} \nPlease check the URL')

        if not res.ok:
            raise ValueError(f'Error in API call to Vectra [{res.status_code:d}]. Reason: {res.text}')

        try:
            return res.json()

        except Exception:
            raise ValueError(f"Failed to parse http response to JSON format. Original response body: \n{res.text}")

    def fetch_incidents(self, last_run: Dict):
        """
        Fetches Detections from Vectra into Demisto Incidents

        :param last_run: Integration's last run
        """
        last_timestamp: str = last_run.get('last_timestamp', self.first_fetch)  # type: ignore
        query_string = f'detection.threat:>={self.t_score_gte}'
        query_string += f' and detection.certainty:>={self.c_score_gte}'
        query_string += f' and detection.last_timestamp:>{last_timestamp}'  # format: "%Y-%m-%dT%H%M"
        query_string += f' and detection.state:{self.state}' if self.state != 'all' else ''
        demisto.info(f'\n\nQuery String:\n{query_string}\n\n')
        params = {
            'query_string': query_string,
            'page_size': self.fetch_size,
            'page': 1,
            'order_field': 'last_timestamp'
        }
        raw_response = self.http_request(params=params, url_suffix='search/detections')  # type: ignore
        demisto.info("\n\n Queried Successfully\n\n")
        # Detections -> Incidents, if exists
        incidents = []
        if 'results' in raw_response:
            res: Union[List[Dict], Dict] = raw_response.get('results')  # type: ignore
            detections: List[Dict] = [res] if not isinstance(res, List) \
                else sorted(res, key=lambda h: h.get('id'))  # type: ignore

            try:
                for detection in detections:
                    incidents.append(create_incident_from_detection(detection))  # type: ignore
                    # format from response: %Y-%m-%dT%H:%M:%SZ
                    response_last_timestamp = datetime.strptime(detection.get('last_timestamp'),  # type: ignore
                                                                "%Y-%m-%dT%H:%M:%SZ").strftime("%Y-%m-%dT%H%M")
                    last_timestamp = max_timestamp(last_timestamp, response_last_timestamp)  # type: ignore

                if incidents:
                    last_run = {'last_timestamp': last_timestamp}

            except ValueError:
                raise
        demisto.info(f"Last run is:\n {last_run}")
        return last_run, incidents


def get_detections_command(client: Client, **kwargs):
    """
    Detection objects contain all the information related to security events detected on the network.

    :QUERY PARAMETERS:
    :keyword fields: Filters objects listed
    :keyword page: Page number. Possible values are a positive integer or last
    :keyword page_size: Possible values are a positive integer or all
    :keyword ordering: Orders records by last timestamp, threat score and certainty score. Default is ascending order.
     Scores can sorted in descending order by prepending the query with “minus” symbol
    :keyword min_id: >= the id provided
    :keyword max_id: <= the id provided
    :keyword state: Filter by state: active, inactive, ignored, ignored for all
    :keyword type_vname: Filter by the detection type (verbose name)
    :keyword category: Filter by the detection category
    :keyword src_ip: Filter by source (ip address)
    :keyword threat_score: Filter by threat score
    :keyword threat_score_gte: Filter by threat score >= the score provided
    :keyword certainty_score: Filter by certainty score
    :keyword certainty_score_gte: Filter by certainty score >= the score provided
    :keyword last_timestamp: Filter by last timestamp
    :keyword host_id: Filter by id of the host object a detection is attributed to
    :keyword tags: Filter by a tag or a comma-separated list of tags
    :keyword destination: Filter by destination in the detection detail set
    :keyword proto: Filter by the protocol in the detection detail set
    :keyword destination_port: Filter by the destination port in the detection detail set
    :keyword inbound_ip: Filter by the inbound_ip in the relayed comm set
    :keyword inbound_proto: Filter by the inbound_proto in the relayed comm set
    :keyword inbound_port: Filter by the inbound_port in the relayed comm set
    :keyword inbound_dns: Filter by the inbound_dns in the relayed comm set
    :keyword outbound_ip: Filter by the outbound_ip in the relayed comm set
    :keyword outbound_proto: Filter by the outbound_proto in the relayed comm set
    :keyword outbound_port: Filter by the outbound_port in the relayed comm set
    :keyword outbound_dns: Filter by the outbound_dns in the relayed_comm_set
    :keyword dns_ip: Filter by the dns_ip in the dns_set
    :keyword dns_request: Filter by the dns_request in the dns_set
    :keyword resp_code: Filter by the resp_code in the dns_set
    :keyword resp: Filter by the resp in the dns_set
    """
    raw_response = client.http_request(params=update_vectra_params(kwargs), url_suffix='detections')
    count = raw_response.get('count')
    if count == 0:
        return "Couldn't find any results", {}, raw_response

    res = raw_response.get('results')  # type: ignore
    dets: List[Dict] = [res] if not isinstance(res, List) else sorted(res, key=lambda h: h.get('id'))  # type: ignore

    headers = ['id', 'category', 'src_ip', 'threat', 'certainty', 'state', 'detection', 'detection_category',
               'detection_type', 'first_timestamp', 'tags', 'targets_key_asset', 'type_vname']
    pages = calc_pages(this_count=len(res), total_count=count)  # type: ignore
    readable_output = tableToMarkdown(
        name=f'Detection table (Showing Page {kwargs.get("page", 1)} out of {pages})',
        t=dets,
        headers=headers
    )

    if 'detection_id' in kwargs:
        if 'summary' in dets[0]:  # type: ignore
            summary = dets[0].get('summary')  # type: ignore
            if summary:
                readable_output += '\n' + tableToMarkdown(name='Summary', t=summary[0], headers=summary[0].keys())

        if 'relayed_comm_set' in dets[0]:  # type: ignore
            relayed_comm_set: List = dets[0].get('relayed_comm_set')  # type: ignore
            if not isinstance(relayed_comm_set, list):
                relayed_comm_set = [relayed_comm_set]
                if len(relayed_comm_set) > 0 and relayed_comm_set[0]:
                    wanted_keys = relayed_comm_set[0].keys().remove('url')
                    readable_output += '\n' + tableToMarkdown(name='Relayed Comm Set', t=relayed_comm_set[0],
                                                              headers=wanted_keys)

    context = []
    for detection in dets:
        context.append(createContext(
            {
                'ID': detection.get('id'),
                'TypeVName': detection.get('type_vname'),
                'Category': detection.get('category'),
                'SourceIP': detection.get('src_ip'),
                'SourceAccount': detection.get('src_account'),
                'SourceHost': detection.get('src_host'),
                'Description': detection.get('description'),
                'Detection': detection.get('detection'),
                'DetectionCategory': detection.get('detection_category'),
                'DetectionType': detection.get('detection_type'),
                'HasActiveTraffic': detection.get('has_active_traffic'),
                'Note': detection.get('note'),
                'TriageRuleID': detection.get('triage_rule_id'),
                'ThreatScore': detection.get('threat'),
                'CertaintyScore': detection.get('certainty'),
                'TargetsKeyAsset': detection.get('targets_key_asset'),
                'FirstTimestamp': detection.get('first_timestamp'),
                'LastTimestamp': detection.get('last_timestamp'),
                'Tags': detection.get('tags'),
                'HostID': detection.get('host', '').split('/')[-1] if 'host' in detection else None
            }, removeNull=True)
        )
    outputs = {'Vectra.Detection(val.ID==obj.ID)': context}

    return readable_output, outputs, raw_response


def get_hosts_command(client: Client, **kwargs):
    """
    Host information includes data that correlates the host data to detected security events.

    :QUERY PARAMETERS:
    :keyword host_id:  Filter by host ID
    :keyword fields:  Filters objects listed
    :keyword page:  Page number. Possible values are a positive integer or last
    :keyword page_size:  Page size. Possible values are a positive integer or all
    :keyword ordering:  Orders records by last timestamp, threat score and certainty score.
        The default out sorts threat and certainty score in ascending order. Scores
        can sorted in descending order by prepending the query with “minus” symbol
    :keyword name: Filter by name
    :keyword state: Filter by state: active, inactive, suspended, ignored, ignored4all
    :keyword last_source: Filter by last_source (ip address)
    :keyword threat_score: Filter by threat score
    :keyword threat_score_gte: Filter by threat score >= the score provided
    :keyword certainty_score: Filter by certainty score
    :keyword certainty_score_gte: Filter by certainty score >= the score provided
    :keyword last_detection_timestamp: Filter by last_detection_timestamp
    :keyword tags: comma-separated list of tags, e.g., tags=baz | tags=foo,bar"
    :keyword key_assest: Filter by key asset: True, False
    :keyword mac_address: Filter by mac address
    """
    raw_response = client.http_request(params=update_vectra_params(kwargs), url_suffix='hosts')
    count = raw_response.get('count')
    if count == 0:
        return "Couldn't find any results", {}, raw_response

    res: List[Dict] = raw_response.get('results')  # type: ignore
    hosts: List[Dict] = [res] if not isinstance(res, List) else sorted(res, key=lambda h: h.get('id'))  # type: ignore

    for host in hosts:
        if 'detection_set' in host:
            host['detection_ids'] = [host.split('/')[-1] for host in host.get('detection_set')]  # type: ignore

    headers = ['id', 'name', 'state', 'threat', 'certainty', 'last_source', 'url', 'assigned_to', 'owner_name',
               'first_timestamp', 'tags', 'note']
    pages = calc_pages(this_count=len(res), total_count=count)  # type: ignore
    readable_output = tableToMarkdown(
        name=f'Hosts table (Showing Page {kwargs.get("page", 1)} out of {pages})',
        t=hosts,
        headers=headers
    )

    context = []
    for host in hosts:
        context.append(
            {
                'ID': host.get('id'),
                'Name': host.get('name'),
                'LastDetection': host.get('last_detection_timestamp'),
                'DetectionID': host.get('detection_ids'),
                'KeyAsset': host.get('key_asset'),
                'State': host.get('state'),
                'IP': host.get('last_source'),
                'Note': host.get('note'),
                'ThreatScore': host.get('threat'),
                'CertaintyScore': host.get('certainty'),
                'HostLuid': host.get('host_luid'),
                'LastDetectionTimestamp': host.get('last_detection_timestamp'),
                'LastModified': host.get('last_modified'),
                'OwnerName': host.get('owner_name'),
                'Severity': host.get('severity'),
                'LastSource': host.get('last_source'),
                'Tags': host.get('tags'),
                'ActiveTraffic': host.get('active_traffic')
            }
        )

    outputs = {'Vectra.Host(val.ID==obj.ID)': context}

    return readable_output, outputs, raw_response


def get_users_command(client: Client, **kwargs):
    """
    User information includes all data corresponding to user accounts

    :QUERY PARAMETERS:
    :keyword username: Filter by username
    :keyword role: Filter by role
    :keyword account_type: Filter by account type (Local, Special, Limited Time Link, LDAP, TACACS)
    :keyword authentication_profile: Filter by authentication profile (LDAP or TACACS only)
    :keyword last_login_gte: Filters for User’s that have logged in since the given timestamp
    """
    raw_response = client.http_request(params=kwargs, url_suffix='users')
    count = raw_response.get('count')
    if count == 0:
        return "Couldn't find any results", {}, raw_response

    res: List[Dict] = raw_response.get('results')  # type: ignore
    users: List[Dict] = [res] if not isinstance(res, List) else sorted(res, key=lambda h: h.get('id'))  # type: ignore

    headers = ['id', 'last_login', 'username', 'email', 'account_type', 'authentication_profile', 'role']
    pages = calc_pages(this_count=len(res), total_count=count)  # type: ignore
    readable_output = tableToMarkdown(
        name=f'Users table (Showing Page {kwargs.get("page", 1)} out of {pages})',
        t=users,
        headers=headers
    )

    context = []
    for user in users:
        context.append(
            {
                'ID': user.get('id'),
                'UserName': user.get('username'),
                'LastLogin': user.get('last_login'),
                'Email': user.get('email'),
                'AccountType': user.get('account_type'),
                'AuthenticationProfile': user.get('authentication_profile'),
                'Role': user.get('role'),
            }
        )
    outputs = {'Vectra.User(val.ID==obj.ID)': context}

    return readable_output, outputs, raw_response


def search_command(client: Client, search_type: str, **kwargs):
    """
    The search API endpoint allows users to perform advanced search against hosts and detections

    :param client: Vectra Client

    :QUERY PARAMETERS:
    :param search_type: The type of search to preform, can be either Hosts or Detections
    :keyword query_string: Query that needs to be performed
    :keyword page_size: Number of results returned per page. the default page_size is 50, max 5000
    """
    raw_response = client.http_request(params=kwargs, url_suffix=f'search/{search_type}')
    count = raw_response.get('count')
    if count == 0:
        return "Couldn't find any results", {}, raw_response

    res: List[Dict] = raw_response.get('results')  # type: ignore
    res: List[Dict] = [res] if not isinstance(res, List) else sorted(res, key=lambda h: h.get('id'))  # type: ignore

    headers = ['id', 'threat', 'certainty', 'state', 'first_timestamp']

    readable_output = tableToMarkdown(name='Search results table', t=res, headers=headers)

    context = []
    for r in res:
        context.append(createContext(
            {
                'ID': r.get('id'),
                'Hostname': r.get('name'),
                'LastDetection': r.get('last_detection_timestamp'),
                'DetectionID': r.get('detection_ids'),
                'ThreatScore': r.get('threat'),
                'CertaintyScore': r.get('certainty'),
                'KeyAsset': r.get('key_asset'),
                'IP': r.get('last_source'),
                'TypeVName': r.get('type_vname'),
                'Category': r.get('category'),
                'SrcIP': r.get('src_ip'),
                'State': r.get('state'),
                'TargetsKeyAsset': r.get('targets_key_asset'),
                'FirstTimestamp': r.get('first_timestamp'),
                'LastTimestamp': r.get('last_timestamp'),
                'Tags': r.get('tags'),
                'HostID': r.get('host', '').split('/')[-1] if 'host' in r else None
            }, removeNull=True)
        )

    path = 'Host' if search_type == 'hosts' else 'Detection'
    outputs = {f'Vectra.{path}(val.ID==obj.ID)': context}

    return readable_output, outputs, raw_response


def get_triage_command(client: Client):
    """
    The rules branch can be used to retrieve a listing of configured Triage rules
    """
    raw_response = client.http_request(url_suffix='rules')
    count = raw_response.get('count')
    if count == 0:
        return "Couldn't find any results", {}, raw_response

    res: List[Dict] = raw_response.get('results')  # type: ignore
    rules: List[Dict] = [res] if not isinstance(res, List) else sorted(res, key=lambda h: h.get('name'))  # type: ignore

    headers = ['id', 'enabled', 'created_timestamp', 'is_whitelist', 'priority', 'active_detections',
               'total_detections', 'template', 'detection_category', 'triage_category', 'detection']
    readable_output = tableToMarkdown(name='Rules table', t=rules, headers=headers)

    context = []
    for rule in rules:
        temp = {
            'ID': rule.get('name'),
            'SmartCategory': rule.get('smart_category'),
            'Description': rule.get('description'),
            'Type': rule.get('type_vname'),
            'Category': rule.get('category'),
            'Created': rule.get('created_timestamp'),
            'LastUpdate': rule.get('last_timestamp'),
            'Host': rule.get('host'),
            'IP': rule.get('ip'),
            'Priority': rule.get('priority'),
            'Remote': [
                {
                    'IP': rule.get('remote1_ip'),
                    'Protocol': rule.get('remote1_proto'),
                    'Port': rule.get('remote1_port'),
                    'DNS': rule.get('remote1_dns')
                },
                {
                    'IP': rule.get('remote2_ip'),
                    'Protocol': rule.get('remote2_proto'),
                    'Port': rule.get('remote2_port'),
                    'DNS': rule.get('remote2_dns')
                }
            ]
        }  # type: ignore
        kerberos = {
            'Account': rule.get('remote1_kerb_account'),
            'Service': rule.get('remote1_kerb_service')
        }
        if kerberos['Account'] or kerberos['Service']:
            temp['Remote'] = {'Kerberos': kerberos}  # type: ignore

        remove_nulls_from_dictionary(temp)
        context.append(temp)

    outputs = {'Vectra.Rule(val.ID==obj.ID)': context}

    return readable_output, outputs, raw_response


def get_proxies_command(client: Client, proxy_id: int = None):
    """
    The proxies API can be used to manage proxy IP addresses (internal or external) in Cognito. The API can
    be used to retrieve the current list of proxy IP addresses or to create new proxy objects in Cognito.

    :param proxy_id: The id of the Proxy object.
    :param client: Vectra Client
    """
    raw_response = client.http_request(url_suffix=f'proxies/{proxy_id}' if proxy_id else 'proxies')
    count = demisto.get(raw_response, 'meta.count')
    if count == 0:
        return "Couldn't find any results", {}, raw_response

    res = raw_response.get('proxies')  # type: ignore
    proxies: List[Dict] = [res] if not isinstance(res, List) else sorted(res, key=lambda h: h.get('id'))  # type: ignore

    headers = ['id', 'source', 'considersProxy', 'address']
    readable_output = tableToMarkdown(name='Rules table', t=proxies, headers=headers)

    context = []
    for proxy in proxies:
        context.append(createContext(
            {
                'ID': proxy.get('id'),
                'Source': proxy.get('source'),
                'ConsidersProxy': proxy.get('considersProxy'),
                'Address': proxy.get('address'),
            }, removeNull=True)
        )
    outputs = {'Vectra.Proxy(val.ID==obj.ID)': context}

    return readable_output, outputs, raw_response


def get_threatfeed_command(client: Client, threatfeed_id: int = None):
    """
    Retrieves the current list of threatFeed objects already configured in the system

    :param threatfeed_id: The id of the ThreatFeed object.
    :param client: Vectra Client
    """
    raw_response = client.http_request(url_suffix=f'threatFeeds/{threatfeed_id}' if threatfeed_id else 'threatFeeds')
    count = demisto.get(raw_response, 'meta.count')
    if count == 0:
        return "Couldn't find any results", {}, raw_response

    res = raw_response.get('threatFeeds')  # type: ignore
    feeds: List[Dict] = [res] if not isinstance(res, List) else sorted(res, key=lambda h: h.get('id'))  # type: ignore

    for feed in feeds:
        feed.update(feed.get('defaults'))  # type: ignore
    headers = ['id', 'name', 'certainty', 'category', 'duration', 'indicatorType']
    readable_output = tableToMarkdown(name='Rules table', t=feeds, headers=headers)

    context = []
    for feed in feeds:
        context.append(createContext(
            {
                'ID': feed.get('id'),
                'Name': feed.get('name'),
                'Duration': feed.get('duration'),
                'Category': feed.get('category'),
                'Certainty': feed.get('certainty'),
                'Data': feed.get('data'),
                'IndicatorType': feed.get('indicatorType'),
            }, removeNull=True)
        )
    outputs = {'Vectra.ThreatFeed(val.ID==obj.ID)': context}

    return readable_output, outputs, raw_response


def module_test(client: Client, last_run: dict):
    """
    Performs basic tests to insure API connection, and to test integration's parameters
    """
    client.fetch_incidents(last_run=last_run)  # will handle any bad request/bad api token
    return 'ok'


# COMMANDS MANAGER / SWITCH PANEL #
def main():
    api_token = demisto.getParam('token')

    # Remove trailing slash to prevent wrong URL path to service
    server_url = demisto.getParam('server').rstrip('/')

    # Fetch only detections that have greater or equal Certainty and Threat scores
    c_score_gte, t_score_gte = int(demisto.params().get('c_score_gte', 0)), int(demisto.params().get('t_score_gte', 0))
    state = demisto.params().get('state')

    # How many time before the first fetch to retrieve incidents
    first_fetch_time = demisto.params().get('first_fetch_time', '7 days')
    first_fetch, _ = parse_date_range(first_fetch_time, date_format=DATE_FORMAT)

    # Remove proxy if not set to true in params
    proxies = handle_proxy()

    fetch_size = int(demisto.params().get('fetch_size', 20))
    verify_certificate = not demisto.params().get('insecure', False)

    LOG(f'Command being called is {demisto.command()}')
    try:
        # create a new Client instance
        client = Client(
            vectra_url=server_url,
            verify=verify_certificate,
            api_token=api_token,
            proxy=proxies,
            fetch_size=max(0, min(fetch_size, MAX_FETCH_SIZE)),
            c_score_gte=c_score_gte,
            t_score_gte=t_score_gte,
            first_fetch=first_fetch,
            state=state
        )

        # execute the current command
        if demisto.command() == 'test-module':
            results = module_test(client, last_run=demisto.getLastRun())
            demisto.results(results)

        elif demisto.command() == 'fetch-incidents':
            next_run, incidents = client.fetch_incidents(last_run=demisto.getLastRun())
            demisto.setLastRun(next_run)
            demisto.incidents(incidents)

        elif demisto.command() == 'vectra-get-detections':
            return_outputs(*get_detections_command(client, **demisto.args()))

        elif demisto.command() == 'vectra-get-users':
            return_outputs(*get_users_command(client, **demisto.args()))

        elif demisto.command() == 'vectra-get-hosts':
            return_outputs(*get_hosts_command(client, **demisto.args()))

        elif demisto.command() == 'vectra-get-proxies':
            return_outputs(*get_proxies_command(client, demisto.getArg('proxy_id')))

        elif demisto.command() == 'vectra-get-threatfeed':
            return_outputs(*get_threatfeed_command(client, demisto.getArg('threatfeed_id')))

        elif demisto.command() == 'vectra-search':
            return_outputs(*search_command(client, **demisto.args()))

        elif demisto.command() == 'vectra-triage':
            return_outputs(*get_triage_command(client))

        elif demisto.command() == 'vectra-get-host-by-id':
            query_string = f'host.id:{demisto.args().get("host_id")}'
            return_outputs(*search_command(client, search_type='hosts', query_string=query_string))

        elif demisto.command() == 'vectra-get-detection-by-id':
            query_string = f'detection.id:{demisto.args().get("detection_id")}'
            return_outputs(*search_command(client, search_type='detections', query_string=query_string))

    # Log exceptions
    except Exception as ex:
        if demisto.command() == 'fetch-incidents':
            LOG(str(ex))
            raise
        else:
            return_error(str(ex))


if __name__ in ['__main__', 'builtin', 'builtins']:
    main()
