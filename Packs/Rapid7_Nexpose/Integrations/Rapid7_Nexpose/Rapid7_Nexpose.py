import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *
import time
import re
import requests
import json


RANGE_OPERATORS = ['in-range', 'is-between', 'not-in-range']
YEAR_IN_MINUTES = 525600
MONTH_IN_MINUTES = 43800
WEEK_IN_MINUTES = 10080
DAY_IN_MINUTES = 1440
HOUR_IN_MINUTES = 60

# disable insecure warnings
requests.packages.urllib3.disable_warnings()
SESSION = ''
USERNAME = demisto.params()['credentials']['identifier']
PASSWORD = demisto.params()['credentials']['password']
VERIFY_SSL = not demisto.params().get('unsecure', False)
TOKEN = demisto.params().get('token')


def get_server_url():
    url = demisto.params()['server']
    url = re.sub('/[\/]+$/', '', url)
    url = re.sub('\/$', '', url)
    return url


BASE_URL = get_server_url()
SERVER_URL = BASE_URL + '/api/3'


def get_login_headers():
    headers = {
        'Content-Type': 'application/x-www-form-urlencoded',
        'Accept': 'application/json'
    }

    if TOKEN is not None:
        headers['Token'] = TOKEN

    return headers


def login():
    url = BASE_URL + '/data/user/login'
    headers = get_login_headers()
    body = {
        'nexposeccusername': USERNAME,
        'nexposeccpassword': PASSWORD
    }
    res = requests.post(url, headers=headers, data=body, verify=VERIFY_SSL)
    if res.status_code < 200 or res.status_code >= 300:
        return ''
    body = res.json()
    if 'sessionID' not in body:
        return ''

    return body['sessionID']


def get_headers():
    headers = {
        'Content-Type': 'application/json'
    }

    if TOKEN is not None:
        headers['Token'] = TOKEN
    return headers


def get_site_headers():
    headers = get_headers()

    headers['Cookie'] = 'nexposeCCSessionID=' + SESSION
    headers['nexposeCCSessionID'] = SESSION

    return headers


def get_site(asset_id):
    url = BASE_URL + '/data/assets/' + str(asset_id) + '/scans'
    headers = get_site_headers()
    res = requests.post(url, headers=headers, auth=(USERNAME, PASSWORD), verify=VERIFY_SSL)
    if res.status_code < 200 or res.status_code >= 300:
        return ''
    response = res.json()
    if response is None or response['records'] is None or len(response['records']) == 0:
        return ''

    return {
        'id': response['records'][0]['siteID'],
        'name': response['records'][0]['siteName'],
        'ip': response['records'][0]['ipAddress']
    }


def send_request(path, method='get', body=None, params=None, headers=None, is_file=False):
    body = body if body is not None else {}
    params = params if params is not None else {}

    url = '{}/{}'.format(SERVER_URL, path)

    headers = headers if headers is not None else get_headers()
    res = requests.request(method, url, headers=headers, data=json.dumps(body), params=params,
                           auth=(USERNAME, PASSWORD), verify=VERIFY_SSL)
    if res.status_code < 200 or res.status_code >= 300:
        raise Exception('Got status code ' + str(
            res.status_code) + ' with url ' + url + ' with body ' + res.content + ' with headers ' + str(res.headers))
    return res.json() if is_file is False else res.content


def iso8601_duration_as_minutes(d):
    if d is None:
        return 0
    if d[0] != 'P':
        raise ValueError('Not an ISO 8601 Duration string')
    minutes = 0
    # split by the 'T'
    for i, item in enumerate(d.split('T')):
        for number, period in re.findall('(?P<number>\d+)(?P<period>S|M|H|D|W|Y)', item):
            # print '%s -> %s %s' % (d, number, unit )
            number = float(number)
            this = 0
            if period == 'Y':
                this = number * YEAR_IN_MINUTES  # 365.25
            elif period == 'W':
                this = number * WEEK_IN_MINUTES
            elif period == 'D':
                this = number * DAY_IN_MINUTES
            elif period == 'H':
                this = number * HOUR_IN_MINUTES
            elif period == 'M':
                # ambiguity betweeen months and minutes
                if i == 0:
                    this = number * MONTH_IN_MINUTES  # assume 30 days
                else:
                    this = number
            elif period == 'S':
                this = number / 60
            minutes = minutes + this
    return minutes


def dq(obj, path):
    '''
    return a value in an object path. in case of multiple objects in path, searches them all.
    @param obj - dictionary tree to search in
    @param path (list) - a path of the desired value in the object. for example: ['root', 'key', 'subkey']
    '''
    if len(path) == 0:
        return obj

    if isinstance(obj, dict):
        if path[0] in obj:
            return dq(obj[path[0]], path[1:])
    elif isinstance(obj, list):
        # in case current obj has multiple objects, search them all.
        line = [dq(o, path) for o in obj]
        return [k for k in line if k is not None]

    # in case of error in the path
    return None


def translate_single_object(obj, map_fields, filter_func=None):
    d = {}
    for f in map_fields:
        if filter_func is None or filter_func(f):
            d[f['to']] = dq(obj, f['from'].split('.'))

    return d


def translate_object(content, map_fields, filter_func=None):
    '''
    Converts object fields according to mapping dictionary
    @param content - original content to copy
    @param mapFields - an object assosiating source and destination object fields
    @filter_func - function to filter out fields
    @returns the mapped object
    '''
    if isinstance(content, (list, tuple)):
        return [translate_single_object(item, map_fields, filter_func) for item in content]
    else:
        return translate_single_object(content, map_fields, filter_func)


def get_list_response(path, method='get', limit=None, body={}, params={}):
    final_result = []  # type: ignore
    page_diff = 0
    page_number = 0

    while True:
        page = page_number
        page_number += 1
        params['page'] = page
        if limit is not None:
            params['size'] = limit
        response = send_request(path, method=method, body=body, params=params)
        if not response:
            break
        if response['resources'] is not None:
            final_result = final_result + response['resources']
        if response['page'] is not None:
            page_diff = response['page']['totalPages'] - response['page']['number']
        if page_diff < 1 or limit is not None:
            break

    return final_result


def get_last_scan(asset):
    if asset['history'] is None:
        return "-"
    sorted_dates = sorted(asset['history'], key=get_datetime_from_asset_history_item,
                          reverse=True)

    if sorted_dates[0] is not None:
        return {
            'date': sorted_dates[0]['date'] if 'date' in sorted_dates[0] else '-',
            'id': sorted_dates[0]['scanId'] if 'scanId' in sorted_dates[0] else '-'
        }
    else:
        return {
            'date': '-',
            'id': '-'
        }


def get_datetime_from_asset_history_item(item):
    try:
        return time.strptime(item['date'], "%Y-%m-%dT%H:%M:%S.%fZ")
    except ValueError:
        return time.strptime(item['date'], "%Y-%m-%dT%H:%M:%SZ")


def get_asset_command():
    asset = get_asset(demisto.args()['id'])

    if asset is None:
        return "Asset not found"
    last_scan = get_last_scan(asset)
    asset['LastScanDate'] = last_scan['date']
    asset['LastScanId'] = last_scan['id']
    asset['Site'] = get_site(asset['id'])['name']

    asset_headers = [
        'AssetId',
        'Addresses',
        'Hardware',
        'Aliases',
        'HostType',
        'Site',
        'OperatingSystem',
        'CPE',
        'LastScanDate',
        'LastScanId',
        'RiskScore'
    ]

    asset_output = translate_object(asset, [
        {'from': 'id', 'to': 'AssetId'},
        {'from': 'addresses.ip', 'to': 'Addresses'},
        {'from': 'addresses.mac', 'to': 'Hardware'},
        {'from': 'hostNames.name', 'to': 'Aliases'},
        {'from': 'type', 'to': 'HostType'},
        {'from': 'Site', 'to': 'Site'},
        {'from': 'os', 'to': 'OperatingSystem'},
        {'from': 'vulnerabilities.total', 'to': 'Vulnerabilities'},
        {'from': 'cpe.v2.3', 'to': 'CPE'},
        {'from': 'LastScanDate', 'to': 'LastScanDate'},
        {'from': 'LastScanId', 'to': 'LastScanId'},
        {'from': 'riskScore', 'to': 'RiskScore'}
    ])

    software_output = None
    services_output = None
    users_output = None

    if 'software' in asset and len(asset['software']) > 0:
        software_headers = [
            'Software',
            'Version'
        ]

        software_output = translate_object(asset['software'], [
            {'from': 'description', 'to': 'Software'},
            {'from': 'version', 'to': 'Version'}
        ])

    if 'services' in asset and len(asset['services']) > 0:
        service_headers = [
            'Name',
            'Port',
            'Product',
            'Protocol'
        ]

        services_output = translate_object(asset['services'], [
            {'from': 'name', 'to': 'Name'},
            {'from': 'port', 'to': 'Port'},
            {'from': 'product', 'to': 'Product'},
            {'from': 'protocol', 'to': 'Protocol'}
        ])

    if 'users' in asset and len(asset['users']) > 0:
        user_headers = [
            'FullName',
            'Name',
            'UserId'
        ]

        users_output = translate_object(asset['users'], [
            {'from': 'name', 'to': 'Name'},
            {'from': 'fullName', 'to': 'FullName'},
            {'from': 'id', 'to': 'UserId'},
        ])

    vulnerability_headers = [
        'Id',
        'Title',
        'Malware',
        'Exploit',
        'CVSS',
        'Risk',
        'PublishedOn',
        'ModifiedOn',
        'Severity',
        'Instances',
    ]

    vulnerabilities = get_vulnerabilities(asset['id'])
    asset['vulnerabilities'] = vulnerabilities
    vulnerabilities_output = []
    cves_output = []  # type: ignore
    for i, v in enumerate(asset['vulnerabilities']):
        detailed_vuln = get_vulnerability(v['id'])
        # Add to raw output
        asset['vulnerabilities'][i] = dict(asset['vulnerabilities'][i].items() + detailed_vuln.items())
        cvss = dq(detailed_vuln['cvss'], ['v2', 'score'])

        if ('cves' in detailed_vuln):
            cves_output = cves_output + map(lambda cve: {
                'ID': cve
            }, detailed_vuln['cves'])

        output_vuln = {
            'Id': v['id'],
            'Title': detailed_vuln['title'],
            'Malware': detailed_vuln['malwareKits'],
            'Exploit': detailed_vuln['exploits'],
            'CVSS': cvss,
            'Risk': detailed_vuln['riskScore'],
            'PublishedOn': detailed_vuln['published'],
            'ModifiedOn': detailed_vuln['modified'],
            'Severity': detailed_vuln['severity'],
            'Instances': v['instances'],
        }

        vulnerabilities_output.append(output_vuln)

    asset_md = tableToMarkdown('Nexpose asset ' + str(asset['id']), asset_output, asset_headers, removeNull=True)
    vulnerabilities_md = tableToMarkdown('Vulnerabilities', vulnerabilities_output, vulnerability_headers,
                                         removeNull=True) if len(vulnerabilities_output) > 0 else ''
    software_md = tableToMarkdown('Software', software_output, software_headers,
                                  removeNull=True) if software_output is not None else ''
    services_md = tableToMarkdown('Services', services_output, service_headers,
                                  removeNull=True) if services_output is not None else ''
    users_md = tableToMarkdown('Users', users_output, user_headers, removeNull=True) if users_output is not None else ''

    md = asset_md + vulnerabilities_md + software_md + services_md + users_md

    asset_output['Vulnerability'] = vulnerabilities_output
    asset_output['Software'] = software_output
    asset_output['Service'] = services_output
    asset_output['User'] = users_output

    endpoint = {
        'IP': asset_output['Addresses'],
        'MAC': asset_output['Hardware'],
        'HostName': asset_output['Aliases'],
        'OS': asset_output['OperatingSystem']
    }

    context = {
        'Nexpose.Asset(val.AssetId==obj.AssetId)': asset_output,
        'Endpoint(val.IP==obj.IP)': endpoint
    }

    if len(cves_output) > 0:
        context['CVE(val.ID==obj.ID)'] = cves_output

    entry = {
        'Type': entryTypes['note'],
        'Contents': asset,
        'ContentsFormat': formats['json'],
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': md,
        'EntryContext': context
    }

    return entry


def get_asset(asset_id):
    path = 'assets/' + str(asset_id)
    return send_request(path)


def get_asset_vulnerability_command():
    v = get_asset_vulnerability(demisto.args()['id'], demisto.args()['vulnerabilityId'])

    if v is None:
        return 'Vulnerability not found'

    vuln_headers = [
        'Id',
        'Title',
        'Severity',
        'RiskScore',
        'CVSS',
        'CVSSV3',
        'Published',
        'Added',
        'Modified',
        'CVSSScore',
        'CVSSV3Score',
        'Categories',
        'CVES'
    ]

    detailed_vuln = get_vulnerability(v['id'])
    # Add to raw output
    v = dict(v.items() + detailed_vuln.items())
    vuln_outputs = translate_object(detailed_vuln, [
        {'from': 'id', 'to': 'Id'},
        {'from': 'title', 'to': 'Title'},
        {'from': 'severity', 'to': 'Severity'},
        {'from': 'riskScore', 'to': 'RiskScore'},
        {'from': 'cvss.v2.vector', 'to': 'CVSS'},
        {'from': 'cvss.v3.vector', 'to': 'CVSSV3'},
        {'from': 'published', 'to': 'Published'},
        {'from': 'added', 'to': 'Added'},
        {'from': 'modified', 'to': 'Modified'},
        {'from': 'cvss.v2.score', 'to': 'CVSSScore'},
        {'from': 'cvss.v3.score', 'to': 'CVSSV3Score'},
        {'from': 'categories', 'to': 'Categories'},
        {'from': 'cves', 'to': 'CVES'}
    ])

    results_headers = [
        "Port",
        "Protocol",
        "Since",
        "Proof",
        "Status"
    ]

    results_output = []  # type: ignore
    if 'results' in v and len(v['results']) > 0:
        results_output = translate_object(v['results'], [
            {'from': 'port', 'to': 'Port'},
            {'from': 'protocol', 'to': 'Protocol'},
            {'from': 'since', 'to': 'Since'},
            {'from': 'proof', 'to': 'Proof'},
            {'from': 'status', 'to': 'Status'}
        ])

    # Remove HTML tags
    for r in results_output:
        r['Proof'] = re.sub('<.*?>', '', r['Proof'])

    solutions_headers = [
        'Type',
        'Summary',
        'Steps',
        'Estimate',
        'AdditionalInformation'
    ]

    solutions_output = None
    solutions = get_vulnerability_solutions(demisto.args()['id'], demisto.args()['vulnerabilityId'])
    # Add to raw output
    v['solutions'] = solutions
    if solutions is not None and len(solutions) > 0:
        solutions_output = translate_object(solutions['resources'], [
            {'from': 'type', 'to': 'Type'},
            {'from': 'summary.text', 'to': 'Summary'},
            {'from': 'steps.text', 'to': 'Steps'},
            {'from': 'estimate', 'to': 'Estimate'},
            {'from': 'additionalInformation.text', 'to': 'AdditionalInformation'}
        ])
        for i, val in enumerate(solutions_output):
            solutions_output[i]['Estimate'] = str(
                iso8601_duration_as_minutes(solutions_output[i]['Estimate'])) + ' minutes'

    vulnerabilities_md = tableToMarkdown('Vulnerability ' + demisto.args()['vulnerabilityId'], vuln_outputs,
                                         vuln_headers, removeNull=True)
    results_md = tableToMarkdown('Checks', results_output, results_headers, removeNull=True) if len(
        results_output) > 0 else ''
    solutions_md = tableToMarkdown('Solutions', solutions_output, solutions_headers,
                                   removeNull=True) if solutions_output is not None else ''
    md = vulnerabilities_md + results_md + solutions_md
    cves = []  # type: ignore
    if (vuln_outputs['CVES'] is not None and len(vuln_outputs['CVES']) > 0):
        cves = map(lambda cve: {
            'ID': cve
        }, vuln_outputs['CVES'])

    vuln_outputs['Check'] = results_output
    vuln_outputs['Solution'] = solutions_output
    asset = {
        'AssetId': demisto.args()['id'],
        'Vulnerability': [vuln_outputs]
    }

    context = {
        'Nexpose.Asset(val.AssetId==obj.AssetId)': asset,
    }

    if len(cves) > 0:
        context['CVE(val.ID==obj.ID)'] = cves  # type: ignore

    entry = {
        'Type': entryTypes['note'],
        'Contents': v,
        'ContentsFormat': formats['json'],
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': md,
        'EntryContext': context
    }

    return entry


def get_vulnerabilities(asset_id):
    path = 'assets/' + str(asset_id) + '/vulnerabilities'
    return get_list_response(path)


def get_asset_vulnerability(asset_id, vulnerability_id):
    path = 'assets/' + str(asset_id) + '/vulnerabilities/' + str(vulnerability_id)
    return send_request(path)


def get_vulnerability(vulnerability_id):
    path = 'vulnerabilities/' + str(vulnerability_id)
    return send_request(path)


def get_vulnerability_solutions(asset_id, vulnerability_id):
    path = 'assets/' + str(asset_id) + '/vulnerabilities/' + str(vulnerability_id) + '/solution'

    return send_request(path)


def search_by_filter(text_filters):
    if (text_filters is None):
        return []

    filters = get_search_filters(text_filters)
    assets = search_assets(filters, demisto.args()['match'], demisto.args().get('limit'), demisto.args().get('sort'))

    return assets


def search_assets_command():
    queries = demisto.args().get('query')
    ip_addresses = demisto.args().get('ipAddressIs')
    host_names = demisto.args().get('hostNameIs')
    risk_score = demisto.args().get('riskScoreHigherThan')
    vulnerability_title = demisto.args().get('vulnerabilityTitleContains')
    siteIds = demisto.args().get('siteIdIn')

    assets = None
    if queries is not None:
        assets = search_by_filter(queries.split(';'))
    elif risk_score is not None:
        assets = search_by_filter(['risk-score is-greater-than ' + str(risk_score)])
    elif vulnerability_title is not None:
        assets = search_by_filter(['vulnerability-title contains ' + vulnerability_title])
    elif siteIds is not None:
        assets = search_by_filter(['site-id in ' + siteIds])
    elif ip_addresses is not None:
        ips = ip_addresses.split(',')
        assets = []
        for i, ip in enumerate(ips):
            assets = assets + search_by_filter(['ip-address is ' + str(ip)])
    elif host_names is not None:
        host_names = host_names.split(',')
        assets = []
        for i, host_name in enumerate(host_names):
            assets = assets + search_by_filter(['host-name is ' + str(host_name)])

    if (assets is None or len(assets) == 0):
        return 'No assets found'

    for asset in assets:
        last_scan = get_last_scan(asset)
        asset['LastScanDate'] = last_scan['date']
        asset['LastScanId'] = last_scan['id']
        site = get_site(asset['id'])
        asset['Site'] = site['name'] if site != '' else ''

    headers = [
        'AssetId',
        'Address',
        'Name',
        'Site',
        'Exploits',
        'Malware',
        'OperatingSystem',
        'RiskScore',
        'Assessed',
        'LastScanDate',
        'LastScanId'
    ]

    outputs = translate_object(assets, [
        {'from': 'id', 'to': 'AssetId'},
        {'from': 'ip', 'to': 'Address'},
        {'from': 'hostName', 'to': 'Name'},
        {'from': 'Site', 'to': 'Site'},
        {'from': 'vulnerabilities.exploits', 'to': 'Exploits'},
        {'from': 'vulnerabilities.malwareKits', 'to': 'Malware'},
        {'from': 'os', 'to': 'OperatingSystem'},
        {'from': 'vulnerabilities.total', 'to': 'Vulnerabilities'},
        {'from': 'riskScore', 'to': 'RiskScore'},
        {'from': 'assessedForVulnerabilities', 'to': 'Assessed'},
        {'from': 'LastScanDate', 'to': 'LastScanDate'},
        {'from': 'LastScanId', 'to': 'LastScanId'}
    ])

    endpoint = map(lambda o: {
        'IP': o['Address'],
        'HostName': o['Name'],
        'OS': o['OperatingSystem']
    }, outputs)

    entry = {
        'Type': entryTypes['note'],
        'Contents': assets,
        'ContentsFormat': formats['json'],
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': tableToMarkdown('Nexpose assets', outputs, headers, removeNull=True),
        'EntryContext': {
            'Nexpose.Asset(val.AssetId==obj.AssetId)': outputs,
            'Endpoint(val.IP==obj.IP)': endpoint
        }
    }

    return entry


def get_search_filters(text_filters):
    filters = []
    for text in text_filters:
        components = text.split(' ')
        field = components[0]
        operator = components[1]
        value = components[2].split(',')
        # Convert numbers to floats if values are numbers
        for i, v in enumerate(value):
            curr_val = None
            try:
                curr_val = float(v)
            except Exception:
                curr_val = v
            value[i] = curr_val

        flt = {
            'field': field,
            'operator': operator,
        }
        if len(value) > 1:
            if operator in RANGE_OPERATORS:
                flt['lower'] = value[0]
                flt['upper'] = value[1]
            else:
                flt['values'] = value
        else:
            flt['value'] = value[0]
        filters.append(flt)
    return filters


def search_assets(filters, match, limit=None, sort=None):
    search_body = {
        'filters': filters,
        'match': match
    }

    path = 'assets/search'
    params = {}
    if sort is not None:
        params['sort'] = sort.split(';')

    return get_list_response(path, method='post', limit=limit, body=search_body, params=params)


def get_assets_command():
    limit = demisto.args().get('limit')
    sort = demisto.args().get('sort')
    assets = get_assets(limit=limit, sort=sort)

    if (assets is None or len(assets) == 0):
        return 'No assets found'

    for asset in assets:
        last_scan = get_last_scan(asset)
        asset['LastScanDate'] = last_scan['date']
        asset['LastScanId'] = last_scan['id']
        site = get_site(asset['id'])
        asset['Site'] = site['name'] if site != '' else ''

    headers = [
        'AssetId',
        'Address',
        'Name',
        'Site',
        'Exploits',
        'Malware',
        'OperatingSystem',
        'Vulnerabilities',
        'RiskScore',
        'Assessed',
        'LastScanDate',
        'LastScanId'
    ]

    outputs = translate_object(assets, [
        {'from': 'id', 'to': 'AssetId'},
        {'from': 'ip', 'to': 'Address'},
        {'from': 'hostName', 'to': 'Name'},
        {'from': 'Site', 'to': 'Site'},
        {'from': 'vulnerabilities.exploits', 'to': 'Exploits'},
        {'from': 'vulnerabilities.malwareKits', 'to': 'Malware'},
        {'from': 'os', 'to': 'OperatingSystem'},
        {'from': 'vulnerabilities.total', 'to': 'Vulnerabilities'},
        {'from': 'riskScore', 'to': 'RiskScore'},
        {'from': 'assessedForVulnerabilities', 'to': 'Assessed'},
        {'from': 'LastScanDate', 'to': 'LastScanDate'},
        {'from': 'LastScanId', 'to': 'LastScanId'}
    ])

    endpoint = map(lambda o: {
        'IP': o['Address'],
        'HostName': o['Name'],
        'OS': o['OperatingSystem']
    }, outputs)

    entry = {
        'Type': entryTypes['note'],
        'Contents': assets,
        'ContentsFormat': formats['json'],
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': tableToMarkdown('Nexpose assets', outputs, headers, removeNull=True),
        'EntryContext': {
            'Nexpose.Asset(val.AssetId==obj.AssetId)': outputs,
            'Endpoint(val.IP==obj.IP)': endpoint
        }
    }

    return entry


def get_assets(limit=None, sort=None):
    params = {}
    if sort is not None:
        params['sort'] = sort.split(';')
    return get_list_response('assets', limit=limit, params=params)


def get_scan_command():
    ids = argToList(str(demisto.args()['id']))

    scans = []
    for id in ids:
        scan = get_scan(id)
        if (scan is None):
            return 'Scan not found'
        scan_entry = get_scan_entry(scan)
        scans.append(scan_entry)

    return scans


def map_scan(scan):
    scan_output = translate_object(scan, [
        {'from': 'id', 'to': 'Id'},
        {'from': 'scanType', 'to': 'ScanType'},
        {'from': 'scanName', 'to': 'ScanName'},
        {'from': 'startedBy', 'to': 'StartedBy'},
        {'from': 'assets', 'to': 'Assets'},
        {'from': 'duration', 'to': 'TotalTime'},
        {'from': 'endTime', 'to': 'Completed'},
        {'from': 'status', 'to': 'Status'},
        {'from': 'message', 'to': 'Message'}
    ])

    if isinstance(scan_output, list):
        for scan in scan_output:
            scan['TotalTime'] = str(iso8601_duration_as_minutes(scan['TotalTime'])) + ' minutes'
    else:
        scan_output['TotalTime'] = str(iso8601_duration_as_minutes(scan_output['TotalTime'])) + ' minutes'

    return scan_output


def get_scan_human_readable(scan_output, title):
    scan_headers = [
        'Id',
        'ScanType',
        'ScanName',
        'StartedBy',
        'Assets',
        'TotalTime',
        'Completed',
        'Status',
        'Message'
    ]

    return tableToMarkdown(title, scan_output, scan_headers, removeNull=True)


def get_scan_entry(scan):
    scan_output = map_scan(scan)

    vuln_headers = [
        'Critical',
        'Severe',
        'Moderate',
        'Total'
    ]

    vuln_output = translate_object(scan['vulnerabilities'], [
        {'from': 'critical', 'to': 'Critical'},
        {'from': 'severe', 'to': 'Severe'},
        {'from': 'moderate', 'to': 'Moderate'},
        {'from': 'total', 'to': 'Total'}
    ])

    scan_hr = get_scan_human_readable(scan_output, 'Nexpose scan ' + str(scan['id']))
    vuln_hr = tableToMarkdown('Vulnerabilities', vuln_output, vuln_headers, removeNull=True)
    hr = scan_hr + vuln_hr

    scan_output['Vulnerabilities'] = vuln_output

    entry = {
        'Type': entryTypes['note'],
        'Contents': scan,
        'ContentsFormat': formats['json'],
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': hr,
        'EntryContext': {
            'Nexpose.Scan(val.Id==obj.Id)': scan_output,
        }
    }

    return entry


def get_scan(scan_id):
    path = 'scans/' + str(scan_id)
    return send_request(path)


def create_site_command():
    assets = argToList(demisto.args()['assets'])
    site = create_site(demisto.args()['name'], assets,
                       demisto.args().get('description'), demisto.args().get('importance'),
                       demisto.args().get('scanTemplateId'))

    if not site or 'id' not in site:
        raise Exception('Site creation failed, could not get the new site')

    output = {
        'Id': site['id']
    }

    md = tableToMarkdown('New site created', output)

    entry = {
        'Type': entryTypes['note'],
        'Contents': site,
        'ContentsFormat': formats['json'],
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': md,
        'EntryContext': {
            'Nexpose.Site(val.Id==obj.Id)': output,
        }
    }

    return entry


def create_site(name, assets, description=None, importance=None, template_id=None):
    site_body = {
        'name': name
    }

    if assets:
        site_body['scan'] = {
            'assets': {
                'includedTargets': {
                    'addresses': assets
                }
            }
        }
    if description:
        site_body['description'] = description
    if importance:
        site_body['importance'] = importance
    if template_id:
        site_body['scanTemplateId'] = template_id

    path = 'sites'

    return send_request(path, 'post', body=site_body)


def delete_site_command():
    site_id = demisto.args()['id']

    res = delete_site(site_id)

    hr = "Site " + str(site_id) + " deleted"

    entry = {
        'Type': entryTypes['note'],
        'Contents': res,
        'ContentsFormat': formats['json'],
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': hr
    }

    return entry


def delete_site(site_id):
    path = 'sites/' + str(site_id)

    return send_request(path, 'delete')


def get_sites_command():
    sites = get_sites(limit=demisto.args().get('limit'), sort=demisto.args().get('sort'))

    if (sites is None or len(sites) == 0):
        return 'No sites found'

    headers = [
        'Id',
        'Name',
        'Assets',
        'Vulnerabilities',
        'Risk',
        'Type',
        'LastScan'
    ]

    outputs = translate_object(sites, [
        {'from': 'id', 'to': 'Id'},
        {'from': 'name', 'to': 'Name'},
        {'from': 'assets', 'to': 'Assets'},
        {'from': 'vulnerabilities.total', 'to': 'Vulnerabilities'},
        {'from': 'riskScore', 'to': 'Risk'},
        {'from': 'type', 'to': 'Type'},
        {'from': 'lastScanTime', 'to': 'LastScan'}
    ])

    entry = {
        'Type': entryTypes['note'],
        'Contents': sites,
        'ContentsFormat': formats['json'],
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': tableToMarkdown('Nexpose sites', outputs, headers, removeNull=True),
        'EntryContext': {
            'Nexpose.Site(val.Id==obj.Id)': outputs,
        }
    }

    return entry


def get_sites(limit=None, sort=None):
    path = 'sites'
    params = {}
    if sort is not None:
        params['sort'] = sort.split(';')
    return get_list_response(path, limit=limit, params=params)


def get_report_templates_command():
    templates = get_report_templates()

    if (templates is None or len(templates) == 0 or 'resources' not in templates):
        return 'No templates found'

    headers = [
        'Id',
        'Name',
        'Description',
        'Type'
    ]

    outputs = translate_object(templates['resources'], [
        {'from': 'id', 'to': 'Id'},
        {'from': 'name', 'to': 'Name'},
        {'from': 'description', 'to': 'Description'},
        {'from': 'type', 'to': 'Type'},
    ])

    entry = {
        'Type': entryTypes['note'],
        'Contents': templates,
        'ContentsFormat': formats['json'],
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': tableToMarkdown('Nexpose templates', outputs, headers, removeNull=True),
        'EntryContext': {
            'Nexpose.Template(val.Id==obj.Id)': outputs,
        }
    }

    return entry


def get_report_templates():
    path = 'report_templates'

    return send_request(path)


def create_assets_report_command():
    assets = str(demisto.args()['assets']).split(',')
    template = demisto.args().get('template')
    name = demisto.args().get('name', 'report ' + str(datetime.now()))
    report_format = demisto.args().get('format', 'pdf')

    scope = {
        'assets': assets
    }

    report_id = create_report(scope, name, template, report_format)

    if report_id is None:
        return 'Could not retrieve report'

    return download_report(report_id, name, report_format)


def create_sites_report_command():
    sites = str(demisto.args()['sites']).split(',')
    template = demisto.args().get('template')
    name = demisto.args().get('name', 'report ' + str(datetime.now()))
    report_format = demisto.args().get('format', 'pdf')

    scope = {
        'sites': sites
    }

    report_id = create_report(scope, name, template, report_format)

    if report_id is None:
        return 'Could not retrieve report'

    return download_report(report_id, name, report_format)


def create_scan_report_command():
    scan = demisto.args()['scan']
    template = demisto.args().get('template')
    name = demisto.args().get('name', 'report ' + str(datetime.now()))
    report_format = demisto.args().get('format', 'pdf')
    scope = {
        'scan': scan
    }

    report_id = create_report(scope, name, template, report_format)

    if report_id is None:
        return 'Could not retrieve report'

    return download_report(report_id, name, report_format)


def create_report(scope, name, template, report_format):
    if template is None:
        templates = get_report_templates()
        if (templates is None or len(templates) == 0 or 'resources' not in templates):
            return 'No templates found'
        template = templates['resources'][0]['id']
    for i, (k, v) in enumerate(scope.items()):
        if not isinstance(v, list):
            scope[k] = int(v)
        else:
            for i, v in enumerate(scope[k]):
                scope[k][i] = int(v)
    path = 'reports'
    body = {
        'scope': scope,
        'template': template,
        'name': name,
        'format': report_format
    }

    result = send_request(path, 'post', body=body)
    return result['id'] if 'id' in result else None


def download_report(report_id, name, report_format):
    # Generate the report
    path = 'reports/' + str(report_id) + ' /generate'
    instance = send_request(path, 'post')
    if (instance is None):
        return 'Failed to generate report'

    headers = {
        'Accept': 'application/json',
        'Accept-Encoding': 'gzip, deflate, br'
    }

    # Wait for the report to be completed
    time.sleep(10)

    # Download
    path = 'reports/' + str(report_id) + '/history/' + str(instance['id']) + '/output'
    report = send_request(path, headers=headers, is_file=True)

    return fileResult(name + '.' + report_format, report, entryTypes['entryInfoFile'])


def start_assets_scan_command():
    ips = demisto.args().get('IPs')
    host_names = demisto.args().get('hostNames')
    name = demisto.args().get('name', 'scan ' + str(datetime.now()))

    text_filters = None
    if ips:
        ips = ips.split(',')
        text_filters = ['ip-address is ' + ips[0]]
    elif host_names:
        host_names = host_names.split(',')
        text_filters = ['host-name is ' + host_names[0]]

    if text_filters is None:
        return 'No IPs or hosts were provided'

    filters = get_search_filters(text_filters)
    asset = search_assets(filters, match='all')

    if asset is None or len(asset) == 0:
        return 'Could not find assets'

    site = get_site(asset[0]['id'])
    if site is None or 'id' not in site:
        return 'Could not find site'

    hosts = []  # type: ignore
    if ips:
        hosts += ips
    if host_names:
        hosts += host_names

    scan_response = start_scan(site['id'], hosts, name)

    if (scan_response is None or 'id' not in scan_response):
        return 'Could not start scan'

    scan = get_scan(scan_response['id'])

    return get_scan_entry(scan)


def start_site_scan_command():
    site = demisto.args()['site']
    name = demisto.args().get('name', 'scan ' + str(datetime.now()))
    hosts = demisto.args().get('hosts', '')

    if not hosts:
        assets = get_site_assets(site)
        hosts = [asset['ip'] for asset in assets]
    else:
        hosts = argToList(hosts)

    scan_response = start_scan(site, hosts, name)

    if (scan_response is None or 'id' not in scan_response):
        return 'Could not start scan'

    scan = get_scan(scan_response['id'])

    return get_scan_entry(scan)


def start_scan(site, hosts, name):
    path = 'sites/' + str(site) + '/scans'
    body = {
        'name': name,
        'hosts': hosts
    }

    return send_request(path, 'post', body=body)


def get_site_assets(site_id):
    path = 'sites/' + site_id + '/assets'

    return get_list_response(path)


def get_scans_command():
    scans = get_scans(demisto.args().get('sort'), demisto.args().get('limit'), demisto.args().get('active'))

    if not scans or len(scans) == 0:
        return 'No scans found'

    scan_output = map_scan(scans)
    scan_hr = get_scan_human_readable(scan_output, 'Nexpose scans')

    entry = {
        'Type': entryTypes['note'],
        'Contents': scans,
        'ContentsFormat': formats['json'],
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': scan_hr,
        'EntryContext': {
            'Nexpose.Scan(val.Id==obj.Id)': scan_output,
        }
    }

    return entry


def get_scans(sort, limit, active):
    path = 'scans'
    params = {}
    if sort is not None:
        params['sort'] = sort.split(';')
    if active is not None:
        params['active'] = active

    return get_list_response(path, method='get', limit=limit, params=params)


def stop_scan_command():
    scan_id = demisto.args()['id']
    res = set_scan_status(scan_id, 'stop')

    entry = {
        'Type': entryTypes['note'],
        'Contents': res,
        'ContentsFormat': formats['json'],
        'ReadableContentsFormat': formats['text'],
        'HumanReadable': 'Succesfully stopped the scan',
    }

    return entry


def pause_scan_command():
    scan_id = demisto.args()['id']
    res = set_scan_status(scan_id, 'pause')

    entry = {
        'Type': entryTypes['note'],
        'Contents': res,
        'ContentsFormat': formats['json'],
        'ReadableContentsFormat': formats['text'],
        'HumanReadable': 'Succesfully paused the scan',
    }

    return entry


def resume_scan_command():
    scan_id = demisto.args()['id']
    res = set_scan_status(scan_id, 'resume')

    entry = {
        'Type': entryTypes['note'],
        'Contents': res,
        'ContentsFormat': formats['json'],
        'ReadableContentsFormat': formats['text'],
        'HumanReadable': 'Succesfully resumed the scan',
    }

    return entry


def set_scan_status(scan_id, scan_status):
    path = 'scans/' + str(scan_id) + '/' + scan_status

    return send_request(path, 'post')


def main():
    try:
        handle_proxy()
        global SESSION
        SESSION = login()
        if demisto.command() == 'test-module':
            get_assets(limit=1)
            demisto.results('ok')
        if demisto.command() == 'nexpose-get-assets':
            demisto.results(get_assets_command())
        if demisto.command() == 'nexpose-get-asset':
            demisto.results(get_asset_command())
        if demisto.command() == 'nexpose-get-asset-vulnerability':
            demisto.results(get_asset_vulnerability_command())
        if demisto.command() == 'nexpose-search-assets':
            demisto.results(search_assets_command())
        if demisto.command() == 'nexpose-get-scan':
            demisto.results(get_scan_command())
        if demisto.command() == 'nexpose-get-sites':
            demisto.results(get_sites_command())
        if demisto.command() == 'nexpose-get-report-templates':
            demisto.results(get_report_templates_command())
        if demisto.command() == 'nexpose-create-assets-report':
            demisto.results(create_assets_report_command())
        if demisto.command() == 'nexpose-create-sites-report':
            demisto.results(create_sites_report_command())
        if demisto.command() == 'nexpose-create-scan-report':
            demisto.results(create_scan_report_command())
        if demisto.command() == 'nexpose-start-site-scan':
            demisto.results(start_site_scan_command())
        if demisto.command() == 'nexpose-start-assets-scan':
            demisto.results(start_assets_scan_command())
        if demisto.command() == 'nexpose-create-site':
            demisto.results(create_site_command())
        if demisto.command() == 'nexpose-delete-site':
            demisto.results(delete_site_command())
        if demisto.command() == 'nexpose-stop-scan':
            demisto.results(stop_scan_command())
        if demisto.command() == 'nexpose-pause-scan':
            demisto.results(pause_scan_command())
        if demisto.command() == 'nexpose-resume-scan':
            demisto.results(resume_scan_command())
        if demisto.command() == 'nexpose-get-scans':
            demisto.results(get_scans_command())
    except Exception as e:
        LOG(e)
        LOG.print_log(False)
        return_error(e.message)


# python2 uses __builtin__ python3 uses builtins
if __name__ == "__builtin__" or __name__ == "builtins":
    main()
