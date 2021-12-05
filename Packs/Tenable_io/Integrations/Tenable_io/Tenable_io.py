import os
import sys
import time
import traceback
from datetime import datetime

import demistomock as demisto  # noqa: F401
import requests
from CommonServerPython import *  # noqa: F401
from requests.exceptions import HTTPError

requests.packages.urllib3.disable_warnings()


FIELD_NAMES_MAP = {
    'ScanType': 'Type',
    'ScanStart': 'StartTime',
    'ScanEnd': 'EndTime',
    'ScannerName': 'Scanner',
    'SeenLast': 'LastSeen',
    'SeenFirst': 'FirstSeen',
    'PluginId': 'Id',
    'Count': 'VulnerabilityOccurences'
}

REMEDIATIONS_NAMES_MAP = {
    'Value': 'Id',
    'Vulns': 'AssociatedVulnerabilities',
    'Hosts': 'AffectedHosts',
    'Remediation': 'Description'
}

ASSET_VULNS_NAMES_MAP = {
    'PluginId': 'Id',
    'PluginFamily': 'Family',
    'PluginName': 'Name',
    'Count': 'VulnerabilityOccurences'
}

GET_SCANS_HEADERS = [
    'FolderId',
    'Id',
    'Name',
    'Targets',
    'Status',
    'StartTime',
    'EndTime',
    'Enabled',
    'Type',
    'Owner',
    'Scanner',
    'Policy',
    'CreationDate',
    'LastModificationDate'
]

LAUNCH_SCAN_HEADERS = [
    'Id',
    'Targets',
    'Status'
]

SCAN_REPORT_INFO_HEADERS = [
    'Id',
    'Name',
    'Targets',
    'Status',
    'StartTime',
    'EndTime',
    'Scanner',
    'Policy'
]

SCAN_REPORT_VULNERABILITIES_HEADERS = [
    'Id',
    'Name',
    'Severity',
    'Description',
    'Synopsis',
    'Solution',
    'FirstSeen',
    'LastSeen',
    'VulnerabilityOccurences'
]

SCAN_REPORT_HOSTS_HEADERS = [
    'Hostname',
    'Score',
    'Severity',
    'Critical',
    'High',
    'Medium',
    'Low'
]

SCAN_REPORT_REMEDIATIONS_HEADERS = [
    'Id',
    'Description',
    'AffectedHosts',
    'AssociatedVulnerabilities'
]

VULNERABILITY_DETAILS_HEADERS = [
    'Name',
    'Severity',
    'Type',
    'Family',
    'Description',
    'Synopsis',
    'Solution',
    'FirstSeen',
    'LastSeen',
    'PublicationDate',
    'ModificationDate',
    'VulnerabilityOccurences',
    'CvssVector',
    'CvssBaseScore',
    'Cvss3Vector',
    'Cvss3BaseScore'
]

ASSET_VULNS_HEADERS = [
    'Id',
    'Name',
    'Severity',
    'Family',
    'VulnerabilityOccurences',
    'VulnerabilityState'
]

severity_to_text = [
    'None',
    'Low',
    'Medium',
    'High',
    'Critical']

BASE_URL = demisto.params()['url']
ACCESS_KEY = demisto.params()['access-key']
SECRET_KEY = demisto.params()['secret-key']
AUTH_HEADERS = {'X-ApiKeys': 'accessKey={}; secretKey={}'.format(ACCESS_KEY, SECRET_KEY)}
NEW_HEADERS = {
    'X-ApiKeys': 'accessKey={}; secretKey={}'.format(ACCESS_KEY, SECRET_KEY),
    'accept': "application/json",
    'content-type': "application/json"
}
USE_SSL = not demisto.params()['unsecure']

if not demisto.params()['proxy']:
    del os.environ['HTTP_PROXY']
    del os.environ['HTTPS_PROXY']
    del os.environ['http_proxy']
    del os.environ['https_proxy']


def flatten(d):
    r = {}  # type: ignore
    for k, v in d.iteritems():
        if isinstance(v, dict):
            r.update(flatten(v))
    d.update(r)
    return d


def filter_dict_null(d):
    if isinstance(d, dict):
        return dict((k, v) for k, v in d.items() if v is not None)
    return d


def filter_dict_keys(d, keys):
    if isinstance(d, list):
        return map(lambda x: filter_dict_keys(x, keys), d)
    if isinstance(d, dict):
        return {k: v for k, v in d.iteritems() if k in keys}
    return d


def convert_severity_values(d):
    if isinstance(d, list):
        return map(convert_severity_values, d)
    if isinstance(d, dict):
        return {k: (severity_to_text[v] if k == 'Severity' else v) for k, v in d.iteritems()}
    return d


def convert_dict_context_dates(d):
    def convert_epoch_to_date(k, v):
        if any(s in k.lower() for s in ('date', 'time')):
            try:
                return datetime.utcfromtimestamp(int(v)).strftime('%Y-%m-%dT%H:%M:%SZ')
            except Exception:
                pass
        return v

    if isinstance(d, list):
        return map(convert_dict_context_dates, d)
    if isinstance(d, dict):
        return {k: convert_dict_context_dates(convert_epoch_to_date(k, v)) for k, v in d.iteritems()}
    return d


def convert_dict_readable_dates(d):
    def convert_epoch_to_date(k, v):
        return formatEpochDate(v) if isinstance(v, int) and any(s in k.lower() for s in ('date', 'time')) else v

    if isinstance(d, list):
        return map(convert_dict_readable_dates, d)
    if isinstance(d, dict):
        return {k: convert_dict_readable_dates(convert_epoch_to_date(k, v)) for k, v in d.iteritems()}
    return d


def get_entry_for_object(title, context_key, obj, headers=None, remove_null=False):
    def intersection(lst1, lst2):
        return [value for value in lst1 if value in lst2]

    if len(obj) == 0:
        return "There is no output result"
    filtered_obj = filter_dict_null(obj)
    if isinstance(filtered_obj, list):
        filtered_obj = map(filter_dict_null, filtered_obj)
    if headers and isinstance(filtered_obj, dict):
        headers = intersection(headers, filtered_obj.keys())

    hr_obj = convert_dict_readable_dates(filtered_obj)
    context_obj = convert_dict_context_dates(filter_dict_keys(filtered_obj, headers) if headers else filtered_obj)

    return {
        'Type': entryTypes['note'],
        'Contents': obj,
        'ContentsFormat': formats['json'],
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': tableToMarkdown(title, hr_obj, headers, removeNull=remove_null),
        'EntryContext': {
            context_key: context_obj
        }
    }


def replace_keys(src, trans_map=FIELD_NAMES_MAP, camelize=True):

    def snake_to_camel(snake_str):
        components = snake_str.split('_')
        return ''.join(map(lambda x: x.decode('utf-8').title(), components))

    def replace(key, trans_map):
        if key in trans_map:
            return trans_map[key]
        return key

    if isinstance(src, list):
        return map(lambda x: replace_keys(x, trans_map, camelize), src)
    if camelize:
        src = {snake_to_camel(k): v for k, v in src.iteritems()}
    if trans_map:
        src = {replace(k, trans_map): v for k, v in src.iteritems()}
    return src


def date_range_to_param(date_range):
    params = {}
    if date_range:
        try:
            date_range = int(date_range)
            params['date_range'] = date_range
        except ValueError:
            return_error("Invalid date range: {}".format(date_range))
    return params


def get_scan_error_message(response, scan_id):
    code = response.status_code
    message = "Error processing request"
    if scan_id:
        message += " for scan with id {}".format(scan_id)
    message += ". Got response status code: {}".format(code)
    if code == 401:
        message += " - Scan is disabled."
    elif code == 403:
        message += " - {}".format(response.json()['error'])
    elif code == 404:
        message += " - Scan does not exist."
    elif code == 409:
        message += " - Scan cannot be launched in its current status."
    return message


# Request/Response methods
# kwargs: request parameters
def send_scan_request(scan_id="", endpoint="", method='GET', ignore_license_error=False, body=None, **kwargs):
    if endpoint:
        endpoint = '/' + endpoint
    full_url = "{0}scans/{1!s}{2}".format(BASE_URL, scan_id, endpoint)
    try:
        res = requests.request(method, full_url, headers=AUTH_HEADERS, verify=USE_SSL, json=body, params=kwargs)
        res.raise_for_status()
        return res.json()
    except HTTPError:
        if ignore_license_error and res.status_code in (403, 500):
            return
        err_msg = get_scan_error_message(res, scan_id)
        if demisto.command() != 'test-module':
            return_error(err_msg)
        else:
            demisto.results(err_msg)
        demisto.error(traceback.format_exc())
        sys.exit(0)
    except ValueError:
        return "No JSON to decode."


def get_scan_info(scans_result_elem):
    response = send_scan_request(scans_result_elem['id'], ignore_license_error=True)
    if response:
        response['info'].update(scans_result_elem)
        return response['info']


def send_vuln_details_request(plugin_id, date_range=None):
    full_url = "{}{}{}/{}".format(BASE_URL, "workbenches/vulnerabilities/", plugin_id, "info")
    res = requests.get(full_url, headers=AUTH_HEADERS, verify=USE_SSL, params=date_range_to_param(date_range))
    return res.json()


def get_vuln_info(vulns):
    vulns_info = {v['plugin_id']: v for v in vulns}
    infos = []
    errors = []
    for pid, info in vulns_info.iteritems():
        vuln_details = send_vuln_details_request(pid)
        if u'error' in vuln_details:
            errors.append(info)
        else:
            info.update(flatten(vuln_details['info']))
            infos.append(info)
    return infos, errors


def send_assets_request(params):
    full_url = "{}{}".format(BASE_URL, "workbenches/assets")
    res = requests.request("GET", full_url, headers=AUTH_HEADERS, params=params, verify=USE_SSL)
    return res.json()


def get_asset_id(params):
    assets = send_assets_request(params)
    if 'error' in assets:
        return_error(assets['error'])
    if assets.get('assets'):
        return assets['assets'][0]['id']
    return None


def send_asset_vuln_request(asset_id, date_range):
    full_url = "{}workbenches/assets/{}/vulnerabilities/".format(BASE_URL, asset_id)
    res = requests.get(full_url, headers=AUTH_HEADERS, verify=USE_SSL, params=date_range_to_param(date_range))
    res.raise_for_status()
    return res.json()


def test_module():
    send_scan_request()
    return 'ok'


def get_scans_command():
    folder_id, last_modification_date = demisto.getArg('folderId'), demisto.getArg('lastModificationDate')
    if last_modification_date:
        last_modification_date = int(time.mktime(datetime.strptime(last_modification_date[0:len('YYYY-MM-DD')],
                                                                   "%Y-%m-%d").timetuple()))
    response = send_scan_request(folder_id=folder_id, last_modification_date=last_modification_date)
    scan_entries = map(get_scan_info, response['scans'])
    valid_scans = filter(lambda x: x is not None, scan_entries)
    invalid_scans = [k for k, v in zip(response['scans'], scan_entries) if v is None]
    res = [get_entry_for_object('Tenable.io - List of Scans', 'TenableIO.Scan(val.Id && val.Id === obj.Id)',
                                replace_keys(valid_scans), GET_SCANS_HEADERS)]
    if invalid_scans:
        res.append(get_entry_for_object('Inactive Web Applications Scans - Renew WAS license to use these scans',
                                        'TenableIO.Scan(val.Id && val.Id === obj.Id)', replace_keys(invalid_scans),
                                        GET_SCANS_HEADERS, remove_null=True))
    return res


def launch_scan_command():
    scan_id, targets = demisto.getArg('scanId'), demisto.getArg('scanTargets')
    scan_info = send_scan_request(scan_id)['info']
    if not targets:
        targets = scan_info.get('targets', '')
    target_list = argToList(targets)
    body = assign_params(alt_targets=target_list)
    res = send_scan_request(scan_id, 'launch', 'POST', body=body)
    res.update({
        'id': scan_id,
        'targets': targets,
        'status': 'pending'
    })

    return get_entry_for_object('The requested scan was launched successfully',
                                'TenableIO.Scan(val.Id && val.Id === obj.Id)', replace_keys(res), LAUNCH_SCAN_HEADERS)


def get_report_command():
    scan_id, info, detailed = demisto.getArg('scanId'), demisto.getArg('info'), demisto.getArg('detailed')
    results = []
    scan_details = send_scan_request(scan_id)
    if info == 'yes':
        scan_details['info']['id'] = scan_id
        scan_details['info'] = replace_keys(scan_details['info'])
        results.append(
            get_entry_for_object('Scan basic info', 'TenableIO.Scan(val.Id && val.Id === obj.Id)', scan_details['info'],
                                 SCAN_REPORT_INFO_HEADERS))

    if 'vulnerabilities' not in scan_details:
        return "No vulnerabilities found."
    vuln_info, vulns_not_found = get_vuln_info(scan_details['vulnerabilities'])
    vuln_info = convert_severity_values(replace_keys(vuln_info))
    results.append(get_entry_for_object('Vulnerabilities', 'TenableIO.Vulnerabilities', vuln_info,
                                        SCAN_REPORT_VULNERABILITIES_HEADERS))
    if len(vulns_not_found) > 0:
        vulns_not_found = replace_keys(vulns_not_found)
        results.append(get_entry_for_object('Vulnerabilities - Missing From Workbench', 'TenableIO.Vulnerabilities',
                                            vulns_not_found, SCAN_REPORT_VULNERABILITIES_HEADERS, True))

    if detailed == 'yes':
        assets = replace_keys(scan_details['hosts'] + scan_details['comphosts'])
        results.append(get_entry_for_object('Assets', 'TenableIO.Assets', assets, SCAN_REPORT_HOSTS_HEADERS))
        if 'remediations' in scan_details and 'remediations' in scan_details['remediations'] and len(
                scan_details['remediations']['remediations']) > 0:
            remediations = replace_keys(scan_details['remediations']['remediations'], REMEDIATIONS_NAMES_MAP)
            results.append(get_entry_for_object('Remediations', 'TenableIO.Remediations', remediations,
                                                SCAN_REPORT_REMEDIATIONS_HEADERS))
    return results


def get_vulnerability_details_command():
    plugin_id, date_range = demisto.getArg('vulnerabilityId'), demisto.getArg('dateRange')
    info = send_vuln_details_request(plugin_id, date_range)
    if 'error' in info:
        return_error(info['error'])
    return get_entry_for_object('Vulnerability details - {}'.format(plugin_id), 'TenableIO.Vulnerabilities',
                                convert_severity_values(replace_keys(flatten(info['info']))),
                                VULNERABILITY_DETAILS_HEADERS)


def args_to_request_params(hostname, ip, date_range):
    if not hostname and not ip:
        return_error("Please provide one of the following arguments: hostname, ip")

    indicator = hostname if hostname else ip

    params = {
        "filter.0.filter": "host.target",
        "filter.0.quality": "eq",
        "filter.0.value": indicator
    }

    if date_range:
        if not date_range.isdigit():
            return_error("Invalid date range: {}".format(date_range))
        else:
            params["date_range"] = date_range

    return params, indicator


def get_vulnerabilities_by_asset_command():
    hostname, ip, date_range = demisto.getArg('hostname'), demisto.getArg('ip'), demisto.getArg('dateRange')
    params, indicator = args_to_request_params(hostname, ip, date_range)

    asset_id = get_asset_id(params)
    if not asset_id:
        return 'No Vulnerabilities for asset {}'.format(indicator)

    info = send_asset_vuln_request(asset_id, date_range)
    if 'error' in info:
        return_error(info['error'])

    vulns = convert_severity_values(replace_keys(info['vulnerabilities'], ASSET_VULNS_NAMES_MAP))
    if vulns:
        entry = get_entry_for_object('Vulnerabilities for asset {}'.format(indicator), 'TenableIO.Vulnerabilities',
                                     vulns, ASSET_VULNS_HEADERS)
        entry['EntryContext']['TenableIO.Assets(val.Hostname === obj.Hostname)'] = {
            'Vulnerabilities': map(lambda x: x['plugin_id'], info['vulnerabilities']),
            'Hostname': indicator
        }
        return entry


def get_scan_status_command():
    scan_id = demisto.getArg('scanId')
    scan_details = send_scan_request(scan_id)
    scan_status = {
        'Id': scan_id,
        'Status': scan_details['info']['status']
    }
    return get_entry_for_object('Scan status for {}'.format(scan_id), 'TenableIO.Scan(val.Id && val.Id === obj.Id)', scan_status)


def pause_scan_command():
    scan_ids = str(demisto.getArg('scanId')).split(",")

    results = []

    for scan_id in scan_ids:
        scan_id = scan_id.strip()

        scan_details = send_scan_request(scan_id)
        scan_status = {
            'Id': scan_id,
            'Status': scan_details['info']['status']
        }

        if scan_status["Status"].lower() == "running":
            send_scan_request(scan_id, "pause", "POST")
            resumed_scan = {
                "Id": scan_id,
                "Status": "Pausing"
            }
            results.append(get_entry_for_object("The requested scan was paused successfully",
                                                'TenableIO.Scan(val.Id && val.Id === obj.Id)',
                                                replace_keys(resumed_scan), ["Id", "Status"]))

        else:
            results.append(
                "Command 'tenable-io-pause-scan' cannot be called while scan status is {} for scanID"
                " {}".format(scan_status["Status"], scan_id))

    return results


def resume_scan_command():
    scan_ids = str(demisto.getArg('scanId')).split(",")

    results = []

    for scan_id in scan_ids:
        scan_id = scan_id.strip()
        scan_details = send_scan_request(scan_id)
        scan_status = {
            'Id': scan_id,
            'Status': scan_details['info']['status']
        }

        if scan_status["Status"].lower() == "paused":
            send_scan_request(scan_id, "resume", "POST")
            resumed_scan = {
                "Id": scan_id,
                "Status": "Resuming"
            }
            results.append(get_entry_for_object("The requested scan was resumed successfully",
                                                'TenableIO.Scan(val.Id && val.Id === obj.Id)',
                                                replace_keys(resumed_scan), ["Id", "Status"]))

        else:
            results.append(
                "Command 'tenable-io-resume-scan' cannot be called while scan status is {} for scanID "
                "{}".format(scan_status["Status"], scan_id))

    return results


if demisto.command() == 'test-module':
    demisto.results(test_module())
elif demisto.command() == 'tenable-io-list-scans':
    demisto.results(get_scans_command())
elif demisto.command() == 'tenable-io-launch-scan':
    demisto.results(launch_scan_command())
elif demisto.command() == 'tenable-io-get-scan-report':
    demisto.results(get_report_command())
elif demisto.command() == 'tenable-io-get-vulnerability-details':
    demisto.results(get_vulnerability_details_command())
elif demisto.command() == 'tenable-io-get-vulnerabilities-by-asset':
    demisto.results(get_vulnerabilities_by_asset_command())
elif demisto.command() == 'tenable-io-get-scan-status':
    demisto.results(get_scan_status_command())
elif demisto.command() == 'tenable-io-pause-scan':
    demisto.results(pause_scan_command())
elif demisto.command() == 'tenable-io-resume-scan':
    demisto.results(resume_scan_command())
