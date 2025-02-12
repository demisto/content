import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
import sys
import time
import traceback
from datetime import datetime
import urllib3
import re

import requests

from requests.exceptions import HTTPError

# Disable insecure warnings
urllib3.disable_warnings()


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
    'Critical'
]


FETCH_COMMAND = {
    'events': 0,
    'assets': 1
}


PARAMS = demisto.params()
BASE_URL = PARAMS['url']
ACCESS_KEY = PARAMS.get('credentials_access_key', {}).get('password') or PARAMS.get('access-key')
SECRET_KEY = PARAMS.get('credentials_secret_key', {}).get('password') or PARAMS.get('secret-key')
USER_AGENT_HEADERS_VALUE = 'Integration/1.0 (PAN; Cortex-XSOAR; Build/2.0)'
AUTH_HEADERS = {'X-ApiKeys': f"accessKey={ACCESS_KEY}; secretKey={SECRET_KEY}"}
HEADERS = AUTH_HEADERS | {
    'accept': "application/json",
    'content-type': "application/json",
    'User-Agent': USER_AGENT_HEADERS_VALUE
}
USE_SSL = not PARAMS['unsecure']
USE_PROXY = PARAMS.get('proxy', False)

if not USE_PROXY:
    del os.environ['HTTP_PROXY']
    del os.environ['HTTPS_PROXY']
    del os.environ['http_proxy']
    del os.environ['https_proxy']

DATE_FORMAT = '%Y-%m-%d'
VENDOR = 'tenable'
PRODUCT = 'io'
CHUNK_SIZE = 5000
ASSETS_NUMBER = 100
MAX_CHUNKS_PER_FETCH = 8
MAX_VULNS_CHUNKS_PER_FETCH = 8
ASSETS_FETCH_FROM = '90 days'
VULNS_FETCH_FROM = '3 days'
MIN_ASSETS_INTERVAL = 60
NOT_FOUND_ERROR = '404'
XSIAM_EVENT_CHUNK_SIZE_LIMIT = 4 * (10 ** 6)    # 4 MB


class Client(BaseClient):

    def list_scan_filters(self):
        return self._http_request(
            'GET', 'filters/scans/reports')

    def get_scan_history(self, scan_id, params) -> dict:
        remove_nulls_from_dictionary(params)
        return self._http_request(
            'GET', f'scans/{scan_id}/history',
            params=params)

    def initiate_export_scan(self, scan_id: str, params: dict, body: dict) -> dict:
        remove_nulls_from_dictionary(params)
        remove_nulls_from_dictionary(body)
        return self._http_request(
            'POST',
            f'scans/{scan_id}/export',
            params=params, json_data=body)

    def check_export_scan_status(self, scan_id: str, file_id: str) -> dict:
        return self._http_request(
            'GET', f'scans/{scan_id}/export/{file_id}/status')

    def download_export_scan(self, scan_id: str, file_id: str, file_format: str) -> dict:
        return fileResult(
            f'scan_{scan_id}_{file_id}.{file_format.lower()}',
            self._http_request(
                'GET', f'scans/{scan_id}/export/{file_id}/download',
                resp_type='content'),
            EntryType.ENTRY_INFO_FILE)

    @staticmethod
    def add_query(query, param_to_add):
        if query:
            return f'{query}&{param_to_add}'
        return f'?{param_to_add}'

    def get_audit_logs_request(self, from_date: str = None, to_date: str = None, actor_id: str = None,
                               target_id: str = None, limit: int = None):
        """

        Args:
            limit: limit number of audit logs to get.
            from_date: date to fetch audit logs from.
            to_date: date which until to fetch audit logs.
            actor_id: fetch audit logs with matching actor id.
            target_id:fetch audit logs with matching target id.

        Returns:
            audit logs fetched from the API.
        """
        query = ''
        if from_date:
            query = self.add_query(query, f'f=date.gt:{from_date}')
        if to_date:
            query = self.add_query(query, f'f=date.lt:{to_date}')
        if actor_id:
            query = self.add_query(query, f'f=actor_id.match:{actor_id}')
        if target_id:
            query = self.add_query(query, f'f=target_id.match:{target_id}')
        if limit:
            query = self.add_query(query, f'limit={limit}')
        else:
            query = self.add_query(query, 'limit=5000')
        res = self._http_request(method='GET', url_suffix=f'/audit-log/v1/events{query}', headers=self._headers)
        return res.get('events', [])

    def get_vuln_export_uuid(self, num_assets: int, last_found: Optional[float]):
        """

        Args:
            num_assets: number of assets used to chunk the vulnerabilities.
            last_found: vulnerabilities that were last found between the specified date (in Unix time) and now.

        Returns: The UUID of the vulnerabilities export job.

        """
        payload: dict[str, Any] = {
            "filters":
                {
                    "last_found": last_found
                },
            "num_assets": num_assets
        }
        demisto.debug(f"my payload is: {payload}")
        res = self._http_request(method='POST', url_suffix='/vulns/export', headers=self._headers, json_data=payload)
        return res.get('export_uuid', '')

    def get_vuln_export_status(self, export_uuid: str):
        """

        Args:
            export_uuid: The UUID of the vulnerabilities export job.

        Returns: The status of the job, and number of chunks available if succeeded.

        """
        res = self._http_request(method='GET', url_suffix=f'/vulns/export/{export_uuid}/status',
                                 headers=self._headers, ok_codes=(200, 404))
        if isinstance(res, dict) and (res.get("status") == 404 or res.get('error')):
            return 'ERROR', []

        return res.get('status'), res.get('chunks_available') or []

    def download_vulnerabilities_chunk(self, export_uuid: str, chunk_id: int):
        """

        Args:
            export_uuid: The UUID of the vulnerabilities export job.
            chunk_id: The ID of the chunk you want to export.

        Returns: Chunk of vulnerabilities from API.

        """

        result = self._http_request(method='GET', url_suffix=f'/vulns/export/{export_uuid}/chunks/{chunk_id}',
                                    headers=self._headers, ok_codes=(200, 404))

        if isinstance(result, dict) and (result.get("status") == 404 or result.get('error')):
            demisto.debug(f"404 error was received, result from api: {result}")
            return NOT_FOUND_ERROR
        return result

    def get_asset_export_uuid(self, fetch_from):
        """

        Args:
            fetch_from: the last asset that was fetched previously.

        Returns: The UUID of the assets export job.

        """
        payload = {
            'chunk_size': CHUNK_SIZE,
            "filters": {
                "updated_at": fetch_from
            }
        }
        demisto.debug(f"my payload is: {payload}")
        res = self._http_request(method='POST', url_suffix='assets/export', json_data=payload,
                                 headers=self._headers)
        return res.get('export_uuid')

    def get_assets_export_status(self, export_uuid):
        """
        Args:
                export_uuid: The UUID of the assets export job.

        Returns: The assets' chunk id.

        """
        res = self._http_request(method='GET', url_suffix=f'assets/export/{export_uuid}/status', headers=self._headers,
                                 ok_codes=(200, 404))
        if isinstance(res, dict) and (res.get("status") == 404 or res.get('error')):
            return 'ERROR', []
        return res.get('status'), res.get('chunks_available')

    def download_assets_chunk(self, export_uuid: str, chunk_id: int):
        """

        Args:
            export_uuid: The UUID of the assets export job.
            chunk_id: The ID of the chunk you want to export.

        Returns: Chunk of assets from API.

        """
        result = self._http_request(method='GET', url_suffix=f'/assets/export/{export_uuid}/chunks/{chunk_id}',
                                    headers=self._headers, ok_codes=(404, 200))
        # export uuid has expired
        if isinstance(result, dict) and (result.get("status") == 404 or result.get('error')):
            demisto.debug(f"404 error was received, result from api: {result}")
            return NOT_FOUND_ERROR
        return result


def flatten(d):
    r = {}  # type: ignore
    for v in d.values():
        if isinstance(v, dict):
            r.update(flatten(v))
    d.update(r)
    return d


def filter_dict_null(d):
    if isinstance(d, dict):
        return {k: v for k, v in d.items() if v is not None}
    return d


def filter_dict_keys(d, keys):
    if isinstance(d, list):
        return [filter_dict_keys(x, keys) for x in d]
    if isinstance(d, dict):
        return {k: v for k, v in d.items() if k in keys}
    return d


def convert_severity_values(d):
    if isinstance(d, list):
        return list(map(convert_severity_values, d))
    if isinstance(d, dict):
        return {k: (severity_to_text[v] if k == 'Severity' else v) for k, v in d.items()}
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
        return list(map(convert_dict_context_dates, d))
    if isinstance(d, dict):
        return {k: convert_dict_context_dates(convert_epoch_to_date(k, v)) for k, v in d.items()}
    return d


def convert_dict_readable_dates(d):
    def convert_epoch_to_date(k, v):
        return formatEpochDate(v) if isinstance(v, int) and any(s in k.lower() for s in ('date', 'time')) else v

    if isinstance(d, list):
        return list(map(convert_dict_readable_dates, d))
    if isinstance(d, dict):
        return {k: convert_dict_readable_dates(convert_epoch_to_date(k, v)) for k, v in d.items()}
    return d


def get_entry_for_object(title, context_key, obj, headers=None, remove_null=False):
    def intersection(lst1, lst2):
        return [value for value in lst1 if value in lst2]

    if len(obj) == 0:
        return "There is no output result"
    filtered_obj = filter_dict_null(obj)
    if isinstance(filtered_obj, list):
        filtered_obj = list(map(filter_dict_null, filtered_obj))
    if headers and isinstance(filtered_obj, dict):
        headers = intersection(headers, list(filtered_obj.keys()))

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
        return ''.join([x.title() for x in components])

    def replace(key, trans_map):
        if key in trans_map:
            return trans_map[key]
        return key

    if isinstance(src, list):
        return [replace_keys(x, trans_map, camelize) for x in src]
    if camelize:
        src = {snake_to_camel(k): v for k, v in src.items()}
    if trans_map:
        src = {replace(k, trans_map): v for k, v in src.items()}
    return src


def date_range_to_param(date_range):
    params = {}
    if date_range:
        try:
            date_range = int(date_range)
            params['date_range'] = date_range
        except ValueError:
            return_error(f"Invalid date range: {date_range}")
    return params


def get_scan_error_message(response, scan_id):
    code = response.status_code
    message = "Error processing request"
    if scan_id:
        message += f" for scan with id {scan_id}"
    message += f". Got response status code: {code}"
    if code == 401:
        message += " - Scan is disabled."
    elif code == 403:
        message += f" - {response.json()['error']}"
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
    full_url = f"{BASE_URL}scans/{scan_id!s}{endpoint}"
    try:
        res = requests.request(method, full_url, headers=AUTH_HEADERS, verify=USE_SSL, json=body, params=kwargs)
        res.raise_for_status()
        return res.json()
    except HTTPError as e:
        demisto.debug(str(e))
        if ignore_license_error and res.status_code in (403, 500):
            return None
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
    return None


def send_vuln_details_request(plugin_id, date_range=None):
    full_url = f"{BASE_URL}workbenches/vulnerabilities/{plugin_id}/info"
    res = requests.get(full_url, headers=AUTH_HEADERS, verify=USE_SSL, params=date_range_to_param(date_range))
    return res.json()


def get_vuln_info(vulns):
    vulns_info = {v['plugin_id']: v for v in vulns}
    infos = []
    errors = []
    for pid, info in vulns_info.items():
        vuln_details = send_vuln_details_request(pid)
        if 'error' in vuln_details:
            errors.append(info)
        else:
            info.update(flatten(vuln_details['info']))
            infos.append(info)
    return infos, errors


def send_assets_request(params):
    full_url = f"{BASE_URL}workbenches/assets"
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
    full_url = f"{BASE_URL}workbenches/assets/{asset_id}/vulnerabilities/"
    res = requests.get(full_url, headers=AUTH_HEADERS, verify=USE_SSL, params=date_range_to_param(date_range))
    res.raise_for_status()
    return res.json()


def send_asset_details_request(asset_id: str) -> Dict[str, Any]:
    """Gets asset details using the '{BASE_URL}workbenches/assets/{asset_id}/info' endpoint.

    Args:
        asset_id (string): id of the asset.

    Returns:
        dict: dict containing information on an asset.
    """
    full_url = f"{BASE_URL}workbenches/assets/{asset_id}/info"
    try:
        res = requests.get(full_url, headers=AUTH_HEADERS, verify=USE_SSL)
        res.raise_for_status()
    except HTTPError as exc:
        return_error(f'Error calling for url {full_url}: error message {exc}')

    return res.json()


def send_asset_attributes_request(asset_id: str) -> Dict[str, Any]:
    """Gets asset attributes using the '{BASE_URL}api/v3/assets/{asset_id}/attributes' endpoint.

    Args:
        asset_id (string): id of the asset.

    Returns:
        dict: dict containing information on an asset.
    """
    full_url = f"{BASE_URL}api/v3/assets/{asset_id}/attributes"
    try:
        res = requests.get(full_url, headers=AUTH_HEADERS, verify=USE_SSL)
        res.raise_for_status()
    except HTTPError as exc:
        return_error(f'Error calling for url {full_url}: error message {exc}')

    return res.json()


def get_timestamp(timestamp):
    return time.mktime(timestamp.timetuple())


def generate_export_uuid(client: Client, last_run):
    """
    Generate a job export uuid in order to fetch vulnerabilities.

    Args:
        client: Client class object.
        first_fetch: time to first fetch from.
        last_run: last run object.
    """
    demisto.info("Getting vulnerabilities export uuid for report.")
    last_found: float = get_timestamp(arg_to_datetime(VULNS_FETCH_FROM))   # type: ignore

    export_uuid = client.get_vuln_export_uuid(num_assets=ASSETS_NUMBER, last_found=last_found)

    demisto.info(f'vulnerabilities export uuid is {export_uuid}')
    last_run.update({'vuln_export_uuid': export_uuid})


def generate_assets_export_uuid(client: Client, assets_last_run):
    """
    Generate a job export uuid in order to fetch assets.

    Args:
        client: Client class object.
        first_fetch: time to first fetch assets from.
        assets_last_run: assets last run object.

    """

    demisto.info("Generating assets export uuid.")
    fetch_from = round(get_timestamp(arg_to_datetime(ASSETS_FETCH_FROM)))

    export_uuid = client.get_asset_export_uuid(fetch_from=fetch_from)
    demisto.debug(f'assets export uuid is {export_uuid}')

    assets_last_run.update({'assets_export_uuid': export_uuid})


def handle_assets_chunks(client: Client, assets_last_run):
    """
    Handle assets chunks stored in the last run object.

    Args:
        client: Client class object.
        assets_last_run: assets last run object.

    """
    demisto.debug("in handle assets chunks")
    stored_chunks = assets_last_run.get('assets_available_chunks', [])
    updated_stored_chunks = stored_chunks.copy()
    export_uuid = assets_last_run.get('assets_export_uuid')
    assets = []
    for chunk_id in stored_chunks[:MAX_CHUNKS_PER_FETCH]:
        result = client.download_assets_chunk(export_uuid=export_uuid, chunk_id=chunk_id)
        if result == NOT_FOUND_ERROR:
            demisto.info("generating new export uuid to start new fetch due to 404 error.")

            export_uuid = client.get_asset_export_uuid(fetch_from=round(get_timestamp(arg_to_datetime(ASSETS_FETCH_FROM))))
            assets_last_run.update({'assets_export_uuid': export_uuid})
            assets_last_run.update({'nextTrigger': '30', "type": FETCH_COMMAND.get('assets')})
            assets_last_run.pop('assets_available_chunks', None)
            demisto.debug(f"after resetting last run sending lastrun: {assets_last_run}")
            return [], assets_last_run
        assets.extend(result)
        updated_stored_chunks.remove(chunk_id)
    if updated_stored_chunks:
        assets_last_run.update({'assets_available_chunks': updated_stored_chunks,
                                'nextTrigger': '30', "type": FETCH_COMMAND.get('assets')})
    else:
        assets_last_run.pop('assets_available_chunks', None)
        assets_last_run.pop('assets_export_uuid', None)
    return assets, assets_last_run


def handle_vulns_chunks(client: Client, assets_last_run):   # pragma: no cover
    """
    Handle vulns chunks stored in the last run object.

    Args:
        client: Client class object.
        assets_last_run: assets last run object.

    """
    demisto.debug("in handle vulns chunks")
    stored_chunks = assets_last_run.get('vulns_available_chunks', [])
    updated_stored_chunks = stored_chunks.copy()
    export_uuid = assets_last_run.get('vuln_export_uuid')
    vulnerabilities = []
    for chunk_id in stored_chunks[:MAX_VULNS_CHUNKS_PER_FETCH]:
        result = client.download_vulnerabilities_chunk(export_uuid=export_uuid, chunk_id=chunk_id)
        if result == NOT_FOUND_ERROR:
            demisto.info("generating new export uuid to start new fetch due to 404 error.")

            export_uuid = client.get_vuln_export_uuid(num_assets=ASSETS_NUMBER,
                                                      last_found=round(get_timestamp(arg_to_datetime(VULNS_FETCH_FROM))))
            assets_last_run.update({'vuln_export_uuid': export_uuid})
            assets_last_run.update({'nextTrigger': '30', "type": FETCH_COMMAND.get('assets')})
            assets_last_run.pop('vulns_available_chunks', None)
            demisto.debug(f"after resetting last run sending lastrun: {assets_last_run}")
            return [], assets_last_run
        vulnerabilities.extend(result)
        updated_stored_chunks.remove(chunk_id)
    for vuln in vulnerabilities:
        vuln['_time'] = vuln.get('received') or vuln.get('indexed')
    if updated_stored_chunks:
        assets_last_run.update({'vulns_available_chunks': updated_stored_chunks,
                                'nextTrigger': '30', "type": FETCH_COMMAND.get('assets')})
    else:
        assets_last_run.pop('vulns_available_chunks', None)
        assets_last_run.pop('vuln_export_uuid', None)
    return vulnerabilities, assets_last_run


def get_asset_export_job_status(client: Client, assets_last_run):
    """
    If job has succeeded (status FINISHED) get all information from all chunks available.
    Args:
        client: Client class object.
        assets_last_run: The last run.

    Returns: All information from all chunks available.

    """
    status, chunks_available = client.get_assets_export_status(export_uuid=assets_last_run.get("assets_export_uuid"))
    demisto.info(f'Assets report status is {status}, and number of available chunks is {chunks_available}')
    if status == 'FINISHED':
        assets_last_run.update({'assets_available_chunks': chunks_available})

    return status


def get_vulnerabilities_export_status(client: Client, assets_last_run):
    """
    If job has succeeded (status FINISHED) get all information from all chunks available.
    Args:
        client: Client class object.
        export_uuid: The UUID of the vulnerabilities export job.

    Returns: All information from all chunks available.

    """
    status, chunks_available = client.get_vuln_export_status(export_uuid=assets_last_run.get("vuln_export_uuid"))
    demisto.info(f'Report status is {status}, and number of available chunks is {chunks_available}')
    if status == 'FINISHED':
        demisto.debug(f"returned {len(chunks_available)} vulns chunks")
        assets_last_run.update({'vulns_available_chunks': chunks_available})

    return status


def test_module(client: Client, params):
    if int(params.get('assetsFetchInterval')) < 60:
        return_error("Assets and vulnerabilities fetch Interval is supposed to be 1 hour minimum.")
    client.list_scan_filters()
    return 'ok'


def relational_date_to_epoch_date_format(date: Optional[str]) -> Optional[int]:
    """ Retrieves date string or relational expression to date YYYY-MM-DD format.
        Example arg is "7 days ago".
        Args:
            date: str - date or relational expression.
        Returns:
            A str in epoch date format or None.
    """
    if date:
        if date.isnumeric():
            return int(date)
        else:
            date_datetime = dateparser.parse(date)  # parser for human readable dates
            if date_datetime:  # dateparser.parse returns datetime representing parsed date if successful, else returns None
                if date := date_datetime.strftime('%Y-%m-%d'):
                    date_int = (int(time.mktime(datetime.strptime(date, "%Y-%m-%d").timetuple())))
                    return date_int
            else:
                raise DemistoException('Tenable.io: Date format is invalid')
    return None


def get_scans_command():
    folder_id = demisto.args().get('folderId'),
    last_modification_date = relational_date_to_epoch_date_format(demisto.getArg('lastModificationDate'))
    response = send_scan_request(folder_id=folder_id, last_modification_date=last_modification_date)
    scan_entries = list(map(get_scan_info, response['scans']))
    valid_scans = [x for x in scan_entries if x is not None]
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
    return get_entry_for_object(f'Vulnerability details - {plugin_id}', 'TenableIO.Vulnerabilities',
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
            return_error(f"Invalid date range: {date_range}")
        else:
            params["date_range"] = date_range

    return params, indicator


def get_asset_details_command() -> CommandResults:
    """
    tenable-io-get-asset-details: Retrieves details for the specified asset to include custom attributes.

    Args:
        None

    Returns:
        CommandResults: A ``CommandResults`` object that is then passed to ``return_results``, that contains asset
        details.
    """
    ip = demisto.getArg('ip')

    if not ip:
        return_error("Please provide an IP address")

    params = {
        "filter.0.filter": "host.target",
        "filter.0.quality": "eq",
        "filter.0.value": ip
    }

    asset_id = get_asset_id(params)
    if not asset_id:
        return CommandResults(readable_output=f'Asset not found: {ip}')

    try:
        info = send_asset_details_request(asset_id)
        attrs = send_asset_attributes_request(asset_id)
        if attrs:
            info["info"]["attributes"] = [
                {attr.get('name', ''): attr.get('value', '')}
                for attr in attrs.get("attributes", [])
            ]

    except DemistoException as e:
        return_error(f'Failed to include custom attributes. {e}')

    readable_output = tableToMarkdown(
        f'Asset Info for {ip}', info["info"], headers=["attributes", "fqdn", "interfaces", "ipv4", "id", "last_seen"])
    return CommandResults(
        readable_output=readable_output,
        raw_response=info["info"],
        outputs_prefix='TenableIO.AssetDetails',
        outputs_key_field='id',
        outputs=info["info"]
    )


def get_vulnerabilities_by_asset_command():
    hostname, ip, date_range = demisto.getArg('hostname'), demisto.getArg('ip'), demisto.getArg('dateRange')
    params, indicator = args_to_request_params(hostname, ip, date_range)

    asset_id = get_asset_id(params)
    if not asset_id:
        return f'No Vulnerabilities for asset {indicator}'

    info = send_asset_vuln_request(asset_id, date_range)
    if 'error' in info:
        return_error(info['error'])

    vulns = convert_severity_values(replace_keys(info['vulnerabilities'], ASSET_VULNS_NAMES_MAP))
    if vulns:
        entry = get_entry_for_object(f'Vulnerabilities for asset {indicator}', 'TenableIO.Vulnerabilities',
                                     vulns, ASSET_VULNS_HEADERS)
        entry['EntryContext']['TenableIO.Assets(val.Hostname === obj.Hostname)'] = {
            'Vulnerabilities': [x['plugin_id'] for x in info['vulnerabilities']],
            'Hostname': indicator
        }
        return entry
    return None


def get_scan_status_command():
    scan_id = demisto.getArg('scanId')
    scan_details = send_scan_request(scan_id)
    scan_status = {
        'Id': scan_id,
        'Status': scan_details['info']['status']
    }
    return get_entry_for_object(f'Scan status for {scan_id}', 'TenableIO.Scan(val.Id && val.Id === obj.Id)',
                                scan_status)


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
                f"Command 'tenable-io-pause-scan' cannot be called while scan status is {scan_status['Status']} for scanID"
                " {scan_id}")

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
                f"Command 'tenable-io-resume-scan' cannot be called while scan status is {scan_status['Status']} for scanID "
                "{scan_id}")

    return results


def export_request(request_params: dict, assets_or_vulns: str) -> dict:
    """Gets the UUID of the assets/vulnerabilities export job.

    Args:
        request_params (dict): The request params.
        assets_or_vulns (string): A string represents part of the endpoint according to the requested (assets or vulnerabilities)

    Returns:
        dict: The UUID of the assets export job or raise DemistoException.
    """
    full_url = f'{BASE_URL}{assets_or_vulns}/export'
    res = requests.post(full_url, headers=HEADERS, verify=USE_SSL, json=request_params)
    if res.status_code != 200:
        raise DemistoException(res.text)
    return res.json()


def export_request_with_export_uuid(export_uuid: str, assets_or_vulns: str) -> dict:
    """Gets status details of the export job.

    Args:
        export_uuid (string): The UUID of the assets/vulnerabilities export job.
        assets_or_vulns (string): A string represents part of the endpoint according to the requested (assets or vulnerabilities)

    Returns:
        dict: Status of the export job or raise DemistoException.
    """
    full_url = f'{BASE_URL}{assets_or_vulns}/export/{export_uuid}/status'
    res = requests.get(full_url, headers=HEADERS, verify=USE_SSL)
    if res.status_code != 200:
        raise DemistoException(res.text)
    return res.json()


def get_chunks_request(export_uuid: str, chunk_id: str, assets_or_vulns: str) -> dict:
    """Gets chunks of assets or vulnerabilities

    Args:
        export_uuid (string): The UUID of the assets/vulnerabilities export job.
        assets_or_vulns (string): A string represents part of the endpoint according to the
                                  requested data (assets or vulnerabilities)
        chunk_id (string): the id of assets/vulnerabilities the chunk requested to export.
    Returns:
        dict: Status of the export job or raise DemistoException.
    """
    full_url = f'{BASE_URL}{assets_or_vulns}/export/{export_uuid}/chunks/{chunk_id}'
    res = requests.get(full_url, headers=HEADERS, verify=USE_SSL)
    if res.status_code != 200:
        raise DemistoException(res.text)
    return res.json()


def get_export_chunks_details(export_uuid_status_response: dict, export_uuid: str, assets_or_vulns: str) -> list[Dict]:
    """Gets All chunks of assets or vulnerabilities export.

    Args:
        export_uuid_status_response (dict): The response with the chunks details.
        export_uuid (string): The UUID of the assets/vulnerabilities export job.
        assets_or_vulns (string): A string represents part of
                                  the endpoint according to the requested data (assets or vulnerabilities)
    Returns:
        dict: Status of the export job.
    """
    chunks_list_id = export_uuid_status_response.get('chunks_available')
    chunks_response_list: list = []
    if chunks_list_id:
        for chunk_id in chunks_list_id:
            chunk_response = get_chunks_request(export_uuid, chunk_id, assets_or_vulns)
            chunks_response_list.extend(chunk_response)
    return chunks_response_list


def export_assets_build_command_result(chunks_details_list: list[dict]) -> CommandResults:
    """Builds command result object from chunks details list

    Args:
        chunks_details_list (list[dict]): a list[dict] of assets details.
    Returns:
        CommandResults: Command Results object with the relevant data.
    """
    headers = ['ASSET ID', 'DNS NAME (FQDN)', 'SYSTEM TYPE', 'OPERATING SYSTEM', 'IPV4 ADDRESS', 'NETWORK',
               'FIRST SEEN', 'LAST SEEN', 'LAST LICENSED SCAN', 'SOURCE', 'TAGS']
    human_readable = []
    for chunk_details in chunks_details_list:
        human_readable_to_append = {}
        if fqdns := chunk_details.get('fqdns'):
            human_readable_to_append['DNS NAME (FQDN)'] = fqdns[0]
        if (tag := chunk_details.get("tags")) and (first_tag := tag[0]):
            human_readable_to_append['TAGS'] = f'{first_tag.get("key")}:{first_tag.get("value")}'
        if (sources := chunk_details.get("sources")) and (first_source := sources[0]):
            human_readable_to_append['SOURCE'] = first_source.get('name')
        if (
            (network_interfaces := chunk_details.get('network_interfaces'))
            and (first_network_interfaces := network_interfaces[0])
        ):
            human_readable_to_append['IPV4 ADDRESS'] = first_network_interfaces.get('ipv4s')
        human_readable_to_append.update(
            {'ASSET ID': chunk_details.get('id'),
             'SYSTEM TYPE': chunk_details.get('system_types'),
             'OPERATING SYSTEM': chunk_details.get('operating_systems'),
             'NETWORK': chunk_details.get('network_name'),
             'FIRST SEEN': chunk_details.get('first_seen'),
             'LAST SEEN': chunk_details.get('last_seen'),
             'LAST LICENSED SCAN': chunk_details.get('last_licensed_scan_date')}
        )
        remove_nulls_from_dictionary(chunk_details)
        human_readable.append(human_readable_to_append)
    return CommandResults(
        outputs_key_field='id',
        outputs_prefix='TenableIO.Asset',
        outputs=chunks_details_list,
        raw_response=chunks_details_list,
        readable_output=tableToMarkdown('Assets', human_readable, headers=headers, removeNull=True)
    )


def request_uuid_export_assets(args: Dict[str, Any]) -> PollResult:
    """
    Gets the UUID of the assets export job.

    Args:
        args (Dict[str, Any]): Arguments passed down by the CLI to provide in the HTTP request.

    Returns:
        PollResult: A result to return to the user which will be set as a CommandResults.
    """
    tag_category = args.get('tagCategory')
    tag_value = args.get('tagValue')
    request_params = remove_empty_elements(
        {
            "chunk_size": arg_to_number(args.get("chunkSize")),
            "include_unlicensed": args.get("isLicensed"),
            "filters": {
                "created_at": relational_date_to_epoch_date_format(
                    args.get("createdAt")
                ),
                "updated_at": relational_date_to_epoch_date_format(args.get("updatedAt")),
                "terminated_at": relational_date_to_epoch_date_format(
                    args.get("terminatedAt")
                ),
                "is_terminated": argToBoolean(args.get("isTerminated")) if args.get("isTerminated") else None,
                "deleted_at": relational_date_to_epoch_date_format(args.get("deletedAt")),
                "is_deleted": argToBoolean(args.get("isDeleted")) if args.get("isDeleted") else None,
                "is_licensed": argToBoolean(args.get("isLicensed")) if args.get("isLicensed") else None,
                "first_scan_time": relational_date_to_epoch_date_format(args.get("firstScanTime")),
                "last_authenticated_scan_time": relational_date_to_epoch_date_format(args.get("lastAuthenticatedScanTime")),
                "last_assessed": relational_date_to_epoch_date_format(args.get("lastAssessed")),
                "servicenow_sysid": argToBoolean(args.get("serviceNowSysId")) if args.get("serviceNowSysId") else None,
                "sources": argToList(args.get("sources")),
                "has_plugin_results": argToBoolean(args.get("hasPluginResults")) if args.get("hasPluginResults") else None,
            },
        })
    if tag_category and tag_value:
        if request_params.get('filters'):
            request_params.get('filters')[f'tag.{tag_category}'] = tag_value
        else:
            request_params['filters'] = {f'tag.{tag_category}': tag_value}

    if (tag_category and not tag_value) or (not tag_category and tag_value):
        raise DemistoException('Please specify tagCategory and tagValue')

    demisto.debug("request params export assets", request_params)
    api_response = export_request(request_params, 'assets')
    export_uuid = api_response.get('export_uuid')
    demisto.debug(f'export_uuid: {export_uuid}')
    status = api_response.get('status')
    return PollResult(
        response=None,
        partial_result=CommandResults(
            outputs_prefix="TenableIO.Asset",
            outputs_key_field="id",
            readable_output="Waiting for export assets to finish...",
        ),
        continue_to_poll=True,
        args_for_next_run={"exportUuid": export_uuid, "status": status, **args},
    )


def build_vpr_score(args: Dict[str, Any]) -> dict:
    """
    Builds the vpr score request body.

    Args:
        args (Dict[str, Any]): Arguments vprScoreOperator, vprScoreRange, vprScoreValue
        passed down by the CLI to provide in the HTTP request.

    Returns:
        dict: vpr score dict.
    """
    if not args.get('vprScoreValue') and args.get('vprScoreOperator'):
        raise DemistoException('Please specify vprScoreValue and vprScoreOperator')
    elif args.get('vprScoreRange') and args.get('vprScoreOperator'):
        raise DemistoException('Please specify only one of vprScoreRange or vprScoreOperator')
    elif args.get('vprScoreValue') and not args.get('vprScoreOperator'):
        raise DemistoException('Please specify vprScoreValue and vprScoreOperator')
    vpr_score_value = args.get('vprScoreValue')
    vpr_score = {}
    if vpr_score_value:
        vpr_score = {'eq': [float(x) for x in argToList(vpr_score_value)] if args.get('vprScoreOperator') == 'equal' else None,
                     'neq': [float(x) for x in argToList(vpr_score_value)]
                     if args.get('vprScoreOperator') == 'not equal' else None,
                     'gt': float(vpr_score_value) if args.get('vprScoreOperator') == 'gt' else None,
                     'lt': float(vpr_score_value) if args.get('vprScoreOperator') == 'lt' else None,
                     'gte': float(vpr_score_value) if args.get('vprScoreOperator') == 'gte' else None,
                     'lte': float(vpr_score_value) if args.get('vprScoreOperator') == 'lte' else None}

    if args.get('vprScoreRange'):
        lower_range_bound, upper_range_bound = validate_range(args.get('vprScoreRange'))
        vpr_score['lte'] = upper_range_bound
        vpr_score['gte'] = lower_range_bound
    return vpr_score


def request_uuid_export_vulnerabilities(args: Dict[str, Any]) -> PollResult:
    """
    Gets the UUID of the vulnerabilities export job.

    Args:
        args (Dict[str, Any]): Arguments passed down by the CLI to provide in the HTTP request.

    Returns:
        PollResult: A result to return to the user which will be set as a CommandResults.
    """
    tag_category = args.get("tagCategory")
    tag_value = args.get("tagValue")
    request_params = remove_empty_elements(
        {
            'num_assets': arg_to_number(args.get('numAssets')),
            'include_unlicensed': argToBoolean(args.get('includeUnlicensed')) if args.get('includeUnlicensed') else None,
            'filters': {
                'cidr_range': args.get('cidrRange'),
                'first_found': relational_date_to_epoch_date_format(args.get('firstFound')),
                'last_fixed': relational_date_to_epoch_date_format(args.get('lastFixed')),
                'last_found': relational_date_to_epoch_date_format(args.get('lastFound')),
                'network_id': args.get('networkId'),
                'plugin_id': [arg_to_number(x) for x in argToList(args.get('pluginId'))],
                'plugin_type': args.get('pluginType'),
                'severity': argToList(args.get('severity')),
                'since': relational_date_to_epoch_date_format(args.get('since')),
                'state': argToList(args.get('state')),
                'vpr_score': build_vpr_score(args),
            }
        }
    )
    if tag_category and tag_value:
        if request_params.get('filters'):
            request_params.get('filters')[f'tag.{tag_category}'] = tag_value
        else:
            request_params['filters'] = {f'tag.{tag_category}': tag_value}

    if (tag_category and not tag_value) or (not tag_category and tag_value):
        raise DemistoException('Please specify tagCategory and tagValue')

    demisto.debug("request params export vulnerabilities", request_params)
    api_response = export_request(request_params, 'vulns')
    export_uuid = api_response.get('export_uuid')
    demisto.debug(f'export_uuid: {export_uuid}')
    return PollResult(
        response=None,
        partial_result=CommandResults(
            outputs_prefix="TenableIO.Vulnerability",
            readable_output="Waiting for export vulnerabilities to finish...",
        ),
        continue_to_poll=True,
        args_for_next_run={"exportUuid": export_uuid, **args},
    )


@polling_function(name=demisto.command(), timeout=arg_to_number(demisto.args().get('timeout', 720)),
                  interval=arg_to_number(demisto.args().get('intervalInSeconds', 15)),
                  requires_polling_arg=False)
def export_assets_command(args: Dict[str, Any]) -> PollResult:
    """
    Polling command to export_assets.
    After the first run, progress will be shown through the status QUEUED, PROCESSING, CANCELED, ERROR and FINISHED.
    Export assets command will run till its status is 'FINISHED'.

    Args:
        args (Dict[str, Any]): Arguments passed down by the CLI to provide in the HTTP request.

    Returns:
        PollResult: A result to return to the user which will be set as a CommandResults.
            The result itself will depend on the stage of polling.
    """
    export_uuid = demisto.args().get('exportUuid')
    if export_uuid:
        demisto.debug(f'export_uuid: {export_uuid}')
        export_uuid_status_response = export_request_with_export_uuid(export_uuid, 'assets')
        status = export_uuid_status_response.get('status')
        if status == 'FINISHED':
            chunks_details_list = get_export_chunks_details(export_uuid_status_response, export_uuid, 'assets')
            command_results = export_assets_build_command_result(chunks_details_list)
            return PollResult(command_results)
        elif status in ('PROCESSING', 'QUEUED'):
            return PollResult(
                response=None,
                partial_result=CommandResults(
                    outputs_prefix="TenableIO.Asset",
                    outputs_key_field="id",
                    readable_output="Waiting for export assets to finish...",
                ),
                continue_to_poll=True,
                args_for_next_run={"exportUuid": export_uuid, "status": status, **args},
            )
        else:
            return PollResult(
                response=CommandResults(
                    outputs_key_field='id',
                    outputs_prefix='TenableIO.Asset',
                    readable_output=f'TenableIO: {status}',
                ),
                continue_to_poll=False,
            )
    else:
        return request_uuid_export_assets(args)


def export_vulnerabilities_build_command_result(chunks_details_list: list[dict]) -> CommandResults:
    """Builds command result object from chunks details list

    Args:
        chunks_details_list (list[dict]): a list[dict] of assets details.
    Returns:
        CommandResults: Command Results object with the relevant data.
    """
    headers = ['ASSET ID', 'ASSET NAME', 'IPV4 ADDRESS', 'OPERATING SYSTEM', 'SYSTEM TYPE', 'DNS NAME (FQDN)',
               'SEVERITY', 'PLUGIN ID', 'PLUGIN NAME', 'VULNERABILITY PRIORITY RATING', 'CVSSV2 BASE SCORE'
               'CVE', 'PROTOCOL', 'PORT', 'FIRST SEEN', 'LAST SEEN', 'DESCRIPTION', 'SOLUTION']
    human_readable = []
    for chunk_details in chunks_details_list:
        asset_details = chunk_details.get('asset')
        plugin_details = chunk_details.get('plugin')
        port_details = chunk_details.get('port')
        human_readable_to_append = {}
        if asset_details:
            human_readable_to_append.update(
                {'ASSET ID': asset_details.get('uuid'),
                 'ASSET NAME': asset_details.get('hostname'),
                 'IPV4 ADDRESS': asset_details.get('ipv4'),
                 'OPERATING SYSTEM': asset_details.get('operating_system'),
                 'SYSTEM TYPE': asset_details.get('device_type'),
                 'DNS NAME (FQDN)': asset_details.get('fqdn')}
            )
        if plugin_details:
            human_readable_to_append.update(
                {'PLUGIN ID': plugin_details.get('id'),
                 'PLUGIN NAME': plugin_details.get('name'),
                 'VULNERABILITY PRIORITY RATING': plugin_details.get("vpr").get("score") if plugin_details.get("vpr") else None,
                 'CVSSV2 BASE SCORE': plugin_details.get('cvss_base_score'),
                 'CVE': plugin_details.get('cve'),
                 'DESCRIPTION': plugin_details.get('description'),
                 'SOLUTION': plugin_details.get('solution')}
            )
        if port_details:
            human_readable_to_append.update(
                {'PORT': port_details.get('port'),
                 'PROTOCOL': port_details.get('protocol')}
            )
        human_readable_to_append.update(
            {'SEVERITY': chunk_details.get('severity'),
             'FIRST SEEN': chunk_details.get('first_found'),
             'LAST SEEN': chunk_details.get('last_found')}
        )

        remove_nulls_from_dictionary(chunk_details)
        human_readable.append(human_readable_to_append)
    return CommandResults(
        outputs_prefix='TenableIO.Vulnerability',
        outputs=chunks_details_list,
        raw_response=chunks_details_list,
        readable_output=tableToMarkdown('Vulnerabilities', human_readable, headers=headers, removeNull=True)
    )


def validate_range(range: Optional[str]) -> tuple[Optional[float], Optional[float]]:
    """
    Validates the vprScoreRange argument for export asset command
    Args:
        range (str): A str represents a range for example 3-5.
    Returns:
        Range if valid else raise DemistoException.
    """
    if range:
        nums = tuple(map(float, range.split("-")))
        if len(nums) != 2 or not 0.1 <= nums[0] <= nums[1] <= 10.0:
            raise DemistoException('Please specify a valid vprScoreRange. The VPR values range is 0.1-10.0.')
        return nums  # type: ignore
    return None, None


@polling_function(name=demisto.command(), timeout=arg_to_number(demisto.args().get('timeout', 600)),
                  interval=arg_to_number(demisto.args().get('intervalInSeconds', 10)),
                  requires_polling_arg=False)
def export_vulnerabilities_command(args: Dict[str, Any]) -> PollResult:
    """
    Polling command to export vulnerabilities.
    After the first run, progress will be shown through the status QUEUED, PROCESSING, CANCELED, ERROR and FINISHED.
    Export vulnerabilities command will run till its status is 'FINISHED' and all the data chunks are exoprted.

    Args:
        args (Dict[str, Any]): Arguments passed down by the CLI to provide in the HTTP request.

    Returns:
        PollResult: A result to return to the user which will be set as a CommandResults.
            The result itself will depend on the stage of polling.
    """
    export_uuid = demisto.args().get('exportUuid')
    if export_uuid:
        demisto.debug(f'export_uuid: {export_uuid}')
        export_uuid_status_response = export_request_with_export_uuid(export_uuid, 'vulns')
        status = export_uuid_status_response.get('status')
        if status == 'FINISHED':
            chunks_details_list = get_export_chunks_details(export_uuid_status_response, export_uuid, 'vulns')
            command_results = export_vulnerabilities_build_command_result(chunks_details_list)
            return PollResult(command_results)
        elif status in ('PROCESSING', 'QUEUED'):
            return PollResult(
                response=None,
                partial_result=CommandResults(
                    outputs_prefix="TenableIO.Vulnerability",
                    readable_output="Waiting for export vulnerabilities to finish...",
                ),
                continue_to_poll=True,
                args_for_next_run={"exportUuid": export_uuid, "status": status, **args},
            )
        else:
            return PollResult(
                response=CommandResults(
                    outputs_prefix='TenableIO.Vulnerability',
                    readable_output=f'TenableIO: {status}',
                ),
                continue_to_poll=False,
            )
    else:
        return request_uuid_export_vulnerabilities(args)


def scan_filters_human_readable(filters: list) -> str:
    context_to_hr = {
        'name': 'Filter name',
        'readable_name': 'Filter Readable name',
        'type': 'Filter Control type',
        'regex': 'Filter regex',
        'readable_regex': 'Readable regex',
        'operators': 'Filter operators',
        'group_name': 'Filter group name',
    }
    return tableToMarkdown(
        'Tenable IO Scan Filters',
        [d | d.get('control', {}) for d in filters],
        headers=list(context_to_hr),
        headerTransform=context_to_hr.get,
        removeNull=True)


def list_scan_filters_command(client: Client) -> CommandResults:

    response_dict = client.list_scan_filters()
    filters = response_dict.get('filters', [])

    return CommandResults(
        outputs_prefix='TenableIO.ScanFilter',
        outputs_key_field='name',
        outputs=filters,
        readable_output=scan_filters_human_readable(filters),
        raw_response=response_dict)


def scan_history_readable(history: list) -> str:
    context_to_hr = {
        'id': 'History id',
        'scan_uuid': 'History uuid',
        'status': 'Status',
        'is_archived': 'Is archived',
        'custom': 'Targets custom',
        'default': 'Targets default',
        'visibility': 'Visibility',
        'time_start': 'Time start',
        'time_end': 'Time end',
    }
    return tableToMarkdown(
        'Tenable IO Scan History',
        [d | d.get('targets', {}) for d in history],
        headers=list(context_to_hr),
        headerTransform=context_to_hr.get,
        removeNull=True)


def scan_history_pagination_params(args: dict) -> dict:
    '''
    Generate pagination parameters for scanning history based on the given arguments.

    This function calculates the 'limit' and 'offset' parameters for pagination
    based on the provided 'page' and 'pageSize' arguments. If 'page' and 'pageSize'
    are valid integer values, the function returns a dictionary containing 'limit'
    and 'offset' calculated accordingly. If 'page' or 'pageSize' are not valid integers,
    the function falls back to using the 'limit' argument or defaults to 50 with an
    'offset' of 0.

    Args:
        args (dict): The demisto.args() dictionary containing the optional arguments for pagination: 'page', 'pageSize', 'limit'.

    Returns:
        dict: A dictionary containing the calculated 'limit' and 'offset' parameters
              for pagination.
    '''
    page = arg_to_number(args.get('page'))
    page_size = arg_to_number(args.get('pageSize'))
    if isinstance(page, int) and isinstance(page_size, int):
        return {
            'limit': page_size,
            'offset': (page - 1) * page_size
        }

    else:
        return {
            'limit': args.get('limit', 50),
            'offset': 0
        }


def scan_history_params(args: dict) -> dict:
    sort_fields = argToList(args.get('sortFields'))
    sort_order = argToList(args.get('sortOrder'))

    if len(sort_order) == 1:
        sort_order *= len(sort_fields)

    return {
        'sort': ','.join(
            f'{field}:{order}'
            for field, order
            in zip(sort_fields, sort_order)),
        'exclude_rollover': args['excludeRollover'],
    } | scan_history_pagination_params(args)


def get_scan_history_command(args: dict[str, Any], client: Client) -> CommandResults:

    response_json = client.get_scan_history(
        args['scanId'],
        scan_history_params(args))
    history = response_json.get('history', '')

    return CommandResults(
        outputs_prefix='TenableIO.ScanHistory',
        outputs_key_field='id',
        outputs=history,
        readable_output=scan_history_readable(history))


def build_filters(filters) -> dict:
    """
    Build a dictionary of filter information from a filters string.

    Args:
        filters (str, optional): A string containing filters in the format "name quality value" separated by commas.
                                 Escaped commas (\\,) and spaces (\\s) are treated as literal characters.
                                 Defaults to None.

    Returns:
        dict: A dictionary where keys are in the format 'filter.i.filter', 'filter.i.quality', and 'filter.i.value',
              and values correspond to the name, quality, and value of each filter component.

    Example:
        filters = "name1 good value1\\,with\\,commas, name2\\swith\\sspaces excellent value2"
        result = build_filters(filters)
        # Output:
        # {
        #     'filter.0.filter': 'name1',
        #     'filter.0.quality': 'good',
        #     'filter.0.value': 'value1,with,commas',
        #     'filter.1.filter': 'name2 with spaces',
        #     'filter.1.quality': 'excellent',
        #     'filter.1.value': 'value2'
        # }
    """
    if not filters:
        return {}

    # split by comma without escaped commas
    split_filters = re.split(r'(?<!\\),', filters)
    # remove delimiters and split into name, quality and value
    filters = (f.replace('\\,', ',').split() for f in split_filters)

    result: dict = {}
    for i, (name, quality, value) in enumerate(filters):
        result |= {
            f'filter.{i}.filter': re.sub(r'(?<!\\)\\s', ' ', name),
            f'filter.{i}.quality': re.sub(r'(?<!\\)\\s', ' ', quality),
            f'filter.{i}.value': re.sub(r'(?<!\\)\\s', ' ', value)
        }

    return result


def export_scan_body(args: dict) -> dict:

    if chapters := args.get('chapters'):
        chapters = ';'.join(argToList(chapters))
    elif args['format'] in ('PDF', 'HTML'):
        raise DemistoException('The "chapters" field must be provided for PDF or HTML formats.')

    body = {
        'format': args['format'].lower(),
        'chapters': chapters,
        'filter.search_type': args['filterSearchType'].lower(),
        'asset_id': args.get('assetId'),
    } | build_filters(args.get('filter'))

    return body


def initiate_export_scan(args: dict, client: Client) -> str:
    return client.initiate_export_scan(
        args['scanId'],
        params={
            'history_id': args.get('historyId'),
            'history_uuid': args.get('historyUuid')
        },
        body=export_scan_body(args)
    ).get('file', '')


@polling_function(
    'tenable-io-export-scan',
    poll_message='Preparing scan report:',
    interval=15,
    requires_polling_arg=False)
def export_scan_command(args: dict[str, Any], client: Client) -> PollResult:
    '''
    Calls three endpoints. The first (called with initiate_export_scan) initiates an export and returns a file ID.
    The second (called with client.check_export_scan_status) checks the status of the export and the function polls
    until the status is 'ready'. The third endpoint is then called (with client.download_export_scan) which downloads
    the file and returns a dict with it's contents (using fileResult).
    '''

    scan_id = args['scanId']
    file_id = (
        args.get('fileId')
        or initiate_export_scan(args, client))
    demisto.debug(f'{file_id=}')

    status_response = client.check_export_scan_status(scan_id, file_id)
    demisto.debug(f'{status_response=}')

    match status_response.get('status'):
        case 'ready':
            return PollResult(
                client.download_export_scan(
                    scan_id, file_id, args['format']),
                continue_to_poll=False)

        case 'loading':
            return PollResult(
                None,
                continue_to_poll=True,
                args_for_next_run={
                    'fileId': file_id,
                    'scanId': scan_id,
                    'format': args['format'],  # not necessary but avoids confusion
                })

        case _:
            raise DemistoException(
                'Tenable IO encountered an error while exporting the scan report file.\n'
                f'Scan ID: {scan_id}\n'
                f'File ID: {file_id}\n')


def get_audit_logs_command(client: Client, from_date: Optional[str] = None, to_date: Optional[str] = None,
                           actor_id: Optional[str] = None, target_id: Optional[str] = None,
                           limit: Optional[int] = None):
    """

    Args:
        client: Client class object.
        from_date: date to fetch audit logs from.
        to_date: date which until to fetch audit logs.
        actor_id: fetch audit logs with matching actor id.
        target_id:fetch audit logs with matching target id.
        limit: limit number of audit logs to get.

    Returns: CommandResults of audit logs from API.

    """
    audit_logs = client.get_audit_logs_request(from_date=from_date,
                                               to_date=to_date,
                                               actor_id=actor_id,
                                               target_id=target_id,
                                               limit=limit)

    readable_output = tableToMarkdown('Audit Logs List:', audit_logs,
                                      removeNull=True,
                                      headerTransform=string_to_table_header)

    results = CommandResults(readable_output=readable_output,
                             raw_response=audit_logs)
    return results, audit_logs


''' FETCH COMMANDS '''


def set_index_audit_logs(dt_now: datetime, dt_start_date: datetime, audit_logs: List[dict], last_index_fetched: int) -> int:
    """
    This function set the new index_audit_logs by the following logic:
        1. if dt_now > dt_start_date that means we're starting a new day (the fetch is per day, so we need to restart the index).
        2. same day with new audit_logs - adding the amount of the new events to the exists index.
        3. same day without new audit_logs - leave the index as the same.
    Args:
        dt_now: the current datetime
        dt_start_date: the start day to fetch in the current cycle
        audit_logs: the audit logs are retrieved in this cycle of fetch
        last_index_fetched: the last index from the previous cycle

    Returns:
        The new last index fetched
    """
    if dt_now > dt_start_date:
        return 0
    elif audit_logs:
        return len(audit_logs) + last_index_fetched
    else:
        return last_index_fetched


def fetch_events_command(client: Client, first_fetch: datetime, last_run: dict, limit: int = 1000):
    """
    Fetches audit logs.
    Args:
        client: Client class object.
        first_fetch: time to first fetch from.
        last_run: last run object.
        limit: number of audit logs to max fetch.

    Returns: vulnerabilities, audit logs and updated last run object

    """

    last_fetch = last_run.get('last_fetch_time')
    last_index_fetched = last_run.get('index_audit_logs', 0)
    if not last_fetch:
        start_date = first_fetch.strftime(DATE_FORMAT)
    else:
        start_date = last_fetch  # type: ignore

    audit_logs: List[dict] = []
    audit_logs_from_api = client.get_audit_logs_request(from_date=start_date)
    demisto.debug(f"got {len(audit_logs_from_api)} events from api")

    if last_index_fetched < len(audit_logs_from_api):
        audit_logs.extend(audit_logs_from_api[last_index_fetched:last_index_fetched + limit])

    for audit_log in audit_logs:
        audit_log['_time'] = audit_log.get('received') or audit_log.get('indexed')

    # creating date now as a string and as a datetime object for comparing
    date_now_as_str = datetime.utcnow().date().strftime(DATE_FORMAT)
    date_now_as_dt = datetime.strptime(date_now_as_str, DATE_FORMAT)

    start_date_as_dt = datetime.strptime(start_date, DATE_FORMAT)  # convert back the start_date to datetime object for comparing
    demisto.debug(f"Tenable_io - {date_now_as_str=}, {start_date=}, {len(audit_logs)}, {last_index_fetched=}")
    index_audit_logs = set_index_audit_logs(date_now_as_dt, start_date_as_dt, audit_logs, last_index_fetched)
    demisto.debug(f"Tenable_io - {index_audit_logs=}")

    last_run.update({'index_audit_logs': index_audit_logs,
                     'last_fetch_time': date_now_as_str})
    demisto.info(f'Done fetching {len(audit_logs)} audit logs, Setting {last_run=}.')
    return audit_logs, last_run


def fetch_assets_command(client: Client, assets_last_run):     # pragma: no cover
    """
    Fetches assets.
    Args:
        assets_last_run: last run object.
        client: Client class object.

    Returns:
        assets fetched from the API.
    """
    assets = []
    # if already in assets_last_run meaning its still polling chunks from api
    export_uuid = assets_last_run.get('assets_export_uuid')
    # if exists, still downloading chunks from prev fetch call
    available_chunks = assets_last_run.get('assets_available_chunks', [])
    if available_chunks:
        assets, assets_last_run = handle_assets_chunks(client, assets_last_run)
    elif export_uuid:
        status = get_asset_export_job_status(client=client, assets_last_run=assets_last_run)

        if status in ['PROCESSING', 'QUEUED']:
            assets_last_run.update({'nextTrigger': '30', "type": FETCH_COMMAND.get('assets')})
        # set params for next run
        if status == 'FINISHED':
            assets, assets_last_run = handle_assets_chunks(client, assets_last_run)
        elif status in ['CANCELLED', 'ERROR']:
            export_uuid = client.get_asset_export_uuid(fetch_from=round(get_timestamp(arg_to_datetime(ASSETS_FETCH_FROM))))
            assets_last_run.update({'assets_export_uuid': export_uuid})
            assets_last_run.update({'nextTrigger': '30', "type": FETCH_COMMAND.get('assets')})

    demisto.info(f'Done fetching {len(assets)} assets, {assets_last_run=}.')
    return assets


def run_assets_fetch(client, last_run):     # pragma: no cover

    demisto.info("fetch assets from the API")
    # starting new fetch for assets, not polling from prev call
    if not last_run.get('assets_export_uuid'):
        generate_assets_export_uuid(client, last_run)

    return fetch_assets_command(client, last_run)


def fetch_vulnerabilities(client: Client, assets_last_run: dict):     # pragma: no cover
    """
    Fetches vulnerabilities if job has succeeded.
    Args:
        last_run: last run object.
        client: Client class object.

    Returns:
        Vulnerabilities fetched from the API.
    """
    vulnerabilities = []
    # if already in assets_last_run meaning its still polling chunks from api
    export_uuid = assets_last_run.get('vuln_export_uuid')
    # if exists, still downloading chunks from prev fetch call
    available_chunks = assets_last_run.get('vulns_available_chunks', [])
    if available_chunks:
        vulnerabilities, assets_last_run = handle_vulns_chunks(client, assets_last_run)
    elif export_uuid:
        status = get_vulnerabilities_export_status(client=client, assets_last_run=assets_last_run)

        if status in ['PROCESSING', 'QUEUED']:
            assets_last_run.update({'nextTrigger': '30', "type": FETCH_COMMAND.get('assets')})
        # set params for next run
        if status == 'FINISHED':
            vulnerabilities, assets_last_run = handle_vulns_chunks(client, assets_last_run)
        elif status in ['CANCELLED', 'ERROR']:
            export_uuid = client.get_vuln_export_uuid(num_assets=ASSETS_NUMBER,
                                                      last_found=get_timestamp(arg_to_datetime(VULNS_FETCH_FROM)))
            assets_last_run.update({'vuln_export_uuid': export_uuid})
            assets_last_run.update({'nextTrigger': '30', "type": FETCH_COMMAND.get('assets')})

    demisto.info(f'Done fetching {len(vulnerabilities)} vulnerabilities, {assets_last_run=}.')
    return vulnerabilities


def run_vulnerabilities_fetch(client, last_run):

    demisto.info("fetch vulnerabilies from the API")
    if not last_run.get('vuln_export_uuid'):
        generate_export_uuid(client, last_run)

    return fetch_vulnerabilities(client, last_run)


def skip_fetch_assets(last_run):     # pragma: no cover
    time_to_check = last_run.get("assets_last_fetch")
    if not time_to_check:
        return False
    passed_time = (time.time() - time_to_check) / 60
    to_skip = not (last_run.get('vuln_export_uuid') or last_run.get('assets_export_uuid')) and (passed_time < MIN_ASSETS_INTERVAL)
    if to_skip:
        demisto.info(f"Skipping fetch-assets command. Only {passed_time} minutes have passed since the last fetch. "
                     f"It should be a minimum of 1 hour.")
    return to_skip


def parse_vulnerabilities(vulns):

    demisto.debug("Parse the vulnerabilities...")
    if not isinstance(vulns, list):
        demisto.debug(f"result is of type: {type(vulns)}")
        vulns = list(vulns)
    for vuln in vulns:
        vuln_str = json.dumps(vuln)
        if sys.getsizeof(vuln_str) > XSIAM_EVENT_CHUNK_SIZE_LIMIT:
            demisto.debug(f"found object with size: {sys.getsizeof(sys.getsizeof(vuln_str))}")
            if vuln.get('output'):
                demisto.debug("replacing output key")
                vuln['output'] = ""
                vuln['isTruncated'] = True
            else:
                demisto.debug("skipping object...")
                continue
        else:
            vuln['isTruncated'] = False
    return vulns


def main():    # pragma: no cover
    """main function, parses params and runs command functions
    """
    args = demisto.args()
    command = demisto.command()
    params = demisto.params()

    access_key = params.get('credentials_access_key', {}).get('password') or params.get('access-key')
    secret_key = params.get('credentials_secret_key', {}).get('password') or params.get('secret-key')
    url = params.get('url')
    verify_certificate = not params.get('unsecure', False)
    proxy = params.get('proxy', False)

    # Events Params
    max_fetch = arg_to_number(params.get('max_fetch')) or 1000
    first_fetch: datetime = arg_to_datetime(params.get('first_fetch', '3 days'))  # type: ignore

    demisto.debug(f'Command being called is {command}')
    try:
        headers = {'X-ApiKeys': f'accessKey={access_key}; secretKey={secret_key}',
                   "Accept": "application/json"}
        client = Client(
            base_url=url,
            verify=verify_certificate,
            headers=headers,
            proxy=proxy)

        if command == 'test-module':
            demisto.results(test_module(client, params))
        elif command == 'tenable-io-list-scans':
            demisto.results(get_scans_command())
        elif command == 'tenable-io-launch-scan':
            demisto.results(launch_scan_command())
        elif command == 'tenable-io-get-scan-report':
            demisto.results(get_report_command())
        elif command == 'tenable-io-get-vulnerability-details':
            demisto.results(get_vulnerability_details_command())
        elif command == 'tenable-io-get-vulnerabilities-by-asset':
            demisto.results(get_vulnerabilities_by_asset_command())
        elif command == 'tenable-io-get-scan-status':
            demisto.results(get_scan_status_command())
        elif command == 'tenable-io-pause-scan':
            demisto.results(pause_scan_command())
        elif command == 'tenable-io-resume-scan':
            demisto.results(resume_scan_command())
        elif command == 'tenable-io-get-asset-details':
            return_results(get_asset_details_command())
        elif command == 'tenable-io-export-assets':
            return_results(export_assets_command(args))
        elif command == 'tenable-io-export-vulnerabilities':
            vulnerabilities: list = []
            results = export_vulnerabilities_command(args)
            if isinstance(results, CommandResults) and results.raw_response:
                vulnerabilities = results.raw_response  # type: ignore
            return_results(results)
            if argToBoolean(args.get('should_push_events', 'false')) and is_xsiam():
                send_data_to_xsiam(vulnerabilities, product=f'{PRODUCT}_vulnerabilities', vendor=VENDOR)

        elif command == 'tenable-io-list-scan-filters':
            return_results(list_scan_filters_command(client))
        elif command == 'tenable-io-get-scan-history':
            return_results(get_scan_history_command(args, client))
        elif command == 'tenable-io-export-scan':
            return_results(export_scan_command(args, client))
        elif command == 'tenable-io-get-audit-logs':
            results, events = get_audit_logs_command(client,
                                                     from_date=args.get('from_date'),
                                                     to_date=args.get('to_date'),
                                                     actor_id=args.get('actor_id'),
                                                     target_id=args.get('target_id'),
                                                     limit=args.get('limit'))
            return_results(results)

            if argToBoolean(args.get('should_push_events', 'false')) and is_xsiam():
                send_data_to_xsiam(events, vendor=VENDOR, product=PRODUCT)
        elif command == 'fetch-events':

            last_run = demisto.getLastRun()
            demisto.debug(f"saved lastrun events: {last_run}")
            events, new_last_run = fetch_events_command(client, first_fetch, last_run, max_fetch)
            send_data_to_xsiam(events, vendor=VENDOR, product=PRODUCT)
            demisto.debug(f"new lastrun events: {last_run}")
            demisto.setLastRun(new_last_run)

        elif command == 'fetch-assets':
            assets = []
            vulnerabilities = []
            assets_last_run = demisto.getAssetsLastRun()
            demisto.debug(f"saved lastrun assets: {assets_last_run}")
            assets_last_run_copy = assets_last_run.copy()
            if skip_fetch_assets(assets_last_run):
                return
            elif not (assets_last_run.get('vuln_export_uuid') or assets_last_run.get('assets_export_uuid')):
                # starting a whole new fetch process for assets
                demisto.debug("starting new fetch")
                assets_last_run.update({"assets_last_fetch": time.time()})
            # Fetch Assets (assets_export_uuid -> continue prev fetch, or, no vuln_export_uuid -> new fetch)
            if assets_last_run_copy.get('assets_export_uuid') or not assets_last_run_copy.get('vuln_export_uuid'):
                assets = run_assets_fetch(client, assets_last_run)
            # Fetch Vulnerabilities
            if assets_last_run_copy.get('vuln_export_uuid') or not assets_last_run_copy.get('assets_export_uuid'):
                vulnerabilities = run_vulnerabilities_fetch(client, last_run=assets_last_run)

            demisto.info(f"Received {len(assets)} assets and {len(vulnerabilities)} vulnerabilities.")

            demisto.debug(f"new lastrun assets: {assets_last_run}")
            demisto.setAssetsLastRun(assets_last_run)

            if assets:
                demisto.debug('sending assets to XSIAM.')
                send_data_to_xsiam(data=assets, vendor=VENDOR, product=f'{PRODUCT}_assets', data_type='assets')
            if vulnerabilities:
                vulnerabilities = parse_vulnerabilities(vulnerabilities)
                demisto.debug('sending vulnerabilities to XSIAM.')
                send_data_to_xsiam(data=vulnerabilities, vendor=VENDOR, product=f'{PRODUCT}_vulnerabilities')

            demisto.info("Done Sending data to XSIAM.")

    except Exception as e:
        return_error(f'Failed to execute {demisto.command()} command.\nError:\n{str(e)}')


if __name__ in ['__main__', 'builtin', 'builtins']:
    main()
