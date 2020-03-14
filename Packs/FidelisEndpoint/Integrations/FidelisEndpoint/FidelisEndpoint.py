import demistomock as demisto
from CommonServerPython import *  # noqa: E402 lgtm [py/polluting-import]
from CommonServerUserPython import *  # noqa: E402 lgtm [py/polluting-import]
"""GLOBALS/PARAMS"""

import requests
from typing import Dict, Tuple, List, Optional, Union

# Disable insecure warnings
requests.packages.urllib3.disable_warnings()

# List processes
LIST_PROCESSES_WINDOWS = '2d32a530-0716-4542-afdc-8da3bd47d8bf'  # disable-secrets-detection
LIST_PROCESSES_LINUX = '5e58a0e9-450d-4394-8360-159d5e38c280'  # disable-secrets-detection
LIST_PROCESSES_MACOS = '020114c2-d000-4876-91b0-97f41a83b067'  # disable-secrets-detection

# Kill processes
KILL_PROCESS_WINDOWS = '8d379688-dde1-451d-8fa2-4f29c84baf97'  # disable-secrets-detection
KILL_PROCESS_MAC_LINUX = '76577d3a-c1d7-4d10-af9e-5825c3f9d016'  # disable-secrets-detection

# Delete file
DELETE_FILE_WINDOWS = '11cb4fae-5516-4391-8a3c-eb09793cd5dd'  # disable-secrets-detection
DELETE_FILE_MAC_LINUX = 'bead9799-401d-4b9e-adca-cf41b20c9118'  # disable-secrets-detection

# Network isolation
NETWORK_ISOLATION_WINDOWS = '1d01cc84-753d-4060-89a7-463567552a62'  # disable-secrets-detection
NETWORK_ISOLATION_MAC_LINUX = 'fd09996a-ef56-49fb-b811-0e5da4bd07ca'  # disable-secrets-detection

# Remove network isolation
REMOVE_NETWORK_ISOLATION_WINDOWS = '99bbaea5-df18-40cc-8759-b5fb61527d5a'  # disable-secrets-detection
REMOVE_NETWORK_ISOLATION_MAC_LINUX = '5e252298-4c50-4cdd-94c0-d6997b79157c'  # disable-secrets-detection


class Client(BaseClient):
    """
    Client to use in the Fidelis Endpoint integration. Overrides BaseClient
    """
    def __init__(self, server_url: str, username: str, password: str, verify: bool, proxy: bool, headers: dict):

        super().__init__(base_url=server_url, verify=verify, proxy=proxy)
        self._username = username
        self._password = password
        self._token = self._generate_token()
        self._headers = headers

        if self._token:
            token = self._token
            headers.update({'Authorization': 'bearer ' + token})

    def _generate_token(self) -> str:
        """Generate a token

        Returns:
            token valid for 10 minutes
        """
        params = {
            'username': self._username,
            'password': self._password
        }
        response = self._http_request('GET', '/authenticate', params=params)
        if response.get('error'):
            raise Exception(response.get('error'))
        token = response.get('data', {}).get('token', '')

        return token

    def test_module_request(self):
        """Performs basic GET request to check if the API is reachable and authentication is successful.

        Returns:
            Response content
        """
        suffix = '/alerts/getalertsV2'
        self._http_request('GET', suffix, params={'take': 1})

    def list_alerts(self, limit: int = None, sort: str = None, facet_search: str = None,
                    start_date=None, end_date=None) -> Dict:

        url_suffix = '/alerts/getalertsV2'
        params = assign_params(
            take=limit,
            sort=sort,
            facetSearch=facet_search,
            startDate=start_date,
            endDate=end_date
        )

        return self._http_request('GET', url_suffix, params=params)

    def get_host_info(self, host_name: Union[None, str], ip_address: Union[None, str]):

        if host_name:
            url_suffix = '/endpoints/v2/0/100/hostname%20Ascending?accessType=3&search={%22searchFields%22:' \
                         '[{%22fieldName%22:%22HostName%22,%22values%22:[{%22value%22:%22' + host_name + '%22}]}]}'

        if ip_address:
            url_suffix = '/endpoints/v2/0/100/hostname%20Ascending?accessType=3&search={%22searchFields%22:' \
                         '[{%22fieldName%22:%22IpAddress%22,%22values%22:[{%22value%22:%22' + ip_address + '%22}]}]}'

        return self._http_request('GET', url_suffix)

    def search_file(self, host, md5, file_extension, file_path, file_size) -> Dict:

        url_suffix = '/files/search'
        body = assign_params(
            hosts=host,
            md5Hashes=md5,
            fileExtensions=file_extension,
            filePathHints=file_path,
            fileSize=file_size
        )

        return self._http_request('POST', url_suffix, json_data=body)

    def file_search_status(self, job_id: str = None, job_result_id: str = None) -> Dict:

        url_suffix = f'/jobs/getjobstatus/{job_id}/{job_result_id}'

        return self._http_request('GET', url_suffix)

    def file_search_results_metadata(self, job_id: str = None, job_result_id: str = None) -> Dict:

        url_suffix = f'/jobs/{job_id}/jobresults/{job_result_id}'

        return self._http_request('GET', url_suffix)

    def get_file(self, file_id: str = None) -> Union[str, bytes]:

        url_suffix = f'/files/{file_id}'

        return self._http_request('GET', url_suffix, resp_type='content')

    def delete_job(self, job_id: str = None) -> Dict:

        url_suffix = f'/jobs/{job_id}'

        return self._http_request('DELETE', url_suffix)

    def list_scripts(self) -> Dict:

        url_suffix = '/packages'

        return self._http_request('GET', url_suffix)

    def script_manifest(self, script_id: str = None) -> Dict:

        url_suffix = f'/packages/{script_id}?type=Manifest'

        return self._http_request('GET', url_suffix)

    def execute_script(self, script_id: str = None, endpoint_ip: str = None, answer: Union[str, int] = None,
                       time_out: int = None, additional_answer: Union[None, str] = None) -> Dict:

        url_suffix = '/jobs/createTask'
        body = {
            'queueExpirationInhours': None,
            'wizardOverridePassword': False,
            'impersonationUser': None,
            'impersonationPassword': None,
            'priority': None,
            'timeoutInSeconds': time_out,
            'packageId': script_id,
            'endpoints': endpoint_ip,
            'isPlaybook': False,
            'taskOptions': [
                {
                    'integrationOutputFormat': None,
                    'scriptId': script_id,
                    'questions': [
                        {
                            'paramNumber': 1,
                            'answer': answer
                        },
                        {
                            'paramNumber': 2,
                            'answer': additional_answer,
                        }
                    ]
                }
            ]
        }

        return self._http_request('POST', url_suffix, json_data=body)

    def convert_ip_to_endpoint_id(self, ip: Union[str, list]) -> Dict:

        url_suffix = '/endpoints/endpointidsbyip'

        body = ip

        return self._http_request('POST', url_suffix, json_data=body)

    def convert_name_to_endpoint_id(self, endpoint_name: Union[str, list]) -> Dict:

        url_suffix = '/endpoints/endpointidsbyname'

        body = endpoint_name

        return self._http_request('POST', url_suffix, json_data=body)

    def list_process(self, script_id: str = None, time_out: int = None, endpoint_id: str = None) -> Dict:

        url_suffix = '/jobs/createTask'
        body = {
            'queueExpirationInhours': None,
            'wizardOverridePassword': False,
            'impersonationUser': None,
            'impersonationPassword': None,
            'priority': None,
            'timeoutInSeconds': time_out,
            'packageId': script_id,
            'endpoints': endpoint_id,
            'isPlaybook': False,
            'taskOptions': [
                {
                    'integrationOutputFormat': None,
                    'scriptId': script_id,
                    'questions': [
                        {
                            'paramNumber': 1,
                            'answer': True,
                        },
                        {
                            'paramNumber': 2,
                            'answer': True,
                        },
                        {
                            'paramNumber': 3,
                            'answer': True
                        }
                    ]
                }
            ]
        }

        return self._http_request('POST', url_suffix, json_data=body)

    def script_job_results(self, job_id: str = None) -> Dict:

        url_suffix = f'/jobresults/{job_id}'

        return self._http_request('POST', url_suffix)

    def kill_process(self, script_id: str = None, pid: int = None, time_out: int = None,
                     endpoint_ip=None) -> Dict:

        url_suffix = '/jobs/createTask'
        body = {
            'queueExpirationInhours': None,
            'wizardOverridePassword': False,
            'impersonationUser': None,
            'impersonationPassword': None,
            'priority': None,
            'timeoutInSeconds': time_out,
            'packageId': script_id,
            'endpoints': endpoint_ip,
            'isPlaybook': False,
            'taskOptions': [
                {
                    'integrationOutputFormat': None,
                    'scriptId': script_id,
                    'questions': [
                        {
                            'paramNumber': 1,
                            'answer': pid
                        }
                    ]
                }
            ]
        }

        return self._http_request('POST', url_suffix, json_data=body)

    def delete_file(self, script_id: str = None, file_path: str = None, time_out: int = None, endpoint_ip=None) -> Dict:

        url_suffix = '/jobs/createTask'
        body = {
            'queueExpirationInhours': None,
            'wizardOverridePassword': False,
            'impersonationUser': None,
            'impersonationPassword': None,
            'priority': None,
            'timeoutInSeconds': time_out,
            'packageId': script_id,
            'endpoints': endpoint_ip,
            'isPlaybook': False,
            'taskOptions': [
                {
                    'integrationOutputFormat': None,
                    'scriptId': script_id,
                    'questions': [
                        {
                            'paramNumber': 1,
                            'answer': file_path
                        }
                    ]
                }
            ]
        }

        return self._http_request('POST', url_suffix, json_data=body)

    def network_isolation(self, script_id: str = None, allowed_server: str = None, time_out: int = None,
                          endpoint_ip=None) -> Dict:

        url_suffix = '/jobs/createTask'
        body = {
            'queueExpirationInhours': None,
            'wizardOverridePassword': False,
            'impersonationUser': None,
            'impersonationPassword': None,
            'priority': None,
            'timeoutInSeconds': time_out,
            'packageId': script_id,
            'endpoints': endpoint_ip,
            'isPlaybook': False,
            'taskOptions': [
                {
                    'integrationOutputFormat': None,
                    'scriptId': script_id,
                    'questions': [
                        {
                            'paramNumber': 1,
                            'answer': allowed_server
                        }
                    ]
                }
            ]
        }

        return self._http_request('POST', url_suffix, json_data=body)

    def remove_network_isolation(self, script_id: str = None, time_out: int = None, endpoint_ip=None) -> Dict:

        url_suffix = '/jobs/createTask'
        body: dict = {
            'queueExpirationInhours': None,
            'wizardOverridePassword': False,
            'impersonationUser': None,
            'impersonationPassword': None,
            'priority': None,
            'timeoutInSeconds': time_out,
            'packageId': script_id,
            'endpoints': endpoint_ip,
            'isPlaybook': False,
            'taskOptions': [
                {
                    'integrationOutputFormat': None,
                    'scriptId': script_id,
                    'questions': [
                        {}
                    ]
                }
            ]
        }

        return self._http_request('POST', url_suffix, json_data=body)

    def get_script_job_status(self, job_result_id: str = None) -> Dict:

        url_suffix = f'/jobs/getjobtargets/{job_result_id}'

        return self._http_request('GET', url_suffix)

    def query_by_hash(self, limit: int = None, start_time: Union[None, int, float] = None,
                      end_time: Union[None, int, float] = None, logic: str = None, file_hash: str = None) -> Dict:

        url_suffix = '/v2/events'
        params = assign_params(pageSize=limit)
        body = {
            'dateRange': {
                'start': start_time,
                'end': end_time
            },
            'resultFields':
                ['endpointName', 'eventType', 'processStartTime', 'parentName', 'pid', 'name', 'path', 'user', 'hash',
                 'parameters'],

            'criteriaV3': {
                'relationshipFilter': None,
                'entityType': 'file',
                'filter': {
                    'filterType': 'composite',
                    'logic': logic,
                    'filters': [
                        {
                            'filterType': 'criteria',
                            'column': 'hash',
                            'operator': '=',
                            'value': file_hash
                        }
                    ]
                }
            }
        }
        response = self._http_request('POST', url_suffix, params=params, json_data=body)
        if response.get('error'):
            raise Exception(response.get('error'))
        return response

    def query_by_process_name(self, limit: int = None, start_time: Union[None, int, float] = None,
                              end_time: Union[None, int, float] = None, logic: str = None,
                              process_name: str = None) -> Dict:

        url_suffix = '/v2/events'
        params = assign_params(pageSize=limit)
        body = {
            'dateRange': {
                'start': start_time,
                'end': end_time
            },
            'resultFields':
                ['endpointName', 'eventType', 'processStartTime', 'parentName', 'pid', 'name', 'path', 'user', 'hash',
                 'parameters'],

            'criteriaV3': {
                'relationshipFilter': None,
                'entityType': 'process',
                'filter': {
                    'filterType': 'composite',
                    'logic': logic,
                    'filters': [
                        {
                            'filterType': 'criteria',
                            'column': 'name',
                            'operator': '=',
                            'value': process_name
                        }
                    ]
                }
            }
        }
        response = self._http_request('POST', url_suffix, params=params, json_data=body)
        if response.get('error'):
            raise Exception(response.get('error'))
        return response

    def query_by_remote_ip(self, limit: int = None, start_time: Union[None, int, float] = None,
                           end_time: Union[None, int, float] = None, logic: str = None, remote_ip: str = None) -> Dict:

        url_suffix = '/v2/events'
        params = assign_params(pageSize=limit)
        body = {
            'dateRange': {
                'start': start_time,
                'end': end_time
            },
            'resultFields':
                ['endpointName', 'eventType', 'endpointId', 'parentName', 'ppid', 'user', 'localIP', 'localPort',
                 'remoteIP', 'remotePort', 'processStartTime', 'firstEventTime', 'lastEventTime',
                 'protocol', 'parentHashSHA1'],

            'criteriaV3': {
                'relationshipFilter': None,
                'entityType': 'network',
                'filter': {
                    'filterType': "composite",
                    'logic': logic,
                    'filters': [
                        {
                            'filterType': 'criteria',
                            'column': 'remoteIP',
                            'operator': '=',
                            'value': remote_ip
                        }
                    ]
                }
            }
        }
        response = self._http_request('POST', url_suffix, params=params, json_data=body)
        if response.get('error'):
            raise Exception(response.get('error'))

        return response

    def query_by_dns_request(self, limit: int = None, start_time: Union[None, int, float] = None,
                             end_time: Union[None, int, float] = None, logic: str = None, url: str = None) -> Dict:

        url_suffix = '/v2/events'
        params = assign_params(pageSize=limit)
        body = {
            'dateRange': {
                'start': start_time,
                'end': end_time
            },
            'resultFields':
                ['endpointName'],

            'criteriaV3': {
                'relationshipFilter': None,
                'entityType': 'dns',
                'filter': {
                    'filterType': 'composite',
                    'logic': logic,
                    'filters': [
                        {
                            'filterType': 'criteria',
                            'column': 'dnsQuestion',
                            'operator': '=~',
                            'value': url
                        }
                    ]
                }
            }
        }
        response = self._http_request('POST', url_suffix, params=params, json_data=body)
        if response.get('error'):
            raise Exception(response.get('error'))

        return response

    def query_by_dns_server_ip(self, limit: int = None, start_time: Union[None, int, float] = None,
                               end_time: Union[None, int, float] = None, logic: str = None,
                               remote_ip: str = None) -> Dict:

        url_suffix = '/v2/events'
        params = assign_params(pageSize=limit)
        body = {
            'dateRange': {
                'start': start_time,
                'end': end_time
            },
            'resultFields':
                ['endpointName'],

            'criteriaV3': {
                'relationshipFilter': None,
                'entityType': 'dns',
                'filter': {
                    'filterType': 'composite',
                    'logic': logic,
                    'filters': [
                        {
                            'filterType': 'criteria',
                            'column': 'remoteIP',
                            'operator': '=',
                            'value': remote_ip
                        }
                    ]
                }
            }
        }
        response = self._http_request('POST', url_suffix, params=params, json_data=body)
        if response.get('error'):
            raise Exception(response.get('error'))

        return response

    def query_by_dns_source_ip(self, limit: int = None, start_time: Union[None, int, float] = None,
                               end_time: Union[None, int, float] = None, logic: str = None, source_ip: str = None,
                               domain: str = None) -> Dict:

        url_suffix = '/v2/events'
        params = assign_params(pageSize=limit)
        body = {
            'dateRange': {
                'start': start_time,
                'end': end_time
            },
            'resultFields':
                ['endpointName'],

            'criteriaV3': {
                'relationshipFilter': None,
                'entityType': 'dns',
                'filter': {
                    'filterType': 'composite',
                    'logic': logic,
                    'filters': [
                        {
                            'filterType': 'criteria',
                            'column': 'dnsQuestion',
                            'operator': '=~',
                            'value': domain
                        },
                        {
                            'filterType': 'criteria',
                            'column': 'localIP',
                            'operator': '=',
                            'value': source_ip
                        }
                    ]
                }
            }
        }
        response = self._http_request('POST', url_suffix, params=params, json_data=body)
        if response.get('error'):
            raise Exception(response.get('error'))

        return response

    def query_events(self, limit: int = None, start_time: Union[None, int, float] = None,
                     end_time: Union[None, int, float] = None, logic: str = None, column: str = None,
                     value: str = None, entity_type: str = None, operator: str = None,
                     additional_filter=None) -> Dict:

        url_suffix = '/v2/events'
        params = assign_params(pageSize=limit)

        body = {
            'dateRange': {
                'start': start_time,
                'end': end_time
            },
            'resultFields':
                ['endpointName', 'eventType', 'processStartTime', 'parentName', 'pid', 'name', 'path', 'user', 'hash',
                 'parameters'],

            'criteriaV3': {
                'relationshipFilter': None,
                'entityType': entity_type,
                'filter': {
                    'filterType': 'composite',
                    'logic': logic,
                    'filters': [
                        {
                            'filterType': 'criteria',
                            'column': column,
                            'operator': operator,
                            'value': value
                        }
                    ]
                }
            }
        }

        if additional_filter:
            body['criteriaV3']['filter']['filters'].append(additional_filter)

        response = self._http_request('POST', url_suffix, params=params, json_data=body)
        if response.get('error'):
            raise Exception(response.get('error'))

        return response


def alert_severity_to_dbot_score(severity_str: str):
    """Converts an severity string to DBot score representation
        alert severity. Can be one of:
        Low    ->  1
        Medium ->  2
        High, Critical   ->  3

    Args:
        severity_str: String representation of severity.

    Returns:
        Dbot representation of severity
    """
    severity_str = severity_str.lower()
    if severity_str == 'low':
        return 1
    elif severity_str == 'medium':
        return 2
    elif severity_str == 'high':
        return 3
    elif severity_str == 'critical':
        return 3
    return 0


def test_module(client: Client, *_):
    """
    Returning 'ok' indicates that the integration works like it is supposed to. Connection to the service is successful.
    """
    client.test_module_request()
    demisto.results('ok')
    return '', {}, {}


def list_alerts_command(client: Client, args: dict) -> Tuple[str, Dict, Dict]:
    limit = args.get('limit', '50')
    sort = args.get('sort')
    facet_search = args.get('facet_search', '')
    start_date = args.get('start_date')
    end_date = args.get('end_date')
    headers = ['ID', 'Name', 'EndpointName', 'EndpointID', 'Source', 'ArtifactName', 'IntelName', 'Severity',
               'CreateDate', 'AlertDate']

    contents = []
    context = []
    response = client.list_alerts(limit, sort, facet_search, start_date, end_date)

    alerts = response.get('data', {}).get('entities', [])
    if not alerts:
        return f'No alerts were found.', {}, {}

    for alert in alerts:
        contents.append({
            'Name': alert.get('name'),
            'ID': alert.get('id'),
            'EndpointName': alert.get('endpointName'),
            'EndpointID': alert.get('endpointId'),
            'Source': alert.get('source'),
            'ArtifactName': alert.get('artifactName'),
            'IntelName': alert.get('intelName'),
            'Severity': alert.get('severity'),
            'CreateDate': alert.get('createDate')
        })

        context.append({
            'Name': alert.get('name'),
            'ID': alert.get('id'),
            'EndpointName': alert.get('endpointName'),
            'EndpointID': alert.get('endpointId'),
            'Source': alert.get('source'),
            'ArtifactName': alert.get('artifactName'),
            'IntelName': alert.get('intelName'),
            'Severity': alert.get('severity'),
            'CreateDate': alert.get('createDate'),
            'HasJob': alert.get('hasJob'),
            'Description': alert.get('description'),
            'IntelID': alert.get('intelId'),
            'SourceType': alert.get('sourceType'),
            'ValidatedDate': alert.get('validatedDate'),
            'EventID': alert.get('eventId'),
            'ActionsTaken': alert.get('actionsTaken'),
            'EventTime': alert.get('eventTime'),
            'ParentEventID': alert.get('parentEventId'),
            'EventType': alert.get('eventType'),
            'EventIndex': alert.get('eventIndex'),
            'Telemetry': alert.get('telemetry'),
            'ReportID': alert.get('reportId'),
            'InsertionDate': alert.get('insertionDate'),
            'AgentTag': alert.get('agentTag')

        })
    entry_context = {'FidelisEndpoint.Alert(val.AlertID && val.AlertID === obj.AlertID)': context}
    human_readable = tableToMarkdown('Fidelis Endpoint Alerts', contents, headers, removeNull=True)

    return human_readable, entry_context, response


def host_info_command(client: Client, args: dict) -> Tuple[str, Dict, Dict]:

    ip_address = args.get('ip_address')
    host = args.get('host')

    if not host and not ip_address:
        return f'You must provide either ip_address or host', {}, {}

    contents = []
    context_standards = []
    headers = ['ID', 'HostName', 'IpAddress', 'OS', 'MacAddress', 'Isolated', 'LastContactDate', 'AgentInstalled',
               'AgentVersion', 'OnNetwork', 'AV_Enabled', 'Groups', 'ProcessorName']
    response = client.get_host_info(host, ip_address)
    hosts = response.get('data', {})
    if not hosts:
        return f'No hosts was found', {}, {}

    host_info = hosts.get('entities', [])
    for host in host_info:
        contents.append({
            'HostName': host.get('hostName'),
            'ID': host.get('id'),
            'IpAddress': host.get('ipAddress'),
            'OS': host.get('os'),
            'MacAddress': host.get('macAddress'),
            'LastContactDate': host.get('lastContactDate'),
            'AgentInstalled': host.get('agentInstalled'),
            'AgentVersion': host.get('agentVersion'),
            'AV_Enabled': host.get('aV_Enabled'),
            'Isolated': host.get('isolated'),
            'OnNetwork': host.get('onNetwork'),
            'Groups': host.get('groups'),
            'ProcessorName': host.get('processorName')
        })

        context_standards.append({
            'HostName': host.get('hostName'),
            'ID': host.get('id'),
            'IpAddress': host.get('ipAddress'),
            'OS': host.get('os'),
            'MACAddress': host.get('macAddress'),
            'Processor': host.get('processorName')
        })

    entry_context = {
        'FidelisEndpoint.Host(val.ID && val.ID === obj.ID)': contents,
        'Endpoint': context_standards
    }
    human_readable = tableToMarkdown('Fidelis Endpoint Host Info', contents, headers=headers, removeNull=True)

    return human_readable, entry_context, response


def file_search(client: Client, args: dict) -> Tuple[str, Dict, Dict]:
    """ Search for files on multiple hosts, using file hash, extension, file size, and other search criteria."""

    host = argToList(args.get('host', ['']))
    md5 = argToList(args.get('md5'))
    file_extension = argToList(args.get('file_extension'))
    file_path = argToList(args.get('file_path'))
    file_size = {
        'value': int(args.get('file_size')),
        'quantifier': 'greaterThan'
    }

    response = client.search_file(host, md5, file_extension, file_path, file_size)
    data = response.get('data', {})
    contents = {
        'JobID': data.get('jobId'),
        'JobResultID': data.get('jobResultId')
    }

    entry_context = {'FidelisEndpoint.FileSearch(val.JobID && val.JobID === obj.JobID)': contents}
    human_readable = tableToMarkdown('Fidelis Endpoint file search', contents)

    return human_readable, entry_context, response


def file_search_status(client: Client, args: dict) -> Tuple[str, Dict, Dict]:
    """Get the file search job status"""

    job_id = args.get('job_id')
    job_result_id = args.get('job_result_id')

    response = client.file_search_status(job_id, job_result_id)
    data = response.get('data', {})
    if not data:
        return 'Could not find any data for this Job ID', {}, {}
    contents = {
        'JobID': job_id,
        'JobResultID': job_result_id,
        'Status': data.get('status')
    }
    status = data.get('status')

    entry_context = {'FidelisEndpoint.FileSearch(val.JobID && val.JobID === obj.JobID)': contents}

    human_readable = f'Fidelis Endpoint file search status is: {status}'

    return human_readable, entry_context, response


def file_search_reasult_metadata(client: Client, args: dict) -> Tuple[str, Dict, Dict]:
    """Get the job results metadata"""

    job_id = args.get('job_id')
    job_result_id = args.get('job_result_id')
    headers = ['ID', 'FileName', 'FilePath', 'MD5Hash', 'FileSize', 'HostName', 'HostIP', 'AgentID']

    response = client.file_search_results_metadata(job_id, job_result_id)
    if not response.get('success'):
        return f'Could not find results for this job ID.', {}, {}
    data = response.get('data', {}).get('jobResultInfos', [])
    contents = {}
    file_standards = {}
    for item in data:
        if item.get('collectedFiles'):
            collected_files = item.get('collectedFiles', [])
            for obj in collected_files:
                contents = {
                    'FileName': obj.get('name'),
                    'ID': obj.get('id'),
                    'MD5Hash': obj.get('mD5Hash'),
                    'FilePath': obj.get('filePath'),
                    'FileSize': obj.get('fileSize'),
                    'HostName': item.get('hostName'),
                    'HostIP': item.get('hostIP'),
                    'AgentID': item.get('agentId')
                }

                file_standards = {
                    'Name': obj.get('name'),
                    'MD5': obj.get('mD5Hash'),
                    'Path': obj.get('filePath'),
                    'Size': obj.get('fileSize'),
                    'Hostname': item.get('hostName')
                }

    entry_context = {
        'FidelisEndpoint.File(val.ID && val.ID === obj.ID)': contents,
        'File': file_standards
    }
    human_readable = tableToMarkdown('Fidelis Endpoint file results metadata', contents, headers=headers, removeNull=True)

    return human_readable, entry_context, response


def get_file_command(client: Client, args: dict):
    file_id: str = str(args.get('file_id'))
    response = client.get_file(file_id)
    attachment_file = fileResult('Fidelis_Endpoint.zip', response)

    return attachment_file


def delete_file_search_job_command(client: Client, args: dict) -> Tuple[str, Dict, Dict]:
    job_id = args.get('job_id')
    response = client.delete_job(job_id)

    return 'The job was successfully deleted', {}, response


def list_scripts_command(client: Client, *_) -> Tuple[str, Dict, Dict]:
    headers = ['ID', 'Name', 'Description']
    response = client.list_scripts()
    res = response.get('data', {})
    scripts = res.get('scripts', [])
    if not scripts:
        return 'No scripts were found.', {}, {}
    contents = []
    for script in scripts:
        contents.append({
            'ID': script.get('id'),
            'Name': script.get('name'),
            'Description': script.get('description')
        })

    entry_context = {'FidelisEndpoint.Script(val.ID && val.ID === obj.ID)': contents}
    human_readable = tableToMarkdown('Fidelis Endpoint scripts', contents, headers)

    return human_readable, entry_context, response


def script_manifest_command(client: Client, args: dict) -> Tuple[str, Dict, Dict]:
    script_id = args.get('script_id')
    headers = ['ID', 'Name', 'Description', 'Platform', 'Command', 'Questions', 'Priority', 'TimeoutSeconds',
               'ResultColumns', 'ImpersonationUser', 'ImpersonationPassword', 'WizardOverridePassword']
    response = client.script_manifest(script_id)
    data = response.get('data', {})

    platforms = [k for k, v in data.get('platforms', {}).items() if v]

    contents = {
        'ID': data.get('id'),
        'Name': data.get('name'),
        'Platform': platforms,
        'Description': data.get('description'),
        'Priority': data.get('priority'),
        'ResultColumns': data.get('resultColumns'),
        'TimeoutSeconds': data.get('timeoutSeconds'),
        'ImpersonationUser': data.get('impersonationUser'),
        'ImpersonationPassword': data.get('impersonationPassword'),
        'Command': data.get('command'),
        'WizardOverridePassword': data.get('wizardOverridePassword'),
        'Questions': data.get('questions')
    }

    entry_context = {'FidelisEndpoint.Script(val.ID && val.ID === obj.ID)': contents}
    human_readable = tableToMarkdown('Fidelis Endpoint script manifest', contents, headers, removeNull=True)

    return human_readable, entry_context, response


def execute_script_command(client: Client, args: dict) -> Tuple[str, Dict, Dict]:
    script_id = args.get('script_id')
    time_out = args.get('time_out')
    endpoint_ip = argToList(args.get('endpoint_ip'))
    endpoint_name = argToList(args.get('endpoint_name'))
    answer = args.get('answer')
    additional_answer = args.get('additional_answer', '')

    if endpoint_ip:
        endpoints = client.convert_ip_to_endpoint_id(endpoint_ip)
        endpoint_id = endpoints.get('data')

    if endpoint_name:
        endpoints = client.convert_name_to_endpoint_id(endpoint_name)
        endpoint_id = endpoints.get('data')

    if endpoint_name and endpoint_ip:
        return 'You must provide only one argument endpoint_ip or endpoint_name', {}, {}

    if not endpoint_ip and not endpoint_name:
        return 'You must provide either endpoint_ip or endpoint_name', {}, {}

    response = client.execute_script(script_id, endpoint_id, answer, time_out, additional_answer)
    context = {
        'ID': script_id,
        'JobID': response.get('data')
    }
    entry_context = {'FidelisEndpoint.Script(val.ID && val.ID === obj.ID)': context}

    return 'The job has been executed successfully', entry_context, response


def list_process_command(client: Client, args: dict) -> Tuple[str, Dict, Dict]:
    endpoint_ip = argToList(args.get('endpoint_ip'))
    endpoint_name = argToList(args.get('endpoint_name'))

    if endpoint_ip:
        endpoints = client.convert_ip_to_endpoint_id(endpoint_ip)
        endpoint_id = endpoints.get('data')

    if endpoint_name:
        endpoints = client.convert_name_to_endpoint_id(endpoint_name)
        endpoint_id = endpoints.get('data')

    if endpoint_name and endpoint_ip:
        return 'You must provide only one argument endpoint_ip or endpoint_name', {}, {}

    if not endpoint_ip and not endpoint_name:
        return 'You must provide either endpoint_ip or endpoint_name', {}, {}

    time_out = args.get('time_out')
    operating_system = args.get('operating_system')
    script_id = ''

    if operating_system == 'Windows':
        script_id = LIST_PROCESSES_WINDOWS

    if operating_system == 'Linux':
        script_id = LIST_PROCESSES_LINUX

    if operating_system == 'macOS':
        script_id = LIST_PROCESSES_MACOS

    response = client.list_process(script_id, time_out, endpoint_id)
    context = {
        'ID': script_id,
        'JobID': response.get('data')
    }
    entry_context = {'FidelisEndpoint.Process(val.ID && val.ID === obj.ID)': context}

    return 'The job has been executed successfully', entry_context, response


def get_script_result(client: Client, args: dict):
    job_id = args.get('job_id')
    headers = ['ID', 'Name', 'EndpointID', 'EndpointName', 'PID', 'User', 'SHA1', 'MD5', 'Path', 'WorkingDirectory',
               'StartTime']

    response = client.script_job_results(job_id)
    hits = response.get('data', {}).get('hits', {}).get('hits', [])
    if not hits:
        return 'No results were found', {}, {}
    contents = []
    context = []
    for hit in hits:
        source_ = hit.get('_source', {})
        contents.append({
            'Path': source_.get('Path'),
            'User': source_.get('User'),
            'SHA1': source_.get('SHA1'),
            'WorkingDirectory': source_.get('Working Directory'),
            'EndpointID': source_.get('_EndpointId'),
            'PID': source_.get('PID'),
            'StartTime': source_.get('Start Time'),
            'EndpointName': source_.get('_EndpointName'),
            'Name': source_.get('Name'),
            'MD5': source_.get('MD5'),
            'ID': hit.get('_id'),
        })

        context.append({
            'Path': source_.get('Path'),
            'User': source_.get('User'),
            'SHA1': source_.get('SHA1'),
            'IsHidden': source_.get('Is Hidden'),
            'WorkingDirectory': source_.get('Working Directory'),
            'EndpointID': source_.get('_EndpointId'),
            'PID': source_.get('PID'),
            'StartTime': source_.get('Start Time'),
            'EndpointName': source_.get('_EndpointName'),
            'Name': source_.get('Name'),
            'ParentPID': source_.get('Parent PID'),
            'CommandLine': source_.get('Command Line'),
            'GroupID': source_.get('_GroupID'),
            'MD5': source_.get('MD5'),
            'Matches': source_.get('Matches'),
            'ID': hit.get('_id'),
            'Tags': hit.get('tags')
        })

    entry_context = {'FidelisEndpoint.ScriptResult(val.ID && val.ID === obj.ID)': context}
    human_readable = tableToMarkdown('Fidelis Endpoint script job results', contents, headers, removeNull=True)

    return human_readable, entry_context, response


def kill_process_by_pid(client: Client, args: dict) -> Tuple[str, Dict, Dict]:
    endpoint_ip = argToList(args.get('endpoint_ip'))
    endpoint_name = argToList(args.get('endpoint_name'))

    if endpoint_ip:
        endpoints = client.convert_ip_to_endpoint_id(endpoint_ip)
        endpoint_id = endpoints.get('data')

    if endpoint_name:
        endpoints = client.convert_name_to_endpoint_id(endpoint_name)
        endpoint_id = endpoints.get('data')

    if endpoint_name and endpoint_ip:
        return 'You must provide only one argument endpoint_ip or endpoint_name', {}, {}

    if not endpoint_ip and not endpoint_name:
        return 'You must provide either endpoint_ip or endpoint_name', {}, {}

    time_out = args.get('time_out')
    operating_system = args.get('operating_system')
    pid = args.get('pid')
    script_id = ''

    if operating_system == 'Windows':
        script_id = KILL_PROCESS_WINDOWS

    if operating_system == 'Linux' or operating_system == 'macOS':
        script_id = KILL_PROCESS_MAC_LINUX

    response = client.kill_process(script_id, pid, time_out, endpoint_id)
    context = {
        'ID': script_id,
        'JobID': response.get('data')
    }
    entry_context = {'FidelisEndpoint.Process(val.ID && val.ID === obj.ID)': context}

    return 'The job has been executed successfully', entry_context, response


def delete_file_command(client: Client, args: dict) -> Tuple[str, Dict, Dict]:
    endpoint_ip = argToList(args.get('endpoint_ip'))
    endpoint_name = argToList(args.get('endpoint_name'))

    if endpoint_ip:
        endpoints = client.convert_ip_to_endpoint_id(endpoint_ip)
        endpoint_id = endpoints.get('data')

    if endpoint_name:
        endpoints = client.convert_name_to_endpoint_id(endpoint_name)
        endpoint_id = endpoints.get('data')

    if endpoint_name and endpoint_ip:
        return 'You must provide only one argument endpoint_ip or endpoint_name', {}, {}

    if not endpoint_ip and not endpoint_name:
        return 'You must provide either endpoint_ip or endpoint_name', {}, {}

    time_out = args.get('time_out')
    operating_system = args.get('operating_system')
    file_path = args.get('file_path')
    script_id = ''

    if operating_system == 'Windows':
        script_id = DELETE_FILE_WINDOWS

    if operating_system == 'Linux' or operating_system == 'macOS':
        script_id = DELETE_FILE_MAC_LINUX

    response = client.delete_file(script_id, file_path, time_out, endpoint_id)
    context = {
        'ID': script_id,
        'JobID': response.get('data')
    }
    entry_context = {'FidelisEndpoint.Script(val.ID && val.ID === obj.ID)': context}

    return 'The job has been executed successfully', entry_context, response


def network_isolation_command(client: Client, args: dict) -> Tuple[str, Dict, Dict]:
    endpoint_ip = argToList(args.get('endpoint_ip'))
    endpoint_name = argToList(args.get('endpoint_name'))

    if endpoint_ip:
        endpoints = client.convert_ip_to_endpoint_id(endpoint_ip)
        endpoint_id = endpoints.get('data')

    if endpoint_name:
        endpoints = client.convert_name_to_endpoint_id(endpoint_name)
        endpoint_id = endpoints.get('data')

    if endpoint_name and endpoint_ip:
        return 'You must provide only one argument endpoint_ip or endpoint_name', {}, {}

    if not endpoint_ip and not endpoint_name:
        return 'You must provide either endpoint_ip or endpoint_name', {}, {}

    time_out = args.get('time_out')
    operating_system = args.get('operating_system')
    allowed_server = args.get('allowed_server')
    script_id = ''

    if operating_system == 'Windows':
        script_id = NETWORK_ISOLATION_WINDOWS

    if operating_system == 'Linux' or operating_system == 'macOS':
        script_id = NETWORK_ISOLATION_MAC_LINUX

    response = client.network_isolation(script_id, allowed_server, time_out, endpoint_id)
    context = {
        'ID': script_id,
        'JobID': response.get('data')
    }
    entry_context = {'FidelisEndpoint.Isolation(val.ID && val.ID === obj.ID)': context}

    return 'The job has been executed successfully', entry_context, response


def remove_network_isolation_command(client: Client, args: dict) -> Tuple[str, Dict, Dict]:
    endpoint_ip = argToList(args.get('endpoint_ip'))
    endpoint_name = argToList(args.get('endpoint_name'))

    if endpoint_ip:
        endpoints = client.convert_ip_to_endpoint_id(endpoint_ip)
        endpoint_id = endpoints.get('data')

    if endpoint_name:
        endpoints = client.convert_name_to_endpoint_id(endpoint_name)
        endpoint_id = endpoints.get('data')

    if endpoint_name and endpoint_ip:
        return 'You must provide only one argument endpoint_ip or endpoint_name', {}, {}

    if not endpoint_ip and not endpoint_name:
        return 'You must provide either endpoint_ip or endpoint_name', {}, {}

    time_out = args.get('time_out')
    operating_system = args.get('operating_system')
    script_id = ''

    if operating_system == 'Windows':
        script_id = REMOVE_NETWORK_ISOLATION_WINDOWS

    if operating_system == 'Linux' or os == 'macOS':
        script_id = REMOVE_NETWORK_ISOLATION_MAC_LINUX

    response = client.remove_network_isolation(script_id, time_out, endpoint_id)
    context = {
        'ID': script_id,
        'JobID': response.get('data')
    }
    entry_context = {'FidelisEndpoint.Isolation(val.ID && val.ID === obj.ID)': context}

    return 'The job has been executed successfully', entry_context, response


def script_job_status(client: Client, args: dict) -> Tuple[str, Dict, Dict]:
    job_result_id = args.get('job_result_id')
    contents = []
    response = client.get_script_job_status(job_result_id)

    results = response.get('data', {}).get('targets', [])

    for result in results:
        contents.append({
            'JobResultID': result.get('jobResultId'),
            'Name': result.get('name'),
            'Status': result.get('status'),
            'JobName': response.get('data').get('jobName')
        })
    entry_context = {'FidelisEndpoint.ScriptResult(val.JobResultID && val.JobResultID === obj.JobResultID)': contents}
    human_readable = tableToMarkdown('Fidelis Endpoint script job status', contents, removeNull=True)

    return human_readable, entry_context, response


def query_file_by_hash(client: Client, args: dict) -> Tuple[str, Dict, Dict]:
    start_time = args.get('start_time')
    end_time = args.get('end_time')
    logic = args.get('logic')
    file_hash = args.get('file_hash')
    limit = args.get('limit')
    if get_hash_type(file_hash) == 'Unknown':
        raise Exception('Enter a valid hash format.')
    contents = []
    context = []
    response = client.query_by_hash(limit, start_time, end_time, logic, file_hash)
    res = response.get('data', {})
    events = res.get('events', [])
    if not events:
        return f'No events were found for file_hash {file_hash}', {}, {}

    for event in events:
        contents.append({
            'EndpointName': event.get('endpointName'),
            'EventType': event.get('eventType'),
            'ProcessStartTime': event.get('processStartTime'),
            'ParentName': event.get('parentName'),
            'PID': event.get('pid'),
            'Name': event.get('name'),
            'Path': event.get('path'),
            'User': event.get('user'),
            'Hash': event.get('hash'),
            'Parameters': event.get('parameters')
        })

        context.append({
            'EventTime': event.get('eventTime'),
            'EndpointName': event.get('endpointName'),
            'EventType': event.get('eventType'),
            'ParentID': event.get('parentId'),
            'TargetID': event.get('targetId'),
            'ParentName': event.get('parentName'),
            'Name': event.get('name'),
            'Path': event.get('path'),
            'Hash': event.get('hash'),
            'Size': event.get('size'),
            'FileVersion': event.get('fileVersion'),
            'Signature': event.get('signature'),
            'SignedTime': event.get('signedTime'),
            'CertificateSubjectName': event.get('certificateSubjectName'),
            'CertificateIssuerName': event.get('certificateIssuerName'),
            'CertificatePublisher': event.get('certificatePublisher'),
            'HashSHA1': event.get('hashSHA1'),
            'HashSHA256': event.get('hashSHA256'),
            'ProcessStartTime': event.get('processStartTime'),
            'EventIndex': event.get('eventIndex'),
            'IndexingTime': event.get('indexingTime'),
            'FileExtension': event.get('fileExtension'),
            'FileType': event.get('fileType'),
            'FileCategory': event.get('fileCategory'),
            'EntityType': event.get('entityType'),
            'StartTime': event.get('startTime')
        })

    entry_context = {'FidelisEndpoint.Query(val.Hash && val.Hash === obj.Hash)': context}
    human_readable = tableToMarkdown('Fidelis Endpoint file hash query results', contents, removeNull=True)
    return human_readable, entry_context, response


def query_process_name_command(client: Client, args: dict) -> Tuple[str, Dict, Dict]:
    start_time = args.get('start_time')
    end_time = args.get('end_time')
    logic = args.get('logic')
    process_name = args.get('process_name')
    limit = args.get('limit')
    headers = ['PID', 'EndpointName', 'Name', 'Path', 'User', 'Hash', 'ProcessStartTime', 'Parameters', 'ParentName',
               'EventType']
    contents = []
    context = []

    response = client.query_by_process_name(limit, start_time, end_time, logic, process_name)
    res = response.get('data', {})
    events = res.get('events', [])
    if not events:
        return f'No events were found for the process {process_name}', {}, {}

    for event in events:
        contents.append({
            'EndpointName': event.get('endpointName'),
            'EventType': event.get('eventType'),
            'ProcessStartTime': event.get('processStartTime'),
            'ParentName': event.get('parentName'),
            'PID': event.get('pid'),
            'Name': event.get('name'),
            'Path': event.get('path'),
            'User': event.get('user'),
            'Hash': event.get('hash'),
            'Parameters': event.get('parameters')
        })

        context.append({
            'EsIndex': event.get('esIndex'),
            'EsDocumentType': event.get('esDocumentType'),
            'EventTime': event.get('eventTime'),
            'EndpointName': event.get('endpointName'),
            'EventType': event.get('eventType'),
            'ParentID': event.get('parentId'),
            'TargetID': event.get('targetId'),
            'PID': event.get('pid'),
            'ParentName': event.get('parentName'),
            'Name': event.get('name'),
            'Path': event.get('path'),
            'Hash': event.get('hash'),
            'User': event.get('user'),
            'ProcessStartTime': event.get('processStartTime'),
            'IndexingTime': event.get('indexingTime'),
            'EntityType': event.get('entityType'),
            'StartTime': event.get('startTime')
        })

    entry_context = {'FidelisEndpoint.Query(val.PID && val.PID === obj.PID)': context}
    human_readable = tableToMarkdown('Fidelis Endpoint process results', contents, headers=headers, removeNull=True)
    return human_readable, entry_context, response


def query_connection_by_remote_ip_command(client: Client, args: dict) -> Tuple[str, Dict, Dict]:
    start_time = args.get('start_time')
    end_time = args.get('end_time')
    logic = args.get('logic')
    remote_ip = args.get('remote_ip')
    limit = args.get('limit')
    contents = []
    context = []

    response = client.query_by_remote_ip(limit, start_time, end_time, logic, remote_ip)
    res = response.get('data', {})
    events = res.get('events', [])
    if not events:
        return f'No events were found for the IP address {remote_ip}', {}, {}

    for event in events:
        contents.append({
            'EndpointName': event.get('endpointName'),
            'EventType': event.get('eventType'),
            'EndpointID': event.get('endpointId'),
            'ProcessStartTime': event.get('processStartTime'),
            'ParentName': event.get('parentName'),
            'PPID': event.get('ppid'),
            'LocalIP': event.get('localIP'),
            'LocalPort': event.get('localPort'),
            'RemoteIP': event.get('remoteIP'),
            'RemotePort': event.get('remotePort'),
            'FirstEventTime': event.get('firstEventTime'),
            'LastEventTime': event.get('lastEventTime'),
            'Protocol': event.get('protocol'),
            'ParentHashSHA1': event.get('parentHashSHA1')
        })

        context.append({
            'EventTime': event.get('eventTime'),
            'EndpointName': event.get('endpointName'),
            'EventType': event.get('eventType'),
            'EndpointID': event.get('endpointId'),
            'ParentID': event.get('parentId'),
            'TargetID': event.get('targetId'),
            'PPID': event.get('ppid'),
            'ParentName': event.get('parentName'),
            'LocalIP': event.get('localIP'),
            'LocalPort': event.get('localPort'),
            'RemoteIP': event.get('remoteIP'),
            'RemotePort': event.get('remotePort'),
            'ProcessStartTime': event.get('processStartTime'),
            'FirstEventTime': event.get('firstEventTime'),
            'LastEventTime': event.get('lastEventTime'),
            'Protocol': event.get('protocol'),
            'EventIndex': event.get('eventIndex'),
            'NetworkDirection': event.get('networkDirection'),
            'EntityType': event.get('entityType'),
            'StartTime': event.get('startTime'),
            'parentHashSHA1': event.get('parentHashSHA1')
        })

    entry_context = {'FidelisEndpoint.Query(val.PPID && val.PPID === obj.PPID)': context}
    human_readable = tableToMarkdown('Fidelis Endpoint query results for connection by remote IP', contents,
                                     removeNull=True)
    return human_readable, entry_context, response


def query_dns_request_command(client: Client, args: dict) -> Tuple[str, Dict, Dict]:
    start_time = args.get('start_time')
    end_time = args.get('end_time')
    logic = args.get('logic')
    url = args.get('url')
    limit = args.get('limit')
    contents = []
    context = []

    response = client.query_by_dns_request(limit, start_time, end_time, logic, url)
    res = response.get('data', {})
    events = res.get('events', [])
    if not events:
        return f'No events were found for the URL {url}', {}, {}

    for event in events:
        contents.append({
            'EndpointName': event.get('endpointName'),
            'EventType': event.get('eventType'),
            'DnsAnswer': event.get('dnsAnswer'),
            'ProcessStartTime': event.get('processStartTime'),
            'LocalIP': event.get('localIP'),
            'LocalPort': event.get('localPort'),
            'RemoteIP': event.get('remoteIP'),
            'RemotePort': event.get('remotePort')
        })

        context.append({
            'EventTime': event.get('eventTime'),
            'EndpointName': event.get('endpointName'),
            'EventType': event.get('eventType'),
            'ParentID': event.get('parentId'),
            'TargetID': event.get('targetId'),
            'LocalIP': event.get('localIP'),
            'LocalPort': event.get('localPort'),
            'RemoteIP': event.get('remoteIP'),
            'RemotePort': event.get('remotePort'),
            'DnsQuestion': event.get('dnsQuestion'),
            'DnsAnswer': event.get('dnsAnswer'),
            'ProcessStartTime': event.get('processStartTime'),
            'EventIndex': event.get('eventIndex'),
            'IndexingTime': event.get('indexingTime'),
            'NetworkDirection': event.get('networkDirection'),
            'EntityType': event.get('entityType'),
            'StartTime': event.get('startTime')
        })

    entry_context = {'FidelisEndpoint.Query(val.ParentID && val.ParentID === obj.ParentID)': context}
    human_readable = tableToMarkdown('Fidelis Endpoint query results for the DNS request', contents,
                                     removeNull=True)
    return human_readable, entry_context, response


def query_by_server_ip_command(client: Client, args: dict) -> Tuple[str, Dict, Dict]:
    start_time = args.get('start_time')
    end_time = args.get('end_time')
    logic = args.get('logic')
    remote_ip = args.get('remote_ip')
    limit = args.get('limit')
    contents = []
    context = []

    response = client.query_by_dns_server_ip(limit, start_time, end_time, logic, remote_ip)
    res = response.get('data', {})
    events = res.get('events', [])
    if not events:
        return f'No events were found for the IP address {remote_ip}', {}, {}

    for event in events:
        contents.append({
            'EndpointName': event.get('endpointName'),
            'EventType': event.get('eventType'),
            'DnsAnswer': event.get('dnsAnswer'),
            'ProcessStartTime': event.get('processStartTime'),
            'LocalIP': event.get('localIP'),
            'LocalPort': event.get('localPort'),
            'RemoteIP': event.get('remoteIP'),
            'RemotePort': event.get('remotePort')
        })

        context.append({
            'EventTime': event.get('eventTime'),
            'EndpointName': event.get('endpointName'),
            'EventType': event.get('eventType'),
            'ParentID': event.get('parentId'),
            'TargetID': event.get('targetId'),
            'LocalIP': event.get('localIP'),
            'LocalPort': event.get('localPort'),
            'RemoteIP': event.get('remoteIP'),
            'RemotePort': event.get('remotePort'),
            'DnsQuestion': event.get('dnsQuestion'),
            'DnsAnswer': event.get('dnsAnswer'),
            'ProcessStartTime': event.get('processStartTime'),
            'EventIndex': event.get('eventIndex'),
            'IndexingTime': event.get('indexingTime'),
            'NetworkDirection': event.get('networkDirection'),
            'EntityType': event.get('entityType'),
            'StartTime': event.get('startTime')
        })

    entry_context = {'FidelisEndpoint.Query(val.TargetID && val.TargetID === obj.TargetID)': context}
    human_readable = tableToMarkdown('Fidelis Endpoint query results for the DNS request by server IP', contents,
                                     removeNull=True)
    return human_readable, entry_context, response


def query_by_source_ip(client: Client, args: dict) -> Tuple[str, Dict, Dict]:
    start_time = args.get('start_time')
    end_time = args.get('end_time')
    logic = args.get('logic')
    source_ip = args.get('source_ip')
    domain = args.get('domain', '')
    limit = args.get('limit')
    contents = []
    context = []
    headers = ['EndpointName', 'LocalIP', 'LocalPort', 'RemoteIP', 'RemotePort', 'ProcessStartTime', 'DnsQuestion',
               'DnsAnswer']
    response = client.query_by_dns_source_ip(limit, start_time, end_time, logic, source_ip, domain)
    res = response.get('data', {})
    events = res.get('events', [])
    if not events:
        return f'No events were found', {}, {}

    for event in events:
        contents.append({
            'EndpointName': event.get('endpointName'),
            'ProcessStartTime': event.get('processStartTime'),
            'LocalIP': event.get('localIP'),
            'LocalPort': event.get('localPort'),
            'RemoteIP': event.get('remoteIP'),
            'RemotePort': event.get('remotePort'),
            'DnsQuestion': event.get('dnsQuestion'),
            'DnsAnswer': event.get('dnsAnswer')
        })

        context.append({
            'EventTime': event.get('eventTime'),
            'EndpointName': event.get('endpointName'),
            'EventType': event.get('eventType'),
            'ParentID': event.get('parentId'),
            'TargetID': event.get('targetId'),
            'LocalIP': event.get('localIP'),
            'LocalPort': event.get('localPort'),
            'RemoteIP': event.get('remoteIP'),
            'RemotePort': event.get('remotePort'),
            'DnsQuestion': event.get('dnsQuestion'),
            'DnsAnswer': event.get('dnsAnswer'),
            'ProcessStartTime': event.get('processStartTime'),
            'EventIndex': event.get('eventIndex'),
            'IndexingTime': event.get('indexingTime'),
            'NetworkDirection': event.get('networkDirection'),
            'EntityType': event.get('entityType'),
            'StartTime': event.get('startTime')
        })

    entry_context = {'FidelisEndpoint.Query(val.TargetID && val.TargetID === obj.TargetID)': context}
    human_readable = tableToMarkdown('Fidelis Endpoint query results for the DNS request by source IP', contents,
                                     headers=headers, removeNull=True)
    return human_readable, entry_context, response


def query_events(client: Client, args: dict) -> Tuple[str, Dict, Dict]:
    start_time = args.get('start_time')
    end_time = args.get('end_time')
    logic = args.get('logic')
    entity_type = args.get('entity_type')
    column = args.get('column')
    value = args.get('value')
    operator = args.get('operator')
    limit = args.get('limit')
    additional_filter = args.get('additional_filter')
    if additional_filter:
        add_filter = additional_filter.split()
        add_filter = {
            'filterType': 'criteria',
            'column': add_filter[0],
            'operator': add_filter[1],
            'value': add_filter[2]
        }
    contents = []
    context = []

    response = client.query_events(limit, start_time, end_time, logic, column, value, entity_type, operator,
                                   add_filter)
    res = response.get('data', {})
    events = res.get('events', [])
    if not events:
        return f'No events were found', {}, {}

    for event in events:
        contents.append({
            'EndpointName': event.get('endpointName'),
            'EventType': event.get('eventType'),
            'ParentID': event.get('parentId'),
            'PID': event.get('pid'),
            'User': event.get('user'),
            'ProcessStartTime': event.get('processStartTime'),
            'LocalIP': event.get('localIP'),
            'LocalPort': event.get('localPort'),
            'RemoteIP': event.get('remoteIP'),
            'RemotePort': event.get('remotePort')
        })

        context.append({
            'EventTime': event.get('eventTime'),
            'EndpointName': event.get('endpointName'),
            'EventType': event.get('eventType'),
            'ParentID': event.get('parentId'),
            'TargetID': event.get('targetId'),
            'PID': event.get('pid'),
            'ParentName': event.get('parentName'),
            'Name': event.get('name'),
            'Path': event.get('path'),
            'Hash': event.get('hash'),
            'User': event.get('user'),
            'LocalIP': event.get('localIP'),
            'LocalPort': event.get('localPort'),
            'RemoteIP': event.get('remoteIP'),
            'RemotePort': event.get('remotePort'),
            'DnsQuestion': event.get('dnsQuestion'),
            'DnsAnswer': event.get('dnsAnswer'),
            'ProcessStartTime': event.get('processStartTime'),
            'EventIndex': event.get('eventIndex'),
            'IndexingTime': event.get('indexingTime'),
            'EntityType': event.get('entityType'),
            'StartTime': event.get('startTime')
        })

    entry_context = {'FidelisEndpoint.Query(val.PID && val.PID === obj.PID)': context}
    human_readable = tableToMarkdown('Fidelis Endpoint query events result', contents,
                                     removeNull=True)
    return human_readable, entry_context, response


def fetch_incidents(client: Client, fetch_time: Optional[str], severity: str, last_run: Dict) -> Tuple[List, Dict]:
    if not last_run:  # if first time running
        new_last_run = {'time': fetch_time}
    else:
        new_last_run = last_run
    incidents: list = list()
    response = client.list_alerts()
    alerts = response.get('data', {}).get('entities', [])
    if alerts:
        last_incident_id = last_run.get('id', 0)
        # Creates incident entry
        incidents = [{
            'name': f"Fidlie Endpoint alert: {alert.get('id')}",
            'occurred': alert.get('createDate'),
            'severity': alert_severity_to_dbot_score(alert.get('severity')),
            'rawJSON': json.dumps(alert)
        } for alert in alerts if alert.get('id') > last_incident_id and alert.get('severity') == severity]
        # New incidents fetched
        if incidents:
            last_incident_timestamp = incidents[-1].get('occurred')
            last_incident_id = alerts[-1].get('id')
            new_last_run = {'time': last_incident_timestamp, 'id': last_incident_id}
    # Return results
    return incidents, new_last_run


def main():
    """
    PARSE AND VALIDATE INTEGRATION PARAMS
    """
    username = demisto.params().get('credentials').get('identifier')
    password = demisto.params().get('credentials').get('password')

    # get the service API url
    base_url = urljoin(demisto.params().get('url'), '/Endpoint/api')

    verify_certificate = not demisto.params().get('insecure', False)

    proxy = demisto.params().get('proxy', False)
    headers = {'ContentType': 'appliaction/json'}

    LOG(f'Command being called is {demisto.command()}')
    try:
        client = Client(base_url, username=username, password=password, verify=verify_certificate, proxy=proxy,
                        headers=headers)

        if demisto.command() == 'test-module':
            # This is the call made when pressing the integration Test button.
            result = test_module(client)
            demisto.results(result)
        elif demisto.command() == 'fetch-incidents':
            fetch_time = demisto.params().get('fetch_time')
            severity = demisto.params().get('severity', 'Medium')
            incidents, last_run = fetch_incidents(client, severity, fetch_time, last_run=demisto.getLastRun())  # type: ignore
            demisto.incidents(incidents)
            demisto.setLastRun(last_run)

        elif demisto.command() == 'fidelis-endpoint-list-alerts':
            return_outputs(*list_alerts_command(client, demisto.args()))

        elif demisto.command() == 'fidelis-endpoint-host-info':
            return_outputs(*host_info_command(client, demisto.args()))

        elif demisto.command() == 'fidelis-endpoint-file-search':
            return_outputs(*file_search(client, demisto.args()))

        elif demisto.command() == 'fidelis-endpoint-file-search-status':
            return_outputs(*file_search_status(client, demisto.args()))

        elif demisto.command() == 'fidelis-endpoint-file-search-result-metadata':
            return_outputs(*file_search_reasult_metadata(client, demisto.args()))

        elif demisto.command() == 'fidelis-endpoint-get-file':
            demisto.results(get_file_command(client, demisto.args()))

        elif demisto.command() == 'fidelis-endpoint-delete-file-search-job':
            return_outputs(*delete_file_search_job_command(client, demisto.args()))

        elif demisto.command() == 'fidelis-endpoint-list-scripts':
            return_outputs(*list_scripts_command(client, demisto.args()))

        elif demisto.command() == 'fidelis-endpoint-get-script-manifest':
            return_outputs(*script_manifest_command(client, demisto.args()))

        elif demisto.command() == 'fidelis-endpoint-list-processes':
            return_outputs(*list_process_command(client, demisto.args()))

        elif demisto.command() == 'fidelis-endpoint-get-script-result':
            return_outputs(*get_script_result(client, demisto.args()))

        elif demisto.command() == 'fidelis-endpoint-kill-process':
            return_outputs(*kill_process_by_pid(client, demisto.args()))

        elif demisto.command() == 'fidelis-endpoint-delete-file':
            return_outputs(*delete_file_command(client, demisto.args()))

        elif demisto.command() == 'fidelis-endpoint-isolate-network':
            return_outputs(*network_isolation_command(client, demisto.args()))

        elif demisto.command() == 'fidelis-endpoint-remove-network-isolation':
            return_outputs(*remove_network_isolation_command(client, demisto.args()))

        elif demisto.command() == 'fidelis-endpoint-script-job-status':
            return_outputs(*script_job_status(client, demisto.args()))

        elif demisto.command() == 'fidelis-endpoint-execute-script':
            return_outputs(*execute_script_command(client, demisto.args()))

        elif demisto.command() == 'fidelis-endpoint-query-file':
            return_outputs(*query_file_by_hash(client, demisto.args()))

        elif demisto.command() == 'fidelis-endpoint-query-process':
            return_outputs(*query_process_name_command(client, demisto.args()))

        elif demisto.command() == 'fidelis-endpoint-query-connection-by-remote-ip':
            return_outputs(*query_connection_by_remote_ip_command(client, demisto.args()))

        elif demisto.command() == 'fidelis-endpoint-query-by-dns':
            return_outputs(*query_dns_request_command(client, demisto.args()))

        elif demisto.command() == 'fidelis-endpoint-query-dns-by-server-ip':
            return_outputs(*query_by_server_ip_command(client, demisto.args()))

        elif demisto.command() == 'fidelis-endpoint-query-dns-by-source-ip':
            return_outputs(*query_by_source_ip(client, demisto.args()))

        elif demisto.command() == 'fidelis-endpoint-query-events':
            return_outputs(*query_events(client, demisto.args()))

    # Log exceptions
    except Exception as e:
        return_error(f'Failed to execute {demisto.command()} command. Error: {str(e)}')


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
