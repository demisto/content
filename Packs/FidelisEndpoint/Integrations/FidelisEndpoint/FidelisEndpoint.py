import demistomock as demisto
from CommonServerPython import *  # noqa: E402 lgtm [py/polluting-import]
from CommonServerUserPython import *  # noqa: E402 lgtm [py/polluting-import]
# IMPORTS

import requests


# Disable insecure warnings
requests.packages.urllib3.disable_warnings()

"""GLOBALS/PARAMS"""
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
        token_ = response.get('data')
        if not token_:
            raise Exception('The token could not be generated. Make sure that the username and password are correct.')

        token = token_.get('token')
        return token

    def test_module_request(self):
        """Performs basic GET request to check if the API is reachable and authentication is successful.

        Returns:
            Response content
        """
        suffix = '/alerts/getalertsV2'
        self._http_request('GET', suffix, params={'take': 1})

    def list_alerts(self, skip: int, limit: int, sort: str, facet_search: str, start_date, end_date):

        url_suffix = '/alerts/getalertsV2'
        params = assign_params(
            skip=skip,
            take=limit,
            sort=sort,
            facetSearch=facet_search,
            startDate=start_date,
            endDate=end_date
        )

        return self._http_request('GET', url_suffix, params=params)

    def get_host_info(self, ip: str):

        url_suffix = '/endpoints/search'
        body = assign_params(ip=ip)

        return self._http_request('POST', url_suffix, json_data=body)

    def search_file(self, host, md5, file_extension, file_path, file_size):

        url_suffix = '/files/search'
        body = assign_params(
            hosts=host,
            md5Hashes=md5,
            fileExtensions=file_extension,
            filePathHints=file_path,
            fileSize=file_size
        )

        return self._http_request('POST', url_suffix, json_data=body)

    def file_search_status(self, job_id: str, job_result_id: str):

        url_suffix = f'/jobs/getjobstatus/{job_id}/{job_result_id}'

        return self._http_request('GET', url_suffix)

    def file_search_results_metadata(self, job_id: str, job_result_id: str):

        url_suffix = f'/jobs/{job_id}/jobresults/{job_result_id}'

        return self._http_request('GET', url_suffix)

    def get_file(self, file_id: str):

        url_suffix = f'/files/{file_id}'

        return self._http_request('GET', url_suffix, resp_type='content')

    def delete_job(self, job_id):

        url_suffix = f'/jobs/{job_id}'

        return self._http_request('DELETE', url_suffix)

    def list_scripts(self):

        url_suffix = '/packages'

        return self._http_request('GET', url_suffix)

    def script_manifest(self, script_id: str):

        url_suffix = f'/packages/{script_id}?type=Manifest'

        return self._http_request('GET', url_suffix)

    def execute_script(self, script_id: str, endpoint_ip: str, answer: str, time_out: int):

        url_suffix = '/jobs/createTask'
        body = {
            "queueExpirationInhours": None,
            "wizardOverridePassword": False,
            "impersonationUser": None,
            "impersonationPassword": None,
            "priority": None,
            "timeoutInSeconds": time_out,
            "packageId": script_id,
            "endpoints": endpoint_ip,
            "isPlaybook": False,
            "taskOptions": [
                {
                    "integrationOutputFormat": None,
                    "scriptId": script_id,
                    "questions": [
                        {
                            "paramNumber": 1,
                            "answer": answer,
                        }
                    ]
                }
            ]
        }

        return self._http_request('POST', url_suffix, json_data=body)

    def convert_ip_to_endpoint_id(self, ip: str):

        url_suffix = '/endpoints/endpointidsbyip'

        body = ip

        return self._http_request('POST', url_suffix, json_data=body)

    def list_process(self, script_id: str, time_out: int, endpoint_ip):

        url_suffix = '/jobs/createTask'
        body = {
            "queueExpirationInhours": None,
            "wizardOverridePassword": False,
            "impersonationUser": None,
            "impersonationPassword": None,
            "priority": None,
            "timeoutInSeconds": time_out,
            "packageId": script_id,
            "endpoints": endpoint_ip,
            "isPlaybook": False,
            "taskOptions": [
                {
                    "integrationOutputFormat": None,
                    "scriptId": script_id,
                    "questions": [
                        {
                            "paramNumber": 1,
                            "answer": True,
                        },
                        {
                            "paramNumber": 2,
                            "answer": True,
                        },
                        {
                            "paramNumber": 3,
                            "answer": True
                        }
                    ]
                }
            ]
        }

        return self._http_request('POST', url_suffix, json_data=body)

    def script_job_results(self, job_id: str):

        url_suffix = f'/jobresults/{job_id}'

        return self._http_request('POST', url_suffix)

    def kill_process(self, script_id: str, pid: int, time_out: int, endpoint_ip):

        url_suffix = '/jobs/createTask'
        body = {
            "queueExpirationInhours": None,
            "wizardOverridePassword": False,
            "impersonationUser": None,
            "impersonationPassword": None,
            "priority": None,
            "timeoutInSeconds": time_out,
            "packageId": script_id,
            "endpoints": endpoint_ip,
            "isPlaybook": False,
            "taskOptions": [
                {
                    "integrationOutputFormat": None,
                    "scriptId": script_id,
                    "questions": [
                        {
                            "paramNumber": 1,
                            "answer": pid
                        }
                    ]
                }
            ]
        }

        return self._http_request('POST', url_suffix, json_data=body)

    def delete_file(self, script_id: str, file_path: str, time_out: int, endpoint_ip):

        url_suffix = '/jobs/createTask'
        body = {
            "queueExpirationInhours": None,
            "wizardOverridePassword": False,
            "impersonationUser": None,
            "impersonationPassword": None,
            "priority": None,
            "timeoutInSeconds": time_out,
            "packageId": script_id,
            "endpoints": endpoint_ip,
            "isPlaybook": False,
            "taskOptions": [
                {
                    "integrationOutputFormat": None,
                    "scriptId": script_id,
                    "questions": [
                        {
                            "paramNumber": 1,
                            "answer": file_path
                        }
                    ]
                }
            ]
        }

        return self._http_request('POST', url_suffix, json_data=body)

    def network_isolation(self, script_id: str, allowed_server: str, time_out: int, endpoint_ip):

        url_suffix = '/jobs/createTask'
        body = {
            "queueExpirationInhours": None,
            "wizardOverridePassword": False,
            "impersonationUser": None,
            "impersonationPassword": None,
            "priority": None,
            "timeoutInSeconds": time_out,
            "packageId": script_id,
            "endpoints": endpoint_ip,
            "isPlaybook": False,
            "taskOptions": [
                {
                    "integrationOutputFormat": None,
                    "scriptId": script_id,
                    "questions": [
                        {
                            "paramNumber": 1,
                            "answer": allowed_server
                        }
                    ]
                }
            ]
        }

        return self._http_request('POST', url_suffix, json_data=body)

    def remove_network_isolation(self, script_id: str, time_out: int, endpoint_ip):

        url_suffix = '/jobs/createTask'
        body = {
            "queueExpirationInhours": None,
            "wizardOverridePassword": False,
            "impersonationUser": None,
            "impersonationPassword": None,
            "priority": None,
            "timeoutInSeconds": time_out,
            "packageId": script_id,
            "endpoints": endpoint_ip,
            "isPlaybook": False,
            "taskOptions": [
                {
                    "integrationOutputFormat": None,
                    "scriptId": script_id,
                    "questions": [
                        {}
                    ]
                }
            ]
        }

        return self._http_request('POST', url_suffix, json_data=body)

    def get_script_job_status(self, job_result_id: str):

        url_suffix = f'/jobs/getjobtargets/{job_result_id}'

        return self._http_request('GET', url_suffix)

    def query_by_hash(self, start_time: str, end_time: str, logic: str, file_hash: str):

        url_suffix = '/v2/events'
        body = {
            "dateRange": {
                "start": start_time,
                "end": end_time
            },
            "resultFields":
                ["endpointName", "eventType", "processStartTime", "parentName", "pid", "name", "path", "user", "hash",
                 "parameters"],

            "criteriaV3": {
                "relationshipFilter": None,
                "entityType": "file",
                "filter": {
                    "filterType": "composite",
                    "logic": logic,
                    "filters": [
                        {
                            "filterType": "criteria",
                            "column": "hash",
                            "operator": "=",
                            "value": file_hash
                        }
                    ]
                }
            }
        }
        response = self._http_request('POST', url_suffix, json_data=body)
        if response.get('error'):
            return_error(response.get('error'))
        if 'data' in response:
            return response.get('data')
        return {}

    def query_by_process_name(self, start_time: str, end_time: str, logic: str, process_name: str):

        url_suffix = '/v2/events?pageSize=1000'
        body = {
            "dateRange": {
                "start": start_time,
                "end": end_time
            },
            "resultFields":
                ["endpointName", "eventType", "processStartTime", "parentName", "pid", "name", "path", "user", "hash",
                 "parameters"],

            "criteriaV3": {
                "relationshipFilter": None,
                "entityType": "process",
                "filter": {
                    "filterType": "composite",
                    "logic": logic,
                    "filters": [
                        {
                            "filterType": "criteria",
                            "column": "name",
                            "operator": "=",
                            "value": process_name
                        }
                    ]
                }
            }
        }
        response = self._http_request('POST', url_suffix, json_data=body)
        if response.get('error'):
            return_error(response.get('error'))
        if 'data' in response:
            return response.get('data')
        return {}

    def query_by_remote_ip(self, start_time: str, end_time: str, logic: str, remote_ip: str):

        url_suffix = '/v2/events?pageSize=1000'
        body = {
            "dateRange": {
                "start": start_time,
                "end": end_time
            },
            "resultFields":
                ["endpointName", "eventType", "endpointId", "parentName", "ppid", "user", "localIP", "localPort",
                 "remoteIP", "remotePort", "processStartTime", "firstEventTime", "lastEventTime",
                 "protocol", "parentHashSHA1"],

            "criteriaV3": {
                "relationshipFilter": None,
                "entityType": "network",
                "filter": {
                    "filterType": "composite",
                    "logic": logic,
                    "filters": [
                        {
                            "filterType": "criteria",
                            "column": "remoteIP",
                            "operator": "=",
                            "value": remote_ip
                        }
                    ]
                }
            }
        }
        response = self._http_request('POST', url_suffix, json_data=body)
        if response.get('error'):
            return_error(response.get('error'))
        if 'data' in response:
            return response.get('data')
        return {}

    def query_by_dns_request(self, start_time: str, end_time: str, logic: str, url: str):

        url_suffix = '/v2/events?pageSize=1000'
        body = {
            "dateRange": {
                "start": start_time,
                "end": end_time
            },
            "resultFields":
                ["endpointName"],

            "criteriaV3": {
                "relationshipFilter": None,
                "entityType": "dns",
                "filter": {
                    "filterType": "composite",
                    "logic": logic,
                    "filters": [
                        {
                            "filterType": "criteria",
                            "column": "dnsQuestion",
                            "operator": '=~',
                            "value": url
                        }
                    ]
                }
            }
        }
        response = self._http_request('POST', url_suffix, json_data=body)
        if response.get('error'):
            return_error(response.get('error'))
        if 'data' in response:
            return response.get('data')
        return {}

    def query_by_dns_server_ip(self, start_time: str, end_time: str, logic: str, remote_ip: str):

        url_suffix = '/v2/events?pageSize=1000'
        body = {
            "dateRange": {
                "start": start_time,
                "end": end_time
            },
            "resultFields":
                ["endpointName"],

            "criteriaV3": {
                "relationshipFilter": None,
                "entityType": "dns",
                "filter": {
                    "filterType": "composite",
                    "logic": logic,
                    "filters": [
                        {
                            "filterType": "criteria",
                            "column": "remoteIP",
                            "operator": '=',
                            "value": remote_ip
                        }
                    ]
                }
            }
        }
        response = self._http_request('POST', url_suffix, json_data=body)
        if response.get('error'):
            return_error(response.get('error'))
        if 'data' in response:
            return response.get('data')
        return {}

    def query_by_dns_source_ip(self, start_time: str, end_time: str, logic: str, source_ip: str, domain: str):

        url_suffix = '/v2/events?pageSize=1000'
        body = {
            "dateRange": {
                "start": start_time,
                "end": end_time
            },
            "resultFields":
                ["endpointName"],

            "criteriaV3": {
                "relationshipFilter": None,
                "entityType": "dns",
                "filter": {
                    "filterType": "composite",
                    "logic": logic,
                    "filters": [
                        {
                            "filterType": "criteria",
                            "column": "dnsQuestion",
                            "operator": "=~",
                            "value": domain
                        },
                        {
                            "filterType": "criteria",
                            "column": "localIP",
                            "operator": '=',
                            "value": source_ip
                        }
                    ]
                }
            }
        }
        response = self._http_request('POST', url_suffix, json_data=body)
        if response.get('error'):
            return_error(response.get('error'))
        if 'data' in response:
            return response.get('data')
        return {}

    def query_events(self, start_time: str, end_time: str, logic: str, column: str, value: str, entity_type: str):

        url_suffix = '/v2/events'
        body = {
            "dateRange": {
                "start": start_time,
                "end": end_time
            },
            "resultFields":
                ["endpointName", "eventType", "processStartTime", "parentName", "pid", "name", "path", "user", "hash",
                 " parameters"],

            "criteriaV3": {
                "relationshipFilter": None,
                "entityType": entity_type,
                "filter": {
                    "filterType": "composite",
                    "logic": logic,
                    "filters": [
                        {
                            "filterType": "criteria",
                            "column": column,
                            "operator": '=',
                            "value": value
                        }
                    ]
                }
            }
        }

        response = self._http_request('POST', url_suffix, json_data=body)
        if response.get('error'):
            return_error(response.get('error'))
        if 'data' in response:
            return response.get('data')
        return {}


def test_module(client: Client, *_):
    """
    Returning 'ok' indicates that the integration works like it is supposed to. Connection to the service is successful.
    """
    client.test_module_request()
    demisto.results('ok')
    return 'ok', {}, {}


def list_alerts_command(client: Client, args: dict):
    """get information about alerts. """

    skip = args.get('skip', 0)
    limit = args.get('limit', 50)
    sort = args.get('sort')
    facet_search = args.get('facet_search', '')
    start_date = args.get('start_date')
    end_date = args.get('end_date')
    headers = ['ID', 'Name', 'EndpointName', 'EndpointID', 'Source', 'ArtifactName', 'IntelName', 'Severity',
               'CreateDate', 'AlertDate']

    contents = []
    context = []
    response = client.list_alerts(skip, limit, sort, facet_search, start_date, end_date)

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

    return human_readable, entry_context, alerts


def host_info_command(client: Client, args: dict):
    ip = args.get('ip')

    contents = []
    context = []

    response = client.get_host_info(ip)
    hosts = response.get('data')
    if not hosts:
        return f'No hosts was found for ip address {ip}', {}, {}
    for host in hosts:
        contents.append({
            'HostName': host.get('hostName'),
            'ID': host.get('id'),
            'IpAddress': host.get('ipAddress'),
            'OS': host.get('os'),
            'ProcessorName': host.get('processorName'),
            'RamSize': host.get('ramSize'),
            'AgentID': host.get('agentId'),
            'AgentVersion': host.get('agentVersion'),
            'CreatedDate': host.get('createdDate')
        })

        context.append({
            'HostName': host.get('hostName'),
            'ID': host.get('id'),
            'IpAddress': host.get('ipAddress'),
            'Description': host.get('description'),
            'ActiveDirectoryID': host.get('activeDirectoryId'),
            'LastContactDate': host.get('lastContactDate'),
            'CreatedDate': host.get('createdDate'),
            'AgentID': host.get('agentId'),
            'AgentVersion': host.get('agentVersion'),
            'Groups': host.get('groups'),
            'OS': host.get('os'),
            'ProcessorName': host.get('processorName'),
            'RamSize': host.get('ramSize'),
            'AVEEnabled': host.get('aV_Enabled'),
            'AREnabled': host.get('aR_Enabled'),
            'IsDeleted': host.get('isDeleted'),
        })

    entry_context = {'FidelisEndpoint.Host(val.ID && val.ID === obj.ID)': context}
    human_readable = tableToMarkdown('Fidelis Endpoint Hosts Info', contents, removeNull=True)

    return human_readable, entry_context, hosts


def file_search(client: Client, args: dict):
    """ search for files on multiple hosts, using file hash, extension, file size, and other search criteria."""

    host = argToList(args.get('host'))
    md5 = argToList(args.get('md5'))
    file_extension = argToList(args.get('file_extension', ''))
    file_path = argToList(args.get('file_path', ''))
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


def file_search_status(client: Client, args: dict):
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

    return human_readable, entry_context, data


def file_search_reasult_metadata(client: Client, args: dict):
    """Get the job results metadata (max 50 results)"""

    job_id = args.get('job_id')
    job_result_id = args.get('job_result_id')

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
    human_readable = tableToMarkdown('Fidelis Endpoint file results metadata', contents, removeNull=True)

    return human_readable, entry_context, response


def get_file(client: Client, args: dict):
    file_id = args.get('file_id')
    response = client.get_file(file_id)
    attachment_file = fileResult('Fidelis_Endpoint.txt', response)

    return attachment_file


def delete_file_search_job(client: Client, args: dict):
    job_id = args.get('job_id')
    response = client.delete_job(job_id)

    return 'The job was successfully deleted', {}, response


def list_scripts_command(client: Client, *_):
    headers = ['ID', 'Name', 'Description']
    response = client.list_scripts()

    scripts = response.get('data', {}).get('scripts', [])
    contents = []
    for script in scripts:
        contents.append({
            'ID': script.get('id'),
            'Name': script.get('name'),
            'Description': script.get('description')
        })

    entry_context = {'FidelisEndpoint.Script(val.ID && val.ID === obj.ID)': contents}
    human_readable = tableToMarkdown('Fidelis Endpoint scripts', contents, headers)

    return human_readable, entry_context, scripts


def script_manifest_command(client: Client, args: dict):
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


def execute_script_command(client: Client, args: dict):
    script_id = args.get('script_id')
    time_out = args.get('time_out')
    endpoint_ip = argToList(args.get('endpoint_ip'))
    endpoints = client.convert_ip_to_endpoint_id(endpoint_ip)
    endpoint_id = endpoints.get('data')
    answer = args.get('answer')

    response = client.execute_script(script_id, endpoint_id, answer, time_out)
    context = {
        'ID': script_id,
        'JobID': response.get('data')
    }
    entry_context = {'FidelisEndpoint.Script(val.ID && val.ID === obj.ID)': context}

    return 'The job has been executed successfully', entry_context, response


def list_process_command(client: Client, args: dict):
    endpoint_ip = argToList(args.get('endpoint_ip'))
    endpoints = client.convert_ip_to_endpoint_id(endpoint_ip)
    endpoint_id = endpoints.get('data')
    time_out = args.get('time_out')
    opearting_system = args.get('opearting_system')
    script_id = ''

    if opearting_system == 'Windows':
        script_id = LIST_PROCESSES_WINDOWS

    if opearting_system == 'Linux':
        script_id = LIST_PROCESSES_LINUX

    if opearting_system == 'macOS':
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
    contents = []
    context = []
    for hit in hits:
        source_ = hit.get('_source')
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


def kill_process_by_pid(client: Client, args: dict):
    endpoint_ip = argToList(args.get('endpoint_ip'))
    endpoints = client.convert_ip_to_endpoint_id(endpoint_ip)
    endpoint_id = endpoints.get('data')
    time_out = args.get('time_out')
    opearting_system = args.get('opearting_system')
    pid = args.get('pid')
    script_id = ''

    if opearting_system == 'Windows':
        script_id = KILL_PROCESS_WINDOWS

    if opearting_system == 'Linux' or opearting_system == 'macOS':
        script_id = KILL_PROCESS_MAC_LINUX

    response = client.kill_process(script_id, pid, time_out, endpoint_id)
    context = {
        'ID': script_id,
        'JobID': response.get('data')
    }
    entry_context = {'FidelisEndpoint.Process(val.ID && val.ID === obj.ID)': context}

    return 'The job has been executed successfully', entry_context, response


def delete_file_command(client: Client, args: dict):
    endpoint_ip = argToList(args.get('endpoint_ip'))
    endpoints = client.convert_ip_to_endpoint_id(endpoint_ip)
    endpoint_id = endpoints.get('data')
    time_out = args.get('time_out')
    opearting_system = args.get('opearting_system')
    file_path = args.get('file_path')
    script_id = ''

    if opearting_system == 'Windows':
        script_id = DELETE_FILE_WINDOWS

    if opearting_system == 'Linux' or opearting_system == 'macOS':
        script_id = DELETE_FILE_MAC_LINUX

    response = client.delete_file(script_id, file_path, time_out, endpoint_id)
    context = {
        'ID': script_id,
        'JobID': response.get('data')
    }
    entry_context = {'FidelisEndpoint.Script(val.ID && val.ID === obj.ID)': context}

    return 'The job has been executed successfully', entry_context, response


def network_isolation_command(client: Client, args: dict):
    endpoint_ip = argToList(args.get('endpoint_ip'))
    endpoints = client.convert_ip_to_endpoint_id(endpoint_ip)
    endpoint_id = endpoints.get('data')
    time_out = args.get('time_out')
    opearting_system = args.get('opearting_system')
    allowed_server = args.get('allowed_server')
    script_id = ''

    if opearting_system == 'Windows':
        script_id = NETWORK_ISOLATION_WINDOWS

    if opearting_system == 'Linux' or opearting_system == 'macOS':
        script_id = NETWORK_ISOLATION_MAC_LINUX

    response = client.network_isolation(script_id, allowed_server, time_out, endpoint_id)
    context = {
        'ID': script_id,
        'JobID': response.get('data')
    }
    entry_context = {'FidelisEndpoint.Isolation(val.ID && val.ID === obj.ID)': context}

    return 'The job has been executed successfully', entry_context, response


def remove_network_isolation_command(client: Client, args: dict):
    endpoint_ip = argToList(args.get('endpoint_ip'))
    endpoints = client.convert_ip_to_endpoint_id(endpoint_ip)
    endpoint_id = endpoints.get('data')
    time_out = args.get('time_out')
    opearting_system = args.get('opearting_system')
    script_id = ''

    if opearting_system == 'Windows':
        script_id = REMOVE_NETWORK_ISOLATION_WINDOWS

    if opearting_system == 'Linux' or os == 'macOS':
        script_id = REMOVE_NETWORK_ISOLATION_MAC_LINUX

    response = client.remove_network_isolation(script_id, time_out, endpoint_id)
    context = {
        'ID': script_id,
        'JobID': response.get('data')
    }
    entry_context = {'FidelisEndpoint.Isolation(val.ID && val.ID === obj.ID)': context}

    return 'The job has been executed successfully', entry_context, response


def script_job_status(client: Client, args: dict):
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


def query_file_by_hash(client: Client, args: dict):
    start_time = args.get('start_time')
    end_time = args.get('end_time')
    logic = args.get('logic')
    file_hash = args.get('file_hash')
    if get_hash_type(file_hash) == 'Unknown':
        raise Exception('Enter a valid hash format.')
    contents = []
    context = []
    response = client.query_by_hash(start_time, end_time, logic, file_hash)
    events = response.get('events', [])

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
            "EventTime": event.get('eventTime'),
            "EndpointName": event.get('endpointName'),
            "EventType": event.get('eventType'),
            "ParentID": event.get('parentId'),
            "TargetID": event.get('targetId'),
            "ParentName": event.get('parentName'),
            "Name": event.get('name'),
            "Path": event.get('path'),
            "Hash": event.get('hash'),
            "Size": event.get('size'),
            "FileVersion": event.get('fileVersion'),
            "Signature": event.get('signature'),
            "SignedTime": event.get('signedTime'),
            "CertificateSubjectName": event.get('certificateSubjectName'),
            "CertificateIssuerName": event.get('certificateIssuerName'),
            "CertificatePublisher": event.get('certificatePublisher'),
            "HashSHA1": event.get('hashSHA1'),
            "HashSHA256": event.get('hashSHA256'),
            "ProcessStartTime": event.get('processStartTime'),
            "EventIndex": event.get('eventIndex'),
            "IndexingTime": event.get('indexingTime'),
            "FileExtension": event.get('fileExtension'),
            "FileType": event.get('fileType'),
            "FileCategory": event.get('fileCategory'),
            "EntityType": event.get('entityType'),
            "StartTime": event.get('startTime')
        })

    entry_context = {'FidelisEndpoint.Query(val.Hash && val.Hash === obj.Hash)': context}
    human_readable = tableToMarkdown('Fidelis Endpoint file hash query results', contents, removeNull=True)
    return human_readable, entry_context, events


def query_process_name_command(client: Client, args: dict):
    start_time = args.get('start_time')
    end_time = args.get('end_time')
    logic = args.get('logic')
    process_name = args.get('process_name')
    contents = []
    context = []

    response = client.query_by_process_name(start_time, end_time, logic, process_name)
    events = response.get('events', [])

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
    human_readable = tableToMarkdown('Fidelis Endpoint process results', contents, removeNull=True)
    return human_readable, entry_context, events


def query_connection_by_remote_ip(client: Client, args: dict):
    start_time = args.get('start_time')
    end_time = args.get('end_time')
    logic = args.get('logic')
    remote_ip = args.get('remote_ip')
    contents = []
    context = []

    response = client.query_by_remote_ip(start_time, end_time, logic, remote_ip)
    events = response.get('events', [])

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
    return human_readable, entry_context, events


def query_dns_request(client: Client, args: dict):
    start_time = args.get('start_time')
    end_time = args.get('end_time')
    logic = args.get('logic')
    url = args.get('url')
    contents = []
    context = []

    response = client.query_by_dns_request(start_time, end_time, logic, url)
    events = response.get('events', [])

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
    return human_readable, entry_context, events


def query_by_server_ip(client: Client, args: dict):
    start_time = args.get('start_time')
    end_time = args.get('end_time')
    logic = args.get('logic')
    remote_ip = args.get('remote_ip')
    contents = []
    context = []

    response = client.query_by_dns_server_ip(start_time, end_time, logic, remote_ip)
    events = response.get('events', [])

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
    return human_readable, entry_context, events


def query_by_source_ip(client: Client, args: dict):
    start_time = args.get('start_time')
    end_time = args.get('end_time')
    logic = args.get('logic')
    source_ip = args.get('source_ip')
    domain = args.get('domain')
    contents = []
    context = []

    response = client.query_by_dns_source_ip(start_time, end_time, logic, source_ip, domain)
    events = response.get('events', [])

    for event in events:
        contents.append({
            'EndpointName': event.get('endpointName'),
            'EventType': event.get('eventType'),
            'ParentID': event.get('parentId'),
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
    human_readable = tableToMarkdown('Fidelis Endpoint query results for the DNS request by source IP', contents,
                                     removeNull=True)
    return human_readable, entry_context, events


def query_events(client: Client, args: dict):
    start_time = args.get('start_time')
    end_time = args.get('end_time')
    logic = args.get('logic')
    entity_type = args.get('entity_type')
    column = args.get('column')
    value = args.get('value')
    contents = []
    context = []

    response = client.query_events(start_time, end_time, logic, column, value, entity_type)
    events = response.get('events', [])

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
    return human_readable, entry_context, events


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
            demisto.results(get_file(client, demisto.args()))

        elif demisto.command() == 'fidelis-endpoint-delete-file-search-job':
            return_outputs(*delete_file_search_job(client, demisto.args()))

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
            return_outputs(*query_connection_by_remote_ip(client, demisto.args()))

        elif demisto.command() == 'fidelis-endpoint-query-by-dns':
            return_outputs(*query_dns_request(client, demisto.args()))

        elif demisto.command() == 'fidelis-endpoint-query-dns-by-server-ip':
            return_outputs(*query_by_server_ip(client, demisto.args()))

        elif demisto.command() == 'fidelis-endpoint-query-dns-by-source-ip':
            return_outputs(*query_by_source_ip(client, demisto.args()))

        elif demisto.command() == 'fidelis-endpoint-query-events':
            return_outputs(*query_events(client, demisto.args()))

    # Log exceptions
    except Exception as e:
        return_error(f'Failed to execute {demisto.command()} command. Error: {str(e)}')


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
