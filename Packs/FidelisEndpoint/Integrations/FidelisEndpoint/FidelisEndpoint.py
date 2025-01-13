import demistomock as demisto
from CommonServerPython import *  # noqa: E402 lgtm [py/polluting-import]
from CommonServerUserPython import *  # noqa: E402 lgtm [py/polluting-import]


import urllib3

urllib3.disable_warnings()

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

    def __init__(self, server_url: str, username: str, password: str, verify: bool, proxy: bool):
        super().__init__(base_url=server_url, verify=verify, proxy=proxy)
        token = self._generate_token(username, password)
        self._headers = {'Authorization': f'Bearer {token}'}

    def _generate_token(self, username: str, password: str) -> str:
        """Generate a token
        Arguments:
            username {str} -- Fidelis username to retrieve token with
            password {str} -- Fidelis password to retrieve token with
        Returns:
            token valid for 10 minutes
        """
        params = {
            'username': username,
            'password': password
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

    def list_alerts(self, limit: str = None, sort: str = None, start_date=None, end_date=None) -> dict:

        url_suffix = '/alerts/getalertsV2'
        params = assign_params(
            take=limit,
            sort=sort,
            startDate=start_date,
            endDate=end_date
        )

        return self._http_request('GET', url_suffix, params=params)

    def get_host_info(self, host_name: str, ip_address: str) -> dict:
        url_suffix = '/endpoints/v2/0/100/hostname Ascending'
        if host_name:
            field_name = 'HostName'
            value = host_name

        elif ip_address:
            field_name = 'IpAddress'
            value = ip_address

        else:
            field_name = ''
            value = ''
            demisto.debug(f"No host_name or ip_address -> {field_name=} {value=}")

        params = {
            'accessType': '3',
            'search': json.dumps({
                'searchFields': [{
                    'fieldName': field_name,
                    'values': [{
                        'value': value
                    }]
                }]
            })
        }

        return self._http_request('GET', url_suffix, params=params)

    def search_file(self, host=None, md5=None, file_extension=None, file_path=None, file_size=None) -> dict:

        url_suffix = '/files/search'
        body = assign_params(
            hosts=host,
            md5Hashes=md5,
            fileExtensions=file_extension,
            filePathHints=file_path,
            fileSize=file_size
        )

        return self._http_request('POST', url_suffix, json_data=body)

    def file_search_status(self, job_id: str = None, job_result_id: str = None) -> dict:

        url_suffix = f'/jobs/getjobstatus/{job_id}/{job_result_id}'

        return self._http_request('GET', url_suffix)

    def file_search_results_metadata(self, job_id: str = None, job_result_id: str = None) -> dict:

        url_suffix = f'/jobs/{job_id}/jobresults/{job_result_id}'

        return self._http_request('GET', url_suffix)

    def get_file(self, file_id: str = None) -> str | bytes:

        url_suffix = f'/files/{file_id}'

        return self._http_request('GET', url_suffix, resp_type='content')

    def delete_job(self, job_id: str = None) -> dict:

        url_suffix = f'/jobs/{job_id}'

        return self._http_request('DELETE', url_suffix)

    def list_scripts(self) -> dict:

        url_suffix = '/packages'

        return self._http_request('GET', url_suffix)

    def script_manifest(self, script_id: str = None) -> dict:

        url_suffix = f'/packages/{script_id}?type=Manifest'

        return self._http_request('GET', url_suffix)

    def execute_script(self, script_id: str = None, endpoint_ip: str = None, answer: str | int = '',
                       time_out: int = None, additional_answer: None | str = None) -> dict:

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

    def convert_ip_to_endpoint_id(self, ip: list = None) -> dict:

        url_suffix = '/endpoints/endpointidsbyip'

        body = ip

        return self._http_request('POST', url_suffix, json_data=body)

    def convert_name_to_endpoint_id(self, endpoint_name: list = None) -> dict:

        url_suffix = '/endpoints/endpointidsbyname'

        body = endpoint_name

        return self._http_request('POST', url_suffix, json_data=body)

    def list_process(self, script_id: str = None, time_out: int = None, endpoint_id: str = None) -> dict:

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

    def script_job_results(self, job_id: str = None) -> dict:

        url_suffix = f'/jobresults/{job_id}'

        return self._http_request('POST', url_suffix)

    def kill_process(self, script_id: str = None, pid: int = None, time_out: int = None,
                     endpoint_ip=None) -> dict:

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

    def delete_file(self, script_id: str = None, file_path: str = None, time_out: int = None, endpoint_ip=None) -> dict:

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
                          endpoint_ip=None) -> dict:

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

    def remove_network_isolation(self, script_id: str = None, time_out: int = None, endpoint_ip: list = None) -> dict:

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

    def get_script_job_status(self, job_result_id: str = None) -> dict:

        url_suffix = f'/jobs/getjobtargets/{job_result_id}'

        return self._http_request('GET', url_suffix)

    def query_file_by_hash(self, limit: str = None, start_time: str = None, end_time: str = None, logic: str = None,
                           file_hash: str = None) -> dict:

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

    def query_by_process_name(self, limit: str = None, start_time: str = None,
                              end_time: str = None, logic: str = None,
                              process_name: str = None) -> dict:

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

    def query_by_remote_ip(self, limit: str = None, start_time: str = None,
                           end_time: str = None, logic: str = None, remote_ip: str = None) -> dict:

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

    def query_by_dns_request(self, limit: str = None, start_time: str = None,
                             end_time: str = None, logic: str = None, url: str = None) -> dict:

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

    def query_by_dns_server_ip(self, limit: str = None, start_time: str = None,
                               end_time: str = None, logic: str = None,
                               remote_ip: str = None) -> dict:

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

    def query_by_dns_source_ip(self, limit: str = None, start_time: str = None,
                               end_time: str = None, logic: str = None, source_ip: str = None,
                               domain: str = None) -> dict:

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

    def query_events(self, limit: str = None, start_time: str = None,
                     end_time: str = None, logic: str = None, column: str = None,
                     value: str = None, entity_type: str = None, operator: str = None,
                     additional_filter: dict = None) -> dict:

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
            body['criteriaV3']['filter']['filters'].append(additional_filter)  # type: ignore

        response = self._http_request('POST', url_suffix, params=params, json_data=body)
        if response.get('error'):
            raise Exception(response.get('error'))

        return response


def get_endpoint_id(client: Client, endpoint_ip: list = None, endpoint_name: list = None):
    if endpoint_name and endpoint_ip:
        raise Exception('You must provide only one of the arguments endpoint_ip or endpoint_name')

    if not endpoint_ip and not endpoint_name:
        raise Exception('You must provide either endpoint_ip or endpoint_name')

    if endpoint_ip:
        endpoints = client.convert_ip_to_endpoint_id(endpoint_ip)
        endpoint_id = endpoints.get('data')

    elif endpoint_name:
        endpoints = client.convert_name_to_endpoint_id(endpoint_name)
        endpoint_id = endpoints.get('data')

    else:
        endpoint_id = {}
        demisto.debug(f"No endpoint_ip or endpoint_name -> {endpoint_id=}")

    return endpoint_id


def test_module(client: Client, fetch_limit: str, *_) -> tuple[str, dict, dict]:
    """
    Returning 'ok' indicates that the integration works like it is supposed to. Connection to the service is successful.
    """
    client.test_module_request()
    if demisto.params().get('isFetch') and int(fetch_limit) < 5:
        return 'Fetch limit must be at lest 5', {}, {}
    return 'ok', {}, {}


def list_alerts_command(client: Client, args: dict) -> tuple[str, dict, dict]:
    limit = args.get('limit', '50')
    sort = args.get('sort')
    start_date = args.get('start_date')
    end_date = args.get('end_date')
    headers = ['ID', 'Name', 'EndpointName', 'EndpointID', 'Source', 'ArtifactName', 'IntelName', 'Severity',
               'CreateDate', 'AlertDate']

    contents = []
    context = []
    response = client.list_alerts(limit, sort, start_date, end_date)
    if not response.get('success'):
        raise Exception(response.get('error'))

    alerts = response.get('data', {}).get('entities', [])
    if not alerts:
        return 'No alerts were found.', {}, {}

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


def host_info_command(client: Client, args: dict) -> tuple[str, dict, dict]:

    ip_address = args.get('ip_address', '')
    host = args.get('host', '')

    if not host and not ip_address:
        raise Exception('You must provide either ip_address or host')

    contents = []
    context_standards = []
    headers = ['ID', 'HostName', 'IpAddress', 'OS', 'MacAddress', 'Isolated', 'LastContactDate', 'AgentInstalled',
               'AgentVersion', 'OnNetwork', 'AV_Enabled', 'Groups', 'ProcessorName']
    response = client.get_host_info(host, ip_address)
    if not response.get('success'):
        raise Exception(response.get('error'))
    hosts = response.get('data', {})
    if not hosts:
        return 'No hosts was found', {}, {}

    host_info = hosts.get('entities', [])
    if not host_info:
        return 'No entities were found for the host', {}, {}
    for host in host_info:
        contents.append({
            'Hostname': host.get('hostName'),
            'ID': host.get('id'),
            'IPAddress': host.get('ipAddress'),
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
            'Hostname': host.get('hostName'),
            'ID': host.get('id'),
            'IPAddress': host.get('ipAddress'),
            'OS': host.get('os'),
            'MACAddress': host.get('macAddress'),
            'Processor': host.get('processorName')
        })

    entry_context = {
        'FidelisEndpoint.Host(val.ID && val.ID === obj.ID)': contents,
        'Endpoint(val.ID && val.ID === obj.ID)': context_standards
    }
    human_readable = tableToMarkdown('Fidelis Endpoint Host Info', contents, headers=headers, removeNull=True)

    return human_readable, entry_context, response


def file_search(client: Client, args: dict) -> tuple[str, dict, dict]:
    """ Search for files on multiple hosts, using file hash, extension, file size, and other search criteria."""

    host = argToList(args.get('host', ['']))
    md5 = argToList(args.get('md5'))
    file_extension = argToList(args.get('file_extension'))
    file_path = argToList(args.get('file_path'))
    try:
        file_size = {
            'value': int(args.get('file_size')),  # type: ignore
            'quantifier': 'greaterThan'
        }
    except Exception as e:
        raise Exception(e)

    response = client.search_file(host, md5, file_extension, file_path, file_size)
    if not response.get('success'):
        raise Exception(response.get('error'))
    data = response.get('data', {})
    contents = {
        'JobID': data.get('jobId'),
        'JobResultID': data.get('jobResultId')
    }

    entry_context = {'FidelisEndpoint.FileSearch(val.JobID && val.JobID === obj.JobID)': contents}
    human_readable = tableToMarkdown('Fidelis Endpoint file search', contents)

    return human_readable, entry_context, response


def file_search_status(client: Client, args: dict) -> tuple[str, dict, dict]:
    """Get the file search job status"""

    job_id = args.get('job_id')
    job_result_id = args.get('job_result_id')

    response = client.file_search_status(job_id, job_result_id)
    if not response.get('success'):
        raise Exception(response.get('error'))
    data = response.get('data', {})
    if not data:
        return 'Could not find any data for this Job ID', {}, {}
    contents = {
        'JobID': job_id,
        'JobResultID': job_result_id,
        'Status': data.get('status', 'Unclassified')
    }
    status = data.get('status')

    entry_context = {'FidelisEndpoint.FileSearch(val.JobID && val.JobID === obj.JobID)': contents}

    human_readable = f'Fidelis Endpoint file search status is: {status}'

    return human_readable, entry_context, response


def file_search_reasult_metadata(client: Client, args: dict) -> tuple[str, dict, dict]:
    """Get the job results metadata"""

    job_id = args.get('job_id')
    job_result_id = args.get('job_result_id')
    headers = ['ID', 'FileName', 'FilePath', 'MD5Hash', 'FileSize', 'HostName', 'HostIP', 'AgentID']

    response = client.file_search_results_metadata(job_id, job_result_id)
    if not response.get('success'):
        return 'Could not find results for this job ID.', {}, {}
    data = response.get('data', {}).get('jobResultInfos', [])
    if not data:
        return 'No results found.\nCheck the job status, it might be still running.', {}, {}
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
        outputPaths['file']: file_standards
    }
    human_readable = tableToMarkdown('Fidelis Endpoint file results metadata', contents, headers=headers, removeNull=True)

    return human_readable, entry_context, response


def get_file_command(client: Client, args: dict):
    file_id: str = args.get('file_id', '')
    file_name: str = args.get('file_name', '')
    response = client.get_file(file_id)
    attachment_file = fileResult(file_name, response)

    return attachment_file


def delete_file_search_job_command(client: Client, args: dict) -> tuple[str, dict, dict]:
    job_id = args.get('job_id')
    response = client.delete_job(job_id)
    if not response.get('success'):
        raise Exception(response.get('error'))

    return 'The job was successfully deleted', {}, response


def list_scripts_command(client: Client, *_) -> tuple[str, dict, dict]:
    headers = ['ID', 'Name', 'Description']
    response = client.list_scripts()
    if not response.get('success'):
        raise Exception(response.get('error'))
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


def script_manifest_command(client: Client, args: dict) -> tuple[str, dict, dict]:
    script_id = args.get('script_id')
    headers = ['ID', 'Name', 'Description', 'Platform', 'Command', 'Questions', 'Priority', 'TimeoutSeconds',
               'ResultColumns', 'ImpersonationUser', 'ImpersonationPassword', 'WizardOverridePassword']
    response = client.script_manifest(script_id)
    if not response.get('success'):
        raise Exception(response.get('error'))
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


def execute_script_command(client: Client, args: dict) -> tuple[str, dict, dict]:
    script_id = args.get('script_id')
    time_out = args.get('time_out')
    endpoint_ip = argToList(args.get('endpoint_ip'))
    endpoint_name = argToList(args.get('endpoint_name'))
    answer = args.get('answer') or ''
    additional_answer = args.get('additional_answer', '')
    endpoint_id = get_endpoint_id(client, endpoint_ip, endpoint_name)

    response = client.execute_script(script_id, endpoint_id, answer, time_out, additional_answer)
    if not response.get('success'):
        raise Exception(response.get('error'))
    job_id = response.get('data')
    context = {
        'ID': script_id,
        'JobID': job_id
    }
    entry_context = {'FidelisEndpoint.Script(val.ID && val.ID === obj.ID)': context}

    return f'The job has been executed successfully. \n Job ID: {job_id}', entry_context, response


def list_process_command(client: Client, args: dict) -> tuple[str, dict, dict]:
    endpoint_ip = argToList(args.get('endpoint_ip'))
    endpoint_name = argToList(args.get('endpoint_name'))
    endpoint_id = get_endpoint_id(client, endpoint_ip, endpoint_name)
    time_out = args.get('time_out')
    operating_system = args.get('operating_system')
    script_id = ''

    if operating_system == 'Windows':
        script_id = LIST_PROCESSES_WINDOWS

    elif operating_system == 'Linux':
        script_id = LIST_PROCESSES_LINUX

    elif operating_system == 'macOS':
        script_id = LIST_PROCESSES_MACOS

    response = client.list_process(script_id, time_out, endpoint_id)
    if not response.get('success'):
        raise Exception(response.get('error'))
    job_id = response.get('data')
    context = {
        'ID': script_id,
        'JobID': job_id
    }
    entry_context = {'FidelisEndpoint.Process(val.ID && val.ID === obj.ID)': context}

    return f'The job has been executed successfully. \n Job ID: {job_id}', entry_context, response


def get_script_result(client: Client, args: dict):
    job_id = args.get('job_id')
    headers = ['ID', 'Name', 'EndpointID', 'EndpointName', 'PID', 'User', 'SHA1', 'MD5', 'Path', 'WorkingDirectory',
               'StartTime']

    response = client.script_job_results(job_id)
    if not response.get('success'):
        raise Exception(response.get('error'))
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


def kill_process_by_pid(client: Client, args: dict) -> tuple[str, dict, dict]:
    endpoint_ip = argToList(args.get('endpoint_ip'))
    endpoint_name = argToList(args.get('endpoint_name'))
    endpoint_id = get_endpoint_id(client, endpoint_ip, endpoint_name)
    time_out = args.get('time_out')
    operating_system = args.get('operating_system')
    pid = args.get('pid')
    script_id = ''

    if operating_system == 'Windows':
        script_id = KILL_PROCESS_WINDOWS

    elif operating_system == 'Linux' or operating_system == 'macOS':
        script_id = KILL_PROCESS_MAC_LINUX

    response = client.kill_process(script_id, pid, time_out, endpoint_id)
    if not response.get('success'):
        raise Exception(response.get('error'))
    job_id = response.get('data')
    context = {
        'ID': script_id,
        'JobID': job_id
    }
    entry_context = {'FidelisEndpoint.Process(val.ID && val.ID === obj.ID)': context}

    return f'The job has been executed successfully. \n Job ID: {job_id}', entry_context, response


def delete_file_command(client: Client, args: dict) -> tuple[str, dict, dict]:
    endpoint_ip = argToList(args.get('endpoint_ip'))
    endpoint_name = argToList(args.get('endpoint_name'))
    endpoint_id = get_endpoint_id(client, endpoint_ip, endpoint_name)
    time_out = args.get('time_out')
    operating_system = args.get('operating_system')
    file_path = args.get('file_path')
    script_id = ''

    if operating_system == 'Windows':
        script_id = DELETE_FILE_WINDOWS

    elif operating_system == 'Linux' or operating_system == 'macOS':
        script_id = DELETE_FILE_MAC_LINUX

    response = client.delete_file(script_id, file_path, time_out, endpoint_id)
    if not response.get('success'):
        raise Exception(response.get('error'))
    job_id = response.get('data')
    context = {
        'ID': script_id,
        'JobID': job_id
    }
    entry_context = {'FidelisEndpoint.Script(val.ID && val.ID === obj.ID)': context}

    return f'The job has been executed successfully. \n Job ID: {job_id}', entry_context, response


def network_isolation_command(client: Client, args: dict) -> tuple[str, dict, dict]:
    endpoint_ip = argToList(args.get('endpoint_ip'))
    endpoint_name = argToList(args.get('endpoint_name'))
    endpoint_id = get_endpoint_id(client, endpoint_ip, endpoint_name)
    time_out = args.get('time_out')
    operating_system = args.get('operating_system')
    allowed_server = args.get('allowed_server')
    script_id = ''

    if operating_system == 'Windows':
        script_id = NETWORK_ISOLATION_WINDOWS

    elif operating_system == 'Linux' or operating_system == 'macOS':
        script_id = NETWORK_ISOLATION_MAC_LINUX

    response = client.network_isolation(script_id, allowed_server, time_out, endpoint_id)
    if not response.get('success'):
        raise Exception(response.get('error'))
    job_id = response.get('data')
    context = {
        'ID': script_id,
        'JobID': job_id
    }
    entry_context = {'FidelisEndpoint.Isolation(val.ID && val.ID === obj.ID)': context}

    return f'The job has been executed successfully. \n Job ID: {job_id}', entry_context, response


def remove_network_isolation_command(client: Client, args: dict) -> tuple[str, dict, dict]:
    endpoint_ip = argToList(args.get('endpoint_ip'))
    endpoint_name = argToList(args.get('endpoint_name'))
    endpoint_id = get_endpoint_id(client, endpoint_ip, endpoint_name)
    time_out = args.get('time_out')
    operating_system = args.get('operating_system')
    script_id = ''

    if operating_system == 'Windows':
        script_id = REMOVE_NETWORK_ISOLATION_WINDOWS

    elif operating_system in {'Linux', 'macOS'}:
        script_id = REMOVE_NETWORK_ISOLATION_MAC_LINUX

    response = client.remove_network_isolation(script_id, time_out, endpoint_id)
    if not response.get('success'):
        raise Exception(response.get('error'))
    job_id = response.get('data')
    context = {
        'ID': script_id,
        'JobID': job_id
    }
    entry_context = {'FidelisEndpoint.Isolation(val.ID && val.ID === obj.ID)': context}

    return f'The job has been executed successfully. \n Job ID: {job_id}', entry_context, response


def script_job_status(client: Client, args: dict) -> tuple[str, dict, dict]:
    job_result_id = args.get('job_result_id')
    contents = []
    response = client.get_script_job_status(job_result_id)
    if not response.get('success'):
        raise Exception(response.get('error'))

    results = response.get('data', {}).get('targets', [])

    for result in results:
        contents.append({
            'JobResultID': result.get('jobResultId'),
            'Name': result.get('name'),
            'Status': result.get('status'),
            'JobName': response.get('data', {}).get('jobName')  # type: ignore
        })
    entry_context = {'FidelisEndpoint.ScriptResult(val.JobResultID && val.JobResultID === obj.JobResultID)': contents}
    human_readable = tableToMarkdown('Fidelis Endpoint script job status', contents, removeNull=True)

    return human_readable, entry_context, response


def query_file_by_hash_command(client: Client, args: dict) -> tuple[str, dict, dict]:
    start_time = args.get('start_time')
    end_time = args.get('end_time')
    logic = args.get('logic')
    file_hash = args.get('file_hash')
    limit = args.get('limit')
    if get_hash_type(file_hash) == 'Unknown':
        raise Exception('Enter a valid hash format.')
    contents = []
    context = []
    file_standards = []
    headers = ['PID', 'EndpointName', 'Name', 'Path', 'User', 'Hash', 'ProcessStartTime', 'Parameters', 'ParentName',
               'EventType']
    response = client.query_file_by_hash(limit, start_time, end_time, logic, file_hash)
    if not response.get('success'):
        raise Exception(response.get('error'))
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

        file_standards.append({
            'Name': event.get('name'),
            'Size': event.get('size'),
            'MD5': event.get('hash'),
            'Extension': event.get('fileExtension'),
            'Type': event.get('fileType'),
            'Path': event.get('path'),
            'Hostname': event.get('endpointName'),
            'SHA1': event.get('hashSHA1'),
            'SHA256': event.get('hashSHA256'),
            'FileVersion': event.get('fileVersion')
        })

    entry_context = {
        'FidelisEndpoint.Query(val.Hash && val.Hash === obj.Hash)': context,
        outputPaths['file']: file_standards
    }
    human_readable = tableToMarkdown('Fidelis Endpoint file hash query results', contents, headers=headers,
                                     removeNull=True)
    return human_readable, entry_context, response


def query_process_name_command(client: Client, args: dict) -> tuple[str, dict, dict]:
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
    if not response.get('success'):
        raise Exception(response.get('error'))
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


def query_connection_by_remote_ip_command(client: Client, args: dict) -> tuple[str, dict, dict]:
    start_time = args.get('start_time')
    end_time = args.get('end_time')
    logic = args.get('logic')
    remote_ip = args.get('remote_ip')
    limit = args.get('limit')
    contents = []
    context = []
    headers = ['EndpointID', 'EndpointName', 'PPID', 'LocalIP', 'LocalPort', 'RemoteIP', 'RemotePort',
               'ProcessStartTime', 'FirstEventTime', 'LastEventTime', 'Protocol', 'ParentHashSHA1', 'ParentName',
               'EventType']

    response = client.query_by_remote_ip(limit, start_time, end_time, logic, remote_ip)
    if not response.get('success'):
        raise Exception(response.get('error'))
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
                                     headers=headers, removeNull=True)
    return human_readable, entry_context, response


def query_dns_request_command(client: Client, args: dict) -> tuple[str, dict, dict]:
    start_time = args.get('start_time')
    end_time = args.get('end_time')
    logic = args.get('logic')
    url = args.get('url')
    limit = args.get('limit')
    contents = []
    context = []
    headers = ['EndpointName', 'LocalIP', 'LocalPort', 'RemoteIP', 'RemotePort', 'ProcessStartTime', 'DnsAnswer',
               'EventType']

    response = client.query_by_dns_request(limit, start_time, end_time, logic, url)
    if not response.get('success'):
        raise Exception(response.get('error'))
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
    human_readable = tableToMarkdown('Fidelis Endpoint query results for the DNS request', contents, headers=headers,
                                     removeNull=True)
    return human_readable, entry_context, response


def query_by_server_ip_command(client: Client, args: dict) -> tuple[str, dict, dict]:
    start_time = args.get('start_time')
    end_time = args.get('end_time')
    logic = args.get('logic')
    remote_ip = args.get('remote_ip')
    limit = args.get('limit')
    contents = []
    context = []
    headers = ['EndpointName', 'LocalIP', 'LocalPort', 'RemoteIP', 'RemotePort', 'ProcessStartTime', 'DnsAnswer',
               'EventType']

    response = client.query_by_dns_server_ip(limit, start_time, end_time, logic, remote_ip)
    if not response.get('success'):
        raise Exception(response.get('error'))
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
                                     headers=headers, removeNull=True)
    return human_readable, entry_context, response


def query_by_source_ip(client: Client, args: dict) -> tuple[str, dict, dict]:
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
    if not response.get('success'):
        raise Exception(response.get('error'))
    res = response.get('data', {})
    events = res.get('events', [])
    if not events:
        return 'No events were found', {}, {}

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


def query_events_command(client: Client, args: dict) -> tuple[str, dict, dict]:
    start_time = args.get('start_time')
    end_time = args.get('end_time')
    logic = args.get('logic')
    entity_type = args.get('entity_type')
    column = args.get('column')
    value = args.get('value')
    operator = args.get('operator')
    limit = args.get('limit')
    additional_filter_string = args.get('additional_filter')
    additional_filter = None
    if additional_filter_string:
        additional_filter_split = additional_filter_string.split()
        if len(additional_filter_split) == 3:
            additional_filter = {
                'filterType': 'criteria',
                'column': additional_filter_split[0],
                'operator': additional_filter_split[1],
                'value': additional_filter_split[2]
            }
        else:
            raise Exception('Make sure that the additional_filter argument is in valid format.\n '
                            'For Example: pid = 1234')

    contents = []
    context = []
    headers = ['PID', 'EndpointName', 'User', 'ProcessStartTime', 'LocalIP', 'LocalPort', 'RemoteIP', 'RemotePort',
               'ParentID', 'EventType']
    response = client.query_events(limit, start_time, end_time, logic, column, value, entity_type, operator,
                                   additional_filter)
    if not response.get('success'):
        raise Exception(response.get('error'))
    res = response.get('data', {})
    events = res.get('events', [])
    if not events:
        return 'No events were found', {}, {}

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
    human_readable = tableToMarkdown('Fidelis Endpoint query events result', contents, headers=headers,
                                     removeNull=True)
    return human_readable, entry_context, response


def fetch_incidents(client: Client, fetch_time: str, fetch_limit: str, last_run: dict) -> tuple[list, dict]:
    last_fetched_alert_create_time = last_run.get('last_fetched_alert_create_time')
    last_fetched_alert_id = last_run.get('last_fetched_alert_id', '')
    if not last_fetched_alert_create_time:
        last_fetched_alert_create_time, _ = parse_date_range(fetch_time, date_format='%Y-%m-%dT%H:%M:%S.000Z')
        last_fetched_alert_id = '0'
    latest_alert_create_date = last_fetched_alert_create_time
    latest_alert_id = last_fetched_alert_id

    incidents = []

    response = client.list_alerts(
        limit=fetch_limit,
        sort='createDate Ascending',
        start_date=last_fetched_alert_create_time
    )
    alerts = response.get('data', {}).get('entities', [])

    for alert in alerts:
        alert_id = alert.get('id')
        if alert_id <= int(last_fetched_alert_id):
            # got an alert we already fetched, skipping it
            continue
        alert_id = str(alert_id)
        alert_create_date = alert.get('createDate')
        incident = {
            'name': f'Fidelis Endpoint alert {alert_id}',
            'occurred': alert_create_date,
            'rawJSON': json.dumps(alert)
        }
        incidents.append(incident)
        latest_alert_create_date = alert_create_date
        latest_alert_id = alert_id

    return incidents, \
        {'last_fetched_alert_create_time': latest_alert_create_date, 'last_fetched_alert_id': latest_alert_id}


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

    LOG(f'Command being called is {demisto.command()}')
    try:
        client = Client(base_url, username=username, password=password, verify=verify_certificate, proxy=proxy)

        if demisto.command() == 'test-module':
            # This is the call made when pressing the integration Test button.
            fetch_limit = demisto.params().get('fetch_limit')
            return_outputs(*test_module(client, fetch_limit))
        elif demisto.command() == 'fetch-incidents':
            fetch_time = demisto.params().get('fetch_time', '3 days')
            fetch_limit = demisto.params().get('fetch_limit', '50')
            incidents, last_run = fetch_incidents(client, fetch_time, fetch_limit, last_run=demisto.getLastRun())  # type: ignore
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
            return_outputs(*query_file_by_hash_command(client, demisto.args()))

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
            return_outputs(*query_events_command(client, demisto.args()))

    # Log exceptions
    except Exception as e:
        err_msg = str(e)
        if 'password=' in err_msg:
            err_msg = re.sub(r'password=([^\s]*)\s', 'password=**** ', err_msg)
        return_error(f'Failed to execute {demisto.command()} command. Error: {err_msg}')


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
