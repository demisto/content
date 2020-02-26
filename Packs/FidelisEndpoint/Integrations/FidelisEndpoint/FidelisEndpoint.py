import demistomock as demisto
from CommonServerPython import *  # noqa: E402 lgtm [py/polluting-import]
from CommonServerUserPython import *  # noqa: E402 lgtm [py/polluting-import]
# IMPORTS

import json
import requests


# Disable insecure warnings
requests.packages.urllib3.disable_warnings()


class Client(BaseClient):
    """
    Client to use in the Fidelis Endpoint integration. Overrides BaseClient
    """
    def __init__(self, server_url: str, username: str, password: str, verify: bool, proxy: bool, headers: dict):

        super().__init__(base_url=server_url, verify=verify)
        self._username = username
        self._password = password
        self._proxies = handle_proxy() if proxy else None
        self._token = self._generate_token()
        self._headers = headers

        if self._token:
            token = self._token['data'].get('token')
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
        token = self._http_request('GET', '/authenticate', params=params)

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

        return self._http_request('GET', url_suffix)

    def delete_job(self, job_id):

        url_suffix = f'/jobs/{job_id}'

        return self._http_request('DELETE', url_suffix)

    def list_scripts(self):

        url_suffix = '/packages'

        return self._http_request('GET', url_suffix)

    def script_manifest(self, script_id: str):

        url_suffix = f'/packages/{script_id}?type=Manifest'

        return self._http_request('GET', url_suffix)

    def execute_script(self, script_id: str, endpoint_ip: str, question: str, time_out: int):

        url_suffix = '/jobs/createTask'
        body = assign_params(
            scriptPackageId=script_id,
            hosts=endpoint_ip,
            questions=question,
            timeoutInSeconds=time_out
        )

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


def test_module(client: Client, *_):
    """
    Returning 'ok' indicates that the integration works like it is supposed to. Connection to the service is successful.

    Args:
        client: HelloWorld client

    Returns:
        'ok' if test passed, anything else will fail the test.
    """

    client.test_module_request()
    demisto.results('ok')
    return '', {}, {}


def list_alerts_command(client: Client, args: dict):
    """get information about alerts. """

    skip = args.get('skip', 0)
    limit = args.get('limit')
    sort = args.get('sort')
    facet_search = args.get('facet_search')
    start_date = args.get('start_date')
    end_date = args.get('end_date')
    headers = ['Name', 'EndpointName', 'EndpointID', 'Source', 'ArtifactName', 'IntelName', 'Severity', 'ID',
               'AlertDate']

    contents = []
    context = []

    response = client.list_alerts(skip, limit, sort, facet_search, start_date, end_date)

    alerts = response.get('data').get('entities')
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
        return f'No hosts was found for ip {ip}', {}, {}
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
    data = response.get('data')
    contents = {
        'JobID': data.get('jobId'),
        'JobResultID': data.get('jobResultId')
    }

    entry_context = {'FidelisEndpoint.FileSearch(val.JobID && val.JobID === obj.JobID)': contents}
    human_readable = tableToMarkdown('Fidelis Endpoint file search', contents)

    return human_readable, entry_context, response


def file_seatch_status(client: Client, args: dict):
    """Get the file search job status"""

    job_id = args.get('job_id')
    job_result_id = args.get('job_result_id')

    response = client.file_search_status(job_id, job_result_id)
    data = response.get('data')
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
    data = response.get('data').get('jobResultInfos')
    contents = {}
    file_standards = {}
    for item in data:
        if item.get('collectedFiles'):
            collected_files = item.get('collectedFiles')
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
    # print(response.encode('utf8'))
    # print(response.json())
    print(response.content)
    sys.exit(0)
    attachment_file = fileResult('test.txt', json.dumps(response))

    return attachment_file, {}, {}


def delete_file_search_job(client: Client, args: dict):
    """removed the job to free-up space on the server. This end-point
    deletes the job from database and cleans up the file system entry for the job."""

    job_id = args.get('job_id')

    response = client.delete_job(job_id)

    return 'The job was successfully deleted', {}, response


def list_scripts_command(client: Client, *_):

    headers = ['Name', 'ID', 'Description']
    response = client.list_scripts()

    scripts = response.get('data').get('scripts')
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
    headers = ['Name', 'ID', 'Description', 'Platform', 'Command', 'Questions', 'Priority', 'TimeoutSeconds',
               'ResultColumns', 'ImpersonationUser', 'ImpersonationPassword', 'WizardOverridePassword']
    response = client.script_manifest(script_id)
    data = response.get('data')

    platforms = [k for k, v in data.get('platforms').items() if v]

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


# def execute_script_command(client: Client, args: dict):
#
#     script_id = args.get('script_id')
#     time_out = args.get('time_out')
#     endpoint_ip = args.get('endpoint_ip')
#     question = args.get('question')
#
#     response = client.execute_script(script_id, endpoint_ip, question, time_out)

def list_process_command(client: Client, args: dict):

    endpoint_ip = argToList(args.get('endpoint_ip'))
    endpoints = client.convert_ip_to_endpoint_id(endpoint_ip)
    endpoint_id = endpoints.get('data')
    time_out = args.get('time_out')
    os = args.get('os')
    script_id = ''

    if os == 'Windows':
        script_id = '2d32a530-0716-4542-afdc-8da3bd47d8bf'

    if os == 'Linux':
        script_id = '5e58a0e9-450d-4394-8360-159d5e38c280'

    if os == 'macOS':
        script_id = '020114c2-d000-4876-91b0-97f41a83b067'

    response = client.list_process(script_id, time_out, endpoint_id)
    context = {
        'ID': script_id,
        'JobID': response.get('data')
    }
    entry_context = {'FidelisEndpoint.Script(val.ID && val.ID === obj.ID)': context}

    return 'The job has been executed successfully', entry_context, response


def get_script_result(client: Client, args: dict):

    job_id = args.get('job_id')
    headers = ['ID', 'Name', 'EndpointID', 'EndpointName', 'PID', 'User', 'SHA1', 'MD5', 'Path', 'WorkingDirectory',
               'StartTime']

    response = client.script_job_results(job_id)
    hits = response.get('data').get('hits').get('hits')
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
            return_outputs(*file_seatch_status(client, demisto.args()))

        elif demisto.command() == 'fidelis-endpoint-file-search-result-metadata':
            return_outputs(*file_search_reasult_metadata(client, demisto.args()))

        elif demisto.command() == 'fidelis-endpoint-get-file':
            return_outputs(*get_file(client, demisto.args()))

        elif demisto.command() == 'fidelis-endpoint-delete-file-search-job':
            return_outputs(*delete_file_search_job(client, demisto.args()))

        elif demisto.command() == 'fidelis-endpoint-list-scripts':
            return_outputs(*list_scripts_command(client, demisto.args()))

        elif demisto.command() == 'fidelis-endpoint-script-manifest':
            return_outputs(*script_manifest_command(client, demisto.args()))

        elif demisto.command() == 'fidelis-endpoint-list-process':
            return_outputs(*list_process_command(client, demisto.args()))

        elif demisto.command() == 'fidelis-endpoint-get-script-result':
            return_outputs(*get_script_result(client, demisto.args()))
    # Log exceptions
    except Exception as e:
        return_error(f'Failed to execute {demisto.command()} command. Error: {str(e)}')


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
