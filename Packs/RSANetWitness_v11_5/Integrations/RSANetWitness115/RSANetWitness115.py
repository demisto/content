import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

DATE_FORMAT = '%Y-%m-%dT%H:%M:%S%MSZ'
SERVICE_ID = None

ERROR_TITLES = {
    400: "400 Bad Request - The request was malformed, check the given arguments\n",
    401: "401 Unauthorized - authentication is required and has failed\n",
    403: "403 Forbidden - he user might not have the necessary permissions for a resource.\n ",
    404: "404 Not Found - The requested resource does not exist.\n",
    500: "500 Internal Server Error - An unexpected error has occurred.\n"

}


class Client(BaseClient):
    def __init__(self, server_url, verify, proxy, headers, auth):
        self.refresh_token = None
        super().__init__(base_url=server_url, verify=verify, proxy=proxy, headers=headers, auth=auth)

    def _http_request(self, method, url_suffix, **kwargs):
        try:
            res = super()._http_request(method, url_suffix, **kwargs)
        except Exception as e:
            if 'Expired Token' in e.__str__():
                self.generate_new_token()
                res = super()._http_request(method, url_suffix, **kwargs)
            else:
                raise e
        return res

    def list_incidents_request(self, until, since, page_size, page_number):
        params = assign_params(until=until, since=since, pageSize=page_size, pageNumber=page_number)
        headers = self._headers
        response = self._http_request('GET', 'rest/api/incidents', params=params, headers=headers,
                                      error_handler=exception_handler)

        return response

    def update_incident_request(self, id_, status, assignee):
        headers = self._headers
        data = assign_params(status=status, assignee=assignee)
        response = self._http_request('PATCH', f'rest/api/incidents/{id_}', json_data=data, headers=headers,
                                      error_handler=exception_handler)

        return response

    def remove_incident_request(self, id_):
        headers = self._headers

        response = self._http_request('DELETE', f'rest/api/incidents/{id_}', headers=headers,
                                      return_empty_response=True, error_handler=exception_handler)

        return response

    def incident_add_journal_entry_request(self, id_, author, notes, milestone):
        data = assign_params(author=author, milestone=milestone, notes=notes)
        headers = self._headers

        response = self._http_request('POST', f'rest/api/incidents/{id_}/journal', json_data=data, headers=headers,
                                      empty_valid_codes=[201], return_empty_response=True,
                                      error_handler=exception_handler)

        return response

    def incident_list_alerts_request(self, id_, page_number, page_size):
        params = assign_params(pageNumber=page_number, pageSize=page_size)
        headers = self._headers

        response = self._http_request('GET', f'rest/api/incidents/{id_}/alerts', params=params, headers=headers,
                                      error_handler=exception_handler)

        return response

    def services_list_request(self, name):
        params = assign_params(name=name)
        headers = self._headers

        response = self._http_request('GET', 'rest/api/services', params=params, headers=headers,
                                      error_handler=exception_handler)

        return response

    def hosts_list_request(self, serviceid, page_number, page_size, added_filter):
        params = assign_params(serviceId=serviceid, pageNumber=page_number, pageSize=page_size)
        headers = self._headers
        data = added_filter
        response = self._http_request('GET', 'rest/api/hosts', params=params, headers=headers, json_data=data,
                                      error_handler=exception_handler)
        return response

    def snapshots_list_for_host_request(self, agent_id, service_id):
        params = assign_params(serviceId=service_id)
        headers = self._headers

        response = self._http_request('GET', f'rest/api/host/{agent_id}/snapshots', params=params, headers=headers,
                                      error_handler=exception_handler)

        return response

    def snapshot_details_get_request(self, agent_id, snapshot_timestamp, serviceid, categories):
        params = assign_params(serviceId=serviceid, categories=categories)
        headers = self._headers

        response = self._http_request(
            'GET', f'rest/api/host/{agent_id}/snapshots/{snapshot_timestamp}', params=params, headers=headers,
            error_handler=exception_handler)

        return response

    def files_list_request(self, serviceid, page_number, page_size):
        params = assign_params(serviceId=serviceid, pageNumber=page_number, pageSize=page_size)
        headers = self._headers

        response = self._http_request('GET', 'rest/api/files', params=params, headers=headers,
                                      error_handler=exception_handler)

        return response

    def scan_request_request(self, agent_id, serviceid, scantype, cpumax):
        params = assign_params(serviceId=serviceid, scanType=scantype, cpuMax=cpumax)
        headers = self._headers

        response = self._http_request('POST', f'rest/api/host/{agent_id}/scan', params=params, headers=headers,
                                      empty_valid_codes=[200], return_empty_response=True,
                                      error_handler=exception_handler)

        return response

    def scan_stop_request_request(self, agent_id, serviceid, scantype):
        params = assign_params(serviceId=serviceid, scanType=scantype)
        headers = self._headers

        response = self._http_request('DELETE', f'rest/api/host/{agent_id}/scan', params=params, headers=headers,
                                      empty_valid_codes=[200], return_empty_response=True,
                                      error_handler=exception_handler)

        return response

    def host_alerts_list_request(self, agent_id, serviceid, alertcategory):
        params = assign_params(serviceId=serviceid, alertCategory=alertcategory)
        headers = self._headers

        response = self._http_request('GET', f'rest/api/host/{agent_id}/alerts', params=params, headers=headers,
                                      error_handler=exception_handler)

        return response

    def file_alerts_list_request(self, checksum, serviceid, alertcategory):
        params = assign_params(serviceId=serviceid, alertCategory=alertcategory)
        headers = self._headers

        response = self._http_request('GET', f'rest/api/file/{checksum}/alerts', params=params, headers=headers,
                                      error_handler=exception_handler)

        return response

    def file_download_wildcard_request(self, agent_id, serviceid, path, countfiles, maxfilesize):
        params = assign_params(serviceId=serviceid)
        data = {"countFiles": countfiles, "maxFileSize": maxfilesize, "path": path}
        headers = self._headers

        response = self._http_request(
            'POST', f'rest/api/host/{agent_id}/download/download-file', params=params, json_data=data, headers=headers,
            empty_valid_codes=[200], return_empty_response=True, error_handler=exception_handler)

        return response

    def mft_download_request_request(self, agent_id, serviceid):
        params = assign_params(serviceId=serviceid)
        headers = self._headers

        response = self._http_request('POST', f'rest/api/host/{agent_id}/download/mft', params=params, headers=headers,
                                      empty_valid_codes=[200], return_empty_response=True,
                                      error_handler=exception_handler)

        return response

    def system_dump_download_request_request(self, agent_id, serviceid):
        params = assign_params(serviceId=serviceid)
        headers = self._headers

        response = self._http_request(
            'POST', f'rest/api/host/{agent_id}/download/system-dump', params=params, headers=headers,
            empty_valid_codes=[200], return_empty_response=True, error_handler=exception_handler)

        return response

    def process_dump_download_request_request(self, agent_id, serviceid, processId, eprocess):
        params = assign_params(serviceId=serviceid)
        headers = self._headers
        data = assign_params(processId=processId, eprocess=eprocess)
        response = self._http_request(
            'POST', f'rest/api/host/{agent_id}/download/process-dump', params=params, headers=headers, json_data=data,
            empty_valid_codes=[200], return_empty_response=True, error_handler=exception_handler)

        return response

    def endpoint_isolate_from_network_request(self, agent_id, serviceid, allowdnsonlybysystem, exclusions, comment):
        params = assign_params(serviceId=serviceid)
        data = assign_params(comment=comment, allowDnsOnlyBySystem=allowdnsonlybysystem, exclusions=exclusions)
        headers = self._headers

        response = self._http_request(
            'POST', f'rest/api/host/{agent_id}/isolation', params=params, json_data=data, headers=headers,
            empty_valid_codes=[200], return_empty_response=True, error_handler=exception_handler)

        return response

    def endpoint_update_exclusions_request(self, agent_id, serviceid, allowdnsonlybysystem, exclusions, comment):
        params = assign_params(serviceId=serviceid)
        data = assign_params(comment=comment, allowDnsOnlyBySystem=allowdnsonlybysystem, exclusions=exclusions)
        headers = self._headers

        response = self._http_request(
            'PATCH', f'rest/api/host/{agent_id}/isolation', params=params, json_data=data, headers=headers,
            empty_valid_codes=[200], return_empty_response=True, error_handler=exception_handler)

        return response

    def endpoint_isolation_remove_request(self, agent_id, serviceid, allowdnsonlybysystem, comment):
        params = assign_params(serviceId=serviceid)
        data = assign_params(comment=comment, allowDnsOnlyBySystem=allowdnsonlybysystem)
        headers = self._headers

        response = self._http_request(
            'DELETE', f'rest/api/host/{agent_id}/isolation', params=params, json_data=data, headers=headers,
            empty_valid_codes=[200], return_empty_response=True, error_handler=exception_handler)

        return response

    def get_token(self, credentials):
        context_dict = demisto.getIntegrationContext()
        cur_token = context_dict.get('token')
        refresh_token = context_dict.get('refresh_token')

        if cur_token:
            self._headers['NetWitness-Token'] = cur_token
            self.refresh_token = refresh_token
        else:
            self.generate_new_token(credentials)

    def generate_new_token(self, credentials=None):
        """
        param: validation_data
        can contain a dict of user name and password


        generate a new token, if credentials are supllied used credentials, by default use the refresh token
        """
        if credentials:
            user_name = credentials['identifier']
            password = credentials['password']
            data = f'username={user_name}&password={password}'
            url = '/rest/api/auth/userpass'

        else:
            data = f'token={self.refresh_token}'
            url = '/rest/api/auth/token'

        headers = {'Content-Type': 'application/x-www-form-urlencoded'}

        response = self._http_request(
            'POST', url, data=data, headers=headers, error_handler=exception_handler)

        new_token = response.get('accessToken')
        refresh_token = response.get('refreshToken')

        if new_token:
            self._headers['NetWitness-Token'] = new_token
            self.refresh_token = refresh_token
            demisto.setIntegrationContext({'token': new_token, 'refresh_token': refresh_token})

        else:
            raise DemistoException("Error in authentication process- couldn't generate a token")


def list_incidents_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    limit = args.get('limit')
    until = create_time(args.get('until'))
    since = create_time(args.get('since'))
    page_size = args.get('page_size', '50')
    page_number = args.get('page_number')
    items = []

    if not limit:
        response = client.list_incidents_request(until, since, page_size, page_number)
        items = response.get('items', [])

    else:
        limit = int(limit)
        page_size = page_size if limit > 100 else limit
        total = 0
        while total < limit:
            response = client.list_incidents_request(until, since, page_size, page_number)
            items += response.get('items', [])
            if not response.get('hasNext'):
                break
            total += len(response.get('items'))

    items = remove_duplicates_in_items(items, 'id')
    context_data = prepare_paging_context_data(response, items, 'Incidents')
    page_number = response.get('pageNumber')
    output = prepare_incidents_readable_items(items)
    total_pages = response.get('totalPages')
    text = f'Total Retrieved Incidents : {len(output)}\n Page number {page_number} out of {total_pages} '
    humanReadable = tableToMarkdown(text, output, ['Id', 'Title', 'Summary', 'Priority', 'RiskScore', 'Status',
                                                   'AlertCount', 'Created', 'LastUpdated', 'Assignee', 'Sources',
                                                   'Categories'])
    command_results = CommandResults(
        outputs=context_data,
        readable_output=humanReadable,
        raw_response=response
    )

    return command_results


def update_incident_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    id_ = args.get('id')
    status = args.get('status')
    assignee = args.get('assignee')

    response = client.update_incident_request(id_, status, assignee)

    items = prepare_incidents_readable_items([response])
    humanReadable = tableToMarkdown(f'Updated Incident {id_}', items,
                                    ['Id', 'Title', 'Summary', 'Priority', 'RiskScore', 'Status',
                                     'AlertCount', 'Created', 'LastUpdated', 'Assignee', 'Sources', 'Categories'])
    command_results = CommandResults(
        outputs_prefix='RSANetWitness115.Incidents(val.id === obj.id)',
        outputs=response,
        readable_output=humanReadable,
        raw_response=response
    )

    return command_results


def remove_incident_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    id_ = args.get('id')

    client.remove_incident_request(id_)
    command_results = CommandResults(
        readable_output=f'Incident {id_} deleted successfully',
    )

    return command_results


def incident_add_journal_entry_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    id_ = args.get('id')
    author = args.get('author')
    notes = args.get('notes')
    milestone = args.get('milestone')

    client.incident_add_journal_entry_request(id_, author, notes, milestone)
    command_results = CommandResults(
        readable_output=f'Journal entry added successfully for incident {id_} '
    )

    return command_results


def incident_list_alerts_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    id_ = args.get('id')
    page_number = args.get('page_number')
    page_size = args.get('page_size', '50')
    limit = args.get('limit')
    items = []
    if not limit:
        response = client.incident_list_alerts_request(id_, page_number, page_size)
        items = response.get('items', [])

    else:
        limit = int(limit)
        page_size = page_size if limit > 100 else limit
        total = 0

        while total < limit:
            response = client.incident_list_alerts_request(id_, page_number, page_size)
            items += response.get('items', [])
            if not response.get('hasNext'):
                break
            total += len(response.get('items'))
            page_number = response.get('pageNumber') + 1

        # remove duplicates that might occur from paging
        items = remove_duplicates_in_items(items, 'id')
    for item in items:
        item['IncidentId'] = id_
    context_data = prepare_paging_context_data(response, items, 'IncidentAlerts')
    page_number = response.get('pageNumber')
    output = prepare_alerts_readable_items(items)
    total_pages = response.get('totalPages')
    text = f'Total Retrieved Alerts : {len(output)} for incident {id_}\n Page number {page_number} out of {total_pages}'
    humanReadable = tableToMarkdown(text, output,
                                    ['Id', 'Title', 'Detail', 'Created', 'Source', 'RiskScore', 'Type', 'Events'],
                                    removeNull=True, )
    command_results = CommandResults(
        outputs=context_data,
        readable_output=humanReadable,
        raw_response=response
    )

    return command_results


def services_list_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    name = args.get('name')

    response = client.services_list_request(name)
    if not response:
        command_results = CommandResults(
            readable_output='No Services were found '
        )
    else:
        command_results = CommandResults(
            outputs_prefix='RSANetWitness115.ServicesList',
            outputs_key_field='id',
            outputs=response,
            raw_response=response
        )

    return command_results


def hosts_list_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    service_id = args.get('service_id', SERVICE_ID)
    page_number = args.get('page_number')
    page_size = args.get('page_size', '50')
    custom_filter = args.get('filter')
    try:
        if custom_filter:
            added_filter = json.loads(custom_filter)
        else:
            added_filter = create_filter(args)
    except ValueError:
        raise DemistoException("filter structure is invalid")

    limit = args.get('limit')
    items = []
    if not limit:
        response = client.hosts_list_request(service_id, page_number, page_size, added_filter)
        items = response.get('items', [])

    else:
        limit = int(limit)
        page_size = page_size if limit > 100 else limit
        total = 0

        while total < limit:
            response = client.hosts_list_request(service_id, page_number, page_size, added_filter)
            items += response.get('items', [])
            if not response.get('hasNext'):
                break
            total += len(response.get('items'))
            page_number = response.get('pageNumber') + 1

        # remove duplicates that might occur from paging
        items = remove_duplicates_in_items(items, 'hostName')
    context_data = prepare_paging_context_data(response, items, 'HostsList')
    page_number = response.get('pageNumber')
    output = prepare_hosts_readable_items(items)
    total_pages = response.get('totalPages')
    text = f'Total Retrieved Hosts : {len(output)} \n Page number {page_number} out of {total_pages}'
    humanReadable = tableToMarkdown(text, output,
                                    ['agentId', 'hostName', 'riskScore', 'networkInterfaces', 'lastSeenTime'],
                                    removeNull=True)
    command_results = CommandResults(
        outputs=context_data,
        readable_output=humanReadable,
        raw_response=response
    )
    return command_results


def endpoint_command(client: Client, args: Dict[str, Any]) -> List[CommandResults]:
    service_id = args.get('service_id', SERVICE_ID)
    endpoint_id = args.get('id')
    ip = args.get('ip')
    host_name = args.get('hostname')
    new_args = assign_params(agent_id=endpoint_id, ip=ip, host_name=host_name)
    added_filter = create_filter(new_args)

    response = client.hosts_list_request(service_id, None, None, added_filter)
    hosts = response.get('items')
    command_results = []

    for host in hosts:
        ips, mac_addresses = get_network_interfaces_info(host)
        endpoint = Common.Endpoint(
            id=host.get('agentId'),
            hostname=host.get('hostName'),
            ip_address=ips,
            mac_address=mac_addresses,
            vendor='RSA NetWitness 11.5 Response')

        endpoint_context = endpoint.to_context().get(Common.Endpoint.CONTEXT_PATH)
        md = tableToMarkdown(f'RSA NetWitness 11.5 -  Endpoint: {host.get("agentId")}', endpoint_context)

        command_results.append(CommandResults(
            readable_output=md,
            raw_response=response,
            indicator=endpoint
        ))

    return command_results


def snapshots_list_for_host_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    agent_id = args.get('agent_id')
    service_id = args.get('service_id', SERVICE_ID)
    response = client.snapshots_list_for_host_request(agent_id, service_id)

    readable_output = [{'Snapshot Id': snapshot_id} for snapshot_id in response]
    humanReadable = tableToMarkdown(f'Snapshot list for agent id {agent_id}-', readable_output, ['Snapshot Id'])
    command_results = CommandResults(
        outputs_prefix='RSANetWitness115.SnapshotsListForHost',
        outputs_key_field='',
        outputs=response,
        readable_output=humanReadable,
        raw_response=response
    )

    return command_results


def snapshot_details_get_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    agent_id = args.get('agent_id')
    snapshot_timestamp = args.get('snapshot_timestamp')
    service_id = args.get('service_id', SERVICE_ID)
    categories = args.get('categories')
    limit = int(args.get('limit', '50'))
    offset = int(args.get('offset', '0'))

    response = client.snapshot_details_get_request(agent_id, snapshot_timestamp, service_id, categories)

    results = response[offset:limit]
    readable_output = prepare_snapshot_readable(results)

    humanReadable = tableToMarkdown(f'Snapshot details for agent id {agent_id}-'
                                    f' \nshowing {limit} results out of {len(response)}',
                                    readable_output, ['hostName', 'agentId', 'scanStartTime', 'directory', 'fileName'])
    command_results = CommandResults(
        outputs_prefix='RSANetWitness115.SnapshotDetailsGet',
        readable_output=humanReadable,
        outputs=results,
        raw_response=results
    )

    return command_results


def files_list_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    service_id = args.get('service_id', SERVICE_ID)
    page_number = args.get('page_number')
    page_size = args.get('page_size', '50')
    limit = args.get('limit')
    items = []
    if not limit:
        response = client.files_list_request(service_id, page_number, page_size)
        items = response.get('items')

    else:
        limit = int(limit)
        page_size = page_size if limit > 100 else limit
        total = 0

        while total < limit:
            response = client.files_list_request(service_id, page_number, page_size)
            items += response.get('items', [])
            if not response.get('hasNext'):
                break
            total += len(response.get('items'))
            page_number = response.get('pageNumber') + 1

        # remove duplicates that might occur from paging
        items = remove_duplicates_in_items(items, 'firstFileName')

    context_data = prepare_paging_context_data(response, items, 'FilesList')
    page_number = response.get('pageNumber')
    output = prepare_files_readable_items(items)
    total_pages = response.get('totalPages')
    text = f'Total Retrieved Files : {len(output)} \n Page number {page_number} out of {total_pages}'
    humanReadable = tableToMarkdown(text, output,
                                    ['File Name', 'Risk Score', 'First Seen Time', 'Reputation', 'Size', 'Signature',
                                     'PE Resources', 'File Status', 'Remediation'],
                                    removeNull=True)

    command_results = CommandResults(
        readable_output=humanReadable,
        outputs=context_data,
        raw_response=response
    )

    return command_results


def scan_request_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    agent_id = args.get('agent_id')
    service_id = args.get('service_id', SERVICE_ID)
    scan_type = 'QUICK_SCAN'
    cpumax = args.get('cpumax')

    client.scan_request_request(agent_id, service_id, scan_type, cpumax)
    command_results = CommandResults(
        readable_output=f"Scan request for host {agent_id} Sent Successfully",
    )

    return command_results


def scan_stop_request_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    agent_id = args.get('agent_id')
    service_id = args.get('service_id', SERVICE_ID)
    scan_type = 'CANCEL_SCAN'

    client.scan_stop_request_request(agent_id, service_id, scan_type)
    command_results = CommandResults(
        readable_output=f'Request for scan cancellation for host {agent_id}, sent successfully',
    )

    return command_results


def host_alerts_list_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    agent_id = args.get('agent_id')
    service_id = args.get('service_id', SERVICE_ID)
    alert_category = args.get('alert_category')

    response = client.host_alerts_list_request(agent_id, service_id, alert_category)
    command_results = CommandResults(
        outputs_prefix='RSANetWitness115.HostAlertsList',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def file_alerts_list_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    checksum = args.get('check_sum')
    service_id = args.get('service_id', SERVICE_ID)
    alert_category = args.get('alert_category')

    response = client.file_alerts_list_request(checksum, service_id, alert_category)
    command_results = CommandResults(
        outputs_prefix='RSANetWitness115.FileAlertsList',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def file_download_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    agent_id = args.get('agent_id')
    service_id = args.get('service_id', SERVICE_ID)
    path = args.get('path')
    count_files = args.get('count_files')
    max_file_size = args.get('max_file_size')

    client.file_download_wildcard_request(agent_id, service_id, path, count_files, max_file_size)
    command_results = CommandResults(
        readable_output=f'Request for download {path} sent successfully'
    )

    return command_results


def mft_download_request_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    agent_id = args.get('agent_id')
    service_id = args.get('service_id', SERVICE_ID)

    client.mft_download_request_request(agent_id, service_id)
    command_results = CommandResults(
        readable_output=f'MFT download request for host {agent_id} sent successfully'
    )

    return command_results


def system_dump_download_request_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    agent_id = args.get('agent_id')
    service_id = args.get('service_id', SERVICE_ID)

    client.system_dump_download_request_request(agent_id, service_id)
    command_results = CommandResults(
        readable_output=f'System Dump download request for host {agent_id} sent successfully'
    )

    return command_results


def process_dump_download_request_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    agent_id = args.get('agent_id')
    service_id = args.get('service_id', SERVICE_ID)
    process_id = args.get('process_id')
    eprocess = args.get('eprocess')
    client.process_dump_download_request_request(agent_id, service_id, process_id, eprocess)
    command_results = CommandResults(
        readable_output='Process Dump request sent successfully'
    )

    return command_results


def endpoint_isolate_from_network_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    agent_id = args.get('agent_id')
    service_id = args.get('service_id', SERVICE_ID)
    allow_dns_only = args.get('allow_dns_only_by_system')
    exclusion_list = create_exclusions_list(args.get('exclusion_list')) if args.get('exclusion_list') else None
    comment = args.get('comment')

    client.endpoint_isolate_from_network_request(agent_id, service_id, allow_dns_only, exclusion_list,
                                                 comment)
    command_results = CommandResults(
        readable_output=f'Isolate request for Host {agent_id} has been sent successfully'
    )

    return command_results


def endpoint_update_exclusions_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    agent_id = args.get('agent_id')
    service_id = args.get('service_id', SERVICE_ID)
    allow_dns_only = args.get('allow_dns_only_by_system')
    exclusion_list = create_exclusions_list(args.get('exclusion_list')) if args.get('exclusion_list') else None
    comment = args.get('comment')

    client.endpoint_update_exclusions_request(agent_id, service_id, allow_dns_only, exclusion_list, comment)
    command_results = CommandResults(
        readable_output=f'Isolate update exclusions request, for Host {agent_id} ,sent successfully'
    )

    return command_results


def endpoint_isolation_remove_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    agent_id = args.get('agent_id')
    service_id = args.get('service_id', SERVICE_ID)
    comment = args.get('comment')
    allow_dns_only = args.get('allow_dns_only_by_system')

    client.endpoint_isolation_remove_request(agent_id, service_id, allow_dns_only, comment)
    command_results = CommandResults(
        readable_output=f'Isolate remove request, for Host {agent_id} ,sent successfully'
    )

    return command_results


def fetch_incidents(client: Client, fetch_time, fetch_limit):
    fetch_limit = int(fetch_limit)
    last_run = demisto.getLastRun()
    if last_run and last_run.get('timestamp'):
        timestamp = last_run.get('timestamp')
        last_fetched_ids = last_run.get('last_fetched_ids', [])
    else:
        last_fetch = dateparser.parse(fetch_time)
        # convert to ISO 8601 format and add Z suffix
        timestamp = last_fetch.isoformat() + 'Z'
        last_fetched_ids = []

    total_items = get_incidents(client, timestamp, fetch_limit, last_fetched_ids)
    incidents: List[Dict] = []
    new_ids = []
    for item in total_items:
        new_ids.append(item.get('id'))
        incident = {"name": f"RSA NetWitness 11.5 {item.get('id')}",
                    "occurred": item.get('created'),
                    "rawJSON": json.dumps(item)}
        # items arrived from last to first - change order
        incidents.insert(0, incident)

    new_last_run = incidents[-1].get('occurred') if incidents else timestamp
    if is_new_run_time_equal_last_run_time(timestamp, new_last_run):
        new_ids.extend(last_fetched_ids)

    demisto.setLastRun({"timestamp": new_last_run, "last_fetched_ids": new_ids})
    return incidents


def get_incidents(client, timestamp, fetch_limit, last_fetched_ids):
    page_size = 100
    response = client.list_incidents_request(None, timestamp, page_size, 0)
    if not response.get('items'):
        return []

    page_number = response.get('totalPages') - 1
    total = 0
    total_items: List[Dict] = []
    while total < fetch_limit and page_number >= 0:
        response = client.list_incidents_request(None, timestamp, page_size, page_number)
        items = response.get('items', [])
        new_items = remove_duplicates_for_fetch(items, last_fetched_ids)
        # items order is from old to new , add new items at the start of list to maintain order
        total_items = new_items + total_items
        total += len(new_items)
        page_number -= 1

    total_items = remove_duplicates_in_items(total_items, 'id')
    # bring the last 'fetch_limit' items, as order is reversed
    total_items = total_items[-fetch_limit:]
    return total_items


def is_new_run_time_equal_last_run_time(last_run_time, new_run_time) -> bool:
    try:
        last_run_datetime = dateparser.parse(last_run_time)
        new_datetime = dateparser.parse(new_run_time)

    except ValueError:
        raise DemistoException("Incorrect date time in fetch")

    return last_run_datetime == new_datetime


def remove_duplicates_for_fetch(items, last_fetched_ids):
    new_items = []
    for item in items:
        if item.get('id') and item.get('id') not in last_fetched_ids:
            new_items.append(item)

    return new_items


def remove_duplicates_in_items(items, id_str: str):
    ids = {}
    new_items = []
    for item in items:
        if item.get(id_str) and item.get(id_str) not in ids:
            ids[item.get(id_str)] = True
            new_items.append(item)

    return new_items


def prepare_incidents_readable_items(items: List[Dict[str, Any]]):
    readable_items = [
        {
            'Id': item.get('id'),
            'Title': item.get('title'),
            'Summary': item.get('summary'),
            'Priority': item.get('priority'),
            'RiskScore': item.get('riskScore'),
            'Status': item.get('status'),
            'AlertCount': item.get('alertCount'),
            'Created': item.get('created'),
            'LastUpdated': item.get('lastUpdated'),
            'Assignee': item.get('assignee'),
            'Sources': item.get('sources'),
            'Categories': item.get('categories')
        } for item in items
    ]

    return remove_empty_elements(readable_items)


def prepare_snapshot_readable(response: List):
    readable_items = [
        {
            'hostName': item.get('hostName'),
            'agentId': item.get('agentId'),
            'scanStartTime': item.get('scanStartTime'),
            'directory': item.get('directory'),
            'fileName': item.get('fileName'),
        } for item in response
    ]

    return remove_empty_elements(readable_items)


def prepare_alerts_readable_items(items: List[Dict[str, Any]]):
    readable_items = [
        {
            'Id': item.get('id'),
            'Title': item.get('title'),
            'Detail': item.get('detail'),
            'Created': item.get('created'),
            'Source': item.get('source'),
            'RiskScore': item.get('riskScore'),
            'Type': item.get('type'),
            'Events': item.get('events')
        } for item in items
    ]

    return remove_empty_elements(readable_items)


def prepare_hosts_readable_items(items: List[Dict[str, Any]]):
    readable_items = [
        {
            'agentId': item.get('agentId'),
            'hostName': item.get('hostName'),
            'riskScore': item.get('riskScore'),
            'networkInterfaces': item.get('networkInterfaces'),
            'lastSeenTime': item.get('lastSeenTime')
        } for item in items
    ]

    return remove_empty_elements(readable_items)


def prepare_files_readable_items(items: List[Dict[str, Any]]):
    readable_items = [
        {
            'File Name': item.get('firstFileName'),
            'Risk Score': item.get('globalRiskScore'),
            'First Seen Time': item.get('firstSeenTime'),
            'Reputation': item.get('reputationStatus'),
            'Size': item.get('size'),
            'Signature': item.get('signature'),
            'PE Resources': item.get('pe', []).get('resources'),
            'File Status': item.get('fileStatus'),
            'Remediation': item.get('remediationAction')
        } for item in items
    ]

    return remove_empty_elements(readable_items)


def prepare_paging_context_data(response: Dict[str, Any], items: List[Dict[str, Any]], suffix: str):
    return {
        f'RSANetWitness115.{suffix}(val.id === obj.id)': items,
        f'RSANetWitness115.paging.{suffix}(true)': {"pageNumber": response.get('pageNumber'),
                                                    "pageSize": response.get('pageSize'),
                                                    "totalPages": response.get('totalPages'),
                                                    "totalItems": response.get('totalItems'),
                                                    "hasNext": response.get('hasNext'),
                                                    "hasPrevious": response.get('hasPrevious')}
    }


def create_end_time(start_time: str, milisec_amount: str, add: bool) -> str:
    time_param = int(milisec_amount)
    timedelta_param = timedelta(milliseconds=time_param)
    if add:
        end_time = dateparser.parse(start_time) + timedelta_param
    else:
        end_time = dateparser.parse(start_time) - timedelta_param
    return end_time.strftime(DATE_FORMAT)


def exception_handler(res):
    try:
        res_data = res.json()
        error_code = res_data['status']
        error_msg = build_error_msg(res_data['errors'])
        exception = DemistoException(ERROR_TITLES.get(error_code, '') + error_msg)

    except Exception:
        exception = DemistoException('Error in API call [{}] - {}'.format(res.status_code, res.reason))

    raise exception


def build_error_msg(error_body):
    ret_error_msg = ''
    for error in error_body:
        if error.get('field'):
            ret_error_msg += 'field ' + error['field']
        if error.get('message'):
            ret_error_msg += ' ' + error['message']
    return ret_error_msg


def create_exclusions_list(ips_str_list):
    ips_list = str.split(ips_str_list, ',')
    exclusion_list = []
    for ip in ips_list:
        ip_type = auto_detect_indicator_type(ip)
        if ip_type not in ('IP', 'IPv6'):
            raise DemistoException(f'Invalid ip address - {ip}')
        is_v4 = ip_type == 'IP'
        ip_data = {"ip": ip, "v4": is_v4}
        exclusion_list.append(ip_data)
    return exclusion_list


def create_filter(args):
    if 'filter' in args:
        return args.get('filter')

    filter_option_args = {'agent_id': 'agentId', 'risk_score': 'riskScore', 'ip': 'networkInterfaces.ipv4',
                          'host_name': 'hostName'}

    expression_list = []
    for arg in filter_option_args:
        if arg in args:
            value = args.get(arg)
            if arg == 'risk_score':
                restriction = "GREATER_THAN_OR_EQUAL_TO"
                values_list = [int(value)]
            else:
                restriction = "IN"
                values_list = argToList(value)

            values_res = [{"value": val} for val in values_list]
            expression = {
                "propertyName": filter_option_args[arg],
                "restrictionType": restriction,
                "propertyValues": values_res
            }
            expression_list.append(expression)
    if expression_list:
        return {"criteria": {"criteriaList": [{"expressionList": expression_list}], "predicateType": "AND"}}
    else:
        return None


def get_network_interfaces_info(endpoint):
    ips_list = []
    mac_address_list = []
    for data in endpoint.get('networkInterfaces', []):
        ips_list.append(data.get('ipv4'))
        mac_address_list.append((data.get('macAddress')))

    return ips_list, mac_address_list


def create_time(given_time) -> str:
    """converts given argument time to iso format,
     if received None returns None"""
    if not given_time:
        return given_time
    datetime_time = arg_to_datetime(given_time)
    if not datetime_time:
        raise DemistoException("Time parameter supplied in invalid, please supply a valid argument")
    return datetime_time.strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def test_module(client: Client, params) -> None:
    if params.get('isFetch'):
        fetch_time = params.get('fetch_time')
        fetch_limit = params.get('fetch_limit')
        if not fetch_limit:
            return_error('enter a fetch limit')
        last_fetch = dateparser.parse(fetch_time)
        if not last_fetch:
            return_error('Incorrect time format for fetch time')
        # convert to ISO 8601 format and add Z suffix
        timestamp = last_fetch.isoformat() + 'Z'
        fetch_limit = int(fetch_limit)

        get_incidents(client, timestamp, fetch_limit, [])

    if SERVICE_ID:
        client.hosts_list_request(SERVICE_ID, 0, 1, None)

    return_results('ok')


def main() -> None:
    params: Dict[str, Any] = demisto.params()
    args: Dict[str, Any] = demisto.args()
    url = params.get('url')
    verify_certificate: bool = not params.get('insecure', False)
    proxy = params.get('proxy', False)

    headers: Dict[str, str] = {}

    command = demisto.command()
    demisto.debug(f'Command being called is {command}')

    try:
        global SERVICE_ID
        requests.packages.urllib3.disable_warnings()
        client: Client = Client(urljoin(url, ''), verify_certificate, proxy, headers=headers, auth={})
        client.get_token(params.get('credentials'))
        SERVICE_ID = params.get('service_id')
        fetch_time = params.get('fetch_time', '1 days')
        fetch_limit = params.get('fetch_limit', '100')

        commands = {
            'rsa-nw-list-incidents': list_incidents_command,
            'rsa-nw-update-incident': update_incident_command,
            'rsa-nw-remove-incident': remove_incident_command,
            'rsa-nw-incident-add-journal-entry': incident_add_journal_entry_command,
            'rsa-nw-incident-list-alerts': incident_list_alerts_command,
            'rsa-nw-services-list': services_list_command,
            'rsa-nw-hosts-list': hosts_list_command,
            'endpoint': endpoint_command,
            'rsa-nw-snapshots-list-for-host': snapshots_list_for_host_command,
            'rsa-nw-snapshot-details-get': snapshot_details_get_command,
            'rsa-nw-files-list': files_list_command,
            'rsa-nw-scan-request': scan_request_command,
            'rsa-nw-scan-stop-request': scan_stop_request_command,
            'rsa-nw-host-alerts-list': host_alerts_list_command,
            'rsa-nw-file-alerts-list': file_alerts_list_command,
            'rsa-nw-file-download': file_download_command,
            'rsa-nw-mft-download-request': mft_download_request_command,
            'rsa-nw-system-dump-download-request': system_dump_download_request_command,
            'rsa-nw-process-dump-download-request': process_dump_download_request_command,
            'rsa-nw-endpoint-isolate-from-network': endpoint_isolate_from_network_command,
            'rsa-nw-endpoint-update-exclusions': endpoint_update_exclusions_command,
            'rsa-nw-endpoint-isolation-remove': endpoint_isolation_remove_command,
        }
        if command == 'test-module':
            test_module(client, params)
        elif command == 'fetch-incidents':
            incidents = fetch_incidents(client, fetch_time, fetch_limit)
            demisto.incidents(incidents)
        elif command == 'endpoint':
            return_results(endpoint_command(client, args))
        elif command in commands:
            return_results(commands[command](client, args))
        else:
            raise NotImplementedError(f'{command} command is not implemented.')

    except Exception as e:
        return_error(str(e))


if __name__ in ['__main__', 'builtin', 'builtins']:
    main()
