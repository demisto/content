import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
from typing import Tuple

ERROR_TITLES = {
    400: "400 Bad Request - The request was malformed, check the given arguments\n",
    401: "401 Unauthorized - authentication is required and has failed\n",
    403: "403 Forbidden - he user might not have the necessary permissions for a resource.\n ",
    404: "404 Not Found - The requested resource does not exist.\n",
    500: "500 Internal Server Error - An unexpected error has occurred.\n"

}
DATE_FORMAT = '%Y-%m-%dT%H:%M:%S.%MZ'


class Client(BaseClient):
    def __init__(self, server_url, verify, proxy, headers, service_id, fetch_time, fetch_limit, cred):
        self.refresh_token = None
        self.service_id = service_id
        self.fetch_time = fetch_time
        self.fetch_limit = fetch_limit
        self.cred = cred
        super().__init__(base_url=server_url, verify=verify, proxy=proxy, headers=headers)

    def get_username(self):
        return self.cred['identifier']

    def get_incident_url(self, inc_id: str):
        return urljoin(self._base_url, f'respond/incident/{inc_id}')

    def _http_request(self, method, url_suffix='', **kwargs):
        """Http request wrapper, handles authentication in case token expires.

           Args:
               method (str): The request method e.g 'GET'
               url_suffix (str): The request url
               **kwargs (dict): The arguments for the real http request

           Returns:
               The request response
           """
        try:
            res = super()._http_request(method, url_suffix, error_handler=exception_handler, **kwargs)
        except Exception as e:
            if 'Expired Token' in e.__str__():
                self.generate_new_token()
                res = super()._http_request(method, url_suffix, error_handler=exception_handler, **kwargs)
            else:
                raise e
        return res

    def list_incidents_request(self, page_size: Optional[str], page_number: Optional[str],
                               until: Optional[str], since: Optional[str]) -> dict:
        params = assign_params(until=until, since=since, pageSize=page_size, pageNumber=page_number)
        response = self._http_request('GET', 'rest/api/incidents', params=params)

        return response

    def get_incident_request(self, inc_id: Optional[str]) -> dict:
        response = self._http_request('GET', f'rest/api/incidents/{inc_id}')

        return response

    def update_incident_request(self, id_: Optional[Any], status: Optional[Any], assignee: Optional[Any]) -> dict:
        data = assign_params(status=status, assignee=assignee)
        response = self._http_request('PATCH', f'rest/api/incidents/{id_}', json_data=data)

        return response

    def remove_incident_request(self, id_: Optional[str]) -> dict:
        response = self._http_request('DELETE', f'rest/api/incidents/{id_}', return_empty_response=True)
        return response

    def incident_add_journal_entry_request(self, id_: Optional[str], author, notes: Optional[str],
                                           milestone: Optional[str]) -> dict:
        data = assign_params(author=author, milestone=milestone, notes=notes)
        response = self._http_request('POST', f'rest/api/incidents/{id_}/journal', json_data=data,
                                      empty_valid_codes=[201], return_empty_response=True)

        return response

    def incident_list_alerts_request(self, page_size: Optional[str], page_number: Optional[str], id_: Optional[str]) \
            -> dict:
        params = assign_params(pageNumber=page_number, pageSize=page_size)
        response = self._http_request('GET', f'rest/api/incidents/{id_}/alerts', params=params)

        return response

    def services_list_request(self, name: Optional[Any]) -> dict:
        params = assign_params(name=name)
        response = self._http_request('GET', 'rest/api/services', params=params)

        return response

    def hosts_list_request(self, page_size: Optional[str], page_number: Optional[str], service_id: Optional[str],
                           added_filter: Optional[dict]) -> dict:
        service_id = service_id or self.service_id
        params = assign_params(serviceId=service_id, pageNumber=page_number, pageSize=page_size)
        data = added_filter
        response = self._http_request('GET', 'rest/api/hosts', params=params, json_data=data)
        return response

    def snapshots_list_for_host_request(self, agent_id: Optional[str], service_id: Optional[str]) -> dict:
        service_id = service_id or self.service_id
        params = assign_params(serviceId=service_id)
        response = self._http_request('GET', f'rest/api/host/{agent_id}/snapshots', params=params)

        return response

    def snapshot_details_get_request(self, agent_id: Optional[str], snapshot_timestamp: Optional[str],
                                     service_id: Optional[str], categories: Optional[list]) -> dict:
        service_id = service_id or self.service_id
        params = assign_params(serviceId=service_id, categories=categories)
        response = self._http_request(
            'GET', f'rest/api/host/{agent_id}/snapshots/{snapshot_timestamp}', params=params)

        return response

    def files_list_request(self, page_size: Optional[str], page_number: Optional[str],
                           service_id: Optional[str]) -> dict:
        service_id = service_id or self.service_id
        params = assign_params(serviceId=service_id, pageNumber=page_number, pageSize=page_size)
        response = self._http_request('GET', 'rest/api/files', params=params)

        return response

    def scan_request_request(self, agent_id: Optional[str], service_id: Optional[str], scan_type: Optional[str],
                             cpu_max: Optional[str]) -> dict:
        service_id = service_id or self.service_id
        params = assign_params(serviceId=service_id, scanType=scan_type, cpuMax=cpu_max)
        response = self._http_request('POST', f'rest/api/host/{agent_id}/scan', params=params,
                                      empty_valid_codes=[200], return_empty_response=True)

        return response

    def scan_stop_request_request(self, agent_id: Optional[str], service_id: Optional[str],
                                  scan_type: Optional[str]) -> dict:
        service_id = service_id or self.service_id
        params = assign_params(serviceId=service_id, scanType=scan_type)
        response = self._http_request('DELETE', f'rest/api/host/{agent_id}/scan', params=params,
                                      empty_valid_codes=[200], return_empty_response=True)

        return response

    def host_alerts_list_request(self, agent_id: Optional[str], service_id: Optional[str],
                                 alert_category: Optional[str]) -> dict:
        service_id = service_id or self.service_id
        params = assign_params(serviceId=service_id, alertCategory=alert_category)
        response = self._http_request('GET', f'rest/api/host/{agent_id}/alerts', params=params)

        return response

    def file_alerts_list_request(self, checksum: Optional[str], service_id: Optional[str],
                                 alert_category: Optional[str]) -> dict:
        service_id = service_id or self.service_id
        params = assign_params(serviceId=service_id, alertCategory=alert_category)
        response = self._http_request('GET', f'rest/api/file/{checksum}/alerts', params=params)

        return response

    def file_download_request(self, agent_id: Optional[str], service_id: Optional[str], path: Optional[str],
                              count_files: Optional[str], max_file_size: Optional[Any]) -> dict:
        service_id = service_id or self.service_id
        params = assign_params(serviceId=service_id)
        if path and '*' in path:
            url = f'rest/api/host/{agent_id}/download/download-files'
            data = {'countFiles': count_files, 'maxFileSize': max_file_size, "path": path}

        else:
            url = f'rest/api/host/{agent_id}/download/download-file'
            data = {"path": path}

        response = self._http_request(
            'POST', url, params=params, json_data=data, empty_valid_codes=[200], return_empty_response=True)

        return response

    def mft_download_request_request(self, agent_id: Optional[str], service_id: Optional[str]) -> dict:
        service_id = service_id or self.service_id
        params = assign_params(serviceId=service_id)
        response = self._http_request('POST', f'rest/api/host/{agent_id}/download/mft', params=params,
                                      empty_valid_codes=[200], return_empty_response=True)

        return response

    def system_dump_download_request_request(self, agent_id: Optional[str], service_id: Optional[str]) -> dict:
        service_id = service_id or self.service_id
        params = assign_params(serviceId=service_id)
        response = self._http_request(
            'POST', f'rest/api/host/{agent_id}/download/system-dump', params=params,
            empty_valid_codes=[200], return_empty_response=True)

        return response

    def process_dump_download_request_request(self, agent_id: Optional[str], service_id: Optional[str],
                                              process_id: Optional[str], eprocess: Optional[str],
                                              file_name: Optional[str], path: Optional[str], file_hash: Optional[str],
                                              process_create_utctime: Optional[str]) -> dict:
        service_id = service_id or self.service_id
        params = assign_params(serviceId=service_id)
        data = assign_params(processId=process_id, eprocess=eprocess, fileName=file_name, path=path, hash=file_hash,
                             processCreateUtcTime=process_create_utctime)
        response = self._http_request(
            'POST', f'rest/api/host/{agent_id}/download/process-dump', params=params, json_data=data,
            empty_valid_codes=[200], return_empty_response=True)

        return response

    def endpoint_isolate_from_network_request(self, agent_id: Optional[str], service_id: Optional[str],
                                              allow_dns_only: Optional[str], exclusions: Optional[list],
                                              comment: Optional[str]) -> dict:
        service_id = service_id or self.service_id
        params = assign_params(serviceId=service_id)
        data = assign_params(comment=comment, allowDnsOnlyBySystem=allow_dns_only, exclusions=exclusions)

        response = self._http_request(
            'POST', f'rest/api/host/{agent_id}/isolation', params=params, json_data=data,
            empty_valid_codes=[200], return_empty_response=True)

        return response

    def endpoint_update_exclusions_request(self, agent_id: Optional[str], service_id: Optional[str],
                                           allow_dns_only: Optional[str], exclusions: Optional[list],
                                           comment: Optional[str]) -> dict:
        service_id = service_id or self.service_id
        params = assign_params(serviceId=service_id)
        data = assign_params(comment=comment, allowDnsOnlyBySystem=allow_dns_only, exclusions=exclusions)
        response = self._http_request(
            'PATCH', f'rest/api/host/{agent_id}/isolation', params=params, json_data=data,
            empty_valid_codes=[200], return_empty_response=True)

        return response

    def endpoint_isolation_remove_request(self, agent_id: Optional[str], service_id: Optional[str],
                                          allow_dns_only: Optional[str], comment: Optional[str]) -> dict:
        service_id = service_id or self.service_id
        params = assign_params(serviceId=service_id)
        data = assign_params(comment=comment, allowDnsOnlyBySystem=allow_dns_only)
        response = self._http_request(
            'DELETE', f'rest/api/host/{agent_id}/isolation', params=params, json_data=data,
            empty_valid_codes=[200], return_empty_response=True)

        return response

    def get_token(self) -> None:
        """Get a token from integration context or generate one,
            save token in the client headers.
           """
        context_dict = demisto.getIntegrationContext()
        cur_token = context_dict.get('token')
        refresh_token = context_dict.get('refresh_token')

        if cur_token:
            self._headers['NetWitness-Token'] = cur_token
            self.refresh_token = refresh_token
        else:
            self.generate_new_token(refresh_token)

    def generate_new_token(self, refresh_token: Optional[str] = None) -> None:
        """Generate a new token via an API request. save the new token to client's headers.

            Args:
                refresh_token (Optional[str]) : refresh token from previous run, if exits.
           """
        if not refresh_token:
            user_name = self.cred['identifier']
            password = self.cred['password']
            data = f'username={user_name}&password={password}'
            url = '/rest/api/auth/userpass'

        else:
            data = f'token={self.refresh_token}'
            url = '/rest/api/auth/token'

        headers = {'Content-Type': 'application/x-www-form-urlencoded'}

        response = self._http_request(
            'POST', url, data=data, headers=headers)

        new_token = response.get('accessToken')
        refresh_token = response.get('refreshToken')

        if new_token:
            self._headers['NetWitness-Token'] = new_token
            self.refresh_token = refresh_token
            demisto.setIntegrationContext({'token': new_token, 'refresh_token': refresh_token})

        else:
            raise DemistoException("Error in authentication process- couldn't generate a token")

    def get_incidents(self) -> Tuple[List[Any], Any, Optional[Any]]:
        """Get incidents for fetch_incidents command.

        Return:
         (list) fetched incidents
         (list) last fetched ids from last run
         (str) timestamp from last rum

           """
        timestamp = None
        fetch_limit = arg_to_number(self.fetch_limit)
        fetch_time = self.fetch_time
        if not fetch_limit or not fetch_time:
            raise DemistoException('Missing parameter - fetch limit or fetch time')
        last_run = demisto.getLastRun()
        if last_run and last_run.get('timestamp'):
            timestamp = last_run.get('timestamp', '')
            last_fetched_ids = last_run.get('last_fetched_ids', [])
        else:
            last_fetch = arg_to_datetime(fetch_time, required=True)
            if last_fetch:
                # convert to ISO 8601 format and add Z suffix
                timestamp = last_fetch.strftime(DATE_FORMAT)
            last_fetched_ids = []

        page_size = '100'
        # set the until argument to prevent duplicates
        until = get_now_time()
        response = self.list_incidents_request(page_size, '0', until, timestamp)
        if not response.get('items'):
            return [], last_fetched_ids, timestamp

        page_number = response.get('totalPages', 1) - 1
        total = 0
        total_items: List[Dict] = []
        while total < fetch_limit and page_number >= 0:
            response = self.list_incidents_request(page_size, page_number, until, timestamp)
            items = response.get('items', [])
            new_items = remove_duplicates_for_fetch(items, last_fetched_ids)
            # items order is from old to new , add new items at the start of list to maintain order
            total_items = new_items + total_items
            total += len(new_items)
            page_number -= 1

        # bring the last 'fetch_limit' items, as order is reversed
        total_items = total_items[len(total_items) - fetch_limit:]
        return total_items, last_fetched_ids, timestamp


def paging_command(limit: Optional[int], page_size: Union[str, None, int], page_number: Optional[str], func_command,
                   page_size_def='50', **kwargs) -> Tuple[Any, Union[list, Any]]:
    """Generic command for requests that support paging.

       Args:
           limit (str): The given limit.
           page_size (str): The given page size.
           page_number (str): The given page_number.
           func_command : The request function.
           page_size_def (str) : The default page size to use, default is 50.

       Returns:
           (dict) The last request response.
           (list) The retrieved items.
       """
    response = {}
    items = []
    if not limit:
        page_size = page_size or page_size_def
        response = func_command(page_size, page_number, **kwargs)
        items = response.get('items', [])
    else:
        if (page_number or page_size) and limit:
            raise DemistoException("Can't supply limit and page number/page size")
        page_size = page_size if limit > 100 else limit
        total = 0
        while total < limit:
            response = func_command(page_size, page_number, **kwargs)
            items += response.get('items', [])
            if not response.get('hasNext'):
                break
            total += len(response.get('items', []))
            page_number = response.get('pageNumber', 0) + 1
        items = items[:limit]

    return response, items


def list_incidents_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    limit = arg_to_number(args.get('limit'))
    # we always supply 'until' argument to prevent duplications due to paging
    until = create_time(args.get('until')) or get_now_time()
    since = create_time(args.get('since'))
    page_size = args.get('page_size')
    page_number = args.get('page_number')
    inc_id = args.get('id')

    if inc_id:
        response = client.get_incident_request(inc_id)
        items = [response]
        context_data = {'RSANetWitness115.Incidents(val.id === obj.id)': response}
        text = f'Incident {inc_id} retrieved-'
    else:
        response, items = paging_command(limit, page_size, page_number, client.list_incidents_request, until=until,
                                         since=since)
        context_data = prepare_paging_context_data(response, items, 'Incidents')
        page_number = response.get('pageNumber')
        total_pages = response.get('totalPages')
        text = f'Total Retrieved Incidents : {len(items)}\n Page number {page_number} out of {total_pages} '

    output = prepare_incidents_readable_items(items)
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
        outputs_prefix='RSANetWitness115.Incidents',
        outputs_key_field='id',
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
    author = args.get('author') or client.get_username()
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
    page_size = args.get('page_size')
    limit = arg_to_number(args.get('limit'))

    response, items = paging_command(limit, page_size, page_number, client.incident_list_alerts_request, id_=id_)

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
    service_id = args.get('service_id')
    page_number = args.get('page_number')
    page_size = args.get('page_size')
    custom_filter = args.get('filter')
    agent_id = args.get('agent_id')
    host_name = args.get('host_name')
    risk_score = args.get('risk_score')
    host_ip = args.get('ip')
    try:
        if custom_filter:
            added_filter = json.loads(custom_filter) if type(custom_filter) is str else custom_filter
        else:
            added_filter = create_filter(
                assign_params(agentId=agent_id, riskScore=risk_score, ip=host_ip, hostName=host_name))
    except ValueError:
        raise DemistoException("filter structure is invalid")

    limit = arg_to_number(args.get('limit'))
    response, items = paging_command(limit, page_size, page_number, client.hosts_list_request, service_id=service_id,
                                     added_filter=added_filter)
    # remove duplicates that might occur from paging
    items = remove_duplicates_in_items(items, 'hostName')
    context_data = prepare_paging_context_data(response, items, 'HostsList', filter_id='agentId')
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
    endpoint_id = args.get('id')
    ip = args.get('ip')
    host_name = args.get('hostname')
    new_args = assign_params(agentId=endpoint_id, ip=ip, hostName=host_name)
    added_filter = create_filter(new_args)

    if not client.service_id:
        raise DemistoException("No Service Id provided - To use endpoint command via RSA NetWitness"
                               " service id must be set in the integration configuration.")
    response = client.hosts_list_request(None, None, None, added_filter)
    hosts = response.get('items', [])
    command_results = []

    for host in hosts:
        ips, mac_addresses = get_network_interfaces_info(host)
        endpoint_entry = Common.Endpoint(
            id=host.get('agentId'),
            hostname=host.get('hostName'),
            ip_address=ips,
            mac_address=mac_addresses,
            vendor='RSA NetWitness 11.5 Response')

        endpoint_context = endpoint_entry.to_context().get(Common.Endpoint.CONTEXT_PATH)
        md = tableToMarkdown(f'RSA NetWitness 11.5 -  Endpoint: {host.get("agentId")}', endpoint_context)

        command_results.append(CommandResults(
            readable_output=md,
            raw_response=response,
            indicator=endpoint_entry
        ))

    return command_results


def snapshots_list_for_host_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    agent_id = args.get('agent_id')
    service_id = args.get('service_id')
    response = client.snapshots_list_for_host_request(agent_id, service_id)

    readable_output = [{'Snapshot Id': snapshot_id} for snapshot_id in response]
    humanReadable = tableToMarkdown(f'Snapshot list for agent id {agent_id}-', readable_output)
    command_results = CommandResults(
        outputs_prefix='RSANetWitness115.SnapshotsListForHost',
        outputs=response,
        readable_output=humanReadable,
        raw_response=response
    )

    return command_results


def snapshot_details_get_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    agent_id = args.get('agent_id')
    snapshot_timestamp = args.get('snapshot_timestamp')
    service_id = args.get('service_id')
    categories = argToList(args.get('categories'))
    limit = arg_to_number(args.get('limit')) or 50
    offset = arg_to_number(args.get('offset')) or 0

    response = client.snapshot_details_get_request(agent_id, snapshot_timestamp, service_id, categories)

    results = response[offset:offset + limit]
    humanReadable = tableToMarkdown(f'Snapshot details for agent id {agent_id}-'
                                    f' \nshowing {len(results)} results out of {len(response)}',
                                    results, ['hostName', 'agentId', 'scanStartTime', 'directory', 'fileName'])
    command_results = CommandResults(
        outputs_prefix='RSANetWitness115.SnapshotDetailsGet',
        readable_output=humanReadable,
        outputs=results,
        raw_response=results
    )

    return command_results


def files_list_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    service_id = args.get('service_id')
    page_number = args.get('page_number')
    page_size = args.get('page_size')
    limit = arg_to_number(args.get('limit'))

    response, items = paging_command(limit, page_size, page_number, client.files_list_request, page_size_def='10',
                                     service_id=service_id)

    # remove duplicates that might occur from paging
    items = remove_duplicates_in_items(items, 'firstFileName')
    context_data = prepare_paging_context_data(response, items, 'FilesList', filter_id='firstFileName')
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
    service_id = args.get('service_id')
    scan_type = 'QUICK_SCAN'
    cpu_max = args.get('cpu_max')

    client.scan_request_request(agent_id, service_id, scan_type, cpu_max)
    command_results = CommandResults(
        readable_output=f"Scan request for host {agent_id}, sent successfully",
    )

    return command_results


def scan_stop_request_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    agent_id = args.get('agent_id')
    service_id = args.get('service_id')
    scan_type = 'CANCEL_SCAN'

    client.scan_stop_request_request(agent_id, service_id, scan_type)
    command_results = CommandResults(
        readable_output=f'Scan cancellation request for host {agent_id}, sent successfully',
    )

    return command_results


def host_alerts_list_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    agent_id = args.get('agent_id')
    service_id = args.get('service_id')
    alert_category = args.get('alert_category')

    response = client.host_alerts_list_request(agent_id, service_id, alert_category)
    command_results = CommandResults(
        outputs_prefix='RSANetWitness115.HostAlerts',
        outputs_key_field='id',
        outputs=response,
        raw_response=response
    )
    return command_results


def file_alerts_list_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    checksum = args.get('check_sum')
    service_id = args.get('service_id')
    alert_category = args.get('alert_category')

    response = client.file_alerts_list_request(checksum, service_id, alert_category)
    command_results = CommandResults(
        outputs_prefix='RSANetWitness115.FileAlerts',
        outputs_key_field='id',
        outputs=response,
        raw_response=response
    )

    return command_results


def file_download_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    agent_id = args.get('agent_id')
    service_id = args.get('service_id')
    path = args.get('path')
    count_files = args.get('count_files')
    max_file_size = args.get('max_file_size')

    client.file_download_request(agent_id, service_id, path, count_files, max_file_size)
    command_results = CommandResults(
        readable_output=f'Request for download {path} sent successfully'
    )

    return command_results


def mft_download_request_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    agent_id = args.get('agent_id')
    service_id = args.get('service_id')

    client.mft_download_request_request(agent_id, service_id)
    command_results = CommandResults(
        readable_output=f'MFT download request for host {agent_id} sent successfully'
    )
    return command_results


def system_dump_download_request_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    agent_id = args.get('agent_id')
    service_id = args.get('service_id')

    client.system_dump_download_request_request(agent_id, service_id)
    command_results = CommandResults(
        readable_output=f'System Dump download request for host {agent_id} sent successfully'
    )
    return command_results


def process_dump_download_request_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    agent_id = args.get('agent_id')
    service_id = args.get('service_id')
    process_id = args.get('process_id')
    eprocess = args.get('eprocess')
    file_name = args.get('file_name')
    path = args.get('path')
    file_hash = args.get('hash')
    process_create_utctime = args.get('process_create_utctime')

    client.process_dump_download_request_request(agent_id, service_id, process_id, eprocess, file_name, path, file_hash,
                                                 process_create_utctime)
    command_results = CommandResults(
        readable_output='Process Dump request sent successfully'
    )

    return command_results


def endpoint_isolate_from_network_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    agent_id = args.get('agent_id')
    service_id = args.get('service_id')
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
    service_id = args.get('service_id')
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
    service_id = args.get('service_id')
    comment = args.get('comment')
    allow_dns_only = args.get('allow_dns_only_by_system')

    client.endpoint_isolation_remove_request(agent_id, service_id, allow_dns_only, comment)
    command_results = CommandResults(
        readable_output=f'Isolate remove request, for Host {agent_id} ,sent successfully'
    )
    return command_results


def fetch_incidents(client: Client) -> list:
    total_items, last_fetched_ids, timestamp = client.get_incidents()
    incidents: List[Dict] = []
    new_ids = []
    for item in total_items:
        inc_id = item.get('id')
        new_ids.append(inc_id)
        item['incident_url'] = client.get_incident_url(inc_id)
        incident = {"name": f"RSA NetWitness 11.5 {item.get('id')} - {item.get('title')}",
                    "occurred": item.get('created'),
                    "rawJSON": json.dumps(item)}
        # items arrived from last to first - change order
        incidents.insert(0, incident)

    new_last_run = incidents[-1].get('occurred') if incidents else timestamp
    # in case a couple of incidents have the same timestamp, we want to add to our last id list and not run over it
    if is_new_run_time_equal_last_run_time(timestamp, new_last_run):
        new_ids.extend(last_fetched_ids)

    demisto.setLastRun({"timestamp": new_last_run, "last_fetched_ids": new_ids})
    return incidents


def is_new_run_time_equal_last_run_time(last_run_time: Optional[Any], new_run_time: Optional[Any]) -> bool:
    """Check if the two given string times are equal.

       Args:
           last_run_time (str): last run time.
           new_run_time (str): new run time.

       Returns:
           (bool) True if the times are equal. False otherwise.
       """
    try:
        last_run_datetime = arg_to_datetime(last_run_time)
        new_datetime = arg_to_datetime(new_run_time)

    except ValueError:
        raise DemistoException("Incorrect date time in fetch")

    return last_run_datetime == new_datetime


def remove_duplicates_for_fetch(items: list, last_fetched_ids: list) -> list:
    """Remove items that were already sent in last fetch.

       Args:
           items (list): Items retrieved in this fetch.
           last_fetched_ids (list): ID's of items from last fetch.

       Returns:
           (list) New items without items from last fetch.
       """
    new_items = []
    for item in items:
        if item.get('id') and item.get('id') not in last_fetched_ids:
            new_items.append(item)

    return new_items


def remove_duplicates_in_items(items: list, id_key: str) -> list:
    """Remove duplicate items based on the given id key,

       Args:
           items (list): The items list.
           id_key (str): The ID key for suplication check.

       Returns:
           (list) New items without duplications.
       """
    ids = {}
    new_items = []
    for item in items:
        item_id = item.get(id_key)
        if item_id not in ids:
            ids[item_id] = True
            new_items.append(item)

    return new_items


def prepare_incidents_readable_items(items: List[Dict[str, Any]]) -> list:
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

    return readable_items


def prepare_alerts_readable_items(items: List[Dict[str, Any]]) -> list:
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

    return readable_items


def prepare_hosts_readable_items(items: List[Dict[str, Any]]) -> list:
    readable_items = [
        {
            'agentId': item.get('agentId'),
            'hostName': item.get('hostName'),
            'riskScore': item.get('riskScore'),
            'networkInterfaces': item.get('networkInterfaces'),
            'lastSeenTime': item.get('lastSeenTime')
        } for item in items
    ]

    return readable_items


def prepare_files_readable_items(items: List[Dict[str, Any]]) -> list:
    readable_items = [
        {
            'File Name': item.get('firstFileName'),
            'Risk Score': item.get('globalRiskScore'),
            'First Seen Time': item.get('firstSeenTime'),
            'Reputation': item.get('reputationStatus'),
            'Size': item.get('size'),
            'Signature': item.get('signature'),
            'PE Resources': item.get('pe', {}).get('resources') if item.get('pe') else None,
            'File Status': item.get('fileStatus'),
            'Remediation': item.get('remediationAction')
        } for item in items
    ]

    return readable_items


def prepare_paging_context_data(response: Dict[str, Any], items: List[Dict[str, Any]], suffix: str,
                                filter_id='id') -> dict:
    if not items:
        data = {}
    else:
        data = {
            f'RSANetWitness115.{suffix}(val.{filter_id} === obj.{filter_id})': items,
            f'RSANetWitness115.paging.{suffix}(true)': {"pageNumber": response.get('pageNumber'),
                                                        "pageSize": response.get('pageSize'),
                                                        "totalPages": response.get('totalPages'),
                                                        "totalItems": response.get('totalItems'),
                                                        "hasNext": response.get('hasNext'),
                                                        "hasPrevious": response.get('hasPrevious')}
        }

    return data


def exception_handler(res):
    """Handle exceptions from requests to API.

       Args:
           res: The response with error.
       """
    try:
        res_data = res.json()
        error_code = res_data['status']
        error_msg = build_error_msg(res_data['errors'])
        exception = DemistoException(ERROR_TITLES.get(error_code, '') + error_msg)

    except Exception:
        exception = DemistoException('Error in API call [{}] - {}'.format(res.status_code, res.reason))

    raise exception


def build_error_msg(error_body: dict) -> str:
    """Build the specific error string from error_body.

       Args:
           error_body (list): The items list.

       Returns:
           (str) Error message.
       """
    ret_error_msg = ''
    for error in error_body:
        if error.get('field'):
            ret_error_msg += 'field ' + error['field']
        if error.get('message'):
            ret_error_msg += ' ' + error['message']
    return ret_error_msg


def create_exclusions_list(ips_str_list: Optional[Any]) -> list:
    """Build exclusion list in API format from ip list.

       Args:
           ips_str_list (str): The IP's list argument from request.

       Returns:
           (list) The exclusion list in the API format.
       """
    ips_list = argToList(ips_str_list, ',')
    exclusion_list = []
    for ip in ips_list:
        ip_type = auto_detect_indicator_type(ip)
        if ip_type not in ('IP', 'IPv6'):
            raise DemistoException(f'Invalid ip address - {ip}')
        is_v4 = ip_type == 'IP'
        ip_data = {"ip": ip, "v4": is_v4}
        exclusion_list.append(ip_data)
    return exclusion_list


def create_filter(args: dict) -> Optional[dict]:
    """
    Create filter in the API format for hosts_list request.

       Args:
           args (dict): Arguments dict with only the following keys - agentId, riskScore, ip, hostName

       Returns:
           (str) The created filter.
       """
    if 'ip' in args.keys():
        args['networkInterfaces.ipv4'] = args.pop('ip')
    expression_list = []
    for arg in args:
        value = args.get(arg)
        if arg == 'riskScore':
            restriction = "GREATER_THAN_OR_EQUAL_TO"
            values_list = [arg_to_number(value)]
        else:
            restriction = "IN"
            values_list = argToList(value)

        values_res = [{"value": val} for val in values_list]
        expression = {
            "propertyName": arg,
            "restrictionType": restriction,
            "propertyValues": values_res
        }
        expression_list.append(expression)
    if expression_list:
        return {"criteria": {"criteriaList": [{"expressionList": expression_list}], "predicateType": "AND"}}
    else:
        return None


def get_network_interfaces_info(endpoint: dict) -> Tuple[list, list]:
    """Retrieve ip and mac lists from an endpoint item.

       Args:
           endpoint (dict): Endpoint item from request response.

       Returns:
           (list) IP's list from the item.
           (list) mac addresses list from the item.
       """
    ips_list = []
    mac_address_list = []
    for data in endpoint.get('networkInterfaces', []):
        ips_list.append(data.get('ipv4'))
        mac_address_list.append((data.get('macAddress')))

    return ips_list, mac_address_list


def create_time(given_time: Optional[Any]) -> Optional[str]:
    """
    Convert given argument time to iso format with Z ending, if received None returns None.

       Args:
           given_time (str): Time argument in str.

       Returns:
           (str) Str time argument in iso format for API.
       """
    if not given_time:
        return None
    datetime_time = arg_to_datetime(given_time)
    if not datetime_time:
        raise DemistoException("Time parameter supplied in invalid, make sure to supply a valid argument")
    return datetime_time.strftime(DATE_FORMAT)


def get_now_time() -> Optional[str]:
    """
    Create a string time of the current time in date format.
       """
    now_time = arg_to_datetime('now')
    if now_time:
        str_now_time = now_time.strftime(DATE_FORMAT)
        return str_now_time
    else:
        return None


def test_module(client: Client, params) -> None:
    if params.get('isFetch'):
        client.get_incidents()

    if params.get('service_id'):
        client.hosts_list_request('1', '0', None, None)

    return_results('ok')


def main() -> None:
    params: Dict[str, Any] = demisto.params()
    args: Dict[str, Any] = demisto.args()
    url = params.get('url')
    verify_certificate: bool = not params.get('insecure', False)
    proxy = params.get('proxy', False)
    service_id = params.get('service_id')
    fetch_time = params.get('first_fetch', '1 days')
    fetch_limit = params.get('max_fetch', '100')
    cred = params.get('credentials')
    headers: Dict[str, str] = {}

    command = demisto.command()
    demisto.debug(f'Command being called is {command}')

    try:
        requests.packages.urllib3.disable_warnings()
        client: Client = Client(url, verify_certificate, proxy, headers=headers, service_id=service_id,
                                fetch_time=fetch_time, fetch_limit=fetch_limit, cred=cred)
        client.get_token()

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
            incidents = fetch_incidents(client)
            demisto.incidents(incidents)
        elif command in commands:
            return_results(commands[command](client, args))
        else:
            raise NotImplementedError(f'{command} command is not implemented.')

    except Exception as e:
        return_error(str(e))


if __name__ in ['__main__', 'builtin', 'builtins']:
    main()

