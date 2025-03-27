import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
from requests import HTTPError
from datetime import datetime, timedelta, UTC


ERROR_TITLES = {
    400: "400 Bad Request - The request was malformed, check the given arguments\n",
    401: "401 Unauthorized - authentication is required and has failed\n",
    403: "403 Forbidden - he user might not have the necessary permissions for a resource.\n ",
    404: "404 Not Found - The requested resource does not exist.\n",
    500: "500 Internal Server Error - An unexpected error has occurred.\n"
}
DATE_FORMAT = '%Y-%m-%dT%H:%M:%S.%MZ'
DEFAULT_MAX_INCIDENT_ALERTS = 50

# =========== Mirroring Mechanism Globals ===========
MAX_NB_MIRROR_PULL = 1500
MIRROR_DIRECTION = {
    'None': None,
    'Incoming': 'In',
    'Outgoing': 'Out',
    'Incoming And Outgoing': 'Both'
}
OUTGOING_MIRRORED_FIELDS = ['status', 'assignee']


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

    def _http_request(self, method, url_suffix='', **kwargs):  # type: ignore[override]
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

    def list_incidents_request(self, page_size: str | None, page_number: str | None,
                               until: str | None, since: str | None) -> dict:
        params = assign_params(until=until, since=since, pageSize=page_size, pageNumber=page_number)
        return self._http_request('GET', 'rest/api/incidents', params=params)

    def get_incident_request(self, inc_id: str | None) -> dict:
        return self._http_request('GET', f'rest/api/incidents/{inc_id}')

    def update_incident_request(self, id_: Any | None, status: Any | None, assignee: Any | None) -> dict:
        data = assign_params(status=status, assignee=assignee)
        return self._http_request('PATCH', f'rest/api/incidents/{id_}', json_data=data)

    def remove_incident_request(self, id_: str | None) -> dict:
        return self._http_request(
            'DELETE', f'rest/api/incidents/{id_}', return_empty_response=True
        )

    def incident_add_journal_entry_request(self, id_: str | None, author, notes: str | None,
                                           milestone: str | None) -> dict:
        data = assign_params(author=author, milestone=milestone, notes=notes)
        return self._http_request(
            'POST',
            f'rest/api/incidents/{id_}/journal',
            json_data=data,
            empty_valid_codes=[201],
            return_empty_response=True,
        )

    def incident_list_alerts_request(self, page_size: str | None, page_number: str | None, id_: str | None) -> dict:
        params = assign_params(pageNumber=page_number, pageSize=page_size)
        return self._http_request(
            'GET', f'rest/api/incidents/{id_}/alerts', params=params
        )

    def services_list_request(self, name: Any | None) -> dict:
        params = assign_params(name=name)
        return self._http_request('GET', 'rest/api/services', params=params)

    def hosts_list_request(self, page_size: str | None, page_number: str | None, service_id: str | None,
                           added_filter: dict | None) -> dict:
        service_id = service_id or self.service_id
        params = assign_params(serviceId=service_id, pageNumber=page_number, pageSize=page_size)
        data = added_filter
        return self._http_request(
            'GET', 'rest/api/hosts', params=params, json_data=data
        )

    def snapshots_list_for_host_request(self, agent_id: str | None, service_id: str | None) -> dict:
        service_id = service_id or self.service_id
        params = assign_params(serviceId=service_id)
        return self._http_request(
            'GET', f'rest/api/host/{agent_id}/snapshots', params=params
        )

    def snapshot_details_get_request(self, agent_id: str | None, snapshot_timestamp: str | None,
                                     service_id: str | None, categories: list | None) -> dict:
        service_id = service_id or self.service_id
        params = assign_params(serviceId=service_id, categories=categories)
        return self._http_request(
            'GET',
            f'rest/api/host/{agent_id}/snapshots/{snapshot_timestamp}',
            params=params,
        )

    def files_list_request(self, page_size: str | None, page_number: str | None,
                           service_id: str | None) -> dict:
        service_id = service_id or self.service_id
        params = assign_params(serviceId=service_id, pageNumber=page_number, pageSize=page_size)
        return self._http_request('GET', 'rest/api/files', params=params)

    def scan_request_request(self, agent_id: str | None, service_id: str | None, scan_type: str | None,
                             cpu_max: str | None) -> dict:
        service_id = service_id or self.service_id
        params = assign_params(serviceId=service_id, scanType=scan_type, cpuMax=cpu_max)
        return self._http_request(
            'POST',
            f'rest/api/host/{agent_id}/scan',
            params=params,
            empty_valid_codes=[200],
            return_empty_response=True,
        )

    def scan_stop_request_request(self, agent_id: str | None, service_id: str | None,
                                  scan_type: str | None) -> dict:
        service_id = service_id or self.service_id
        params = assign_params(serviceId=service_id, scanType=scan_type)
        return self._http_request(
            'DELETE',
            f'rest/api/host/{agent_id}/scan',
            params=params,
            empty_valid_codes=[200],
            return_empty_response=True,
        )

    def host_alerts_list_request(self, agent_id: str | None, service_id: str | None,
                                 alert_category: str | None) -> dict:
        service_id = service_id or self.service_id
        params = assign_params(serviceId=service_id, alertCategory=alert_category)
        return self._http_request(
            'GET', f'rest/api/host/{agent_id}/alerts', params=params
        )

    def file_alerts_list_request(self, checksum: str | None, service_id: str | None,
                                 alert_category: str | None) -> dict:
        service_id = service_id or self.service_id
        params = assign_params(serviceId=service_id, alertCategory=alert_category)
        return self._http_request(
            'GET', f'rest/api/file/{checksum}/alerts', params=params
        )

    def file_download_request(self, agent_id: str | None, service_id: str | None, path: str | None,
                              count_files: str | None, max_file_size: Any | None) -> dict:
        service_id = service_id or self.service_id
        params = assign_params(serviceId=service_id)
        if path and '*' in path:
            url = f'rest/api/host/{agent_id}/download/download-files'
            data = {'countFiles': count_files, 'maxFileSize': max_file_size, "path": path}

        else:
            url = f'rest/api/host/{agent_id}/download/download-file'
            data = {"path": path}

        return self._http_request(
            'POST',
            url,
            params=params,
            json_data=data,
            empty_valid_codes=[200],
            return_empty_response=True,
        )

    def mft_download_request_request(self, agent_id: str | None, service_id: str | None, path: str | None) -> dict:
        service_id = service_id or self.service_id
        params = assign_params(serviceId=service_id, path=path)
        return self._http_request(
            'POST',
            f'rest/api/host/{agent_id}/download/mft',
            params=params,
            empty_valid_codes=[200],
            return_empty_response=True,
        )

    def system_dump_download_request_request(self, agent_id: str | None, service_id: str | None) -> dict:
        service_id = service_id or self.service_id
        params = assign_params(serviceId=service_id)
        return self._http_request(
            'POST',
            f'rest/api/host/{agent_id}/download/system-dump',
            params=params,
            empty_valid_codes=[200],
            return_empty_response=True,
        )

    def process_dump_download_request_request(self, agent_id: str | None, service_id: str | None,
                                              process_id: str | None, eprocess: str | None,
                                              file_name: str | None, path: str | None, file_hash: str | None,
                                              process_create_utctime: str | None) -> dict:
        service_id = service_id or self.service_id
        params = assign_params(serviceId=service_id)
        data = assign_params(processId=process_id, eprocess=eprocess, fileName=file_name, path=path, hash=file_hash,
                             processCreateUtcTime=process_create_utctime)
        return self._http_request(
            'POST',
            f'rest/api/host/{agent_id}/download/process-dump',
            params=params,
            json_data=data,
            empty_valid_codes=[200],
            return_empty_response=True,
        )

    def endpoint_isolate_from_network_request(self, agent_id: str | None, service_id: str | None,
                                              allow_dns_only: str | None, exclusions: list | None,
                                              comment: str | None) -> dict:
        service_id = service_id or self.service_id
        params = assign_params(serviceId=service_id)
        data = assign_params(comment=comment, allowDnsOnlyBySystem=allow_dns_only, exclusions=exclusions)

        return self._http_request(
            'POST',
            f'rest/api/host/{agent_id}/isolation',
            params=params,
            json_data=data,
            empty_valid_codes=[200],
            return_empty_response=True,
        )

    def endpoint_update_exclusions_request(self, agent_id: str | None, service_id: str | None,
                                           allow_dns_only: str | None, exclusions: list | None,
                                           comment: str | None) -> dict:
        service_id = service_id or self.service_id
        params = assign_params(serviceId=service_id)
        data = assign_params(comment=comment, allowDnsOnlyBySystem=allow_dns_only, exclusions=exclusions)
        return self._http_request(
            'PATCH',
            f'rest/api/host/{agent_id}/isolation',
            params=params,
            json_data=data,
            empty_valid_codes=[200],
            return_empty_response=True,
        )

    def endpoint_isolation_remove_request(self, agent_id: str | None, service_id: str | None,
                                          allow_dns_only: str | None, comment: str | None) -> dict:
        service_id = service_id or self.service_id
        params = assign_params(serviceId=service_id)
        data = assign_params(comment=comment, allowDnsOnlyBySystem=allow_dns_only)
        return self._http_request(
            'DELETE',
            f'rest/api/host/{agent_id}/isolation',
            params=params,
            json_data=data,
            empty_valid_codes=[200],
            return_empty_response=True,
        )

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

    def generate_new_token(self, refresh_token: str | None = None) -> None:
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
            # since context store other data, we get the context, update the right field and set the context
            context_dict = demisto.getIntegrationContext()
            context_dict["token"] = new_token
            context_dict["refresh_token"] = refresh_token
            demisto.setIntegrationContext(context_dict)

        else:
            raise DemistoException("Error in authentication process- couldn't generate a token")

    def get_incidents(self) -> tuple[list[Any], Any, Any | None]:
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
            if last_fetch := arg_to_datetime(fetch_time, required=True):
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
        total_items: list[dict] = []
        while total < fetch_limit and page_number >= 0:
            try:
                response = self.list_incidents_request(page_size, page_number, until, timestamp)
            except HTTPError as e:
                if e.response is not None and e.response.status_code == 429:
                    raise DemistoException(
                        'Too many requests, try later or reduce the number of Fetch Limit parameter.'
                    ) from e
                raise e

            items = response.get('items', [])
            new_items = remove_duplicates_for_fetch(items, last_fetched_ids)
            # items order is from old to new , add new items at the start of list to maintain order
            total_items = new_items + total_items
            total += len(new_items)
            page_number -= 1

        # bring the last 'fetch_limit' items, as order is reversed
        total_items = total_items[len(total_items) - fetch_limit:]
        return total_items, last_fetched_ids, timestamp


def paging_command(limit: int | None, page_size: Union[str, None, int], page_number: str | None, func_command,
                   page_size_def='50', **kwargs) -> tuple[Any, Union[list, Any]]:
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
        if page_number or page_size:
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


def list_incidents_command(client: Client, args: dict[str, Any]) -> CommandResults:
    limit = arg_to_number(args.get('limit'))
    # we always supply 'until' argument to prevent duplications due to paging
    until = create_time(args.get('until')) or get_now_time()
    since = create_time(args.get('since'))
    page_size = args.get('page_size')
    page_number = args.get('page_number')

    if inc_id := args.get('id'):
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
    return CommandResults(
        outputs=context_data,
        readable_output=humanReadable,
        raw_response=response,
    )


def update_incident_command(client: Client, args: dict[str, Any]) -> CommandResults:
    id_ = args.get('id')
    status = args.get('status')
    assignee = args.get('assignee')

    response = client.update_incident_request(id_, status, assignee)

    items = prepare_incidents_readable_items([response])
    humanReadable = tableToMarkdown(f'Updated Incident {id_}', items,
                                    ['Id', 'Title', 'Summary', 'Priority', 'RiskScore', 'Status',
                                     'AlertCount', 'Created', 'LastUpdated', 'Assignee', 'Sources', 'Categories'])
    return CommandResults(
        outputs_prefix='RSANetWitness115.Incidents',
        outputs_key_field='id',
        outputs=response,
        readable_output=humanReadable,
        raw_response=response,
    )


def remove_incident_command(client: Client, args: dict[str, Any]) -> CommandResults:
    id_ = args.get('id')

    client.remove_incident_request(id_)
    return CommandResults(
        readable_output=f'Incident {id_} deleted successfully',
    )


def incident_add_journal_entry_command(client: Client, args: dict[str, Any]) -> CommandResults:
    id_ = args.get('id')
    author = args.get('author') or client.get_username()
    notes = args.get('notes')
    milestone = args.get('milestone')

    client.incident_add_journal_entry_request(id_, author, notes, milestone)
    return CommandResults(
        readable_output=f'Journal entry added successfully for incident {id_} '
    )


def incident_list_alerts_command(client: Client, args: dict[str, Any]) -> CommandResults:
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
    return CommandResults(
        outputs=context_data,
        readable_output=humanReadable,
        raw_response=response,
    )


def services_list_command(client: Client, args: dict[str, Any]) -> CommandResults:
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


def hosts_list_command(client: Client, args: dict[str, Any]) -> CommandResults:
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
    return CommandResults(
        outputs=context_data,
        readable_output=humanReadable,
        raw_response=response,
    )


def endpoint_command(client: Client, args: dict[str, Any]) -> list[CommandResults]:
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


def snapshots_list_for_host_command(client: Client, args: dict[str, Any]) -> CommandResults:
    agent_id = args.get('agent_id')
    service_id = args.get('service_id')
    response = client.snapshots_list_for_host_request(agent_id, service_id)

    readable_output = [{'Snapshot Id': snapshot_id} for snapshot_id in response]
    humanReadable = tableToMarkdown(f'Snapshot list for agent id {agent_id}-', readable_output)
    return CommandResults(
        outputs_prefix='RSANetWitness115.SnapshotsListForHost',
        outputs=response,
        readable_output=humanReadable,
        raw_response=response,
    )


def snapshot_details_get_command(client: Client, args: dict[str, Any]) -> CommandResults:
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
    return CommandResults(
        outputs_prefix='RSANetWitness115.SnapshotDetailsGet',
        readable_output=humanReadable,
        outputs=results,
        raw_response=results,
    )


def files_list_command(client: Client, args: dict[str, Any]) -> CommandResults:
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

    return CommandResults(
        readable_output=humanReadable,
        outputs=context_data,
        raw_response=response,
    )


def scan_request_command(client: Client, args: dict[str, Any]) -> CommandResults:
    agent_id = args.get('agent_id')
    service_id = args.get('service_id')
    scan_type = 'QUICK_SCAN'
    cpu_max = args.get('cpu_max')

    client.scan_request_request(agent_id, service_id, scan_type, cpu_max)
    return CommandResults(
        readable_output=f"Scan request for host {agent_id}, sent successfully",
    )


def scan_stop_request_command(client: Client, args: dict[str, Any]) -> CommandResults:
    agent_id = args.get('agent_id')
    service_id = args.get('service_id')
    scan_type = 'CANCEL_SCAN'

    client.scan_stop_request_request(agent_id, service_id, scan_type)
    return CommandResults(
        readable_output=f'Scan cancellation request for host {agent_id}, sent successfully',
    )


def host_alerts_list_command(client: Client, args: dict[str, Any]) -> CommandResults:
    agent_id = args.get('agent_id')
    service_id = args.get('service_id')
    alert_category = args.get('alert_category')

    response = client.host_alerts_list_request(agent_id, service_id, alert_category)
    return CommandResults(
        outputs_prefix='RSANetWitness115.HostAlerts',
        outputs_key_field='id',
        outputs=response,
        raw_response=response,
    )


def file_alerts_list_command(client: Client, args: dict[str, Any]) -> CommandResults:
    checksum = args.get('check_sum')
    service_id = args.get('service_id')
    alert_category = args.get('alert_category')

    response = client.file_alerts_list_request(checksum, service_id, alert_category)
    return CommandResults(
        outputs_prefix='RSANetWitness115.FileAlerts',
        outputs_key_field='id',
        outputs=response,
        raw_response=response,
    )


def file_download_command(client: Client, args: dict[str, Any]) -> CommandResults:
    agent_id = args.get('agent_id')
    service_id = args.get('service_id')
    path = args.get('path')
    count_files = args.get('count_files')
    max_file_size = args.get('max_file_size')

    client.file_download_request(agent_id, service_id, path, count_files, max_file_size)
    return CommandResults(
        readable_output=f'Request for download {path} sent successfully'
    )


def mft_download_request_command(client: Client, args: dict[str, Any]) -> CommandResults:
    agent_id = args.get('agent_id')
    service_id = args.get('service_id')
    path = args.get('path')

    client.mft_download_request_request(agent_id, service_id, path=path)

    return CommandResults(
        readable_output=f'MFT download request for host {agent_id} sent successfully'
    )


def system_dump_download_request_command(client: Client, args: dict[str, Any]) -> CommandResults:
    agent_id = args.get('agent_id')
    service_id = args.get('service_id')

    client.system_dump_download_request_request(agent_id, service_id)
    return CommandResults(
        readable_output=f'System Dump download request for host {agent_id} sent successfully'
    )


def process_dump_download_request_command(client: Client, args: dict[str, Any]) -> CommandResults:
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
    return CommandResults(
        readable_output='Process Dump request sent successfully'
    )


def endpoint_isolate_from_network_command(client: Client, args: dict[str, Any]) -> CommandResults:
    agent_id = args.get('agent_id')
    service_id = args.get('service_id')
    allow_dns_only = args.get('allow_dns_only_by_system')
    exclusion_list = create_exclusions_list(args.get('exclusion_list')) if args.get('exclusion_list') else None
    comment = args.get('comment')

    client.endpoint_isolate_from_network_request(agent_id, service_id, allow_dns_only, exclusion_list,
                                                 comment)
    return CommandResults(
        readable_output=f'Isolate request for Host {agent_id} has been sent successfully'
    )


def endpoint_update_exclusions_command(client: Client, args: dict[str, Any]) -> CommandResults:
    agent_id = args.get('agent_id')
    service_id = args.get('service_id')
    allow_dns_only = args.get('allow_dns_only_by_system')
    exclusion_list = create_exclusions_list(args.get('exclusion_list')) if args.get('exclusion_list') else None
    comment = args.get('comment')

    client.endpoint_update_exclusions_request(agent_id, service_id, allow_dns_only, exclusion_list, comment)
    return CommandResults(
        readable_output=f'Isolate update exclusions request, for Host {agent_id} ,sent successfully'
    )


def endpoint_isolation_remove_command(client: Client, args: dict[str, Any]) -> CommandResults:
    agent_id = args.get('agent_id')
    service_id = args.get('service_id')
    comment = args.get('comment')
    allow_dns_only = args.get('allow_dns_only_by_system')

    client.endpoint_isolation_remove_request(agent_id, service_id, allow_dns_only, comment)
    return CommandResults(
        readable_output=f'Isolate remove request, for Host {agent_id} ,sent successfully'
    )


def fetch_alerts_related_incident(client: Client, incident_id: str, max_alerts: int) -> list[dict[str, Any]]:
    """
    Returns the alerts that are associated with the given incident.
    """
    alerts: list[dict] = []
    has_next = True
    page_number = 0
    while has_next and len(alerts) < max_alerts:
        demisto.debug(f"fetching alerts, {page_number=}")
        try:
            response_body = client.incident_list_alerts_request(
                page_number=str(page_number),
                id_=incident_id,
                page_size=None
            )
        except HTTPError as e:
            if e.response is not None and e.response.status_code == 429:
                raise DemistoException(
                    'Too many requests, try later or reduce the number of Fetch Limit parameter.'
                ) from e
            raise e

        except Exception:
            demisto.error(f"Error occurred while fetching alerts related to {incident_id=}. {page_number=}")
            raise

        items = response_body.get('items', [])
        alerts.extend(items[:max_alerts - len(alerts)])
        page_number += 1
        has_next = response_body.get('hasNext', False)

    return alerts


def fetch_incidents(client: Client, params: dict) -> list:
    total_items, last_fetched_ids, timestamp = client.get_incidents()
    incidents: list[dict] = []
    new_ids = []
    context_dict = demisto.getIntegrationContext()
    inc_data = context_dict.get("IncidentsDataCount", {})
    for item in total_items:
        inc_id = item['id']
        new_ids.append(inc_id)
        item['incident_url'] = client.get_incident_url(inc_id)

        # add to incident object an array of all related alerts
        if params['import_alerts']:
            max_alerts = min(arg_to_number(params.get('max_alerts')) or DEFAULT_MAX_INCIDENT_ALERTS, DEFAULT_MAX_INCIDENT_ALERTS)
            item['alerts'] = fetch_alerts_related_incident(client, inc_id, max_alerts)

        item['mirror_instance'] = demisto.integrationInstance()
        item['mirror_direction'] = MIRROR_DIRECTION.get(str(params.get('mirror_direction')))

        incident = {"name": f"RSA NetWitness 11.5 {inc_id} - {item.get('title')}",
                    "occurred": item.get('created'),
                    "rawJSON": json.dumps(item)}
        # items arrived from last to first - change order
        incidents.insert(0, incident)
        inc_data[inc_id] = struct_inc_context(item.get('alertCount'), item.get('eventCount'), item.get('created'))
    # store some data for mirroring purposes
    demisto.setIntegrationContext(context_dict)

    new_last_run = incidents[-1].get('occurred') if incidents else timestamp
    # in case a couple of incidents have the same timestamp, we want to add to our last id list and not run over it
    if is_new_run_time_equal_last_run_time(timestamp, new_last_run):
        new_ids.extend(last_fetched_ids)

    demisto.setLastRun({"timestamp": new_last_run, "last_fetched_ids": new_ids})
    return incidents


def is_new_run_time_equal_last_run_time(last_run_time: Any | None, new_run_time: Any | None) -> bool:
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

    except ValueError as e:
        raise DemistoException("Incorrect date time in fetch") from e

    return last_run_datetime == new_datetime


def remove_duplicates_for_fetch(items: list, last_fetched_ids: list) -> list:
    """Remove items that were already sent in last fetch.

       Args:
           items (list): Items retrieved in this fetch.
           last_fetched_ids (list): ID's of items from last fetch.

       Returns:
           (list) New items without items from last fetch.
       """
    return [
        item
        for item in items
        if item.get('id') and item.get('id') not in last_fetched_ids
    ]


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


def prepare_incidents_readable_items(items: list[dict[str, Any]]) -> list:
    return [
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
            'Categories': item.get('categories'),
        }
        for item in items
    ]


def prepare_alerts_readable_items(items: list[dict[str, Any]]) -> list:
    return [
        {
            'Id': item.get('id'),
            'Title': item.get('title'),
            'Detail': item.get('detail'),
            'Created': item.get('created'),
            'Source': item.get('source'),
            'RiskScore': item.get('riskScore'),
            'Type': item.get('type'),
            'Events': item.get('events'),
        }
        for item in items
    ]


def prepare_hosts_readable_items(items: list[dict[str, Any]]) -> list[dict]:
    return [
        {
            'agentId': item.get('agentId'),
            'hostName': item.get('hostName'),
            'riskScore': item.get('riskScore'),
            'networkInterfaces': item.get('networkInterfaces'),
            'lastSeenTime': item.get('lastSeenTime'),
        }
        for item in items
    ]


def prepare_files_readable_items(items: list[dict[str, Any]]) -> list[dict]:
    return [
        {
            'File Name': item.get('firstFileName'),
            'Risk Score': item.get('globalRiskScore'),
            'First Seen Time': item.get('firstSeenTime'),
            'Reputation': item.get('reputationStatus'),
            'Size': item.get('size'),
            'Signature': item.get('signature'),
            'PE Resources': item.get('pe', {}).get('resources')
            if item.get('pe')
            else None,
            'File Status': item.get('fileStatus'),
            'Remediation': item.get('remediationAction'),
        }
        for item in items
    ]


def prepare_paging_context_data(response: dict[str, Any], items: list[dict[str, Any]], suffix: str,
                                filter_id='id') -> dict:
    return (
        {}
        if not items
        else {
            f'RSANetWitness115.{suffix}(val.{filter_id} === obj.{filter_id})': items,
            f'RSANetWitness115.paging.{suffix}(true)': {
                "pageNumber": response.get('pageNumber'),
                "pageSize": response.get('pageSize'),
                "totalPages": response.get('totalPages'),
                "totalItems": response.get('totalItems'),
                "hasNext": response.get('hasNext'),
                "hasPrevious": response.get('hasPrevious'),
            },
        }
    )


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
        exception = DemistoException(f'Error in API call [{res.status_code}] - {res.reason}')

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


def create_exclusions_list(ips_str_list: Any | None) -> list:
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


def create_filter(args: dict) -> dict | None:
    """
    Create filter in the API format for hosts_list request.

       Args:
           args (dict): Arguments dict with only the following keys - agentId, riskScore, ip, hostName

       Returns:
           (str) The created filter.
       """
    if 'ip' in args:
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


def get_network_interfaces_info(endpoint: dict) -> tuple[list, list]:
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
        mac_address_list.append(data.get('macAddress'))

    return ips_list, mac_address_list


def create_time(given_time: Any | None) -> str | None:
    """
    Convert given argument time to iso format with Z ending, if received None returns None.

       Args:
           given_time (str): Time argument in str.

       Returns:
           (str) Str time argument in iso format for API.
       """
    if not given_time:
        return None
    if datetime_time := arg_to_datetime(given_time):
        return datetime_time.strftime(DATE_FORMAT)
    else:
        raise DemistoException("Time parameter supplied in invalid, make sure to supply a valid argument")


def get_now_time() -> str | None:
    """
    Create a string time of the current time in date format.
    """
    if now_time := arg_to_datetime('now'):
        return now_time.strftime(DATE_FORMAT)
    else:
        return None


'''Mirror in and out'''


def get_mapping_fields_command() -> GetMappingFieldsResponse:
    """
    This command pulls the remote schema for the different incident types, and their associated incident fields,
    from the remote system.
    Returns: A list of keys you want to map
    """
    mapping_response = GetMappingFieldsResponse()
    incident_type_scheme = SchemeTypeMapping(type_name='RSA Netwitness incident')

    for field in OUTGOING_MIRRORED_FIELDS:
        incident_type_scheme.add_field(name=field)

    mapping_response.add_scheme_type(incident_type_scheme)

    return mapping_response


def xsoar_status_to_rsa_status(xsoar_status: int, xsoar_close_reason: str) -> str | None:
    """
    xsoar_status_to_rsa_status: Convert XSOAR status to RSA status
    Args:
        xsoar_status: XSOAR status
        xsoar_close_reason: XSOAR close reason

    Returns:
        str: RSA status
    """
    if xsoar_status == 2 and xsoar_close_reason == "False positive":
        return "ClosedFalsePositive"
    elif xsoar_status == 2:
        return "Closed"
    elif xsoar_status == 1:
        return "New"
    return None


def update_remote_system_command(client: Client, args: dict, params: dict) -> str:
    """update-remote-system command: pushes local changes to the remote system

    :type client: ``Client``
    :param client: XSOAR client to use

    :type args: ``Dict[str, Any]``
    :param args:
        all command arguments, usually passed from ``demisto.args()``.
        ``args['data']`` the data to send to the remote system
        ``args['entries']`` the entries to send to the remote system
        ``args['incidentChanged']`` boolean telling us if the local incident indeed changed or not
        ``args['remoteId']`` the remote incident id

    :return:
        ``str`` containing the remote incident id - really important if the incident is newly created remotely

    :rtype: ``str``
    """
    parsed_args = UpdateRemoteSystemArgs(args)
    if parsed_args.delta:
        demisto.debug(f'Got the following delta keys {str(list(parsed_args.delta.keys()))}')

    demisto.debug(f"Starting mirror out for the remote incident {parsed_args.remote_incident_id}")
    new_incident_id: str = parsed_args.remote_incident_id

    xsoar_status = parsed_args.data.get("status")
    xsoar_close_reason = parsed_args.data.get("closeReason")
    response = client.get_incident_request(new_incident_id)
    rsa_status = xsoar_status_to_rsa_status(xsoar_status, xsoar_close_reason)

    if rsa_status and response["status"] != rsa_status:
        demisto.debug(f"Current status should be {rsa_status} on RSA but is {response['status']}, updating incident...")
        response = client.update_incident_request(parsed_args.remote_incident_id, rsa_status, response.get("assignee"))
        demisto.debug(json.dumps(response))
    else:
        demisto.debug(f'Skipping updating remote incident fields [{parsed_args.remote_incident_id}] as it is '
                      f'not new nor changed.')

    return new_incident_id


def get_remote_data_command(client: Client, args: dict, params: dict):
    """
    get-remote-data command: Returns an updated incident and entries
    Args:
        client: XSOAR client to use
        args:
            id: incident id to retrieve
            lastUpdate: when was the last time we retrieved data

    Returns:
        GetRemoteDataResponse: The Response containing the update incident to mirror and the entries
    """

    entries = []
    remote_args = GetRemoteDataArgs(args)
    inc_id = remote_args.remote_incident_id
    close_incident = argToBoolean(params.get('close_incident', True))
    fetch_alert = argToBoolean(params.get("import_alerts", False))
    max_fetch_alerts = min(arg_to_number(params.get('max_alerts')) or DEFAULT_MAX_INCIDENT_ALERTS, DEFAULT_MAX_INCIDENT_ALERTS)

    response = client.get_incident_request(inc_id)

    # check if the user enable alerts fetching
    if fetch_alert:
        demisto.debug(f'Pulling alerts from incident {inc_id} !')
        inc_alert_count = int(response['alertCount'])
        if inc_alert_count <= max_fetch_alerts:
            alerts = fetch_alerts_related_incident(client, inc_id, inc_alert_count)
            demisto.debug(f'{len(alerts)} alerts pulled !')
            response['alerts'] = alerts
        else:
            demisto.debug("Skipping this step, max number of pull alerts reached for this incident !")

    if (response.get('status') == 'Closed' or response.get('status') == 'ClosedFalsePositive') and close_incident:
        demisto.info(f'Closing incident related to incident {inc_id}')
        entries = [{
            'Type': EntryType.NOTE,
            'Contents': {
                'dbotIncidentClose': True,
                'closeReason': 'Incident was closed on RSA Netwitness.'
            },
            'ContentsFormat': EntryFormat.JSON
        }]

    int_cont = get_integration_context()
    inc_data = int_cont.get("IncidentsDataCount", {})
    inc_data[inc_id] = struct_inc_context(response.get('alertCount'), response.get('eventCount'), response.get('created'))
    demisto.setIntegrationContext(int_cont)

    return GetRemoteDataResponse(mirrored_object=response, entries=entries)


def get_modified_remote_data_command(client: Client, args: dict, params: dict):
    """ Gets the list of all incident ids that have change since a given time

    Args:
        client (Client): Client object
        args (dict): The command argumens

    Returns:
        GetModifiedRemoteDataResponse: The response containing the list of ids of notables changed

    """
    modified_incidents_ids = []
    remote_args = GetModifiedRemoteDataArgs(args)
    max_fetch_alerts = min(arg_to_number(params.get('max_alerts')) or DEFAULT_MAX_INCIDENT_ALERTS, DEFAULT_MAX_INCIDENT_ALERTS)
    max_time_mirror_inc = min(arg_to_number(params.get("max_mirror_time")) or 3, 24)
    last_update = remote_args.last_update
    last_update_format = dateparser.parse(last_update, settings={'TIMEZONE': 'UTC'})  # converts to a UTC timestamp

    demisto.debug(f'Running get-modified-remote-data command. Last update is: {last_update_format}')

    # setting request
    datetime_now = datetime.now()
    since = datetime_now - timedelta(days=max_time_mirror_inc)
    since_format = since.strftime(DATE_FORMAT)
    until_format = datetime_now.strftime(DATE_FORMAT)
    response, items = paging_command(MAX_NB_MIRROR_PULL, None, None, client.list_incidents_request,
                                     until=until_format, since=since_format)

    demisto.debug(f"Total Retrieved Incidents : {len(items)} in {response.get('totalPages')} pages")

    # clean the integration context data of "old" incident
    clean_old_inc_context(max_time_mirror_inc)
    intCont = get_integration_context().get("IncidentsDataCount", {})
    for inc in items:
        if intCont.get(inc.get('id')):
            save_alert_count = intCont.get(inc.get('id'), {}).get('alertCount')
            save_event_count = intCont.get(inc.get('id'), {}).get('eventCount')
            demisto.debug(f"Last run incident {inc.get('id')} => "
                          f"Alert count: {save_alert_count} "
                          f"Event count: {save_event_count}")
            if save_alert_count != inc.get('alertCount') or save_event_count != inc.get('eventCount'):
                # compare the save nb of alert to see if we need to pull the alert or not
                if save_alert_count <= max_fetch_alerts:
                    modified_incidents_ids.append(inc.get("id"))
                    continue  # if added no need to do it twice
                else:
                    demisto.debug(f"Skipping this step, max number of pull alerts already reached"
                                  f"({save_alert_count} > {max_fetch_alerts}) for the incident {inc.get('id')} !")
        inc_last_update = arg_to_datetime(inc["lastUpdated"])
        if inc_last_update and last_update_format:
            demisto.debug(f"Incident {inc.get('id')} - "
                          f"Last run {last_update_format.timestamp()} - Last updated {inc_last_update.timestamp()} - "
                          f"Need update => {last_update_format.timestamp() < inc_last_update.timestamp()}")
            if last_update_format.timestamp() < inc_last_update.timestamp():
                modified_incidents_ids.append(inc.get("id"))
                continue  # if added no need to do it twice

    return GetModifiedRemoteDataResponse(list(set(modified_incidents_ids)))


def struct_inc_context(alert_count, event_count, created):
    """
    Strcture uses in the context data to save incident alert/event
    """
    return {"alertCount": alert_count, "eventCount": event_count, "Created": created}


def clean_old_inc_context(max_time_mirror_inc: int):
    """
    Clean the integration context of old incident
    """
    demisto.debug(f"Current context integration before cleaning => {json.dumps(clean_secret_integration_context())}")
    int_cont = demisto.getIntegrationContext()
    inc_data = int_cont.get("IncidentsDataCount", {})
    current_time = datetime.now()
    current_time = current_time.replace(tzinfo=UTC)
    total_know = 0
    res = {}
    for inc_id, inc in inc_data.items():
        inc_created = arg_to_datetime(inc["Created"])
        if inc_created:
            inc_created = inc_created.replace(tzinfo=UTC)
            diff = current_time - inc_created
            if diff.days <= max_time_mirror_inc:  # maximum RSA aggregation time 24 days
                res[inc_id] = inc
            else:
                demisto.debug(f"Incident {inc_id} has expired => {diff.days}")
                total_know += 1
    demisto.debug(f"{total_know} incidents cleaned from integration context for exceeding RSA monitoring age")
    demisto.debug(f"Current context integration after cleaning => {json.dumps(clean_secret_integration_context())}")
    int_cont["IncidentsDataCount"] = res
    demisto.setIntegrationContext(int_cont)


def clean_secret_integration_context() -> dict:
    """
    Sanitize context for output purpose
    """
    int_cont = demisto.getIntegrationContext()
    int_cont["refresh_token"] = "SECRET REPLACED"
    int_cont["token"] = "SECRET REPLACED"
    return int_cont


def test_module(client: Client, params) -> None:
    if params.get('isFetch'):
        client.get_incidents()

    if params.get('service_id'):
        client.hosts_list_request('1', '0', None, None)

    return_results('ok')


def main() -> None:
    command = demisto.command()
    params: dict[str, Any] = demisto.params()
    args: dict[str, Any] = demisto.args()
    url = params.get('url')
    verify_certificate: bool = not params.get('insecure', False)
    proxy = params.get('proxy', False)
    service_id = params.get('service_id')
    fetch_time = params.get('first_fetch', '1 days')
    fetch_limit = params.get('max_fetch', '100')
    cred = params.get('credentials')
    headers: dict[str, str] = {}

    demisto.debug(f'Command being called is {command}')

    try:
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
            incidents = fetch_incidents(client, params)
            demisto.incidents(incidents)
        elif command == 'get-remote-data':
            return_results(get_remote_data_command(client, args, params))
        elif demisto.command() == 'get-modified-remote-data':
            return_results(get_modified_remote_data_command(client, args, params))
        elif command == 'update-remote-system':
            return_results(update_remote_system_command(client, args, params))
        elif demisto.command() == 'get-mapping-fields':
            return_results(get_mapping_fields_command())
        elif command in commands:
            return_results(commands[command](client, args))
        else:
            raise NotImplementedError(f'{command} command is not implemented.')

    except Exception as e:
        return_error(str(e))


if __name__ in ['__main__', 'builtin', 'builtins']:
    main()
