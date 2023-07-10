import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
from typing import Any, Dict, List, cast, Tuple

import urllib3

# Disable insecure warnings
urllib3.disable_warnings()

DEFAULT_SEARCH_LIMIT = 100
MAX_ALERTS = 100  # max alerts per fetch
TIME_FORMAT = "%Y-%m-%dT%H:%M:%S"
URL_SUFFIX = "/public_api/v1"
SEVERITY_DICT = {
    'informational': IncidentSeverity.INFO,
    'low': IncidentSeverity.LOW,
    'medium': IncidentSeverity.MEDIUM,
    'high': IncidentSeverity.HIGH,
    'critical': IncidentSeverity.CRITICAL
}


class Client(BaseClient):
    """
    Client class to interact with the service API.
    """

    def __init__(self, base_url, verify, proxy, headers):
        """
        Class initialization.
        """
        super().__init__(base_url, verify=verify, proxy=proxy, headers=headers)

    def list_alerts_request(self, request_data: Dict) -> Dict[str, Any]:
        """Get a list of all asm alerts '/alerts/get_alerts/' endpoint.

        Args:
            request_data (dict): dict of parameters for API call.

        Returns:
            dict: dict containing list of external services.
        """

        response = self._http_request('POST', '/alerts/get_alerts/', json_data=request_data)

        return response

    def list_external_service_request(self, search_params: List[Dict]) -> Dict[str, Any]:
        """Get a list of all your external services using the '/assets/get_external_services/' endpoint.

        Args:
            search_params (list): list of search parameters to add to the API call body.

        Returns:
            dict: dict containing list of external services.
        """
        data = {"request_data": {"filters": search_params, "search_to": DEFAULT_SEARCH_LIMIT}}

        response = self._http_request('POST', '/assets/get_external_services/', json_data=data)

        return response

    def get_external_service_request(self, service_id_list: List[str]) -> Dict[str, Any]:
        """Get service details using the '/assets/get_external_service/' endpoint.

        Args:
            service_id_list (list): single service id in list format.

        Returns:
            dict: dict containing information on single external service.
        """
        data = {"request_data": {"service_id_list": service_id_list}}

        response = self._http_request('POST', '/assets/get_external_service', json_data=data)

        return response

    def list_external_ip_address_range_request(self) -> Dict[str, Any]:
        """Get a list of all your internet exposure IP ranges using the '/assets/get_external_ip_address_ranges/' endpoint.

        Returns:
            dict: dict containing list of external ip address ranges.
        """
        data = {"request_data": {"search_to": DEFAULT_SEARCH_LIMIT}}

        response = self._http_request('POST', '/assets/get_external_ip_address_ranges/', json_data=data)

        return response

    def get_external_ip_address_range_request(self, range_id_list: List[str]) -> Dict[str, Any]:
        """Get external IP address range details using the '/assets/get_external_ip_address_range/' endpoint.

        Args:
            range_id_list (list): single range id in list format.

        Returns:
            dict: dict containing information on external ip address range.
        """
        data = {"request_data": {"range_id_list": range_id_list}}

        response = self._http_request('POST', '/assets/get_external_ip_address_range/', json_data=data)

        return response

    def list_asset_internet_exposure_request(self, search_params: List[dict]) -> Dict[str, Any]:
        """Get a list of all your internet exposure assets using the '/assets/get_assets_internet_exposure/' endpoint.

        Args:
            search_params (list): list of search parameters to add to the API call body.

        Returns:
            dict: dict containing list of internet exposure assets.
        """
        data = {"request_data": {"filters": search_params, "search_to": DEFAULT_SEARCH_LIMIT}}

        response = self._http_request('POST', '/assets/get_assets_internet_exposure/', json_data=data)

        return response

    def get_asset_internet_exposure_request(self, asm_id_list: List[str]) -> Dict[str, Any]:
        """Get internet exposure asset details using the '/assets/get_asset_internet_exposure/' endpoint.

        Args:
            asm_id_list (list): single attack surface management id in list format.

        Returns:
            dict: dict containing information on an internet exposure asset.
        """
        data = {"request_data": {"asm_id_list": asm_id_list}}

        response = self._http_request('POST', '/assets/get_asset_internet_exposure/', json_data=data)

        return response


''' HELPER FUNCTIONS '''


def format_asm_id(formatted_response: List[dict]) -> List[dict]:
    """
    Takes the response from the asm-list-asset-internet-exposure command and converts `asm_id` key from list to str

    Args:
        formatted_response (list): response from asm-list-asset-internet-exposure command (json)

    Returns:
        list: list of dictionaries of parsed/formatted json object
    """

    if formatted_response:
        for entry in formatted_response:
            if entry.get('asm_ids'):
                entry['asm_ids'] = entry['asm_ids'][0]

    return formatted_response


''' COMMAND FUNCTIONS '''


def list_alerts_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    """
    asm-list-alerts command: Returns list of asm alerts.

    Args:
        client (Client): CortexXpanse client to use.
        args (dict): all command arguments, usually passed from ``demisto.args()``.
            ``args['alert_id_list']`` List of integers of the Alert ID.
            ``args['severity']`` List of strings of the Alert severity.
            ``args['lte_creation_time']`` string of time format "2019-12-31T23:59:00".
            ``args['gte_creation_time']`` string of time format "2019-12-31T23:59:00".
            ``args['sort_by_creation_time']`` optional - enum (asc,desc).
            ``args['sort_by_severity']`` optional - enum (asc,desc).
            ``args['page']`` Page number (for pagination). The default is 0 (the first page).
            ``args['limit']`` Maximum number of incidents to return per page. The default and maximum is 100.

    Returns:
        CommandResults: A ``CommandResults`` object that is then passed to ``return_results``, that contains external
        services.
    """
    alert_id_list = argToList(args.get('alert_id_list'))
    severity = argToList(args.get('severity'))
    lte_creation_time = args.get('lte_creation_time')
    gte_creation_time = args.get('gte_creation_time')
    sort_by_creation_time = args.get('sort_by_creation_time')
    sort_by_severity = args.get('sort_by_severity')
    page = int(args.get('page', 0))
    limit = int(args.get('limit', MAX_ALERTS))

    search_from = page * limit
    search_to = search_from + limit

    if limit > MAX_ALERTS:
        raise ValueError('Limit cannot be more than 100, please try again')
    if sort_by_creation_time and sort_by_severity:
        raise ValueError('Should be provide either sort_by_creation_time or '
                         'sort_by_severity. Can\'t provide both')

    # starts with param to only look for ASM alerts.  Can add others if defined.
    search_params = [{"field": "alert_source", "operator": "in", "value": ["ASM"]}]
    if alert_id_list:
        alert_id_ints = [int(i) for i in alert_id_list]
        search_params.append({"field": "alert_id_list", "operator": "in", "value": alert_id_ints})  # type: ignore
    if severity:
        search_params.append({"field": "severity", "operator": "in", "value": severity})
    if lte_creation_time:
        search_params.append({
            'field': 'creation_time',
            'operator': 'lte',
            'value': date_to_timestamp(lte_creation_time, TIME_FORMAT)
        })
    if gte_creation_time:
        search_params.append({
            'field': 'creation_time',
            'operator': 'gte',
            'value': date_to_timestamp(gte_creation_time, TIME_FORMAT)
        })

    if sort_by_creation_time:
        request_data = {"request_data": {"filters": search_params, 'search_from': search_from,
                        'search_to': search_to, "sort": {"field": "creation_time", "keyword": sort_by_creation_time}}}
    elif sort_by_severity:
        request_data = {"request_data": {"filters": search_params, 'search_from': search_from,
                        'search_to': search_to, "sort": {"field": "severity", "keyword": sort_by_severity}}}
    else:
        request_data = {"request_data": {"filters": search_params, 'search_from': search_from, 'search_to': search_to}}

    response = client.list_alerts_request(request_data)

    parsed = response.get('reply', {}).get('alerts')
    markdown = tableToMarkdown('ASM Alerts', parsed, removeNull=True, headerTransform=string_to_table_header)
    command_results = CommandResults(
        outputs_prefix='ASM.Alert',
        outputs_key_field='alert_id',
        outputs=parsed,
        raw_response=response,
        readable_output=markdown
    )

    return command_results


def list_external_service_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    """
    asm-list-external-service command: Returns list of external services.

    Args:
        client (Client): CortexXpanse client to use.
        args (dict): all command arguments, usually passed from ``demisto.args()``.
            ``args['ip_address']`` IP Address to search on.
            ``args['domain']`` Domain to search on.
            ``args['is_active']`` If the service active or not.
            ``args['discovery_type']`` how service was discovered.

    Returns:
        CommandResults: A ``CommandResults`` object that is then passed to ``return_results``, that contains external
        services.
    """
    ip_address = args.get('ip_address')
    domain = args.get('domain')
    is_active = args.get('is_active')
    discovery_type = args.get('discovery_type')
    # create list of search parameters or pass empty list.
    search_params = []
    if ip_address:
        search_params.append({"field": "ip_address", "operator": "eq", "value": ip_address})
    if domain:
        search_params.append({"field": "domain", "operator": "contains", "value": domain})
    if is_active:
        search_params.append({"field": "is_active", "operator": "in", "value": [is_active]})
    if discovery_type:
        search_params.append({"field": "discovery_type", "operator": "in", "value": [discovery_type]})

    response = client.list_external_service_request(search_params)
    parsed = response.get('reply', {}).get('external_services')
    markdown = tableToMarkdown('External Services', parsed, removeNull=True, headerTransform=string_to_table_header)
    command_results = CommandResults(
        outputs_prefix='ASM.ExternalService',
        outputs_key_field='service_id',
        outputs=parsed,
        raw_response=response,
        readable_output=markdown
    )

    return command_results


def get_external_service_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    """
    asm-get-external-service command: Returns details of single external service.
    Returns error if more than one service_id was provided in comma separated format.

    Args:
        client (Client): CortexXpanse client to use.
        args (dict): all command arguments, usually passed from ``demisto.args()``.
            ``args['service_id']`` A string representing the service ID you want to get details for.

    Returns:
        CommandResults: A ``CommandResults`` object that is then passed to ``return_results``,
        that contains external service information.
    """
    # assume that only one service_id was passed in or fail.
    service_id = str(args.get('service_id'))
    service_id_list = service_id.split(",")
    if len(service_id_list) > 1:
        raise ValueError("This command only supports one service_id at this time")

    response = client.get_external_service_request(service_id_list)
    parsed = response.get('reply', {}).get('details')
    markdown = tableToMarkdown('External Service', parsed, removeNull=True, headerTransform=string_to_table_header)
    command_results = CommandResults(
        outputs_prefix='ASM.ExternalService',
        outputs_key_field='service_id',
        outputs=parsed,
        raw_response=response,
        readable_output=markdown
    )

    return command_results


def list_external_ip_address_range_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    """
    asm-list-external-ip-address-range command: Returns list of external ip ranges.

    Args:
        client (Client): CortexXpanse client to use.
        args (dict): all command arguments, usually passed from ``demisto.args()`` (not used in this function).

    Returns:
        CommandResults: A ``CommandResults`` object that is then passed to ``return_results``,
        that contains external IP address ranges.
    """
    response = client.list_external_ip_address_range_request()
    parsed = response.get('reply', {}).get('external_ip_address_ranges')
    markdown = tableToMarkdown('External IP Address Ranges', parsed, removeNull=True,
                               headerTransform=string_to_table_header)
    command_results = CommandResults(
        outputs_prefix='ASM.ExternalIpAddressRange',
        outputs_key_field='range_id',
        outputs=parsed,
        raw_response=response,
        readable_output=markdown
    )

    return command_results


def get_external_ip_address_range_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    """
    asm-get-external-ip-address-range command: Returns details of single external ip range.
    Returns error if more than one range_id was provided in comma separated format.

    Args:
        client (Client): CortexXpanse client to use.
        args (dict): all command arguments, usually passed from ``demisto.args()``.
            ``args['range_id']`` A string representing the range ID for which you want to get the details for.

    Returns:
        CommandResults: A ``CommandResults`` object that is then passed to ``return_results``,
        that contains external ip range information.
    """
    # assume that only one range_id was passed in or fail.
    range_id = str(args.get('range_id'))
    range_id_list = range_id.split(",")
    if len(range_id_list) > 1:
        raise ValueError("This command only supports one range_id at this time")

    response = client.get_external_ip_address_range_request(range_id_list)
    parsed = response.get('reply', {}).get('details')
    markdown = tableToMarkdown('External IP Address Range', parsed, removeNull=True,
                               headerTransform=string_to_table_header)
    command_results = CommandResults(
        outputs_prefix='ASM.ExternalIpAddressRange',
        outputs_key_field='range_id',
        outputs=parsed,
        raw_response=response,
        readable_output=markdown
    )

    return command_results


def list_asset_internet_exposure_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    """
    asm-list-asset-internet-exposure command: Returns list of external internet exposures.

    Args:
        client (Client): CortexXpanse client to use.
        args (dict): all command arguments, usually passed from ``demisto.args()``.
            ``args['ip_address']`` IP Address to search on.
            ``args['name']`` name of asset to search on.
            ``args['type']`` type of external service.
            ``args['has_active_external_services']`` if the internet exposure have an active external service.

    Returns:
        CommandResults: A ``CommandResults`` object that is then passed to ``return_results``,
        that contains external internet exposures.
    """
    ip_address = args.get('ip_address')
    name = args.get('name')
    asm_type = args.get('type')
    has_active_external_services = args.get('has_active_external_services')
    # create list of search parameters or pass empty list.
    search_params = []
    if ip_address:
        search_params.append({"field": "ip_address", "operator": "eq", "value": ip_address})
    if name:
        search_params.append({"field": "name", "operator": "contains", "value": name})
    if asm_type:
        search_params.append({"field": "type", "operator": "in", "value": [asm_type]})
    if has_active_external_services:
        search_params.append({"field": "has_active_external_services", "operator": "in", "value": [has_active_external_services]})

    response = client.list_asset_internet_exposure_request(search_params)
    formatted_response = response.get('reply', {}).get('assets_internet_exposure')
    parsed = format_asm_id(formatted_response)
    markdown = tableToMarkdown('Asset Internet Exposures', parsed, removeNull=True,
                               headerTransform=string_to_table_header)
    command_results = CommandResults(
        outputs_prefix='ASM.AssetInternetExposure',
        outputs_key_field='asm_ids',
        outputs=parsed,
        raw_response=response,
        readable_output=markdown
    )

    return command_results


def get_asset_internet_exposure_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    """
    asm-get-asset-internet-exposure command: Returns details of single external internet exposure.
    Returns error if more than one asm_id was provided in comma separated format.

    Args:
        client (Client): CortexXpanse client to use.
        args (dict): all command arguments, usually passed from ``demisto.args()``.
            ``args['asm_id']`` A string representing the asset ID for which you want to get the details for.

    Returns:
        CommandResults: A ``CommandResults`` object that is then passed to ``return_results``,
        that contains internet exposure information.
    """
    # assume that only one asm_id was passed in or fail.
    asm_id = str(args.get('asm_id'))
    asm_id_list = asm_id.split(",")
    if len(asm_id_list) > 1:
        raise ValueError("This command only supports one asm_id at this time")

    response = client.get_asset_internet_exposure_request(asm_id_list)
    parsed = response.get('reply', {}).get('details')
    markdown = tableToMarkdown('Asset Internet Exposure', parsed, removeNull=True,
                               headerTransform=string_to_table_header)
    command_results = CommandResults(
        outputs_prefix='ASM.AssetInternetExposure',
        outputs_key_field='asm_ids',
        outputs=parsed,
        raw_response=response,
        readable_output=markdown
    )

    return command_results


def fetch_incidents(client: Client, max_fetch: int, last_run: Dict[str, int],
                    first_fetch_time: Optional[int], severity: Optional[list]
                    ) -> Tuple[Dict[str, int], List[dict]]:
    """
    This function will execute each interval (default is 1 minute).

    Args:
        client (Client): CortexXpanse client to use.
        max_fetch (int): Maximum numbers of incidents per fetch.
        last_run: The greatest incident created_time we fetched from last fetch
        first_fetch_time: If last_run is None then fetch all incidents since first_fetch_time
        severity: The severity of the alerts that will be fetched.

    Returns:
        next_run: This will be last_run in the next fetch-incidents
        incidents: Incidents that will be created in Cortex XSOAR
    """
    # Get the last fetch time, if exists
    last_fetch = last_run.get('last_fetch', None)

    # Handle first time fetch
    if last_fetch is None:
        last_fetch = first_fetch_time
    else:
        last_fetch = int(last_fetch)

    latest_created_time = cast(int, last_fetch)
    incidents = []

    # Changed from 'last_fetch' to 'latest_created time' because they are the same and fixed type error.
    filters = [{'field': 'alert_source', 'operator': 'in', 'value': ['ASM']}, {
        'field': 'creation_time', 'operator': 'gte', 'value': latest_created_time + 1}]
    if severity:
        filters.append({"field": "severity", "operator": "in", "value": severity})

    request_data = {'request_data': {'filters': filters, 'search_from': 0,
                                     'search_to': max_fetch, 'sort': {'field': 'creation_time', 'keyword': 'asc'}}}

    raw = client.list_alerts_request(request_data)

    items = raw.get('reply', {}).get('alerts')
    for item in items:
        # for item in items.outputs:
        incident_created_time = item['detection_timestamp']
        incident = {
            'name': item['name'],
            'details': item['description'],
            'occurred': timestamp_to_datestring(incident_created_time),
            'rawJSON': json.dumps(item),
            'severity': SEVERITY_DICT[item.get('severity', 'Low')]
        }

        incidents.append(incident)

        if incident_created_time > latest_created_time:
            latest_created_time = incident_created_time

    next_run = {'last_fetch': latest_created_time}
    return next_run, incidents


def test_module(client: Client, params: Dict[str, Any], first_fetch_time: Optional[int]) -> None:
    """
    Tests API connectivity and authentication'
    When 'ok' is returned it indicates the integration works like it is supposed to and connection to the service is
    successful.
    Raises exceptions if something goes wrong.

    Args:
        client (Client): CortexXpanse client to use.
        params (Dict): Integration parameters.
        first_fetch_time (int): The first fetch time as configured in the integration params.

    Returns:
        str: 'ok' if test passed, anything else will raise an exception and will fail the test.
    """
    try:
        client.list_external_service_request([])

        if params.get('isFetch'):  # Tests fetch incident:
            severity = params.get('severity')
            max_fetch = int(params.get('max_fetch', 10))
            fetch_incidents(
                client=client,
                max_fetch=max_fetch,
                last_run={},
                first_fetch_time=first_fetch_time,
                severity=severity
            )
    except DemistoException as e:
        if 'Forbidden' in str(e):
            raise DemistoException('Authorization Error: make sure API Key is correctly set')
        else:
            raise e
    return_results('ok')


def main() -> None:
    """
    main function
    """
    params: Dict[str, Any] = demisto.params()
    args: Dict[str, Any] = demisto.args()

    command = demisto.command()
    demisto.debug(f'Command being called is {command}')

    try:
        first_fetch_time = arg_to_datetime(
            arg=params.get('first_fetch', '3 days'),
            arg_name='First fetch timestamp',
            required=True
        )
        first_fetch_timestamp = int(first_fetch_time.timestamp()) * 1000 if first_fetch_time else None
        severity = params.get('severity')
        max_fetch = int(params.get('max_fetch', 10))
        creds = params.get('credentials', {})
        api = creds.get('password', '')
        auth_id = creds.get('identifier', '')
        headers = {
            'Authorization': f'{api}',
            'x-xdr-auth-id': f'{auth_id}',
            'Content-Type': 'application/json'
        }

        proxy = params.get('proxy', False)
        handle_proxy()
        verify_certificate = not params.get('insecure', False)

        url = params.get('url', '')
        add_sensitive_log_strs(api)
        base_url = urljoin(url, URL_SUFFIX)
        client = Client(
            base_url=base_url,
            verify=verify_certificate,
            headers=headers,
            proxy=proxy)

        commands = {
            'asm-list-external-service': list_external_service_command,
            'asm-get-external-service': get_external_service_command,
            'asm-list-external-ip-address-range': list_external_ip_address_range_command,
            'asm-get-external-ip-address-range': get_external_ip_address_range_command,
            'asm-list-asset-internet-exposure': list_asset_internet_exposure_command,
            'asm-get-asset-internet-exposure': get_asset_internet_exposure_command,
            'asm-list-alerts': list_alerts_command
        }

        if command == 'test-module':
            test_module(client, params, first_fetch_timestamp)
        if command == 'fetch-incidents':
            next_run, incidents = fetch_incidents(
                client=client,
                max_fetch=max_fetch,
                last_run=demisto.getLastRun(),
                first_fetch_time=first_fetch_timestamp,
                severity=severity)

            demisto.setLastRun(next_run)
            demisto.incidents(incidents)
        elif command in commands:
            return_results(commands[command](client, args))
        else:
            raise NotImplementedError(f'{command} command is not implemented.')

    except Exception as e:
        return_error(f'Failed to execute {command} command.\nError:\n{str(e)}')


''' ENTRY POINT '''

if __name__ in ['__main__', 'builtin', 'builtins']:
    main()
