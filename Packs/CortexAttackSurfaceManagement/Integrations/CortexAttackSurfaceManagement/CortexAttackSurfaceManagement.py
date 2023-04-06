import urllib3
import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
from typing import Dict, Any, List
from requests import Response  # Used to typing Response as a return from functions

# Disable insecure warnings
urllib3.disable_warnings()

DEFAULT_SEARCH_LIMIT = 100


class NotFoundError(Exception):
    pass


class ProcessingError(Exception):
    pass


class Client(BaseClient):
    """
    Client class to interact with the service API.
    """

    def __init__(self, base_url, verify, proxy, headers):
        """
        Class initialization.
        """
        super().__init__(base_url, verify=verify, proxy=proxy, headers=headers)

    def list_remediation_rule_request(self, request_data: Dict) -> Dict[str, Any]:
        """Get a list of all your remediation rules using the 'xpanse_remediation_rules/rules/' endpoint.

        Args:
            request_data (dict): dict of parameters for API call.

        Returns:
            dict: dict containing list of external services.
        """

        response = self._http_request('POST', '/xpanse_remediation_rules/rules/', json_data=request_data, error_handler=get_api_error)

        return response

    def list_external_service_request(self, search_params: List[Dict]) -> Dict[str, Any]:
        """Get a list of all your external services using the '/assets/get_external_services/' endpoint.

        Args:
            search_params (list): list of search parameters to add to the API call body.

        Returns:
            dict: dict containing list of external services.
        """
        data = {"request_data": {"filters": search_params, "search_to": DEFAULT_SEARCH_LIMIT}}

        response = self._http_request('POST', '/assets/get_external_services/', json_data=data, error_handler=get_api_error)

        return response

    def get_external_service_request(self, service_id_list: List[str]) -> Dict[str, Any]:
        """Get service details using the '/assets/get_external_service/' endpoint.

        Args:
            service_id_list (list): single service id in list format.

        Returns:
            dict: dict containing information on single external service.
        """
        data = {"request_data": {"service_id_list": service_id_list}}

        response = self._http_request('POST', '/assets/get_external_service', json_data=data, error_handler=get_api_error)

        return response

    def list_external_ip_address_range_request(self) -> Dict[str, Any]:
        """Get a list of all your internet exposure IP ranges using the '/assets/get_external_ip_address_ranges/' endpoint.

        Returns:
            dict: dict containing list of external ip address ranges.
        """
        data = {"request_data": {"search_to": DEFAULT_SEARCH_LIMIT}}

        response = self._http_request('POST', '/assets/get_external_ip_address_ranges/', json_data=data, error_handler=get_api_error)

        return response

    def get_external_ip_address_range_request(self, range_id_list: List[str]) -> Dict[str, Any]:
        """Get external IP address range details using the '/assets/get_external_ip_address_range/' endpoint.

        Args:
            range_id_list (list): single range id in list format.

        Returns:
            dict: dict containing information on external ip address range.
        """
        data = {"request_data": {"range_id_list": range_id_list}}

        response = self._http_request('POST', '/assets/get_external_ip_address_range/', json_data=data, error_handler=get_api_error)

        return response

    def list_asset_internet_exposure_request(self, search_params: List[dict]) -> Dict[str, Any]:
        """Get a list of all your internet exposure assets using the '/assets/get_assets_internet_exposure/' endpoint.

        Args:
            search_params (list): list of search parameters to add to the API call body.

        Returns:
            dict: dict containing list of internet exposure assets.
        """
        data = {"request_data": {"filters": search_params, "search_to": DEFAULT_SEARCH_LIMIT}}

        response = self._http_request('POST', '/assets/get_assets_internet_exposure/', json_data=data, error_handler=get_api_error)

        return response

    def get_asset_internet_exposure_request(self, asm_id_list: List[str]) -> Dict[str, Any]:
        """Get internet exposure asset details using the '/assets/get_asset_internet_exposure/' endpoint.

        Args:
            asm_id_list (list): single attack surface management id in list format.

        Returns:
            dict: dict containing information on an internet exposure asset.
        """
        data = {"request_data": {"asm_id_list": asm_id_list}}

        response = self._http_request('POST', '/assets/get_asset_internet_exposure/', json_data=data, error_handler=get_api_error)

        return response

    def start_remediation_confirmation_scan(self, alert_internal_id: str, service_id: str, attack_surface_rule_id: str) -> Response:
        """Retrieves ID of active (running) scan if it already exists for the given service; otherwise, creates new a scan.

        Args:
            alert_internal_id (str): _description_
            service_id (str): _description_
            attack_surface_rule_id (str): _description_

        Raises:
            ProcessingError: Custom error to handling 500 error with an internal error code 100 for having incorrect request values.
            NotFoundError: Custom error for handling 500 error that is a "The server encountered an unexpected internal server error" error from waitress.

        Returns:
            Dict[str, Any]: dictionary containing response information that includes a scan ID.
        """
        data = {"request_data": {"alert_internal_id": alert_internal_id, "service_id": service_id, "attack_surface_rule_id": attack_surface_rule_id}}

        response = self._http_request(method='POST',
                                      url_suffix='remediation_confirmation_scanning/requests/get_or_create/',
                                      json_data=data,
                                      resp_type="response",
                                      error_handler=get_api_error
                                      )

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


def get_api_error(response):
    if response.status_code == 500 and "text/plain" in response.headers["Content-Type"]:
        raise NotFoundError("The endpoint for scanning could not be contacted")
    elif response.status_code == 500 and response is not None:
        try:
            json_response = response.json()
            error_code = json_response.get('reply', {}).get("err_code", {})
        except Exception as err:
            print(f"Unexpected {err=}, {type(err)=}")
        else:
            if error_code:
                rcs_err_msg = json_response.get('reply', {}).get("err_msg", {})
                raise ProcessingError(f"Got error message '{rcs_err_msg}'. Please check you that your inputs are correct.")


''' COMMAND FUNCTIONS '''


def list_remediation_rule_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    """
    asm-list-remediation-rule command: Returns list of remediation path rules.

    Args:
        client (Client): CortexAttackSurfaceManagment client to use.
        args (dict): all command arguments, usually passed from ``demisto.args()``.
            ``args['asm_rule_id']`` A string representing the ASM Rule ID you want to get association
            remediation path rules for.
            ``args['sort_by_creation_time']`` optional - enum (asc,desc).

    Returns:
        CommandResults: A ``CommandResults`` object that is then passed to ``return_results``,
        that contains list of remediation path rules.
    """
    asm_rule_id = str(args.get('asm_rule_id'))
    sort_by_creation_time = args.get('sort_by_creation_time')

    # create list of search parameters or pass empty list.
    search_params = []
    if asm_rule_id:
        search_params.append({"field": "attack_surface_rule_id", "operator": "eq", "value": asm_rule_id})
    if sort_by_creation_time:
        request_data = {"request_data": {"filters": search_params, 'search_from': 0,
                        'search_to': DEFAULT_SEARCH_LIMIT, "sort": {"field": "created_at", "keyword": sort_by_creation_time}}}
    else:
        request_data = {"request_data": {"filters": search_params, 'search_from': 0,
                        'search_to': DEFAULT_SEARCH_LIMIT}}

    response = client.list_remediation_rule_request(request_data)
    parsed = response.get('reply', {}).get('remediation_rules')
    markdown = tableToMarkdown('Remediation Rules', parsed, removeNull=True, headerTransform=string_to_table_header)
    command_results = CommandResults(
        outputs_prefix='ASM.RemediationRule',
        outputs_key_field='rule_id',
        outputs=parsed,
        raw_response=response,
        readable_output=markdown
    )

    return command_results


def list_external_service_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    """
    asm-list-external-service command: Returns list of external services.

    Args:
        client (Client): CortexAttackSurfaceManagment client to use.
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
        client (Client): CortexAttackSurfaceManagment client to use.
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
        client (Client): CortexAttackSurfaceManagment client to use.
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
        client (Client): CortexAttackSurfaceManagment client to use.
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
        client (Client): CortexAttackSurfaceManagment client to use.
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
        client (Client): CortexAttackSurfaceManagment client to use.
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


def start_remediation_confirmation_scan_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    """
    asm-start-remediation_confirmation_scan command: Starts a new scan or gets existing scan ID.

    Args:
        client (Client): CortexAttackSurfaceManagment client to use.
        args (dict): all command arguments, usually passed from ``demisto.args()`` (not used in this function).

    Returns:
        CommandResults: A ``CommandResults`` object that is then passed to ``return_results``,
        that contains the ID of the Remediation Confirmation Scan.
    """
    service_id = str(args.get('service_id'))
    attack_surface_rule_id = str(args.get('attack_surface_rule_id'))
    alert_internal_id = args.get('alert_internal_id')
    if isinstance(alert_internal_id, str):
        try:
            alert_internal_id = int(alert_internal_id)
        except ValueError:
            print("The value of alert_internal_id is not an integer. Please update the value.")
        else:
            if alert_internal_id < 0:
                raise ValueError(f"Expected a non-negative integer, but got {alert_internal_id}.")

    response = client.start_remediation_confirmation_scan(alert_internal_id=alert_internal_id,
                                                          service_id=service_id,
                                                          attack_surface_rule_id=attack_surface_rule_id)

    json_response = response.json()
    formatted_outputs = json_response.get('reply', {})

    if response.status_code == 201:
        formatted_outputs.update({"scan_creation_status": "created"})
    elif response.status_code == 200:
        formatted_outputs.update({"scan_creation_status": "existing"})

    markdown = tableToMarkdown('External IP Address Ranges',
                               formatted_outputs,
                               removeNull=True,
                               headerTransform=string_to_table_header)
    command_results = CommandResults(
        outputs_prefix='ASM.RemediationScan',
        outputs_key_field='',
        outputs=formatted_outputs,
        raw_response=response,
        readable_output=markdown
    )
    return command_results


def test_module(client: Client) -> None:
    """
    Tests API connectivity and authentication'
    When 'ok' is returned it indicates the integration works like it is supposed to and connection to the service is
    successful.
    Raises exceptions if something goes wrong.

    Args:
        client (Client): CortexAttackSurfaceManagment client to use.

    Returns:
        str: 'ok' if test passed, anything else will raise an exception and will fail the test.
    """
    try:
        client.list_external_service_request([])
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

        url_suffix = "/public_api/v1"
        url = params.get('url', '')
        add_sensitive_log_strs(api)
        base_url = urljoin(url, url_suffix)
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
            'asm-list-remediation-rule': list_remediation_rule_command,
            'asm-start-remediation_confirmation_scan': start_remediation_confirmation_scan_command
        }

        if command == 'test-module':
            test_module(client)
        elif command in commands:
            return_results(commands[command](client, args))
        else:
            raise NotImplementedError(f'{command} command is not implemented.')

    except Exception as e:
        return_error(f'Failed to execute {command} command.\nError:\n{str(e)}')


''' ENTRY POINT '''

if __name__ in ['__main__', 'builtin', 'builtins']:
    main()
