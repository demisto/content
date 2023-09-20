import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
from typing import Any, cast

import urllib3

# Disable insecure warnings
urllib3.disable_warnings()

DEFAULT_SEARCH_LIMIT = 100
MAX_ALERTS = 100  # max alerts per fetch
TIME_FORMAT = "%Y-%m-%dT%H:%M:%S"
V1_URL_SUFFIX = "/public_api/v1"
V2_URL_SUFFIX = "/public_api/v2"
SEVERITY_DICT = {
    'informational': IncidentSeverity.INFO,
    'low': IncidentSeverity.LOW,
    'medium': IncidentSeverity.MEDIUM,
    'high': IncidentSeverity.HIGH,
    'critical': IncidentSeverity.CRITICAL
}
ASSIGN = "assign"
REMOVE = 'remove'
INCIDENT_STATUSES = [
    "new",
    "under_investigation",
    "resolved_-_no_longer_observed",
    "resolved_-_no_risk",
    "resolved_-_risk_accepted",
    "resolved_-_contested_asset",
    "resolved_-_remediated_automatically",
    "resolved"
]

ALERT_STATUSES = [
    "new",
    "under_investigation",
    "resolved_no_risk",
    "resolved_risk_accepted",
    "resolved_contested_asset",
    "resolved_remediated_automatically",
    "resolved"
]


class Client(BaseClient):
    """
    Client class to interact with the service API.
    """

    def __init__(self, base_url, verify, proxy, headers):
        """
        Class initialization.
        """
        super().__init__(base_url, verify=verify, proxy=proxy, headers=headers)

    def list_alerts_request(self, request_data: dict) -> dict[str, Any]:
        """Get a list of all asm alerts '/alerts/get_alerts_multi_events/' endpoint.

        Args:
            request_data (dict): dict of parameters for API call.

        Returns:
            dict: dict containing list of external services.
        """

        response = self._http_request('POST', f'{V2_URL_SUFFIX}/alerts/get_alerts_multi_events/', json_data=request_data)

        return response

    def list_external_service_request(self, search_params: list[dict]) -> dict[str, Any]:
        """Get a list of all your external services using the '/assets/get_external_services/' endpoint.

        Args:
            search_params (list): list of search parameters to add to the API call body.

        Returns:
            dict: dict containing list of external services.
        """
        data = {"request_data": {"filters": search_params, "search_to": DEFAULT_SEARCH_LIMIT}}

        response = self._http_request('POST', f'{V1_URL_SUFFIX}/assets/get_external_services/', json_data=data)

        return response

    def get_external_service_request(self, service_id_list: list[str]) -> dict[str, Any]:
        """Get service details using the '/assets/get_external_service/' endpoint.

        Args:
            service_id_list (list): single service id in list format.

        Returns:
            dict: dict containing information on single external service.
        """
        data = {"request_data": {"service_id_list": service_id_list}}

        response = self._http_request('POST', f'{V1_URL_SUFFIX}/assets/get_external_service', json_data=data)

        return response

    def list_external_ip_address_range_request(self) -> dict[str, Any]:
        """Get a list of all your internet exposure IP ranges using the '/assets/get_external_ip_address_ranges/' endpoint.

        Returns:
            dict: dict containing list of external ip address ranges.
        """
        data = {"request_data": {"search_to": DEFAULT_SEARCH_LIMIT}}

        response = self._http_request('POST', f'{V1_URL_SUFFIX}/assets/get_external_ip_address_ranges/', json_data=data)

        return response

    def get_external_ip_address_range_request(self, range_id_list: list[str]) -> dict[str, Any]:
        """Get external IP address range details using the '/assets/get_external_ip_address_range/' endpoint.

        Args:
            range_id_list (list): single range id in list format.

        Returns:
            dict: dict containing information on external ip address range.
        """
        data = {"request_data": {"range_id_list": range_id_list}}

        response = self._http_request('POST', f'{V1_URL_SUFFIX}/assets/get_external_ip_address_range/', json_data=data)

        return response

    def list_asset_internet_exposure_request(self, search_params: list[dict]) -> dict[str, Any]:
        """Get a list of all your internet exposure assets using the '/assets/get_assets_internet_exposure/' endpoint.

        Args:
            search_params (list): list of search parameters to add to the API call body.

        Returns:
            dict: dict containing list of internet exposure assets.
        """
        data = {"request_data": {"filters": search_params, "search_to": DEFAULT_SEARCH_LIMIT}}

        response = self._http_request('POST', f'{V1_URL_SUFFIX}/assets/get_assets_internet_exposure/', json_data=data)

        return response

    def get_asset_internet_exposure_request(self, asm_id_list: list[str]) -> dict[str, Any]:
        """Get internet exposure asset details using the '/assets/get_asset_internet_exposure/' endpoint.

        Args:
            asm_id_list (list): single attack surface management id in list format.

        Returns:
            dict: dict containing information on an internet exposure asset.
        """
        data = {"request_data": {"asm_id_list": asm_id_list}}

        response = self._http_request('POST', f'{V1_URL_SUFFIX}/assets/get_asset_internet_exposure/', json_data=data)

        return response

    def list_attack_surface_rules_request(self, search_params: list[dict], limit: int = DEFAULT_SEARCH_LIMIT) -> dict[str, Any]:
        """List attack surface rules using the '/get_attack_surface_rules/' endpoint.

        Args:
            search_params (list): list of search parameters to add to the API call body.

        Returns:
            dict: dict containing list of attack surface rules.
        """
        data = {"request_data": {"filters": search_params, "search_to": limit}}

        response = self._http_request('POST', f'{V1_URL_SUFFIX}/get_attack_surface_rules/', json_data=data)

        return response

    def apply_tags_to_assets_request(self, search_params: list[dict], tags: str, operation: str) -> dict[str, Any]:
        """Assigns tags to assets with the 'tags/assets_internet_exposure/assign' endpoint.

        Args:
            search_params (list): list of request parameters to add to the API call body.

        Returns:
            dict: dict containing whether the assignment request was successful.
        """
        data = {"request_data": {"filters": search_params, "tags": [tags]}}

        response = self._http_request('POST', f'{V1_URL_SUFFIX}/assets/tags/assets_internet_exposure/{operation}/',
                                      json_data=data)

        return response

    def apply_tags_to_ranges_request(self, search_params: list[dict], tags: str, operation: str) -> dict[str, Any]:
        """Assigns tags to assets with the 'tags/external_ip_address_ranges/assign' endpoint.

        Args:
            search_params (list): list of request parameters to add to the API call body.

        Returns:
            dict: dict containing whether the assignment request was successful.
        """
        data = {"request_data": {"filters": search_params, "tags": [tags]}}

        response = self._http_request('POST', f'{V1_URL_SUFFIX}/assets/tags/external_ip_address_ranges/{operation}/',
                                      json_data=data)

        return response

    def list_incidents_request(self, request_data: dict[str, Any]) -> dict[str, Any]:
        """Fetches matching incidents from the 'incidents/get_incidents' endpoint.

        Args:
            request_data (dict): Parameters to add to the API call body.

        Returns:
            dict: dict containing whether the assignment request was successful.
        """
        response = self._http_request('POST', f'{V1_URL_SUFFIX}/incidents/get_incidents/', json_data=request_data)

        return response

    def update_incident_request(self, request_data: dict[str, Any]) -> dict[str, Any]:
        """Updates an incident via the 'incidents/update_incident' endpoint.

        Args:
            request_data (dict): Parameters to add to the API call body.

        Returns:
            dict: dict containing whether the update request was successful.
        """
        data = {"request_data": request_data}

        response = self._http_request('POST', f'{V1_URL_SUFFIX}/incidents/update_incident/', json_data=data)

        return response

    def update_alert_request(self, request_data: dict[str, Any]) -> dict[str, Any]:
        """Updates alerts via the 'alerts/update_alerts' endpoint.

        Args:
            request_data (dict): Parameters to add to the API call body.

        Returns:
            dict: dict containing whether the update request was successful.
        """
        data = {"request_data": request_data}

        response = self._http_request('POST', f'{V1_URL_SUFFIX}/alerts/update_alerts/', json_data=data)

        return response


''' HELPER FUNCTIONS '''


def format_asm_id(formatted_response: list[dict]) -> list[dict]:
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


def list_alerts_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """
    asm-list-alerts command: Returns list of asm alerts.

    Args:
        client (Client): CortexXpanse client to use.
        args (dict): all command arguments, usually passed from ``demisto.args()``.
            ``args['alert_id_list']`` List of integers of the Alert ID.
            ``args['severity']`` List of strings of the Alert severity.
            ``args['status']`` List of strings of the Alert status.
            ``args['business_units_list']`` List of business units of the Alert status.
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
    status = argToList(args.get('status'))
    business_units_list = argToList(args.get('business_units_list'))
    lte_creation_time = args.get('lte_creation_time')
    gte_creation_time = args.get('gte_creation_time')
    sort_by_creation_time = args.get('sort_by_creation_time')
    sort_by_severity = args.get('sort_by_severity')
    tags = argToList(args.get('tags'))
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
    if status:
        search_params.append({"field": "status", "operator": "in", "value": status})
    if business_units_list:
        search_params.append({"field": "business_units_list", "operator": "in", "value": business_units_list})
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
    if tags:
        search_params.append({"field": "tags", "operator": "in", "value": tags})

    if sort_by_creation_time:
        request_data = {"request_data": {"filters": search_params, 'search_from': search_from,
                                         'search_to': search_to,
                                         "sort": {"field": "creation_time", "keyword": sort_by_creation_time}}}
    elif sort_by_severity:
        request_data = {"request_data": {"filters": search_params, 'search_from': search_from,
                                         'search_to': search_to, "sort": {"field": "severity", "keyword": sort_by_severity}}}
    else:
        request_data = {"request_data": {"filters": search_params, 'search_from': search_from, 'search_to': search_to}}

    try:
        response = client.list_alerts_request(request_data)
    except Exception:
        command_results = CommandResults(
            outputs_prefix='ASM.Alert',
            outputs_key_field='alert_id',
            outputs=[],
            raw_response={'reply': {'alerts': []}},
            readable_output=tableToMarkdown('ASM Alerts', [], removeNull=True, headerTransform=string_to_table_header)
        )
        return command_results

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


def list_external_service_command(client: Client, args: dict[str, Any]) -> CommandResults:
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


def get_external_service_command(client: Client, args: dict[str, Any]) -> CommandResults:
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


def list_external_ip_address_range_command(client: Client, args: dict[str, Any]) -> CommandResults:
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


def get_external_ip_address_range_command(client: Client, args: dict[str, Any]) -> CommandResults:
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


def list_asset_internet_exposure_command(client: Client, args: dict[str, Any]) -> CommandResults:
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


def get_asset_internet_exposure_command(client: Client, args: dict[str, Any]) -> CommandResults:
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


def list_attack_surface_rules_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """
    asm-list-attack_surface_rules command: Returns list of attack surface rules.

    Args:
        client (Client): CortexXpanse client to use.
        args (dict): all command arguments, usually passed from ``demisto.args()``.
            ``args['enabled_status']`` Enablement status to search rules with.
            ``args['category']`` Category of rule to search on.
            ``args['priority']`` Priority of rule to search on.
            ``args['attack_surface_rule_id']`` ID of attack surface rule.
            ``args['limit']`` How many rules to return.

    Returns:
        CommandResults: A ``CommandResults`` object that is then passed to ``return_results``,
        that contains attack surface rules.
    """
    enabled_status = argToList(args.get('enabled_status'))
    category = argToList(args.get('category'))
    priority = argToList(args.get('priority'))
    attack_surface_rule_id = argToList(args.get('attack_surface_rule_id'))
    limit = int(args.get('limit', DEFAULT_SEARCH_LIMIT))
    # create list of search parameters or pass empty list.
    search_params = []
    if enabled_status:
        search_params.append({"field": "enabled_status", "operator": "in", "value": enabled_status})
    if category:
        search_params.append({"field": "category", "operator": "in", "value": category})
    if priority:
        search_params.append({"field": "priority", "operator": "in", "value": priority})
    if attack_surface_rule_id:
        search_params.append({"field": "attack_surface_rule_id", "operator": "in", "value": attack_surface_rule_id})

    response = client.list_attack_surface_rules_request(search_params=search_params, limit=limit)
    formatted_response = response.get('reply', {}).get('attack_surface_rules')
    parsed = format_asm_id(formatted_response)
    markdown = tableToMarkdown('Attack Surface Rules', parsed, removeNull=True,
                               headerTransform=string_to_table_header)
    command_results = CommandResults(
        outputs_prefix='ASM.AttackSurfaceRules',
        outputs_key_field='attack_surface_rule_id',
        outputs=parsed,
        raw_response=response,
        readable_output=markdown
    )

    return command_results


def assign_tag_to_assets_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """
    asm-tag-asset-assign command: Assigns a tag to a list of assets.

    Args:
        client (Client): CortexXpanse client to use.
        args (dict): all command arguments, usually passed from ``demisto.args()``.
            ``args['asm_id_list']`` Asset IDs to assign a tag to.
            ``args['tags']`` Name of the tag to add to the assets.


    Returns:
        CommandResults: A ``CommandResults`` object that is then passed to ``return_results``
    """
    asm_id_list = argToList(args.get('asm_id_list'))
    tags = argToList(args.get('tags'))

    search_params = []
    if asm_id_list:
        search_params.append({"field": "asm_id_list", "operator": "in", "value": asm_id_list})
    else:
        raise ValueError('asm_id_list must contain at least one entry.')

    if not tags:
        raise ValueError('a value for "tags" must be provided.')

    response = client.apply_tags_to_assets_request(search_params=search_params, tags=tags, operation=ASSIGN)

    formatted_response = response.get('reply', {}).get('assign_tags')
    command_results = CommandResults(
        outputs=f"Assignment operation: {formatted_response}",
        raw_response=response,
        readable_output=f"Assignment operation: {formatted_response}",
        outputs_prefix='ASM.TagAssignment'
    )

    return command_results


def remove_tag_to_assets_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """
    asm-tag-asset-remove command: Assigns a tag to a list of assets.

    Args:
        client (Client): CortexXpanse client to use.
        args (dict): all command arguments, usually passed from ``demisto.args()``.
            ``args['asm_id_list']`` Asset IDs to remove a tag from.
            ``args['tags']`` Name of the tags to remove from the assets.


    Returns:
        CommandResults: A ``CommandResults`` object that is then passed to ``return_results``
    """
    asm_id_list = argToList(args.get('asm_id_list'))
    tags = argToList(args.get('tags'))

    search_params = []
    if asm_id_list:
        search_params.append({"field": "asm_id_list", "operator": "in", "value": asm_id_list})
    else:
        raise ValueError('asm_id_list must contain at least one entry.')

    if not tags:
        raise ValueError('a value for "tags" must be provided.')

    response = client.apply_tags_to_assets_request(search_params=search_params, tags=tags, operation=REMOVE)

    formatted_response = response.get('reply', {}).get('remove_tags')
    command_results = CommandResults(
        outputs=f"Removal operation: {formatted_response}",
        raw_response=response,
        readable_output=f"Removal operation: {formatted_response}",
        outputs_prefix='ASM.TagRemoval'
    )

    return command_results


def assign_tag_to_ranges_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """
    asm-tag-range-assign command: Assigns a tag to a list of IP ranges.

    Args:
        client (Client): CortexXpanse client to use.
        args (dict): all command arguments, usually passed from ``demisto.args()``.
            ``args['range_id_list']`` Range IDs to assign a tag to.
            ``args['tags']`` Name of the tag to add to the ranges.


    Returns:
        CommandResults: A ``CommandResults`` object that is then passed to ``return_results``
    """
    range_id_list = argToList(args.get('range_id_list'))
    tags = argToList(args.get('tags'))

    search_params = []
    if range_id_list:
        search_params.append({"field": "range_id_list", "operator": "in", "value": range_id_list})
    else:
        raise ValueError('range_id_list must contain at least one entry.')

    if not tags:
        raise ValueError('a value for "tags" must be provided.')

    response = client.apply_tags_to_ranges_request(search_params=search_params, tags=tags, operation=ASSIGN)

    formatted_response = response.get('reply', {}).get('assign_tags')
    command_results = CommandResults(
        outputs=f"Assignment operation: {formatted_response}",
        raw_response=response,
        readable_output=f"Assignment operation: {formatted_response}",
        outputs_prefix='ASM.TagAssignment'
    )

    return command_results


def remove_tag_to_ranges_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """
    asm-tag-range-remove command: Assigns a tag to a list of IP Ranges.

    Args:
        client (Client): CortexXpanse client to use.
        args (dict): all command arguments, usually passed from ``demisto.args()``.
            ``args['range_id_list']`` Range IDs to remove a tag from.
            ``args['tags']`` Name of the tags to remove from the ranges.


    Returns:
        CommandResults: A ``CommandResults`` object that is then passed to ``return_results``
    """
    range_id_list = argToList(args.get('range_id_list'))
    tags = argToList(args.get('tags'))

    search_params = []
    if range_id_list:
        search_params.append({"field": "range_id_list", "operator": "in", "value": range_id_list})
    else:
        raise ValueError('range_id_list must contain at least one entry.')

    if not tags:
        raise ValueError('a value for "tags" must be provided.')

    response = client.apply_tags_to_ranges_request(search_params=search_params, tags=tags, operation=REMOVE)

    formatted_response = response.get('reply', {}).get('remove_tags')
    command_results = CommandResults(
        outputs=f"Removal operation: {formatted_response}",
        raw_response=response,
        readable_output=f"Removal operation: {formatted_response}",
        outputs_prefix='ASM.TagRemoval'
    )

    return command_results


def list_incidents_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """
    asm-list-alerts command: Returns list of asm incidents.

    Args:
        client (Client): CortexXpanse client to use.
        args (dict): all command arguments, usually passed from ``demisto.args()``.
            ``args['incident_id_list']`` List of integers of the Incident ID.
            ``args['description']`` A string to search for in the Incident description.
            ``args['status']`` The status of the incident.
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
    incident_id_list = argToList(args.get('incident_id_list'))
    description = args.get('description')
    status = args.get('status')
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

    # starts with param to only look for ASM incidents.  Can add others if defined.
    search_params = [{"field": "alert_sources", "operator": "in", "value": ["ASM"]}]
    if incident_id_list:
        search_params.append({"field": "incident_id_list", "operator": "in", "value": incident_id_list})  # type: ignore
    if description:
        search_params.append({"field": "description", "operator": "contains", "value": description})
    if status:
        search_params.append({"field": "status", "operator": "eq", "value": status})
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
                                         'search_to': search_to,
                                         "sort": {"field": "creation_time", "keyword": sort_by_creation_time}}}
    elif sort_by_severity:
        request_data = {"request_data": {"filters": search_params, 'search_from': search_from,
                                         'search_to': search_to, "sort": {"field": "severity", "keyword": sort_by_severity}}}
    else:
        request_data = {"request_data": {"filters": search_params, 'search_from': search_from, 'search_to': search_to}}

    response = client.list_incidents_request(request_data)

    parsed = response.get('reply', {}).get('incidents')
    markdown = tableToMarkdown('ASM Incidents', parsed, removeNull=True, headerTransform=string_to_table_header)
    command_results = CommandResults(
        outputs_prefix='ASM.Incident',
        outputs_key_field='incident_id',
        outputs=parsed,
        raw_response=response,
        readable_output=markdown
    )

    return command_results


def update_incident_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """
    asm-update-incident command: Updates the state of an incident.

    Args:
        client (Client): CortexXpanse client to use.
        args (dict): all command arguments, usually passed from ``demisto.args()``.
            ``args['incident_id']`` ID of the incident to modify
            ``args['alert_id']`` Used for scoping updates such as comments
            ``args['assigned_user_mail']`` Email address of the user to assign incident to
            ``args['manual_severity']`` Administrator-defined severity for the incident
            ``args['status']`` Updated incident status
            ``args['resolve_comment']`` Optional resolution comment when resolving the incident
            ``args['comment']`` A comment to add to the incident. If an alert_id is supplied it will be prefixed to the comment.

    Returns:
        CommandResults: A ``CommandResults`` object that is then passed to ``return_results``
    """
    incident_id = args.get('incident_id')
    alert_id = args.get('alert_id')
    assigned_user_mail = args.get('assigned_user_mail')
    manual_severity = args.get('manual_severity')
    status = args.get('status')
    resolve_comment = args.get('resolve_comment')
    comment = args.get('comment')

    update_params = {"update_data": {}}  # type: ignore
    if incident_id:
        update_params["incident_id"] = str(incident_id)  # type: ignore
    else:
        raise ValueError('incident_id must be defined.')

    if assigned_user_mail:
        update_params["update_data"]["assigned_user_mail"] = assigned_user_mail
    if manual_severity:
        update_params["update_data"]["manual_severity"] = manual_severity
    if status:
        if status in INCIDENT_STATUSES:
            update_params["update_data"]["status"] = status
        else:
            raise ValueError(f'status must be one of {INCIDENT_STATUSES}')
    if resolve_comment and status and "resolved" in status:
        update_params["update_data"]["resolve_comment"] = resolve_comment
    if comment:
        if alert_id:
            update_params["update_data"]["comment"] = {"comment_action": "add", "value": f"[Alert: {alert_id}] {comment}"}
        else:
            update_params["update_data"]["comment"] = {"comment_action": "add", "value": comment}

    response = client.update_incident_request(request_data=update_params)

    formatted_response = response.get('reply')
    command_results = CommandResults(
        outputs=f"Update operation successful: {formatted_response}",
        raw_response=response,
        readable_output=f"Update operation successful: {formatted_response}",
        outputs_prefix='ASM.IncidentUpdate'
    )

    return command_results


def update_alert_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """
    asm-update-alerts command: Updates the state of an alert.

    Args:
        client (Client): CortexXpanse client to use.
        args (dict): all command arguments, usually passed from ``demisto.args()``.
            ``args['alert_id_list']`` IDs of the alerts to modify
            ``args['severity']`` The severity of the alert
            ``args['status']`` Updated alert status
            ``args['comment']`` A comment to add to the alert.

    Returns:
        CommandResults: A ``CommandResults`` object that is then passed to ``return_results``
    """
    alert_id_list = argToList(args.get('alert_id_list'))
    severity = args.get('severity')
    status = args.get('status')

    update_params = {"update_data": {}}  # type: ignore
    if alert_id_list:
        update_params["alert_id_list"] = alert_id_list
    else:
        raise ValueError('alert_id_list must be defined.')

    if severity:
        update_params["update_data"]["severity"] = severity
    if status:
        if status in ALERT_STATUSES:
            update_params["update_data"]["status"] = status
        else:
            raise ValueError(f'status must be one of {ALERT_STATUSES}')

    response = client.update_alert_request(request_data=update_params)

    formatted_response = response.get('reply', {}).get("alerts_ids")
    command_results = CommandResults(
        outputs=f"Updated alerts: {formatted_response}",
        raw_response=response,
        readable_output=f"Updated alerts: {formatted_response}",
        outputs_prefix='ASM.UpdatedAlerts'
    )

    return command_results


def fetch_incidents(client: Client, max_fetch: int, last_run: dict[str, int],
                    first_fetch_time: Optional[int], severity: Optional[list],
                    status: Optional[list], tags: Optional[str]
                    ) -> tuple[dict[str, int], list[dict]]:
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
    last_fetch = first_fetch_time if last_fetch is None else int(last_fetch)

    latest_created_time = cast(int, last_fetch)
    incidents = []

    # Changed from 'last_fetch' to 'latest_created time' because they are the same and fixed type error.
    filters = [{'field': 'alert_source', 'operator': 'in', 'value': ['ASM']}, {
        'field': 'creation_time', 'operator': 'gte', 'value': latest_created_time + 1}]
    if severity:
        filters.append({"field": "severity", "operator": "in", "value": severity})
    if status:
        filters.append({"field": "status", "operator": "in", "value": status})
    if tags:
        filters.append({"field": "tags", "operator": "in", "value": tags.split(',')})

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


def test_module(client: Client, params: dict[str, Any], first_fetch_time: Optional[int]) -> None:
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
            status = params.get('status')
            tags = params.get('tags')
            max_fetch = int(params.get('max_fetch', 10))
            fetch_incidents(
                client=client,
                max_fetch=max_fetch,
                last_run={},
                first_fetch_time=first_fetch_time,
                severity=severity,
                status=status,
                tags=tags
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
    params: dict[str, Any] = demisto.params()
    args: dict[str, Any] = demisto.args()

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
        status = params.get('status')
        tags = params.get('tags')
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
        base_url = url
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
            'asm-list-alerts': list_alerts_command,
            'asm-list-attack-surface-rules': list_attack_surface_rules_command,
            'asm-tag-asset-assign': assign_tag_to_assets_command,
            'asm-tag-asset-remove': remove_tag_to_assets_command,
            'asm-tag-range-assign': assign_tag_to_ranges_command,
            'asm-tag-range-remove': remove_tag_to_ranges_command,
            'asm-list-incidents': list_incidents_command,
            'asm-update-incident': update_incident_command,
            'asm-update-alerts': update_alert_command
        }

        if command == 'test-module':
            test_module(client, params, first_fetch_timestamp)
        if command == 'fetch-incidents':
            next_run, incidents = fetch_incidents(
                client=client,
                max_fetch=max_fetch,
                last_run=demisto.getLastRun(),
                first_fetch_time=first_fetch_timestamp,
                severity=severity,
                status=status,
                tags=tags
            )

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
