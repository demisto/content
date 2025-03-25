import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401


from typing import Any
from datetime import datetime, timedelta
from dateutil import parser

import urllib3

# Disable insecure warnings
urllib3.disable_warnings()

DEFAULT_SEARCH_LIMIT = int(demisto.params().get('search_limit', 100))
MAX_ALERTS = 100  # max alerts per fetch
TIME_FORMAT = "%Y-%m-%dT%H:%M:%S"
TIME_FORMAT_Z = "%Y-%m-%dT%H:%M:%SZ"
V1_URL_SUFFIX = "/public_api/v1"
V2_URL_SUFFIX = "/public_api/v2"
PACK_VERSION = "1.2.6"
DEMISTO_VERSION = demisto.demistoVersion()
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
    "reopened",
    "under_investigation",
    "resolved_no_risk",
    "resolved_risk_accepted",
    "resolved_contested_asset",
    "resolved_remediated_automatically",
    "resolved"
]
ASSET_HEADER_HEADER_LIST = [
    "name",
    "ip",
    "first_observed",
    "last_observed",
    "domain",
    "asset_type",
    "asm_ids",
    "asset_explainers",
    "service_type",
    "tags",
    "recent_ips",
    "domain_details"
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

    def list_asset_internet_exposure_request(self, search_params: list[dict], search_from: int = 0,
                                             search_to: int = DEFAULT_SEARCH_LIMIT) -> dict[str, Any]:
        """Get a list of all your internet exposure assets using the '/assets/get_assets_internet_exposure/' endpoint.

        Args:
            search_params (list): list of search parameters to add to the API call body.
            search_from (int): Starting search index.
            search_to (int): Ending search index.

        Returns:
            dict: dict containing list of internet exposure assets.
        """
        data = {"request_data": {"filters": search_params, "search_to": int(search_to), "search_from": int(search_from)}}

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

    def get_incident_request(self, incident_id: str) -> dict[str, Any]:
        """Fetches an incident from the 'incidents/get_incident_extra_data' endpoint.

        Args:
            incident_id (str): Incident ID

        Returns:
            dict: dict containing whether the assignment request was successful.
        """
        request_data = {
            "request_data": {"incident_id": incident_id}
        }
        response = self._http_request('POST', f'{V1_URL_SUFFIX}/incidents/get_incident_extra_data/', json_data=request_data)

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

    def get_external_websites(self, request_data: Dict[str, Any]) -> Dict[str, Any]:
        data = {"request_data": request_data}

        response = self._http_request('POST', f'{V1_URL_SUFFIX}/assets/get_external_websites/', json_data=data)

        return response

    def add_note_to_asset(self, asm_asset_id: str, entity_type: str, annotation_note: str, should_append: bool) -> dict[str, Any]:
        """Adds an annotation (also called a note) to an asset or IP range
        using the /assets/assets_internet_exposure/annotation endpoint.

        Args:
            asm_asset_id (str): The Xpanse asset ID.
            entity_type (str): The type of Xpanse asset, Allowed values: 'asset' or 'ip_range'.
            annotation_note (str): The custom note to be added to the notes section of the asset in Xpanse

        Returns:
            dict[str, Any]: a response that indicates if adding the note succeeded.
        """
        data = {
            "request_data":
                {"assets":
                    [{"entity_id": asm_asset_id,
                        "entity_type": entity_type,
                        "annotation": annotation_note
                      }],
                    "should_append": should_append
                 }
        }

        response = self._http_request('POST', f'{V1_URL_SUFFIX}/assets/assets_internet_exposure/annotation', json_data=data)

        return response


''' HELPER FUNCTIONS '''


def is_timestamp_within_days(timestamp, days: int):
    """_summary_

    Args:
        timestamp (_type_): _description_
        days (int): _description_
        debug_msg (str): _description_

    Returns:
        _type_: _description_
    """
    timestamp = timestamp.replace(" ", "").replace("Z", "")
    date_part, time_part = timestamp.split('T')
    main_time, fractional_seconds = time_part.split('.')
    fractional_seconds = fractional_seconds[:6]
    timestamp = f"{date_part}T{main_time}.{fractional_seconds}"
    target_time = datetime.strptime(timestamp, '%Y-%m-%dT%H:%M:%S.%f')

    current_time = datetime.now()
    time_difference = current_time - target_time

    if time_difference >= timedelta(days=days):
        demisto.debug(f"The timestamp was not within the last {days} days.")
        return False
    else:
        demisto.debug(f"The timestamp was within the last {days} days.")
        return True


def append_search_param(search_params, field, operator, value):
    """
    Appends a search parameter to the given list of search parameters.

    Args:
        search_params (list): The list of search parameters to append to.
        field (str): The name of the field to search on.
        operator (str): The operator to use for the search (e.g. "eq", "contains", "in").
        value (any): The value to search for.

    Returns:
        None
    """

    search_params.append(
        {
            "field": field,
            "operator": operator,
            "value": value
        }
    )


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
            ``args['case_id_list']`` List of integers of the Case ID.
            ``args['tags']`` List of tags.
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
    case_id_list = argToList(args.get('case_id_list'))
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
    if case_id_list:
        case_id_ints = [int(i) for i in case_id_list]
        search_params.append({"field": "case_id_list", "operator": "in", "value": case_id_ints})  # type: ignore

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
            ``args['search_from']`` Represents the start offset index of results.
            ``args['search_to']`` Represents the end offset index of results.

    Returns:
        CommandResults: A ``CommandResults`` object that is then passed to ``return_results``,
        that contains external internet exposures.
    """
    ip_address = args.get('ip_address')
    name = args.get('name')
    asm_type = args.get('type')
    has_active_external_services = args.get('has_active_external_services')
    search_from = int(args.get('search_from', 0))
    search_to = int(args.get('search_to', DEFAULT_SEARCH_LIMIT))
    asm_id_list = args.get("asm_id_list")
    ipv6_address = args.get("ipv6_address")
    gcp_cloud_tags = args.get("gcp_cloud_tags")
    azure_cloud_tags = args.get("azure_cloud_tags")
    aws_cloud_tags = args.get("aws_cloud_tags")
    has_xdr_agent = args.get("has_xdr_agent")
    externally_detected_providers = args.get("externally_detected_providers")
    externally_inferred_cves = args.get("externally_inferred_cves")
    business_units_list = args.get("business_units_list")
    has_bu_overrides = args.get("has_bu_overrides")
    mac_addresses = args.get("mac_addresses")
    # create list of search parameters or pass empty list.
    search_params: List[Dict[str, Any]] = []

    if ip_address:
        append_search_param(search_params, "ip_address", "eq", ip_address)

    if name:
        append_search_param(search_params, "name", "contains", name)

    if asm_type:
        append_search_param(search_params, "type", "in", [asm_type])

    if has_active_external_services:
        append_search_param(search_params, "has_active_external_services", "in", [has_active_external_services])

    if asm_id_list:
        append_search_param(search_params, "asm_id_list", "in", str(asm_id_list).split(","))

    if ipv6_address:
        append_search_param(search_params, "ipv6_address", "eq", str(ipv6_address))

    if aws_cloud_tags:
        append_search_param(search_params, "aws_cloud_tags", "in", str(aws_cloud_tags).split(","))

    if gcp_cloud_tags:
        append_search_param(search_params, "gcp_cloud_tags", "in", str(gcp_cloud_tags).split(","))

    if azure_cloud_tags:
        append_search_param(search_params, "azure_cloud_tags", "in", str(azure_cloud_tags).split(","))

    if has_xdr_agent:
        append_search_param(search_params, "has_xdr_agent", "in", str(has_xdr_agent).split(","))

    if externally_detected_providers:
        append_search_param(search_params, "externally_detected_providers", "contains", externally_detected_providers)

    if externally_inferred_cves:
        append_search_param(search_params, "externally_inferred_cves", "contains", str(externally_inferred_cves))

    if business_units_list:
        append_search_param(search_params, "business_units_list", "in", str(business_units_list).split(","))

    if has_bu_overrides:
        append_search_param(search_params, "has_bu_overrides", "eq", has_bu_overrides.lower() != 'false')

    if mac_addresses:
        append_search_param(search_params, "mac_addresses", "contains", mac_addresses)

    response = client.list_asset_internet_exposure_request(
        search_params=search_params, search_to=search_to, search_from=search_from)
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
    asm-list-incidents command: Returns list of asm incidents.

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
    starred = args.get('starred')
    cloud_management_status = args.get('cloud_management_status')
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
    if starred:
        search_params.append({"field": "starred", "operator": "eq", "value": starred})
    if cloud_management_status:
        search_params.append({"field": "cloud_management_status", "operator": "eq", "value": cloud_management_status})
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


def get_incident_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """
    asm-get-incident command: Returns a single incident

    Args:
        client (Client): CortexXpanse client to use.
        args (dict): all command arguments, usually passed from ``demisto.args()``.
            ``args['incident_id']`` Integer of the Incident ID.

    Returns:
        CommandResults: A ``CommandResults`` object that is then passed to ``return_results``, that contains incident details
    """
    incident_id = args.get('incident_id')

    if not incident_id:
        raise ValueError('Incident ID must be provided.')

    response = client.get_incident_request(incident_id)

    parsed = response.get('reply', {})
    incident = parsed.get('incident', {})
    alerts = []
    for alert in parsed.get("alerts", {}).get("data", {}):
        alerts.append({
            "alert_id": alert.get("alert_id"),
            "name": alert.get("name"),
            "description": alert.get("description"),
            "resolution_status": alert.get("resolution_status"),
        })
    incident["alerts"] = alerts
    markdown = tableToMarkdown('ASM Incident', incident, removeNull=True, headerTransform=string_to_table_header)
    command_results = CommandResults(
        outputs_prefix='ASM.Incident',
        outputs_key_field='incident_id',
        outputs=incident,
        raw_response=response,
        readable_output=markdown
    )

    return command_results


def list_external_websites_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    """
    list_external_websites command: Get external websites .

    Args:
        client (Client): CortexXpanse client to use.
        args (dict): all command arguments, usually passed from ``demisto.args()``.
            ``args['filter']`` Used for filter websites based on authentication type
            ``args['limit']`` Used for limit num of results

    Returns:
        CommandResults: A ``CommandResults`` object that is then passed to ``return_results``
    """
    limit = int(args.get('limit', DEFAULT_SEARCH_LIMIT))
    searchFilter = args.get('authentication')
    if limit > 500:
        raise ValueError('Limit cannot be more than 500, please try again')

    filters = {'filters': [], 'search_to': limit}
    if searchFilter:
        filters['filters'] = [{'field': 'authentication',
                               'operator': 'contains',
                               'value': searchFilter}]

    response = client.get_external_websites(filters)

    hosts = []
    for each in response['reply']['websites']:
        hosts.append({'Host': each['host'], 'Authentication type': each['authentication']})

    human_readable = (f"Total results: {len(hosts)}\n \
        {tableToMarkdown('External Websites', hosts, ['Host', 'Authentication type'])}" if hosts else "No Results")
    command_results = CommandResults(
        outputs_prefix='ASM.ExternalWebsite',
        outputs_key_field='',
        raw_response=response,
        readable_output=human_readable
    )

    if outputs := response.get('reply', {}).get('websites', None):
        command_results.outputs = outputs

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
            ``args['resolution_comment']`` A comment to add to the alert.

    Returns:
        CommandResults: A ``CommandResults`` object that is then passed to ``return_results``
    """
    alert_id_list = argToList(args.get('alert_id_list'))
    severity = args.get('severity')
    status = args.get('status')
    comment = str(args.get('resolution_comment'))

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
    if comment:
        update_params["update_data"]["comment"] = comment

    response = client.update_alert_request(request_data=update_params)

    formatted_response = response.get('reply', {}).get("alerts_ids")
    command_results = CommandResults(
        outputs=f"Updated alerts: {formatted_response}",
        raw_response=response,
        readable_output=f"Updated alerts: {formatted_response}",
        outputs_prefix='ASM.UpdatedAlerts'
    )

    return command_results


def add_note_to_asset_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """Adds an annotation (also called a note) to an asset or IP range
       using the /assets/assets_internet_exposure/annotation endpoint.

    Args:
        client (Client): CortexXpanse client to use.
        args (dict): all command arguments, usually passed from demisto.args().
            args['asset_id'] (str): The Xpanse asset ID.
            args['entity_type'] (str): The type of Xpanse asset, Allowed values: 'asset' or 'ip_range'.
            args['annotation_note'] (str): The custom note to be added to the notes section of the asset in Xpanse

    Returns:
        CommandResults: A CommandResults demisto object that is then passed to return_results
    """
    asset_id = str(args.get('asset_id'))
    entity_type = str(args.get('entity_type'))
    note_to_add = str(args.get('note_to_add'))
    should_append = argToBoolean(args.get('should_append'))

    response = client.add_note_to_asset(asm_asset_id=asset_id,
                                        entity_type=entity_type,
                                        annotation_note=note_to_add,
                                        should_append=should_append)
    response_message = {"status": response.get('reply', {})}
    response_message['asset'] = asset_id
    markdown = tableToMarkdown('Add Note to Asset Command Results:',
                               response_message.get('status'),
                               headers=['Status'],
                               removeNull=True)
    command_results = CommandResults(
        outputs_prefix='ASM.AssetAnnotation',
        outputs_key_field='',
        outputs=response_message,
        raw_response=response,
        readable_output=markdown
    )

    return command_results


def ip_command(client: Client, args: dict[str, Any]) -> CommandResults:
    command_results = CommandResults(
        outputs_prefix='',
        outputs_key_field=None,
        outputs=None,
        raw_response=None,
        readable_output="The `!ip` command for the Cortex Xpanse integration has been deprecated, "
                        "please use the `asm-get-asset-internet-exposure` command or the "
                        "[Xpanse Feed Integration](https://xsoar.pan.dev/docs/reference/integrations/xpanse-feed)."
    )
    return command_results


def domain_command(client: Client, args: dict[str, Any]) -> CommandResults:
    command_results = CommandResults(
        outputs_prefix='',
        outputs_key_field=None,
        outputs=None,
        raw_response=None,
        readable_output="The `!domain` command for the Cortex Xpanse integration has been deprecated, "
                        "please use the `asm-get-asset-internet-exposure` command or the "
                        "[Xpanse Feed Integration](https://xsoar.pan.dev/docs/reference/integrations/xpanse-feed)."
    )
    return command_results


def reset_last_run_command() -> str:
    """
    Puts the reset flag inside integration context.
    Returns:
        (str): 'fetch-incidents was reset successfully'.
    """
    try:
        demisto.setLastRun([])
        return 'fetch-incidents was reset successfully.'
    except DemistoException as e:
        raise DemistoException(f'Error: fetch-incidents was not reset. Reason: {e}')


def fetch_incidents(client: Client, max_fetch: int, last_run: dict[str, int],
                    first_fetch_time: Optional[int], severity: Optional[list],
                    status: Optional[list], tags: Optional[str], look_back: int = 0
                    ) -> List[Any]:
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
    next_page_token = last_run.get('next_page_token')
    xsoar_incidents = []

    start_xpanse_fetch_time, end_xpanse_fetch_time = get_fetch_run_time_range(
        last_run=last_run, first_fetch=str(first_fetch_time), look_back=look_back, date_format=TIME_FORMAT_Z
    )

    # Create epoch timestamp for list_alerts_request()
    parsed_time = parser.isoparse(start_xpanse_fetch_time)
    look_back_epoch_time = int(parsed_time.timestamp() * 1000)
    demisto.debug(f"CortexXpanse - last fetched alert timestamp with look back: {look_back_epoch_time}")

    request_data: dict = {"request_data": {}}
    # `server_creation_time` is used to reflect the most accurate timestamp of the creation of Xpanse alerts
    filters = [
        {'field': 'alert_source', 'operator': 'in', 'value': ['ASM']},
        {'field': 'server_creation_time', 'operator': 'gte', 'value': look_back_epoch_time}
    ]

    optional_filters = {
        "severity": severity,
        "status": status,
        "tags": tags.split(',') if tags else None
    }

    for field, value in optional_filters.items():
        if value:
            filters.append({"field": field, "operator": "in", "value": value})

    if next_page_token:
        request_data["request_data"].update({"next_page_token": next_page_token})

    request_data["request_data"].update({
        'filters': filters,
        'search_from': 0,
        'search_to': max_fetch + 1,  # Alerts indexed higher than this value are not returned in the final results set.
        'use_page_token': True,
        'sort': {'field': 'server_creation_time', 'keyword': 'asc'}
    })

    demisto.debug(f"CortexXpanse - Logger - request data: {request_data}")

    raw = client.list_alerts_request(request_data)

    next_page_token = raw.get('reply', {}).get('next_page_token')
    alerts = raw.get('reply', {}).get('alerts')
    if next_page_token:
        alerts = sorted(alerts, key=lambda alert: alert['local_insert_ts'])  # Sort is not supported when using the use_page_token / next_page_token fields.  # noqa: E501

    filtered_alerts = filter_incidents_by_duplicates_and_limit(
        incidents_res=alerts, last_run=last_run, fetch_limit=(max_fetch + 1), id_field='alert_id'
    )

    for alert in filtered_alerts:
        alert_created_time = datetime.fromtimestamp(alert.get('local_insert_ts') / 1000.0).strftime(TIME_FORMAT_Z)  # local_insert_ts is the closest time to alert creation time in Xpanse.  # noqa: E501

        alert = {
            'name': alert['name'],
            'details': alert['description'],
            'occurred': alert_created_time,  # occurred in XSOAR same time a Xpanse alert was created.
            'rawJSON': json.dumps(alert),
            'xpanse_alert_id': alert['alert_id'],
            'severity': SEVERITY_DICT[alert.get('severity', 'Low')]
        }
        xsoar_incidents.append(alert)

    demisto.debug(f"CortexXpanse - Logger - Number of incidents: {len(xsoar_incidents)}")
    if len(xsoar_incidents) > 0:
        demisto.debug(f"CortexXpanse - Logger - Last fetched alert timestamp: {str(last_run.get('last_fetch', None))}")
        alert_id_list = [alert['alert_id'] for alert in filtered_alerts]
        demisto.debug(f"CortexXpanse - Logger - Xpanse alerts ingested: {alert_id_list}")
        demisto.debug(f"CortexXpanse - Logger - Request data: {request_data}")

    last_run = update_last_run_object(
        last_run=last_run,
        incidents=xsoar_incidents,
        fetch_limit=max_fetch,
        start_fetch_time=start_xpanse_fetch_time,
        end_fetch_time=end_xpanse_fetch_time,
        look_back=look_back,
        created_time_field='occurred',
        id_field='xpanse_alert_id',
        date_format=TIME_FORMAT_Z
    )
    last_run.update({'next_page_token': next_page_token})
    demisto.debug(f"CortexXpanse - Logger - last_run: {str(last_run)}")
    demisto.setLastRun(last_run)

    return xsoar_incidents


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
            look_back = int(params.get('look_back', 0))
            max_fetch = int(params.get('max_fetch', 10))

            if look_back > 720:
                raise DemistoException('The Look Back value is currently set too high. Please adjust it to 720 minutes or less.')
            fetch_incidents(
                client=client,
                max_fetch=max_fetch,
                last_run={},
                look_back=look_back,
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
        look_back = int(params.get('look_back', 0))
        max_fetch = int(params.get('max_fetch', 10))
        creds = params.get('credentials', {})
        api = creds.get('password', '')
        auth_id = creds.get('identifier', '')
        headers = {
            'Authorization': f'{api}',
            'x-xdr-auth-id': f'{auth_id}',
            'Content-Type': 'application/json',
            "User-Agent": f"Cortex Xpanse Integration Pack/{PACK_VERSION} XSOAR/{DEMISTO_VERSION}"
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

        # To debug integration instance configuration.
        integration_context = demisto.getIntegrationContext()
        if 'xpanse_integration_severity' in integration_context:
            xpanse_integration_severity = integration_context.get('xpanse_integration_severity')
            if xpanse_integration_severity != severity:
                demisto.setIntegrationContext({"xpanse_integration_severity": severity})
                demisto.debug(demisto.debug(f"CortexXpanse - Integration Severity: {severity}"))

        commands = {
            'asm-add-note-to-asset': add_note_to_asset_command,
            'asm-get-asset-internet-exposure': get_asset_internet_exposure_command,
            'asm-get-attack-surface-rule': list_attack_surface_rules_command,
            'asm-get-external-ip-address-range': get_external_ip_address_range_command,
            'asm-get-external-service': get_external_service_command,
            'asm-get-incident': get_incident_command,
            'asm-list-alerts': list_alerts_command,
            'asm-list-asset-internet-exposure': list_asset_internet_exposure_command,
            'asm-list-external-ip-address-range': list_external_ip_address_range_command,
            'asm-list-external-service': list_external_service_command,
            'asm-list-external-websites': list_external_websites_command,
            'asm-list-incidents': list_incidents_command,
            'asm-tag-asset-assign': assign_tag_to_assets_command,
            'asm-tag-asset-remove': remove_tag_to_assets_command,
            'asm-tag-range-assign': assign_tag_to_ranges_command,
            'asm-tag-range-remove': remove_tag_to_ranges_command,
            'asm-update-alerts': update_alert_command,
            'asm-update-incident': update_incident_command,
            'domain': domain_command,
            'ip': ip_command,
        }

        if command == 'test-module':
            test_module(client, params, first_fetch_timestamp)
        elif command == 'fetch-incidents':
            incidents = fetch_incidents(
                client=client,
                max_fetch=max_fetch,
                last_run=demisto.getLastRun(),
                first_fetch_time=first_fetch_timestamp,
                severity=severity,
                status=status,
                tags=tags,
                look_back=look_back
            )
            demisto.incidents(incidents)
        elif command == 'asm-reset-last-run':
            return_results(reset_last_run_command())
        elif command in commands:
            return_results(commands[command](client, args))
        else:
            raise NotImplementedError(f'{command} command is not implemented.')

    except Exception as e:
        return_error(f'Failed to execute {command} command.\nError:\n{str(e)}')


''' ENTRY POINT '''

if __name__ in ['__main__', 'builtin', 'builtins']:
    main()
