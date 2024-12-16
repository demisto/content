import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
import urllib3
from typing import Dict, Any, List
from requests import Response  # Used to typing Response as a return from functions

# Disable insecure warnings
urllib3.disable_warnings()

DEFAULT_SEARCH_LIMIT = 100


class NotFoundError(Exception):
    """Exception raised when an error is encountered that does
    not have an error message, like with a waitress error"""


class ProcessingError(Exception):
    """Exception raised when a 500 error is returned from the API
    with a json body containing an error code and message"""


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

        response = self._http_request(
            "POST",
            "/xpanse_remediation_rules/rules/",
            json_data=request_data,
            error_handler=get_api_error,
        )

        return response

    def list_external_service_request(self, search_params: List[Dict]) -> Dict[str, Any]:
        """Get a list of all your external services using the '/assets/get_external_services/' endpoint.

        Args:
            search_params (list): list of search parameters to add to the API call body.

        Returns:
            dict: dict containing list of external services.
        """
        data = {
            "request_data": {"filters": search_params, "search_to": DEFAULT_SEARCH_LIMIT}
        }

        response = self._http_request(
            "POST",
            "/assets/get_external_services/",
            json_data=data,
            error_handler=get_api_error,
        )

        return response

    def get_external_service_request(self, service_id_list: List[str]) -> Dict[str, Any]:
        """Get service details using the '/assets/get_external_service/' endpoint.

        Args:
            service_id_list (list): single service id in list format.

        Returns:
            dict: dict containing information on single external service.
        """
        data = {"request_data": {"service_id_list": service_id_list}}

        response = self._http_request(
            "POST",
            "/assets/get_external_service",
            json_data=data,
            error_handler=get_api_error,
        )

        return response

    def list_external_ip_address_range_request(self) -> Dict[str, Any]:
        """Get a list of all your internet exposure IP ranges using the '/assets/get_external_ip_address_ranges/' endpoint.

        Returns:
            dict: dict containing list of external ip address ranges.
        """
        data = {"request_data": {"search_to": DEFAULT_SEARCH_LIMIT}}

        response = self._http_request(
            "POST",
            "/assets/get_external_ip_address_ranges/",
            json_data=data,
            error_handler=get_api_error,
        )

        return response

    def get_external_ip_address_range_request(
        self, range_id_list: List[str]
    ) -> Dict[str, Any]:
        """Get external IP address range details using the '/assets/get_external_ip_address_range/' endpoint.

        Args:
            range_id_list (list): single range id in list format.

        Returns:
            dict: dict containing information on external ip address range.
        """
        data = {"request_data": {"range_id_list": range_id_list}}

        response = self._http_request(
            "POST",
            "/assets/get_external_ip_address_range/",
            json_data=data,
            error_handler=get_api_error,
        )

        return response

    def get_attack_surface_rule_request(
        self, search_params: List[dict]
    ) -> Dict[str, Any]:
        """Get Attack Surface Rule details for an attack surface rule id using the '/get_attack_surface_rules/' endpoint.

        Args:
            attack_surface_rule_id (str): Coma separated attack surface rule ids.

        Returns:
            dict: dict containing information about Attack surface rule.
        """
        data = {"request_data": {"filters": search_params}}
        response = self._http_request(
            "POST",
            "/get_attack_surface_rules/",
            json_data=data,
            error_handler=get_api_error
        )
        return response

    def list_asset_internet_exposure_request(
        self, search_params: List[dict]
    ) -> Dict[str, Any]:
        """Get a list of all your internet exposure assets using the '/assets/get_assets_internet_exposure/' endpoint.

        Args:
            search_params (list): list of search parameters to add to the API call body.

        Returns:
            dict: dict containing list of internet exposure assets.
        """
        data = {
            "request_data": {"filters": search_params, "search_to": DEFAULT_SEARCH_LIMIT}
        }

        response = self._http_request(
            "POST",
            "/assets/get_assets_internet_exposure/",
            json_data=data,
            error_handler=get_api_error,
        )

        return response

    def get_asset_internet_exposure_request(
        self, asm_id_list: List[str]
    ) -> Dict[str, Any]:
        """Get internet exposure asset details using the '/assets/get_asset_internet_exposure/' endpoint.

        Args:
            asm_id_list (list): single attack surface management id in list format.

        Returns:
            dict: dict containing information on an internet exposure asset.
        """
        data = {"request_data": {"asm_id_list": asm_id_list}}

        response = self._http_request(
            "POST",
            "/assets/get_asset_internet_exposure/",
            json_data=data,
            error_handler=get_api_error,
        )

        return response

    def start_remediation_confirmation_scan(
        self, alert_internal_id: int, service_id: str, attack_surface_rule_id: str
    ) -> Response:
        """Retrieves ID of active (running) scan if it already exists for the given service; otherwise, creates new a scan.

        Args:
            alert_internal_id (str): _description_
            service_id (str): _description_
            attack_surface_rule_id (str): _description_

        Returns:
            Dict[str, Any]: dictionary containing response information that includes a scan ID.
        """

        data = {
            "request_data": {
                "filters": [
                    {
                        "field": "attack_surface_rule_id",
                        "operator": "EQ",
                        "value": attack_surface_rule_id,
                    },
                    {
                        "field": "alert_internal_id",
                        "operator": "EQ",
                        "value": alert_internal_id,
                    },
                    {"field": "service_id", "operator": "EQ", "value": service_id},
                ]
            }
        }

        response = self._http_request(
            method="POST",
            url_suffix="remediation_confirmation_scanning/requests/get_or_create/",
            json_data=data,
            resp_type="response",
            error_handler=get_api_error,
        )

        return response

    def get_remediation_confirmation_scan_status(self, scan_id: str) -> Response:
        """Retrieves ID of active (running) scan if it already exists for the given service; otherwise, creates new a scan.

        Args:
            alert_internal_id (str): _description_
            service_id (str): _description_
            attack_surface_rule_id (str): _description_

        Returns:
            Dict[str, Any]: dictionary containing response information that includes a scan ID.
        """
        data = {
            "request_data": {
                "filters": [{"field": "id", "operator": "EQ", "value": scan_id}]
            }
        }

        response = self._http_request(
            method="POST",
            url_suffix="/remediation_confirmation_scanning/requests/get/",
            json_data=data,
            resp_type="response",
            error_handler=get_api_error,
        )

        return response


""" HELPER FUNCTIONS """


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
            if entry.get("asm_ids"):
                entry["asm_ids"] = entry["asm_ids"][0]

    return formatted_response


def get_api_error(response: Response):
    """Raises a formatted error based on the response from the base_error file from the server.

    Args:
        response: Response object from an API endpoint.
    Raises:
        NotFoundError: Exception for when an API endpoint
            returns an error that does not have a corresponding error message.
        ProcessingError: Exception for when an API endpoint returns an error message.
    """
    error_code, error_message, extra_message, rcs_err_msg = "", "", "", ""
    try:
        json_response = response.json()
        error_code = json_response.get("reply", {}).get("err_code", {})
        error_message = json_response.get("reply", {}).get("err_msg", {})
        extra_message = json_response.get("reply", {}).get("err_extra", {})
        rcs_err_msg = f"{error_message}. {extra_message}"
        response.raise_for_status()
    except requests.exceptions.HTTPError as err:
        if "Forbidden" not in str(err):
            raise ProcessingError(f"{error_code} - Received error message: '{rcs_err_msg}'.")
        else:
            pass
    except (AttributeError, TypeError) as err:
        if "Forbidden" not in str(err):
            raise NotFoundError(f"{type(err).__name__} - {str(err)}")


""" COMMAND FUNCTIONS """


def list_remediation_rule_command(args: Dict[str, Any], client: Client) -> CommandResults:
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
    asm_rule_id = str(args.get("asm_rule_id"))
    sort_by_creation_time = args.get("sort_by_creation_time")

    # create list of search parameters or pass empty list.
    search_params = []
    if asm_rule_id:
        search_params.append(
            {"field": "attack_surface_rule_id", "operator": "eq", "value": asm_rule_id}
        )
    if sort_by_creation_time:
        request_data = {
            "request_data": {
                "filters": search_params,
                "search_from": 0,
                "search_to": DEFAULT_SEARCH_LIMIT,
                "sort": {"field": "created_at", "keyword": sort_by_creation_time},
            }
        }
    else:
        request_data = {
            "request_data": {
                "filters": search_params,
                "search_from": 0,
                "search_to": DEFAULT_SEARCH_LIMIT,
            }
        }

    response = client.list_remediation_rule_request(request_data)
    parsed = response.get("reply", {}).get("remediation_rules")
    markdown = tableToMarkdown(
        "Remediation Rules",
        parsed,
        removeNull=True,
        headerTransform=string_to_table_header,
    )
    command_results = CommandResults(
        outputs_prefix="ASM.RemediationRule",
        outputs_key_field="rule_id",
        outputs=parsed,
        raw_response=response,
        readable_output=markdown,
    )

    return command_results


def list_external_service_command(args: Dict[str, Any], client: Client) -> CommandResults:
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
    ip_address = args.get("ip_address")
    domain = args.get("domain")
    is_active = args.get("is_active")
    discovery_type = args.get("discovery_type")
    # create list of search parameters or pass empty list.
    search_params = []
    if ip_address:
        search_params.append(
            {"field": "ip_address", "operator": "eq", "value": ip_address}
        )
    if domain:
        search_params.append({"field": "domain", "operator": "contains", "value": domain})
    if is_active:
        search_params.append(
            {"field": "is_active", "operator": "in", "value": [is_active]}
        )
    if discovery_type:
        search_params.append(
            {"field": "discovery_type", "operator": "in", "value": [discovery_type]}
        )

    response = client.list_external_service_request(search_params)
    parsed = response.get("reply", {}).get("external_services")
    markdown = tableToMarkdown(
        "External Services",
        parsed,
        removeNull=True,
        headerTransform=string_to_table_header,
    )
    command_results = CommandResults(
        outputs_prefix="ASM.ExternalService",
        outputs_key_field="service_id",
        outputs=parsed,
        raw_response=response,
        readable_output=markdown,
    )

    return command_results


def get_external_service_command(args: Dict[str, Any], client: Client) -> CommandResults:
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
    service_id = str(args.get("service_id"))
    service_id_list = service_id.split(",")
    if len(service_id_list) > 1:
        raise ValueError("This command only supports one service_id at this time")

    response = client.get_external_service_request(service_id_list)
    parsed = response.get("reply", {}).get("details")
    markdown = tableToMarkdown(
        "External Service",
        parsed,
        removeNull=True,
        headerTransform=string_to_table_header,
    )
    command_results = CommandResults(
        outputs_prefix="ASM.ExternalService",
        outputs_key_field="service_id",
        outputs=parsed,
        raw_response=response,
        readable_output=markdown,
    )

    return command_results


def list_external_ip_address_range_command(
    args: Dict[str, Any], client: Client
) -> CommandResults:
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
    parsed = response.get("reply", {}).get("external_ip_address_ranges")
    markdown = tableToMarkdown(
        "External IP Address Ranges",
        parsed,
        removeNull=True,
        headerTransform=string_to_table_header,
    )
    command_results = CommandResults(
        outputs_prefix="ASM.ExternalIpAddressRange",
        outputs_key_field="range_id",
        outputs=parsed,
        raw_response=response,
        readable_output=markdown,
    )

    return command_results


def get_external_ip_address_range_command(
    args: Dict[str, Any], client: Client
) -> CommandResults:
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
    range_id = str(args.get("range_id"))
    range_id_list = range_id.split(",")
    if len(range_id_list) > 1:
        raise ValueError("This command only supports one range_id at this time")

    response = client.get_external_ip_address_range_request(range_id_list)
    parsed = response.get("reply", {}).get("details")
    markdown = tableToMarkdown(
        "External IP Address Range",
        parsed,
        removeNull=True,
        headerTransform=string_to_table_header,
    )
    command_results = CommandResults(
        outputs_prefix="ASM.ExternalIpAddressRange",
        outputs_key_field="range_id",
        outputs=parsed,
        raw_response=response,
        readable_output=markdown,
    )

    return command_results


def get_attack_surface_rule_command(
    args: Dict[str, Any], client: Client
) -> CommandResults:
    """
    asm-get-attack-surface-rule command: Returns attack surface rule details.

    Args:
        client (Client): CortexAttackSurfaceManagment client to use.
        args (dict): all command arguments, usually passed from ``demisto.args()``

    Returns:
        CommandResults: A ``CommandResults`` object that is then passed to ``return_results``,
        that contains Remediation guidance information.
    """
    attack_surface_rule_id = args.get("attack_surface_rule_id")
    enabled_status = args.get("enabled_status")
    priority = args.get("priority")
    category = args.get("category")

    search_params = []
    if attack_surface_rule_id:
        search_params.append({
            "field": "attack_surface_rule_id",
            "operator": "in",
            "value": attack_surface_rule_id.split(",")
        })
    if enabled_status:
        search_params.append({
            "field": "enabled_status",
            "operator": "in",
            "value": enabled_status.split(",")
        })
    if priority:
        search_params.append({
            "field": "priority",
            "operator": "in",
            "value": priority.split(",")
        })
    if category:
        search_params.append({
            "field": "category",
            "operator": "in",
            "value": category.split(",")
        })

    response = client.get_attack_surface_rule_request(search_params)
    parsed = response.get("reply", {}).get("attack_surface_rules")
    command_results = CommandResults(
        outputs_prefix="ASM.AttackSurfaceRule",
        outputs_key_field="attack_surface_rule",
        outputs=parsed,
        raw_response=response,
    )

    return command_results


def list_asset_internet_exposure_command(
    args: Dict[str, Any], client: Client
) -> CommandResults:
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
    ip_address = args.get("ip_address")
    name = args.get("name")
    asm_type = args.get("type")
    has_active_external_services = args.get("has_active_external_services")
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
        append_search_param(search_params, "has_bu_overrides", "eq", False if has_bu_overrides.lower() == 'false' else True)

    if mac_addresses:
        append_search_param(search_params, "mac_addresses", "contains", mac_addresses)

    response = client.list_asset_internet_exposure_request(search_params)
    formatted_response = response.get("reply", {}).get("assets_internet_exposure", [])
    parsed = format_asm_id(formatted_response)
    markdown = tableToMarkdown(
        "Asset Internet Exposures",
        parsed,
        removeNull=True,
        headerTransform=string_to_table_header,
    )
    command_results = CommandResults(
        outputs_prefix="ASM.AssetInternetExposure",
        outputs_key_field="asm_ids",
        outputs=parsed,
        raw_response=response,
        readable_output=markdown,
    )

    return command_results


def get_asset_internet_exposure_command(
    args: Dict[str, Any], client: Client
) -> CommandResults:
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
    asm_id = str(args.get("asm_id"))
    asm_id_list = asm_id.split(",")
    if len(asm_id_list) > 1:
        raise ValueError("This command only supports one asm_id at this time")

    response = client.get_asset_internet_exposure_request(asm_id_list)
    parsed = response.get("reply", {}).get("details")
    markdown = tableToMarkdown(
        "Asset Internet Exposure",
        parsed,
        removeNull=True,
        headerTransform=string_to_table_header,
    )
    command_results = CommandResults(
        outputs_prefix="ASM.AssetInternetExposure",
        outputs_key_field="asm_ids",
        outputs=parsed,
        raw_response=response,
        readable_output=markdown,
    )

    return command_results


def start_remediation_confirmation_scan_command(
    args: Dict[str, Any], client: Client
) -> CommandResults:
    """
    asm-start-remediation-confirmation-scan command: Starts a new scan or gets an existing scan ID.

    Args:
        client (Client): CortexAttackSurfaceManagment client to use.
        args (dict): all command arguments, usually passed from ``demisto.args()`` (not used in this function).

    Returns:
        CommandResults: A ``CommandResults`` object that is then passed to ``return_results``,
        that contains the ID of the Remediation Confirmation Scan.
    """
    service_id = str(args.get("service_id"))
    attack_surface_rule_id = str(args.get("attack_surface_rule_id"))
    alert_internal_id = int(args.get("alert_internal_id", ""))
    if alert_internal_id < 0:
        raise ValueError(
            f"Expected a non-negative integer, but got {alert_internal_id}."
        )

    response = client.start_remediation_confirmation_scan(
        alert_internal_id=alert_internal_id,
        service_id=service_id,
        attack_surface_rule_id=attack_surface_rule_id,
    )

    demisto.debug(response.status_code)

    json_response = response.json()
    formatted_outputs = json_response.get("reply", {})

    if response.status_code == 201:
        formatted_outputs.update({"scan_creation_status": "created"})
    elif response.status_code == 200:
        formatted_outputs.update({"scan_creation_status": "existing"})

    markdown = tableToMarkdown(
        "Creation of Remediation Confirmation Scan",
        formatted_outputs,
        removeNull=True,
        headerTransform=string_to_table_header,
    )
    command_results = CommandResults(
        outputs_prefix="ASM.RemediationScan",
        outputs_key_field="",
        outputs=formatted_outputs,
        raw_response=json_response,
        readable_output=markdown,
    )
    return command_results


@polling_function(name=demisto.command(),
                  interval=arg_to_number(demisto.args().get('interval_in_seconds', 600)),
                  timeout=arg_to_number(demisto.args().get('timeout_in_seconds', 11000)),
                  requires_polling_arg=False  # This means it will always be default to poll, poll=true
                  )
def get_remediation_confirmation_scan_status_command(args: Dict[str, Any], client: Client):
    """
    asm-get-remediation-confirmation-scan-status command: Polls for status of an existing remediation confirmation scan.

    Args:
        client (Client): CortexAttackSurfaceManagment client to use.
        args (dict): all command arguments, usually passed from ``demisto.args()`` (not used in this function).

    Returns:
        PollResult: A ``PollResult`` object that is then passed to ``return_results``,
        that contains the ID of the Remediation Confirmation Scan and a success or failure message.
    """
    scan_id = str(args.get("scan_id"))
    response = client.get_remediation_confirmation_scan_status(scan_id=scan_id)
    json_response = response.json()
    scan_status = json_response.get('reply').get('status')

    if scan_status == "IN_PROGRESS":
        return PollResult(
            response=None,
            partial_result=CommandResults(
                outputs_prefix="ASM.RemediationScan",
                outputs_key_field="scan_id",
                readable_output="Waiting for remediation confirmation scan to finish..."
            ),
            continue_to_poll=True,
            args_for_next_run={"scan_id": scan_id, **args}
        )
    elif scan_status == "SUCCESS":
        formatted_outputs = json_response.get("reply", {})
        markdown = tableToMarkdown(
            "Status of Remediation Confirmation Scan",
            formatted_outputs,
            removeNull=True,
            headerTransform=string_to_table_header,
        )
        command_results = CommandResults(
            outputs_prefix="ASM.RemediationScan",
            outputs_key_field="",
            outputs=formatted_outputs,
            raw_response=json_response,
            readable_output=markdown,
        )
        return PollResult(
            response=command_results,
            continue_to_poll=False)
    elif scan_status == "FAILED_TIMEOUT" or scan_status == "FAILED_ERROR":
        formatted_outputs = json_response.get("reply", {})
        command_results = CommandResults(
            outputs_prefix="ASM.RemediationScan",
            outputs_key_field="",
            outputs=formatted_outputs,
            raw_response=json_response,
            readable_output="The remediation confirmation scan timed out or failed."
        )
        return PollResult(response=command_results, continue_to_poll=False)
    else:
        formatted_outputs = json_response.get("reply", {})
        command_results = CommandResults(
            outputs_prefix="ASM.RemediationScan",
            outputs_key_field="",
            outputs=formatted_outputs,
            raw_response=json_response,
            readable_output="The remediation confirmation scan timed out or failed."
        )
        return PollResult(response=command_results, continue_to_poll=False)


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
        if "Forbidden" in str(e):
            raise DemistoException("Authorization Error: make sure API Key is correctly set")
        else:
            raise e
    return_results("ok")


def main() -> None:
    """
    main function
    """
    params: Dict[str, Any] = demisto.params()
    args: Dict[str, Any] = demisto.args()

    command = demisto.command()
    demisto.debug(f"Command being called is {command}")

    try:
        creds = params.get("credentials", {})
        api = creds.get("password", "")
        auth_id = creds.get("identifier", "")
        headers = {
            "Authorization": f"{api}",
            "x-xdr-auth-id": f"{auth_id}",
            "Content-Type": "application/json",
        }

        proxy = params.get("proxy", False)
        handle_proxy()
        verify_certificate = not params.get("insecure", False)

        url_suffix = "/public_api/v1"
        url = params.get("url", "")
        add_sensitive_log_strs(api)
        base_url = urljoin(url, url_suffix)
        client = Client(
            base_url=base_url, verify=verify_certificate, headers=headers, proxy=proxy
        )

        commands = {
            "asm-list-external-service": list_external_service_command,
            "asm-get-external-service": get_external_service_command,
            "asm-list-external-ip-address-range": list_external_ip_address_range_command,
            "asm-get-external-ip-address-range": get_external_ip_address_range_command,
            "asm-get-attack-surface-rule": get_attack_surface_rule_command,
            "asm-list-asset-internet-exposure": list_asset_internet_exposure_command,
            "asm-get-asset-internet-exposure": get_asset_internet_exposure_command,
            "asm-list-remediation-rule": list_remediation_rule_command,
            "asm-start-remediation-confirmation-scan": start_remediation_confirmation_scan_command,
            "asm-get-remediation-confirmation-scan-status": get_remediation_confirmation_scan_status_command,
        }

        if command == "test-module":
            test_module(client)
        elif command in commands:
            return_results(commands[command](args, client))
        else:
            raise NotImplementedError(f"{command} command is not implemented.")

    except Exception as e:
        return_error(f"Failed to execute {command} command.\nError:\n{str(e)}")


""" ENTRY POINT """

if __name__ in ["__main__", "builtin", "builtins"]:
    main()
