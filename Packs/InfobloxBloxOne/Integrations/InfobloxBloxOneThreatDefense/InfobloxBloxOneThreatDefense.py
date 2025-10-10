import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
from CommonServerUserPython import *

import ipaddress

SEVERITY_MAP = {"INFO": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
THREAT_LEVELS = ["LOW", "MEDIUM", "HIGH"]
INCIDENT_SEVERITY_MAP = {"INFO": "Info", "MEDIUM": "Medium", "HIGH": "High", "CRITICAL": "Critical"}
INCIDENT_LINK = "https://csp.infoblox.com/#/insights-console/insight/{}/summary"
ERRORS = {
    "INVALID_MAX_FETCH": "Invalid Max Fetch: {}. Max Fetch must be a positive integer ranging from 1 to 200.",
}
MAC_PATTERN = re.compile(
    r"^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})|([0-9a-fA-F]{4}\.[0-9a-fA-F]{4}\.[0-9a-fA-F]{4})|([0-9A-Fa-f]{12})$"
)
VENDOR_NAME = "InfobloxThreatDefense"
BASE_URL = "https://csp.infoblox.com"
DEFAULT_FIRST_FETCH = "24 hours"
MARKDOWN_CHARS = r"\*_{}[]()#+-!"
BACKOFF_FACTOR = 7.5  # Consider its double.
TOTAL_RETRIES = 4
TOTAL_RETRIES_ON_ENRICHMENT = 0
DEFAULT_TIMEOUT = 60
TIMEOUT_ON_ENRICHMENT = 15
STATUS_CODE_TO_RETRY = (429, *(status_code for status_code in requests.status_codes._codes if status_code >= 500))  # type: ignore
VALID_CODES = [
    status_code
    for status_code in requests.status_codes._codes  # type: ignore
    if status_code  # type: ignore[attr-defined]
    >= 200
    and status_code < 300
]
OK_CODES = (400, 401, 403, 404, 521, *VALID_CODES)  # type: ignore

OUTPUT_PREFIX = {
    "IP": "InfobloxCloud.IP",
    "Domain": "InfobloxCloud.Domain",
    "URL": "InfobloxCloud.URL",
}

MESSAGES = {
    "INVALID_JSON_OBJECT": "Failed to parse json object from response: {}.",
    "STATUS_CODE": "Error in API call [{}] - {}",
    "INVALID_ARGUMENT_RESPONSE": "Invalid argument value while trying to get information from Infoblox Cloud: ",
    "INVALID_API_KEY": "Encountered error while trying to get information from Infoblox Cloud: "
    "Invalid Service API Key configured.",
    "NO_RECORD_FOUND": "No record found for given argument(s): Not Found.",
    "TEST_CONNECTIVITY_FAILED": "Test connectivity failed. Please provide valid input parameters.",
    "REQUIRED_ARGUMENT": "The '{}' is a required argument.",
    "NO_INFO_FOUND": "No {} information found for {}: {}.",
    "KEY_NOT_FOUND": "Key {} not found in response.",
    "INVALID_VALUE": "The value '{}' is invalid for '{}'.",
    "INVALID_IP_ADDRESS": "The following IP Addresses were found invalid: {}",
    "INVALID_DNS_EVENT_THREAT_LEVEL": "Invalid threat level configured for parameter 'DNS Event Threat Level' with option: {}",
}


class BloxOneTDClient(BaseClient):
    def __init__(self, api_key, verify=True, proxy=False):
        integration_reliability = demisto.params().get("integrationReliability")
        self.integration_reliability = integration_reliability
        self.last_response = None
        super().__init__(headers={"Authorization": f"Token {api_key}"}, base_url=BASE_URL, verify=verify, proxy=proxy)

    def http_request(self, method, url_suffix, params=None, json_data=None):
        """
        Get http response based on url and given parameters.

        :param method: Specify http methods
        :param url_suffix: url encoded url suffix
        :param params: None
        :param json_data: None
        :return: http response on json
        """
        demisto.debug(f"Requesting Infoblox Cloud with method: {method}, url_suffix: {url_suffix} and params: {params}")
        # For reputation commands which run during an enrichment we limit the timeout and the retries
        retries = TOTAL_RETRIES_ON_ENRICHMENT if is_time_sensitive() else TOTAL_RETRIES
        timeout = TIMEOUT_ON_ENRICHMENT if is_time_sensitive() else DEFAULT_TIMEOUT

        resp = self._http_request(
            method=method,
            url_suffix=url_suffix,
            params=params,
            json_data=json_data,
            retries=retries,
            status_list_to_retry=STATUS_CODE_TO_RETRY,
            backoff_factor=BACKOFF_FACTOR,
            raise_on_redirect=False,
            raise_on_status=False,
            resp_type="response",
            ok_codes=OK_CODES,
            timeout=timeout,
        )  # type: ignore

        status_code = resp.status_code

        self.last_response = resp

        if status_code == 204:
            return None

        if status_code == 401:
            raise DemistoException(MESSAGES["STATUS_CODE"].format(status_code, MESSAGES["INVALID_API_KEY"]))

        try:
            resp_json = resp.json()
        except ValueError as exception:
            raise DemistoException(
                MESSAGES["STATUS_CODE"].format(status_code, MESSAGES["INVALID_JSON_OBJECT"].format(resp.text)), exception
            ) from exception

        if status_code not in VALID_CODES:
            if status_code == 400:
                raise DemistoException(
                    MESSAGES["STATUS_CODE"].format(
                        status_code,
                        MESSAGES["INVALID_ARGUMENT_RESPONSE"]
                        + str(resp_json.get("detail", resp_json.get("message", json.dumps(resp_json)))),
                    )
                )
            if status_code == 404:
                raise DemistoException(MESSAGES["STATUS_CODE"].format(status_code, MESSAGES["NO_RECORD_FOUND"]))
            if status_code in (521, 403):
                raise DemistoException(MESSAGES["STATUS_CODE"].format(status_code, MESSAGES["TEST_CONNECTIVITY_FAILED"]))
            self.client_error_handler(resp)

        return resp_json

    def dossier_source_list(self) -> list[str]:
        url_suffix = "/tide/api/services/intel/lookup/sources"
        res = self.http_request("GET", url_suffix=url_suffix)
        return [source for source, enabled in res.items() if enabled]

    def lookalike_domain_list(
        self,
        user_filter: Optional[str] = None,
        target_domain: Optional[str] = None,
        detected_at: Optional[str] = None,
        limit: int = 50,
        offset: Optional[int] = None,
    ) -> List[Dict]:
        url_suffix = "/api/tdlad/v1/lookalike_domains"
        filter_params: Dict[str, Any] = {key: val for key, val in [("_limit", limit), ("_offset", offset)] if val}

        # there is no reference in the docs but it seems that one of the following is correct
        # - the filters combination is OR
        # - we can't filter by more than filter
        # as a result we decided to allow just one filter at a time
        if user_filter:
            _filter = user_filter
        elif target_domain:
            _filter = f'target_domain=="{target_domain}"'
        else:  # detected_at != None
            _filter = f'detected_at>="{detected_at}"'

        filter_params["_filter"] = _filter

        return self.http_request("GET", url_suffix=url_suffix, params=filter_params)["results"]

    def dossier_lookup_get_create(self, indicator_type: str, value: str, sources: Optional[List[str]] = None) -> str:
        url_suffix = f"/tide/api/services/intel/lookup/indicator/{indicator_type}"
        params: Dict[str, Any] = {"value": value}
        if sources:
            params["source"] = sources

        data = self.http_request("GET", url_suffix=url_suffix, params=params)
        return data["job_id"]

    def dossier_lookup_get_is_done(self, job_id: str) -> bool:
        url_suffix = f"/tide/api/services/intel/lookup/jobs/{job_id}/pending"
        data = self.http_request("GET", url_suffix=url_suffix)
        if data["state"] == "completed":
            if data["status"] == "success":
                return True
            raise DemistoException(f"job {job_id} is completed with status: {data['status']}\ndetails: {data}")
        return False

    def dossier_lookup_get_results(self, job_id: str) -> Dict:
        url_suffix = f"/tide/api/services/intel/lookup/jobs/{job_id}/results"
        return self.http_request("GET", url_suffix=url_suffix)

    def soc_insights_list(self, params: dict) -> list[dict]:
        """
        :param params: Dictionary of parameters.
        :return: List of SOC insights.
        """
        url_suffix = "api/v1/insights"
        return self.http_request("GET", url_suffix=url_suffix, params=params)

    def soc_insight_indicators_list(self, params: dict, soc_insight_id: str) -> list[dict]:
        """
        :param params: Dictionary of parameters.
        :return: List of SOC insight indicators.
        """
        url_suffix = f"api/v1/insights/{soc_insight_id}/indicators"
        return self.http_request("GET", url_suffix=url_suffix, params=params)

    def soc_insight_events_list(self, params: dict, soc_insight_id: str) -> list[dict]:
        """
        :param params: Dictionary of parameters.
        :return: List of SOC insight events.
        """
        url_suffix = f"api/v1/insights/{soc_insight_id}/events"
        return self.http_request("GET", url_suffix=url_suffix, params=params)

    def soc_insight_assets_list(self, params: dict, soc_insight_id: str) -> list[dict]:
        """
        :param params: Dictionary of parameters.
        :return: List of SOC insight assets.
        """
        url_suffix = f"api/v1/insights/{soc_insight_id}/assets"
        return self.http_request("GET", url_suffix=url_suffix, params=params)

    def soc_insight_comments_list(self, params: dict, soc_insight_id: str) -> list[dict]:
        """
        :param params: Dictionary of parameters.
        :return: List of SOC insight comments.
        """
        url_suffix = f"api/v1/insights/{soc_insight_id}/comments"
        return self.http_request("GET", url_suffix=url_suffix, params=params)

    def get_named_list(self, params: Dict):
        """
        :param params: Dictionary of parameters.
        :return: Named list.
        """
        url_suffix = "/api/atcfw/v1/named_lists/0"
        response = self.http_request("GET", url_suffix=url_suffix, params=params)
        return response

    def remove_named_list_items(self, named_list_id: str, data: Dict):
        """
        :param named_list_id: ID of the named list.
        :param data: Dictionary of data to remove from the named list.
        """
        url_suffix = f"/api/atcfw/v1/named_lists/{named_list_id}/items"
        self.http_request("DELETE", url_suffix=url_suffix, json_data=data)

    def update_named_list(self, named_list_id: str, data: Dict):
        """
        :param named_list_id: ID of the named list.
        :param data: Dictionary of data to update the named list.
        :return: Updated named list.
        """
        url_suffix = f"/api/atcfw/v1/named_lists/{named_list_id}/items"
        response = self.http_request("POST", url_suffix=url_suffix, json_data=data)
        return response

    def get_indicator_threat_info(self, indicator_value: str, indicator_type: str) -> dict[str, Any]:
        """Gets the indicator threat information using the '/tide/api/data/threats' API endpoint.

        :type indicator_value: ``str``
        :param indicator_value: Indicator value to get the reputation for.

        :type indicator_type: ``str``
        :param indicator_type: Indicator type to get the reputation for.

        :return: dict containing the indicator threat information as returned from the API.
        :rtype: ``Dict[str, Any]``
        """
        params = {"type": indicator_type, indicator_type: indicator_value, "rlimit": 1}
        if indicator_type == "ip" and is_ipv6_valid(indicator_value):
            params["include_ipv6"] = "true"
        return self.http_request(method="GET", url_suffix="/tide/api/data/threats", params=params)

    def get_ip_address_info(self, ip: str) -> dict[str, Any]:
        """Gets IP address information from the address management API.

        :type ip: ``str``
        :param ip: IP address to get information for.

        :return: dict containing the IP address information.
        :rtype: ``Dict[str, Any]``
        """
        return self.http_request(
            method="GET", url_suffix="/api/ddi/v1/ipam/address", params={"_filter": f"address=='{ip}'", "_limit": 1}
        )

    def get_domain_address_info(self, domain: str) -> dict[str, Any]:
        """Gets domain address information from the address management API.

        :type domain: ``str``
        :param domain: Domain to get information for.

        :return: dict containing the domain address information.
        :rtype: ``Dict[str, Any]``
        """
        return self.http_request(
            method="GET", url_suffix="/api/ddi/v1/ipam/host", params={"_filter": f"name=='{domain}'", "_limit": 1}
        )

    def get_indicator_threat_info_text_search(self, indicator_value: str, indicator_type: str) -> dict[str, Any]:
        """Gets the indicator threat information using the '/tide/api/data/threats' API endpoint.

        :type indicator_value: ``str``
        :param indicator_value: Indicator value to get the reputation for.

        :type indicator_type: ``str``
        :param indicator_type: Indicator type to get the reputation for.

        :return: dict containing the indicator threat information as returned from the API.
        :rtype: ``Dict[str, Any]``
        """
        return self.http_request(
            method="GET",
            url_suffix="/tide/api/data/threats",
            params={"type": indicator_type, "text_search": indicator_value, "rlimit": 1},
        )

    def mac_enrich(self, mac: str) -> Dict[str, Any]:
        """Gets DHCP lease information for a specific MAC address.

        :type mac: ``str``
        :param mac: MAC address to lookup.

        :return: dict containing the DHCP lease information as returned from the API
        :rtype: ``Dict[str, Any]``
        """
        return self.http_request(
            method="GET", url_suffix="/api/ddi/v1/dhcp/lease", params={"_filter": f"hardware=='{mac}'", "_limit": 1}
        )

    def list_dns_security_events(self, params: dict) -> list[dict]:
        """
        List DNS security events from Infoblox Cloud.

        :param params: Dictionary of parameters for filtering DNS security events.
        :return: List of DNS security events.
        """
        url_suffix = "/api/dnsdata/v2/dns_event"
        return self.http_request("GET", url_suffix=url_suffix, params=params)


def check_empty(x: Any) -> bool:
    """
    Check if input is empty (None, empty dict, empty list, or empty string).

    :param x: Input to check.
    :type x: Any
    :return: True if x is empty, False otherwise.
    :rtype: bool
    """
    return x is None or x == {} or x == [] or x == ""


def string_escape_markdown(data: Any):
    """
    Escape any chars that might break a markdown string.
    :param data: The data to be modified (required).
    :return: A modified data.
    """
    if isinstance(data, str):
        data = "".join(["\\" + str(c) if c in MARKDOWN_CHARS else str(c) for c in data])
    elif isinstance(data, list):
        new_data = []
        for sub_data in data:
            if isinstance(sub_data, str):
                sub_data = "".join(["\\" + str(c) if c in MARKDOWN_CHARS else str(c) for c in sub_data])
            new_data.append(sub_data)
        data = new_data
    return data


def trim_args(args: Dict[str, Any]):
    """
    Trim the arguments for extra spaces.

    :type args: Dict
    :param args: it contains arguments of the command
    """
    for key, value in args.items():
        if isinstance(value, str):
            args[key] = value.strip()

    return args


def validate_argument(value: Any, name: str) -> str:
    """
    Check if empty value is passed as value for argument and raise appropriate ValueError.

    :type value: Any
    :param value: value of the argument.

    :type name: str
    :param name: name of the argument.
    """
    if not value:
        raise ValueError(MESSAGES["REQUIRED_ARGUMENT"].format(name))
    return value


def validate_key(response: dict, name: str):
    """
    Check if the given key exists in the response and raise appropriate ValueError.

    :type response: dict
    :param response: response of the command.

    :type name: str
    :param name: name of the key.
    """
    if not response or not response.get(name):
        raise ValueError(MESSAGES["KEY_NOT_FOUND"].format(name))
    return response.get(name)


def remove_empty_elements_for_hr(d: Any) -> Any:
    """
    Recursively remove empty lists, empty dicts, or None elements from a dictionary or list.
    :param d: Input dictionary or list.
    :return: Dictionary or list with all empty lists, and empty dictionaries removed.
    """
    if not isinstance(d, dict | list):
        return str(d) if isinstance(d, int | float) else d
    elif isinstance(d, list):
        return [v for v in (remove_empty_elements_for_hr(v) for v in d) if not check_empty(v)]
    return {k: v for k, v in ((k, remove_empty_elements_for_hr(v)) for k, v in d.items()) if not check_empty(v)}


def header_transformer_for_ip(header: str) -> str:
    """
    To transform the header for the markdown table.

    :type header: ``str``
    :param header: Header name.

    :return: The title cased header.
    :rtype: ``str``
    """
    return header.replace("_", " ").title().replace("Ip", "IP")


def header_transformer_for_url(header: str) -> str:
    """
    To transform the header for the markdown table.

    :type header: ``str``
    :param header: Header name.

    :return: The title cased header.
    :rtype: ``str``
    """
    return header.replace("_", " ").title().replace("Url", "URL")


def validate_ip_addresses(ips_list: list[str]) -> tuple[list[str], list[str]]:
    """
    Given a list of IP addresses, returns the invalid and valid ips.

    :type ips_list: ``List[str]``
    :param ips_list: List of ip addresses.

    :return: invalid_ip_addresses and valid_ip_addresses.
    :rtype: ``Tuple[List[str], List[str]]``
    """
    invalid_ip_addresses = []
    valid_ip_addresses = []
    for ip in ips_list:
        ip = ip.strip().strip('"')
        if ip:
            if is_ip_valid(ip, accept_v6_ips=True):
                valid_ip_addresses.append(ip)
            else:
                invalid_ip_addresses.append(ip)
    return invalid_ip_addresses, valid_ip_addresses


def get_dbot_score_from_threat_level(threat_level: int) -> int:
    """
    Return DBot score based on threat level.

    :param threat_level: Threat level score from 0 to 100.
    :type threat_level: ``int``

    :return: DBot score value.
    :rtype: ``int``
    """
    if threat_level is None:
        return Common.DBotScore.NONE

    if threat_level >= 80:
        return Common.DBotScore.BAD
    if threat_level >= 30:
        return Common.DBotScore.SUSPICIOUS
    if threat_level > 0:
        return Common.DBotScore.GOOD

    return Common.DBotScore.NONE


def prepare_hr_for_ip(
    ip: str, threat_data: dict[str, Any], address_data: dict[str, Any], dbot_score_obj: Common.DBotScore
) -> str:
    """
    Prepare Human Readable output for IP command.

    Args:
        ip: IP address being queried.
        threat_data: Threat intelligence data from API.
        address_data: Address information data from API.
        dbot_score: DBot score for the IP.

    Returns:
        Human readable markdown output.
    """
    # Main header
    readable_output = f"## Information for the given {dbot_score_obj.to_readable()} IP: {ip}\n\n"

    # Threat Intelligence Section
    if threat_data:
        # Clean threat data for display
        clean_threat_data = remove_empty_elements_for_hr(threat_data)

        readable_output += (
            tableToMarkdown(
                "Threat Intelligence Summary",
                clean_threat_data,
                headerTransform=header_transformer_for_ip,
                removeNull=True,
                is_auto_json_transform=True,
            )
            + "\n"
        )
    # Address Information Section
    if address_data:
        # Clean address data for display
        clean_address_data = remove_empty_elements_for_hr(address_data)

        readable_output += tableToMarkdown(
            "Address Information",
            clean_address_data,
            headerTransform=header_transformer_for_ip,
            removeNull=True,
            is_auto_json_transform=True,
        )

    return readable_output


def prepare_hr_for_named_list(json_data: Dict[str, Any], table_name: str = "Named List Details") -> str:
    """
    Prepare human-readable for ip block, ip unblock, domain block, domain unblock command.

    :type json_data: Dict[str, Any]
    :param json_data: Response of the command

    :type table_name: str
    :param table_name: Name of the table to display

    :rtype: str
    :return: Human readable string for the command
    """
    tags = json_data.get("tags")
    if tags:
        tags = [f"{k}: {v}" for k, v in tags.items()]
        tags = string_escape_markdown(tags)
    hr_output = {
        "ID": json_data.get("id"),
        "Name": json_data.get("name"),
        "Type": json_data.get("type"),
        "Description": json_data.get("description"),
        "Items": string_escape_markdown(json_data.get("items")),
        "Confidence Level": json_data.get("confidence_level"),
        "Threat Level": json_data.get("threat_level"),
        "Tags": tags,
        "Created Time": json_data.get("created_time"),
        "Updated Time": json_data.get("updated_time"),
    }

    headers = [
        "ID",
        "Name",
        "Type",
        "Description",
        "Items",
        "Confidence Level",
        "Threat Level",
        "Tags",
        "Created Time",
        "Updated Time",
    ]

    return tableToMarkdown(table_name, hr_output, headers=headers, removeNull=True)


def prepare_hr_for_soc_insights(insights: list[dict[str, Any]]) -> str:
    """
    Prepare human-readable for SOC insights command.

    :type insights: list[dict[str, Any]]
    :param insights: List of insights.

    :rtype: str
    :return: Human readable string for the command.
    """
    table_name = "SOC Insights"
    hr_output = []
    for insight in insights:
        hr_output.append(
            {
                "ID": insight.get("insightId"),
                "Priority": insight.get("priorityText"),
                "Class": insight.get("tClass"),
                "Threat Type": insight.get("threatType"),
                "Status": insight.get("status"),
                "Threat Family": insight.get("tFamily"),
                "Feed Source": insight.get("feedSource"),
                "Most Recent At": insight.get("mostRecentAt"),
            }
        )
    headers = [
        "ID",
        "Priority",
        "Class",
        "Threat Type",
        "Status",
        "Threat Family",
        "Feed Source",
        "Most Recent At",
    ]
    return tableToMarkdown(table_name, hr_output, headers=headers, removeNull=True)


def prepare_hr_for_soc_insight_indicators(indicators: list[dict[str, Any]], soc_insight_id: str) -> str:
    """
    Prepare human-readable for SOC insight indicators command.

    :type indicators: list[dict[str, Any]]
    :param indicators: List of indicators.

    :type soc_insight_id: str
    :param soc_insight_id: ID of the insight.

    :rtype: str
    :return: Human readable string for the command.
    """
    table_name = f"Indicators for the given SOC Insight: {soc_insight_id}"
    hr_output = []
    for indicator in indicators:
        hr_output.append(
            {
                "Action": indicator.get("action"),
                "Confidence": indicator.get("confidence"),
                "Max Threat Level": indicator.get("threatLevelMax"),
                "Indicator": indicator.get("indicator"),
                "Count": indicator.get("count"),
                "Max Time": indicator.get("timeMax"),
                "Min Time": indicator.get("timeMin"),
            }
        )
    headers = [
        "Action",
        "Confidence",
        "Max Threat Level",
        "Indicator",
        "Count",
        "Max Time",
        "Min Time",
    ]
    return tableToMarkdown(table_name, hr_output, headers=headers, removeNull=True)


def prepare_hr_for_soc_insight_events(events: list[dict[str, Any]], soc_insight_id: str) -> str:
    """
    Prepare human-readable for SOC insight events command.

    :type events: list[dict[str, Any]]
    :param events: List of events.

    :type soc_insight_id: str
    :param soc_insight_id: ID of the SOC insight.

    :rtype: str
    :return: Human readable string for the command.
    """
    table_name = f"Events for the given SOC Insight: {soc_insight_id}"
    hr_output = []
    for event in events:
        hr_output.append(
            {
                "Confidence Level": event.get("confidenceLevel"),
                "Threat Level": event.get("threatLevel"),
                "Threat Family": event.get("threatFamily"),
                "Action": event.get("action"),
                "Class": event.get("class"),
                "Detected": event.get("detected"),
            }
        )
    headers = [
        "Confidence Level",
        "Threat Level",
        "Threat Family",
        "Action",
        "Class",
        "Detected",
    ]
    return tableToMarkdown(table_name, hr_output, headers=headers, removeNull=True)


def prepare_hr_for_soc_insight_assets(assets: list[dict[str, Any]], soc_insight_id: str) -> str:
    """
    Prepare human-readable for SOC insight assets command.

    :type assets: list[dict[str, Any]]
    :param assets: List of assets.

    :type soc_insight_id: str
    :param soc_insight_id: ID of the insight.

    :rtype: str
    :return: Human readable string for the command.
    """
    table_name = f"Assets for the given SOC Insight: {soc_insight_id}"
    hr_output = []
    for asset in assets:
        hr_output.append(
            {
                "Count": asset.get("count"),
                "QIP": asset.get("qip"),
                "Max Threat Level": asset.get("threatLevelMax"),
                "Location": asset.get("location"),
                "Threat Indicator Distinct Count": asset.get("threatIndicatorDistinctCount"),
                "Time Max": asset.get("timeMax"),
                "Time Min": asset.get("timeMin"),
                "Most Recent Action": asset.get("mostRecentAction"),
            }
        )
    headers = [
        "Count",
        "QIP",
        "Max Threat Level",
        "Location",
        "Threat Indicator Distinct Count",
        "Time Max",
        "Time Min",
        "Most Recent Action",
    ]
    return tableToMarkdown(table_name, hr_output, headers=headers, removeNull=True)


def prepare_hr_for_soc_insight_comments(comments: list[dict[str, Any]], soc_insight_id: str) -> str:
    """
    Prepare human-readable for SOC insight comments command.

    :type comments: list[dict[str, Any]]
    :param comments: List of comments.

    :type soc_insight_id: str
    :param soc_insight_id: ID of the insight.

    :rtype: str
    :return: Human readable string for the command.
    """
    table_name = f"Comments for the given SOC Insight: {soc_insight_id}"
    hr_output = []
    for comment in comments:
        hr_output.append(
            {
                "Comment Changer": comment.get("commentsChanger"),
                "Date Changed": comment.get("dateChanged"),
                "Status": comment.get("status"),
                "Comment": string_escape_markdown(comment.get("newComment")),
            }
        )
    headers = [
        "Comment Changer",
        "Date Changed",
        "Status",
        "Comment",
    ]
    return tableToMarkdown(table_name, hr_output, headers=headers, removeNull=True)


def prepare_hr_for_domain(
    domain: str, threat_data: dict[str, Any], address_data: dict[str, Any], dbot_score_obj: Common.DBotScore
) -> str:
    """
    Prepare Human Readable output for Domain command.

    :param domain: Domain being queried.
    :type domain: ``str``

    :param threat_data: Threat intelligence data from API.
    :type threat_data: ``Dict[str, Any]``

    :param address_data: Address information data from API.
    :type address_data: ``Dict[str, Any]``

    :param dbot_score: DBot score for the URL.
    :type dbot_score: ``Common.DBotScore``

    :return: Human readable markdown output.
    :rtype: ``str``
    """
    # Main header
    readable_output = f"## Information for the given {dbot_score_obj.to_readable()} Domain: {domain}\n\n"

    # Threat Intelligence Section
    if threat_data:
        # Clean threat data for display
        clean_threat_data = remove_empty_elements_for_hr(threat_data)

        readable_output += (
            tableToMarkdown(
                "Threat Intelligence Summary",
                clean_threat_data,
                headerTransform=string_to_table_header,
                removeNull=True,
                is_auto_json_transform=True,
            )
            + "\n"
        )

    # Address Information Section
    if address_data:
        # Clean address data for display
        clean_address_data = remove_empty_elements_for_hr(address_data)

        readable_output += tableToMarkdown(
            "Address Information",
            clean_address_data,
            headerTransform=string_to_table_header,
            removeNull=True,
            is_auto_json_transform=True,
        )
    return readable_output


def prepare_hr_for_url(url: str, threat_data: Dict[str, Any], dbot_score_obj: Common.DBotScore) -> str:
    """
    Prepare Human Readable output for URL command.

    :param url: URL being queried.
    :type url: ``str``

    :param threat_data: Threat intelligence data from API.
    :type threat_data: ``Dict[str, Any]``

    :param dbot_score: DBot score for the URL.
    :type dbot_score: ``Common.DBotScore``

    :return: Human readable markdown output.
    :rtype: ``str``
    """
    # Main header
    readable_output = f"## Information for the given {dbot_score_obj.to_readable()} URL: {url}\n\n"

    # Clean threat data for display
    clean_threat_data = remove_empty_elements_for_hr(threat_data)

    readable_output += (
        tableToMarkdown(
            "Threat Intelligence Summary",
            clean_threat_data,
            headerTransform=header_transformer_for_url,
            removeNull=True,
            is_auto_json_transform=True,
        )
        + "\n"
    )
    return readable_output


def dossier_lookup_task_output(task: Dict) -> Dict:
    params = task.get("params", {})
    return {
        "Task Id": task.get("task_id"),
        "Type": params.get("type"),
        "Target": params.get("target"),
        "Source": params.get("source"),
    }


def dossier_source_list_command(client: BloxOneTDClient) -> CommandResults:
    sources = client.dossier_source_list()
    return CommandResults(
        outputs_prefix="BloxOneTD",
        outputs={"DossierSource": sources},
    )


def validate_and_format_lookalike_domain_list_args(args: Dict) -> Dict:
    if len(list(filter(bool, [args.get("filter"), args.get("target_domain"), args.get("detected_at")]))) != 1:
        raise DemistoException(
            "Please provide one of the following arguments 'target_domain', 'detected_at' or 'filter'"
            " (Exactly one of them, more than one is argument is not accepted)."
        )

    if args.get("detected_at"):
        detected_at = dateparser.parse(args["detected_at"], settings={"TIMEZONE": "UTC", "TO_TIMEZONE": "UTC"})
        if detected_at is None:
            raise DemistoException(f"could not parse {args['detected_at']} as a time value.")
        args["detected_at"] = detected_at.replace(tzinfo=None).isoformat(timespec="milliseconds")
    return args


def lookalike_domain_list_command(client: BloxOneTDClient, args: Dict) -> CommandResults:
    args = validate_and_format_lookalike_domain_list_args(args)

    data = client.lookalike_domain_list(
        user_filter=args.get("filter"),
        target_domain=args.get("target_domain"),
        detected_at=args.get("detected_at"),
        limit=arg_to_number(args.get("limit")) or 50,
        offset=arg_to_number(args.get("offset")) or 0,
    )
    readable_outputs = tableToMarkdown("Results", data, headerTransform=camelize_string)
    return CommandResults(outputs_prefix="BloxOneTD.LookalikeDomain", outputs=data, readable_output=readable_outputs)


def dossier_lookup_get_command_results(data: Dict) -> CommandResults:
    headers = ["Task Id", "Type", "Target", "Source"]
    outputs = data.get("results", [])
    readable_output_data = list(map(dossier_lookup_task_output, outputs))
    readable_output = tableToMarkdown(name="Lookalike Domain List", t=readable_output_data, headers=headers)
    return CommandResults(
        outputs_prefix="BloxOneTD.DossierLookup", outputs=outputs, readable_output=readable_output, raw_response=data
    )


def dossier_lookup_get_schedule_polling_result(args: Dict, first_time: bool = False) -> CommandResults:
    next_run_in_seconds = arg_to_number(args.get("interval_in_seconds")) or 10
    timeout_in_seconds = arg_to_number(args.get("timeout")) or 600
    args["timeout"] = timeout_in_seconds - next_run_in_seconds
    scheduled_command = ScheduledCommand(
        command="bloxone-td-dossier-lookup-get",
        next_run_in_seconds=next_run_in_seconds,
        timeout_in_seconds=timeout_in_seconds,
        args=args,
    )
    readable_output = None if not first_time else f"Job '{args['job_id']}' is still running, it may take a little while..."

    return CommandResults(readable_output=readable_output, scheduled_command=scheduled_command)


def dossier_lookup_get_command(client: BloxOneTDClient, args: Dict) -> CommandResults:
    job_id = args.get("job_id")
    first_time = False
    if job_id is None:
        job_id = client.dossier_lookup_get_create(args["indicator_type"], args["value"], sources=argToList(args.get("sources")))
        first_time = True

    if client.dossier_lookup_get_is_done(job_id):
        data = client.dossier_lookup_get_results(job_id)
        return dossier_lookup_get_command_results(data)
    args["job_id"] = job_id
    return dossier_lookup_get_schedule_polling_result(args, first_time)


def ip_command(client: BloxOneTDClient, args: Dict[str, Any]) -> List[CommandResults]:
    """
    Get IP reputation from Infoblox BloxOne Threat Defense.

    Args:
        client: BloxOne Threat Defense client.
        args: Command arguments

    Returns:
        CommandResults object with IP reputation data.
    """
    ips = argToList(args.get("ip"))
    invalid_ips, valid_ips = validate_ip_addresses(ips)
    total_ips = len(valid_ips + invalid_ips)
    if invalid_ips:
        return_warning(MESSAGES["INVALID_IP_ADDRESS"].format(", ".join(invalid_ips)), exit=len(invalid_ips) == total_ips)
    validate_argument(valid_ips, "ip")
    valid_ips = list(set(valid_ips))

    command_results: List[CommandResults] = []

    for ip in valid_ips:
        # Get threat intelligence and address data
        threat_result = client.get_indicator_threat_info(ip, "ip")
        address_result = client.get_ip_address_info(ip)

        # Extract threat data
        threat_data = None
        if threat_result and threat_result.get("threat"):
            threat_data = threat_result["threat"][0]

        # Extract address data
        address_data = None
        if address_result and address_result.get("results") and len(address_result["results"]) > 0:
            address_data = address_result["results"][0]

        if not threat_data and not address_data:
            return_warning(MESSAGES["NO_INFO_FOUND"].format("threat and address", "IP", ip))
            continue

        # Calculate DBot score based on threat data
        dbot_score = Common.DBotScore.NONE
        if threat_data:
            threat_level = threat_data.get("threat_level")
            confidence = threat_data.get("confidence", 0)
            dbot_score = get_dbot_score_from_threat_level(threat_level)

        # Create DBot score object
        dbot_score_obj = Common.DBotScore(
            indicator=ip,
            indicator_type=DBotScoreType.IP,
            integration_name=VENDOR_NAME,
            score=dbot_score,
            reliability=client.integration_reliability,
        )

        dbot_score_obj.integration_name = VENDOR_NAME

        # Create IP indicator object
        ip_indicator = Common.IP(ip=ip, dbot_score=dbot_score_obj)
        ip_indicator.tags = []

        # Map threat intelligence fields to IP indicator
        if threat_data:
            # Add basic threat intelligence details
            received = threat_data.get("received")
            if received:
                ip_indicator.detection_engines = 1

            class_ = threat_data.get("class")
            if class_:
                ip_indicator.malware_family = class_

            type_ = threat_data.get("type")
            if type_:
                ip_indicator.threat_types = [
                    Common.ThreatTypes(threat_category=type_, threat_category_confidence=str(confidence or ""))
                ]

            # Add extended threat information if available
            extended = threat_data.get("extended", {})
            if extended and isinstance(extended, dict):
                ip_indicator.tags.extend(
                    [f"{key}: {value}" for key, value in extended.items() if value and isinstance(value, str)]
                )

                notes = extended.get("notes")
                if notes:
                    ip_indicator.description = notes
                    dbot_score_obj.malicious_description = notes

        # Map address information fields
        if address_data:
            # Extract hostname from names if available
            names = address_data.get("names")
            if names and isinstance(names, list):
                for name_entry in names:
                    if isinstance(name_entry, dict) and name_entry.get("name") and not ip_indicator.hostname:
                        ip_indicator.hostname = name_entry["name"]
                        break

            # Determine if IP is internal based on usage field
            usage = address_data.get("usage")
            if usage and isinstance(usage, list):
                usage_list = usage
                internal_indicators = ["internal", "private", "corporate", "DHCP LEASED"]
                is_internal = any(
                    any(indicator.lower() in str(usage).lower() for indicator in internal_indicators)
                    for usage in usage_list
                    if usage
                )
                ip_indicator.internal = is_internal

            # Add protocol information if available
            protocol = address_data.get("protocol")
            if protocol:
                ip_indicator.tags.append(f"Protocol: {protocol}")

            # Add state information if available
            state = address_data.get("state")
            if state:
                ip_indicator.tags.append(f"State: {state}")

            address_data_tags = address_data.get("tags")
            if address_data_tags and isinstance(address_data_tags, dict):
                ip_indicator.tags.extend(
                    [f"{key}: {value}" for key, value in address_data_tags.items() if value and isinstance(value, str)]
                )

        # Prepare outputs for context
        outputs = {
            "ip": ip,
            "Threat": threat_data,
            "Address": address_data,
        }

        # Create comprehensive readable output
        readable_output = prepare_hr_for_ip(ip, threat_data, address_data, dbot_score_obj)  # type: ignore

        # Create indicator timeline
        timeline = None
        if threat_data and threat_data.get("received"):
            timeline = IndicatorsTimeline(
                indicators=[ip],
                category="Threat Intelligence Update",
                message=f"IP was identified with threat level: {threat_level or 'Unknown'}, "
                f"confidence: {confidence or 'Unknown'}%",
            )

        command_result = CommandResults(
            outputs_prefix=OUTPUT_PREFIX["IP"],
            outputs_key_field="ip",
            outputs=remove_empty_elements(outputs),
            readable_output=readable_output,
            raw_response={"threat_data": threat_result, "address_data": address_result},
            indicator=ip_indicator,
            indicators_timeline=timeline,
        )
        command_results.append(command_result)

    return command_results


def domain_command(client: BloxOneTDClient, args: Dict[str, Any]) -> List[CommandResults]:
    """
    Get domain/host reputation from Infoblox BloxOne Threat Defense.

    :param client: BloxOneTDClient instance.
    :type client: ``BloxOneTDClient``

    :param args: Command arguments.
    :type args: ``Dict[str, Any]``

    :return: CommandResults object with URL reputation data.
    :rtype: ``List[CommandResults]``
    """
    domains = argToList(args.get("domain"))
    valid_domains = [domain.strip() for domain in domains if domain.strip()]
    validate_argument(valid_domains, "domain")
    valid_domains = list(set(valid_domains))
    command_results = []
    for domain in valid_domains:
        threat_result = client.get_indicator_threat_info(domain, "host")
        address_result = client.get_domain_address_info(domain)

        # Extract threat data
        threat_data = None
        if threat_result and threat_result.get("threat"):
            threat_data = threat_result["threat"][0]

        # Extract address data
        address_data = None
        if address_result and address_result.get("results") and len(address_result["results"]) > 0:
            address_data = address_result["results"][0]

        if not threat_data and not address_data:
            return_warning(MESSAGES["NO_INFO_FOUND"].format("threat and address", "Domain", domain))
            continue

        # Calculate DBot score based on threat data
        dbot_score = Common.DBotScore.NONE
        if threat_data:
            threat_level = threat_data.get("threat_level")
            confidence = threat_data.get("confidence", 0)
            dbot_score = get_dbot_score_from_threat_level(threat_level)

        # Create DBot score object
        dbot_score_obj = Common.DBotScore(
            indicator=domain,
            indicator_type=DBotScoreType.DOMAIN,
            integration_name=VENDOR_NAME,
            score=dbot_score,
            reliability=client.integration_reliability,
        )

        dbot_score_obj.integration_name = VENDOR_NAME

        domain_indicator = Common.Domain(domain=domain, dbot_score=dbot_score_obj)
        domain_indicator.tags = []

        # Map threat intelligence fields to domain indicator
        if threat_data:
            # Add basic threat intelligence details
            received = threat_data.get("received")
            if received:
                domain_indicator.detection_engines = 1

            class_ = threat_data.get("class")
            if class_:
                domain_indicator.malware_family = class_

            type_ = threat_data.get("type")
            if type_:
                domain_indicator.threat_types = [
                    Common.ThreatTypes(threat_category=type_, threat_category_confidence=str(confidence or ""))
                ]

            # Add extended threat information if available
            extended = threat_data.get("extended", {})
            if extended and isinstance(extended, dict):
                domain_indicator.tags.extend(
                    [f"{key}: {value}" for key, value in extended.items() if value and isinstance(value, str)]
                )

                notes = extended.get("notes")
                if notes:
                    domain_indicator.description = notes
                    dbot_score_obj.malicious_description = notes

        # Map address information fields
        relationships = []
        create_relationships = demisto.params().get("create_relationships")
        if address_data:
            # Add extended address information if available
            addresses = address_data.get("addresses")
            if addresses and isinstance(addresses, list) and create_relationships:
                for address in addresses:
                    address_value = address.get("address")
                    if is_ip_valid(address_value, accept_v6_ips=True):
                        relationship = EntityRelationship(
                            name=EntityRelationship.Relationships.RESOLVES_TO,
                            entity_a=domain,
                            entity_a_type=FeedIndicatorType.Domain,
                            entity_b=address_value,
                            entity_b_type=FeedIndicatorType.IP,
                            source_reliability=client.integration_reliability,
                            brand=VENDOR_NAME,
                        )
                        relationships.append(relationship)

            address_data_tags = address_data.get("tags")
            if address_data_tags and isinstance(address_data_tags, dict):
                domain_indicator.tags.extend(
                    [f"{key}: {value}" for key, value in address_data_tags.items() if value and isinstance(value, str)]
                )

        domain_indicator.relationships = relationships

        # Prepare outputs for context
        outputs = {
            "domain": domain,
            "Threat": threat_data,
            "Address": address_data,
        }

        # Create comprehensive readable output
        readable_output = prepare_hr_for_domain(domain, threat_data, address_data, dbot_score_obj)  # type: ignore

        # Create indicator timeline
        timeline = None
        if threat_data and threat_data.get("received"):
            timeline = IndicatorsTimeline(
                indicators=[domain],
                category="Threat Intelligence Update",
                message=f"Domain was identified with threat level: {threat_level or 'Unknown'}, "
                f"confidence: {confidence or 'Unknown'}%",
            )

        command_result = CommandResults(
            outputs_prefix=OUTPUT_PREFIX["Domain"],
            outputs_key_field="domain",
            outputs=remove_empty_elements(outputs),
            readable_output=readable_output,
            raw_response={"threat_data": threat_result, "address_data": address_result},
            indicator=domain_indicator,
            indicators_timeline=timeline,
            relationships=relationships,
        )
        command_results.append(command_result)

    return command_results


def url_command(client: BloxOneTDClient, args: Dict[str, Any]) -> List[CommandResults]:
    """
    Get URL reputation from Infoblox BloxOne Threat Defense.

    :param client: BloxOneTDClient instance.
    :type client: ``BloxOneTDClient``

    :param args: Command arguments.
    :type args: ``Dict[str, Any]``

    :return: CommandResults object with URL reputation data.
    :rtype: ``List[CommandResults]``
    """
    urls = argToList(args.get("url"))
    valid_urls = [url.strip() for url in urls if url.strip()]
    validate_argument(valid_urls, "url")

    valid_urls = list(set(valid_urls))
    command_results = []
    for url in valid_urls:
        threat_result = client.get_indicator_threat_info_text_search(url, "url")
        # Extract threat data
        threat_data = None
        if threat_result and threat_result.get("threat"):
            threat_data = threat_result["threat"][0]

        if not threat_data:
            return_warning(MESSAGES["NO_INFO_FOUND"].format("threat", "URL", url))
            continue

        threat_level = threat_data.get("threat_level")
        confidence = threat_data.get("confidence", 0)

        dbot_score = get_dbot_score_from_threat_level(threat_level)

        # Create DBot score object
        dbot_score_obj = Common.DBotScore(
            indicator=url,
            indicator_type=DBotScoreType.URL,
            integration_name=VENDOR_NAME,
            score=dbot_score,
            reliability=client.integration_reliability,
        )

        dbot_score_obj.integration_name = VENDOR_NAME

        url_indicator = Common.URL(url=url, dbot_score=dbot_score_obj)
        url_indicator.tags = []

        # Map threat intelligence fields to URL indicator
        # Add basic threat intelligence details
        received = threat_data.get("received")
        if received:
            url_indicator.detection_engines = 1

        class_ = threat_data.get("class")
        if class_:
            url_indicator.malware_family = class_

        type_ = threat_data.get("type")
        if type_:
            url_indicator.threat_types = [
                Common.ThreatTypes(threat_category=type_, threat_category_confidence=str(confidence or ""))
            ]

        # Add extended threat information if available
        extended = threat_data.get("extended", {})
        if extended and isinstance(extended, dict):
            url_indicator.tags.extend([f"{key}: {value}" for key, value in extended.items() if value and isinstance(value, str)])

            notes = extended.get("notes")
            if notes:
                url_indicator.description = notes
                dbot_score_obj.malicious_description = notes

        outputs = {
            "url": url,
            "Threat": threat_data,
        }

        # Create comprehensive readable output
        readable_output = prepare_hr_for_url(url, threat_data, dbot_score_obj)

        # Create indicator timeline
        timeline = None
        if threat_data.get("received"):
            timeline = IndicatorsTimeline(
                indicators=[url],
                category="Threat Intelligence Update",
                message=f"URL was identified with threat level: {threat_level or 'Unknown'}, "
                f"confidence: {confidence or 'Unknown'}%",
            )

        command_result = CommandResults(
            outputs_prefix=OUTPUT_PREFIX["URL"],
            outputs_key_field="url",
            outputs=remove_empty_elements(outputs),
            readable_output=readable_output,
            raw_response={"threat_data": threat_result},
            indicator=url_indicator,
            indicators_timeline=timeline,
        )
        command_results.append(command_result)

    return command_results


def mac_enrich_command(client, args: Dict[str, Any]) -> CommandResults:
    """
    Enriches a MAC address with DHCP lease information.

    Args:
        client: The Infoblox client.
        args: Command arguments from Demisto.

    Returns:
        CommandResults object with MAC address enrichment data
    """
    mac = args.get("mac")
    if not mac:
        raise ValueError(MESSAGES["REQUIRED_ARGUMENT"].format("mac"))
    if not bool(MAC_PATTERN.match(mac)):
        raise ValueError(MESSAGES["INVALID_VALUE"].format(mac, "mac"))

    response = client.mac_enrich(mac)

    if not response or not response.get("results") or len(response.get("results", [])) == 0:
        return CommandResults(readable_output=MESSAGES["NO_INFO_FOUND"].format("DHCP lease", "MAC", mac))

    lease_data = response.get("results")[0]

    clean_lease_data = remove_empty_elements_for_hr(lease_data)
    if "options" in clean_lease_data:
        lease_options = None
        try:
            lease_options_str = clean_lease_data["options"]
            lease_options = json.loads(lease_options_str)
            if lease_options and "Options" in lease_options:
                lease_options = lease_options["Options"]
            clean_lease_data["options"] = lease_options if lease_options else lease_options_str
        except Exception:
            pass
    readable_output = tableToMarkdown(
        f"DHCP Lease Information for MAC: {mac}",
        clean_lease_data,
        headerTransform=header_transformer_for_ip,
        removeNull=True,
        is_auto_json_transform=True,
    )

    # Return results
    return CommandResults(
        outputs_key_field="hardware",
        readable_output=readable_output,
        outputs_prefix="InfobloxCloud.DHCPLease",
        outputs=remove_empty_elements(lease_data),
        raw_response=response,
    )


def command_test_module(client: BloxOneTDClient) -> str:
    params = demisto.params()
    is_fetch = params.get("isFetch", False)
    if is_fetch:
        fetch_incidents(client, params, is_test=True)
    else:
        client.dossier_source_list()
    return "ok"


def fetch_incidents(client: BloxOneTDClient, params: dict, is_test: bool = False):
    """
    Fetches new SOC insights and DNS security events and creates incidents for them.
    :param client: BloxOneTDClient instance.
    :param params: Dictionary of parameters.
    :param is_test: Whether this is a test run.
    :return: None
    """
    max_fetch = arg_to_number(params.get("max_fetch"))
    if max_fetch is None:
        max_fetch = 50
    if max_fetch > 200:  # type: ignore
        if is_test:
            raise ValueError(ERRORS["INVALID_MAX_FETCH"].format(max_fetch))
        max_fetch = 200
        demisto.debug(
            f"The max fetch value is {max_fetch}, which is greater than the maximum allowed value of 200. Setting it to 200."
        )
    elif max_fetch < 1:  # type: ignore
        raise ValueError(ERRORS["INVALID_MAX_FETCH"].format(max_fetch))

    incidents = []
    last_run = demisto.getLastRun() or {}

    # Determine what to fetch based on parameters
    ingestion_type = params.get("ingestion_type", "SOC Insight")

    # Fetch SOC insights if enabled
    if ingestion_type == "SOC Insight":
        insights_incidents, last_run = fetch_soc_insights(client, params, last_run, max_fetch, is_test)
        incidents.extend(insights_incidents)

    # Fetch DNS security events if enabled
    if ingestion_type == "DNS Security Event":
        dns_incidents, last_run = fetch_dns_security_events(client, params, last_run, max_fetch, is_test)
        incidents.extend(dns_incidents)

    if is_test:
        return

    if not incidents:
        demisto.debug("[Infoblox] No incidents found.")
    else:
        demisto.debug(f"[Infoblox] Total {len(incidents)} incidents fetched for {ingestion_type}.")

    # Create incidents
    demisto.incidents(incidents)

    # Save the updated last run data
    demisto.setLastRun(last_run)


def fetch_dns_security_events(
    client: BloxOneTDClient, params: dict, last_run: dict, max_fetch: int, is_test: bool = False
) -> tuple[list, dict]:
    """
    Fetches DNS security events and creates incidents for them.
    :param client: BloxOneTDClient instance.
    :param params: Dictionary of parameters.
    :param last_run: Last run data.
    :param max_fetch: Maximum number of events to fetch.
    :param is_test: Whether this is a test run.
    :return: Tuple of incidents list and next run data.
    """
    incidents = []

    # Get the last fetch time for DNS events
    last_fetch_time = last_run.get("dns_events_last_fetch")

    # If no last fetch time, use first_fetch parameter
    if last_fetch_time:
        last_fetch_time = arg_to_datetime(last_fetch_time).timestamp()  # type: ignore
    else:
        last_fetch_time = arg_to_datetime(  # type: ignore
            params.get("first_fetch", DEFAULT_FIRST_FETCH), "first_fetch"
        ).timestamp()

    # Build API parameters
    api_params: dict[str, Any] = {
        "_limit": max_fetch,
        "t0": int(last_fetch_time),
        "t1": int(arg_to_datetime("now").timestamp()),  # type: ignore
    }

    # Add optional filters
    if params.get("dns_events_queried_name"):
        api_params["qname"] = ",".join(  # Note: API expects 'qname' not 'queried_name'
            item.strip() for item in argToList(params.get("dns_events_queried_name", [])) if item.strip()
        )
    if params.get("dns_events_policy_name"):
        api_params["policy_name"] = ",".join(
            item.strip() for item in argToList(params.get("dns_events_policy_name", [])) if item.strip()
        )
    if params.get("dns_events_threat_level"):
        threat_levels = [item.strip() for item in argToList(params.get("dns_events_threat_level", [])) if item.strip()]
        threat_levels_upper = [item.upper() for item in threat_levels]
        for level, upper_level in zip(threat_levels, threat_levels_upper):
            if upper_level not in THREAT_LEVELS:
                raise ValueError(MESSAGES["INVALID_DNS_EVENT_THREAT_LEVEL"].format(level))
        api_params["threat_level"] = ",".join(threat_levels_upper)
    if params.get("dns_events_threat_class"):
        api_params["threat_class"] = ",".join(
            item.strip() for item in argToList(params.get("dns_events_threat_class", [])) if item.strip()
        )
    if params.get("dns_events_threat_family"):
        api_params["threat_family"] = ",".join(
            item.strip() for item in argToList(params.get("dns_events_threat_family", [])) if item.strip()
        )
    if params.get("dns_events_threat_indicator"):
        api_params["threat_indicator"] = ",".join(
            item.strip() for item in argToList(params.get("dns_events_threat_indicator", [])) if item.strip()
        )
    if params.get("dns_events_policy_action"):
        api_params["policy_action"] = ",".join(
            item.strip() for item in argToList(params.get("dns_events_policy_action", [])) if item.strip()
        )
    if params.get("dns_events_feed_name"):
        api_params["feed_name"] = ",".join(
            item.strip() for item in argToList(params.get("dns_events_feed_name", [])) if item.strip()
        )
    if params.get("dns_events_network"):
        api_params["network"] = ",".join(item.strip() for item in argToList(params.get("dns_events_network", [])) if item.strip())

    # Fetch DNS security events
    response = client.list_dns_security_events(api_params)
    events = response.get("result", []) if isinstance(response, dict) else response  # type: ignore

    demisto.debug(f"[Infoblox DNS Security Events] Fetched {len(events)} events from API.")

    if is_test:
        return [], {}

    if not events:
        demisto.debug("[Infoblox DNS Security Events] No events found.")
        return [], last_run

    latest_event_time = events[0].get("event_time")
    events = events[::-1]
    last_run_ids = last_run.get("dns_events_ids", [])
    new_event_ids = []
    duplicate_event_ids = []

    for event in events:
        event_time = event.get("event_time")
        qname_truncated = event.get("qname", "")[:20]
        event["incident_type"] = "Infoblox Cloud DNS Security Event"
        # Create a composite key with fields separated by '|'
        key_parts = [
            event_time,
            qname_truncated,
            event.get("device", ""),
            event.get("feed_name", ""),
        ]
        composite_key = "|".join([str(part) for part in key_parts if part])
        if composite_key in last_run_ids:
            duplicate_event_ids.append(composite_key)
            continue
        last_run_ids.append(composite_key)
        new_event_ids.append(composite_key)

        # Create incident for each DNS security event
        incident_name = f"Infoblox DNS Security Event - {event.get('tclass', 'Unknown')} : {qname_truncated}"

        incident = {
            "name": incident_name,
            "details": json.dumps(event),
            "rawJSON": json.dumps(event),
            "severity": SEVERITY_MAP.get(event.get("severity", "INFO"), 1),
            "occurred": event_time,
        }
        incidents.append(incident)

    # Update next run data
    demisto.debug(f"[Infoblox DNS Security Events] Setting last_fetch_time to {latest_event_time} and index to 1.")
    last_run["dns_events_last_fetch"] = latest_event_time
    demisto.debug(f"[Infoblox DNS Security Events] Found {len(new_event_ids)} new events with IDs: {', '.join(new_event_ids)}.")
    last_run["dns_events_ids"] = last_run_ids

    if duplicate_event_ids:
        demisto.debug(
            f"[Infoblox DNS Security Events] {len(duplicate_event_ids)} duplicate events were skipped with"
            f"IDs: {', '.join(duplicate_event_ids)}."
        )

    return incidents, last_run


def fetch_soc_insights(
    client: BloxOneTDClient, params: dict, last_run: dict, max_fetch: int, is_test: bool = False
) -> tuple[list, dict]:
    """
    Fetches new SOC insights and creates incidents for them.
    :param client: BloxOneTDClient instance.
    :param params: Dictionary of parameters.
    :param last_run: Last run data.
    :param max_fetch: Maximum number of insights to fetch.
    :param is_test: Whether this is a test run.
    :return: Tuple of incidents list and next run data.
    """
    incidents = []
    last_run_ids = last_run.get("soc_insight_ids", [])

    params = {
        "status": params.get("soc_insight_status"),
        "priority": params.get("soc_insight_priority_level"),
        "threat_type": params.get("soc_insight_threat_type"),
    }

    results = client.soc_insights_list(params)
    insights = results.get("insightList", [])  # type: ignore
    soc_insight_ids = []
    new_insights = []
    new_insight_ids = []
    duplicate_insight_ids = []

    for insight in insights:
        soc_insight_id = insight.get("insightId")
        if not soc_insight_id or soc_insight_id in last_run_ids:
            duplicate_insight_ids.append(soc_insight_id) if soc_insight_id else None
            continue
        insight["incident_link"] = INCIDENT_LINK.format(soc_insight_id)
        new_insights.append(insight)
        last_run_ids.append(soc_insight_id)
        new_insight_ids.append(soc_insight_id)
        soc_insight_ids.append(insight.get("insightId"))
        if len(new_insights) >= max_fetch:  # type: ignore
            break

    if is_test:
        return [], {}

    for insight in new_insights:
        threat_type = insight.get("threatType")
        threat_family = insight.get("tFamily")
        insight["incident_type"] = "Infoblox Cloud SOC Insight"
        incident = {
            "name": f"Infoblox SOC Insight - {threat_type} : {threat_family}",  # noqa: E203
            "details": json.dumps(insight),
            "rawJSON": json.dumps(insight),
            "severity": SEVERITY_MAP.get(insight["priorityText"], 1),
        }
        incidents.append(incident)

    if not insights:
        demisto.debug("[Infoblox SOC Insight] No SOC Insights found.")
        return [], last_run

    # Update next run data
    last_run["soc_insight_ids"] = last_run_ids
    demisto.debug(f"[Infoblox SOC Insight] Found {len(new_insight_ids)} new SOC Insights with IDs: {', '.join(new_insight_ids)}.")

    demisto.debug(
        f"[Infoblox SOC Insight] {len(duplicate_insight_ids)} duplicate SOC Insights were skipped with"
        f"IDs: {', '.join(duplicate_insight_ids)}."
    )

    return incidents, last_run


def remove_duplicate_entries(indicator_list: list[str]) -> list[str]:
    """
    Remove duplicate entries in a list.
    :param indicator_list: List of indicators.
    :return: List of indicators without duplicates.
    """
    result = []
    for item in indicator_list:
        if item.strip() and item.strip() not in result:
            result.append(item.strip())
    return result


def generic_named_list_method(
    client: BloxOneTDClient, args: dict[str, Any], data: dict[str, Any], is_remove: bool = False
) -> CommandResults:
    """
    Generic method for named list operations.
    :param client: BloxOneTDClient instance.
    :param args: Dictionary of arguments.
    :param data: Dictionary of data to update the named list.
    :return: CommandResults instance.
    """
    params = {
        "name": validate_argument(args.get("custom_list_name"), "custom_list_name"),  # type: ignore
        "type": validate_argument(args.get("custom_list_type"), "custom_list_type"),  # type: ignore
    }
    try:
        named_list = client.get_named_list(params)
    except DemistoException as error:
        if client.last_response.text:  # type: ignore
            text = client.last_response.text  # type: ignore
            raise ValueError(f"{error}\n{text}")
        raise ValueError(f"Failed to get named list: {error}")
    named_list_id = validate_key(named_list.get("results"), "id")
    items = data.get("items")
    items = remove_duplicate_entries(items)  # type: ignore
    data["items"] = items
    indicators = ", ".join(items)
    if is_remove:
        try:
            client.remove_named_list_items(named_list_id, data)
            title = f"'{indicators}' indicators removed from the '{args.get('custom_list_name')}' list"
        except Exception as error:
            match = re.search(r"(\d+)\s+Items", str(error))
            if match:
                number = int(match.group(1))
                raise ValueError(f"{number} indicators were not present in the list.")
            raise ValueError(f"Failed to remove indicators from named list: {error}")
    else:
        try:
            client.update_named_list(named_list_id, data)
            title = f"'{indicators}' indicators added to the '{args.get('custom_list_name')}' list"
        except Exception as error:
            raise ValueError(f"Failed to add indicators to named list: {error}")
    data = client.get_named_list(params)
    named_list = validate_key(data, "results")
    return CommandResults(
        readable_output=prepare_hr_for_named_list(named_list, title),
        outputs_prefix="InfobloxCloud.CustomList",
        outputs_key_field="id",
        outputs=remove_empty_elements(named_list),
        raw_response=data,
    )


def validate_ip(ip: str):
    """
    Validate an IP address or CIDR.
    :param ip: IP address or CIDR.
    :return: Validated IP address or CIDR.
    """
    ip = validate_argument(ip, "ip")
    for fn in [ipaddress.ip_address, lambda v: ipaddress.ip_network(v, strict=False)]:
        try:
            fn(ip)
            return ip
        except ValueError:
            continue
    raise ValueError(f"Invalid IP or CIDR: {ip}")


def validate_ip_list(ip_list: str) -> list[str]:
    """
    Validate a list of IP addresses or CIDRs.
    :param ip_list: List of IP addresses or CIDRs.
    :return: Validated list of IP addresses or CIDRs.
    """
    ip_list = argToList(ip_list, ",")
    ip_list = [ip.strip() for ip in ip_list if ip.strip()]
    for ip in ip_list:
        validate_ip(ip)
    ip_list = validate_argument(ip_list, "ip")  # type: ignore
    return ip_list  # type: ignore


def validate_domain(domain: str):
    """
    Validate a domain.
    :param domain: Domain.
    :return: Validated domains.
    """
    domains = argToList(domain, ",")
    domains = [domain.strip() for domain in domains if domain.strip()]
    domains = validate_argument(domains, "domain")  # type: ignore
    return domains


def validate_datetime(time_string: str, name: str) -> str | None:
    """
    Validate a datetime.
    :param time_string: Time string.
    :param name: Name of the time string.
    :return: Validated datetime.
    """
    time_obj = arg_to_datetime(time_string, name)
    if time_obj:
        return time_obj.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3]  # type: ignore
    return None


def block_ip_command(client: BloxOneTDClient, args: dict[str, Any]) -> CommandResults:
    """
    Block an IP in a custom list.
    :param client: BloxOneTDClient instance.
    :param args: Dictionary of arguments.
    :return: CommandResults instance.
    """
    ip_list = validate_ip_list(args.get("ip"))  # type: ignore
    data = {"items": ip_list}
    return generic_named_list_method(client, args, data)


def unblock_ip_command(client: BloxOneTDClient, args: dict[str, Any]) -> CommandResults:
    """
    Unblock an IP from a custom list.
    :param client: BloxOneTDClient instance.
    :param args: Dictionary of arguments.
    :return: CommandResults instance.
    """
    ip_list = validate_ip_list(args.get("ip"))  # type: ignore
    data = {"items": ip_list}
    return generic_named_list_method(client, args, data)


def block_domain_command(client: BloxOneTDClient, args: dict[str, Any]) -> CommandResults:
    """
    Block an domain in a custom list.
    :param client: BloxOneTDClient instance.
    :param args: Dictionary of arguments.
    :return: CommandResults instance.
    """
    domain = validate_domain(args.get("domain"))  # type: ignore
    data = {"items": domain}
    return generic_named_list_method(client, args, data)


def unblock_domain_command(client: BloxOneTDClient, args: dict[str, Any]) -> CommandResults:
    """
    Unblock an domain from a custom list.
    :param client: BloxOneTDClient instance.
    :param args: Dictionary of arguments.
    :return: CommandResults instance.
    """
    domain = validate_domain(args.get("domain"))  # type: ignore
    data = {"items": domain}
    return generic_named_list_method(client, args, data)


def infobloxcloud_customlist_indicator_remove(client: BloxOneTDClient, args: dict[str, Any]) -> CommandResults:
    """
    Unblock an IP from a custom list.
    :param client: BloxOneTDClient instance.
    :param args: Dictionary of arguments.
    :return: CommandResults instance.
    """
    indicators = argToList(args.get("indicators"), ",")
    indicators = remove_duplicate_entries(indicators)
    indicators = validate_argument(indicators, "indicators")
    data = {"items": indicators}
    return generic_named_list_method(client, args, data, is_remove=True)


def list_soc_insights_command(client: BloxOneTDClient, args: dict[str, Any]) -> CommandResults:
    """
    List SOC insights.
    :param client: BloxOneTDClient instance.
    :param args: Dictionary of arguments.
    :return: CommandResults instance.
    """
    params = {
        "status": args.get("status"),
        "priority": args.get("priority"),
        "threat_type": args.get("threat_type"),
    }
    insights = client.soc_insights_list(params)
    insights = insights.get("insightList", [])  # type: ignore
    if not insights:
        return CommandResults(
            readable_output="No SOC Insights found.",
            raw_response=insights,
        )
    return CommandResults(
        readable_output=prepare_hr_for_soc_insights(insights),
        outputs_prefix="InfobloxCloud.SOCInsight",
        outputs_key_field="insightId",
        outputs=remove_empty_elements(insights),
        raw_response=insights,
    )


def list_soc_insight_indicators_command(client: BloxOneTDClient, args: dict[str, Any]) -> CommandResults:
    """
    List SOC insight indicators.
    :param client: BloxOneTDClient instance.
    :param args: Dictionary of arguments.
    :return: CommandResults instance.
    """
    soc_insight_id = validate_argument(args.get("soc_insight_id"), "soc_insight_id")
    params = {
        "confidence": args.get("confidence"),
        "indicator": args.get("indicator"),
        "action": args.get("action"),
        "actor": args.get("actor"),
        "limit": arg_to_number(args.get("limit", 50)),
        "from": validate_datetime(args.get("start_time"), "start_time"),  # type: ignore
        "to": validate_datetime(args.get("end_time"), "end_time"),  # type: ignore
    }
    params = remove_empty_elements(params)
    indicators = client.soc_insight_indicators_list(params, soc_insight_id)
    indicators = indicators.get("indicators", [])  # type: ignore
    if not indicators:
        return CommandResults(
            readable_output="No indicators found.",
            raw_response=indicators,
        )
    return CommandResults(
        readable_output=prepare_hr_for_soc_insight_indicators(indicators, soc_insight_id),
        outputs_prefix="InfobloxCloud.Indicator",
        outputs_key_field="indicatorId",
        outputs=remove_empty_elements(indicators),
        raw_response=indicators,
    )


def list_soc_insight_events_command(client: BloxOneTDClient, args: dict[str, Any]) -> CommandResults:
    """
    List SOC insight events.
    :param client: BloxOneTDClient instance.
    :param args: Dictionary of arguments.
    :return: CommandResults instance.
    """
    soc_insight_id = validate_argument(args.get("soc_insight_id"), "soc_insight_id")
    device_ip = args.get("device_ip")
    if device_ip and not is_ip_valid(device_ip, accept_v6_ips=True):
        raise ValueError(MESSAGES["INVALID_VALUE"].format(device_ip, "device_ip"))
    params = {
        "threat_level": args.get("threat_level"),
        "confidence_level": args.get("confidence_level"),
        "query": args.get("query"),
        "query_type": args.get("query_type"),
        "limit": arg_to_number(args.get("limit", 50)),
        "from": validate_datetime(args.get("start_time"), "start_time"),  # type: ignore
        "to": validate_datetime(args.get("end_time"), "end_time"),  # type: ignore
        "source": args.get("source"),
        "device_ip": device_ip,
        "indicator": args.get("indicator"),
    }
    params = remove_empty_elements(params)
    events = client.soc_insight_events_list(params, soc_insight_id)
    events = events.get("events", [])  # type: ignore
    if not events:
        return CommandResults(
            readable_output="No events found.",
            raw_response=events,
        )
    return CommandResults(
        readable_output=prepare_hr_for_soc_insight_events(events, soc_insight_id),
        outputs_prefix="InfobloxCloud.Event",
        outputs_key_field="eventId",
        outputs=remove_empty_elements(events),
        raw_response=events,
    )


def list_soc_insight_assets_command(client: BloxOneTDClient, args: dict[str, Any]) -> CommandResults:
    """
    List SOC insight assets.
    :param client: BloxOneTDClient instance.
    :param args: Dictionary of arguments.
    :return: CommandResults instance.
    """
    qip = args.get("qip")
    cmac = args.get("cmac")
    if qip and not is_ip_valid(qip, accept_v6_ips=True):
        raise ValueError(MESSAGES["INVALID_VALUE"].format(qip, "qip"))
    if cmac and not bool(MAC_PATTERN.match(cmac)):
        raise ValueError(MESSAGES["INVALID_VALUE"].format(cmac, "cmac"))
    soc_insight_id = validate_argument(args.get("soc_insight_id"), "soc_insight_id")
    params = {
        "qip": qip,
        "cmac": cmac,
        "os_version": args.get("os_version"),
        "user": args.get("user"),
        "limit": arg_to_number(args.get("limit", 50)),
        "from": validate_datetime(args.get("start_time"), "start_time"),  # type: ignore
        "to": validate_datetime(args.get("end_time"), "end_time"),  # type: ignore
    }
    params = remove_empty_elements(params)
    assets = client.soc_insight_assets_list(params, soc_insight_id)
    assets = assets.get("assets", [])  # type: ignore
    if not assets:
        return CommandResults(
            readable_output="No assets found.",
            raw_response=assets,
        )
    return CommandResults(
        readable_output=prepare_hr_for_soc_insight_assets(assets, soc_insight_id),
        outputs_prefix="InfobloxCloud.Asset",
        outputs_key_field="assetId",
        outputs=remove_empty_elements(assets),
        raw_response=assets,
    )


def list_soc_insight_comments_command(client: BloxOneTDClient, args: dict[str, Any]) -> CommandResults:
    """
    List SOC insight comments.
    :param client: BloxOneTDClient instance.
    :param args: Dictionary of arguments.
    :return: CommandResults instance.
    """
    soc_insight_id = validate_argument(args.get("soc_insight_id"), "soc_insight_id")
    limit = arg_to_number(args.get("limit", 50))
    if limit < 0:  # type: ignore
        raise ValueError("Limit should not be less than 0.")
    params = {
        "from": validate_datetime(args.get("start_time"), "start_time"),  # type: ignore
        "to": validate_datetime(args.get("end_time"), "end_time"),  # type: ignore
    }
    params = remove_empty_elements(params)
    comments = client.soc_insight_comments_list(params, soc_insight_id)
    comments = comments.get("comments", [])  # type: ignore
    if not comments:
        return CommandResults(
            readable_output="No comments found.",
            raw_response=comments,
        )
    if limit != 0:
        comments = comments[:limit]
    return CommandResults(
        readable_output=prepare_hr_for_soc_insight_comments(comments, soc_insight_id),
        outputs_prefix="InfobloxCloud.Comment",
        outputs_key_field="commentId",
        outputs=remove_empty_elements(comments),
        raw_response=comments,
    )


def main():
    params = demisto.params()
    client = BloxOneTDClient(
        api_key=params["credentials"]["password"],
        verify=not argToBoolean(params.get("insecure", False)),
        proxy=argToBoolean(params.get("proxy", False)),
    )
    commands_with_args = {
        "bloxone-td-dossier-lookup-get": dossier_lookup_get_command,
        "bloxone-td-lookalike-domain-list": lookalike_domain_list_command,
    }

    commands_without_args = {
        "test-module": command_test_module,
        "bloxone-td-dossier-source-list": dossier_source_list_command,
    }

    new_commands_with_args = {
        "infobloxcloud-block-ip": block_ip_command,
        "infobloxcloud-unblock-ip": unblock_ip_command,
        "infobloxcloud-block-domain": block_domain_command,
        "infobloxcloud-unblock-domain": unblock_domain_command,
        "infobloxcloud-customlist-indicator-remove": infobloxcloud_customlist_indicator_remove,
        "ip": ip_command,
        "domain": domain_command,
        "url": url_command,
        "infobloxcloud-mac-enrich": mac_enrich_command,
        "infobloxcloud-soc-insight-list": list_soc_insights_command,
        "infobloxcloud-soc-insight-indicator-list": list_soc_insight_indicators_command,
        "infobloxcloud-soc-insight-event-list": list_soc_insight_events_command,
        "infobloxcloud-soc-insight-asset-list": list_soc_insight_assets_command,
        "infobloxcloud-soc-insight-comment-list": list_soc_insight_comments_command,
    }

    command = demisto.command()
    demisto.debug(f"Command being called is {command}")
    try:
        if command in commands_without_args:
            results = commands_without_args[command](client)
            return_results(results)
        elif command in commands_with_args:
            args = demisto.args()
            results = commands_with_args[command](client, args)
            return_results(results)
        elif command in new_commands_with_args:
            command_args = trim_args(demisto.args())
            remove_nulls_from_dictionary(command_args)
            results = new_commands_with_args[command](client, command_args)
            return_results(results)
        elif command == "fetch-incidents":
            fetch_incidents(client, params)
        else:
            raise NotImplementedError(f"command {command} is not implemented.")
    except Exception as e:
        auth_error = isinstance(e, DemistoException) and e.res is not None and e.res.status_code == 401  # pylint: disable=E1101
        if auth_error:
            error_msg = "authentication error"
        else:
            error_msg = f"an error occurred while executing command {command}\nerror: {e}"

        return_error(error_msg, e)


if __name__ in ("__main__", "builtins"):
    main()
