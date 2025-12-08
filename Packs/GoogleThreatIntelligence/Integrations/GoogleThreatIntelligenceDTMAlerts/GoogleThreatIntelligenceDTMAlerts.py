import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

"""
An integration module for the Google Threat Intelligence DTM Alerts API.
API Documentation:
    https://gtidocs.virustotal.com/reference/get-alerts
"""

from collections.abc import Callable

COMMAND_PREFIX = "gti"
BASE_URL = "https://www.virustotal.com/api/v3"
DTM_ALERT_INCIDENT_LINK = "https://advantage.mandiant.com/dtm/alerts/{}"
DTM_ALERT_INCIDENT_TYPE = "dtm_alert"
INTEGRATION_TOOL = "CortexGTI"
OK_CODES = (200, 401)
STATUS_CODE_TO_RETRY = [429, *(status_code for status_code in requests.status_codes._codes if status_code >= 500)]  # type: ignore
MAX_RETRIES = 4
BACKOFF_FACTOR = 7.5
MAX_FETCH = 25
DEFAULT_MAX_FETCH = 25
DEFAULT_PAGE_SIZE = 10
DEFAULT_FETCH_TIME = "1 days"
DEFAULT_SORT_VALUE = "Created At"
DEFAULT_FETCH_SORT_ORDER = "Asc"
DEFAULT_SORT_ORDER = "Desc"
DEFAULT_BOOL_VALUE = True
DATE_TIME_FORMAT = "%Y-%m-%dT%H:%M:%S.%fZ"
ALERTS_SEVERITY_LIST = ["low", "medium", "high"]
ALERTS_SEVERITY_HUMAN_READABLE = ["Low", "Medium", "High"]
ALERTS_ORDER_HUMAN_READABLE = ["Asc", "Desc"]
ALERTS_SORT_HUMAN_READABLE = ["Created At", "Updated At", "ID", "Monitor ID"]
ALERTS_ORDER_LIST = ["asc", "desc"]
ALERTS_ORDER_HR_LIST = ["Asc", "Desc"]
ALERTS_SORT_LIST = ["created_at", "updated_at", "id", "monitor_id"]
ALERTS_SORT_HR_LIST = ["Created At", "Updated At", "ID", "Monitor ID"]
MIRROR_DIRECTION = {"Outgoing": "Out"}
DTM_ALERT_INCIDENT_STATUS_MAPPING = {
    1: "in_progress",  # incident status: active
    2: "closed",  # incident status: done
}
ALERTS_STATUS_LIST = [
    "new",
    "read",
    "in_progress",
    "escalated",
    "closed",
    "no_action_required",
    "duplicate",
    "not_relevant",
    "tracked_external",
]
ALERTS_STATUS_HUMAN_READABLE = [
    "New",
    "Read",
    "In Progress",
    "Escalated",
    "Closed",
    "No Action Required",
    "Duplicate",
    "Not Relevant",
    "Tracked External",
]
ALERT_STATUS_HR_MAPPING = {
    "new": "New",
    "read": "Read",
    "in_progress": "In Progress",
    "escalated": "Escalated",
    "closed": "Closed",
    "no_action_required": "No Action Required",
    "duplicate": "Duplicate",
    "not_relevant": "Not Relevant",
    "tracked_external": "Tracked External",
}
ALERTS_ALERT_TYPE_LIST = [
    "Compromised Credentials",
    "Domain Discovery",
    "Forum Post",
    "Message",
    "Paste",
    "Shop Listing",
    "Tweet",
    "Web Content",
]
ALERT_TYPE_TO_INCIDENT_SEVERITY = {
    "low": 1,
    "medium": 2,
    "high": 3,
}
OUTPUT_PREFIX = {"ALERT_LIST": "GoogleThreatIntelligenceDTMAlerts.Alerts"}
MESSAGES = {
    "NO_RECORDS_FOUND": "No {} were found for the given argument(s).",
    "NO_RECORD_FOUND": "No {} was found for the given argument(s).",
    "REQUIRED_ARGUMENT": "Missing argument {}.",
}
ERROR_MESSAGES = {
    "INVALID_MAX_FETCH": "'{}' is invalid 'max_fetch' value. Max fetch for DTM Alerts should be between 1 and 25.",
    "INVALID_PAGE_SIZE": "'{}' is an invalid value for 'page_size'. Value must be between 1 and 25.",
    "INVALID_MSCORE_GTE": "'{}' is an invalid value for 'mscore_gte'. Value must be between 0 and 100.",
    "INVALID_OBJECT": "Failed to parse {} object from response: {}",
    "UNAUTHORIZED_REQUEST": "{} Unauthorized request: Invalid API key provided {}.",
    "INVALID_DTM_ALERT_TRUNCATE": "'{}' is Invalid 'truncate' value. Value must be a non-negative integer.",
    "INVALID_ARGUMENT": "'{}' is an invalid value for '{}'. Value must be in {}.",
}
ENDPOINTS = {
    "alert_list": "dtm/alerts",
    "alert_get": "dtm/alerts/{}",
    "alert_update": "dtm/alerts/{}",
    "alert_stat": "dtm/alerts/stats",
}


class Client(BaseClient):
    """Client for Google Threat Intelligence DTM Alerts API."""

    def __init__(self, verify_certificate: bool, proxy: bool, api_key: str):
        super().__init__(
            BASE_URL,
            verify=verify_certificate,
            proxy=proxy,
            headers={
                "x-apikey": api_key,
                "x-tool": INTEGRATION_TOOL,
                "Accept": "application/json",
                "Content-Type": "application/json",
            },
        )

    def http_request(
        self,
        method: str,
        url_suffix: str = "",
        params: Dict[str, Any] | None = None,
        data: Dict[str, Any] | None = None,
        json_data: Dict[str, Any] | None = None,
        response_type: str = "response",
        **kwargs,
    ):
        """
        Makes an HTTP request to the server.

        Args:
            method (str): The HTTP method (e.g., GET, POST, PUT, DELETE).
            url_suffix (str): The URL suffix to be appended to the base URL. Defaults to an empty string.
            params (dict): Query parameters to be appended to the URL. Defaults to None.
            data (object): Data to be sent in the request body. Defaults to None.
            json_data (dict): JSON data to be sent in the request body. Defaults to None.
            response_type (str): The expected response type. Defaults to None.
            **kwargs: Additional keyword arguments.

        Returns:
            object: The response object or None.
        """
        # Set the headers for the request, including the User-Agent and Authorization.
        headers = self._headers

        log_header = {**headers, "x-apikey": "***********"}  # type: ignore
        demisto.debug(
            f"Making API request at {method} {url_suffix} with headers:{log_header}, "
            f"params:{params} and body:{data or json_data}"
        )

        # Make the HTTP request using the _http_request method, passing the necessary parameters.
        res = self._http_request(
            method=method,
            url_suffix=url_suffix,
            headers=headers,
            data=data,
            json_data=json_data,
            params=params,
            retries=MAX_RETRIES,
            status_list_to_retry=STATUS_CODE_TO_RETRY,
            ok_codes=OK_CODES,
            backoff_factor=BACKOFF_FACTOR,
            resp_type="response",
            raise_on_status=True,
            **kwargs,
        )

        if res.status_code in [401]:
            try:
                err_msg = ERROR_MESSAGES["UNAUTHORIZED_REQUEST"].format(res.status_code, str(res.json()))
            except ValueError:
                err_msg = ERROR_MESSAGES["UNAUTHORIZED_REQUEST"].format(res.status_code, str(res))
            raise DemistoException(err_msg)

        # Parse successful response based on requested type
        try:
            if response_type == "json":
                return res.json()
            elif response_type == "response":
                return res
            else:
                return res  # Default to response object
        except ValueError as e:
            raise DemistoException(
                ERROR_MESSAGES["INVALID_OBJECT"].format(response_type, res.content),
                e,
                res,
            )

    def get_alert_list(self, query_params: dict, response_type: str):
        """
        See Also:
            https://gtidocs.virustotal.com/reference/get-alerts
        """

        return self.http_request(
            method="GET", url_suffix=ENDPOINTS["alert_list"], params=query_params, response_type=response_type
        )

    def get_alert(self, alert_id: str, query_params: dict) -> dict:
        """
        See Also:
            https://gtidocs.virustotal.com/reference/get-alerts-id
        """
        return self.http_request(
            method="GET", url_suffix=ENDPOINTS["alert_get"].format(alert_id), params=query_params, response_type="json"
        )

    def patch_alert_update(self, alert_id: str, payload: Dict[str, Any]) -> dict:
        """
        See Also:
            https://gtidocs.virustotal.com/reference/patch-alerts-id
        """
        return self.http_request(
            method="PATCH", url_suffix=ENDPOINTS["alert_update"].format(alert_id), json_data=payload, response_type="json"
        )

    def get_alert_stat(self):
        """
        get dtm alert statistics.
        """
        return self.http_request(method="GET", url_suffix=ENDPOINTS["alert_stat"], response_type="json")


# DTM Alert Helper functions
def validate_argument(value, name) -> Any:
    """
    Check if empty string is passed as value for argument and raise appropriate ValueError.

    Args:
        value: Value of the argument.
        name: Name of the argument.

    Returns:
        str: Value of the argument.

    Raises:
        ValueError: If the value is empty string.
    """
    if not value:
        raise ValueError(MESSAGES["REQUIRED_ARGUMENT"].format(name))
    return value


def trim_spaces_from_args(args):
    """
    Trim spaces from values of the args dict.

    Args:
        args: Dict to trim spaces from

    Returns:
        dict: Dict with trimmed spaces from values
    """
    for key, val in args.items():
        if isinstance(val, str):
            args[key] = val.strip()

    return args


def remove_empty_elements_for_fetch(d: Any) -> Any:
    """
    Recursively remove empty lists, empty dicts, or None elements from a dictionary or list.
    :param d: Input dictionary or list.
    :return: Dictionary or list with all empty lists, and empty dictionaries removed.
    """
    if not isinstance(d, dict | list):
        return d
    elif isinstance(d, list):
        return [v for v in (remove_empty_elements_for_fetch(v) for v in d) if not check_empty(v)]
    return {k: v for k, v in ((k, remove_empty_elements_for_fetch(v)) for k, v in d.items()) if not check_empty(v)}


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


def check_empty(x: Any) -> bool:
    """
    Check if input is empty (None, empty dict, empty list, or empty string).

    :param x: Input to check.
    :type x: Any
    :return: True if x is empty, False otherwise.
    :rtype: bool
    """
    return x is None or x == {} or x == [] or x == ""


def get_gti_dtm_alert_get_params(args: dict) -> dict:
    """
    Helper function to get query parameters for DTM alert get API.
    Args:
        args: Dictionary of arguments.

    Returns:
        dict: Dictionary of query parameters.
    """
    refs = argToBoolean(args.get("include_more_details", DEFAULT_BOOL_VALUE))
    sanitize = arg_to_bool_or_none(args.get("sanitize"))
    truncate = arg_to_number(args.get("truncate"), arg_name="truncate")

    if truncate and truncate < 0:
        raise ValueError(ERROR_MESSAGES["INVALID_DTM_ALERT_TRUNCATE"].format(truncate))

    params = {
        "sanitize": sanitize,
        "refs": refs,
        "truncate": truncate,
    }

    remove_nulls_from_dictionary(params)
    return params


def build_gti_dtm_alert_get_output(alert_data: dict):
    """Build human-readable output and context for DTM alert.

    Args:
        alert_data: Alert data from DTM alert API.

    Returns:
        tuple: (context, readable_output)
    """
    hr_content = []
    context = []
    context.append(remove_empty_elements(alert_data))
    alert_status = alert_data.get("status", "")
    hr_content.append(
        {
            "Alert ID": alert_data.get("id", ""),
            "Title": alert_data.get("title", ""),
            "Alert Summary": alert_data.get("ai_doc_summary", ""),
            "Alert Type": alert_data.get("alert_type", ""),
            "Severity": alert_data.get("severity", "").capitalize(),
            "Status": ALERT_STATUS_HR_MAPPING.get(alert_status, alert_status.capitalize()),
            "Monitor ID": alert_data.get("monitor_id", ""),
            "Indicator Score": alert_data.get("indicator_mscore", ""),
            "Created At": alert_data.get("created_at", ""),
            "Updated At": alert_data.get("updated_at", ""),
            "Tags": alert_data.get("tags", ""),
        }
    )

    headers = [
        "Alert ID",
        "Title",
        "Alert Summary",
        "Alert Type",
        "Severity",
        "Status",
        "Monitor ID",
        "Indicator Score",
        "Created At",
        "Updated At",
        "Tags",
    ]

    # Create human-readable output using tableToMarkdown
    readable_output = tableToMarkdown("DTM Alert", hr_content, headers=headers, removeNull=True)

    return context, readable_output


def validate_alert_status_update_args(args: dict) -> tuple:
    """
    Helper function to validate update DTM alert status arguments.
    Args:
        args: Dictionary of arguments.
    Returns:
        tuple: (alert_id, status)
    """
    alert_id = validate_argument(args.get("alert_id"), "alert_id")
    status = validate_argument(args.get("status"), "status")
    status = status.lower().replace(" ", "_")

    if status not in ALERTS_STATUS_LIST:
        raise ValueError(ERROR_MESSAGES["INVALID_ARGUMENT"].format(status, "status", ALERTS_STATUS_HUMAN_READABLE))

    return alert_id, status


def build_alert_status_update_output(alert_data: dict):
    """Build human-readable output and context for DTM alert status update.

    Args:
        alert_data: Alert data from DTM alert API.

    Returns:
        tuple: (context, readable_output)
    """
    context = []
    context.append(remove_empty_elements(alert_data))

    hr_content = []
    alert_status = alert_data.get("status", "")
    hr_content.append(
        {
            "Alert ID": alert_data.get("id", ""),
            "Status": ALERT_STATUS_HR_MAPPING.get(alert_status, alert_status.capitalize()),
        }
    )

    headers = ["Alert ID", "Status"]

    # Create human-readable output using tableToMarkdown
    readable_output = tableToMarkdown("Alert Status Updated Successfully.", hr_content, headers=headers, removeNull=True)

    return context, readable_output


def validate_dtm_alert_list_args(
    size: int | None = None,
    order: str | None = None,
    sort: str | None = None,
    alert_type: list[str] | None = None,
    status: list[str] | None = None,
    severity: list[str] | None = None,
    mscore_gte: int | None = None,
    fetch: bool = False,
):
    """
    Validate DTM Alert list arguments.
    Args:
        size: Size of the page.
        order: Order of the alerts.
        sort: Sort of the alerts.
        alert_type: Type of the alerts.
        status: Status of the alerts.
        severity: Severity of the alerts.
        mscore_gte: Minimum score of the alerts.
    Raises:
        ValueError: If the arguments are invalid.
    """
    if size is not None and (size > MAX_FETCH or size < 1):
        if fetch:
            raise ValueError(ERROR_MESSAGES["INVALID_MAX_FETCH"].format(size))
        else:
            raise ValueError(ERROR_MESSAGES["INVALID_PAGE_SIZE"].format(size, MAX_FETCH))

    if order and order.lower() not in ALERTS_ORDER_LIST:
        raise ValueError(ERROR_MESSAGES["INVALID_ARGUMENT"].format(order, "order", ALERTS_ORDER_HUMAN_READABLE))

    if sort and sort.lower().replace(" ", "_") not in ALERTS_SORT_LIST:
        raise ValueError(ERROR_MESSAGES["INVALID_ARGUMENT"].format(sort, "sort", ALERTS_SORT_HUMAN_READABLE))

    if alert_type:
        for alert in alert_type:
            if alert not in ALERTS_ALERT_TYPE_LIST:
                raise ValueError(ERROR_MESSAGES["INVALID_ARGUMENT"].format(alert, "type", ALERTS_ALERT_TYPE_LIST))

    if status:
        for stat in status:
            if stat.lower().replace(" ", "_") not in ALERTS_STATUS_LIST:
                raise ValueError(ERROR_MESSAGES["INVALID_ARGUMENT"].format(stat, "status", ALERTS_STATUS_HUMAN_READABLE))

    if severity:
        for sev in severity:
            if sev.lower() not in ALERTS_SEVERITY_LIST:
                raise ValueError(ERROR_MESSAGES["INVALID_ARGUMENT"].format(sev, "severity", ALERTS_SEVERITY_HUMAN_READABLE))

    if mscore_gte and (mscore_gte < 0 or mscore_gte > 100):
        raise ValueError(ERROR_MESSAGES["INVALID_MSCORE_GTE"].format(mscore_gte))


def get_dtm_alert_list_query_params(
    refs: bool,
    monitor_name: bool,
    order: str | None = None,
    sort: str | None = None,
    size: int | None = None,
    start_time: datetime | None = None,
    end_time: datetime | None = None,
    monitor_id: list[str] | None = None,
    alert_type: list[str] | None = None,
    tags: list[str] | None = None,
    status: list[str] | None = None,
    severity: list[str] | None = None,
    mscore_gte: int | None = None,
    has_analysis: bool | None = None,
    search: str | None = None,
    match_value: list[str] | None = None,
):
    """Helper function to get query parameters for DTM alerts API

    Args:
        order(str): Order of the alerts.
        sort(str): Sort of the alerts.
        size(int): Size of the alerts.
        start_time(str): Start time of the alerts.
        end_time(str): End time of the alerts.
        monitor_id(list[str]): Monitor ID of the alerts.
        alert_type(list[str]): Alert type of the alerts.
        tags(list[str]): Tags of the alerts.
        status(list[str]): Status of the alerts.
        severity(list[str]): Severity of the alerts.
        mscore_gte(int): Minimum score of the alerts.
        refs(str): References of the alerts.
        monitor_name(str): Monitor name of the alerts.
        has_analysis(str): Has analysis of the alerts.
        search(str): Search of the alerts.
        match_value(list[str]): Match value of the alerts.

    Returns:
        dict: Dictionary of query parameters
    """
    if status:
        status = [stat.lower().replace(" ", "_") for stat in status]
    if severity:
        severity = [sev.lower() for sev in severity]
    if order:
        order = order.lower()
    if sort:
        sort = sort.lower().replace(" ", "_")

    params = {
        "order": order,
        "sort": sort,
        "size": size,
        "since": start_time,
        "until": end_time,
        "monitor_id": monitor_id,
        "alert_type": alert_type,
        "tags": tags,
        "status": status,
        "severity": severity,
        "mscore_gte": mscore_gte,
        "refs": refs,
        "monitor_name": monitor_name,
        "has_analysis": has_analysis,
        "search": search,
        "match_value": match_value,
    }

    remove_nulls_from_dictionary(params)
    return params


def build_dtm_alert_list_output(alerts_data: list, monitor_name: bool) -> tuple:
    """Build human-readable output and context for DTM alerts.
    Args:
        alerts_data(list): List of alerts from DTM alerts API.
        monitor_name(bool): Boolean to include monitor name in human-readable output.

    Returns:
        tuple: (context, readable_output)
    """
    hr_content = []
    context = []

    for alert in alerts_data:
        alert = remove_empty_elements(alert)
        context.append(alert)
        alert_status = alert.get("status", "")
        # Extract key fields for human-readable table matching your structure
        hr_content.append(
            {
                "Alert ID": alert.get("id", ""),
                "Title": alert.get("title", ""),
                "Alert Summary": alert.get("ai_doc_summary", ""),
                "Alert Type": alert.get("alert_type", ""),
                "Severity": alert.get("severity", "").capitalize(),
                "Status": ALERT_STATUS_HR_MAPPING.get(alert_status, alert_status.capitalize() if alert_status else ""),
                "Monitor ID": alert.get("monitor_id", ""),
                "Monitor Name": alert.get("monitor_name", "") if monitor_name else "",
                "Indicator Score": alert.get("indicator_mscore", ""),
                "Created At": alert.get("created_at", ""),
                "Updated At": alert.get("updated_at", ""),
                "Tags": alert.get("tags", ""),
            }
        )

    headers = [
        "Alert ID",
        "Title",
        "Alert Summary",
        "Alert Type",
        "Severity",
        "Status",
        "Monitor ID",
        "Monitor Name",
        "Indicator Score",
        "Created At",
        "Updated At",
        "Tags",
    ]

    # Create human-readable output using tableToMarkdown
    readable_output = tableToMarkdown("DTM Alerts", hr_content, headers=headers, removeNull=True)

    return context, readable_output


def get_mirroring():
    """
    Get the mirroring configuration parameters from the Demisto integration parameters.

    Returns:
        dict: A dictionary containing the mirroring configuration parameters.
    """
    params = demisto.params()
    mirror_direction = params.get("mirror_direction", "None").strip()
    return {"mirror_direction": MIRROR_DIRECTION.get(mirror_direction), "mirror_instance": demisto.integrationInstance()}


def extract_tags_from_dtm_stats(client: Client):
    """
    Extract tags from the dtm alerts statistics.
    """
    response = client.get_alert_stat()
    all_tags = response.get("tag", [])
    tags_list = {}
    for tag in all_tags:
        alert_tag = tag.get("tag", "")
        if alert_tag:
            tags_list[alert_tag.lower()] = alert_tag
    return tags_list


# DTM Alert command functions
def test_module(client: Client) -> str:
    """
    Test module for Google Threat Intelligence DTM Alerts.
    Args:
        client: Client object.
    Returns:
        str: "ok" if connection with Google Threat Intelligence is successful.
    """
    params = demisto.params()
    is_fetch = params.get("isFetch", False)
    if is_fetch:
        fetch_incidents(client, {}, params, is_test=True)
    else:
        query_params = {"size": 1}
        client.get_alert_list(query_params, "json")

    # return ok is connection with Google Threat Intelligence is successful.
    return "ok"


def gti_dtm_alert_get_command(client: Client, args: dict) -> CommandResults:
    """
    Get DTM alert for the specified alert ID.

    Args:
        client: Client object to use.
        args: arguments obtained from demisto.args().

    Returns:
        CommandResult object.
    """
    alert_id = validate_argument(args.get("alert_id"), "alert_id")
    query_params = get_gti_dtm_alert_get_params(args)
    raw_response = client.get_alert(alert_id, query_params)

    if not raw_response:
        return CommandResults(readable_output=MESSAGES["NO_RECORD_FOUND"].format("DTM Alert"))

    context, hr = build_gti_dtm_alert_get_output(raw_response)

    return CommandResults(
        outputs_prefix=OUTPUT_PREFIX["ALERT_LIST"],
        outputs_key_field="id",
        outputs=context,
        raw_response=raw_response,
        readable_output=hr,
    )


def gti_dtm_alert_list_command(client: Client, args: dict) -> CommandResults:
    """
    List DTM alerts for the specified filter parameters.

    Args:
        client(Client): Client object to use.
        args(dict): arguments obtained from demisto.args().

    Returns:
        CommandResults: CommandResult object
    """
    size = arg_to_number(args.get("page_size", DEFAULT_PAGE_SIZE), arg_name="page_size")
    order = args.get("order", DEFAULT_SORT_ORDER)
    sort = args.get("sort", DEFAULT_SORT_VALUE)
    start_time = arg_to_datetime(args.get("start_time"))
    end_time = arg_to_datetime(args.get("end_time"))
    monitor_id = argToList(args.get("monitor_id"))
    alert_type = argToList(args.get("alert_type"))
    tags = argToList(args.get("tags"))
    status = argToList(args.get("status"))
    severity = argToList(args.get("severity"))
    mscore_gte = arg_to_number(args.get("mscore_gte"), arg_name="mscore_gte")
    refs = argToBoolean(args.get("include_more_details", DEFAULT_BOOL_VALUE))
    monitor_name = argToBoolean(args.get("include_monitor_name", "No"))
    has_analysis = arg_to_bool_or_none(args.get("has_analysis"))
    search = args.get("search")
    match_value = argToList(args.get("match_value"))

    validate_dtm_alert_list_args(
        size=size,
        order=order,
        sort=sort,
        alert_type=alert_type,
        status=status,
        severity=severity,
        mscore_gte=mscore_gte,
    )

    if start_time:
        start_time = start_time.strftime(DATE_TIME_FORMAT)  # type: ignore
    if end_time:
        end_time = end_time.strftime(DATE_TIME_FORMAT)  # type: ignore

    query_params = get_dtm_alert_list_query_params(
        size=size,
        order=order,
        sort=sort,
        start_time=start_time,
        end_time=end_time,
        monitor_id=monitor_id,
        alert_type=alert_type,
        tags=tags,
        status=status,
        severity=severity,
        mscore_gte=mscore_gte,
        refs=refs,
        monitor_name=monitor_name,
        has_analysis=has_analysis,
        search=search,
        match_value=match_value,
    )

    raw_response = client.get_alert_list(query_params, response_type="json")

    alerts_data = raw_response.get("alerts", [])
    if not alerts_data:
        return CommandResults(readable_output=MESSAGES["NO_RECORDS_FOUND"].format("DTM Alerts"))

    monitor_name_bool = argToBoolean(monitor_name)
    context, hr = build_dtm_alert_list_output(alerts_data, monitor_name=monitor_name_bool)

    return CommandResults(
        outputs_prefix=OUTPUT_PREFIX["ALERT_LIST"],
        outputs_key_field="id",
        outputs=context,
        raw_response=raw_response,
        readable_output=hr,
    )


def gti_dtm_alert_status_update_command(client: Client, args: dict) -> CommandResults:
    """
    Update DTM alert status for the specified alert ID.

    Args:
        client: Client object to use.
        args: arguments obtained from demisto.args()

    Returns:
        CommandResult object
    """

    alert_id, status = validate_alert_status_update_args(args)

    payload = {"status": status}

    raw_response = client.patch_alert_update(alert_id=alert_id, payload=payload)

    context, hr = build_alert_status_update_output(raw_response)

    return CommandResults(
        outputs_prefix=OUTPUT_PREFIX["ALERT_LIST"],
        outputs_key_field="id",
        outputs=context,
        raw_response=raw_response,
        readable_output=hr,
    )


def fetch_incidents(
    client: Client, last_run: dict, params: dict, is_test: bool = False
) -> tuple[List[Dict[str, Any]], Dict[str, Any]]:
    """
    Fetch DTM Alerts as incidents from Google Threat Intelligence.

    Args:
        client (Client): Google Threat Intelligence client object.
        params (Dict[str, Any]): Fetch incidents parameters.

    Returns:
        List[Dict[str, Any]]: List of fetched incidents.
        Dict[str, Any]: Next run parameters.
    """
    # Get parameters with guaranteed non-None fallbacks
    first_fetch_time = arg_to_datetime(params.get("first_fetch", DEFAULT_FETCH_TIME))
    max_fetch = arg_to_number(params.get("max_fetch", DEFAULT_MAX_FETCH), "Max Fetch")

    # Initialize variables
    alert_incidents: List[Dict[str, Any]] = []
    next_run_params: Dict[str, Any] = {}

    # Get parameters
    status = argToList(params.get("alert_status"))
    severity = argToList(params.get("alert_severity"))
    mscore_gte = arg_to_number(params.get("alert_mscore_gte"), "Alert mscore")
    alert_type = argToList(params.get("alert_type"))
    monitor_id = argToList(params.get("alert_monitor_ids"))
    tags = argToList(params.get("alert_tags"))
    match_value = argToList(params.get("alert_match_value"))
    search = params.get("alert_search")

    # validate parameters
    validate_dtm_alert_list_args(
        size=max_fetch, alert_type=alert_type, status=status, severity=severity, mscore_gte=mscore_gte, fetch=DEFAULT_BOOL_VALUE
    )

    # Get query parameters
    query_params = get_dtm_alert_list_query_params(
        refs=DEFAULT_BOOL_VALUE,
        monitor_name=DEFAULT_BOOL_VALUE,
        order=DEFAULT_FETCH_SORT_ORDER,
        sort=DEFAULT_SORT_VALUE,
        size=max_fetch,
        monitor_id=monitor_id,
        alert_type=alert_type,
        tags=tags,
        status=status,
        severity=severity,
        mscore_gte=mscore_gte,
        search=search,
        match_value=match_value,
    )

    # Get data from last_run
    next_page_link = last_run.get("next_page_link")
    current_alert_ids = last_run.get("alert_ids", [])
    last_alert_created_at = last_run.get("last_alert_created_at", first_fetch_time.strftime(DATE_TIME_FORMAT))  # type: ignore

    if not last_run:
        query_params["since"] = last_alert_created_at
        response = client.get_alert_list(query_params, response_type="response")
    else:
        if next_page_link:
            # Pagination request without query parameters when page_link exist in last_run
            page_params = {"page": next_page_link}
            response = client.get_alert_list(page_params, response_type="response")
        else:
            # Initial or new time-based request
            query_params["since"] = last_alert_created_at
            response = client.get_alert_list(query_params, response_type="response")

    # Extract data from response
    alerts_response = response.json()  # type: ignore
    response_headers = response.headers  # type: ignore
    alerts_list = alerts_response.get("alerts", [])

    if is_test:
        return alert_incidents, next_run_params

    # Create incidents from alerts
    found_alert_ids = []
    duplicate_alert_ids = []
    for alert in alerts_list:
        alertid = alert.get("id")
        # Skip duplicates and invalid alerts with no id
        if not alertid or alertid in current_alert_ids:
            duplicate_alert_ids.append(alertid)
            continue

        # Update mirror params
        mirror_params = get_mirroring()
        mirror_params.update({"mirror_id": alertid})
        alert.update(mirror_params)

        alert_status = alert.get("status", "")
        alert["incident_type"] = DTM_ALERT_INCIDENT_TYPE
        alert["incident_link"] = DTM_ALERT_INCIDENT_LINK.format(alertid)
        alert["status"] = ALERT_STATUS_HR_MAPPING.get(alert_status, alert_status.capitalize())
        alert_doc_details = remove_empty_elements_for_hr(alert.get("doc"))

        readable_output = (
            (
                tableToMarkdown(
                    "Source Information",
                    alert_doc_details,
                    headerTransform=string_to_table_header,
                    removeNull=True,
                    is_auto_json_transform=True,
                )
            )
            if alert_doc_details
            else "No Source Information found for DTM Alert."
        )

        alert["doc_markdown"] = readable_output
        alert = remove_empty_elements_for_fetch(alert)
        alert_incidents.append(
            {
                "name": alert.get("title", ""),
                "occurred": alert.get("created_at", ""),
                "details": json.dumps(alert),
                "rawJSON": json.dumps(alert),
                "severity": ALERT_TYPE_TO_INCIDENT_SEVERITY.get(alert.get("severity", ""), 0),
            }
        )
        found_alert_ids.append(alert.get("id"))

    # Extract next page link from Link header
    next_page = response_headers.get("link", "")
    next_page_link = None
    if next_page:
        m = re.search(r"[?&]page=([^&>;]+)", next_page)
        if m:
            next_page_link = m.group(1)

    next_run_params["alert_ids"] = current_alert_ids + found_alert_ids

    # Update next_run_params
    if next_page_link and len(alerts_list) == max_fetch:
        # PAGINATION CONTINUES: Next page exists and current page is full
        next_run_params["next_page_link"] = next_page_link
        next_run_params["last_alert_created_at"] = alerts_list[-1].get("created_at")
    else:
        # PAGINATION ENDS: Next page does not exist or current page is not full
        next_run_params.pop("next_page_link", None)
        next_run_params["last_alert_created_at"] = alerts_list[-1].get("created_at") if alerts_list else last_alert_created_at

    demisto.debug(f"Fetched {len(found_alert_ids)} new incidents")
    demisto.debug(f"next_run_params: {next_run_params}")
    demisto.debug(f"Fetched duplicate DTM Alert {len(duplicate_alert_ids)}")

    return alert_incidents, next_run_params


# Mirroring Commands
def update_remote_system_command(client: Client, args: Dict) -> str:
    """
    Update a remote DTM alert based on changes in the XSOAR incident.

    Args:
        client (Client): An instance of the Client class.
        args (Dict): A dictionary containing the arguments required for updating the remote system.

    Returns:
        str: The ID of the updated remote alert.
    """
    parsed_args = UpdateRemoteSystemArgs(args)
    remote_alert_id = parsed_args.remote_incident_id
    mirror_alert_id = parsed_args.data.get("alertid", "")
    incident_status = parsed_args.inc_status
    delta = parsed_args.delta or {}
    xsoar_tags = delta.get("tags") or []
    incident_changed = parsed_args.incident_changed

    demisto.debug(f"Incident changed: {incident_changed}")
    demisto.debug(f"Delta information: {delta}")
    demisto.debug(f"Mirroring update for DTM alert: {mirror_alert_id} (remote_id: {remote_alert_id})")
    demisto.debug(f"Incident status: {incident_status}, XSOAR tags: {xsoar_tags}")

    if not mirror_alert_id:
        demisto.debug("No mirror alert ID found for update")
        return remote_alert_id

    # Prepare update data
    update_data = {}

    # Update external status when incident is closed or when incident is active with no changes or incident get reopen
    reopen_incident = False
    if delta and delta.get("closingUserId") == "" and delta.get("runStatus") == "":
        reopen_incident = True

    is_update_status = (
        incident_status == IncidentStatus.DONE or (incident_status == IncidentStatus.ACTIVE and not delta) or reopen_incident
    )

    if incident_changed and is_update_status:
        update_data["status"] = DTM_ALERT_INCIDENT_STATUS_MAPPING[incident_status]
        demisto.debug(f"Status update: {DTM_ALERT_INCIDENT_STATUS_MAPPING[incident_status]}")

    # Update tags when tags exist in delta and incident is changed
    if incident_changed and xsoar_tags:
        # Get existing tags from GTI platform
        gti_platform_tags = extract_tags_from_dtm_stats(client=client)

        # Get current DTM alert data
        current_alert = client.get_alert(alert_id=mirror_alert_id, query_params={"refs": "false"})
        current_tags = current_alert.get("tags", [])

        # Preserve existing order and append new tags, avoiding duplicates
        new_tags = current_tags.copy()

        # Process XSOAR tags to match GTI platform tags (case-sensitive)
        for xsoar_tag in xsoar_tags:
            # Check if this tag exists in GTI platform (case-insensitive lookup)
            xsoar_tag_lower = xsoar_tag.lower().strip()

            if xsoar_tag_lower in gti_platform_tags:
                # Use the exact case from GTI platform
                platform_tag = gti_platform_tags[xsoar_tag_lower]
                if platform_tag not in current_tags:
                    new_tags.append(platform_tag)
            else:
                # Tag doesn't exist in GTI platform, add in tags list
                clean_tag = xsoar_tag.strip()
                if clean_tag not in current_tags:
                    new_tags.append(clean_tag)

        if new_tags != current_tags:  # if tags changed then append to update data
            update_data["tags"] = new_tags
            demisto.debug(f"Tags update: {current_tags} -> {new_tags}")

    # Perform single update if there are changes
    if update_data:
        client.patch_alert_update(mirror_alert_id, update_data)
        demisto.debug(f"Updated DTM alert {mirror_alert_id} with: {update_data}")
    else:
        demisto.debug("No changes detected, skipping update")

    return remote_alert_id


def main():
    params = demisto.params()
    params = trim_spaces_from_args(params)
    remove_nulls_from_dictionary(params)

    # get connectivity parameters
    api_key = str(dict_safe_get(params, ["credentials", "password"])).strip()
    verify_certificate = not argToBoolean(params.get("insecure", False))
    proxy = argToBoolean(params.get("proxy", False))

    command = demisto.command()
    demisto.debug(f"Command being called is {command}")

    commands: dict[str, Callable] = {
        "gti-dtm-alert-list": gti_dtm_alert_list_command,
        "gti-dtm-alert-get": gti_dtm_alert_get_command,
        "gti-dtm-alert-status-update": gti_dtm_alert_status_update_command,
    }
    try:
        result = None
        # Creates client
        client = Client(verify_certificate, proxy, api_key)
        # Get Command args
        args = demisto.args()
        if command == "test-module":
            result = test_module(client)
        elif command == "fetch-incidents":
            last_run = demisto.getLastRun()
            # Fetch incidents
            incidents, next_run = fetch_incidents(client, last_run, params)
            demisto.incidents(incidents)
            demisto.setLastRun(next_run)
        elif command == "update-remote-system":
            result = update_remote_system_command(client, args)
        elif command in commands:
            # remove nulls from dictionary and trim space from args
            args = trim_spaces_from_args(args)
            remove_nulls_from_dictionary(args)
            result = commands[command](client, args)
        else:
            raise NotImplementedError(f"Command {command} is not implemented")

        return_results(result)  # Returns either str, CommandResults and a list of CommandResults

    # Log exceptions and return errors
    except Exception as e:
        return_error(f"Failed to execute {command} command.\nError:\n{str(e)}")


if __name__ in ("__main__", "__builtin__", "builtins"):  # pragma: no cover
    main()
