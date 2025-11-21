"""Dataminr Pulse - ReGenAI Integration for Cortex XSOAR (aka Demisto)."""

from functools import reduce
from operator import concat
from urllib.parse import urlparse, parse_qs
from collections.abc import Callable
from copy import deepcopy

import demistomock as demisto
import urllib3
from CommonServerPython import *  # noqa # pylint: disable=unused-wildcard-import
from CommonServerUserPython import *  # noqa

# Disable insecure warnings
urllib3.disable_warnings()

""" CONSTANTS """

# Base URL for the Dataminr Pulse ReGenAI API.
BASE_URL = "https://api.dataminr.com"

ENDPOINTS = {
    # Authentication endpoint for the Dataminr Pulse API.
    "AUTH_ENDPOINT": "/auth/v1/token",
    # Watchlists endpoint for the Dataminr Pulse API.
    "WATCHLISTS_ENDPOINT": "/pulse/v1/lists",
    # Alerts endpoint for the Dataminr Pulse API.
    "ALERTS_ENDPOINT": "/pulse/v1/alerts",
}

DATE_FORMAT = "%Y-%m-%dT%H:%M:%SZ"  # ISO8601 format with UTC, default in XSOAR

# Date format for displaying date in human-readable format in war room.
HR_DATE_FORMAT = "%d %b %Y, %I:%M %p UTC"

APPLICATION_NAME = "palo_alto_cortex_xsoar"
OK_CODES = (200, 201, 401)
DEFAULT_NUMBER_OF_ALERTS_TO_RETRIEVE = 40
MAX_NUMBER_OF_ALERTS_TO_RETRIEVE = 100
STATUS_LIST_TO_RETRY = (429, *(status_code for status_code in requests.status_codes._codes if status_code >= 500))  # type: ignore
EARLY_EXPIRY_TIME = 30000  # in milliseconds
DEFAULT_ALERT_TYPE = "All"
VENDOR_NAME = "DataminrPulse"
CUSTOM_OUTPUT_PREFIX = "DataminrPulse.{}"

ERRORS = {
    "INVALID_JSON_OBJECT": "Status code: {}. Failed to parse json object from response: {}.",
    "UNAUTHORIZED_REQUEST": "Status code: {}. Unauthorized request: {}.",
    "GENERAL_AUTH_ERROR": "Status code: {}. Error occurred while creating an authorization token. "
    "Please check the Client ID, Client Secret {}.",
    "NOT_MATCHED_WATCHLIST_NAMES": "No matching watchlist data was found for the {} watchlist names configured in the instance.",
    "INVALID_NUM": '{} is invalid value for "{}". Value should be greater than 0 and less than or equal to {}.',
    "ATMOST_ONE_ALLOWED": 'At most one argument, either "{}" or "{}" is allowed.',
    "JSON_DECODE": "Failed to parse '{}' JSON string.",
    "REQUIRED_ARG": "Required argument '{}' is missing.",
}

ALERT_TYPE_TO_INCIDENT_SEVERITY = {"Alert": 1, "Urgent": 3, "Flash": 4}
DEFAULT_RELIABILITY = "A - Completely reliable"

# Output prefix for the alerts.
OUTPUT_PREFIX_ALERTS = "DataminrPulse.Alerts"
# Output prefix for the lists.
OUTPUT_PREFIX_WATCHLISTS = "DataminrPulse.WatchLists"
# Output prefix for the cursor.
OUTPUT_PREFIX_CURSOR = "DataminrPulse.Cursor"

""" CLIENT CLASS """


class DataminrPulseReGenAIClient(BaseClient):
    """DataminrPulseClient class to interact with the Dataminr Pulse API."""

    def __init__(self, client_id: str = "", client_secret: str = "", verify: bool = False, proxy: bool = False):
        """
        Constructor for the DataminrPulseClient class.

        :type client_id: ``str``
        :param client_id: Client ID to be used for authentication.

        :type client_secret: ``str``
        :param client_secret: Client Secret to be used for authentication.

        :type verify: ``bool``
        :param verify: Whether the request should verify the SSL certificate.

        :type proxy: ``bool``
        :param proxy: Whether to run the integration using the system proxy.
        """
        self.client_id = client_id
        self.client_secret = client_secret
        self.base_url = BASE_URL
        super().__init__(base_url=self.base_url, verify=verify, proxy=proxy, headers={})

    def http_request(
        self,
        method,
        url_suffix,
        params=None,
        status_list_to_retry=STATUS_LIST_TO_RETRY,
        backoff_factor=30,
        retries=3,
        internal_retries=3,
        **kwargs,
    ) -> Optional[dict]:
        """
        Method to override private _http_request of BaseClient to handle specific status code.

        :type method: ``str``
        :param method: The HTTP method, for example: GET, POST, and so on.

        :type url_suffix: ``str``
        :param url_suffix: The API endpoint.

        :type params: ``dict``
        :param params: URL parameters to specify the query.

        :type status_list_to_retry: ``iterable``
        :param status_list_to_retry: A set of integer HTTP status codes that we should force a retry on.

        :type backoff_factor ``float``
        :param backoff_factor: A backoff factor to apply between attempts

        :type retries: ``int``
        :param retries: How many retries should be made in case of a failure.

        :type internal_retries: ``int``
        :param internal_retries: How many retries should be made in case of an auth failure.

        :return: Response dict.
        :rtype: ``Optional[dict]``
        """
        # Adds a valid authentication token to the headers.
        dma_token = self.get_dma_token(use_existing_token=True)
        headers = {
            "Authorization": f"Bearer {dma_token}",
            "X-Application-Name": APPLICATION_NAME,
        }
        self._headers.update(headers)
        res = self._http_request(
            method=method,
            url_suffix=url_suffix,
            params=params,
            status_list_to_retry=status_list_to_retry,
            backoff_factor=backoff_factor,
            retries=retries,
            resp_type="response",
            ok_codes=OK_CODES,
            **kwargs,
        )
        res_status_code = res.status_code

        try:
            json_data = res.json()
        except ValueError as exception:
            raise DemistoException(ERRORS["INVALID_JSON_OBJECT"].format(res_status_code, res.content), exception)

        # If the success response is received, then return it.
        if res_status_code in [200, 201]:
            return json_data

        # If authentication failure happens.
        if res_status_code in [401]:
            if internal_retries > 0:
                dma_token = self.get_dma_token(use_existing_token=False)
                headers = {
                    "Authorization": f"Bearer {dma_token}",
                    "X-Application-Name": APPLICATION_NAME,
                }
                self._headers.update(headers)
                internal_retries = internal_retries - 1
                return self.http_request(
                    method=method,
                    url_suffix=url_suffix,
                    params=params,
                    status_list_to_retry=status_list_to_retry,
                    backoff_factor=backoff_factor,
                    retries=retries,
                    internal_retries=internal_retries,
                )
            try:
                err_msg = ERRORS["UNAUTHORIZED_REQUEST"].format(res_status_code, str(res.json()))
            except ValueError:
                err_msg = ERRORS["UNAUTHORIZED_REQUEST"].format(res_status_code, str(res))
            raise DemistoException(err_msg)
        return None

    def get_dma_token(self, use_existing_token: bool = True) -> Optional[str]:
        """
        Get a DMA token that was previously created if it is still valid, else, generate a new authorization token from
        the client id, client secret and refresh token.

        :type use_existing_token ``bool``
        :param use_existing_token: Use existing token if it is still valid.

        :return: DMA token.
        :rtype: ``Optional[str]``
        """
        integration_context: dict = get_integration_context()
        previous_token: dict = integration_context.get("token", {})

        # Check if there is existing valid authorization token.
        if (
            previous_token.get("dmaToken")
            and use_existing_token
            and previous_token.get("expire") > datetime.now(timezone.utc).timestamp() * 1000  # type: ignore
        ):
            demisto.debug("Got authentication token from the integration context.")
            return previous_token.get("dmaToken")  # type: ignore

        demisto.debug("Trying to generate a new authentication token.")
        data = {"client_id": self.client_id, "client_secret": self.client_secret, "grant_type": "api_key"}

        headers = {
            "Content-Type": "application/x-www-form-urlencoded",
            "X-Application-Name": APPLICATION_NAME,
        }
        res = super()._http_request(
            method="POST",
            url_suffix=ENDPOINTS["AUTH_ENDPOINT"],
            resp_type="response",
            headers=headers,
            data=data,
            ok_codes=OK_CODES,
            status_list_to_retry=STATUS_LIST_TO_RETRY,
        )
        res_status_code = res.status_code

        try:
            res = res.json()
        except ValueError as exception:
            raise DemistoException(ERRORS["INVALID_JSON_OBJECT"].format(res_status_code, res.content), exception)

        if "errors" in res:
            raise DemistoException(ERRORS["GENERAL_AUTH_ERROR"].format(res_status_code, str(res)))
        if res.get("dmaToken"):
            expiry_time = res.get("expire", 0) - EARLY_EXPIRY_TIME
            demisto.debug(
                f"Setting the expiry time of the authentication token to {timestamp_to_datestring(expiry_time, is_utc=True)}."
            )
            new_token = {"dmaToken": res.get("dmaToken"), "expire": expiry_time}
            integration_context.update({"token": new_token})
            set_integration_context(integration_context)
            return res.get("dmaToken")
        return None

    def get_alerts(
        self,
        watchlist_ids: Optional[list] = None,
        query: Optional[str] = None,
        _from: Optional[str] = None,
        to: Optional[str] = None,
        page_size: int = DEFAULT_NUMBER_OF_ALERTS_TO_RETRIEVE,
    ) -> Optional[dict]:
        """
        Retrieves the alerts stored on the Dataminr platform.

        :type watchlist_ids ``Optional[list]``
        :param watchlist_ids: List of watchlist id.

        :type query ``Optional[str]``
        :param query: Terms to search within Dataminr Alerts.

        :type _from ``Optional[str]``
        :param _from: Provide cursor value to get alerts after that.

        :type to ``Optional[str]``
        :param to: Provide cursor value to get alerts before that.

        :type page_size ``int``
        :param page_size: Maximum number of alerts to return.

        :return: A dictionary of alerts.
        :rtype: ``Optional[dict]``
        """
        params = {
            "pageSize": page_size,
            "from": _from,
            "to": to,
            "query": query,
        }
        remove_nulls_from_dictionary(params)
        if watchlist_ids:
            params["lists"] = ",".join(map(str, watchlist_ids))  # type: ignore
        return self.http_request(method="GET", url_suffix=ENDPOINTS["ALERTS_ENDPOINT"], params=params)

    def get_watchlists(self) -> Optional[dict]:
        """Retrieves the watchlists stored on the Dataminr platform.

        :return: A dictionary of Watchlists grouped by their types.
        :rtype: ``Optional[Dict]``
        """
        return self.http_request(method="GET", url_suffix=ENDPOINTS["WATCHLISTS_ENDPOINT"])


""" HELPER FUNCTIONS """


def validate_params_for_alerts_get(
    watchlist_ids: Optional[list] = None,
    watchlist_names: Optional[list] = None,
    page_size: int = DEFAULT_NUMBER_OF_ALERTS_TO_RETRIEVE,
    use_configured_watchlist_names: bool = False,
    is_fetch: bool = False,
    _from: Optional[str] = None,
    to: Optional[str] = None,
):
    """
    To validate arguments for the alerts get.

    :type watchlist_ids ``Optional[List]``
    :param watchlist_ids: List of watchlist id.

    :type watchlist_names ``Optional[List]``
    :param watchlist_names: Watchlist names.

    :type page_size ``int``
    :param page_size: Maximum number of alerts to return.

    :type use_configured_watchlist_names ``bool``
    :param use_configured_watchlist_names: Use configured watchlist names.

    :type is_fetch ``bool``
    :param is_fetch: Function is called by fetch_incident method.

    :type _from ``Optional[str]``
    :param _from: Start cursor for the alerts.

    :type to ``Optional[str]``
    :param to: End cursor for the alerts.
    """
    if is_fetch and (page_size < 1 or page_size > MAX_NUMBER_OF_ALERTS_TO_RETRIEVE):
        raise ValueError(ERRORS["INVALID_NUM"].format(page_size, "Max Fetch", MAX_NUMBER_OF_ALERTS_TO_RETRIEVE))
    elif page_size < 1 or page_size > MAX_NUMBER_OF_ALERTS_TO_RETRIEVE:
        raise ValueError(ERRORS["INVALID_NUM"].format(page_size, "num", MAX_NUMBER_OF_ALERTS_TO_RETRIEVE))

    if (is_fetch or use_configured_watchlist_names) and (watchlist_names and not watchlist_ids):
        raise ValueError(ERRORS["NOT_MATCHED_WATCHLIST_NAMES"].format(watchlist_names))

    if _from and to:
        raise ValueError(ERRORS["ATMOST_ONE_ALLOWED"].format("from", "to"))


def transform_watchlists_data(watchlists_data: Optional[dict] = None) -> list:
    """
    Transform watchlist data from dictionary to single List.

    :type watchlists_data ``Optional[dict]``
    :param watchlists_data: Response to be converted in single list.

    :return: List of response.
    :rtype: ``list``
    """
    list_of_watchlists = watchlists_data.get("lists", {}).values()  # type: ignore
    # The returned object is a dictionary where the lists are grouped by their type.
    # So, modifying this object and creating a list of all list objects as the object itself contains
    # a property named "type" in it, which defines the type of the list.
    list_of_watchlists = list(list_of_watchlists)
    # The created list will be the list of lists. So, flattening the list is required.
    list_of_watchlists = reduce(concat, list_of_watchlists)
    return list_of_watchlists


def get_watchlist_ids(client: DataminrPulseReGenAIClient, watchlist_names: Optional[list] = None) -> list:
    """
    Get watchlist IDs as per the given watchlist names using integration context and get_watchlists method from client.

    :type client ``DataminrPulseReGenAIClient``
    :param client: DataminrPulseReGenAIClient to get watchlists data.

    :type watchlist_names ``Optional[List]``
    :param watchlist_names: Watchlist names.

    :return: Watchlist IDs.
    :rtype: ``list``
    """
    watchlists_data: list = transform_watchlists_data(client.get_watchlists())
    watchlist_names_in_lower = [watchlist_name.lower() for watchlist_name in watchlist_names] if watchlist_names else []
    filtered_watchlists_data: list = (
        list(
            filter(
                lambda watchlist_data: watchlist_data.get("name").lower() in watchlist_names_in_lower,  # type: ignore
                watchlists_data,
            )
        )
        if watchlist_names
        else watchlists_data
    )
    if not filtered_watchlists_data:
        demisto.debug(
            f'No matching watchlist data was found for the "{watchlist_names}" watchlist names configured in the instance.'
        )
        return []
    watchlist_ids: list = [watchlist_data.get("id") for watchlist_data in filtered_watchlists_data]
    watchlist_ids: list = list(filter(None, watchlist_ids))
    return watchlist_ids


def create_media_html(alert: dict) -> str:
    """
    Create HTML content for the media.

    :type alert: ``dict``
    :param alert: Alert data.

    :rtype: ``str``
    :return: HTML content for the media.
    """
    media = alert.get("publicPost", {}).get("media", [])
    if not media:
        return ""

    photo_media = list(filter(lambda photo: photo.get("type") == "photo" or photo.get("type") == "image", media))
    if not photo_media:
        return ""

    html_content = []

    for photo in photo_media:
        html_content.append(f'<img src="{photo.get("href", "")}" alt="Photo">')

    media_html = "\n".join(html_content)
    return media_html


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


def trim_spaces_from_args(args: Dict) -> Dict:
    """Trim spaces from values of the args Dict.

    :type args: ``Dict``
    :param args: Dict to trim spaces from.

    :rtype: ``Dict``
    :return: Arguments after trim spaces.
    """
    for key, val in args.items():
        if isinstance(val, str):
            args[key] = val.strip()
        elif isinstance(val, dict):
            args[key] = trim_spaces_from_args(val)
        elif isinstance(val, list):
            for i in range(len(val)):
                if isinstance(val[i], str):
                    val[i] = val[i].strip()
                elif isinstance(val[i], dict):
                    val[i] = trim_spaces_from_args(val[i])

    return args


def prepare_hr_for_watchlists_get(watchlists: List) -> str:
    """
    Prepare human-readable string for war room entry.

    :type watchlists: ``List``
    :param watchlists: List of watchlists.

    :return: Human-readable output.
    :rtype: ``str``
    """
    # The title of the table.
    title = "Watchlists"
    # Data dictionary for the table.
    hr_outputs = [
        {
            "Watchlist ID": wl.get("id", ""),
            "Watchlist Name": wl.get("name", ""),
            "Watchlist Type": wl.get("type", ""),
            "Watchlist Sub Type": wl.get("subType", ""),
        }
        for wl in watchlists
    ]
    # Table headers.
    headers = ["Watchlist ID", "Watchlist Name", "Watchlist Type", "Watchlist Sub Type"]
    return tableToMarkdown(title, hr_outputs, headers, removeNull=True)


def prepare_hr_for_alerts(alerts: List) -> str:
    """Prepare Human Readable output for alerts.

    :type alerts: ``List``
    :param alerts: Response from the API.

    :rtype: ``str``
    :return: Human readable output.
    """
    # The title of the table.
    title = "Alerts"

    # This will store the data dictionaries for the table.
    hr_outputs = []

    for alert in alerts:
        # List of watchlist names matched in the alert.
        watchlist_names = [watchlist.get("name") for watchlist in alert.get("listsMatched", [])]
        intel_agents = deepcopy(alert.get("intelAgents", []))
        intel_agents_summary = []
        discovered_entities = []

        for intel_agent in intel_agents:
            intel_agents_summary.extend(intel_agent.get("summary", []))
            discovered_entities.extend(intel_agent.get("discoveredEntities", []))

        for summary in intel_agents_summary:
            summary["type"] = ", ".join(summary.get("type", []))
            summary["content"] = "\n".join(summary.get("content", []))

        for discovered_entity in discovered_entities:
            if discovered_entity.get("type") == "threatActor" and discovered_entity.get("aliases"):
                discovered_entity["aliases"] = ", ".join(discovered_entity.get("aliases", []))
            elif discovered_entity.get("type") == "malware" and discovered_entity.get("affectedOperatingSystems"):
                discovered_entity["affectedOperatingSystems"] = ", ".join(discovered_entity.get("affectedOperatingSystems", []))
            elif discovered_entity.get("type") == "vulnerability" and discovered_entity.get("exploitPocLinks"):
                discovered_entity["exploitPocLinks"] = ", ".join(discovered_entity.get("exploitPocLinks", []))

        hr_outputs.append(
            {
                "Alert Type": alert.get("alertType", {}).get("name", ""),
                "Alert ID": f"[{alert.get('alertId', '')}]({alert.get('dataminrAlertUrl', '')})",
                "Alert Name": alert.get("headline", ""),
                "Intel Agents Summary": intel_agents_summary if intel_agents_summary else "",
                "Intel Agents Discovered Entities": discovered_entities if discovered_entities else "",
                "Live Brief": alert.get("liveBrief", ""),
                "Watchlist Name": ", ".join(watchlist_names),
                "Alert Time": alert.get("alertTimestamp", ""),
                "Alert Location": alert.get("estimatedEventLocation", {}).get("name", ""),
                "Post Link": alert.get("publicPost", {}).get("href", ""),
                "Alert Topics": alert.get("alertTopics", ""),
            }
        )

    # Table headers.
    headers = [
        "Alert Type",
        "Alert ID",
        "Alert Name",
        "Intel Agents Summary",
        "Intel Agents Discovered Entities",
        "Live Brief",
        "Watchlist Name",
        "Alert Time",
        "Alert Location",
        "Post Link",
        "Alert Topics",
    ]
    return tableToMarkdown(
        title,
        hr_outputs,
        headers,
        removeNull=True,
        url_keys=["Post Link"],
        json_transform_mapping={
            "Alert Topics": JsonTransformer(is_nested=True),
            "Intel Agents Summary": JsonTransformer(is_nested=True),
            "Intel Agents Discovered Entities": JsonTransformer(is_nested=True),
            "Live Brief": JsonTransformer(is_nested=True),
        },
    )


def prepare_hr_for_cursor(cursor: Dict) -> str:
    """Prepare Human Readable output for cursor.

    :type cursor: ``Dict``
    :param cursor: Contains from and to parameter.

    :rtype: ``str``
    :return: Human readable output.
    """
    # The title of the table.
    title = "Cursor for pagination"

    # This will store the data dictionaries for the table.
    _from = cursor.get("from")
    if _from:
        _from = re.escape(_from)
    to = cursor.get("to")
    if to:
        to = re.escape(to)
    hr_outputs = [{"from": _from, "to": to}]

    # Table headers.
    headers = ["from", "to"]
    return tableToMarkdown(title, hr_outputs, headers, removeNull=True)


def create_vulnerability_indicators(alert: dict) -> list:
    """
    Create vulnerability indicators for the alert.

    :type alert: ``dict``
    :param alert: Alert data.

    :rtype: ``list``
    :return: List of vulnerability indicators.
    """
    vulnerability_intel_agents_list = []
    vulnerability_metadata_list = alert.get("metadata", {}).get("cyber", {}).get("vulnerabilities", [])
    intel_agents = alert.get("intelAgents", [])

    for vulnerability in vulnerability_metadata_list:
        if "epssScore" in vulnerability:
            vulnerability["epssScore"] = str(vulnerability.get("epssScore", "0")) + "%"

    for intel_agent in intel_agents:
        discovered_entities = intel_agent.get("discoveredEntities", [])
        for discovered_entity in discovered_entities:
            if discovered_entity.get("type", "") == "vulnerability":
                discovered_entity["id"] = discovered_entity.get("name", "")
                if "epssScore" in discovered_entity:
                    discovered_entity["epssScore"] = str(discovered_entity.get("epssScore", "0")) + "%"
                vulnerability_intel_agents_list.append(discovered_entity)

    merged = {}
    for vuln in vulnerability_intel_agents_list:
        vid = vuln.get("id")
        if vid is not None:
            merged[vid] = deepcopy(vuln)

    for vuln in vulnerability_metadata_list:
        vid = vuln.get("id")
        if vid is None:
            continue
        if vid in merged:
            merged[vid] = merge_dicts(merged[vid], vuln)
        else:
            merged[vid] = deepcopy(vuln)

    return list(merged.values())


def create_malware_indicators(alert: dict) -> list:
    """
    Create malware indicators for the alert.

    :type alert: ``dict``
    :param alert: Alert data.

    :rtype: ``list``
    :return: List of malware indicators.
    """
    malware_intel_agents_list = []
    malware_metadata_list = alert.get("metadata", {}).get("cyber", {}).get("malware", [])
    intel_agents = alert.get("intelAgents", [])

    for malware in malware_metadata_list:
        malware["name"] = "Malware: [" + malware.get("name", "") + "]"

    for intel_agent in intel_agents:
        discovered_entities = intel_agent.get("discoveredEntities", [])
        for discovered_entity in discovered_entities:
            if discovered_entity.get("type", "") == "malware":
                discovered_entity["name"] = "Malware: [" + discovered_entity.get("name", "") + "]"
                malware_intel_agents_list.append(discovered_entity)

    merged = {}
    for malware in malware_intel_agents_list:
        mid = malware.get("name")
        if mid is not None:
            merged[mid] = deepcopy(malware)

    for malware in malware_metadata_list:
        mid = malware.get("name")
        if mid is None:
            continue
        if mid in merged:
            merged[mid] = merge_dicts(merged[mid], malware)
        else:
            merged[mid] = deepcopy(malware)

    return list(merged.values())


def create_threat_actors_indicators(alert: dict) -> list:
    """
    Create threat actors indicators for the alert.

    :type alert: ``dict``
    :param alert: Alert data.

    :rtype: ``list``
    :return: List of threat actors indicators.
    """
    threat_actor_intel_agents_list = []
    threat_actor_metadata_list = alert.get("metadata", {}).get("cyber", {}).get("threatActors", [])
    intel_agents = alert.get("intelAgents", [])

    for threat_actor in threat_actor_metadata_list:
        threat_actor["name"] = "Threat Actor: [" + threat_actor.get("name", "") + "]"

    for intel_agent in intel_agents:
        discovered_entities = intel_agent.get("discoveredEntities", [])
        for discovered_entity in discovered_entities:
            if discovered_entity.get("type", "") == "threatActor":
                discovered_entity["name"] = "Threat Actor: [" + discovered_entity.get("name", "") + "]"
                threat_actor_intel_agents_list.append(discovered_entity)

    merged = {}
    for actor in threat_actor_intel_agents_list:
        name = actor.get("name")
        if name:
            merged[name] = deepcopy(actor)

    for actor in threat_actor_metadata_list:
        name = actor.get("name")
        if not name:
            continue
        if name in merged:
            merged[name] = merge_dicts(merged[name], actor)
        else:
            merged[name] = deepcopy(actor)

    return list(merged.values())


def create_flight_data(alert: dict) -> dict:
    """
    Create flight data for the alert.

    :type alert: ``dict``
    :param alert: Alert data.

    :rtype: ``dict``
    :return: Flight data.
    """
    sub_headline_content = alert.get("subHeadline", {}).get("content", [])
    flight_data = {}

    for item in sub_headline_content:
        # Skip empty or whitespace-only lines
        if not item.strip():
            continue

        # Check if it contains a colon (valid key-value format)
        if ":" in item:
            key, value = item.split(":", 1)
            key, value = key.strip(), value.strip()

            # Only add if both key and value are non-empty
            if key and value:
                flight_data[key] = value

    return flight_data


def calculate_dbot_score(cvss: float) -> int:
    if cvss >= 4.0:
        return Common.DBotScore.BAD
    elif cvss > 0.0:
        return Common.DBotScore.SUSPICIOUS
    else:
        return Common.DBotScore.NONE


def merge_dicts(d1: dict, d2: dict) -> dict:
    """
    Merge two dictionaries recursively and handle duplicate values.
    Works for dict, list, string, number, etc.
    """
    merged = dict(d1)  # start with a copy of d1

    for key, value in d2.items():
        if key not in merged:
            # New key, just add
            merged[key] = value

    return merged


def create_relationship_for_malware(malware: dict) -> list:
    """
    Create a list of relationships objects from the malware and threat actor.

    :type malware: ``dict``
    :param malware: Malware of API.

    :return: List of EntityRelationship objects containing all the relationships.
    :rtype: ``List``
    """
    relationships = []
    source_malware = malware.get("name", "")
    integration_reliability = demisto.params().get("integrationReliability", DEFAULT_RELIABILITY)

    for threat_actor in malware.get("threatActors", []):
        threat_actor_name = "Threat Actor: [" + threat_actor.get("name", "") + "]"
        relationships.append(
            EntityRelationship(
                name=EntityRelationship.Relationships.ORIGINATED_FROM,
                entity_a=source_malware,
                entity_a_type="Dataminr Pulse Malware Indicator",
                entity_b=threat_actor_name,
                entity_b_type="Dataminr Pulse Threat Actor Indicator",
                source_reliability=integration_reliability,
                brand=VENDOR_NAME,
            )
        )

    return relationships


""" COMMAND FUNCTIONS """


def test_module(client: DataminrPulseReGenAIClient) -> str:
    """Tests API connectivity and authentication'

    Returning 'ok' indicates that the integration works like it is supposed to.
    Connection to the service is successful.
    Raises:
     exceptions if something goes wrong.

    :type client: ``DataminrPulseReGenAIClient``
    :param client: DataminrPulseReGenAIClient to be used.

    :rtype: ``str``
    :return: 'ok' if test passed, anything else will fail the test.
    """
    params = demisto.params()
    is_fetch = params.get("isFetch", False)
    if is_fetch:
        fetch_incidents(client, {}, params, is_test=True)
    else:
        client.get_alerts(page_size=1)
    # Return OK, indicating the connection to the platform is successful.
    return "ok"


def fetch_incidents(
    client: DataminrPulseReGenAIClient, last_run: dict[str, Any], params: dict[str, Any], is_test: bool = False
) -> tuple[dict, list]:
    """Fetch alerts as an incidents.

    :type client: ``DataminrPulseReGenAIClient``
    :param client: DataminrPulseReGenAIClient to be used.

    :type last_run: ``dict[str, Any]``
    :param last_run: last run object obtained from demisto.getLastRun().

    :type params: `dict[str, Any]``
    :param params: Arguments to be used for fetch incident.

    :type is_test: ``bool``
    :param is_test: If test_module called fetch_incident.

    :rtype: ``tuple[dict, list]``
    :return: Tuple of last run object and list of fetched incidents.
    """
    page_size: int = arg_to_number(
        params.get("max_fetch", DEFAULT_NUMBER_OF_ALERTS_TO_RETRIEVE),  # type: ignore
        arg_name="Max Fetch",
    )
    watchlist_names = argToList(params.get("watchlist_names"), transform=lambda s: s.strip())
    query = params.get("query")
    alert_type: str = params.get("alert_type", DEFAULT_ALERT_TYPE)

    if query:
        query = query.strip()

    _from = last_run.get("from")
    last_watchlist_names = last_run.get("last_watchlist_names", [])
    last_query = last_run.get("last_query")
    found_alert_ids = last_run.get("found_alert_ids", [])

    watchlist_names_lower = []
    last_watchlist_names_lower = []
    if watchlist_names and isinstance(watchlist_names, list):
        watchlist_names_lower = [name.lower() for name in watchlist_names]
        watchlist_names_lower.sort()

    if last_watchlist_names and isinstance(last_watchlist_names, list):
        last_watchlist_names_lower = [name.lower() for name in last_watchlist_names]
        last_watchlist_names_lower.sort()

    watchlist_ids = get_watchlist_ids(client=client, watchlist_names=watchlist_names)
    if last_watchlist_names_lower != watchlist_names_lower or last_query != query:
        demisto.debug("Watchlist names or query changed in configuration, so fetching incident from start")
        _from = None

    if not is_test and page_size > 100:
        page_size = 100

    validate_params_for_alerts_get(
        watchlist_ids=watchlist_ids,
        watchlist_names=watchlist_names,
        page_size=page_size,
        use_configured_watchlist_names=False,
        is_fetch=True,
    )

    response = client.get_alerts(watchlist_ids=watchlist_ids, query=query, _from=_from, page_size=page_size)

    alert_response, _from, to = [], "", ""
    if response:
        alert_response = response.get("alerts", [])
        _from = response.get("previousPage", "")
        to = response.get("nextPage", "")

    alert_valid_response = remove_empty_elements(alert_response)

    from_url = urlparse(_from)
    from_params = parse_qs(from_url.query)
    from_value = from_params.get("to", [None])[0]  # type: ignore

    to_url = urlparse(to)
    to_params = parse_qs(to_url.query)
    to_value = to_params.get("from", [None])[0]  # type: ignore

    cursor_response = {"from": from_value, "to": to_value}
    cursor_valid_response = remove_empty_elements(cursor_response)

    if is_test:
        return {}, []

    next_run = last_run.copy()

    incidents = []

    duplicate_alert_ids_in_current_fetch = []
    new_alert_ids_in_current_fetch = []

    for alert in alert_valid_response:
        alert_type_name = alert.get("alertType", {}).get("name", "")
        if alert_type != "All" and (not alert_type_name or alert_type_name.lower() != alert_type.lower()):
            continue
        alert_id = alert.get("alertId")
        if alert_id in found_alert_ids:
            demisto.debug(f"Found existing alert. Alert ID: {alert_id}")
            duplicate_alert_ids_in_current_fetch.append(alert_id)
            continue

        media_html = create_media_html(alert)
        alert["media_html"] = media_html

        vulnerability_indicators = create_vulnerability_indicators(alert)
        alert["vulnerability_indicators"] = vulnerability_indicators

        malware_indicators = create_malware_indicators(alert)
        alert["malware_indicators"] = malware_indicators

        threat_actors_indicators = create_threat_actors_indicators(alert)
        alert["threat_actors_indicators"] = threat_actors_indicators

        flight_data = create_flight_data(alert)
        alert["flight_data"] = flight_data

        occurred_date = alert.get("alertTimestamp", "")
        incident_name = alert.get("headline", "")

        incidents.append(
            {
                "name": "✨ " + incident_name if alert.get("intelAgents", []) else incident_name,
                "occurred": occurred_date,
                "rawJSON": json.dumps(alert),
                "severity": ALERT_TYPE_TO_INCIDENT_SEVERITY.get(alert_type_name, 0),
            }
        )
        found_alert_ids.append(alert_id)
        new_alert_ids_in_current_fetch.append(alert_id)

    next_run["found_alert_ids"] = found_alert_ids

    if alert_valid_response and cursor_valid_response:
        next_run["from"] = cursor_valid_response.get("to")
        next_run["last_watchlist_names"] = watchlist_names
        next_run["last_query"] = query

    demisto.debug(f"Total alerts fetch as an incident: {len(incidents)}")
    demisto.debug(f"New alert IDs in current fetch: {new_alert_ids_in_current_fetch}")
    demisto.debug(f"Duplicate alert IDs in current fetch: {duplicate_alert_ids_in_current_fetch}")
    demisto.debug(f"All Alert IDs store in last run: {next_run['found_alert_ids']}")
    demisto.debug(f"Next page cursor: {next_run['from']}")

    return next_run, incidents


def dataminrpulse_watchlists_get_command(client: DataminrPulseReGenAIClient, args: Dict[str, Any]) -> CommandResults:
    """Retrieve the Watchlist stored on the Dataminr platform.

    :type client: ``DataminrPulseReGenAIClient``
    :param client: DataminrPulseReGenAIClient to be used.

    :type args: ``Dict[str, Any]``
    :param args: Arguments provided by user.

    :rtype: ``CommandResults``
    :return: Standard command result.
    """
    # Retrieve the lists stored on the Dataminr platform.
    raw_lists_resp = client.get_watchlists()
    list_of_watchlists = transform_watchlists_data(raw_lists_resp)
    # Create a human-readable output for the war room entry.
    hr_output = prepare_hr_for_watchlists_get(list_of_watchlists)
    # Create and return a CommandResults object to return_results function.
    return CommandResults(
        outputs_prefix=OUTPUT_PREFIX_WATCHLISTS,
        outputs_key_field="id",
        outputs=list_of_watchlists,
        readable_output=hr_output,
        raw_response=raw_lists_resp,
    )


def dataminrpulse_alerts_get(client: DataminrPulseReGenAIClient, args: Dict[str, Any]) -> List[CommandResults]:
    """Retrieve the list of the alerts that meet the specified filter criteria.

    :type client: ``DataminrPulseReGenAIClient``
    :param client: DataminrPulseReGenAIClient to be used.

    :type args: ``Dict[str, Any]``
    :param args: Arguments provided by user.

    :rtype: ``List[CommandResults]``
    :return: Standard command results.
    """
    watchlist_names: List = argToList(args.get("watchlist_names", ""))
    watchlist_ids: List = argToList(args.get("watchlist_ids", ""))
    query: str = args.get("query", "")
    _from: str = args.get("from", "")
    to: str = args.get("to", "")
    num: int = arg_to_number(args.get("num", DEFAULT_NUMBER_OF_ALERTS_TO_RETRIEVE), arg_name="num")  # type: ignore
    use_configured_watchlist_names: bool = argToBoolean(args.get("use_configured_watchlist_names", "yes"))

    if use_configured_watchlist_names and not watchlist_ids:
        watchlist_ids = get_watchlist_ids(client, watchlist_names)

    validate_params_for_alerts_get(
        watchlist_ids=watchlist_ids,
        watchlist_names=watchlist_names,
        page_size=num,
        use_configured_watchlist_names=use_configured_watchlist_names,
        _from=_from,
        to=to,
    )

    response = client.get_alerts(watchlist_ids, query, _from, to, num)
    alert_response = response.get("alerts", [])  # type: ignore
    alert_valid_response = remove_empty_elements(alert_response)
    hr_output_for_alerts = prepare_hr_for_alerts(alert_valid_response)

    _from = response.get("previousPage", "")  # type: ignore
    to = response.get("nextPage", "")  # type: ignore

    from_url = urlparse(_from)
    from_params = parse_qs(from_url.query)
    from_value = from_params.get("to", [None])[0]  # type: ignore

    to_url = urlparse(to)
    to_params = parse_qs(to_url.query)
    to_value = to_params.get("from", [None])[0]  # type: ignore

    cursor_response = {"from": from_value, "to": to_value}
    cursor_valid_response = remove_empty_elements(cursor_response)

    hr_output_for_cursor = prepare_hr_for_cursor(cursor_valid_response)

    alert_results = CommandResults(
        outputs_prefix=OUTPUT_PREFIX_ALERTS,
        outputs_key_field="alertId",
        outputs=alert_valid_response,
        readable_output=hr_output_for_alerts,
        raw_response=response,
    )

    cursor_results = CommandResults(
        outputs_prefix=OUTPUT_PREFIX_CURSOR,
        outputs_key_field=["from", "to"],
        outputs=cursor_valid_response,
        readable_output=hr_output_for_cursor,
        raw_response=cursor_response,
    )

    return [alert_results, cursor_results]


def dataminrpulse_vulnerability_enrich_command(client: DataminrPulseReGenAIClient, args: Dict[str, Any]) -> list[CommandResults]:
    """
    Enrich the "Dataminr Pulse Vulnerability Indicator" custom indicator with relevant data.

    :type client: ``DataminrPulseReGenAIClient``
    :param client: DataminrPulseReGenAIClient to be used.

    :type args: ``Dict[str, Any]``
    :param args: Arguments provided by user.

    :rtype: ``CommandResults``
    :return: Standard command result.
    """
    vulnerability_json_data: Any = args.get("vulnerability_json_data")
    vulnerability_list: list = []

    if not vulnerability_json_data:
        raise ValueError(ERRORS["REQUIRED_ARG"].format("vulnerability_json_data"))

    try:
        vulnerability_list = json.loads(vulnerability_json_data)
    except json.JSONDecodeError:
        raise ValueError(ERRORS["JSON_DECODE"].format("vulnerability_json_data"))

    results = []
    if not vulnerability_list:
        return CommandResults(readable_output="No vulnerabilities found.")  # type: ignore

    for vulnerability in vulnerability_list:
        indicator_value = vulnerability.get("id", "")

        dbot_score = Common.DBotScore(
            indicator=indicator_value,
            indicator_type=DBotScoreType.CUSTOM,
            integration_name=VENDOR_NAME,
            score=calculate_dbot_score(float(vulnerability.get("cvss", Common.DBotScore.NONE))),
            reliability=demisto.params().get("integrationReliability", DEFAULT_RELIABILITY),
        )

        custom_indicator = Common.CustomIndicator(
            value=indicator_value,
            indicator_type="Dataminr Pulse Vulnerability Indicator",
            data=remove_empty_elements(vulnerability),
            context_prefix="DataminrPulseVulnerabilityIndicator",
            dbot_score=dbot_score,
        )

        hr = tableToMarkdown("Vulnerability", remove_empty_elements_for_hr(vulnerability), is_auto_json_transform=True)

        results.append(
            CommandResults(
                outputs=remove_empty_elements(vulnerability),
                outputs_prefix=CUSTOM_OUTPUT_PREFIX.format("Vulnerability"),
                outputs_key_field="id",
                indicator=custom_indicator,
                raw_response=vulnerability,
                readable_output=hr,
            )
        )

    return results


def dataminrpulse_malware_enrich_command(client: DataminrPulseReGenAIClient, args: Dict[str, Any]) -> list[CommandResults]:
    """
    Enrich the "Dataminr Pulse Malware Indicator" custom indicator with relevant data.

    :type client: ``DataminrPulseReGenAIClient``
    :param client: DataminrPulseReGenAIClient to be used.

    :type args: ``Dict[str, Any]``
    :param args: Arguments provided by user.

    :rtype: ``CommandResults``
    :return: Standard command result.
    """
    malware_json_data: Any = args.get("malware_json_data")
    malware_list: list = []

    if not malware_json_data:
        raise ValueError(ERRORS["REQUIRED_ARG"].format("malware_json_data"))

    try:
        malware_list = json.loads(malware_json_data)
    except json.JSONDecodeError:
        raise ValueError(ERRORS["JSON_DECODE"].format("malware_json_data"))

    results = []
    if not malware_list:
        return CommandResults(readable_output="No malware found.")  # type: ignore

    for malware in malware_list:
        indicator_value = malware.get("name", "")

        dbot_score = Common.DBotScore(
            indicator=indicator_value,
            indicator_type=DBotScoreType.CUSTOM,
            integration_name=VENDOR_NAME,
            score=Common.DBotScore.BAD,
            reliability=demisto.params().get("integrationReliability", DEFAULT_RELIABILITY),
        )

        relationships = []
        if demisto.params().get("create_relationships", True):
            relationships = create_relationship_for_malware(malware)

        custom_indicator = Common.CustomIndicator(
            value=indicator_value,
            indicator_type="Dataminr Pulse Malware Indicator",
            data=remove_empty_elements(malware),
            context_prefix="DataminrPulseMalwareIndicator",
            dbot_score=dbot_score,
            relationships=relationships,
        )

        hr = tableToMarkdown("Malware", remove_empty_elements_for_hr(malware), is_auto_json_transform=True)

        results.append(
            CommandResults(
                outputs=remove_empty_elements(malware),
                outputs_prefix=CUSTOM_OUTPUT_PREFIX.format("Malware"),
                outputs_key_field="name",
                indicator=custom_indicator,
                raw_response=malware,
                readable_output=hr,
            )
        )

    return results


def dataminrpulse_threat_actor_enrich_command(client: DataminrPulseReGenAIClient, args: Dict[str, Any]) -> list[CommandResults]:
    """
    Enrich the "Dataminr Pulse Threat Actor Indicator" custom indicator with relevant data.

    :type client: ``DataminrPulseReGenAIClient``
    :param client: DataminrPulseReGenAIClient to be used.

    :type args: ``Dict[str, Any]``
    :param args: Arguments provided by user.

    :rtype: ``CommandResults``
    :return: Standard command result.
    """
    threat_actor_json_data: Any = args.get("threat_actor_json_data")
    threat_actor_list: list = []

    if not threat_actor_json_data:
        raise ValueError(ERRORS["REQUIRED_ARG"].format("threat_actor_json_data"))

    try:
        threat_actor_list = json.loads(threat_actor_json_data)
    except json.JSONDecodeError:
        raise ValueError(ERRORS["JSON_DECODE"].format("threat_actor_json_data"))

    results = []
    if not threat_actor_list:
        return CommandResults(readable_output="No threat actors found.")  # type: ignore

    for threat_actor in threat_actor_list:
        indicator_value = threat_actor.get("name", "")

        dbot_score = Common.DBotScore(
            indicator=indicator_value,
            indicator_type=DBotScoreType.CUSTOM,
            integration_name=VENDOR_NAME,
            score=Common.DBotScore.BAD,
            reliability=demisto.params().get("integrationReliability", DEFAULT_RELIABILITY),
        )

        custom_indicator = Common.CustomIndicator(
            value=indicator_value,
            indicator_type="Dataminr Pulse Threat Actor Indicator",
            data=remove_empty_elements(threat_actor),
            context_prefix="DataminrPulseThreatActorIndicator",
            dbot_score=dbot_score,
        )

        hr = tableToMarkdown("Threat Actor", remove_empty_elements_for_hr(threat_actor), is_auto_json_transform=True)

        results.append(
            CommandResults(
                outputs=remove_empty_elements(threat_actor),
                outputs_prefix=CUSTOM_OUTPUT_PREFIX.format("ThreatActor"),
                outputs_key_field="name",
                indicator=custom_indicator,
                raw_response=threat_actor,
                readable_output=hr,
            )
        )

    return results


def main():
    """main function, parses params and runs command functions"""

    # Retrieve the configuration parameters.
    params = trim_spaces_from_args(demisto.params())
    remove_nulls_from_dictionary(params)

    # Credentials for connecting with the Dataminr Pulse API.
    client_id = params.get("credentials", {}).get("identifier")
    client_secret = params.get("credentials", {}).get("password")

    # Default configuration parameters for handling proxy and SSL Certificate validation.
    verify_certificate = not argToBoolean(params.get("insecure", False))
    proxy = argToBoolean(params.get("proxy", False))

    # Parameters for fetch incident mechanism
    watchlist_names = params.get("watchlist_names")

    # Retrieve the name of the command being called.
    command = demisto.command()
    demisto.debug(f"The command being called is {command}.")

    demisto_commands: Dict[str, Callable] = {
        "dataminrpulse-watchlists-get": dataminrpulse_watchlists_get_command,
        "dataminrpulse-alerts-get": dataminrpulse_alerts_get,
        "dataminrpulse-vulnerability-enrich": dataminrpulse_vulnerability_enrich_command,
        "dataminrpulse-malware-enrich": dataminrpulse_malware_enrich_command,
        "dataminrpulse-threat-actor-enrich": dataminrpulse_threat_actor_enrich_command,
    }

    try:
        client = DataminrPulseReGenAIClient(
            client_id=client_id, client_secret=client_secret, proxy=proxy, verify=verify_certificate
        )

        # Execute the respective command function based on the command name got from the Demisto.
        if command == "test-module":
            return_results(test_module(client))
        elif command == "fetch-incidents":
            last_run = demisto.getLastRun()
            next_run, incidents = fetch_incidents(client, last_run, params)
            demisto.info(f"Fetched {len(incidents)} new incidents")
            demisto.incidents(incidents)
            demisto.setLastRun(next_run)
        elif command in demisto_commands:
            args = demisto.args()
            if command == "dataminrpulse-alerts-get":
                args.update({"watchlist_names": watchlist_names})
            remove_nulls_from_dictionary(trim_spaces_from_args(args))
            return_results(demisto_commands[command](client, args))
        else:
            raise NotImplementedError(f"The command {command} is not implemented.")

    # Log exceptions and return errors
    except Exception as e:
        demisto.error(traceback.format_exc())  # Print the traceback.
        return_error(f"Failed to execute {command} command.\nError: \n{str(e)}")


if __name__ in ("__main__", "__builtin__", "builtins"):  # pragma: no cover
    main()
