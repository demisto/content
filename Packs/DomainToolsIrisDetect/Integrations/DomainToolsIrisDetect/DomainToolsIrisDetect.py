"""
DomainTools Iris Detect XSOAR Integration
"""

from hashlib import sha256
from hmac import new
from math import ceil
from collections.abc import Callable
from urllib.parse import urlencode, urlunparse
from urllib3 import disable_warnings
from CommonServerPython import *  # noqa # pylint: disable=unused-wildcard-import

# Disable insecure warnings
disable_warnings()  # pylint: disable=no-member

""" CONSTANTS """

INTEGRATION_CONTEXT_NAME = "DomainToolsIrisDetect"
DOMAINTOOLS_PARAMS: Dict[str, Any] = {
    "app_partner": "cortex_xsoar",
    "app_name": "iris_detect_for_xsoar",
    "app_version": "1",
}

DEFAULT_HEADERS: Dict[str, str] = {
    "accept": "application/json",
    "Content-Type": "application/json",
}
TIMEOUT = 60.0
RETRY = 3
DOMAINTOOLS_API_BASE_URL = "api.domaintools.com"
DOMAINTOOLS_API_VERSION = "v1"

DOMAINTOOLS_MANAGE_WATCHLIST_ENDPOINT = (
    f"/{DOMAINTOOLS_API_VERSION}/iris-detect/domains/"
)
DOMAINTOOLS_NEW_DOMAINS_ENDPOINT = (
    f"/{DOMAINTOOLS_API_VERSION}/iris-detect/domains/new/"
)
DOMAINTOOLS_WATCHED_DOMAINS_ENDPOINT = (
    f"/{DOMAINTOOLS_API_VERSION}/iris-detect/domains/watched/"
)
DOMAINTOOLS_IGNORED_DOMAINS_ENDPOINT = (
    f"/{DOMAINTOOLS_API_VERSION}/iris-detect/domains/ignored/"
)
DOMAINTOOLS_MONITOR_DOMAINS_ENDPOINT = (
    f"/{DOMAINTOOLS_API_VERSION}/iris-detect/monitors/"
)
DOMAINTOOLS_ESCALATE_DOMAINS_ENDPOINT = (
    f"/{DOMAINTOOLS_API_VERSION}/iris-detect/escalations/"
)

DOMAINTOOLS_ESCALATE_DOMAINS_HEADER = "Escalated Domains"
DOMAINTOOLS_WATCHED_DOMAINS_HEADER = "Watched Domains"
DOMAINTOOLS_IGNORE_DOMAINS_HEADER = "Ignored Domains"
DOMAINTOOLS_BLOCKED_DOMAINS_HEADER = "Blocked Domains"
DOMAINTOOLS_NEW_DOMAINS_HEADER = "New Domains"
DOMAINTOOLS_MONITORS_HEADER = "Monitor List"
DOMAINTOOLS_NEW_DOMAINS_INCIDENT_NAME = "DomainTools Iris Detect New Domains Since"
DOMAINTOOLS_CHANGED_DOMAINS_INCIDENT_NAME = (
    "DomainTools Iris Detect Changed Domains Since"
)
DOMAINTOOLS_BLOCKED_DOMAINS_INCIDENT_NAME = (
    "DomainTools Iris Detect Blocked Domains Since"
)
NEW_DOMAIN_TIMESTAMP = "new_domain_last_run"
CHANGED_DOMAIN_TIMESTAMP = "changed_domain_last_run"
DT_TIMESTAMP_DICT = {
    NEW_DOMAIN_TIMESTAMP: "discovered_since",
    CHANGED_DOMAIN_TIMESTAMP: "changed_since",
}
CONTEXT_PATH_KEY = {
    DOMAINTOOLS_ESCALATE_DOMAINS_HEADER: "Escalated",
    DOMAINTOOLS_WATCHED_DOMAINS_HEADER: "Watched",
    DOMAINTOOLS_IGNORE_DOMAINS_HEADER: "Ignored",
    DOMAINTOOLS_BLOCKED_DOMAINS_HEADER: "Blocked",
    DOMAINTOOLS_NEW_DOMAINS_HEADER: "New",
    DOMAINTOOLS_MONITORS_HEADER: "Monitor",
}
INCIDENT_TYPE = {
    DOMAINTOOLS_NEW_DOMAINS_INCIDENT_NAME: "DomainTools Iris Detect New Domains",
    DOMAINTOOLS_CHANGED_DOMAINS_INCIDENT_NAME: "DomainTools Iris Detect Changed Domains",
    DOMAINTOOLS_BLOCKED_DOMAINS_INCIDENT_NAME: "DomainTools Iris Detect Blocked Domains",
}
INDICATOR_TYPE = "DomainTools Iris Detect"
INCLUDE_DOMAIN_DATA_VALUE = 1
DATE_TIME_FORMAT = "%Y-%m-%dT%H:%M:%SZ"  # ISO8601 format with UTC, default in XSOAR
NO_DOMAINS_FOUND = "No Domains Found."
LIMIT_ERROR_MSG = "Invalid Input Error: limit should be greater than zero."
DEFAULT_DAYS_BACK = "3 days"
MAX_DAYS_BACK = 30
DATE_FORMAT = "%Y-%m-%d %H:%M:%S.%f"
DEFAULT_PAGE_SIZE = 50
DEFAULT_OFFSET = 0
PAGE_NUMBER_ERROR_MSG = "Invalid Input Error: page number should be greater than zero."
PAGE_SIZE_ERROR_MSG = "Invalid Input Error: page size should be greater than zero."
MONITOR_DOMAINS_LIMIT = 500
INCLUDE_COUNTS_LIMIT = 100
INCLUDE_DOMAIN_DATA_LIMIT = 50
DEFAULT_LIMIT = 100
DEFAULT_PREVIEW_LIMIT = 10
BATCH_SIZE = 2000


class DTSigner:
    """
    A class for generating digital signatures using the DomainTools API.

    Args:
        api_username (str): The API username for the DomainTools API.
        api_key (str): The API key for the DomainTools API.

    Attributes:
        api_username (str): The API username for the DomainTools API.
        api_key (str): The API key for the DomainTools API.

    Methods:
        sign(timestamp, uri): Generates a digital signature for the given timestamp and URI.
    """

    def __init__(self, api_username: str, api_key: str) -> None:
        self.api_username = api_username
        self.api_key = api_key

    def sign(self, timestamp: str, uri: str) -> str:
        """
        Generates a digital signature for the given timestamp and URI.

        Args:
            timestamp (str): The timestamp to include in the signature.
            uri (str): The URI to include in the signature.

        Returns:
            str: The generated digital signature.
        """
        params = "".join([self.api_username, timestamp, uri])
        return new(
            self.api_key.encode("utf-8"), params.encode("utf-8"), digestmod=sha256
        ).hexdigest()


""" CLIENT CLASS """


class Client(BaseClient):
    """
    This Client implements API calls, and does not contain any XSOAR logic.
    Should only do requests and return data.
    It inherits from BaseClient defined in CommonServer Python.
    Most calls use _http_request() that handles proxy, SSL verification, etc.
    For this implementation, no special attributes defined
    Args:
          username (str): Domaintools username.
          api_key (str): Domaintools api key.
          new_domains (str): Specifies the action for new domains, either "Import Indicators Only" or
          "Create Incidents and Import Indicators".
          changed_domains (str): Specifies the action for changed domains, either "Import Indicators Only" or
          "Create Incidents and Import Indicators".
          blocked_domains (str): Specifies the action for blocked domains, either "Import Indicators Only" or
          "Create Incidents and Import Indicators"
          risk_score_ranges(List): List of risk score ranges to filter domains by
          include_domain_data(bool): specifies whether to include DomainTools
          Iris Detect Whois, DNS Records or not.
          verify (bool): specifies whether to verify the SSL certificate or not.
          proxy (bool): specifies if to use XSOAR proxy settings.
    """

    def __init__(
        self,
        username: str,
        api_key: str,
        new_domains: str,
        changed_domains: str,
        blocked_domains: str,
        risk_score_ranges: List,
        include_domain_data: Optional[bool] = None,
        first_fetch: str = "3 days",
        fetch_limit: Optional[int] = 50,
        verify=None,
        proxy=None,
    ):
        super().__init__(
            DOMAINTOOLS_API_BASE_URL,
            verify=verify,
            headers=DEFAULT_HEADERS,
            proxy=proxy,
        )
        self.username = username
        self.api_key = api_key
        self.risk_score_ranges = risk_score_ranges
        self.include_domain_data = include_domain_data
        self.first_fetch = first_fetch
        self.fetch_limit = fetch_limit
        self.new_domains = new_domains
        self.changed_domains = changed_domains
        self.blocked_domains = blocked_domains

    def query_dt_api(self, end_point: str, method: str, **kwargs):
        """
        Send a query to the DomainTools Iris API and get the response.

        Args:
            end_point (str): DomainTools Iris API endpoint to send the query_dt_api to.
            method (str): The HTTP method to use for the request ('GET', 'POST', 'PATCH').
            kwargs: Additional parameters for the request:
                params (Dict): URL parameters to include in the request.
                json_data (Dict): JSON data to include in the request.

        Returns:
            response (requests.Response): The server response from the DomainTools Iris API.
        """
        signer = DTSigner(self.username, self.api_key)
        timestamp = datetime.utcnow().strftime(DATE_TIME_FORMAT)

        query = {
            "api_username": self.username,
            "signature": signer.sign(timestamp, end_point),
            "timestamp": timestamp,
        }
        full_url = urlunparse(
            ("https", DOMAINTOOLS_API_BASE_URL, end_point, "", urlencode(query), None)
        )
        return self._http_request(
            method=method,
            full_url=full_url,
            headers=DEFAULT_HEADERS,
            params=kwargs.get("params", {}),
            json_data=kwargs.get("json_data", {}),
            timeout=TIMEOUT,
            retries=RETRY,
            error_handler=dt_error_handler,
        )

    def create_indicator_from_detect_domain(
        self, item: Dict, term: Dict
    ) -> Dict[str, Any]:
        """Return the indicator object for the given DomainTools Iris Detect domain object.

        Args:
            item (Dict): A DomainTools Iris Detect domain object.
            term (Dict): A dictionary to get term values from the monitor list.

        Returns:
            Dict: The indicator object containing various fields and values.
        """
        risk_score_components = flatten_nested_dict(
            item.get("risk_score_components", {})
        )

        return {
            "name": "DomainTools Iris Detect",
            "value": item.get("domain", ""),
            "occurred": item.get("discovered_date", ""),
            "type": INDICATOR_TYPE,
            "rawJSON": item,
            "fields": {
                "irisdetectterm": item.get("monitor_term"),
                "domainname": item.get("domain", ""),
                "creation_date": item.get("discovered_date", ""),
                "updated_date": item.get("changed_date", ""),
                "domain_status": item.get("status", ""),
                "irisdetectdiscovereddate": item.get("discovered_date", ""),
                "irisdetectchangeddate": item.get("changed_date", ""),
                "irisdetectdomainstatus": item.get("status", ""),
                "irisdetectdomainstate": (
                    "blocked"
                    if any(
                        result.get("escalation_type", "") == "blocked"
                        for result in item.get("escalations", [])
                    )
                    else item.get("state", "")
                ),
                "domaintoolsriskscore": item.get("risk_score", ""),
                "domaintoolsriskscorestatus": item.get("risk_score_status", ""),
                "irisdetectdomainid": item.get("id", ""),
                "irisdetectescalations": [
                    {
                        "escalationtype": result.get("escalation_type", ""),
                        "id": result.get("id", ""),
                        "created": result.get("created", ""),
                        "createdby": result.get("created_by", ""),
                    }
                    for result in item.get("escalations", [])
                ],
                "irisdetecthostingipdetails": [
                    {
                        "countrycode": result.get("country_code", ""),
                        "ip": result.get("ip", ""),
                        "isp": result.get("isp", ""),
                    }
                    for result in item.get("ip", [])
                ],
                "registrant_name": item.get("registrar", ""),
                "registrant_email": ", ".join(item.get("registrant_contact_email", [])),
                "name_servers": ", ".join(
                    result.get("host", "") for result in item.get("name_server", [])
                ),
                "irisdetectmailserversexists": item.get("mx_exists", ""),
                "irisdetectmailserverdetails": [
                    {"host": result.get("host", "")} for result in item.get("mx", [])
                ],
                "domaintoolsriskscorecomponents": {
                    key: risk_score_components.get(key, "")
                    for key in ["proximity", "phishing", "malware", "spam", "evidence"]
                },
                "last_seen_by_source": item.get("changed_date", ""),
                "first_seen_by_source": item.get("discovered_date", ""),
            },
        }

    def process_dt_domains_into_xsoar(
        self,
        domains_list: List[Dict[str, Any]],
        incident_name: str,
        last_run: str,
        term: Dict[str, Any],
        enable_incidents: bool = True,
    ) -> List[Any]:
        """
        Create indicators and, optionally, an incident in XSOAR for a list of
        DomainTools Iris Detect domains.

        Args:
            domains_list (List[Dict[str, Any]]): A list of DomainTools Iris Detect domain objects.
            incident_name (str): The name of the incident to be created based on the domain type.
            term (Dict[str, Any]): A dictionary containing the domains that need to be monitored.
            last_run (str): A timestamp string indicating the last run.
            enable_incidents (bool): Specifies whether to create an incident or not. Default is True.

        Returns:
            List[Dict[str, Any]]: A list containing the incident object if one was created,
            otherwise an empty list.
        """
        for domain in domains_list:
            domain["monitor_term"] = join_dict_values_for_keys(
                domain.get("monitor_ids", []), term
            )
        indicators = [
            self.create_indicator_from_detect_domain(item, term)
            for item in domains_list
        ]
        if not indicators:
            return []

        for batched in batch(indicators, batch_size=BATCH_SIZE):
            demisto.createIndicators(batched)
        demisto.info(f"Added {len(indicators)} indicators to demisto")

        if enable_incidents:
            last_run_dt_without_ms = (
                datetime.strptime(get_last_run(last_run), DATE_FORMAT).replace(
                    microsecond=0
                )
                if get_last_run(last_run)
                else None
            )
            first_run_dt_without_ms = (
                datetime.now() - timedelta(days=validate_first_fetch(self.first_fetch))
            ).replace(microsecond=0)
            incident = {
                "name": f"{incident_name} "
                f"{last_run_dt_without_ms or first_run_dt_without_ms}",
                "details": json.dumps(domains_list),
                "rawJSON": json.dumps({"incidents": domains_list}),
                "type": INCIDENT_TYPE[incident_name],
            }
            return [incident]

        return []

    def fetch_dt_domains_from_api(
        self, end_point: str, last_run: str
    ) -> tuple[List[Dict], str]:
        """
        Makes an API call to the Domain Tools API endpoint and retrieves domain data based on the provided
        parameters.

        Args:
            end_point (str): The API endpoint to call.
            last_run (str): The timestamp of the last successful API call.

        Returns:
            Tuple[List[Dict], str]: A tuple containing a list of watchlist domains and a timestamp of the current
            API call.

        """

        last_run_value = get_last_run(last_run)
        if last_run_value:
            params = DOMAINTOOLS_PARAMS | {
                DT_TIMESTAMP_DICT[last_run]: last_run_value,
                "include_domain_data": (
                    INCLUDE_DOMAIN_DATA_VALUE if self.include_domain_data else 0
                ),
            }
            demisto.info(f"Found last run, fetching domains from {last_run_value}")
        else:
            days_back = validate_first_fetch(self.first_fetch)
            params = DOMAINTOOLS_PARAMS | {
                DT_TIMESTAMP_DICT[last_run]: datetime.now() - timedelta(days=days_back),
                "include_domain_data": (
                    INCLUDE_DOMAIN_DATA_VALUE if self.include_domain_data else 0
                ),
            }
            demisto.info(f"First run, fetching domains from last {days_back} days")

        if self.risk_score_ranges:
            params["risk_score_ranges[]"] = self.risk_score_ranges

        results: List = []
        while True:
            response = self.query_dt_api(end_point, "GET", params=params)
            results.extend(response.get("watchlist_domains", []))
            if response.get("total_count") == len(results):
                break
            params["offset"] = response.get("offset") + response.get("limit")
        return results, str(datetime.utcnow())

    def fetch_and_process_domains(self) -> None:
        """Fetches DomainTools domain information and creates incidents in XSOAR."""

        def process_domains(
            process_endpoint: str,
            process_timestamp_key: str,
            process_incident_name: str,
            import_only: bool,
            process_filter_func: Optional[
                Callable[[List[Dict[str, Any]]], List[Dict[str, Any]]]
            ] = None,
        ) -> str:
            """
            Process domains by calling DomainTools API, filtering results, and converting them into XSOAR incidents.

            Args:
                process_endpoint (str): The DomainTools API endpoint to call.
                process_timestamp_key (str): The key for the timestamp of the domain.
                process_incident_name (str): The incident name to use for the created incidents.
                import_only (bool): If True, import only indicators.
                process_filter_func (Optional[Callable[[List[Dict[str, Any]]], List[Dict[str, Any]]]]):
                 Optional function to filter the domains.

            Returns:
                str: The last run timestamp.
            """
            domains_list, last_run = self.fetch_dt_domains_from_api(
                process_endpoint, process_timestamp_key
            )
            if process_filter_func:
                domains_list = process_filter_func(domains_list)
            incidents.extend(
                self.process_dt_domains_into_xsoar(
                    domains_list,
                    process_incident_name,
                    process_timestamp_key,
                    term,
                    not import_only,
                )
            )
            return last_run

        def filter_blocked_domains(
            domains: List[Dict[str, Any]]
        ) -> List[Dict[str, Any]]:
            """
            Filters the list of domains to return only the blocked domains.

            Args:
                domains (List[Dict[str, Any]]): The list of domains to filter.

            Returns:
                List[Dict[str, Any]]: The filtered list of blocked domains.
            """
            return [
                domain
                for domain in domains
                if domain.get("escalations")
                and any(
                    escalation.get("escalation_type") == "blocked"
                    for escalation in domain["escalations"]
                )
            ]

        monitor_result = self.query_dt_api(
            DOMAINTOOLS_MONITOR_DOMAINS_ENDPOINT, "GET", params=DOMAINTOOLS_PARAMS
        )
        term = {
            results.get("id"): results.get("term")
            for results in monitor_result.get("monitors", [])
        }
        incidents: List[Any] = []

        domains_to_process = [
            (
                DOMAINTOOLS_WATCHED_DOMAINS_ENDPOINT,
                CHANGED_DOMAIN_TIMESTAMP,
                DOMAINTOOLS_CHANGED_DOMAINS_INCIDENT_NAME,
                self.changed_domains,
                None,  # add default value for filter_func parameter
            ),
            (
                DOMAINTOOLS_WATCHED_DOMAINS_ENDPOINT,
                CHANGED_DOMAIN_TIMESTAMP,
                DOMAINTOOLS_BLOCKED_DOMAINS_INCIDENT_NAME,
                self.blocked_domains,
                filter_blocked_domains,
            ),
            (
                DOMAINTOOLS_NEW_DOMAINS_ENDPOINT,
                NEW_DOMAIN_TIMESTAMP,
                DOMAINTOOLS_NEW_DOMAINS_INCIDENT_NAME,
                self.new_domains,
                None,  # add default value for filter_func parameter
            ),
        ]

        last_runs = {CHANGED_DOMAIN_TIMESTAMP: "", NEW_DOMAIN_TIMESTAMP: ""}

        for (
            endpoint,
            timestamp_key,
            incident_name,
            domain_setting,
            filter_func,
        ) in domains_to_process:
            if domain_setting:
                last_runs[timestamp_key] = process_domains(
                    endpoint,
                    timestamp_key,
                    incident_name,
                    domain_setting == "Import Indicators Only",
                    filter_func,
                )

        demisto.setIntegrationContext(last_runs)
        demisto.info(f"Adding {len(incidents)} incidents to demisto")
        demisto.incidents(incidents)


def join_dict_values_for_keys(key_ids: List, term: Dict) -> str:
    """
    Generates the term to use for a DomainTools Iris Detect API request.

    Args:
        key_ids (List): The key_ids to use to generate the monitor term.
        term (Dict): The term to update with the generated term.

    Returns:
        str: The generated term.

    """
    values = [term.get(key, "") for key in key_ids]
    return ", ".join(filter(None, values)) if any(values) else ""


def validate_first_fetch(value: str) -> int:
    """
    Validates the input value of first_fetch and returns the corresponding number of days back.

    Args:
        value (str): The input value for first_fetch.

    Returns:
        int: The number of days back.

    """
    try:
        days_ago = int(value.strip().split()[0])
        if days_ago <= 0:
            days_ago = MAX_DAYS_BACK
    except (ValueError, IndexError):
        days_ago = MAX_DAYS_BACK

    return min(MAX_DAYS_BACK, days_ago)


def get_last_run(context_key) -> str:
    """
    Gets last run time
    Returns:
        last run for specific domain type.
    """
    return demisto.getIntegrationContext().get(context_key)


def fetch_domains(client: Client) -> bool:
    """
    Calling fetch_and_process_domains.

    Args:
        client(object): Client class object.
    """
    client.fetch_and_process_domains()
    return True


def module_test(client: Client) -> str:
    """
    Tests API connectivity and authentication
    When 'ok' is returned it indicates the integration works like
    it is supposed to and connection to the service is successful.
    Args:
        client(Client): Client class object.
    Returns:
        Connection ok.
    """
    DOMAINTOOLS_PARAMS["preview"] = True
    client.query_dt_api(
        DOMAINTOOLS_NEW_DOMAINS_ENDPOINT,
        "GET",
        params=DOMAINTOOLS_PARAMS,
    )
    return "ok"


def dt_error_handler(response: requests.Response) -> None:
    """
    Error Handler for DomainTools Iris Detect
    Args:
        response (response): DomainTools Iris Detect response
    Raise:
        DemistoException
    """

    specific_error_messages = {
        400: "Bad Request: The request was invalid or cannot be otherwise served.",
        401: "Unauthorized: Authentication is required and has failed or has not been provided.",
        403: "Forbidden: The request is understood, but it has been refused or access is not allowed.",
        404: "Not Found: The requested resource could not be found.",
        500: "Internal Server Error: An error occurred on the server side.",
        206: "Partial Content: The requested resource has been partially returned.",
    }

    if response.status_code in {206} | set(range(400, 600)):
        try:
            error_json = response.json().get("error", {})
            error_message = (
                error_json.get("message")
                or " ".join(error_json.get("messages", []))
                or specific_error_messages.get(
                    response.status_code, "An unknown error occurred."
                )
            )
        except ValueError:
            error_message = specific_error_messages.get(
                response.status_code, "An unknown error occurred."
            )

        raise DemistoException(error_message, res=response)


def format_common_fields(result: Dict[Any, Any]) -> Dict[str, Any]:
    """
    Formats the common fields of the given result dictionary.

    Args:
        result (Dict[Any, Any]): The input result dictionary containing the raw data.

    Returns:
        Dict[str, Any]: A formatted dictionary with the common fields mapped to their respective keys.
    """

    return {
        "dt_domain": result.get("domain"),
        "dt_state": result.get("state"),
        "dt_status": result.get("status"),
        "dt_discovered_date": result.get("discovered_date"),
        "dt_changed_date": result.get("changed_date"),
        "dt_escalations": result.get("escalations"),
        "dt_risk_score": result.get("risk_score"),
        "dt_risk_status": result.get("risk_score_status"),
        "dt_mx_exists": result.get("mx_exists"),
        "dt_tld": result.get("tld"),
        "dt_domain_id": result.get("id"),
        "dt_monitor_ids": result.get("monitor_ids"),
        "dt_create_date": result.get("create_date"),
        "dt_registrar": result.get("registrar"),
        "dt_registrant_contact_email": result.get("registrant_contact_email"),
    }


def format_monitor_fields(result: Dict[Any, Any]) -> Dict[str, Any]:
    """
    Formats the monitor fields.

    Args:
        result (Dict[Any, Any]): The input result dictionary containing the raw data.

    Returns:
        Dict[str, Any]: A formatted dictionary with the monitor fields mapped to their respective keys.
    """

    return {
        "dt_term": result.get("term"),
        "dt_monitor_id": result.get("id"),
        "dt_state": result.get("state"),
        "dt_match_substring_variations": result.get("match_substring_variations"),
        "dt_nameserver_exclusions": result.get("nameserver_exclusions"),
        "dt_text_exclusions": result.get("text_exclusions"),
        "dt_created_date": result.get("created_date"),
        "dt_updated_date": result.get("updated_date"),
        "dt_status": result.get("status"),
        "dt_created_by": result.get("created_by"),
    }


def format_blocklist_fields(result: Dict[Any, Any]) -> Dict[str, Any]:
    """
    Formats the block list fields.

    Args:
        result (Dict[Any, Any]): The input result dictionary containing the raw data.

    Returns:
        Dict[str, Any]: A formatted dictionary with the block fields mapped to their respective keys.
    """
    return {
        "dt_watchlist_domain_id": result.get("watchlist_domain_id"),
        "dt_escalation_type": result.get("escalation_type"),
        "dt_id": result.get("id"),
        "dt_created_date_result": result.get("created_date"),
        "dt_updated_date": result.get("updated_date"),
        "dt_created_by": result.get("created_by"),
    }


def format_watchlist_fields(result: Dict[Any, Any]) -> Dict[str, Any]:
    """
    Formats the watchlist fields.

    Args:
        result (Dict[Any, Any]): The input result dictionary containing the raw data.

    Returns:
        Dict[str, Any]: A formatted dictionary with the watch fields mapped to their respective keys.
    """
    return {
        "dt_domain": result.get("domain"),
        "dt_state": result.get("state"),
        "dt_discovered_date": result.get("discovered_date"),
        "dt_changed_date": result.get("changed_date"),
        "dt_domain_id": result.get("id"),
    }


def format_data(
    result: Dict[str, List[Dict[str, Any]]],
    field: str,
    output_prefix: str,
    data_key: str,
) -> Dict[str, Any]:
    """
    Extracts and formats data.

    Args:
        result: A dictionary containing data to be formatted.
        field: The key for the field in the `result` dictionary that contains the relevant data.
        output_prefix: A prefix to use when creating keys for the formatted output.
        data_key: The key for the data within each item in the `field` list.

    Returns:
        A dictionary with the formatted data. If the data is empty or missing, returns None.
        If the data contains a single item, returns a dictionary with the formatted data.
        If the data contains multiple items, returns a list of dictionaries, each with the formatted data.
    """
    data = result.get(field, [])
    output = {f"{output_prefix}_raw": data if data else None}

    for count, item in enumerate(data, start=1):
        output[f"{output_prefix}_{count}"] = item.get(data_key)

    return output


def format_risk_score_components(result: Dict[Any, Any]) -> Dict[str, Any]:
    """
    Map fields from Iris Detect risk score components.

    Args:
        result(Dict): Domain Object
    Returns:
        Dict: mapped risk score components object
    """
    components = result.get("risk_score_components", {})
    threat_profile = components.get("threat_profile", {})
    return {
        "dt_proximity_score": components.get("proximity"),
        "dt_threat_profile_malware": threat_profile.get("malware"),
        "dt_threat_profile_phishing": threat_profile.get("phishing"),
        "dt_threat_profile_spam": threat_profile.get("spam"),
        "dt_threat_profile_evidence": threat_profile.get("evidence"),
    }


def flatten_nested_dict(nested_dict: Dict[Any, Any]) -> Dict[str, Any]:
    """
    To flatten dict.

    Args:
        nested_dict(Dict): nested dict
    Returns:
        Dict: flatted dict
    """

    result: Dict[Any, Any] = {}
    for key, value in nested_dict.items():
        if isinstance(value, dict):
            result.update(flatten_nested_dict(value))
        else:
            result[key] = value
    return result


def create_common_api_arguments(args: Dict[str, Any]) -> Dict[str, Any]:
    """
    Constructs a dictionary of arguments that are commonly used when querying the DomainTools Iris Detect API.

    Args:
        args (Dict[str, Any]): A dictionary of arguments specifying the options for retrieving domains.

    Returns:
        Dict[str, Any]: A dictionary of arguments to use when querying the DomainTools Iris API.
            - "monitor_id" (str): The ID of the monitor to filter domains by.
            - "tlds[]" (List[str]): A list of TLDs to filter domains by.
            - "include_domain_data" (bool): Whether to include full domain data in the response.
            - "risk_score_ranges[]" (List[str]): A list of risk score ranges to filter domains by.
            - "sort[]" (List[str]): A list of fields to sort the results by.
            - "order" (str): The order to sort the results by ("asc" or "desc").
            - "mx_exists" (bool): Whether to filter domains by whether they have MX records.
            - "preview" (bool): Whether to return only a preview of the results.
            - "search" (str): A search query to filter domains by.
            - "limit" (int): The maximum number of results to return.
            - "page" (int): The page number of the results to retrieve.
            - "page_size" (int): The number of results to display per page.
    """
    return {
        "monitor_id": args.get("monitor_id"),
        "tlds[]": argToList(args.get("tlds")),
        "include_domain_data": (
            argToBoolean(args.get("include_domain_data"))
            if args.get("include_domain_data")
            else None
        ),
        "risk_score_ranges[]": argToList(args.get("risk_score_ranges")),
        "sort[]": argToList(args.get("sort")),
        "order": args.get("order"),
        "mx_exists": (
            argToBoolean(args.get("mx_exists")) if args.get("mx_exists") else None
        ),
        "preview": argToBoolean(args.get("preview")) if args.get("preview") else None,
        "search": args.get("search"),
        "limit": arg_to_number(args.get("limit")),
        "page": arg_to_number(args.get("page")),
        "page_size": arg_to_number(args.get("page_size")),
    }


def create_escalated_api_arguments(args: Dict[str, Any]) -> Dict[str, Any]:
    """
    Constructs a dictionary of arguments to use when query the DomainTools Iris API for escalated domains.

    Args:
        args (Dict): A dictionary of arguments specifying the options for retrieving escalated domains.

    Returns:
        Dict: A dictionary of arguments to use when query the DomainTools Iris API for escalated domains.
            - "escalated_since" (str): The start of the escalation period to search for.
            - "escalation_types[]" (List[str]): A list of escalation types to filter by.
            - "changed_since" (str): The start of the date range to filter domains that have changed since.
            - "discovered_since" (str): The start of the date range to filter domains that have been discovered since.
    """
    return {
        "escalated_since": args.get("escalated_since"),
        "escalation_types[]": args.get("escalation_types"),
        "changed_since": args.get("changed_since"),
    }


def pagination(
    page: Optional[int], page_size: Optional[int], limit: Optional[int]
) -> tuple[int, int]:
    """
    Define pagination.
    Args:
       limit: Records per page.
       page: The page number.
       page_size: The number of requested results per page.
    Returns:
       limit (int): Records per page.
       offset (int): The number of records to be skipped.
    """

    if page is not None and page <= 0:
        raise DemistoException(PAGE_NUMBER_ERROR_MSG)
    if page_size is not None and page_size <= 0:
        raise DemistoException(PAGE_SIZE_ERROR_MSG)
    if limit is not None and limit <= 0:
        raise DemistoException(LIMIT_ERROR_MSG)
    if page_size and limit:
        limit = page_size
    return limit or page_size or DEFAULT_PAGE_SIZE, (
        page - 1 if page else DEFAULT_OFFSET
    ) * (page_size or DEFAULT_PAGE_SIZE)


def get_command_title_string(
    sub_context: str, page: Optional[int], page_size: Optional[int], hits: Optional[int]
) -> str:
    """
    Generates a command title string based on the provided context and pagination information.

    Args:
        sub_context (str): The sub-context to be included in the command title string.
        page (Optional[int]): The current page number in the pagination.
        page_size (Optional[int]): The number of items per page in the pagination.
        hits (Optional[int]): The total number of items available in the pagination.

    Returns:
        str: The command title string with the provided sub-context and pagination information.
    """
    if page and page_size and hits is not None and (page > 0 and page_size > 0):
        total_page = ceil(hits / page_size) if hits > 0 else 1
        return (
            f"{sub_context} \nCurrent page size: {page_size}\n"
            f"Showing page {page} out of {total_page}"
        )

    return f"{sub_context}"


def get_max_limit(end_point: str, dt_args: Dict[str, Any]) -> int:
    """
    Calculate the maximum limit of results that can be fetched from a specific API endpoint.

    This function determines the maximum limit based on the provided endpoint and arguments.
    It considers the endpoint, and the boolean flags `include_counts` and `include_domain_data` in the `dt_args` dictionary.

    Args:
        end_point (str): The API endpoint.
        dt_args (Dict[str, Any]): A dictionary containing the arguments required for the API query.

    Returns:
        int: The maximum limit of results that can be fetched.

    Constants:
        MONITOR_DOMAINS_LIMIT (int): The maximum limit for the monitor domains endpoint when include_counts is False (500).
        INCLUDE_COUNTS_LIMIT (int): The maximum limit when include_counts is True (100).
        INCLUDE_DOMAIN_DATA_LIMIT (int): The maximum limit when include_domain_data is True (50).
        DEFAULT_LIMIT (int): The default maximum limit when none of the other conditions are met (100).
    """
    include_counts = dt_args.get("include_counts", False)
    include_domain_data = dt_args.get("include_domain_data", False)

    return (
        MONITOR_DOMAINS_LIMIT
        if end_point == DOMAINTOOLS_MONITOR_DOMAINS_ENDPOINT and not include_counts
        else (
            INCLUDE_COUNTS_LIMIT
            if include_counts
            else INCLUDE_DOMAIN_DATA_LIMIT if include_domain_data else DEFAULT_LIMIT
        )
    )


def get_results_helper(
    client: Client,
    end_point: str,
    dt_args: Dict[str, Any],
    result_key: str,
    tb_header_name: str,
) -> tuple[List[Any], str]:
    """
    Helper function to get results for the given endpoint and result_key.

    Args:
        client: DomainTools client to use.
        end_point: The endpoint to query_dt_api for results.
        dt_args: Dictionary containing arguments for the query_dt_api.
        result_key: The key in the response JSON to get results from.
        tb_header_name: The readable output header.

    Returns:
        Tuple containing the results list and the title of the readable output str.
    """
    max_limit = get_max_limit(end_point, dt_args)
    page = dt_args.get("page", 1)
    page_size = dt_args.get("page_size", DEFAULT_PAGE_SIZE)
    limit = dt_args.get("limit")
    preview = dt_args.get("preview")
    limit, offset = pagination(page, page_size, limit)
    if preview:
        limit = DEFAULT_PREVIEW_LIMIT
    results: List = []
    total_count = 0

    while True:
        fetch_size = (
            min(limit - len(results), max_limit) if limit is not None else max_limit
        )
        if fetch_size <= 0:
            break

        dt_args.update({"offset": offset, "limit": fetch_size})

        response = client.query_dt_api(
            end_point, "GET", params=DOMAINTOOLS_PARAMS | dt_args
        )

        total_count = response.get("total_count", 0)
        new_results = response.get(result_key, [])

        if not new_results:
            break

        results.extend(new_results)
        offset += len(new_results)
        if len(new_results) < fetch_size:
            break

    return results, get_command_title_string(
        tb_header_name, page, page_size, total_count
    )


def fetch_domain_tools_api_results(
    client: Client, end_point: str, tb_header_name: str, dt_args: Dict[str, Any]
) -> CommandResults:
    """
    Gets the results for a DomainTools API endpoint.

    Args:
        client (Client): The instance of the client to use.
        end_point (str): The API endpoint to query_dt_api.
        tb_header_name (str): The name to use for the table header in the command results.
        dt_args (Dict): The arguments to use for the API request.

    Returns:
        CommandResults: The results of the command.

    """

    results, title = get_results_helper(
        client, end_point, dt_args, "watchlist_domains", tb_header_name
    )
    indicator_list: List[Dict] = []

    if results:
        if dt_args.get("include_domain_data"):
            for result in results:
                indicator = format_common_fields(result) | format_risk_score_components(
                    result
                )
                indicator.update(
                    format_data(result, "ip", "dt_ip_address", "ip")
                    | format_data(result, "name_server", "dt_nameServer", "host")
                    | format_data(result, "mx", "dt_mailServer", "host")
                )
                indicator_list.append(indicator)
        else:
            for result in results:
                indicator = format_common_fields(result) | format_risk_score_components(
                    result
                )
                indicator_list.append(indicator)
    return CommandResults(
        outputs=results,
        outputs_prefix=f"{INTEGRATION_CONTEXT_NAME}.{CONTEXT_PATH_KEY[tb_header_name]}",
        outputs_key_field="domain",
        readable_output=(
            tableToMarkdown(name=title, t=indicator_list)
            if indicator_list
            else NO_DOMAINS_FOUND
        ),
    )


def domaintools_iris_detect_get_watched_domains_command(
    client: Client, args: Dict[str, Any]
) -> CommandResults:
    """
    domaintools_iris_detect_get_watched_domains_command: Get the watched domains list.
    Args:
        client: DomainTools client to use.
        args: all command arguments, usually passed from ``demisto.args()``.
    Returns:
        fetch_domain_tools_api_results: A ``CommandResults`` object that is then passed
         to ``return_results``, that contains result which will display in
         war room.
    """
    return fetch_domain_tools_api_results(
        client,
        DOMAINTOOLS_WATCHED_DOMAINS_ENDPOINT,
        DOMAINTOOLS_WATCHED_DOMAINS_HEADER,
        create_common_api_arguments(args) | create_escalated_api_arguments(args),
    )


def domaintools_iris_detect_get_new_domains_command(
    client: Client, args: Dict[str, Any]
) -> CommandResults:
    """
    domaintools_iris_detect_get_new_domains_command: Get the new domains list.
    Args:
        client: DomainTools client to use.
        args: all command arguments, usually passed from ``demisto.args()``.
    Returns:
        fetch_domain_tools_api_results: A ``CommandResults`` object that is then passed
         to ``return_results``, that contains result which will display in
         war room.
    """
    return fetch_domain_tools_api_results(
        client,
        DOMAINTOOLS_NEW_DOMAINS_ENDPOINT,
        DOMAINTOOLS_NEW_DOMAINS_HEADER,
        create_common_api_arguments(args)
        | {"discovered_since": args.get("discovered_since")},
    )


def domaintools_iris_detect_get_ignored_domains_command(
    client: Client, args: Dict[str, Any]
) -> CommandResults:
    """
    domaintools_iris_detect_get_ignored_domains_command: Get the ignored domains list.
    Args:
        client: DomainTools client to use.
        args: all command arguments, usually passed from ``demisto.args()``.
    Returns:
        fetch_domain_tools_api_results: A ``CommandResults`` object that is then passed
         to ``return_results``, that contains result which will display in
         war room.
    """
    return fetch_domain_tools_api_results(
        client,
        DOMAINTOOLS_IGNORED_DOMAINS_ENDPOINT,
        DOMAINTOOLS_IGNORE_DOMAINS_HEADER,
        create_common_api_arguments(args) | create_escalated_api_arguments(args),
    )


def domaintools_iris_detect_get_blocklist_domains_command(
    client: Client, args: Dict[str, Any]
) -> CommandResults:
    """
    domaintools_iris_detect_get_blocklist_domains_command: Get the blocked domains list.
    Args:
        client: DomainTools client to use.
        args: all command arguments, usually passed from ``demisto.args()``.
    Returns:
        fetch_domain_tools_api_results: A ``CommandResults`` object that is then passed
         to ``return_results``, that contains result which will display in
         war room.
    """
    return fetch_domain_tools_api_results(
        client,
        DOMAINTOOLS_WATCHED_DOMAINS_ENDPOINT,
        DOMAINTOOLS_BLOCKED_DOMAINS_HEADER,
        create_common_api_arguments(args)
        | create_escalated_api_arguments(args)
        | {"escalation_types[]": "blocked"},
    )


def domaintools_iris_detect_get_escalated_domains_command(
    client: Client, args: Dict[str, Any]
) -> CommandResults:
    """
    domaintools_iris_detect_get_escalated_domains_command: Get the escalated domains
    list.
    Args:
        client: DomainTools client to use.
        args: all command arguments, usually passed from ``demisto.args()``.
    Returns:
        fetch_domain_tools_api_results: A ``CommandResults`` object that is then passed
         to ``return_results``, that contains result which will display in
         war room.
    """
    return fetch_domain_tools_api_results(
        client,
        DOMAINTOOLS_WATCHED_DOMAINS_ENDPOINT,
        DOMAINTOOLS_ESCALATE_DOMAINS_HEADER,
        create_common_api_arguments(args)
        | create_escalated_api_arguments(args)
        | {"escalation_types[]": "google_safe"},
    )


def domaintools_iris_detect_get_monitors_list_command(
    client: Client, args: Dict[str, Any]
) -> CommandResults:
    """
    Get the monitor domains list.

    Args:
        client: DomainTools client to use.
        args: Command arguments, usually passed from ``demisto.args()``.

    Returns:
        A ``CommandResults`` object that is then passed to ``return_results``,
        which contains the result to display in the war room.
    """

    results, title = get_results_helper(
        client,
        DOMAINTOOLS_MONITOR_DOMAINS_ENDPOINT,
        {
            "datetime_counts_since": arg_to_datetime(args.get("datetime_counts_since")),
        }
        | create_common_api_arguments(args)
        | create_escalated_api_arguments(args),
        "monitors",
        DOMAINTOOLS_MONITORS_HEADER,
    )

    if results:
        monitor_data = [format_monitor_fields(result) for result in results]
        headers = list(monitor_data[0].keys())
        readable_output = tableToMarkdown(
            name=title, t=monitor_data, removeNull=True, headers=headers
        )
    else:
        readable_output = NO_DOMAINS_FOUND
    return CommandResults(
        outputs=results,
        outputs_prefix=f"{INTEGRATION_CONTEXT_NAME}.Monitor",
        outputs_key_field="",
        readable_output=readable_output,
    )


def handle_domain_action(
    client: Client, args: Dict[str, Any], action: str
) -> CommandResults:
    """
    Performs the specified action on one or more watchlist domains.

    Args:
        client (Client): The instance of the client to use.
        args (Dict[str, Any]): A dictionary containing the command arguments.
        action (str): The name of the action to perform.

    Returns:
        CommandResults: The results of the command.

    """
    action_params = {
        "watched": (
            "PATCH",
            DOMAINTOOLS_MANAGE_WATCHLIST_ENDPOINT,
            DOMAINTOOLS_WATCHED_DOMAINS_HEADER,
            format_watchlist_fields,
            "WatchedDomain",
        ),
        "ignored": (
            "PATCH",
            DOMAINTOOLS_MANAGE_WATCHLIST_ENDPOINT,
            DOMAINTOOLS_IGNORE_DOMAINS_HEADER,
            format_watchlist_fields,
            "IgnoredDomain",
        ),
        "google_safe": (
            "POST",
            DOMAINTOOLS_ESCALATE_DOMAINS_ENDPOINT,
            DOMAINTOOLS_ESCALATE_DOMAINS_HEADER,
            format_blocklist_fields,
            "EscalatedDomain",
        ),
        "blocked": (
            "POST",
            DOMAINTOOLS_ESCALATE_DOMAINS_ENDPOINT,
            DOMAINTOOLS_BLOCKED_DOMAINS_HEADER,
            format_blocklist_fields,
            "BlockedDomain",
        ),
    }
    method, endpoint, header, format_func, context_output_string = action_params[action]

    data = {
        "watchlist_domain_ids": argToList(args.get("watchlist_domain_ids"))
    } | DOMAINTOOLS_PARAMS

    if action in ["watched", "ignored"]:
        data |= {"state": action}
    else:
        data |= {"escalation_type": action}

    indicators_list = [
        dict(format_func(result))
        for result in client.query_dt_api(endpoint, method, json_data=data).get(
            "watchlist_domains" if action in ["watched", "ignored"] else "escalations",
            [],
        )
    ]

    return CommandResults(
        outputs=indicators_list,
        outputs_prefix=f"{INTEGRATION_CONTEXT_NAME}.{context_output_string}",
        outputs_key_field="",
        readable_output=(
            tableToMarkdown(name=header, t=indicators_list)
            if indicators_list
            else NO_DOMAINS_FOUND
        ),
        raw_response=indicators_list,
    )


def domaintools_iris_detect_watch_domains_command(
    client: Client, args: Dict[str, Any]
) -> CommandResults:
    """
    Watch domains for changes using DomainTools Iris API.

    Args:
        client (Client): A DomainTools Iris API client.
        args (args: Dict[str, Any]): A dictionary of arguments specifying the domains to watch.

    Returns:
        A ``CommandResults`` object that is then passed to ``return_results``,
        which contains the result to display in the war room.
    """
    return handle_domain_action(client, args, "watched")


def domaintools_iris_detect_ignore_domains_command(
    client: Client, args: Dict[str, Any]
) -> CommandResults:
    """
    Ignore domains using DomainTools Iris API.

    Args:
        client (Client): A DomainTools Iris API client.
        args (args: Dict[str, Any]): A dictionary of arguments specifying the domains to ignore.

    Returns:
        A ``CommandResults`` object that is then passed to ``return_results``,
        which contains the result to display in the war room.
    """
    return handle_domain_action(client, args, "ignored")


def domaintools_iris_detect_escalate_domains_command(
    client: Client, args: Dict[str, Any]
) -> CommandResults:
    """
    Escalate domains to Google Safe Browsing using DomainTools Iris API.

    Args:
        client (Client): A DomainTools Iris API client.
        args (Dict[str, Any]): A dictionary of arguments specifying the domains to escalate.

    Returns:
        A ``CommandResults`` object that is then passed to ``return_results``,
         which contains the result to display in the war room.
    """
    return handle_domain_action(client, args, "google_safe")


def domaintools_iris_detect_blocklist_domains_command(
    client: Client, args: Dict[str, Any]
) -> CommandResults:
    """
    Blocklist domains using DomainTools Iris API.

    Args:
        client (Client): A DomainTools Iris API client.
        args (Dict): A dictionary of arguments specifying the domains to blocklist.

    Returns:
        A ``CommandResults`` object that is then passed to ``return_results``,
         which contains the result to display in the war room.
    """
    return handle_domain_action(client, args, "blocked")


def reset_last_run() -> CommandResults:
    """
    Reset the last run from the integration context
    """
    demisto.setIntegrationContext({})
    return CommandResults(readable_output="Fetch history deleted successfully")


def main() -> None:
    """PARSE AND VALIDATE INTEGRATION PARAMS"""
    command = demisto.command()
    args = demisto.args()
    params = demisto.params()
    username = params.get("credentials", {}).get("identifier")
    api_key = params.get("credentials", {}).get("password")
    verify_certificate = not params.get("insecure", False)
    proxy = params.get("proxy", False)
    handle_proxy()
    risk_score_ranges = argToList(params.get("risk_score_ranges"))
    include_domain_data = params.get("include_domain_data")
    first_fetch_time = params.get("first_fetch", DEFAULT_DAYS_BACK).strip()
    fetch_limit = arg_to_number(params.get("max_fetch", 50))
    new_domains = params.get("new_domains")
    changed_domains = params.get("changed_domains")
    blocked_domains = params.get("blocked_domains")
    try:
        client = Client(
            username,
            api_key,
            new_domains,
            changed_domains,
            blocked_domains,
            risk_score_ranges,
            include_domain_data,
            first_fetch_time,
            fetch_limit,
            verify=verify_certificate,
            proxy=proxy,
        )
        commands = {
            "domaintools-iris-detect-get-new-domains": domaintools_iris_detect_get_new_domains_command,
            "domaintools-iris-detect-get-watched-domains": domaintools_iris_detect_get_watched_domains_command,
            "domaintools-iris-detect-get-ignored-domains": domaintools_iris_detect_get_ignored_domains_command,
            "domaintools-iris-detect-get-escalated-domains": domaintools_iris_detect_get_escalated_domains_command,
            "domaintools-iris-detect-get-blocklist-domains": domaintools_iris_detect_get_blocklist_domains_command,
            "domaintools-iris-detect-get-monitors-list": domaintools_iris_detect_get_monitors_list_command,
            "domaintools-iris-detect-escalate-domains": domaintools_iris_detect_escalate_domains_command,
            "domaintools-iris-detect-blocklist-domains": domaintools_iris_detect_blocklist_domains_command,
            "domaintools-iris-detect-watch-domains": domaintools_iris_detect_watch_domains_command,
            "domaintools-iris-detect-ignore-domains": domaintools_iris_detect_ignore_domains_command,
        }
        demisto.info(f"Command being called is {command}")
        command_output: Any
        if command == "test-module":
            command_output = module_test(client)

        elif command in commands:
            command_output = commands[command](client, args)

        elif command == "fetch-incidents":
            command_output = fetch_domains(client)

        elif command == "domaintools-iris-detect-reset-fetch-indicators":
            command_output = reset_last_run()

        else:
            raise NotImplementedError(f"Command {command} is not supported")
        return_results(command_output)
    except Exception as err:
        return_error(f"Failed to execute {command} command.\nError: {err}")


""" ENTRY POINT """

if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
