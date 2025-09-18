from datetime import datetime, UTC
from json import dumps
from typing import Any

import demistomock as demisto
from CommonServerPython import *  # noqa: F401 # pylint:# disable=unused-wildcard-import
from requests import Response
from urllib3 import disable_warnings

# Disable insecure warnings
disable_warnings()  # Disable SSL warnings

INTEGRATION_CONTEXT_NAME = "SpyCloud"
INVALID_CREDENTIALS_ERROR_MSG = (
    "Authorization Error: The provided API Key for SpyCloud is invalid. Please provide a valid API Key."
)
MAX_RETRIES = 5
BACK_OFF_TIME = 0.1
DEFAULT_FETCH_LIMIT = 200

# Error and endpoint constants
PAGE_NUMBER_ERROR_MSG = "Invalid Input Error: page number should be greater than zero."
PAGE_SIZE_ERROR_MSG = "Invalid Input Error: page size should be greater than zero."
LIMIT_EXCEED = "LimitExceededException"
TOO_MANY_REQUESTS = "TooManyRequestsException"
INVALID_IP = "Invalid IP"
INVALID_API_KEY = "Invalid API key"
X_AMAZON_ERROR_TYPE = "x-amzn-ErrorType"
SPYCLOUD_ERROR = "SpyCloud-Error"
INVALID_IP_MSG = "Kindly contact SpyCloud support to whitelist your IP Address."
WRONG_API_URL = "Verify that the API URL parameter is correct and that you have access to the server from your host"
MONTHLY_QUOTA_EXCEED_MSG = "You have exceeded your monthly quota. Kindly contact SpyCloud support."

# Relative endpoints — base_url should include /enterprise-v2/
WATCHLIST_ENDPOINT = "breach/data/watchlist"
DOMAIN_ENDPOINT = "breach/data/domains/"
DATE_TIME_FORMAT = "%Y-%m-%dT%H:%M:%SZ"
DEFAULT_DATE = "-1days"

INCIDENT_TYPE = {
    2: "SpyCloud Informative Data",
    5: "SpyCloud Informative Data",
    20: "SpyCloud Breach Data",
    25: "SpyCloud Malware Data",
}
INCIDENT_NAME = {
    2: "SpyCloud Informative Alert on",
    5: "SpyCloud Informative Alert on",
    20: "SpyCloud Breach Alert on",
    25: "SpyCloud Malware Alert on",
}
SEVERITY_VALUE = {
    2: IncidentSeverity.INFO,
    5: IncidentSeverity.INFO,
    20: IncidentSeverity.HIGH,
    25: IncidentSeverity.CRITICAL,
}


class Client(BaseClient):
    """
    This Client implements API calls, and does not contain any XSOAR logic.
    Should only do requests and return data.
    It inherits from BaseClient defined in CommonServer Python.
    Most calls use _http_request() that handles proxy, SSL verification, etc.
    For this implementation, no special attributes defined
    """

    def __init__(self, base_url: str, apikey: str, verify=None, proxy=None):
        headers = {"Accept": "application/json", "X-API-Key": apikey, "User-Agent": "paloalto_xsoar_v1.5.0"}
        super().__init__(
            base_url=base_url,
            verify=verify,
            proxy=proxy,
            headers=headers,
        )

    def query_spy_cloud_api(self, end_point: str, params: dict[Any, Any] = None, is_retry: bool = False) -> dict:
        """
        Args:
         end_point (str): SpyCloud endpoint.
         params (dict): Params.
         is_retry (bool): Boolean Variable to check whether retry required.
        Returns:
         Return the raw API response from SpyCloud API.
        """
        if params is None:
            params = {}

        url_path = urljoin(self._base_url, end_point) if not is_retry else end_point

        demisto.debug(f"[SpyCloud] Calling API endpoint: {url_path}")
        if params:
            demisto.debug(f"[SpyCloud] With query params: {params}")

        retries = None
        status_list_to_retry = None
        backoff_factor = None

        if is_retry:
            retries = MAX_RETRIES
            status_list_to_retry = {429, 504}
            backoff_factor = BACK_OFF_TIME

        response = self._http_request(
            method="GET",
            full_url=url_path,
            params=params,
            headers=self._headers,
            retries=retries,
            status_list_to_retry=status_list_to_retry,
            backoff_factor=backoff_factor,
            error_handler=self.spy_cloud_error_handler,
        )
        return response

    def spy_cloud_error_handler(self, response: Response):
        """
        Error Handler for SpyCloud
        Args:
            response (response): SpyCloud response
        Raise:
             DemistoException
        """
        response_headers = response.headers
        err_msg = response.json().get("message") or response.json().get("errorMessage")
        if response.status_code == 429:
            if TOO_MANY_REQUESTS in response_headers.get(X_AMAZON_ERROR_TYPE, ""):
                self.query_spy_cloud_api(response.url, is_retry=True)
            elif LIMIT_EXCEED in response_headers.get(X_AMAZON_ERROR_TYPE, ""):
                raise DemistoException(MONTHLY_QUOTA_EXCEED_MSG, res=response)
        elif response.status_code == 403:
            if INVALID_IP in response_headers.get(SPYCLOUD_ERROR, ""):
                raise DemistoException(f"{response_headers.get(SPYCLOUD_ERROR, '')}. {INVALID_IP_MSG}", res=response)
            elif INVALID_API_KEY in response_headers.get(SPYCLOUD_ERROR, ""):
                raise DemistoException(INVALID_CREDENTIALS_ERROR_MSG, res=response)
            else:
                raise DemistoException(WRONG_API_URL, res=response)
        else:
            raise DemistoException(err_msg, res=response)

    @staticmethod
    def set_last_run():
        """
        sets the last run
        """
        current_date = datetime.now(UTC)
        demisto.setLastRun({"lastRun": current_date.strftime(DATE_TIME_FORMAT)})

    @staticmethod
    def get_last_run() -> str:
        """
        Gets last run time in timestamp
        Returns:
            last run in timestamp, or '' if no last run
        """
        return demisto.getLastRun().get("lastRun")


def create_spycloud_args(args: dict, client: Client) -> dict:
    """
    This function creates a dictionary of the arguments sent to the SpyCloud
    API based on the demisto.args().
    Args:
        args: demisto.args()
        client: Client class
    Returns:
        Return arguments dict.
    """
    now = datetime.now(UTC)
    last_run = client.get_last_run()

    if last_run:
        last_run_dt = arg_to_datetime(last_run)
        since = since_modification_date = last_run_dt.strftime("%Y-%m-%d") if isinstance(last_run_dt, datetime) else None
        until = until_modification_date = now.strftime("%Y-%m-%d")
    else:
        since_dt = arg_to_datetime(args.get("first_fetch") or DEFAULT_DATE)
        since = since_dt.strftime("%Y-%m-%d") if since_dt else None
        until = now.strftime("%Y-%m-%d")
        since_mod_dt = arg_to_datetime(args.get("since_modification_date", DEFAULT_DATE), "Since Modification Date")
        since_modification_date = since_mod_dt.strftime("%Y-%m-%d") if since_mod_dt else None
        until_modification_date = now.strftime("%Y-%m-%d")

    severity_list = argToList(args.get("severity", []))
    supported_severities = {"2", "5", "25", "20"}
    if any(sev not in supported_severities for sev in severity_list):
        raise DemistoException("Invalid input error: supported values for severity are: 2, 5, 20, 25")

    return {
        "type": args.get("type", ""),
        "severity": ",".join(severity_list),
        "source_id": args.get("source_id", ""),
        "query": args.get("query", ""),
        "domain_search": args.get("domain_search", ""),
        "watchlist_type": args.get("watchlist_type", ""),
        "salt": args.get("salt"),
        "since": since,
        "until": until,
        "since_modification_date": since_modification_date,
        "until_modification_date": until_modification_date,
        "fetch_limit": args.get("fetch_limit", DEFAULT_FETCH_LIMIT),
    }


def fetch_domain_or_watchlist_data(client: Client, args: dict, base_args: dict) -> list:
    """
    Args:
         client (Client): Client class object.
         args (dict): demisto.args().
         base_args (dict): Custom Param.
        Returns:
         Return Watchlist or domain specific data.
    """
    domain_search = (args.get("domain_search") or "").strip()
    type_param = (args.pop("type", "") or "").strip()
    results = []

    def build_endpoint(base: str, domain: str = None) -> str:
        endpoint = base
        if domain:
            endpoint += domain
        if type_param:
            delimiter = "&" if "?" in endpoint else "?"
            endpoint += f"{delimiter}type={type_param}"
        return endpoint

    def fetch_paginated(endpoint_url: str) -> None:
        cursor = None
        while True:
            try:
                params = dict(base_args)
                if cursor:
                    params["cursor"] = cursor
                response = client.query_spy_cloud_api(endpoint_url, params)

                results.extend(response.get("results", []))
                cursor = response.get("cursor")
                if not cursor:
                    break
            except Exception as e:
                demisto.error(f"[SpyCloud] Failed to fetch data from {endpoint_url}: {e}")
                break

    if domain_search:
        required_types = {"email_domain", "target_domain"}
        current_types = set(type_param.split(",")) if type_param else set()
        type_param = ",".join(sorted(current_types | required_types))

        domains = [d.strip() for d in domain_search.split(",") if d.strip()]
        demisto.debug(f"[SpyCloud] Detected domain_search values: {domains}")

        for domain in domains:
            endpoint = build_endpoint(DOMAIN_ENDPOINT, domain)
            fetch_paginated(endpoint)
    else:
        endpoint = build_endpoint(WATCHLIST_ENDPOINT)
        fetch_paginated(endpoint)
    return results


def build_iterators(client: Client, results: list) -> list:
    """
    Function to parse data and create relationship.
    Args:
        client: Client class
        results: API response.
    Returns:
        list of incidents
    """
    incident_record = []
    for item in results:
        source_id = item.get("source_id")
        catalog_resp = client.query_spy_cloud_api(f"breach/catalog/{source_id}", {}).get("results", [])
        item["breach_title"] = catalog_resp[0].get("title") if catalog_resp else ""
        severity = item["severity"]
        name_ext = item.get("email") or (item.get("ip_addresses") or [""])[0] or item.get("username") or item["document_id"]
        incident_record.append(
            {
                "type": INCIDENT_TYPE[severity],
                "name": f"{INCIDENT_NAME[severity]} {name_ext}",
                "rawJSON": dumps(item),
                "severity": SEVERITY_VALUE[severity],
                "dbotMirrorId": item["document_id"],
            }
        )
    return incident_record


def remove_duplicate(since_response: list, modified_response: list) -> list:
    """
    Function to remove duplicate record from two different calls.
    Args:
        since_response: response when only since parameter given.
        modified_response: response when only since parameter given.
    """
    id_set = {rec["document_id"] for rec in modified_response}
    modified_response.extend(res for res in since_response if res["document_id"] not in id_set)
    return modified_response


def fetch_incident(client: Client, args: dict):
    """
    Function to create Incident and Indicator to XSOAR platform.
    Args:
        client(Client): Client class object
        args: demisto.args()
    """
    left_results = demisto.getIntegrationContext().get("results")

    try:
        max_fetch = int(args.get("fetch_limit", DEFAULT_FETCH_LIMIT))
    except (ValueError, TypeError):
        max_fetch = DEFAULT_FETCH_LIMIT

    if left_results:
        incident_record = build_iterators(client, left_results[:max_fetch])
        if len(left_results) <= max_fetch:
            demisto.setIntegrationContext({"results": []})
        else:
            demisto.setIntegrationContext({"results": left_results[max_fetch:]})
        return incident_record

    param = create_spycloud_args(args, client)
    since = param.pop("since")
    until = param.pop("until")
    since_modification_date = param.pop("since_modification_date")
    until_modification_date = param.pop("until_modification_date")

    since_results = fetch_domain_or_watchlist_data(client, args, {**param, "since": since, "until": until})
    modified_results = fetch_domain_or_watchlist_data(
        client,
        args,
        {**param, "since_modification_date": since_modification_date, "until_modification_date": until_modification_date},
    )

    client.set_last_run()
    incidents = remove_duplicate(since_results, modified_results)

    if len(incidents) > max_fetch:
        demisto.setIntegrationContext({"results": incidents[max_fetch:]})
        return build_iterators(client, incidents[:max_fetch])
    return build_iterators(client, incidents)


def test_module(client: Client, params: dict) -> str:
    """
    Tests API connectivity and authentication
    When 'ok' is returned it indicates the integration works like
    it is supposed to and connection to the service is successful.
    Args:
        client(Client): Client class object
    Returns:
        Connection ok
    """
    args = create_spycloud_args(params, client)
    client.query_spy_cloud_api(WATCHLIST_ENDPOINT, args)
    return "ok"


def main():
    """
    PARSE AND VALIDATE INTEGRATION PARAMS
    """
    params = demisto.params()
    apikey = params.get("apikey")
    verify_certificate = not params.get("insecure", False)
    proxy = params.get("proxy", False)
    handle_proxy()
    command = demisto.command()

    try:
        base_url = params.get("url")
        client = Client(base_url, apikey, verify=verify_certificate, proxy=proxy)
        if command == "test-module":
            return_results(test_module(client, params))
        elif command == "fetch-incidents":
            demisto.incidents(fetch_incident(client, params))
        else:
            raise NotImplementedError(f"command {command} is not supported")
    except Exception as e:
        return_error(f"Failed to execute {command} command. Error: {e!s}")


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
