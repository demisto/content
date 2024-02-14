from datetime import datetime
from json import dumps

import demistomock as demisto
from CommonServerPython import *  # noqa: F401 # pylint:# disable=unused-wildcard-import
from typing import Any
from requests import Response
from urllib3 import disable_warnings

# Disable insecure warnings
disable_warnings()  # pylint: disable=no-member

INTEGRATION_CONTEXT_NAME = "SpyCloud"
INVALID_CREDENTIALS_ERROR_MSG = (
    "Authorization Error: The provided API Key "
    "for SpyCloud is invalid. Please provide a "
    "valid API Key."
)
MAX_RETRIES = 5
BACK_OFF_TIME = 0.1
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
MONTHLY_QUOTA_EXCEED_MSG = (
    "You have exceeded your monthly quota. Kindly contact SpyCloud support."
)
WATCHLIST_ENDPOINT = "breach/data/watchlist"
DATE_TIME_FORMAT = "%Y-%m-%dT%H:%M:%SZ"  # ISO8601 format with UTC, default
DEFAULT_DATE = "-1days"
# in XSOAR
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
    25: IncidentSeverity.CRITICAL
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
        super().__init__(
            base_url=base_url,
            verify=verify,
            proxy=proxy,
            headers={"Content-type": "application/json", "X-API-Key": apikey, "User-Agent": "XSOAR-ENT/1.0.0 "},
        )
        self.apikey = apikey

    def query_spy_cloud_api(
        self, end_point: str, params: dict[Any, Any] = None, is_retry: bool = False
    ) -> dict:
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
        retries = None
        status_list_to_retry = None
        backoff_factor = None
        if is_retry:
            retries = MAX_RETRIES
            status_list_to_retry = {429}
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
                raise DemistoException(
                    f'{response_headers.get(SPYCLOUD_ERROR, "")}. '
                    f""
                    f"{INVALID_IP_MSG}",
                    res=response,
                )
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
        current_date = datetime.utcnow()
        demisto.setLastRun({"lastRun": current_date.strftime(DATE_TIME_FORMAT)})

    @staticmethod
    def get_last_run() -> str:
        """Gets last run time in timestamp
        Returns:
            last run in timestamp, or '' if no last run
        """

        last_run = demisto.getLastRun().get('lastRun')
        if last_run:
            last_run = arg_to_datetime(last_run)
            last_run = last_run.strftime("%Y-%m-%d")
        return last_run


""" HELPER FUNCTIONS """


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
    client.query_spy_cloud_api("breach/data/watchlist", args)
    return "ok"


def build_iterators(client: Client, results: list) -> list:
    """
    Function to parse data and create relationship.
    Args:
        client: Client class
        results: API response.
    Returns:
        Connection ok
    """
    incident_record = []
    for item in results:
        source_id = item.get("source_id")
        catalog_resp = client.query_spy_cloud_api(
            f"breach/catalog/{source_id}", {}
        ).get("results", [])
        breach_title = catalog_resp[0].get("title") if catalog_resp else ""
        item["breach_title"] = breach_title
        severity = item["severity"]
        email = item.get('email')
        ip_add = item.get('ip_addresses')
        username = item.get('username')
        name_ext = email or (ip_add[0] if ip_add else username) or item["document_id"]
        incident = {
            "type": INCIDENT_TYPE[severity],
            "name": f"{INCIDENT_NAME[severity]} {name_ext}",
            "rawJSON": dumps(item),
            "severity": SEVERITY_VALUE[severity],
            "dbotMirrorId": item["document_id"],
        }
        incident_record.append(incident)
    return incident_record


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
    spycloud_args: dict
    last_run = client.get_last_run()
    since: Any
    since_modification_date: Any
    until: Any
    until_modification_date: Any
    if last_run:
        since = since_modification_date = until = until_modification_date = last_run
    else:
        since = arg_to_datetime(args.get("first_fetch", DEFAULT_DATE), "Since")
        until = arg_to_datetime(args.get("until", DEFAULT_DATE), "Until")
        since_modification_date = arg_to_datetime(
            args.get("since_modification_date", DEFAULT_DATE), "Since Modification Date"
        )
        until_modification_date = arg_to_datetime(
            args.get("until_modification_date", DEFAULT_DATE),
            "Until Modification Date",
        )
        if until:
            until = until.strftime("%Y-%m-%d")
        if since:
            since = since.strftime("%Y-%m-%d")
        if since_modification_date:
            since_modification_date = since_modification_date.strftime("%Y-%m-%d")
        if until_modification_date:
            until_modification_date = until_modification_date.strftime("%Y-%m-%d")
    severity_list = argToList(args.get("severity", []))
    supported_severities = {"2", "5", "25", "20"}
    invalid_severities = [
        severity for severity in severity_list if severity not in supported_severities
    ]
    if invalid_severities:
        raise DemistoException(
            f"Invalid input error: supported values for severity are: {', '.join(supported_severities)}"
        )

    spycloud_args = {
        "type": args.get("type", ""),
        "severity": ",".join(severity_list),
        "source_id": args.get("source_id", ""),
        "query": args.get("query", ""),
        "watchlist_type": args.get("watchlist_type", ""),
        "salt": args.get("salt"),
        "since": since,
        "until": until,
        "since_modification_date": since_modification_date,
        "until_modification_date": until_modification_date,
    }
    return spycloud_args


def remove_duplicate(since_response: list, modified_response: list) -> list:
    """
    Function to remove duplicate record from two different calls.
    Args:
        since_response: response when only since parameter given.
        modified_response: response when only since parameter given.
    """
    demisto.debug(f"since_length {len(since_response)}")
    demisto.debug(f"mod_length {len(modified_response)}")
    id_set = {rec["document_id"] for rec in modified_response}
    modified_response.extend(
        res for res in since_response if res["document_id"] not in id_set
    )
    return modified_response


def fetch_incident(client: Client, args: dict):
    """
    Function to create Incident and Indicator to XSOAR platform.
    Args:
        client(Client): Client class object
        args: demisto.args()
    """
    cursor_since, cursor_since_modification = " ", " "
    modified_results, since_results = [], []
    left_results = demisto.getIntegrationContext().get("results")
    if left_results and len(left_results) > 0:
        demisto.debug(f"length of left_result {len(left_results)}")
        incident_record = build_iterators(client, left_results[:200])
        if len(left_results) < 200:
            demisto.setIntegrationContext({"results": []})
        else:
            demisto.setIntegrationContext({"results": left_results[200:]})
        return incident_record
    last_run = client.get_last_run()
    demisto.debug(f"last_run_today {last_run}")
    if last_run == datetime.utcnow().strftime("%Y-%m-%d"):
        return []
    param = create_spycloud_args(args, client)
    since = param.pop("since")
    until = param.pop("until")
    since_modification_date = param.pop("since_modification_date")
    until_modification_date = param.pop("until_modification_date")
    while True:
        since_response = (
            client.query_spy_cloud_api(
                WATCHLIST_ENDPOINT,
                {"cursor": cursor_since, "since": since, "until": until, **param},
            )
            if cursor_since
            else {}
        )
        since_results.extend(since_response.get("results", []))
        modified_response = (
            client.query_spy_cloud_api(
                WATCHLIST_ENDPOINT,
                {
                    "cursor": cursor_since_modification,
                    "since_modification_date": since_modification_date,
                    "until_modification_date": until_modification_date,
                    **param,
                },
            )
            if cursor_since_modification
            else {}
        )
        modified_results.extend(modified_response.get("results", []))
        cursor_since = since_response.get("cursor", "")
        cursor_since_modification = modified_response.get("cursor", "")
        if (not cursor_since or cursor_since == "") and (
            not cursor_since_modification or cursor_since_modification == ""
        ):
            client.set_last_run()
            break
    incidents = remove_duplicate(since_results, modified_results)
    if len(incidents) > 200:
        incident_record = build_iterators(client, incidents[:200])
        demisto.setIntegrationContext({"results": incidents[200:]})
        return incident_record
    incident_record = build_iterators(client, incidents)
    return incident_record


def main():
    """
    PARSE AND VALIDATE INTEGRATION PARAMS
    """
    params = demisto.params()
    demisto.info(f"params {params}")
    apikey = params.get("apikey")
    verify_certificate = not params.get("insecure", False)
    proxy = params.get("proxy", False)
    handle_proxy()
    command = demisto.command()
    try:
        base_url = params.get("url")
        client = Client(base_url, apikey, verify=verify_certificate, proxy=proxy)
        demisto.info(f"Command being called is {command}")
        if command == "test-module":
            return_results(test_module(client, params))
        elif command == "fetch-incidents":
            incidents = fetch_incident(client, params)
            demisto.incidents(incidents)
        else:
            raise NotImplementedError(f"command {command} is not supported")
    except Exception as e:
        return_error(f"Failed to execute {command} command. Error: {str(e)}")


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
