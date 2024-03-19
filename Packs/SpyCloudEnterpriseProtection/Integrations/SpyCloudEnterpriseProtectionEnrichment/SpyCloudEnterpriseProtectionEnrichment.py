from math import ceil
from typing import Any
from collections import namedtuple
import requests
from urllib3 import disable_warnings
from CommonServerPython import *  # noqa: F401 # pylint: disable=unused-wildcard-import


# Disable insecure warnings
disable_warnings()  # pylint: disable=no-member

""" CONSTANT """

INTEGRATION_CONTEXT_NAME = "SpyCloud"
INVALID_CREDENTIALS_ERROR_MSG = (
    "Authorization Error: The provided API Key "
    "for SpyCloud is invalid. Please provide a "
    "valid API Key."
)
DEFAULT_PAGE_SIZE = 50
MAX_RETRIES = 5
BACK_OFF_TIME = 0.1
DEFAULT_OFFSET = 0
PAGE_NUMBER_ERROR_MSG = "Invalid Input Error: page number should be greater than zero."
PAGE_SIZE_ERROR_MSG = "Invalid Input Error: page size should be greater than zero."
LIMIT_EXCEED = "LimitExceededException"
TOO_MANY_REQUESTS = "TooManyRequestsException"
INVALID_IP = "Invalid IP"
INVALID_API_KEY = "Invalid API key"
X_AMAZON_ERROR_TYPE = "x-amzn-ErrorType"
WRONG_API_URL = "Verify that the API URL parameter is correct and that you have access to the server from your host"
SPYCLOUD_ERROR = "SpyCloud-Error"
INVALID_IP_MSG = "Kindly contact SpyCloud support to whitelist your IP Address."
MONTHLY_QUOTA_EXCEED_MSG = (
    "You have exceeded your monthly quota. Kindly contact SpyCloud support."
)
COMMAND_PARAMS = namedtuple(
    "COMMAND_PARAMS",
    ["endpoint", "title_string", "context", "key_field", "search_args"],
)


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
            headers={"Content-type": "application/json", "X-API-Key": apikey},
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
        url_path = f"{self._base_url}{end_point}" if not is_retry else end_point
        if not is_retry:
            retries = None
            status_list_to_retry = None
            backoff_factor = None
        else:
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

    def spy_cloud_error_handler(self, response: requests.Response):
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
                    f'{response_headers.get(SPYCLOUD_ERROR, "")}.  {INVALID_IP_MSG}',
                    res=response,
                )
            elif INVALID_API_KEY in response_headers.get(SPYCLOUD_ERROR, ""):
                raise DemistoException(INVALID_CREDENTIALS_ERROR_MSG, res=response)
            else:
                raise DemistoException(WRONG_API_URL, res=response)
        else:
            raise DemistoException(err_msg)


""" HELPER FUNCTIONS """


def pagination(page: int | None, page_size: int | None, limit: int | None):
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
    if page and page <= 0:
        raise DemistoException(PAGE_NUMBER_ERROR_MSG)
    if page_size and page_size <= 0:
        raise DemistoException(PAGE_SIZE_ERROR_MSG)

    if page_size and limit:
        limit = page_size
    page = page - 1 if page else DEFAULT_OFFSET
    page_size = page_size or DEFAULT_PAGE_SIZE

    limit = limit or page_size or DEFAULT_PAGE_SIZE
    offset = page * page_size

    return limit, offset


def get_paginated_results(results: list, offset: int, limit: int) -> list:
    return results[offset:offset + limit]


def test_module(client: Client) -> str:
    """
    Tests API connectivity and authentication
    When 'ok' is returned it indicates the integration works like
    it is supposed to and connection to the service is successful.
    Args:
        client(Client): Client class object
    Returns:
        Connection ok
    """
    client.query_spy_cloud_api("breach/data/watchlist", {})

    return "ok"


def create_spycloud_args(args: dict) -> dict:
    """
    This function creates a dictionary of the arguments sent to the SpyCloud
    API based on the demisto.args().
    Args:
        args: demisto.args()
    Returns:
        Return arguments dict.
    """

    spycloud_args: dict = {}
    since: Any = arg_to_datetime(args.get("since", None), "Since")
    until: Any = arg_to_datetime(args.get("until", None), "Until")
    since_modification_date: Any = arg_to_datetime(
        args.get("since_modification_date", None), "Since Modification Date"
    )
    until_modification_date: Any = arg_to_datetime(
        args.get("until_modification_date", None), "Until Modification Date"
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
    for severity in severity_list:
        if severity not in ["2", "5", "25", "20"]:
            raise DemistoException(
                "Invalid input Error: supported values for "
                "severity are: 2, 5, 20, 25"
            )
    spycloud_args["since"] = since
    spycloud_args["until"] = until
    spycloud_args["type"] = args.get("type", "")
    spycloud_args["severity"] = args.get("severity")
    spycloud_args["source_id"] = args.get("source_id", "")
    spycloud_args["query"] = args.get("query", "")
    spycloud_args["type"] = args.get("type", "")
    spycloud_args["watchlist_type"] = args.get("watchlist_type", "")
    spycloud_args["since_modification_date"] = since_modification_date
    spycloud_args["until_modification_date"] = until_modification_date
    spycloud_args["salt"] = args.get("salt")
    return spycloud_args


def breaches_lookup_to_markdown(response: list[dict], title: str):
    """
    Parsing the SpyCloud data
    Args:
        response (list): SpyCloud response data
        title (str): Title string
    Returns:
        A string representation of the markdown table
    """
    record_list = []
    for data in response:
        new_record = {
            "Title": data.get("title"),
            "SpyCloud Publish Date": data.get("spycloud_publish_date"),
            "Description": data.get("description"),
            "Confidence": data.get("confidence"),
            "ID": data.get("id"),
            "Acquisition Date": data.get("acquisition_date"),
            "UUID": data.get("uuid"),
            "Type": data.get("type"),
        }
        record_list.append(new_record)
    headers = record_list[0] if record_list else {}
    headers = list(headers.keys())
    markdown = tableToMarkdown(title, record_list, headers=headers, removeNull=True)
    return markdown


def lookup_to_markdown_table(response: list[dict], title: str):
    """
    Parsing the SpyCloud data
    Args:
        response (list): SpyCloud response data
        title (str): Title string
    Returns:
        A string representation of the markdown table
    """
    record_list = []
    for data in response:
        new_record = {
            "Source ID": data.get("source_id"),
            "Email": data.get("email"),
            "Full Name": data.get("full_name"),
            "User Name": data.get("username"),
            "Email Domain": data.get("email_domain"),
            "Email Username": data.get("email_username"),
            "Target Domain": data.get("target_domain"),
            "Target Subdomain": data.get("target_subdomain"),
            "Password": data.get("password"),
            "Password Plaintext": data.get("password_plaintext"),
            "Password Type": data.get("password_type"),
            "Target URL": data.get("target_url"),
            "User Browser": data.get("user_browser"),
            "IP Addresses": data.get("ip_addresses"),
            "Infected Machine ID": data.get("infected_machine_id"),
            "Infected Path": data.get("infected_path"),
            "Infected Time": data.get("infected_time"),
            "User System Domain": data.get("user_sys_domain"),
            "User Hostname": data.get("user_hostname"),
            "User OS": data.get("user_os"),
            "User SYS Registered Owner": data.get("user_sys_registered_owner"),
            "SpyCloud Publish Date": data.get("spycloud_publish_date"),
            "Confidence": data.get("confidence"),
            "ID": data.get("id"),
            "Domain": data.get("domain"),
            "Document ID": data.get("document_id"),
            "UUID": data.get("uuid"),
            "Severity": data.get("severity"),
            "Sighting": data.get("sighting"),
        }
        record_list.append(new_record)
    headers = record_list[0] if record_list else {}
    headers = list(headers.keys())
    markdown = tableToMarkdown(title, record_list, headers=headers, removeNull=True)
    return markdown


def command_helper_function(client: Client, args: dict[str, Any], command: str):
    """
    A helper function that aids in pagination for querying an API.

    Args:
        client: SpyCloud client to use.
        args: demisto.args().
        command: Command to execute

    Returns:
        CommandResults: A ``CommandResults`` object that is then passed to
        ``return_results``, that contains an updated result.
    """
    results = []
    spycloud_args = create_spycloud_args(args)

    page = arg_to_number(args.get("page"), arg_name="page")
    page_size = arg_to_number(args.get("page_size"), arg_name="page_size")
    limit = arg_to_number(args.get("limit", DEFAULT_PAGE_SIZE), arg_name="limit")
    all_results = argToBoolean(args.get("all_results", False))
    endpoint, title_string, context, key_field, search_args = command_dict[command]
    endpoint = endpoint.format(args.get(search_args))
    title_string = title_string.format(args.get(search_args))
    response = client.query_spy_cloud_api(endpoint, spycloud_args)
    total_records = response.get("hits", 0)
    if total_records <= 0:
        return CommandResults(readable_output="No data to present.\n")
    title = get_command_title_string(title_string, page, page_size, total_records)
    results += response.get("results", [])
    cursor = response.get("cursor", "")
    if all_results:
        while cursor:
            res = client.query_spy_cloud_api(endpoint, {"cursor": cursor})
            cursor = res.get("cursor")
            results += res.get("results", [])
    else:
        updated_limit, offset = pagination(page, page_size, limit)
        if total_records > offset:
            for _i in range(offset // 1000):
                res = client.query_spy_cloud_api(endpoint, {"cursor": cursor})
                cursor, results = res.get("cursor"), results + res.get("results", [])
        else:
            return CommandResults(
                readable_output=f"No data available for page {page}. Total "
                f"are {ceil(total_records / page_size)}"
            )
        results = get_paginated_results(results, offset, updated_limit)
    breach_command = ["spycloud-breach-catalog-list", "spycloud-breach-catalog-get"]
    readable_output = (
        lookup_to_markdown_table(results, title)
        if command not in breach_command
        else breaches_lookup_to_markdown(results, title)
    )

    return CommandResults(
        readable_output=readable_output,
        outputs_prefix=f"{INTEGRATION_CONTEXT_NAME}.{context}",
        outputs_key_field=key_field,
        outputs=results,
    )


def get_command_title_string(
    sub_context: str, page: int | None, page_size: int | None, hits: int | None
) -> str:
    """
    Define command title
    Args:
        sub_context: Commands sub_context
        page: page_number
        page_size: page_size
        hits: total number of page
    Returns:
        Returns the title for the readable output
    """
    if page and page_size and (page > 0 and page_size > 0):
        total_page = ceil(hits / page_size) if hits and hits > 0 else 1
        return (
            f"{sub_context} \nCurrent page size: {page_size}\n"
            f"Showing page {page} out of {total_page}"
        )

    return f"{sub_context}"


command_dict = {
    "spycloud-breach-catalog-list": COMMAND_PARAMS(
        "breach/catalog",
        "Breach List",
        "BreachList",
        "uuid",
        "",
    ),
    "spycloud-breach-catalog-get": COMMAND_PARAMS(
        "breach/catalog/{}",
        "Breach data for id {}",
        "BreachData",
        "id",
        "id",
    ),
    "spycloud-domain-data-get": COMMAND_PARAMS(
        "breach/data/domains/{}",
        "Breach List for domain {}",
        "Domain",
        "document_id",
        "domain",
    ),
    "spycloud-username-data-get": COMMAND_PARAMS(
        "breach/data/usernames/{}",
        "Breach List for username {}",
        "Username",
        "document_id",
        "username",
    ),
    "spycloud-ip-address-data-get": COMMAND_PARAMS(
        "breach/data/ips/{}",
        "Breach List for IP address {}",
        "IPAddress",
        "document_id",
        "ip",
    ),
    "spycloud-email-data-get": COMMAND_PARAMS(
        "breach/data/emails/{}",
        "Breach List for Email address {}",
        "EmailAddress",
        "document_id",
        "email",
    ),
    "spycloud-password-data-get": COMMAND_PARAMS(
        "breach/data/passwords/{}",
        "Breach List for Password {}",
        "Password",
        "document_id",
        "password",
    ),
    "spycloud-watchlist-data-list": COMMAND_PARAMS(
        "breach/data/watchlist",
        "Watchlist Data",
        "Watchlist",
        "document_id",
        "",
    ),
    "spycloud-compass-device-data-get": COMMAND_PARAMS(
        "compass/data/devices/{}",
        "Compass Devices - Data",
        "CompassDeviceData",
        "document_id",
        "infected_machine_id",
    ),
    "spycloud-compass-data-list": COMMAND_PARAMS(
        "compass/data",
        "Compass Data List",
        "CompassDataList",
        "document_id",
        "",
    ),
    "spycloud-compass-device-list": COMMAND_PARAMS(
        "compass/devices",
        "Compass Device List",
        "CompassDeviceList",
        "document_id",
        "",
    ),
    "spycloud-compass-application-data-get": COMMAND_PARAMS(
        "compass/data/applications/{}",
        "Compass Applications - Data",
        "CompassDeviceData",
        "document_id",
        "target_application",
    ),
}


def main():
    """
    PARSE AND VALIDATE INTEGRATION PARAMS
    """
    params = demisto.params()
    apikey = params.get("apikey")
    args = demisto.args()
    verify_certificate = not params.get("insecure", False)
    proxy = params.get("proxy", False)
    handle_proxy()
    command = demisto.command()
    try:
        base_url = params.get("url")
        client = Client(base_url, apikey, verify=verify_certificate, proxy=proxy)
        demisto.info(f"Command being called is {command}")
        if command == "test-module":
            return_results(test_module(client))
        elif command in command_dict:
            return_results(command_helper_function(client, args, command))
        else:
            raise NotImplementedError(f"command {command} is not supported")
    except Exception as e:
        return_error(f"Failed to execute {command} command. Error: {str(e)}")


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
