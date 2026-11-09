from collections.abc import Callable
from datetime import timezone
from typing import Any

import demistomock as demisto
from CommonServerPython import *
from oci.regions import is_region
from oci.signer import Signer

""" CONSTANTS """

DATE_FORMAT = "%Y-%m-%dT%H:%M:%S.%fZ"  # ISO8601 format with UTC, default in XSOAR
VENDOR = "oracle"
PRODUCT = "cloud_infrastructure"
MAX_EVENTS_TO_FETCH = 1000
FETCH_DEFAULT_TIME = "3 days"
PORT = 20190901
SEARCHLOG_DATE_FORMAT = "%Y-%m-%dT%H:%M:%S.000Z"
SEARCHLOG_FIRST_FETCH_TIME_IN_MINUTES = 10
AUDIT_EVENT_TYPE = "Audit"
SEARCHLOG_EVENT_TYPE = "Search Logs"
CLOUDGUARD_EVENT_TYPE = "CloudGuard Problems"
# Last run keys per event type. These keys are persisted between fetch cycles and must not be renamed.
AUDIT_LAST_RUN_KEY = "lastRun"
SEARCHLOG_LAST_RUN_KEY = "SearchLog"
CLOUDGUARD_LAST_RUN_KEY = "CloudGuardProblems"
EVENT_TYPE_LAST_RUN_KEYS = {
    AUDIT_EVENT_TYPE: AUDIT_LAST_RUN_KEY,
    SEARCHLOG_EVENT_TYPE: SEARCHLOG_LAST_RUN_KEY,
    CLOUDGUARD_EVENT_TYPE: CLOUDGUARD_LAST_RUN_KEY,
}
EVENT_TYPE_TABLE_TITLES = {
    AUDIT_EVENT_TYPE: "Oracle Cloud Infrastructure Audit Events",
    SEARCHLOG_EVENT_TYPE: "Oracle Cloud Infrastructure Search Logs Events",
    CLOUDGUARD_EVENT_TYPE: "Oracle Cloud Infrastructure CloudGuard Problems",
}
SEARCHLOG_QUERY_REQUIRED_ERROR = "The parameter 'Search log query' is required in order to fetch search logs."
CLOUDGUARD_API_VERSION = "20200131"
CLOUDGUARD_PAGE_SIZE = 1000
# Single timestamp format used for every CloudGuard fetch-window value (request params and stored cursor).
CLOUDGUARD_DATE_FORMAT = "%Y-%m-%dT%H:%M:%S.%fZ"
# ListProblems query parameters that are set by the collector and therefore can not be overridden by the user.
CLOUDGUARD_COLLECTOR_CONTROLLED_KEYS = {
    "compartmentId",
    "compartmentIdInSubtree",
    "accessLevel",
    "timeLastDetectedGreaterThanOrEqualTo",
    "timeLastDetectedLessThanOrEqualTo",
    "sortBy",
    "sortOrder",
    "limit",
    "page",
}
# ListProblems filter query parameters that may be passed through the 'CloudGuard Problems query' parameter.
CLOUDGUARD_ALLOWED_QUERY_KEYS = {
    "lifecycleDetail",
    "lifecycleState",
    "region",
    "riskLevel",
    "resourceType",
    "city",
    "state",
    "country",
    "label",
    "detectorRuleIdList",
    "detectorType",
    "targetId",
    "problemCategory",
    "resourceId",
    "timeFirstDetectedGreaterThanOrEqualTo",
    "timeFirstDetectedLessThanOrEqualTo",
}

""" CLIENT CLASS """


class Client(BaseClient):
    """Client class to interact with the OCI SDK and API requests.
    Will validate the fetching related parameters and create an OCI Singer object which will be used to fetch audit events.
    """

    def __init__(
        self,
        verify_certificate: bool,
        proxy: bool,
        user_ocid: str,
        private_key: str,
        key_fingerprint: str,
        tenancy_ocid: str,
        region: str,
        compartment_id: str,
        private_key_type: str,
    ):
        self.singer = self.build_singer_object(user_ocid, private_key, key_fingerprint, tenancy_ocid, private_key_type)
        self.base_url = self.build_audit_base_url(region)
        self.searchlog_url = self.build_searchlog_url(region)
        self.cloudguard_url = self.build_cloudguard_url(region)
        self.compartment_id = compartment_id if compartment_id else tenancy_ocid
        super().__init__(proxy=proxy, verify=verify_certificate, auth=self.singer, base_url=self.base_url)

    def build_singer_object(
        self, user_ocid: str, private_key: str, key_fingerprint: str, tenancy_ocid: str, private_key_type: str
    ) -> dict[str, str]:
        """Build a singer object.
        The Signer used as part of making raw requests.

        Args:
            user_ocid (str): User OCID parameter.
            private_key (str): Private Key parameter.
            key_fingerprint (str): API Key Fingerprint parameter.
            tenancy_ocid (str): Tenancy OCID parameter.
            private_key_type (str): The type of the private key.

        Raises:
            DemistoException: If the singer object is invalid.

        Returns:
            (dict): A config dictionary that can be used to create Audit clients.
        """
        try:
            validated_private_key = self.validate_private_key_syntax(private_key, private_key_type)

            singer = Signer(
                tenancy=tenancy_ocid,
                user=user_ocid,
                fingerprint=key_fingerprint,
                private_key_content=validated_private_key,
                private_key_file_location=None,
            )
        except Exception as e:
            raise DemistoException(
                "Could not create a valid OCI singer object, Please check the instance configuration parameters.", exception=e
            ) from e

        return singer

    def build_audit_base_url(self, region: str) -> str:
        """Build the base URL for the client.

        Args:
            region (str): Region parameter.

        Raises:
            DemistoException: If the region is not valid.

        Returns:
            str: Base URL for the client.
        """
        if not is_region(region):
            raise DemistoException(
                "Could not create a valid OCI configuration dictionary due to invalid region parameter. "
                "Please check your OCI-related instance configuration parameters."
            )

        return f"https://audit.{region}.oraclecloud.com/{PORT}/auditEvents"

    def build_searchlog_url(self, region: str) -> str:
        """Build the base URL for the search logs API.

        Args:
            region (str): Region parameter.

        Raises:
            DemistoException: If the region is not valid.

        Returns:
            str: Base URL for the search logs API.
        """
        if not is_region(region):
            raise DemistoException(
                "Could not create a valid OCI configuration dictionary due to invalid region parameter. "
                "Please check your OCI-related instance configuration parameters."
            )

        return f"https://logging.{region}.oci.oraclecloud.com/20190909/search"

    def build_cloudguard_url(self, region: str) -> str:
        """Build the URL for the Cloud Guard ListProblems API.

        Args:
            region (str): Region parameter. Must be the Cloud Guard reporting region in order to return Problems.

        Raises:
            DemistoException: If the region is not valid.

        Returns:
            str: URL for the Cloud Guard ListProblems API.
        """
        if not is_region(region):
            raise DemistoException(
                "Could not create a valid OCI configuration dictionary due to invalid region parameter. "
                "Please check your OCI-related instance configuration parameters."
            )

        return f"https://cloudguard-cp-api.{region}.oci.oraclecloud.com/{CLOUDGUARD_API_VERSION}/problems"

    def validate_private_key_syntax(self, private_key_parameter: str, private_key_type: str) -> str:
        """Validate private key parameter syntax.
        The Private Key parameter needs to be provided to the OCI SDK singer object in a specific format.
        The most common way to obtain the private key is to download a .pem file from the OCI console.
        If copied from a .pem file, the private key parameter may contain unnecessary spaces.
        Further more, since the format uses \n as part of the key,
        passing this value as a configuration parameter may result in escaped \n characters.

        This function will preform the following actions on the private key parameter:
            - Unescape the string.
            - Remove unnecessary spaces in the string.

        Example:
        Raw Private Key parameter: -----BEGIN PRIVATE KEY-----\\n\n THIS-IS-A\\n\n PRIVATE-KEY\\n\n -----END PRIVATE KEY-----
        Output: -----BEGIN PRIVATE KEY-----\nTHIS-IS-A\nPRIVATE-KEY\n-----END PRIVATE KEY-----

        Args:
            private_key_parameter (str): Private Key parameter.
            private_key_type(str): The type of the private key PKCS#1 and PKCS#8.
                More info about the types: https://stackoverflow.com/questions/48958304/pkcs1-and-pkcs8-format-for-rsa-private-key

        Returns:
            str: Private Key parameter unescaped and spaceless.
        """
        private_key = stringUnEscape(private_key_parameter)
        private_key = private_key.replace("\n\n", "\n")

        if " " not in private_key:
            return private_key

        demisto.debug(f"{private_key_type=}")
        if private_key_type == "PKCS#8":
            prefix = "-----BEGIN PRIVATE KEY-----"
            postfix = "-----END PRIVATE KEY-----"
        else:
            prefix = "-----BEGIN RSA PRIVATE KEY-----"
            postfix = "-----END RSA PRIVATE KEY-----"

        private_key = private_key.replace(prefix, "").replace(postfix, "")

        private_key_sections = private_key.strip().split(" ")
        striped_private_key = "".join(private_key_sections)
        return prefix + "\n" + striped_private_key + "\n" + postfix


""" Event related functions """


def add_time_key_to_events(events: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """
    Add the _time key to the events.
    It is the current decided solution for the _time data model field.
    Note:   _time used to be parsed as a parsing rule in XSIAM,
            but to avoid a lot of cases where parsing rules were created only for _time field,
            now the current acceptable solution is to "map" this attribute programmatically.
    Args:
        events (list[dict[str, Any]]): The events to add the time key to.
    Returns:
        list[dict[str, Any]]: The events with the _time key.
    """
    for event in events:
        if event_time := event.get("eventTime"):
            event["_time"] = event_time

    return events


def get_last_event_time(events: list, first_fetch_time: datetime) -> str:
    """Get the latest event time from the fetched events list for next fetch cycle.
    - Given a non empty list of events, the function will return the time of the last event (most recent event) + 1 milliseconds.
    - If the event list is empty, the function will return the current first fetch time.

    Args:
        events (list): list of fetched events.
        first_fetch_time (datetime): current first fetch time.

    Returns:
        str: first fetch time for next fetch cycle.
        - If the events list is not empty, return the time of the latest event + 1 milliseconds.
        - If the events list is empty, return the current first fetch time.
    """
    if not events:
        return first_fetch_time.strftime(DATE_FORMAT)

    last_event_time = events[-1].get("eventTime")
    if not isinstance(last_event_time, datetime):
        last_event_time = arg_to_datetime(arg=last_event_time, settings={"RETURN_AS_TIMEZONE_AWARE": False})

    return (
        (last_event_time + timedelta(milliseconds=1)).strftime(DATE_FORMAT)
        if last_event_time
        else first_fetch_time.strftime(DATE_FORMAT)
    )


def get_fetch_time(last_run: str | None, first_fetch_param: str) -> datetime | None:
    """Calculates the time in which the current fetch should start from.

    Args:
        last_run (Optional[str]): Last run time from previous fetch.
        first_fetch_param (str): First fetch time parameter.

    Returns:
        Optional[datetime]: Maximum datetime value between last run from previous fetch and first fetch time parameter.
    """
    first_fetch_param_datetime = arg_to_datetime(arg=first_fetch_param)

    # if last_run is None (first time we are fetching) -> return first_fetch_arg datetime object
    if not last_run:
        return first_fetch_param_datetime
    else:
        last_run_datetime = arg_to_datetime(arg=last_run, settings={"RETURN_AS_TIMEZONE_AWARE": False})

    if last_run_datetime and first_fetch_param_datetime:
        return max(last_run_datetime, first_fetch_param_datetime)
    else:
        return arg_to_datetime(arg=FETCH_DEFAULT_TIME)


def events_to_command_results(events: list[dict[str, Any]], title: str) -> CommandResults:
    """Returns a CommandResults object with a table of fetched events.

    Args:
        events (list[dict[str, Any]]): list of fetched events.
        title (str): The title of the table of fetched events.
    Returns:
        CommandResults: CommandResults object with a table of fetched events.
    """
    return CommandResults(
        readable_output=tableToMarkdown(title, events, removeNull=True, headerTransform=pascalToSpace),
        raw_response=events,
    )


def audit_log_api_request(client: Client, start_time: str, next_page: str | None = None) -> requests.Response:
    """Makes HTTP GET request to an OCI API endpoint.

    Args:
        client (Client): client object.
        start_time (str): start time query parameter.
        next_page (str | None, optional): next page query parameter for pagination. Defaults to None.

    Returns:
        requests.Response: raw response from the API.
    """
    params = {"compartmentId": client.compartment_id, "startTime": start_time, "endTime": datetime.now().strftime(DATE_FORMAT)}
    if next_page:
        params["opc-next-page"] = next_page
    demisto.debug(f"[API] Requesting OCI audit events. compartmentId={client.compartment_id} url={client.base_url} {params=}")
    try:
        return client._http_request(method="GET", params=params, resp_type="response")
    except Exception as e:
        raise DemistoException(
            f"OCI audit events request failed for compartmentId={client.compartment_id} at {client.base_url}: {e}"
        ) from e


def searchlogs_api_request(
    client: Client, time_start: str, time_end: str, search_query: str, limit: int = 1000, next_page: str | None = None
) -> requests.Response:
    """Makes HTTP POST request to the OCI Search Logs API endpoint.

    Args:
        client (Client): client object.
        time_start (str): start time for the search query.
        time_end (str): end time for the search query.
        search_query (str): the search query string.
        limit (int, optional): maximum number of results to return. Defaults to 1000.
        next_page (str | None, optional): next page query parameter for pagination. Defaults to None.

    Returns:
        requests.Response: raw response from the API.
    """
    url = client.searchlog_url
    body = {"timeStart": time_start, "timeEnd": time_end, "searchQuery": search_query, "isReturnFieldInfo": False}
    params: dict[str, str | int] = {"limit": limit}
    if next_page:
        params["page"] = next_page

    demisto.debug(f"Sending http request to get search log events with {body=} {params=}")
    try:
        return client._http_request(method="POST", full_url=url, params=params, json_data=body, resp_type="response")
    except Exception as e:
        raise DemistoException(f"OCI search log events request failed at {url}: {e}") from e


def add_millisecond_to_timestamp(timestamp: str) -> str:
    """Add 1 millisecond to the given timestamp.

    Args:
        timestamp (str): Timestamp to add 1 millisecond to.

    Raises:
        DemistoException: If datetime conversion fails.

    Returns:
        str: Timestamp with 1 millisecond added.
    """
    try:
        timestamp_datetime = arg_to_datetime(arg=timestamp, settings={"RETURN_AS_TIMEZONE_AWARE": False})
        if isinstance(timestamp_datetime, datetime):
            return (timestamp_datetime + timedelta(milliseconds=1)).strftime(DATE_FORMAT)
        else:
            raise DemistoException("Datetime conversion failed.")
    except Exception as e:
        raise DemistoException(message=e) from e


def deduplicate_events(
    events: list[dict[str, Any]],
    last_fetched_ids: list[str],
    key_func: Callable[[dict[str, Any]], Any] | None = None,
) -> list[dict[str, Any]]:
    """Remove already-processed events based on previously fetched IDs.

    Args:
        events (list[dict[str, Any]]): The events to deduplicate.
        last_fetched_ids (list[str]): The keys of the previously fetched events.
        key_func (Callable | None): Function that returns the deduplication key of an event. Defaults to the event 'id'.

    Returns:
        list[dict[str, Any]]: The events whose key was not previously fetched.
    """
    get_key = key_func or (lambda event: event.get("id"))

    if not last_fetched_ids:
        demisto.debug("[Dedup] No deduplication needed (first run - no previous IDs)")
        return events

    demisto.debug(f"[Dedup] Checking {len(events)} events against {len(last_fetched_ids)} previously fetched IDs")

    # Convert to set for O(1) lookup
    fetched_ids_set = set(last_fetched_ids)

    # Filter out events that were already fetched
    new_events = [event for event in events if get_key(event) not in fetched_ids_set]

    skipped_count = len(events) - len(new_events)
    if skipped_count > 0:
        demisto.debug(f"[Dedup] Skipped {skipped_count} duplicates. {len(new_events)} new events remain.")
    else:
        demisto.debug("[Dedup] No duplicates found.")

    return new_events


def get_searchlogs_events(
    client: Client, search_log_query: str, max_fetch: int, last_searchlogs_ids: list[str], first_fetch_time: str
) -> tuple[list[dict[str, Any]], dict]:
    """Fetch search log events from the OCI Search Logs API.

    Retrieves events using the OCI Search Logs API, handles pagination, deduplication,
    and computes the last run state for the next fetch cycle.

    Args:
        client (Client): Client object for API requests.
        search_log_query (str): The search log query string from the instance configuration.
        max_fetch (int): The maximum number of events to fetch.
        last_searchlogs_ids (list[str]): The last fetched events IDs.
        first_fetch_time (str): The start time to fetch events from.

    Raises:
        DemistoException: If a Search Logs API request fails or the start time is invalid.

    Returns:
        tuple[list[dict[str, Any]], dict]: A tuple containing:
            - list of search log events.
            - last run dict with keys 'lastRun' (str) and 'LastFetchedIds' (list[str]).
    """
    searchlogs_events: list[dict[str, Any]] = []
    last_run = first_fetch_time
    searchlogs_time_end = (arg_to_datetime(first_fetch_time) + timedelta(days=14)).strftime(SEARCHLOG_DATE_FORMAT)  # type: ignore

    searchlogs_res = searchlogs_api_request(
        client=client, time_start=first_fetch_time, time_end=searchlogs_time_end, search_query=search_log_query
    )

    for result in json.loads(searchlogs_res.content).get("results", []):
        event_data = result.get("data", {}).get("logContent", {})
        searchlog_time = event_data.get("time")
        event_data["_time"] = searchlog_time
        if not searchlog_time:
            demisto.debug(f"Search log event with Id {event_data.get('id')} has no time field.")
        searchlogs_events.append(event_data)

    while len(searchlogs_events) < max_fetch and (next_page := searchlogs_res.headers._store.get("opc-next-page")):  # type: ignore[attr-defined]
        searchlogs_res = searchlogs_api_request(
            client=client,
            time_start=first_fetch_time,
            time_end=searchlogs_time_end,
            search_query=search_log_query,
            next_page=next_page[1],
        )

        results = json.loads(searchlogs_res.content).get("results", [])
        if not results:
            break

        for result in results:
            event_data = result.get("data", {}).get("logContent", {})
            event_data["_time"] = event_data.get("time")
            searchlogs_events.append(event_data)

    if searchlogs_events:
        # Deduplicate
        searchlogs_events = deduplicate_events(searchlogs_events, last_searchlogs_ids)
        searchlogs_events = searchlogs_events[:max_fetch]

    if searchlogs_events:
        last_run = searchlogs_events[-1]["_time"]
        last_searchlogs_ids = [
            str(event.get("id")) for event in searchlogs_events if event.get("_time") == last_run and event.get("id")
        ]

    return searchlogs_events, {"lastRun": last_run, "LastFetchedIds": last_searchlogs_ids}


""" CloudGuard Problems related functions """


def parse_cloudguard_query(cloudguard_query: str | None) -> dict[str, str]:
    """Parse the 'CloudGuard Problems query' parameter into ListProblems query parameters.

    The query is a list of key=value pairs separated by ';' (e.g. riskLevel=CRITICAL;lifecycleState=ACTIVE).

    Args:
        cloudguard_query (str | None): The raw query parameter value.

    Raises:
        DemistoException: If a pair is malformed or a key is not a supported ListProblems filter.

    Returns:
        dict[str, str]: The parsed filters. Empty if no query was provided.
    """
    filters: dict[str, str] = {}
    if not cloudguard_query:
        return filters

    for pair in cloudguard_query.split(";"):
        pair = pair.strip()
        if not pair:
            continue
        key, separator, value = pair.partition("=")
        key, value = key.strip(), value.strip()
        if not separator or not key or not value:
            raise DemistoException(
                f"Invalid 'CloudGuard Problems query' entry: '{pair}'. Expected key=value pairs separated by ';' "
                "(for example: riskLevel=CRITICAL;lifecycleState=ACTIVE)."
            )
        if key in CLOUDGUARD_COLLECTOR_CONTROLLED_KEYS:
            raise DemistoException(
                f"The key '{key}' in 'CloudGuard Problems query' can not be set manually, it is managed by the collector "
                "to control the fetch window, sorting and pagination. Remove it from the query. "
                f"Supported keys are: {', '.join(sorted(CLOUDGUARD_ALLOWED_QUERY_KEYS))}."
            )
        if key not in CLOUDGUARD_ALLOWED_QUERY_KEYS:
            raise DemistoException(
                f"Unsupported key '{key}' in 'CloudGuard Problems query'. "
                f"Supported keys are: {', '.join(sorted(CLOUDGUARD_ALLOWED_QUERY_KEYS))}."
            )
        filters[key] = value

    return filters


def format_cloudguard_time(value: datetime | str | None) -> str:
    """Normalize a timestamp to the single CloudGuard timestamp format (UTC, CLOUDGUARD_DATE_FORMAT).

    Args:
        value (datetime | str | None): A datetime object or a timestamp string (RFC3339 or relative, e.g. '3 days').

    Raises:
        DemistoException: If the value can not be parsed as a timestamp.

    Returns:
        str: The timestamp formatted with CLOUDGUARD_DATE_FORMAT in UTC.
    """
    try:
        parsed = value if isinstance(value, datetime) else arg_to_datetime(value)
    except ValueError:
        parsed = None
    if not isinstance(parsed, datetime):
        raise DemistoException(f"Could not parse CloudGuard timestamp: {value}")
    if parsed.tzinfo:
        parsed = parsed.astimezone(timezone.utc)  # noqa: UP017
    return parsed.strftime(CLOUDGUARD_DATE_FORMAT)


def get_cloudguard_first_fetch_time(first_fetch_param: str) -> str:
    """Get the start of the first CloudGuard fetch window from the 'First fetch time' parameter.

    Args:
        first_fetch_param (str): First fetch time parameter.

    Returns:
        str: The first fetch time formatted with CLOUDGUARD_DATE_FORMAT.
    """
    return format_cloudguard_time(arg_to_datetime(first_fetch_param) or arg_to_datetime(FETCH_DEFAULT_TIME))


def cloudguard_problems_api_request(
    client: Client,
    time_start: str,
    time_end: str,
    filters: dict[str, str],
    limit: int = CLOUDGUARD_PAGE_SIZE,
    next_page: str | None = None,
) -> requests.Response:
    """Makes HTTP GET request to the OCI Cloud Guard ListProblems API endpoint.

    Args:
        client (Client): client object.
        time_start (str): start of the fetch window (timeLastDetectedGreaterThanOrEqualTo).
        time_end (str): end of the fetch window (timeLastDetectedLessThanOrEqualTo).
        filters (dict[str, str]): user-supplied ListProblems filters.
        limit (int, optional): page size. Defaults to CLOUDGUARD_PAGE_SIZE.
        next_page (str | None, optional): page token for pagination. Defaults to None.

    Returns:
        requests.Response: raw response from the API.
    """
    url = client.cloudguard_url
    params: dict[str, Any] = {
        **filters,
        "compartmentId": client.compartment_id,
        "compartmentIdInSubtree": "true",
        "accessLevel": "ACCESSIBLE",
        "timeLastDetectedGreaterThanOrEqualTo": time_start,
        "timeLastDetectedLessThanOrEqualTo": time_end,
        "sortBy": "timeLastDetected",
        "sortOrder": "ASC",
        "limit": limit,
    }
    if next_page:
        params["page"] = next_page

    demisto.debug(f"[API] Requesting OCI CloudGuard problems. url={url} {params=}")
    try:
        return client._http_request(method="GET", full_url=url, params=params, resp_type="response")
    except Exception as e:
        raise DemistoException(f"OCI CloudGuard problems request failed at {url}: {e}") from e


def get_problem_dedup_key(problem: dict[str, Any]) -> str:
    """Build the deduplication key of a CloudGuard Problem.

    A Problem keeps the same id when it is detected again, so the id is combined with timeLastDetected
    to make each (new or updated) occurrence unique.

    Args:
        problem (dict[str, Any]): A CloudGuard Problem.

    Returns:
        str: The deduplication key in the format '<id>|<timeLastDetected>'.
    """
    return f"{problem.get('id')}|{problem.get('timeLastDetected')}"


def add_cloudguard_fields(problem: dict[str, Any]) -> dict[str, Any]:
    """Set the _time, _source_log_type and _ENTRY_STATUS fields of a CloudGuard Problem.

    - _time is mapped from timeLastDetected.
    - _source_log_type is 'CloudGuard Problems'.
    - _ENTRY_STATUS is 'new' when timeLastDetected == timeFirstDetected and 'updated' when timeLastDetected is later.

    Args:
        problem (dict[str, Any]): A CloudGuard Problem.

    Returns:
        dict[str, Any]: The same Problem with the added fields.
    """
    time_last_detected = problem.get("timeLastDetected")
    problem["_time"] = time_last_detected
    problem["_source_log_type"] = CLOUDGUARD_EVENT_TYPE

    first_detected = arg_to_datetime(problem.get("timeFirstDetected"))
    last_detected = arg_to_datetime(time_last_detected)
    if first_detected and last_detected:
        problem["_ENTRY_STATUS"] = "updated" if last_detected > first_detected else "new"
    else:
        demisto.debug(f"CloudGuard problem {problem.get('id')} is missing a detection time, _ENTRY_STATUS was not set.")

    return problem


def build_cloudguard_last_run(
    problems: list[dict[str, Any]], previous_last_run: str, previous_fetched_keys: list[str]
) -> dict[str, Any]:
    """Compute the CloudGuard last run for the next fetch cycle.

    Args:
        problems (list[dict[str, Any]]): The Problems fetched in this cycle (sorted by timeLastDetected ascending).
        previous_last_run (str): The previous cursor (formatted with CLOUDGUARD_DATE_FORMAT).
        previous_fetched_keys (list[str]): The deduplication keys stored in the previous cycle.

    Returns:
        dict[str, Any]: last run dict with keys 'lastRun' (str, CLOUDGUARD_DATE_FORMAT) and 'LastFetchedIds' (list[str]).
    """
    if not problems or not problems[-1].get("timeLastDetected"):
        return {"lastRun": previous_last_run, "LastFetchedIds": previous_fetched_keys}

    last_run = format_cloudguard_time(problems[-1]["timeLastDetected"])
    keys = [
        get_problem_dedup_key(problem)
        for problem in problems
        if problem.get("timeLastDetected") and format_cloudguard_time(problem["timeLastDetected"]) == last_run
    ]
    if last_run == previous_last_run:
        # The cursor did not move, keep the previous keys so those Problems are not fetched again.
        keys = list(dict.fromkeys(previous_fetched_keys + keys))

    return {"lastRun": last_run, "LastFetchedIds": keys}


def get_cloudguard_problems(
    client: Client, filters: dict[str, str], max_fetch: int, last_fetched_keys: list[str], first_fetch_time: str
) -> tuple[list[dict[str, Any]], dict]:
    """Fetch Problems from the OCI Cloud Guard ListProblems API.

    Handles pagination, deduplication (by id + timeLastDetected), _time/_ENTRY_STATUS enrichment
    and computes the last run state for the next fetch cycle.

    Args:
        client (Client): Client object for API requests.
        filters (dict[str, str]): user-supplied ListProblems filters.
        max_fetch (int): The maximum number of Problems to fetch.
        last_fetched_keys (list[str]): The deduplication keys stored in the previous cycle.
        first_fetch_time (str): The start of the fetch window.

    Raises:
        DemistoException: If a ListProblems request fails. No Problems are returned in that case,
            so the last run is not advanced and the window is fetched again in the next cycle.

    Returns:
        tuple[list[dict[str, Any]], dict]: A tuple containing:
            - list of CloudGuard Problems.
            - last run dict with keys 'lastRun' (str) and 'LastFetchedIds' (list[str]).
    """
    problems: list[dict[str, Any]] = []
    time_end = format_cloudguard_time(datetime.now(timezone.utc))  # noqa: UP017
    next_page: str | None = None

    while len(problems) < max_fetch:
        response = cloudguard_problems_api_request(
            client=client, time_start=first_fetch_time, time_end=time_end, filters=filters, next_page=next_page
        )
        items = json.loads(response.content).get("items", [])
        problems.extend(deduplicate_events(items, last_fetched_keys, key_func=get_problem_dedup_key))

        next_page = response.headers.get("opc-next-page")
        if not items or not next_page:
            break

    problems = [add_cloudguard_fields(problem) for problem in problems[:max_fetch]]
    demisto.info(f"OCI: {len(problems)} CloudGuard problems fetched from start time: {first_fetch_time}.")
    return problems, build_cloudguard_last_run(problems, first_fetch_time, last_fetched_keys)


def fetch_cloudguard_problems(
    client: Client, cloudguard_query: str | None, max_fetch: int, cloudguard_last_run: dict[str, Any], first_fetch: str
) -> tuple[list[dict[str, Any]], dict]:
    """Run the CloudGuard Problems fetch flow: parse the user query, resolve the fetch window start and fetch.

    Args:
        client (Client): Client object for API requests.
        cloudguard_query (str | None): The raw 'CloudGuard Problems query' parameter.
        max_fetch (int): The maximum number of Problems to fetch.
        cloudguard_last_run (dict[str, Any]): The CloudGuard last run sub-key from the previous cycle.
        first_fetch (str): The 'First fetch time' parameter.

    Raises:
        DemistoException: If the query is invalid or a ListProblems request fails.

    Returns:
        tuple[list[dict[str, Any]], dict]: The fetched Problems and the CloudGuard last run for the next cycle.
    """
    filters = parse_cloudguard_query(cloudguard_query)
    stored_cursor = cloudguard_last_run.get("lastRun")
    start_time = format_cloudguard_time(stored_cursor) if stored_cursor else get_cloudguard_first_fetch_time(first_fetch)
    return get_cloudguard_problems(client, filters, max_fetch, cloudguard_last_run.get("LastFetchedIds", []), start_time)


class EventFetchError(DemistoException):
    """Raised when an event type fetch fails after some events were already collected.

    Carries the partial events and the matching last run so the caller can still send them
    and advance the last run of that event type.
    """

    def __init__(self, message: str, events: list[dict[str, Any]], last_run: Any):
        super().__init__(message)
        self.events = events
        self.last_run = last_run


def get_events(
    client: Client, first_fetch_time: datetime | None, max_fetch: int, push_events_on_error: bool
) -> tuple[list[dict[str, Any]], str]:
    """Get events from an oracle cloud infrastructure tenant.
    - The request returns a maximum of 100 events per call by default.
    - This function uses pagination, meaning it will make multiple request as needed to reach the desired amount of events.

    Args:
        client (Client): Client object for requests.
        first_fetch_time (datetime): The start time to fetch events from.
        max_fetch (int): The limit of events to fetch.
        push_events_on_error (bool): Whether to push available fetched events to XSIAM if an error occurred while fetching events.

    Raises:
        DemistoException: If the first fetch time is invalid or an error occurred while fetching events.
        EventFetchError: If an error occurred after some events were collected and push_events_on_error is False.

    Returns:
        tuple[list[dict[str, Any]], str]: A tuple of the events list and the last event time for next fetch cycle.
    """
    if not isinstance(first_fetch_time, datetime):
        raise DemistoException("Could not resolve First fetch time parameter.")

    # Initialize before the try so the except handler can safely reference them
    # even if the first API call fails.
    events: list[dict[str, Any]] = []
    last_event_time = first_fetch_time.strftime(DATE_FORMAT)

    try:
        response = audit_log_api_request(client=client, start_time=first_fetch_time.strftime(DATE_FORMAT))
        events = json.loads(response.content)

        if not events:
            return [], first_fetch_time.strftime(DATE_FORMAT)

        if isinstance(events, dict):
            events = [events]

        # pagination handling
        while len(events) < max_fetch and (next_page := response.headers._store.get("opc-next-page")):  # type: ignore
            current_start_time = add_millisecond_to_timestamp(events[-1].get("eventTime"))  # type: ignore[arg-type]
            response = audit_log_api_request(client=client, start_time=current_start_time, next_page=next_page[1])
            events.extend(json.loads(response.content))

        last_event_time = get_last_event_time(events, first_fetch_time)
        events = add_time_key_to_events(events)

    # Handle the case where an error occurred while fetching events,
    # and there are currently available events that can and need to be sent to XSIAM.
    except Exception as e:
        error_message = f"Error while fetching events: {e}"
        if not events:
            raise DemistoException(error_message) from e
        last_event_time = get_last_event_time(events, first_fetch_time)
        events = add_time_key_to_events(events)
        if push_events_on_error:
            handle_fetched_events(events, last_event_time)
            raise DemistoException(error_message) from e
        raise EventFetchError(error_message, events, last_event_time) from e

    demisto.info(f"OCI: {len(events)} Events fetched from start time: {first_fetch_time}.")
    return events, last_event_time


def handle_fetched_events(events: list[dict[str, Any]], last_event_time: str):
    """Handles fetched events.
    - Sends the events to XSIAM.
    - Sets the last run for next fetch cycle.

    Args:
        events (list[dict[str, Any]]): Fetched events.
        last_event_time (str): Last event time.
    """
    if events:
        send_events_to_xsiam(events, vendor=VENDOR, product=PRODUCT)
        demisto.info(f"OCI: {len(events)} events were sent to XSIAM at {datetime.now()}.")
        last_run = demisto.getLastRun()
        last_run["lastRun"] = last_event_time
        demisto.setLastRun(last_run)
        demisto.info(f"OCI: Set last run to {last_event_time}")
    else:
        demisto.info("OCI: No new events fetched, Last run was not updated.")


""" Fetch orchestration """


def migrate_last_run(last_run: Any) -> dict[str, Any]:
    """Normalize a last run saved by any previous version of the collector.

    Older versions stored only the Audit 'lastRun' string, later versions added the 'SearchLog' sub-dict,
    and this version adds the 'CloudGuardProblems' sub-dict. Missing keys are fine (each event type starts
    from its first fetch time), malformed values are dropped so they can not break the fetch, and unknown
    keys are kept as-is.

    Args:
        last_run (Any): The raw last run returned by demisto.getLastRun().

    Returns:
        dict[str, Any]: A last run dict that is safe to use by every event type.
    """
    if not isinstance(last_run, dict):
        demisto.debug(f"OCI: Ignoring invalid last run of type {type(last_run).__name__}.")
        return {}

    migrated = dict(last_run)
    audit_last_run = migrated.get(AUDIT_LAST_RUN_KEY)
    if audit_last_run is not None and not isinstance(audit_last_run, str):
        demisto.debug(f"OCI: Dropping invalid Audit last run: {audit_last_run}")
        migrated.pop(AUDIT_LAST_RUN_KEY)

    for sub_key in (SEARCHLOG_LAST_RUN_KEY, CLOUDGUARD_LAST_RUN_KEY):
        sub_last_run = migrated.get(sub_key)
        if sub_last_run is None:
            continue
        if not isinstance(sub_last_run, dict):
            demisto.debug(f"OCI: Dropping invalid {sub_key} last run: {sub_last_run}")
            migrated.pop(sub_key)
            continue
        if not isinstance(sub_last_run.get("LastFetchedIds", []), list):
            migrated[sub_key] = {**sub_last_run, "LastFetchedIds": []}

    return migrated


def fetch_searchlog_events(
    client: Client, search_log_query: str | None, max_fetch: int, searchlog_last_run: dict[str, Any]
) -> tuple[list[dict[str, Any]], dict]:
    """Run the Search Logs fetch flow: validate the query, resolve the fetch window start and fetch.

    Args:
        client (Client): Client object for API requests.
        search_log_query (str | None): The 'Search log query' parameter.
        max_fetch (int): The maximum number of events to fetch.
        searchlog_last_run (dict[str, Any]): The Search Logs last run sub-key from the previous cycle.

    Raises:
        DemistoException: If the query is missing or a Search Logs request fails.

    Returns:
        tuple[list[dict[str, Any]], dict]: The fetched events and the Search Logs last run for the next cycle.
    """
    if not search_log_query:
        raise DemistoException(SEARCHLOG_QUERY_REQUIRED_ERROR)

    start_time = searchlog_last_run.get("lastRun") or (
        datetime.now() - timedelta(minutes=SEARCHLOG_FIRST_FETCH_TIME_IN_MINUTES)
    ).strftime(SEARCHLOG_DATE_FORMAT)
    return get_searchlogs_events(client, search_log_query, max_fetch, searchlog_last_run.get("LastFetchedIds", []), start_time)


def run_event_type_fetchers(
    fetchers: dict[str, Callable[[], tuple[list[dict[str, Any]], Any]]],
) -> dict[str, tuple[list[dict[str, Any]], Any]]:
    """Run each event type fetcher independently so a failure in one does not stop the others.

    When an event type fails, the error is logged and the remaining event types keep running.
    The failed event type keeps its previous last run (unless partial events were collected), so it is retried
    in the next fetch cycle.

    Args:
        fetchers (dict): Event type name to a callable returning (events, last_run).

    Returns:
        dict: Event type to (events, last_run) for every type that returned events
              (including partial events of a failed type).
    """
    fetched: dict[str, tuple[list[dict[str, Any]], Any]] = {}
    for event_type, fetcher in fetchers.items():
        try:
            fetched[event_type] = fetcher()
        except EventFetchError as e:
            demisto.error(
                f"OCI: Failed to fetch {event_type} events ({len(e.events)} events collected before the error), "
                f"continuing with the other event types. Error: {e}"
            )
            fetched[event_type] = (e.events, e.last_run)
        except Exception as e:
            demisto.error(f"OCI: Failed to fetch {event_type} events, continuing with the other event types. Error: {e}")
    return fetched


def send_fetched_events(fetched: dict[str, tuple[list[dict[str, Any]], Any]], last_run: dict[str, Any]) -> dict[str, Any]:
    """Send the fetched events of every event type to XSIAM and update only their last run keys.

    Event types with no events (or that failed before collecting any) keep their previous last run.

    Args:
        fetched (dict): Event type to (events, last_run) as returned by run_event_type_fetchers.
        last_run (dict[str, Any]): The current last run.

    Returns:
        dict[str, Any]: The updated last run.
    """
    for event_type, (events, event_type_last_run) in fetched.items():
        if not events:
            demisto.info(f"OCI: No new {event_type} events fetched, Last run was not updated.")
            continue
        send_events_to_xsiam(events, vendor=VENDOR, product=PRODUCT)
        demisto.info(f"OCI: {len(events)} {event_type} events were sent to XSIAM at {datetime.now()}.")
        last_run[EVENT_TYPE_LAST_RUN_KEYS[event_type]] = event_type_last_run
    return last_run


""" Test module """


def check_audit_connectivity(client: Client) -> None:
    """Test the Audit API with an empty time window.

    Args:
        client (Client): Client for API requests.
    """
    datetime_now = datetime.now().strftime(DATE_FORMAT)
    params = {"compartmentId": client.compartment_id, "startTime": datetime_now, "endTime": datetime_now}
    client._http_request(method="GET", params=params)


def check_searchlog_connectivity(client: Client, search_log_query: str | None) -> None:
    """Validate the 'Search log query' parameter and test the Search Logs API.

    Args:
        client (Client): Client for API requests.
        search_log_query (str | None): The 'Search log query' parameter.

    Raises:
        DemistoException: If the query is missing.
    """
    if not search_log_query:
        raise DemistoException(SEARCHLOG_QUERY_REQUIRED_ERROR)
    now = datetime.now()
    searchlogs_api_request(
        client=client,
        time_start=now.strftime(SEARCHLOG_DATE_FORMAT),
        time_end=(now + timedelta(days=14)).strftime(SEARCHLOG_DATE_FORMAT),
        search_query=search_log_query,
    )


def check_cloudguard_connectivity(client: Client, cloudguard_query: str | None) -> None:
    """Validate the 'CloudGuard Problems query' parameter and test the Cloud Guard ListProblems API.

    Args:
        client (Client): Client for API requests.
        cloudguard_query (str | None): The raw 'CloudGuard Problems query' parameter.
    """
    cloudguard_filters = parse_cloudguard_query(cloudguard_query)
    datetime_now = format_cloudguard_time(datetime.now(timezone.utc))  # noqa: UP017
    cloudguard_problems_api_request(
        client=client, time_start=datetime_now, time_end=datetime_now, filters=cloudguard_filters, limit=1
    )


def test_module(
    client: Client, search_log_query: str | None, event_types_to_fetch: list, cloudguard_query: str | None = None
) -> str:
    """Tests API connectivity and authentication for every selected event type.

    Every selected event type is tested, even if an earlier one failed, so the error lists all the failing event types.

    Args:
        client (Client): Client for SDK interaction and api requests.
        search_log_query (str | None): The search log query string from the instance configuration.
        event_types_to_fetch (list): The event types selected in the instance configuration.
        cloudguard_query (str | None): The raw 'CloudGuard Problems query' parameter.

    Raises:
        DemistoException: If at least one selected event type failed, listing every failing event type and its error.

    Returns:
        str: 'ok' if test passed, anything else will raise an exception and will fail the test.
    """
    all_checks: dict[str, Callable[[], None]] = {
        AUDIT_EVENT_TYPE: lambda: check_audit_connectivity(client),
        SEARCHLOG_EVENT_TYPE: lambda: check_searchlog_connectivity(client, search_log_query),
        CLOUDGUARD_EVENT_TYPE: lambda: check_cloudguard_connectivity(client, cloudguard_query),
    }

    errors: dict[str, Exception] = {}
    for event_type, check in all_checks.items():
        if event_type not in event_types_to_fetch:
            continue
        try:
            check()
        except Exception as e:
            demisto.debug(f"OCI: test-module failed for {event_type}: {e}")
            errors[event_type] = e

    if errors:
        details = "\n".join(f"- {event_type}: {error}" for event_type, error in errors.items())
        raise DemistoException(f"Error while testing the following event types:\n{details}")

    return "ok"


""" MAIN FUNCTION """


def main():
    params = demisto.params()
    args = demisto.args()
    command = demisto.command()
    last_run = migrate_last_run(demisto.getLastRun())
    last_run_time = last_run.get(AUDIT_LAST_RUN_KEY)
    demisto.info(f"OCI: last_run_time value {last_run_time}")
    max_fetch = arg_to_number(params.get("max_fetch")) or MAX_EVENTS_TO_FETCH
    first_fetch = params.get("first_fetch", FETCH_DEFAULT_TIME)
    should_push_events = argToBoolean(args.get("should_push_events", False))
    private_key_type = params.get("private_key_type") or "PKCS#8"
    searchlogs_query = params.get("search_log_query")
    searchlog_last_run = last_run.get(SEARCHLOG_LAST_RUN_KEY, {})
    cloudguard_last_run = last_run.get(CLOUDGUARD_LAST_RUN_KEY, {})
    event_types_to_fetch = argToList(params.get("event_types_to_fetch", [AUDIT_EVENT_TYPE]))

    demisto.info(f"OCI: Command being called is {command}")

    try:
        client = Client(
            verify_certificate=not params.get("insecure", False),
            proxy=params.get("proxy", False),
            user_ocid=params.get("user_ocid"),
            private_key=params.get("credentials", {}).get("password"),
            key_fingerprint=params.get("credentials", {}).get("identifier"),
            tenancy_ocid=params.get("tenancy_ocid"),
            region=params.get("region"),
            compartment_id=params.get("compartment_id"),
            private_key_type=private_key_type,
        )
        demisto.info("OCI: Client created successfully.")

        if command == "test-module":
            return_results(test_module(client, searchlogs_query, event_types_to_fetch, params.get("cloudguard_query")))

        elif command in ("oracle-cloud-infrastructure-get-events", "fetch-events"):
            push_events = command == "fetch-events" or should_push_events

            # Each event type is fetched independently: a failure in one type (bad query, API error,
            # invalid first fetch time) is logged with its error and the other event types keep running.
            all_fetchers: dict[str, Callable[[], tuple[list[dict[str, Any]], Any]]] = {
                SEARCHLOG_EVENT_TYPE: lambda: fetch_searchlog_events(client, searchlogs_query, max_fetch, searchlog_last_run),
                CLOUDGUARD_EVENT_TYPE: lambda: fetch_cloudguard_problems(
                    client, params.get("cloudguard_query"), max_fetch, cloudguard_last_run, first_fetch
                ),
                AUDIT_EVENT_TYPE: lambda: get_events(
                    client,
                    get_fetch_time(last_run=last_run_time, first_fetch_param=first_fetch),
                    max_fetch,
                    push_events_on_error=False,
                ),
            }
            selected_fetchers = {event_type: f for event_type, f in all_fetchers.items() if event_type in event_types_to_fetch}
            fetched = run_event_type_fetchers(selected_fetchers)

            if push_events:
                last_run = send_fetched_events(fetched, last_run)
                demisto.setLastRun(last_run)
                demisto.info(f"OCI: Set last run to {last_run}")
            else:
                for event_type, (events, _) in fetched.items():
                    return_results(events_to_command_results(events, EVENT_TYPE_TABLE_TITLES[event_type]))
        else:
            return_error(f"Command {command} does not exist for this integration.")
    except Exception as e:
        return_error(f"Failed to execute {command} command.\nError:\n{e!s}")


""" ENTRY POINT """

if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
