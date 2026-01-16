from collections.abc import Callable
from urllib.parse import unquote

from CommonServerPython import *
import demistomock as demisto  # noqa: F401

"""
An integration module for the Google Threat Intelligence ASM Issues API.
API Documentation:
    https://gtidocs.virustotal.com/reference/get_search-issues-search-string
"""


COMMAND_PREFIX = "gti"
BASE_URL = "https://www.virustotal.com/api/v3"
ASM_INCIDENT_LINK = "https://asm.advantage.mandiant.com/issues/{}"
OK_CODES = (200, 401)
STATUS_CODE_TO_RETRY = [429, *(status_code for status_code in requests.status_codes._codes if status_code >= 500)]  # type: ignore
MAX_RETRIES = 4
BACKOFF_FACTOR = 7.5
MAX_FETCH = 200
DEFAULT_API_MAX_FETCH = 50
DEFAULT_MAX_FETCH = 100
MAX_ISSUE_SIZE = 1000
MAX_OUTGOING_NOTE_LIMIT = 50000
DEFAULT_FETCH_TIME = "1 days"
OUTPUT_PREFIX = {"ISSUE_LIST": "GoogleThreatIntelligenceASMIssues.Issues"}
MIRROR_DIRECTION = {"Outgoing": "Out"}
ASM_ISSUE_INCIDENT_STATUS_MAPPING = {
    1: "open_in_progress",  # incident status: active
    2: "closed",  # incident status: done
}
DATE_TIME_FORMAT = "%Y-%m-%dT%H:%M:%S.%fZ"
DEFAULT_FETCH_TIME = "1 days"
OUTPUT_PREFIX = {"ISSUE_LIST": "GoogleThreatIntelligenceASMIssues.Issues"}
ISSUE_TO_INCIDENT_SEVERITY = {
    1: 4,
    2: 3,
    3: 2,
    4: 1,
    5: 0.5,
}
MESSAGES = {
    "NO_RECORDS_FOUND": "No {} were found for the given argument(s).",
    "NO_RECORD_FOUND": "No {} was found for the given argument(s).",
    "REQUIRED_ARGUMENT": "Missing argument {}.",
    "NO_STATUS_UPDATED": "No {} status was updated.",
}
ERROR_MESSAGES = {
    "INVALID_MAX_FETCH": "'{}' is invalid 'max_fetch' value. Max fetch for ASM Issues should be between 1 and 200.",
    "INVALID_PAGE_SIZE": "'{}' is an invalid value for 'page_size'. Value must be between 1 and 1000.",
    "INVALID_OBJECT": "Failed to parse {} object from response: {}",
    "UNAUTHORIZED_REQUEST": "{} Unauthorized request: Invalid API key provided {}.",
    "INVALID_ARGUMENT": "'{}' is an invalid value for '{}'. Value must be in {}.",
}
ASM_ISSUE_STATUS_LIST = [
    "open",
    "triaged",
    "in progress",
    "closed",
    "mitigated",
    "resolved",
    "duplicate",
    "out of scope",
    "false positive",
    "risk accepted",
    "benign",
    "unable to reproduce",
    "track externally",
]
ASM_ISSUE_STATUS_HUMAN_READABLE = [
    "Open",
    "Triaged",
    "In Progress",
    "Closed",
    "Mitigated",
    "Resolved",
    "Duplicate",
    "Out of Scope",
    "False Positive",
    "Risk Accepted",
    "Benign",
    "Unable to Reproduce",
    "Track Externally",
]
ASM_ISSUE_STATUS_API_MAPPING = {
    "open": "open_new",
    "triaged": "open_triaged",
    "in progress": "open_in_progress",
    "closed": "closed",
    "mitigated": "closed_mitigated",
    "resolved": "closed_resolved",
    "duplicate": "closed_duplicate",
    "out of scope": "closed_out_of_scope",
    "false positive": "closed_false_positive",
    "risk accepted": "closed_risk_accepted",
    "benign": "closed_benign",
    "unable to reproduce": "closed_no_repro",
    "track externally": "closed_tracked_externally",
}
ASM_ISSUE_HR_STATUS_MAPPING = {
    "open_new": "Open",
    "open_triaged": "Triaged",
    "open_in_progress": "In Progress",
    "closed": "Closed",
    "closed_mitigated": "Mitigated",
    "closed_resolved": "Resolved",
    "closed_duplicate": "Duplicate",
    "closed_out_of_scope": "Out of Scope",
    "closed_false_positive": "False Positive",
    "closed_risk_accepted": "Risk Accepted",
    "closed_benign": "Benign",
    "closed_no_repro": "Unable to Reproduce",
    "closed_tracked_externally": "Track Externally",
}
ENDPOINTS = {
    "issue_list": "asm/search/issues/{}",
    "issue_get": "asm/issues/{}",
    "issue_status_update": "asm/issues/{}/status",
    "issue_tags": "asm/tags/issue/{}",
    "issue_update_notes": "asm/notes/issue/{}",
}


class Client(BaseClient):
    """Client for Google Threat Intelligence ASM Issues API."""

    def __init__(self, verify_certificate: bool, proxy: bool, api_key: str, project_id: str):
        self.project_id = project_id
        super().__init__(
            BASE_URL,
            verify=verify_certificate,
            proxy=proxy,
            headers={
                "x-apikey": api_key,
                "Accept": "application/json",
                "Content-Type": "application/json",
                "PROJECT-ID": project_id,
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
        headers: Dict[str, Any] | None = None,
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
        # if not provided ASM Project ID for commands
        if not headers:
            headers = self._headers

        log_header = {**headers, "x-apikey": "***********"}  # type: ignore
        demisto.debug(
            f"Making API request at {method} {url_suffix} with headers:{log_header},"
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

    def get_issue_list(self, query_params: dict, search_string: str, project_id: str | None = None, response_type: str = "json"):
        """
        See Also:
            https://gtidocs.virustotal.com/reference/get_search-issues-search-string
        """
        headers = None
        if project_id:
            headers = self._headers.copy()
            headers.update({"PROJECT-ID": project_id})

        response = self.http_request(
            method="GET",
            url_suffix=ENDPOINTS["issue_list"].format(search_string),
            params=query_params,
            response_type=response_type,
            headers=headers,
        )

        if not response.get("success") or not response.get("result"):
            raise ValueError(
                f"Failed to retrieve ASM issues from Google Threat Intelligence API. Verify the search string and project ID"
                f" are correct, and try again. Provided Search string: '{search_string}', Project ID: '{project_id}'"
            )

        return response

    def asm_issue_get(self, issue_id: str, project_id: str | None = None) -> dict:
        """
        Get a particular ASM issue by ID.
        Args:
            issue_id(str): Issue ID.
            project_id(str): Project ID.
        Returns:
            dict: ASM issue.
        """
        headers = None
        if project_id:
            headers = self._headers.copy()
            headers["PROJECT-ID"] = project_id

        return self.http_request(
            method="GET",
            url_suffix=ENDPOINTS["issue_get"].format(issue_id),
            response_type="json",
            headers=headers,
        )

    def asm_issue_status_update(self, issue_id: str, payload: dict[str, Any], project_id: str | None = None) -> dict:
        """
        Update the status of a particular ASM issue by ID.
        Args:
            issue_id(str): Issue ID.
            payload(dict): Payload to update the issue.
            project_id(str): Project ID.
        Returns:
            dict: ASM issue.
        """
        headers = None
        if project_id:
            headers = self._headers.copy()
            headers["PROJECT-ID"] = project_id

        return self.http_request(
            method="POST",
            url_suffix=ENDPOINTS["issue_status_update"].format(issue_id),
            headers=headers,
            response_type="json",
            json_data=payload,
        )

    def asm_issue_tags_update(self, issue_id: str, payload: dict[str, Any]) -> dict:
        """
        Update the tags of a particular ASM issue by ID.
        Args:
            issue_id(str): Issue ID.
            tags(list): New tags of the issue.
        Returns:
            dict: ASM issue.
        """
        return self.http_request(
            method="POST",
            url_suffix=ENDPOINTS["issue_tags"].format(issue_id),
            response_type="json",
            json_data=payload,
        )

    def asm_issue_tags_get(self, issue_id: str) -> dict:
        """
        Get the tags of a particular ASM issue by ID.
        Args:
            issue_id(str): Issue ID.
        Returns:
            dict: ASM issue.
        """
        return self.http_request(
            method="GET",
            url_suffix=ENDPOINTS["issue_tags"].format(issue_id),
            response_type="json",
        )

    def asm_issue_notes_update(self, issue_id: str, payload: dict[str, Any]) -> dict:
        """
        Update the notes of a particular ASM issue by ID.
        Args:
            issue_id(str): Issue ID.
            notes(list): New notes of the issue.
        Returns:
            dict: ASM issue.
        """
        return self.http_request(
            method="POST",
            url_suffix=ENDPOINTS["issue_update_notes"].format(issue_id),
            response_type="json",
            json_data=payload,
        )


# ASM Issues Helper functions


def validate_argument(value, name) -> Any:
    """
    Check if empty string is passed as value for argument and raise appropriate ValueError.

    Args:
        value: Value of the argument.
        name: Name of the argument.

    Returns:
        Any: Value of the argument.

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


def build_asm_issue_list_output(issue_data: list, hr_title: str) -> tuple:
    """Build human-readable output and context for ASM issues.
    Args:
        issue_data(list): List of issues from ASM issues API.
        hr_title(str): Human-readable title.

    Returns:
        tuple: (context, readable_output)
    """
    hr_content = []
    context = []

    for issue in issue_data:
        context.append(remove_empty_elements(issue))
        # Extract key fields for human-readable table matching your structure
        issue_summary = issue.get("summary", {})
        issue_status = issue_summary.get("status", "")
        hr_content.append(
            {
                "Issue ID": issue.get("uid", ""),
                "Issue Name": issue.get("pretty_name", ""),
                "Issue Description": issue.get("description", ""),
                "Status": ASM_ISSUE_HR_STATUS_MAPPING.get(issue_status, issue_status),
                "Severity": issue_summary.get("severity", ""),
                "Entity Name": issue.get("entity_name", ""),
                "Entity uid": issue.get("entity_uid", ""),
                "Entity Type": issue.get("entity_type", ""),
                "Collection": issue.get("collection", ""),
                "Confidence": issue_summary.get("confidence", ""),
                "Last Seen": issue.get("last_seen", ""),
                "First Seen": issue.get("first_seen", ""),
                "Tags": issue.get("tags", ""),
            }
        )

    headers = [
        "Issue ID",
        "Issue Name",
        "Issue Description",
        "Status",
        "Severity",
        "Entity Name",
        "Entity uid",
        "Entity Type",
        "Collection",
        "Confidence",
        "Last Seen",
        "First Seen",
        "Tags",
    ]

    # Create human-readable output using tableToMarkdown
    readable_output = tableToMarkdown(hr_title, hr_content, headers=headers, removeNull=True)

    return context, readable_output


def build_asm_issue_status_update_output(issue_data: dict) -> tuple:
    """
    Build human-readable output and context for ASM issue status update.
    Args:
        issue_data(dict): Issue data obtained from ASM issue status update API.
    Returns:
        tuple: (context, readable_output)

    """
    context = []
    context.append(remove_empty_elements(issue_data))

    hr_content = []

    hr_content.append(
        {
            "Issue ID": issue_data.get("uid", ""),
            "Status": ASM_ISSUE_HR_STATUS_MAPPING.get(issue_data.get("result", ""), ""),
        }
    )

    headers = ["Issue ID", "Status"]

    # Create human-readable output using tableToMarkdown
    readable_output = tableToMarkdown("ASM Issue Status Updated Successfully.", hr_content, headers=headers, removeNull=True)

    return context, readable_output


def clean_search_string(search_string):
    """
    Cleans the given search string by removing keyword:value pairs of timestamp and normalizing spacing.

    Args:
        search_string (str): The search string to be cleaned.

    Returns:
        str: The cleaned search string.

    Steps:
        1.Add a space if a timestamp keyword is directly attached to the previous word.
        2.Create a regex pattern to detect timestamp_keyword:value pairs.
        3.Strip out all matched keyword–value pairs from the search string.
        4.Clean up the spacing by collapsing multiple spaces and trimming edges.
        5.log the final cleaned search string for debugging.
    """
    timestamp_keys = ["last_seen_after", "last_seen_before", "first_seen_after"]

    # Step 1: Add a space if a timestamp keyword is directly attached to the previous word.
    for timestamp_key in timestamp_keys:
        search_string = re.sub(r"(?<![\s])(" + re.escape(timestamp_key) + r")\s*:", r" \1:", search_string)

    # Step 2: Create a regex pattern to detect timestamp_keyword:value pairs.
    pattern = r"\b(?:" + "|".join(re.escape(k) for k in timestamp_keys) + r")\s*:\s*[^ \n\t]+"

    # Step 3: Strip out all matched keyword–value pairs from the search string.
    cleaned = re.sub(pattern, "", search_string)

    # Step 4: Clean up the spacing by collapsing multiple spaces and trimming edges.
    cleaned = re.sub(r"\s+", " ", cleaned).strip()

    # Step 5: Log the final cleaned search string for debugging.
    demisto.debug(f"Cleaned search string for ASM: {cleaned}")

    return cleaned


def bump_timestamp(timestamp_str: str) -> str:
    """Helper function to increment timestamp by 1 second"""
    timestamp_dt = datetime.strptime(timestamp_str, DATE_TIME_FORMAT)
    timestamp_dt += timedelta(seconds=1)

    # issue timestamps supports only support microsecond precision
    timestamp_dt = format_datetime(timestamp_dt)

    return timestamp_dt


def format_datetime(dt: datetime) -> str:
    """Formats a datetime object into an ISO 8601 string with millisecond precision.

    This helper function converts a Python datetime object into a string format
    `YYYY-MM-DDTHH:MM:SS.sssZ`. It truncates microseconds to milliseconds to ensure compatibility.

    Args:
        dt (datetime): The datetime object to format.

    Returns:
        str: The formatted datetime string in ISO 8601 format with millisecond
             precision and a 'Z' for UTC.
    """
    return dt.strftime(DATE_TIME_FORMAT)[:-4] + "Z"


def get_mirroring():
    """
    Get the mirroring configuration parameters from the Demisto integration parameters.

    Returns:
        dict: A dictionary containing the mirroring configuration parameters.
    """
    params = demisto.params()
    mirror_direction = params.get("mirror_direction", "None").strip()
    mirror_tags = params.get("note_tag", "").strip()
    return {
        "mirror_direction": MIRROR_DIRECTION.get(mirror_direction),
        "mirror_instance": demisto.integrationInstance(),
        "mirror_tags": mirror_tags,
    }


def extract_tags(client: Client, issue_id: str) -> dict[str, str]:
    tags_dict = {}
    response = client.asm_issue_tags_get(issue_id)
    exisiting_tags = response.get("result", [])
    for tag in exisiting_tags:
        tags_dict[tag.lower()] = tag
    return tags_dict


# ASM Issue command functions
def test_module(client: Client) -> str:
    """
    Test module for Google Threat Intelligence ASM Issues.
    Args:
        client: Client object.
    Returns:
        str: "ok" if connection with Google Threat Intelligence is successful.
    """
    params = demisto.params()
    is_fetch = params.get("isFetch", False)

    if is_fetch:
        fetch_incidents(client=client, last_run={}, params=params, is_test=True)
    else:
        query_params = {"page_size": 1}
        search_string = "status_new:open"
        client.get_issue_list(query_params, search_string)

    # return ok is connection with Google Threat Intelligence is successful.
    return "ok"


def gti_asm_issue_get_command(client: Client, args: dict) -> CommandResults:
    """
    Get ASM issue details for the specified issue ID.

    Args:
        client(Client): Client object to use.
        args(dict): arguments obtained from demisto.args().

    Returns:
        CommandResults: CommandResult object
    """
    issue_id = validate_argument(args.get("issue_id"), "issue_id")
    project_id = args.get("project_id")

    if not project_id:
        project_id = client.project_id

    raw_response = client.asm_issue_get(issue_id=issue_id, project_id=project_id)

    issue_data = raw_response.get("result", {})

    if not raw_response.get("success") or not issue_data:
        return CommandResults(readable_output=MESSAGES["NO_RECORD_FOUND"].format("ASM Issue"))

    if isinstance(issue_data, dict):
        issue_data = [issue_data]

    context, hr = build_asm_issue_list_output(issue_data, "ASM Issue")

    return CommandResults(
        outputs_prefix=OUTPUT_PREFIX["ISSUE_LIST"],
        outputs_key_field="uid",
        outputs=context,
        raw_response=raw_response,
        readable_output=hr,
    )


def gti_asm_issue_status_update_command(client: Client, args: dict) -> CommandResults:
    """
    Update the status of a particular ASM issue by ID.
    Args:
        client(Client): Client object to use.
        args(dict): arguments obtained from demisto.args().
    Returns:
        CommandResults: CommandResult object
    """
    issue_id = validate_argument(args.get("issue_id"), "issue_id")
    project_id = args.get("project_id")
    status = validate_argument(args.get("status"), "status")

    if not project_id:
        project_id = client.project_id

    if status and status.lower() not in ASM_ISSUE_STATUS_LIST:
        raise ValueError(ERROR_MESSAGES["INVALID_ARGUMENT"].format(status, "status", ASM_ISSUE_STATUS_HUMAN_READABLE))

    payload = {"status": ASM_ISSUE_STATUS_API_MAPPING.get(status.lower())}

    raw_response = client.asm_issue_status_update(project_id=project_id, issue_id=issue_id, payload=payload)

    if not raw_response.get("success"):
        return CommandResults(readable_output=MESSAGES["NO_STATUS_UPDATED"].format("ASM Issue"))

    raw_response["uid"] = issue_id
    context, hr = build_asm_issue_status_update_output(raw_response)

    return CommandResults(
        outputs_prefix=OUTPUT_PREFIX["ISSUE_LIST"],
        outputs_key_field="uid",
        outputs=context,
        raw_response=raw_response,
        readable_output=hr,
    )


def gti_asm_issue_list_command(client: Client, args: dict) -> CommandResults:
    """
    List ASM issues for the specified filter parameters.

    Args:
        client(Client): Client object to use.
        args(dict): arguments obtained from demisto.args().

    Returns:
        CommandResults: CommandResult object
    """
    project_id = args.get("project_id")
    search_string = args.get("search_string", " ")
    page_size = arg_to_number(args.get("page_size", DEFAULT_API_MAX_FETCH), "page_size")

    if not project_id:
        project_id = client.project_id

    if page_size is not None and (page_size > MAX_ISSUE_SIZE or page_size < 1):
        raise ValueError(ERROR_MESSAGES["INVALID_PAGE_SIZE"].format(page_size, MAX_ISSUE_SIZE))

    query_params = {"page_size": page_size}

    raw_response = client.get_issue_list(project_id=project_id, query_params=query_params, search_string=search_string)

    if not (raw_response.get("success") and raw_response.get("result", {}).get("hits", [])):
        return CommandResults(readable_output=MESSAGES["NO_RECORDS_FOUND"].format("ASM Issues"))

    issue_data = raw_response.get("result", {}).get("hits", [])

    context, hr = build_asm_issue_list_output(issue_data, "ASM Issues")

    return CommandResults(
        outputs_prefix=OUTPUT_PREFIX["ISSUE_LIST"],
        outputs_key_field="uid",
        outputs=context,
        raw_response=raw_response,
        readable_output=hr,
    )


def fetch_incidents(
    client: Client, last_run: dict, params: dict, is_test: bool = False
) -> tuple[List[Dict[str, Any]], Dict[str, Any]]:
    """
    Fetch ASM issues as incidents from Google Threat Intelligence.

    Args:
        client (Client): Google Threat Intelligence client object.
        last_run (dict): Last run data containing timestamp and index.
        params (Dict[str, Any]): Fetch incidents parameters.
        is_test (bool): Whether this is a test run.

    Returns:
        List[Dict[str, Any]]: List of fetched incidents.
        Dict[str, Any]: Next run parameters.
    """
    # Get parameters with guaranteed non-None fallbacks
    first_fetch_time = arg_to_datetime(params.get("first_fetch", DEFAULT_FETCH_TIME))  # type: ignore
    max_fetch = arg_to_number(params.get("max_fetch", DEFAULT_MAX_FETCH), "max_fetch")
    search_string = params.get("search_string", " ")

    # Validate max_fetch
    if max_fetch is not None and (max_fetch > MAX_FETCH or max_fetch < 1):
        raise ValueError(ERROR_MESSAGES["INVALID_MAX_FETCH"].format(max_fetch))

    # Initialize variables
    issue_incidents: List[Dict[str, Any]] = []
    next_run_params: Dict[str, Any] = {}

    # Initialize fetch params
    last_seen_after = last_run.get("asm_latest_issue_last_seen", format_datetime(first_fetch_time))  # type: ignore
    index = last_run.get("index", 1)
    seen_ids = last_run.get("issue_ids", [])
    last_max_fetch = last_run.get("max_fetch", max_fetch)
    last_search_string = last_run.get("search_string", search_string)

    # Handle parameter changes
    search_string_changed = last_search_string != search_string
    max_fetch_changed = last_max_fetch != max_fetch

    # Handle changes in search string or max_fetch
    if search_string_changed or max_fetch_changed:
        # Recalculate index or reset it based on the type of change
        if not search_string_changed and max_fetch_changed:
            # Only max_fetch changed - recalculate index to maintain position
            demisto.debug(f"max_fetch changed from {last_max_fetch} to {max_fetch}, recalculating index")
            items_processed = (index - 1) * last_max_fetch
            index = (items_processed // max_fetch) + 1
        else:
            # Search string changed (with or without max_fetch) - reset index
            demisto.debug(f"Search string changed from '{last_search_string}' to '{search_string}', resetting index to 1")
            index = 1

    demisto.debug(f"Starting fetch with last_seen_after={last_seen_after}, index={index}, seen_ids count={len(seen_ids)}")

    # Handle index limit reached - increment timestamp by 1 second and Max index steps to avoid infinite loop
    max_index = MAX_ISSUE_SIZE // max_fetch  # type: ignore

    # Calculate limit for pagination
    api_limit = min(max_fetch * index, MAX_ISSUE_SIZE)  # API limit is 1000

    # decode the search string and remove all the time params from search string
    decoded_search_string = unquote(search_string)
    cleaned_search_string = clean_search_string(decoded_search_string)

    # Add last seen time to search string
    final_search_string = f"{cleaned_search_string} last_seen_after:{last_seen_after}".strip()

    query_params = {"page_size": api_limit}

    demisto.debug(f"API call with search_string='{final_search_string}', page_size={api_limit}, index={index}")

    issue_response = client.get_issue_list(query_params=query_params, search_string=final_search_string)

    if is_test:
        return [], {}

    # Parse response
    issue_data = issue_response.get("result", {}).get("hits", [])

    demisto.debug(f"API returned {len(issue_data)} issues")

    found_issue_ids = []
    duplicate_issue_ids = []

    for issue in issue_data:
        issue_id = issue.get("uid")

        # Skip duplicates and invalid issues with no id
        if not issue_id or issue_id in seen_ids:
            if issue_id:
                duplicate_issue_ids.append(issue_id)
            continue

        # Update mirror params
        mirror_params = get_mirroring()
        mirror_params.update({"mirror_id": issue_id})
        issue.update(mirror_params)

        issue["incident_link"] = ASM_INCIDENT_LINK.format(issue_id)
        issue = remove_empty_elements(issue)
        issue_incidents.append(
            {
                "name": issue.get("pretty_name", ""),
                "occurred": issue.get("first_seen", ""),
                "details": json.dumps(issue),
                "rawJSON": json.dumps(issue),
                "severity": ISSUE_TO_INCIDENT_SEVERITY.get(issue.get("summary", {}).get("severity", 0)),
            }
        )
        found_issue_ids.append(issue_id)

    demisto.debug(f"Found {len(duplicate_issue_ids)} duplicates, found new issues IDs size: {len(found_issue_ids)}")
    demisto.debug(f"new issue IDs: {found_issue_ids}")

    new_last_timestamp = issue_data[-1].get("last_seen") if issue_data else last_seen_after
    new_seen_ids = seen_ids + found_issue_ids

    # if issue data is not found, return empty list and next run params
    if not issue_data:
        return [], last_run

    if new_last_timestamp == last_seen_after:
        if len(issue_data) < api_limit or index >= max_index:
            # Bump timestamp in either case:
            # 1. Partial response (< api_limit) = end of data for this timestamp
            # 2. Index limit reached (>= max_index) = prevent infinite loop
            new_last_timestamp = bump_timestamp(last_seen_after)
            new_index = 1
        else:
            # Continue with same timestamp, increment index
            new_index = index + 1
    else:
        # Different timestamp - use new timestamp as-is
        new_index = 1

    next_run_params = {
        "asm_latest_issue_last_seen": new_last_timestamp,
        "index": new_index,
        "issue_ids": new_seen_ids,
        "max_fetch": max_fetch,
        "search_string": search_string,
    }

    demisto.debug(f"Returning {len(issue_incidents)} incidents, next_run: {next_run_params}")
    return issue_incidents, next_run_params


# Mirroring Commands
def update_remote_system_command(client: Client, args: Dict) -> str:
    """
    Update a remote ASM issues based on changes in the XSOAR incident.

    Args:
        client (Client): An instance of the Client class.
        args (Dict): A dictionary containing the arguments required for updating the remote system.

    Returns:
        str: The ID of the updated remote alert.
    """
    parsed_args = UpdateRemoteSystemArgs(args)
    remote_issue_id = parsed_args.remote_incident_id
    mirror_issue_id = parsed_args.data.get("gtiasmissueuid", "")

    # Get XSOAR incident id
    xsoar_incident_id = parsed_args.data.get("id", "")
    incident_status = parsed_args.inc_status
    delta = parsed_args.delta or {}
    xsoar_tags = delta.get("tags") or []
    incident_changed = parsed_args.incident_changed
    new_entries = parsed_args.entries

    demisto.debug(f"Incident changed: {incident_changed}")
    demisto.debug(f"Delta Information for incident: {delta}")
    demisto.debug(f"Mirroring update for DTM alert: {mirror_issue_id} (remote_id: {remote_issue_id})")
    demisto.debug(f"Incident status: {incident_status}, XSOAR tags: {xsoar_tags}")

    if not mirror_issue_id:
        demisto.debug("No mirror alert ID found for update")
        return remote_issue_id

    # Update external status when incident is closed or when incident is active with no changes or incident get reopen
    reopen_incident = False
    if delta and delta.get("closingUserId") == "" and delta.get("runStatus") == "":
        reopen_incident = True
    is_update_status = (
        incident_status == IncidentStatus.DONE or (incident_status == IncidentStatus.ACTIVE and not delta) or reopen_incident
    )

    if incident_changed and is_update_status:
        update_data = {"status": ASM_ISSUE_INCIDENT_STATUS_MAPPING[incident_status]}
        client.asm_issue_status_update(issue_id=mirror_issue_id, payload=update_data)

    # Update tags when tags exist in delta and incident is changed
    if incident_changed and xsoar_tags:
        # get issue tags list
        existing_issue_tags = extract_tags(client=client, issue_id=mirror_issue_id)
        for tag in xsoar_tags:
            if tag.lower() not in existing_issue_tags:
                update_data = {"tag_name": tag}
                client.asm_issue_tags_update(issue_id=mirror_issue_id, payload=update_data)
            else:
                demisto.debug(f"Tag {tag} already exists for issue {mirror_issue_id}")

    if new_entries:
        for entry in new_entries:
            entry_id = entry.get("id")
            demisto.debug(f'Sending the entry with ID: {entry_id} and Type: {entry.get("type")}')

            # Get note content and user
            entry_content = entry.get("contents", "")
            entry_user = entry.get("user", "dbot") or "dbot"
            note_text = (
                f"[Mirrored From XSOAR] | Incident ID: {xsoar_incident_id} | Note: {entry_content} | Added By: {entry_user}"
            )
            if len(note_text) > MAX_OUTGOING_NOTE_LIMIT:
                demisto.info(
                    f"Skipping outgoing mirroring for issue note with XSOAR Incident ID:{xsoar_incident_id}, "
                    "because the note length exceeds 8000 characters."
                )
            else:
                # API request for adding notes
                payload = {"note_text": note_text}
                client.asm_issue_notes_update(issue_id=mirror_issue_id, payload=payload)

    # For Closing notes
    delta_keys = parsed_args.delta.keys()
    if "closingUserId" in delta_keys and parsed_args.incident_changed and parsed_args.inc_status == IncidentStatus.DONE:
        # Check if incident status is Done
        close_notes = parsed_args.data.get("closeNotes", "")
        close_reason = parsed_args.data.get("closeReason", "")
        close_user_id = parsed_args.data.get("closingUserId", "")
        closing_note = (
            f"[Mirrored From XSOAR] | Incident ID: {xsoar_incident_id} | Close Reason: {close_reason} |"
            f"Closed By: {close_user_id} | Close Notes: {close_notes}"
        )
        if len(closing_note) > MAX_OUTGOING_NOTE_LIMIT:
            demisto.info(
                f"Skipping outgoing mirroring for closing notes with XSOAR Incident ID {xsoar_incident_id}, "
                f"because the note length exceeds {MAX_OUTGOING_NOTE_LIMIT} characters."
            )
        else:
            # API request for adding notes
            payload = {"note_text": closing_note}
            client.asm_issue_notes_update(issue_id=mirror_issue_id, payload=payload)

    return remote_issue_id


def main():
    params = demisto.params()
    params = trim_spaces_from_args(params)
    remove_nulls_from_dictionary(params)

    # get connectivity parameters
    api_key = str(dict_safe_get(params, ["credentials", "password"])).strip()
    verify_certificate = not argToBoolean(params.get("insecure", False))
    proxy = argToBoolean(params.get("proxy", False))
    project_id = params.get("project_id", "")

    command = demisto.command()
    demisto.debug(f"Command being called is {command}")

    commands: dict[str, Callable] = {
        "gti-asm-issue-get": gti_asm_issue_get_command,
        "gti-asm-issue-status-update": gti_asm_issue_status_update_command,
        "gti-asm-issue-list": gti_asm_issue_list_command,
    }
    try:
        result = None
        # Creates client
        client = Client(verify_certificate, proxy, api_key, project_id)
        # Get Command args
        args = demisto.args()
        if command == "test-module":
            result = test_module(client)
        elif command == "update-remote-system":
            result = update_remote_system_command(client, args)
        elif command == "fetch-incidents":
            last_run = demisto.getLastRun()
            incidents, next_run = fetch_incidents(client, last_run, params)
            demisto.setLastRun(next_run)
            demisto.incidents(incidents)
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
