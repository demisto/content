import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401


''' CONSTANTS '''

DATE_FORMAT = '%Y-%m-%dT%H:%M:%SZ'
TOKEN_EXPIRY_BUFFER = timedelta(seconds=10)
DEFAULT_LIMIT = 50
MAX_LIMIT = 3000


''' CLIENT CLASS '''


class Client(BaseClient):
    """
    Exabeam Client: A Python Wrapper for Interacting with the Exabeam API
    """

    def __init__(self, base_url: str, client_id: str, client_secret: str, verify: bool,
                 proxy: bool):
        super().__init__(base_url=f'{base_url}', verify=verify, proxy=proxy, timeout=20)
        self.client_id = client_id
        self.client_secret = client_secret
        self.access_token = None

        self._authenticate()

    def _authenticate(self):
        """
        Authenticates to the Exabeam API using the provided client_id and client_password.
        This function must be called before any other API calls.
        Note: the session is automatically closed in BaseClient's __del__
        """
        integration_context = demisto.getIntegrationContext()
        access_token = integration_context.get("access_token")
        expiry_time_str = integration_context.get("expiry_time_utc")

        if self._is_token_valid(access_token, expiry_time_str):
            self.access_token = access_token
        else:
            self._get_new_token()

    def _is_token_valid(self, access_token, expiry_time_str):
        """
        Checks if the current token is valid and not expired with a security buffer.
        """
        if not access_token or not expiry_time_str:
            return False

        current_time_utc = datetime.now(timezone.utc)
        expiry_time_utc = datetime.fromisoformat(expiry_time_str)
        return current_time_utc < (expiry_time_utc - TOKEN_EXPIRY_BUFFER)

    def _get_new_token(self):
        """
        Fetches a new token from the Exabeam API and updates the integration context.
        """
        data = {
            "client_id": self.client_id,
            "client_secret": self.client_secret,
            "grant_type": "client_credentials",
        }

        response = self._http_request(
            method="POST",
            full_url=f"{self._base_url}/auth/v1/token",
            data=data,
        )

        new_token = response.get('access_token')
        expires_in = response.get("expires_in")
        current_time_utc = datetime.now(timezone.utc)
        expiry_time_utc = current_time_utc + timedelta(seconds=expires_in)

        demisto.setIntegrationContext({"access_token": new_token, "expiry_time_utc": expiry_time_utc.isoformat()})
        self.access_token = new_token

    def request(self, **kargs):
        """
        Executes an HTTP request with automatic token refresh on expiration.

        This method sets the required headers, including the Authorization token,
        and performs the HTTP request using `_http_request`. If the request fails
        due to an expired JWT token, the token is refreshed and the request is retried.

        Args:
            **kargs: Arbitrary keyword arguments passed to `_http_request`,
                    such as method, url, data, params, etc.

        Returns:
            Any: The response from the HTTP request, typically a JSON object.

        Raises:
            DemistoException: If the response contains an error message or if
                            the request fails due to reasons other than token expiration.
        """
        kargs["headers"] = {
            "accept": "application/json",
            "Content-Type": "application/json",
            "Authorization": f"Bearer {self.access_token}",
        }

        def _make_request() -> Any:
            response = self._http_request(**kargs)
            if isinstance(response, dict) and (error := response.get("errors", {})):
                raise DemistoException(error.get("message"))
            return response

        try:
            return _make_request()
        except DemistoException as e:
            if (
                hasattr(e, "res")
                and hasattr(e.res, "status_code")
                and e.res.status_code == 401  # type: ignore
                and "Jwt is expired" in e.res.text  # type: ignore
            ):
                self._get_new_token()
                kargs["headers"]["Authorization"] = f"Bearer {self.access_token}"
                return _make_request()
            else:
                raise

    def event_search_request(self, data_dict: dict) -> dict:
        """
        Performs basic get request to check if the server is reachable.
        """
        data = json.dumps(data_dict)
        full_url = f"{self._base_url}/search/v2/events"
        response = self.request(
            method="POST",
            full_url=full_url,
            data=data,
        )
        return response

    def case_search_request(self, data_dict: dict) -> dict:
        """
        Searches for cases in the threat center.
        """
        data = json.dumps(data_dict)
        full_url = f"{self._base_url}/threat-center/v1/search/cases"
        response = self.request(method="POST", full_url=full_url, data=data)
        return response

    def get_case_request(self, case_id: int) -> dict:
        """
        Retrieves details of a specific case by its ID.
        """
        full_url = f"{self._base_url}/threat-center/v1/cases/{case_id}"
        response = self.request(
            method="GET",
            full_url=full_url
        )
        return response

    def alert_search_request(self, data_dict: dict) -> dict:
        """
        Searches for alerts in the threat center.
        """
        data = json.dumps(data_dict)
        full_url = f"{self._base_url}/threat-center/v1/search/alerts"
        response = self.request(method="POST", full_url=full_url, data=data,)
        return response

    def create_table_record(self, table_id, json_data):
        """
        Creates a new record in the specified table.
        """
        full_url = f"{self._base_url}/context-management/v1/tables/{table_id}/addRecords"
        response = self.request(method="POST", full_url=full_url, json_data=json_data)
        return response

    def check_tracker_id(self, tracker_id):
        """
        Checks the upload status of a tracker by its ID.
        """
        full_url = f"{self._base_url}/context-management/v1/tables/uploadStatus/{tracker_id}"
        response = self.request(method="GET", full_url=full_url)
        return response

    def list_context_table(self) -> dict:
        """
        Lists all context tables.
        """
        full_url = f"{self._base_url}/context-management/v1/tables"
        response = self.request(method="GET", full_url=full_url)
        return response

    def get_context_table(self, table_id) -> dict:
        """
        Retrieves details of a specific context table by its ID.
        """
        full_url = f"{self._base_url}/context-management/v1/tables/{table_id}"
        response = self.request(method="GET", full_url=full_url)
        return response

    def delete_context_table(self, table_id, params) -> dict:
        """
        Deletes a context table and optionally any unused custom attributes.
        """
        full_url = f"{self._base_url}/context-management/v1/tables/{table_id}"
        response = self.request(method="DELETE", full_url=full_url, params=params)
        return response

    def get_table_record_list(self, table_id, params) -> dict:
        """
        Retrieves a list of records from a specific table.
        """
        full_url = f"{self._base_url}/context-management/v1/tables/{table_id}/records"
        response = self.request(method="GET", full_url=full_url, params=params)
        return response

    def get_alert_request(self, alert_id: int) -> dict:
        """
        Retrieves details of a specific alert by its ID.
        """
        full_url = f"{self._base_url}/threat-center/v1/alerts/{alert_id}"
        response = self.request(method="GET", full_url=full_url)
        return response


""" HELPER FUNCTIONS """


def get_date(time: str, arg_name: str):
    """
    Get the date from a given time string.

    Args:
        time (str): The time string to extract the date from.

    Returns:
        str: The date extracted from the time string formatted in ISO 8601 format (YYYY-MM-DD),
        or None if the time string is invalid.
    """
    date_time = arg_to_datetime(arg=time, arg_name=arg_name, required=True)
    if not date_time:
        raise DemistoException(f"There was an issue parsing the {arg_name} provided.")
    date = date_time.strftime(DATE_FORMAT)
    return date


def transform_string(input_str: str) -> str:
    """
    Transform the input string into a formatted string.

    Args:
        input_str (str): The input string to be transformed. It should be in the format "key:value".

    Returns:
        str: The transformed string where the value part is converted to lowercase if it's "true" or "false",
        otherwise it's enclosed in double quotes.

    Examples:
        transform_string("status:true") -> 'status:true'
        transform_string("message:Hello World") -> 'message:"Hello World"'
    """
    if ':' not in input_str:
        return input_str
    key, value = input_str.split(':', 1)
    if value.lower() in ['true', 'false']:
        return f'{key}:{value.lower()}'
    else:
        return f'{key}:"{value}"'


def process_string(input_str: str) -> str:
    """
    Process the input string by splitting it based on logical operators and transforming each part.

    Args:
        input_str: The input string to be processed. It may contain logical operators such as 'AND', 'OR', 'NOT', 'TO'.

    Returns:
        str: The processed string where each part is transformed using the transform_string function.
    """
    logical_operators = ['AND', 'OR', 'NOT', 'TO']
    transformed_parts = []
    start_index = 0

    for end_index in range(len(input_str)):
        if any(op in input_str[start_index:end_index] for op in logical_operators):
            part = input_str[start_index:end_index].strip()
            operator = next(op for op in logical_operators if op in part)
            part = part.replace(operator, "").strip()
            transformed_parts.append(transform_string(part))
            transformed_parts.append(operator)
            start_index = end_index + 1

    if start_index < len(input_str):
        remaining_part = input_str[start_index:].strip()
        if remaining_part:
            transformed_parts.append(transform_string(remaining_part))

    return ' '.join(transformed_parts)


def _parse_entry(entry: dict, fields_to_filter: list[str] = None):  # type: ignore
    """
    Parse a single entry from the API response into a dictionary, optionally filtering specific fields.

    Args:
        entry (dict): The entry from the API response.
        fields_to_filter (list[str], optional): A list of field names to include in the returned dictionary.
            If None, all fields are included.

    Returns:
        dict: The parsed entry dictionary, filtered by fields_to_filter if provided, or all fields if not.
    """

    if fields_to_filter:
        entry = {key: value for key, value in entry.items() if key in fields_to_filter}

    parsed = {
        "Id": entry.get("id"),
        "Raw Log Ids": entry.get("rawLogIds"),
        "Tier": entry.get("tier"),
        "Is Parsed": entry.get("parsed"),
        "Raw Logs": entry.get("rawLogs"),
        "Time": entry.get("time"),
        "Products": entry.get("products"),
        "Src Hosts": entry.get("srcHosts"),
        "Subscription Code": entry.get("subscriptionCode"),
        "Dest Hosts": entry.get("destHosts"),
        "Alert Name": entry.get("alertName"),
        "Case ID": entry.get("caseId"),
        "Src IPs": entry.get("srcIps"),
        "Alert ID": entry.get("alertId"),
        "Risk Score": entry.get("riskScore"),
        "Has Attachments": entry.get("hasAttachments"),
        "Vendors": entry.get("vendors"),
        "Grouped by Key": entry.get("groupedbyKey"),
        "Case Creation Timestamp": entry.get("caseCreationTimestamp"),
        "Priority": entry.get("priority"),
        "Last Modified Timestamp": entry.get("lastModifiedTimestamp"),
        "Tags": entry.get("tags"),
        "Stage": entry.get("stage"),
        "Dest IPs": entry.get("destIps"),
        "Queue": entry.get("queue"),
        "Name": entry.get("name"),
        "Source": entry.get("source"),
        "Context Type": entry.get("contextType"),
        "# Items": entry.get("totalItems"),
        "Status": entry.get("status"),
        "Last Updated": entry.get("lastUpdated"),
        "Rules": len(entry.get("rules", [])) if isinstance(entry.get("rules"), list) else None,
        "Mitre Ttps": len(entry.get("mitres", [])) if isinstance(entry.get("mitres"), list) else None,
        "Use Cases": len(entry.get("useCases", [])) if isinstance(entry.get("useCases"), list) else None,
        "users": len(entry.get("users", [])) if isinstance(entry.get("users"), list) else None,
    }

    final = remove_empty_elements(parsed)
    return final if final else None


def _parse_group_by(entry: dict, titles: list):
    """
    Parses a single entry from the API response into a dictionary based on provided titles.

    Args:
        entry (dict): The entry from the API response.
        titles (list): A list of keys to extract from the entry.

    Returns:
        dict or None: The parsed entry dictionary with non-empty elements or None if all elements are empty.
    """
    parsed = {}
    for title in titles:
        parsed.update({title: entry.get(title)})
    final = remove_empty_elements(parsed)
    return final if final else None


def get_limit(args: dict) -> int:
    """
    Get the limit value specified in the arguments.

    Args:
        args: A dictionary containing the 'limit' argument.

    Returns:
        int: The limit value if specified and less than or equal to 3000; otherwise, returns 3000 as the maximum limit.
        If the 'limit' argument is not present in the dictionary or is None, returns 50 as the default limit.
    """
    if limit := arg_to_number(args.get('limit')):
        return min(int(limit), MAX_LIMIT)

    return DEFAULT_LIMIT


def error_fixes(error: str):
    new_error = ""
    if 'not enough values to unpack' in error:
        new_error = ("Recommendation:\nValidate the query argument "
                     "against the syntax documentation in the integration description.")

    return new_error


def transform_dicts(input_dict: Dict[str, List[str]]) -> List[Dict[str, str]]:
    """
    Transforms a dictionary of lists into a list of dictionaries.

    This function takes a dictionary where each key is associated with a list of values and transforms it
    into a list of dictionaries, where each dictionary contains the corresponding elements from each list.

    Args:
        input_dict (Dict[str, List[str]]): The input dictionary where each key maps to a list of values.
                                           All lists must be of the same length.

    Returns:
        List[Dict[str, str]]: A list of dictionaries where each dictionary is constructed by taking the i-th element
                              from each list in the input dictionary.
    """
    # Checking that the lists are equal in length
    lengths = {len(v) for v in input_dict.values()}
    if len(lengths) > 1:
        raise DemistoException("All lists in the attributes must have the same length")

    length = next(iter(lengths))
    keys = list(input_dict.keys())

    result = []
    for i in range(length):
        entry = {key: input_dict[key][i] for key in keys}
        result.append(entry)

    return result


def convert_all_timestamp_to_datestring(incident: dict) -> dict:
    """
    Converts specified timestamp fields in an incident dictionary to date strings.

    Args:
        incident (dict): A dictionary containing incident data with timestamp fields.

    Returns:
        dict: The incident dictionary with timestamp fields converted to date strings.
    """
    keys = ['caseCreationTimestamp', 'lastModifiedTimestamp', 'creationTimestamp',
            'ingestTimestamp', 'approxLogTime', 'lastUpdated']
    for key in keys:
        if key in incident:
            incident[key] = timestamp_to_datestring(incident[key] / 1000, date_format=DATE_FORMAT)
    return incident


def filter_existing_cases(cases: list[dict], ids_exists: list[str]) -> list:
    """
    Filters out cases that already exist in the provided list of existing IDs.

    Args:
        cases (list[dict]): A list of case dictionaries to be filtered. Each dictionary should contain at least a "caseId" key.
        ids_exists (list[str]): A list of existing case IDs to check against.

    Returns:
        list[dict]: A list of case dictionaries that do not have IDs present in the `ids_exists` list.
    """
    if ids_exists:
        demisto.debug(f"Existing IDs in last_run: {ids_exists}")

        filtered_cases = []
        for case in cases:
            case_id = case.get("caseId")
            if case_id not in ids_exists:
                filtered_cases.append(case)
            else:
                demisto.debug(f"Case with ID {case_id} already exists, skipping.")
        demisto.debug(f"After filtered cases count: {len(filtered_cases)}")
    else:
        filtered_cases = cases
    return filtered_cases


def update_last_run(cases: list, end_time: str) -> dict:
    """
    Updates the last run time and list of case IDs based on the provided cases.

    Args:
        cases (list): A list of case dictionaries, each containing a 'caseCreationTimestamp' and 'caseId'.
        end_time (str): The end time to use if no cases are provided.

    Returns:
        dict: A dictionary with:
            - 'time': The latest case creation timestamp formatted as a date string (or end_time if no cases are provided).
            - 'last_ids': A list of case IDs where the 'caseCreationTimestamp' matches the latest timestamp exactly.
    """
    if cases:
        max_timestamp = max(case.get("caseCreationTimestamp", 0) for case in cases)
        list_ids = [case.get("caseId", "") for case in cases if case.get("caseCreationTimestamp", 0) == max_timestamp]
        last_run_time = timestamp_to_datestring(max_timestamp / 1000, date_format=DATE_FORMAT)
    else:
        last_run_time = end_time
        list_ids = []

    last_run = {
        "time": last_run_time,
        "last_ids": list_ids
    }
    return last_run


def format_incidents(cases: list[dict]) -> list[dict]:
    """
    Converts a list of cases into a list of incidents with formatted timestamps.

    Args:
        cases (list): A list of case dictionaries.

    Returns:
        list: A list of incident dictionaries, each containing:
            - 'Name': The alert name from the case.
            - 'rawJSON': The case data as a JSON string.
    """
    incidents = []
    for case in cases:
        case = convert_all_timestamp_to_datestring(case)
        alert_name = case.get("alertName", "")
        incidents.append({
            "Name": alert_name,
            "rawJSON": json.dumps(case),
        })
    return incidents


def format_record_keys(dict_list):
    new_list = []
    for input_dict in dict_list:
        new_dict = {}
        for key, value in input_dict.items():
            new_key = key.replace('_', ' ').title()
            new_dict[new_key] = value
        new_list.append(new_dict)
    return new_list


''' COMMAND FUNCTIONS '''


def event_search_command(client: Client, args: dict) -> CommandResults:
    """
    Search for logs using the Exabeam client with the provided arguments.

    Args:
        client: An instance of the Exabeam client used to make the search request.
        args: A dictionary containing search query parameters and options.

    Returns:
        CommandResults: A CommandResults object containing the search results in both structured and human-readable formats.
    """
    start_time = get_date(args.get('start_time', '7 days ago'), "start_time")
    end_time = get_date(args.get('end_time', 'today'), "end_time")
    if start_time > end_time:
        raise DemistoException("Start time must be before end time.")

    kwargs = {
        'filter': process_string(args.get('query', '')),
        'fields': argToList(args.get('fields', '*')),
        'limit': get_limit(args),
        'startTime': start_time,
        'endTime': end_time,
    }
    group_by = args.get('group_by')
    if group_by:
        group_list = argToList(group_by)
        kwargs.update({'groupBy': group_list, 'fields': group_list})

    response = client.event_search_request(kwargs)

    if error := response.get("errors", {}):
        raise DemistoException(error.get("message"))

    data_response = response.get("rows", {})

    human_readable = []
    for entry in data_response:
        if group_by:
            if parsed_entry := _parse_group_by(entry, group_list):
                human_readable.append(parsed_entry)
        elif parsed_entry := _parse_entry(entry):
            human_readable.append(parsed_entry)

    return CommandResults(
        outputs_prefix="ExabeamPlatform.Event",
        outputs=data_response,
        readable_output=tableToMarkdown(name="Logs", t=human_readable),
    )


def case_search_command(client: Client, args: dict) -> CommandResults:
    return generic_search_command(client, args, "case")


def alert_search_command(client: Client, args: dict) -> CommandResults:
    return generic_search_command(client, args, "alert")


def generic_search_command(client: Client, args: dict, item_type: str) -> CommandResults:
    """
    Searches for and retrieves items based on the provided item type and arguments.

    Args:
        client (Client): API client instance.
        args (dict): Search and filter parameters, including optional item IDs.
        item_type (str): Type of item to search for ('case' or 'alert').

    Returns:
        CommandResults: Contains search results and a Markdown table of the results.
    """
    if item_id := args.get(f"{item_type}_id"):
        if item_type == "case":
            data_response = [client.get_case_request(item_id)]
        elif item_type == "alert":
            data_response = [client.get_alert_request(item_id)]
        table_name = f"{item_type.capitalize()}"
    else:
        start_time = get_date(args.get('start_time', '7 days ago'), "start_time")
        end_time = get_date(args.get('end_time', 'today'), "end_time")
        if start_time > end_time:
            raise DemistoException("The start time argument must be earlier than the end time.")
        kwargs = {
            'filter': process_string(args.get('query') or ""),
            'fields': argToList(args.get('fields', '*')),
            'startTime': start_time,
            'endTime': end_time,
        }
        all_results = argToBoolean(args.get("all_results", False))
        if not all_results:
            kwargs['limit'] = get_limit(args)
        if order_by := args.get("order_by", ""):
            kwargs["orderBy"] = argToList(order_by)

        if item_type == "case":
            response = client.case_search_request(kwargs)
        elif item_type == "alert":
            response = client.alert_search_request(kwargs)
        else:
            response = {}
            demisto.debug(f"{item_type=} -> {response=}")
        data_response = response.get("rows", [])
        table_name = f"{item_type.capitalize()}s"

    fields_to_human_readable = ["caseId", "alertId", "riskScore", "priority", "groupedbyValue", "groupedbyKey",
                                "rules", "mitres", "useCases", "users", "stage", "queue"]
    human_readable = [_parse_entry(row, fields_to_human_readable)for row in data_response]

    include_related_rules = argToBoolean(args.get("include_related_rules", False))
    if not include_related_rules:
        for row in data_response:
            row.pop("rules", None)

    return CommandResults(
        outputs_prefix=f"ExabeamPlatform.{item_type.capitalize()}",
        outputs=data_response,
        readable_output=tableToMarkdown(name=table_name, t=human_readable)
    )


def context_table_list_command(client: Client, args: dict) -> CommandResults:
    """
    Retrieves and returns context tables based on provided arguments.

    Args:
        client (Client): The client instance used for API requests.
        args (dict): A dictionary of arguments. May include:
            - 'table_id': ID of a specific context table to retrieve.
            - 'include_attributes': Boolean to determine if attributes should be included in the output.

    Returns:
        CommandResults: Contains:
            - outputs_prefix: Prefix for the output keys.
            - outputs: The raw data response from the API.
            - readable_output: A Markdown table of the context tables.
    """
    if (table_id := args.get("table_id")):
        response = client.get_context_table(table_id)
        readable_output = _parse_entry(response)
        table_name = "Table"
    else:
        limit = get_limit(args)

        response = client.list_context_table()[:limit]

        include_attributes = argToBoolean(args.get("include_attributes"))

        readable_output = []
        for table in response:
            table = convert_all_timestamp_to_datestring(table)
            parsed_table = _parse_entry(table)
            readable_output.append(parsed_table)
            if not include_attributes:
                table.pop("attributes", None)
        table_name = "Tables"

    return CommandResults(
        outputs_prefix="ExabeamPlatform.ContextTable",
        outputs=response,
        readable_output=tableToMarkdown(name=table_name, t=readable_output)
    )


def context_table_delete_command(client: Client, args: dict) -> CommandResults:
    """
    Deletes a context table based on the provided table ID and optional parameters.

    Args:
        client (Client): The client instance used for API requests.
        args (dict): A dictionary of arguments. May include:
            - 'table_id': ID of the context table to delete.
            - 'delete_unused_custom_attributes': Boolean to specify if unused custom attributes should be deleted.

    Returns:
        CommandResults: Contains a readable message confirming the deletion of the context table.
    """
    table_id = args.get("table_id")
    include_attributes = argToBoolean(args.get("delete_unused_custom_attributes"))
    params = {"deleteUnusedCustomAttributes": str(include_attributes)}

    response = client.delete_context_table(table_id, params)
    table_id_response = response.get("id", None)

    return CommandResults(
        readable_output=f"The context table with ID {table_id_response} has been successfully deleted."
    )


def table_record_list_command(client: Client, args: dict) -> CommandResults:
    """
    Retrieves records from a specified table, with support for pagination.

    Args:
        client (Client): The client instance used for API requests.
        args (dict): A dictionary of arguments, including:
            - 'table_id' (str): ID of the table from which to retrieve records.
            - 'limit' (int, optional): Maximum number of records to retrieve. Defaults to a predefined limit.
            - 'page' (int, optional): The page number to retrieve. Defaults to 1 if 'page_size' is provided.
            - 'page_size' (int, optional): Number of records per page. Defaults to a predefined limit if 'page' is provided.

    Returns:
        CommandResults: The results of the command, including the records retrieved.
    """
    table_id = args.get("table_id")
    limit = arg_to_number(args.get("limit")) or DEFAULT_LIMIT
    page = arg_to_number(args.get("page"))
    page_size = arg_to_number(args.get("page_size"))
    records: list = []
    offset = 0

    if page:
        limit = min(page_size or DEFAULT_LIMIT, MAX_LIMIT)
        offset = (page - 1) * limit

    while len(records) < limit:
        params = {
            'limit': min(limit - len(records), MAX_LIMIT),
            'offset': offset
        }

        response = client.get_table_record_list(table_id, params)
        fetched_records = response.get("records", [])
        if not fetched_records:
            break

        records.extend(fetched_records)
        offset = len(records)

    readable_output = format_record_keys(records)

    return CommandResults(
        outputs_prefix="ExabeamPlatform.Record",
        outputs=records,
        readable_output=tableToMarkdown(name=f"Records of table id: {table_id}", t=readable_output)
    )


@polling_function(
    name="exabeam-platform-table-record-create",
    interval=arg_to_number(demisto.args().get("interval_in_seconds")),  # type: ignore
    timeout=arg_to_number(demisto.args().get("timeout")),  # type: ignore
    poll_message="Create records in process:",
    requires_polling_arg=False,
)
def table_record_create_command(args: dict, client: Client) -> PollResult:
    """
    Creates table records and polls their creation status.

    On first run, sends a request to create records and retrieves a `tracker_id`.
    On subsequent runs, checks the status using the `tracker_id`.

    Args:
        args (dict): Includes 'tracker_id', 'table_id', 'attributes', and 'operation'.
        client (Client): The client for API requests.

    Returns:
        PollResult: Contains the status and results of the record creation.
    """
    if not (tracker_id := args.get("tracker_id")):
        table_id = args.get("table_id")
        attributes = args.get("attributes", "")
        list_of_dict_attributes = transform_dicts(attributes)
        operation = args.get("operation")
        payload = {
            "operation": operation,
            "data": list_of_dict_attributes,
        }

        response = client.create_table_record(table_id, payload)
        tracker_id = response.get("trackerId", "")

    tracker_response = client.check_tracker_id(tracker_id)
    upload_status = tracker_response.get("uploadStatus")
    human_readable = {"Total Uploaded": tracker_response.get(
        "totalUploaded"), "Total Errors": tracker_response.get("totalErrors")}

    return PollResult(
        response=CommandResults(readable_output=tableToMarkdown("Completed", human_readable)),
        continue_to_poll=(upload_status != "completed"),
        args_for_next_run=args.update({"tracker_id": tracker_id}),
    )


def fetch_incidents(client: Client, params: dict[str, str], last_run) -> tuple[list, dict]:
    """
    Fetches incidents from the client based on specified parameters and updates the last run time.

    Args:
        client (Client): The client instance used for API requests.
        params (dict[str, str]): Dictionary of parameters for fetching incidents, including:
            - 'fetch_query': Filter query for incidents.
            - 'max_fetch': Maximum number of incidents to fetch.
            - 'first_fetch': Time range for the first fetch.
        last_run (dict): Last run data used to filter existing incidents.

    Returns:
        tuple[list, dict]:
            - A list of incidents.
            - Updated last run data.
    """
    demisto.debug(f"Last run before the fetch run: {last_run}")

    filter_query = params.get("fetch_query")
    limit = arg_to_number(params.get("max_fetch"))
    demisto.debug(f"Fetching incidents with limit={limit}")

    first_fetch = params.get("first_fetch", "3 days")
    start_time, end_time = get_fetch_run_time_range(last_run=last_run, first_fetch=first_fetch, date_format=DATE_FORMAT)
    demisto.debug(f"Fetching incidents between start_time={start_time} and end_time={end_time}")

    args = {"order_by": "caseCreationTimestamp", "query": filter_query, "start_time": start_time, "end_time": end_time,
            "limit": limit, "include_related_rules": True}

    cases = case_search_command(client, args).outputs
    if not isinstance(cases, list):
        raise DemistoException("The response did not contain a list of cases.")
    demisto.debug(f"Response contain {len(cases)} cases")

    ids_exists = last_run.get("last_ids", [])
    cases = filter_existing_cases(cases, ids_exists)

    last_run = update_last_run(cases, end_time)
    demisto.debug(f"Last run after the fetch run: {last_run}")

    incidents = format_incidents(cases)
    demisto.debug(f"After the fetch incidents count: {len(incidents)}")
    return incidents, last_run


def test_module(client: Client) -> str:    # pragma: no cover
    """test function

    Args:
        client: Client

    Returns:
        'ok' if successful
        If we've reached this point, it indicates that the login process was successful.

    """
    if client.access_token and generic_search_command(client, {}, "case"):
        return 'ok'
    else:
        raise DemistoException('Access Token Generation Failure.')


''' MAIN FUNCTION '''


def main() -> None:  # pragma: no cover
    params = demisto.params()
    args = demisto.args()
    command = demisto.command()
    credentials = params.get('credentials', {})
    client_id = credentials.get('identifier')
    client_secret = credentials.get('password')
    base_url = params.get('url', '')
    verify_certificate = not params.get('insecure', False)
    proxy = params.get('proxy', False)

    try:
        client = Client(
            base_url.rstrip('/'),
            verify=verify_certificate,
            client_id=client_id,
            client_secret=client_secret,
            proxy=proxy)

        demisto.debug(f'Command being called is {demisto.command()}')

        if command == 'test-module':
            return_results(test_module(client))
        elif command == 'fetch-incidents':
            last_run = demisto.getLastRun()
            incidents, next_run = fetch_incidents(client, params, last_run)
            demisto.setLastRun(next_run)
            demisto.incidents(incidents)
        elif command == 'exabeam-platform-event-search':
            return_results(event_search_command(client, args))
        elif command == 'exabeam-platform-case-search':
            return_results(case_search_command(client, args))
        elif command == 'exabeam-platform-alert-search':
            return_results(alert_search_command(client, args))
        elif command == 'exabeam-platform-context-table-list':
            return_results(context_table_list_command(client, args))
        elif command == 'exabeam-platform-context-table-delete':
            return_results(context_table_delete_command(client, args))
        elif command == 'exabeam-platform-table-record-list':
            return_results(table_record_list_command(client, args))
        elif command == 'exabeam-platform-table-record-create':
            return_results(table_record_create_command(args, client))
        else:
            raise NotImplementedError(f"Command {command} is not supported")

    except Exception as e:
        recommend = error_fixes(str(e))
        demisto.info(str(e))
        return_error(f'Failed to execute {demisto.command()} command.\nError:\n{str(e)}\n{recommend}')


''' ENTRY POINT '''


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
