import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401


''' CONSTANTS '''

DATE_FORMAT = '%Y-%m-%dT%H:%M:%SZ'
TOKEN_EXPIRY_BUFFER = timedelta(seconds=10)
DEFAULT_LIMIT = 50
MAX_LIMIT = 3000
# TODO: remove print
print(f"{demisto.args()=}")
print(f"{demisto.params()=}")


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
        kargs["headers"] = {
            "accept": "application/json",
            "Content-Type": "application/json",
            "Authorization": f"Bearer {self.access_token}",
        }

        def _make_request() -> Any:
            # TODO: remove print
            # print(f"{kargs}")
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
        """
        data = json.dumps(data_dict)
        full_url = f"{self._base_url}/threat-center/v1/search/cases"
        response = self.request(
            method="POST",
            full_url=full_url,
            data=data,
        )
        return response

    def get_case_request(self, case_id: int) -> dict:
        """
        """
        full_url = f"{self._base_url}/threat-center/v1/cases/{case_id}"
        response = self.request(
            method="GET",
            full_url=full_url
        )
        return response

    def alert_search_request(self, data_dict: dict) -> dict:
        """
        """
        data = json.dumps(data_dict)
        full_url = f"{self._base_url}/threat-center/v1/search/alerts"
        response = self.request(method="POST", full_url=full_url, data=data,)
        return response

    def create_table_record(self, table_id, json_data):
        """ """
        full_url = f"{self._base_url}/context-management/v1/tables/{table_id}/addRecords"
        response = self.request(method="POST", full_url=full_url, json_data=json_data)
        return response

    def check_tracker_id(self, tracker_id):
        """ """
        full_url = f"{self._base_url}/context-management/v1/tables/uploadStatus/{tracker_id}"
        response = self.request(method="GET", full_url=full_url)
        return response

    def list_context_table(self) -> dict:
        """ """
        full_url = f"{self._base_url}/context-management/v1/tables"
        response = self.request(method="GET", full_url=full_url)
        return response

    def get_context_table(self, table_id) -> dict:
        """ """
        full_url = f"{self._base_url}/context-management/v1/tables/{table_id}"
        response = self.request(method="GET", full_url=full_url)
        return response

    def delete_context_table(self, table_id, params) -> dict:
        """ """
        full_url = f"{self._base_url}/context-management/v1/tables/{table_id}"
        response = self.request(method="DELETE", full_url=full_url, params=params)
        return response

    def get_table_record_list(self, table_id, params) -> dict:
        """ """
        full_url = f"{self._base_url}/context-management/v1/tables/{table_id}/records"
        response = self.request(method="GET", full_url=full_url, params=params)
        return response

    def get_alert_request(self, case_id: int) -> dict:
        """
        """
        full_url = f"{self._base_url}/threat-center/v1/alerts/{case_id}"
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


def _parse_entry(entry: dict):
    """
    Parse a single entry from the API response to a dictionary.
    Args:
        entry: The entry from the API response.
    Returns:
        dict: The parsed entry dictionary.
    """
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
        "Users": entry.get("users"),
        "Tags": entry.get("tags"),
        "Use Cases": entry.get("useCases"),
        "Stage": entry.get("stage"),
        "Mitres": entry.get("mitres"),
        "Dest IPs": entry.get("destIps"),
        "Queue": entry.get("queue"),
        "Name": entry.get("name"),
        "Source": entry.get("source"),
        "Context Type": entry.get("contextType"),
        "# Items": entry.get("totalItems"),
        "Status": entry.get("status"),
        "Last Updated": entry.get("lastUpdated"),
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
    if limit := args.get('limit'):
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


def process_attributes(attributes: str) -> Dict[str, List[str]]:
    if not (attributes.startswith("{") and attributes.endswith("}")):
        attributes = "{" + attributes + "}"

    attributes_dict = json.loads(attributes)
    return attributes_dict


def convert_all_timestamp_to_datestring(incident: dict) -> dict:
    keys = ['caseCreationTimestamp', 'lastModifiedTimestamp', 'creationTimestamp',
            'ingestTimestamp', 'approxLogTime', 'lastUpdated']
    for key in keys:
        if key in incident:
            incident[key] = timestamp_to_datestring(incident[key] / 1000, date_format=DATE_FORMAT)
    return incident


def filter_existing_cases(cases, last_run):
    """
    Filters out cases that already exist in the last run.

    Args:
        cases (list[dict]): List of cases to filter.
        last_run (dict): Dictionary containing the last run information, including existing case IDs.

    Returns:
        list[dict]: Filtered list of cases.
    """
    ids_exists = last_run.get("last_ids", [])
    demisto.debug(f"Existing IDs: {ids_exists}")

    filtered_cases = []
    for case in cases:
        case_id = case.get("caseId")
        if case_id not in ids_exists:
            filtered_cases.append(case)
        else:
            demisto.debug(f"Case with ID {case_id} already exists, skipping.")

    demisto.debug(f"Filtered cases count: {len(filtered_cases)}")
    return filtered_cases


def update_last_run(cases, end_time):
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


def create_incidents(cases):
    incidents = []
    for case in cases:
        case = convert_all_timestamp_to_datestring(case)
        alert_name = case.get("alertName", "")
        incidents.append({
            "Name": alert_name,
            "rawJSON": json.dumps(case),
        })
    return incidents


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
    if (case_id := args.get("case_id")):
        data_response = client.get_case_request(case_id)
        human_readable = _parse_entry(data_response)
    else:
        start_time = get_date(args.get('start_time', '7 days ago'), "start_time")
        end_time = get_date(args.get('end_time', 'today'), "end_time")
        if start_time > end_time:
            raise DemistoException("Start time must be before end time.")

        kwargs = {
            'filter': process_string(args.get('query', '')),
            'fields': argToList(args.get('fields', '*')),
            'startTime': start_time,
            'endTime': end_time,
        }

        all_results = argToBoolean(args.get("all_results", False))
        if not all_results:
            kwargs['limit'] = get_limit(args)

        if (order_by := args.get("order_by", "")):
            kwargs["orderBy"] = argToList(order_by)

        response = client.case_search_request(kwargs)
        data_response = response.get("rows", [])

        include_related_rules = argToBoolean(args.get("include_related_rules", False))
        human_readable = []
        for row in data_response:
            if parsed_row := _parse_entry(row):
                human_readable.append(parsed_row)
            if not include_related_rules:
                row.pop("rules", None)

    return CommandResults(
        outputs_prefix="ExabeamPlatform.Case",
        outputs=data_response,
        readable_output=tableToMarkdown(name="Cases", t=human_readable)
    )


def alert_search_command(client: Client, args: dict) -> CommandResults:
    if (alert_id := args.get("alert_id")):
        data_response = client.get_alert_request(alert_id)
        human_readable = _parse_entry(data_response)
    else:
        start_time = get_date(args.get('start_time', '7 days ago'), "start_time")
        end_time = get_date(args.get('end_time', 'today'), "end_time")
        if start_time > end_time:
            raise DemistoException("Start time must be before end time.")

        kwargs = {
            'filter': process_string(args.get('query') or ""),
            'fields': argToList(args.get('fields', '*')),
            'startTime': start_time,
            'endTime': end_time,
        }

        if (order_by := args.get("order_by", "")):
            kwargs["orderBy"] = argToList(order_by)

        all_results = argToBoolean(args.get("all_results"))
        if not all_results:
            kwargs['limit'] = get_limit(args)

        response = client.alert_search_request(kwargs)
        data_response = response.get("rows", [])

        include_related_rules = argToBoolean(args.get("include_related_rules"))
        human_readable = []
        for row in data_response:
            if parsed_row := _parse_entry(row):
                human_readable.append(parsed_row)
            if not include_related_rules:
                row.pop("rules", None)

    return CommandResults(
        outputs_prefix="ExabeamPlatform.Alert",
        outputs=data_response,
        readable_output=tableToMarkdown(name="Alert", t=human_readable)
    )


def context_table_list_command(client: Client, args: dict) -> CommandResults:
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
    table_id = args.get("table_id", 0)
    include_attributes = argToBoolean(args.get("delete_unused_custom_attributes"))
    params = {"deleteUnusedCustomAttributes": str(include_attributes)}

    response = client.delete_context_table(table_id, params)
    table_id_response = response.get("id", None)

    return CommandResults(
        readable_output=f"The context table with ID {table_id_response} has been successfully deleted."
    )


def table_record_list_command(client: Client, args: dict) -> CommandResults:
    table_id = args.get("table_id")
    params = {'limit': get_limit(args)}

    response = client.get_table_record_list(table_id, params)
    records = response.get("records", [])

    return CommandResults(
        outputs_prefix="ExabeamPlatform.Record",
        outputs=records,
        readable_output=tableToMarkdown(name=f"Records of table id: {table_id}", t=records)
    )


@polling_function(
    name="exabeam-platform-table-record-create",
    interval=arg_to_number(demisto.args().get("interval_in_seconds")),  # type: ignore
    timeout=arg_to_number(demisto.args().get("timeout")),  # type: ignore
    poll_message="Create records in process:",
    requires_polling_arg=False,
)
def table_record_create_command(args: dict, client: Client) -> PollResult:
    if not (tracker_id := args.get("tracker_id")):
        table_id = args.get("table_id")
        attributes = args.get("attributes", "")
        attributes_dict = process_attributes(attributes)
        list_of_dict_attributes = transform_dicts(attributes_dict)
        operation = args.get("operation")
        payload = {
            "operation": operation,
            "data": list_of_dict_attributes,
        }

        response = client.create_table_record(table_id, payload)
        tracker_id = response.get("trackerId", "")

    tracker_response = client.check_tracker_id(tracker_id)
    upload_status = tracker_response.get("uploadStatus")
    # TODO: print
    # print(f"{upload_status=}")
    human_readable = {"Total Uploaded": tracker_response.get(
        "totalUploaded"), "Total Errors": tracker_response.get("totalErrors")}

    return PollResult(
        response=CommandResults(readable_output=tableToMarkdown("Completed", human_readable)),
        continue_to_poll=(upload_status != "completed"),
        args_for_next_run=args.update({"tracker_id": tracker_id}),
    )


def fetch_incidents(client: Client, params: dict[str, str], last_run) -> tuple[list, dict]:

    demisto.debug(f"Last run before the fetch run: {last_run}")

    filter_query = process_string(params.get("fetch_query") or "")
    limit = arg_to_number(params.get("max_fetch"))
    demisto.debug(f"Fetching incidents with limit={limit}")

    first_fetch = params.get("first_fetch", "3 days")
    start_time, end_time = get_fetch_run_time_range(last_run=last_run, first_fetch=first_fetch, date_format=DATE_FORMAT)
    demisto.debug(f"Fetching incidents between start_time={start_time} and end_time={end_time}")

    args = {"query": filter_query, "start_time": start_time, "end_time": end_time, "limit": limit, "include_related_rules": True}

    cases = case_search_command(client, args).outputs
    if not isinstance(cases, list):
        raise DemistoException("The response did not contain a list of cases.")
    demisto.debug(f"Response contain {len(cases)} cases")

    cases = filter_existing_cases(cases, last_run)
    demisto.debug(f"After filtered cases count: {len(cases)}")

    last_run = update_last_run(cases, end_time)
    incidents = create_incidents(cases)

    demisto.debug(f"Last run after the fetch run: {last_run}")
    return incidents, last_run


def test_module(client: Client) -> str:    # pragma: no cover
    """test function

    Args:
        client: Client

    Returns:
        'ok' if successful
        If we've reached this point, it indicates that the login process was successful.

    """
    if client.access_token:
        return 'ok'
    else:
        raise DemistoException('Access Token Generation Failure.')


''' MAIN FUNCTION '''


def main() -> None:
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
