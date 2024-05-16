import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *

""" CONSTANTS """

HEADERS = {"Accept": "application/json", "Csrf-Token": "nocheck"}

ISO_8601_FORMAT = "%Y-%m-%d"


""" CLIENT CLASS """


class Client(BaseClient):
    """
    Client to use in the Exabeam DataLake integration. Overrides BaseClient
    """

    def __init__(self, base_url: str, username: str, password: str, verify: bool,
                 proxy: bool, headers):
        super().__init__(base_url=f'{base_url}', headers=headers, verify=False, proxy=proxy, timeout=20)
        self.username = username
        self.password = password

        self._login()

    def _login(self):
        """
        Logs in to the Exabeam API using the provided username and password.
        This function must be called before any other API calls.
        Note: the session is automatically closed in BaseClient's __del__
        """
        headers = {"Csrf-Token": "nocheck"}
        data = {"username": self.username, "password": self.password}

        self._http_request(
            "POST",
            full_url=f"{self._base_url}/api/auth/login",
            headers=headers,
            data=data,
        )

    def test_module_request(self):
        """
        Performs basic get request to check if the server is reachable.
        """
        self._http_request('GET', full_url=f'{self._base_url}/api/auth/check', resp_type='text')

    def query_datalake_request(self, search_query: dict) -> dict:
        return self._http_request(
            "POST",
            full_url=f"{self._base_url}/dl/api/es/search",
            data=json.dumps(search_query),
            headers={"kbn-version": "5.1.1-SNAPSHOT", "Content-Type": "application/json"},
        )


""" HELPER FUNCTIONS """


def _parse_entry(entry: dict) -> dict:
    """
    Parse a single entry from the API response to a dictionary.

    Args:
        entry: The entry from the API response.

    Returns:
        dict: The parsed entry dictionary.
    """
    source: dict = entry.get("_source", {})
    return {
        "Id": entry.get("_id"),
        "Vendor": source.get("Vendor"),
        "Created_at": source.get("@timestamp"),
        "Product": source.get("Product"),
        "Message": source.get("message")
    }


def dates_in_range(start_time: Any, end_time: Any) -> list[str]:
    """
     Generate a list of dates within a specified range.

    Args:
        start_time: The start date of the range in the format "YYYY-MM-DD".
        end_time: The end date of the range in the format "YYYY-MM-DD".

    Raises:
        DemistoException: If the start time is not before the end time, or if the difference between start time and end time is
        greater than 10 days.

    Returns:
        list: A list of dates within the specified range, formatted as strings in the format "YYYY.MM.DD".
    """
    start_time = datetime.strptime(start_time, "%Y-%m-%d")
    end_time = datetime.strptime(end_time, "%Y-%m-%d")

    if start_time >= end_time:
        raise DemistoException("Start time must be before end time")

    if (end_time - start_time).days > 10:
        raise DemistoException("Difference between start time and end time must be less than or equal to 10 days")

    dates = []
    current_date = start_time
    while current_date <= end_time:
        dates.append(current_date.strftime("%Y.%m.%d"))
        current_date += timedelta(days=1)

    return dates


def get_date(time: str):
    """
    Get the date from a given time string.

    Args:
        time (str): The time string to extract the date from.

    Returns:
        str: The date extracted from the time string formatted in ISO 8601 format (YYYY-MM-DD),
        or None if the time string is invalid.
    """
    date_time = arg_to_datetime(arg=time, arg_name="Start time", required=True)
    if date_time:
        date = date_time.strftime(ISO_8601_FORMAT)
    return date


def calculate_page_parameters(args: dict) -> tuple[int, int]:
    """
      Calculate the page parameters for pagination.

    Args:
        args: A dictionary containing the arguments passed to the function.

    Raises:
        DemistoException: If invalid combinations of arguments are provided. You can only provide 'limit'
        alone or 'page' and 'page_size' together.

    Returns:
        tuple: A tuple containing two integers representing the 'from' and 'size' parameters for pagination.
        'from' is the index of the first item to retrieve, and 'size' is the number of items to retrieve.
    """
    page_arg = args.get('page')
    page_size_arg = args.get('page_size')
    limit_arg = args.get('limit')

    if (limit_arg and (page_arg or page_size_arg)) or ((not (page_arg and page_size_arg)) and (page_arg or page_size_arg)):
        raise DemistoException("You can only provide 'limit' alone or 'page' and 'page_size' together.")

    if args.get('page') and args.get('page_size'):
        page = arg_to_number(args.get('page', '1'))
        page_size = arg_to_number(args.get('page_size', '50'))
        if page and page_size:
            from_param = page * page_size - page_size
            size_param = page_size
    else:
        from_param = 0
        size_param = arg_to_number(args.get('limit', '50')) or 50

    return from_param, size_param


""" COMMAND FUNCTIONS """


def query_datalake_command(client: Client, args: dict, cluster_name: str) -> CommandResults:
    """
    Query the datalake command and return the results in a formatted table.

    Args:
        client: The client object for interacting with the API.
        args: The arguments passed to the command.

    Returns:
        CommandResults: The command results object containing outputs and readable output.
    """
    from_param, size_param = calculate_page_parameters(args)

    start_time = get_date(args.get("start_time", "7 days ago"))
    end_time = get_date(args.get("end_time", "today"))
    dates = dates_in_range(start_time, end_time)
    dates_in_format = ["exabeam-" + date for date in dates]

    search_query = {
        "sortBy": [
            {"field": "@timestamp", "order": "desc", "unmappedType": "date"}
        ],
        "query": args.get("query", "*"),
        "from": from_param,
        "size": size_param,
        "clusterWithIndices": [
            {
                "clusterName": cluster_name,
                "indices": dates_in_format,
            }
        ]
    }

    response = client.query_datalake_request(search_query).get("responses", [{}])

    if error := response[0].get("error", {}):
        raise DemistoException(f"Error in query: {error.get('root_cause', [{}])[0].get('reason', 'Unknown error occurred')}")

    data_response = response[0].get("hits", {}).get("hits", [])

    table_to_markdown = [_parse_entry(entry) for entry in data_response]

    return CommandResults(
        outputs_prefix="ExabeamDataLake.Event",
        outputs=data_response,
        readable_output=tableToMarkdown(name="Logs", t=table_to_markdown),
    )


def test_module(client: Client):    # pragma: no cover
    """test function

    Args:
        client: Client

    Returns:
        ok if successful
    """
    client.test_module_request()
    return 'ok'


""" MAIN FUNCTION """


def main() -> None:    # pragma: no cover
    params = demisto.params()
    args = demisto.args()
    command = demisto.command()

    credentials = params.get('credentials', {})
    username = credentials.get('identifier')
    password = credentials.get('password')
    base_url = params.get('url', '')
    verify_certificate = not params.get('insecure', False)
    proxy = params.get('proxy', False)
    headers = {'Accept': 'application/json', 'Csrf-Token': 'nocheck'}
    cluster_name = params.get('cluster_name', 'local')

    try:
        client = Client(
            base_url.rstrip('/'),
            verify=verify_certificate,
            username=username,
            password=password,
            proxy=proxy,
            headers=headers
        )

        demisto.debug(f"Command being called is {command}")

        if command == "test-module":
            return_results(test_module(client))
        elif command == "exabeam-data-lake-search":
            return_results(query_datalake_command(client, args, cluster_name))
        else:
            raise NotImplementedError(f"Command {command} is not supported")

    except Exception as e:
        return_error(f"Failed to execute {command} command.\nError:\n{str(e)}")


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
