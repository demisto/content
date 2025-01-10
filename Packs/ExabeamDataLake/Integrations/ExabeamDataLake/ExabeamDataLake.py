import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *

import urllib3
# Disable insecure warnings
urllib3.disable_warnings()

""" CONSTANTS """

ISO_8601_FORMAT = "%Y-%m-%d"


""" CLIENT CLASS """


class Client(BaseClient):
    """
    Client to use in the Exabeam DataLake integration. Overrides BaseClient
    """

    def __init__(self, base_url: str, username: str, password: str, verify: bool,
                 proxy: bool):
        super().__init__(base_url=f'{base_url}', verify=verify, proxy=proxy, timeout=20)
        self.username = username
        self.password = password

        self._login()

    def _login(self):
        """
        Logs in to the Exabeam API using the provided username and password.
        This function must be called before any other API calls.
        """
        data = {"username": self.username, "password": self.password}
        self._http_request(
            "POST",
            full_url=f"{self._base_url}/api/auth/login",
            headers={'Accept': 'application/json', 'Csrf-Token': 'nocheck'},
            data=data,
        )

    def _logout(self) -> None:
        """
        The _logout method initiates a logout request, utilizing a GET HTTP request to the specified endpoint for
        user session termination.
        """
        self._http_request('GET', full_url=f"{self._base_url}/api/auth/logout")

    def test_module_request(self):
        """
        Performs basic get request to check if the server is reachable.
        """
        self._http_request('GET', full_url=f'{self._base_url}/api/auth/check', resp_type='text')

    def query_datalake_request(self, args: dict, from_param: int, size_param: int, cluster_name: str,
                               dates_in_format: list) -> dict:
        """
        Queries the Exabeam Data Lake API with the provided search query and returns the response.
        """
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
        return self._http_request(
            "POST",
            full_url=f"{self._base_url}/dl/api/es/search",
            data=json.dumps(search_query),
            headers={'Content-Type': 'application/json', 'Csrf-Token': 'nocheck'},
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
        raise DemistoException("Start time must be before end time.")

    if (end_time - start_time).days > 10:
        raise DemistoException("Difference between start time and end time must be less than or equal to 10 days.")

    dates = []
    current_date = start_time
    while current_date <= end_time:
        dates.append(current_date.strftime("%Y.%m.%d"))
        current_date += timedelta(days=1)

    return dates


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
    date = date_time.strftime(ISO_8601_FORMAT)
    return date


def get_limit(args: dict, arg_name: str) -> int:
    """
    Get the limit value specified in the arguments.

    Args:
        args: A dictionary containing the 'limit' argument.

    Returns:
        int: The limit value if specified and less than or equal to 3000; otherwise, returns 3000 as the maximum limit.
        If the 'limit' argument is not present in the dictionary or is None, returns 50 as the default limit.
    """
    if limit := args.get(arg_name):
        return min(int(limit), 3000)

    return 50


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

    if page_arg and page_size_arg:
        page = arg_to_number(args.get('page', '1'))
        page_size = get_limit(args, "page_size")
        if page == 0 or page_size == 0:
            raise DemistoException("Both 'page' and 'page_size' must be greater than 0.")
        if page and page_size:
            if page < 0 or page_size < 0:
                raise DemistoException("Both 'page' and 'page_size' must be greater than 0.")
            from_param = page * page_size - page_size
            size_param = page_size
        else:
            from_param = 0
            size_param = 0
            demisto.debug(f"{from_param=} {size_param=}")
    else:
        from_param = 0
        size_param = get_limit(args, "limit")

    return from_param, size_param


""" COMMAND FUNCTIONS """


def query_data_lake_command(client: Client, args: dict, cluster_name: str) -> CommandResults:
    """
    Query the datalake command and return the results in a formatted table.

    Args:
        client: The client object for interacting with the API.
        args: The arguments passed to the command.

    Returns:
        CommandResults: The command results object containing outputs and readable output.
    """
    from_param, size_param = calculate_page_parameters(args)

    start_time = get_date(args.get("start_time", "7 days ago"), "start_time")
    end_time = get_date(args.get("end_time", "today"), "end_time")
    dates = dates_in_range(start_time, end_time)
    dates_in_format = ["exabeam-" + date for date in dates]

    response = client.query_datalake_request(args, from_param, size_param, cluster_name, dates_in_format).get("responses", [{}])

    data_response = response[0].get("hits", {}).get("hits", [])

    human_readable = [_parse_entry(entry) for entry in data_response]

    return CommandResults(
        outputs_prefix="ExabeamDataLake.Event",
        outputs=data_response,
        readable_output=tableToMarkdown(name="Logs", t=human_readable, headers=[
                                        "Id", "Vendor", "Product", "Created_at", "Message"])
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

    credentials: dict = params.get('credentials', {})
    username = credentials.get('identifier', '')
    password = credentials.get('password', '')
    base_url: str = params.get('url', '')
    verify_certificate = not params.get('insecure', False)
    proxy = params.get('proxy', False)
    cluster_name = params.get('cluster_name', 'local')
    client = None

    try:
        client = Client(
            base_url.rstrip('/'),
            username=username,
            password=password,
            verify=verify_certificate,
            proxy=proxy
        )

        demisto.debug(f"Command being called is {command}")

        if command == "test-module":
            return_results(test_module(client))
        elif command == "exabeam-data-lake-search":
            return_results(query_data_lake_command(client, args, cluster_name))
        else:
            raise NotImplementedError(f"Command {command} is not supported")

    except Exception as e:
        demisto.info(str(e))
        return_error(f'Failed to execute {demisto.command()} command.\nError:\n{str(e)}')

    finally:
        if client:
            client._logout()


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
