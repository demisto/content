import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
from CommonServerUserPython import *  # noqa

import urllib3

# Disable insecure warnings
urllib3.disable_warnings()


''' CONSTANTS '''

DATE_FORMAT = '%Y-%m-%dT%H:%M:%SZ'


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

        self._login()

    def _login(self):
        """
        Logs in to the Exabeam API using the provided client_id and client_password.
        This function must be called before any other API calls.
        Note: the session is automatically closed in BaseClient's __del__
        """
        data = {"client_id": self.client_id, "client_secret": self.client_secret, "grant_type": "client_credentials"}

        response = self._http_request(
            "POST",
            full_url=f"{self._base_url}/auth/v1/token",
            data=data,
        )
        self.access_token = response.get('access_token')

    def search_request(self, data_dict: dict) -> dict:
        """
        Performs basic get request to check if the server is reachable.
        """
        data = json.dumps(data_dict)
        full_url = f"{self._base_url}/search/v2/events"
        response = self._http_request(
            "POST",
            full_url=full_url,
            data=data,
            headers={"Authorization": f"Bearer {self.access_token}", "Content-Type": "application/json"}
        )
        return response


''' HELPER FUNCTIONS '''


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
        "Time": entry.get("time")
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
        return min(int(limit), 3000)

    return 50


def error_fixes(error: str):
    new_error = ""
    if 'not enough values to unpack' in error:
        new_error = ("Recommendation:\nValidate the query argument "
                     "against the syntax documentation in the integration description.")

    return new_error


''' COMMAND FUNCTIONS '''


def search_command(client: Client, args: dict) -> CommandResults:
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

    response = client.search_request(kwargs)

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
        elif command == 'exabeam-platform-event-search':
            return_results(search_command(client, args))
        else:
            raise NotImplementedError(f"Command {command} is not supported")

    except Exception as e:
        recommend = error_fixes(str(e))
        demisto.info(str(e))
        return_error(f'Failed to execute {demisto.command()} command.\nError:\n{str(e)}\n{recommend}')


''' ENTRY POINT '''


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
