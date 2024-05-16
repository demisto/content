import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
from CommonServerUserPython import *  # noqa

import urllib3

# Disable insecure warnings
urllib3.disable_warnings()


''' CONSTANTS '''

DATE_FORMAT = '%Y-%m-%dT%H:%M:%SZ'  # ISO8601 format with UTC, default in XSOAR

''' CLIENT CLASS '''


class Client(BaseClient):
    """Client class to interact with the service API

    This Client implements API calls, and does not contain any XSOAR logic.
    Should only do requests and return data.
    It inherits from BaseClient defined in CommonServer Python.
    Most calls use _http_request() that handles proxy, SSL verification, etc.
    For this  implementation, no special attributes defined
    """

    def __init__(self, base_url: str, client_id: str, client_secret: str, verify: bool,
                 proxy: bool, headers):
        super().__init__(base_url=f'{base_url}', headers=headers, verify=False, proxy=proxy, timeout=20)
        self.client_id = client_id
        self.client_secret = client_secret
        self.access_token = None

        self._login()

    def _login(self):
        """
        Logs in to the Exabeam API using the provided username and password.
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

    def search_request(self, data):
        """
        Performs basic get request to check if the server is reachable.
        """
        data = json.dumps(data)
        full_url = f"{self._base_url}/search/v2/events"
        response = self._http_request(
            "POST",
            full_url=full_url,
            data=data,
            headers={"Authorization": f"Bearer {self.access_token}", "Content-Type": "application/json"}
        )
        return response


''' HELPER FUNCTIONS '''


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
        date = date_time.strftime(DATE_FORMAT)
    return date


def adjust_string_pattern(filter_str):
    logical_operators = re.findall(r'\bAND\b|\bTO\b|\bNOT\b|\bOR\b', filter_str)
    conditions = re.split(r'\bAND\b|\bTO\b|\bNOT\b|\bOR\b', filter_str)
    adjusted_conditions = []

    for condition in conditions:
        parts = condition.split(':')
        if len(parts) == 2:
            field, value = parts
            if value.strip().lower() in ['true', 'false']:
                adjusted_conditions.append(condition.strip())
            else:
                adjusted_conditions.append(f'{field.strip()}:\\"{value.strip()}\\"')
        else:
            adjusted_conditions.append(condition.strip())

    adjusted_filter = ''
    for i in range(len(adjusted_conditions)):
        adjusted_filter += adjusted_conditions[i]
        if i < len(logical_operators):
            adjusted_filter += ' ' + logical_operators[i] + ' '

    return adjusted_filter


def _parse_entry(entry: dict):
    """
    Parse a single entry from the API response to a dictionary.
    Args:
        entry: The entry from the API response.
    Returns:
        dict: The parsed entry dictionary.
    """
    parsed = {
        "activity": entry.get("activity"),
        "activity_type": entry.get("activity_type"),
        "business_criticality": entry.get("business_criticality"),
        "host": entry.get("host"),
        "landscape": entry.get("landscape"),
        "outcome": entry.get("outcome"),
        "platform": entry.get("platform"),
        "product": entry.get("product"),
        "product_category": entry.get("product_category"),
        "subject": entry.get("subject"),
        "time": entry.get("time"),
        "vendor": entry.get("vendor")
    }
    final = remove_empty_elements(parsed)
    return final


''' COMMAND FUNCTIONS '''


def search_command(client: Client, args: dict):
    filter = args.get('query', '')
    filter = adjust_string_pattern(filter)
    # filter = "alert_subject:\"Inhibit System Recovery\" AND tier:\"Tier 1\" AND process_blocked:TRUE"
    kwargs = {
        'filter': "",
        'fields': argToList(args.get('fields', '*')),
        'limit': arg_to_number(args.get('limit', '50')),
        'startTime': get_date(args.get('start_time', '7 days ago')),
        'endTime': get_date(args.get('end_time', 'today')),
    }
    if args.get('group_by'):
        kwargs.update({'group_by': argToList(args.get('group_by'))})

    response = client.search_request(kwargs)

    if error := response.get("errors", {}):
        raise DemistoException(error.get("message"))

    data_response = response.get("rows")

    table_to_markdown = [_parse_entry(entry) for entry in data_response]

    return CommandResults(
        outputs_prefix="ExabeamPlatform.Event",
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
    # ADD COMMENT THAT IF WE ARRIVED HERE IT MEANS THAT THE LOGIN SUCCEEDED
    return 'ok'


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
    headers = {'Accept': 'application/json', 'Csrf-Token': 'nocheck'}

    demisto.debug(f'Command being called is {demisto.command()}')
    try:
        client = Client(
            base_url.rstrip('/'),
            verify=verify_certificate,
            client_id=client_id,
            client_secret=client_secret,
            proxy=proxy,
            headers=headers)

        if command == 'test-module':
            return_results(test_module(client))
        elif command == 'exabeam-platform-event-search':
            return_results(search_command(client, args))

    # Log exceptions and return errors
    except Exception as e:
        return_error(f'Failed to execute {demisto.command()} command.\nError:\n{str(e)}')


''' ENTRY POINT '''


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
