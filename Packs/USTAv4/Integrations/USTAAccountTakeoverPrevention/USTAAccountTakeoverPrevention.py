import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
from CommonServerUserPython import *  # noqa

import urllib3
from typing import Any

# Disable insecure warnings
urllib3.disable_warnings()

USTA_API_PREFIX = 'api/threat-stream/v4/'

DATE_FORMAT = '%Y-%m-%dT%H:%M:%SZ'  # ISO8601 format with UTC, default in XSOAR

USTA_TICKET_STATUSES = {
    "all": None,
    "in_progress": "in_progress",
    "open": "open",
    "closed": "closed",
    "out of scope": "out_of_scope",
    "passive": "passive",
}

MAX_ALERTS_TO_FETCH = 100


class Client(BaseClient):
    def __init__(self, base_url, verify, proxy, headers):
        super().__init__(base_url=base_url, verify=verify, proxy=proxy, headers=headers)

    def check_auth(self):
        self._http_request('GET', 'company/me', error_handler=self._http_error_handler)

    def compromised_credentials_api_request(self, **kwargs) -> list:
        params = assign_params(**kwargs)
        headers = self._headers

        demisto.debug(f'compromised_credentials_api_request: {params}')

        response = self._http_request(
            'GET',
            'security-intelligence/account-takeover-prevention/compromised-credentials-tickets',
            params=params,
            headers=headers
        )
        count = response.get('count', 0)
        next_url = response.get('next', None)
        results = response.get('results', [])

        demisto.debug(f'compromised_credentials_api_request: Fetched {count} results')

        while next_url:
            demisto.debug(f'compromised_credentials_api_request: Fetching next page: {next_url}')
            response_next = self._http_request('GET', full_url=next_url, headers=headers)
            results += response_next.get('results', [])
            next_url = response_next.get('next', None)
        return results

    def compromised_credentials_search_api_request(self, **kwargs) -> dict:
        params = assign_params(**kwargs)
        headers = self._headers
        demisto.debug(f'compromised_credentials_search_api_request: {params}')
        return self._http_request(
            'GET',
            'security-intelligence/account-takeover-prevention/compromised-credentials-tickets',
            params=params,
            headers=headers
        )

    @staticmethod
    def _http_error_handler(response):
        # Handle error responses here to proper error messages to the user
        if response.status_code == 401:
            raise DemistoException('Authorization Error: make sure API Key is correctly set')
        if response.status_code == 429:
            raise DemistoException('Rate limit exceeded. Please try again later..!')


def check_module(client: Client):
    try:
        client.check_auth()
    except DemistoException as e:
        if 'Connection Timeout Error' in str(e):
            return ValueError('Unable to connect to the USTA API! Make sure that your IP is whitelisted in the USTA.')
        raise e
    return 'ok'


def convert_to_demisto_severity(severity: str) -> int:
    return {
        'low': IncidentSeverity.LOW,
        'medium': IncidentSeverity.MEDIUM,
        'high': IncidentSeverity.HIGH,
        'critical': IncidentSeverity.CRITICAL,
        'unknown': IncidentSeverity.UNKNOWN
    }[severity]


def create_paging_header(results_num: int, page: int, size: int) -> str:
    header = f'Showing {results_num} results'
    if size is not None:
        header += f', Size={size}'
    if page is not None:
        header += f', from Page {page}'
    return header + '\n'


def fetch_incidents(
    client: Client,
    max_results: int,
    last_run: dict,
    first_fetch_time: str,
    status: Union[str, None] = None
) -> tuple[dict, list[dict]]:
    """Fetches the account takeover prevention module incidents using the USTA API. If the last_run is empty, fetch incidents
    from the given first_fetch_time. Otherwise, fetch incidents from the last run.

    Args:
        client (Client): USTA Account Takeover Prevention HTTP client.
        status (Union[int, None]): The status of the ticket to fetch. If None, fetch all tickets.
        first_fetch_time (str): The first fetch time to fetch incidents from.
    """
    if last_fetch := last_run.get('last_fetch', None):
        first_fetch_time = last_fetch

    assert first_fetch_time

    last_ids: list[int] = last_run.get('last_ids', []) or []

    incidents: list[dict[str, Any]] = []

    alerts = client.compromised_credentials_api_request(status=status, start=first_fetch_time, size=max_results)
    demisto.debug(f'Received {len(alerts)} alerts from server.')

    # API returns the newest alerts first so instead of -1 we need to get the first alert's created time
    last_fetched_time = alerts[0]['created'] if alerts else last_fetch

    new_last_ids: list[int] = []

    for alert in alerts:

        # skip the alerts which are already fetched and it is always sorted by created field.
        if alert['created'] == last_fetched_time:
            new_last_ids.append(alert['id'])

        if alert['id'] in last_ids:
            demisto.debug(f"Skipping already fetched alert: {alert['id']}")
            continue

        # if "is_corporate" is True, then the alert is Compromised Employee Credentials
        # if "is_corporate" is False, then the alert is Compromised End-User Credentials

        alert_corporate_type = 'Employee' if alert.get('is_corporate') else 'End-User'
        severity = 'critical' if alert_corporate_type == 'Employee' else 'medium'
        ticket_id = alert.get('id')

        incident = {
            'name': f'[{alert_corporate_type}] Compromised Credentials: USTA Ticket ID : {ticket_id}',
            'occurred': alert.get('created'),
            'severity': convert_to_demisto_severity(severity),
            'rawJSON': json.dumps(alert)
        }
        incidents.append(incident)

    demisto.debug(f"setting next run- {last_fetched_time=}")
    next_run = {'last_fetch': last_fetched_time, 'last_ids': new_last_ids}

    return next_run, incidents


def compromised_credentials_search_command(client: Client, args: dict) -> CommandResults:
    username = args.get('username', None)
    size = args.get('page_size', None)
    page = args.get('page', None)

    if not username:
        raise ValueError('Please provide a username to search for.')

    if results := client.compromised_credentials_search_api_request(username=username, page=page, size=size):
        readable_output = create_paging_header(
            results_num=results.get('count', 0),
            page=page,
            size=size,
        ) + tableToMarkdown('Account Takeover Prevention', results.get('results', []))
        return CommandResults(
            outputs_prefix='USTA.AccountTakeoverPrevention',
            outputs_key_field='id',
            outputs=results,
            readable_output=readable_output
        )
    return CommandResults(
        readable_output='No results found.',
        outputs={},
    )


def main() -> None:
    # demisto params and args
    params: dict[str, Any] = demisto.params()
    args: dict[str, Any] = demisto.args()

    # Instance parameters
    verify_certificate: bool = not params.get('insecure', False)
    base_url = urljoin(params['url'], USTA_API_PREFIX)
    proxy = params.get('proxy', False)
    api_key = params.get('api_key')
    cmd = demisto.command()

    # How much time before the first fetch to retrieve alerts
    first_fetch_time = arg_to_datetime(
        arg=params.get('first_fetch', '3 days'),
        arg_name='First fetch time',
        required=True
    )
    assert first_fetch_time

    demisto.debug(f'Command being called is {demisto.command()}')
    try:

        headers: dict = {
            'Authorization': f'Bearer {api_key}',
            'Content-Type': 'application/json'
        }

        client = Client(
            base_url=base_url,
            verify=verify_certificate,
            headers=headers,
            proxy=proxy
        )

        commands = {
            'usta-atp-search-username': compromised_credentials_search_command,
        }

        if cmd == 'test-module':
            return_results(check_module(client))
        elif cmd == 'fetch-incidents':
            status = USTA_TICKET_STATUSES.get(params.get('status', 'Open').lower())
            max_results = arg_to_number(
                arg=params.get('max_fetch'),
                arg_name='max_fetch',
                required=False
            )
            if not max_results or max_results > MAX_ALERTS_TO_FETCH:
                max_results = MAX_ALERTS_TO_FETCH

            next_run, incidents = fetch_incidents(
                client=client,
                max_results=max_results,
                last_run=demisto.getLastRun(),
                first_fetch_time=datetime.strftime(first_fetch_time, DATE_FORMAT),
                status=status
            )
            demisto.incidents(incidents)
            demisto.setLastRun(next_run)
        elif cmd in commands:
            return_results(commands[cmd](client, args))

    # Log exceptions and return errors
    except Exception as e:
        return_error(f'Failed to execute {demisto.command()} command.\nError:\n{str(e)}')


''' ENTRY POINT '''


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
