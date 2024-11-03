import demistomock as demisto
from CommonServerPython import *  # noqa # pylint: disable=unused-wildcard-import
from CommonServerUserPython import *  # noqa

import urllib3

# Disable insecure warnings
urllib3.disable_warnings()

''' CONSTANTS '''

DATE_FORMAT = '%Y-%m-%dT%H:%M:%SZ'  # ISO8601 format with UTC, default in XSOAR
VENDOR = 'orca'
PRODUCT = 'security'

''' CLIENT CLASS '''


class Client(BaseClient):

    def __init__(self, server_url: str, headers: dict, proxy: bool = False, verify: bool = False):
        super().__init__(base_url=server_url, verify=verify, proxy=proxy, headers=headers)

    def get_alerts_request(self, max_fetch: int, last_fetch: str, next_page_token: Optional[str]) -> dict:
        """ Retrieve information about alerts.
            Args:
                max_fetch: int - Limit number of returned records.
                last_fetch: str - the date and time of the last fetch
                next_page_token: Optional[str] - the token to the next page
            Returns:
                A dictionary with the alerts details.
        """
        params = {
            'limit': max_fetch,
            'dsl_filter': "{\n\"filter\":\n[\n{\n\"field\": \"state.created_at\",\n\"range\": {\n\""
                          "gt\": \"" + last_fetch + "\"\n}\n}\n],\n\"sort\":\n[\n{\"field\":"
                                                    "\"state.created_at\",\n\"order\":\"asc\"\n}\n]}",
            'show_all_statuses_alerts': True,
            'show_informational_alerts': True,
        }
        if next_page_token:
            params['next_page_token'] = next_page_token

        demisto.info(f'In get_alerts request {params=}')
        return self._http_request(method='GET', url_suffix='/query/alerts', params=params)


''' HELPER FUNCTIONS '''


def add_time_key_to_alerts(alerts: List[dict]) -> List[dict]:
    """
    Adds the _time key to the alerts.
    Args:
        alerts: List[Dict] - list of events to add the _time key to.
    Returns:
        list: The events with the _time key.
    """
    if alerts:
        for alert in alerts:
            create_time = arg_to_datetime(arg=alert.get('state', {}).get('created_at'))
            alert['_time'] = create_time.strftime(DATE_FORMAT) if create_time else None
            demisto.debug(f'{alert.get("state", {}).get("alert_id")=} , {alert.get("_time")=}')
    return alerts


''' COMMAND FUNCTIONS '''


def test_module(client: Client, last_fetch: str, max_fetch: int) -> str:
    """ Test the connection to Orca Security.
    Args:
        client: client - An Orca client.
        last_fetch: str - The time and date of the last fetch alert
        max_fetch: int - The maximum number of events per fetch
    Returns:
        'ok' if the connection was successful, else throws exception.
    """
    try:
        client.get_alerts_request(max_fetch, last_fetch, None)
        return 'ok'
    except DemistoException as e:
        if 'Error in API call [404] - Not Found' in e.message:
            raise Exception('Error in API call [404] - Not Found\n{"error": "URL is invalid"}')
        else:
            raise Exception(e.message)


def get_alerts(client: Client, max_fetch: int, last_fetch: str, next_page_token: str = None) -> tuple:
    """ Retrieve information about alerts.
    Args:
        client: client - An Orca client.
        max_fetch: int - The maximum number of events per fetch
        last_fetch: str - The time and date of the last fetch alert
        next_page_token: str - The token to the next page.
    Returns:
        - list of alerts
        - next_page_token if exist
    """
    response = client.get_alerts_request(max_fetch, last_fetch, next_page_token)
    next_page_token = response.get('next_page_token')
    alerts = response.get('data', [])
    demisto.debug(f'Get Alerts Response {next_page_token=} , {len(alerts)=}\n {alerts=}')
    return alerts, next_page_token


''' MAIN FUNCTION '''


def main() -> None:
    command = demisto.command()
    api_token = demisto.params().get('credentials', {}).get('password')
    server_url = f"{demisto.params().get('server_url')}/api"
    first_fetch = demisto.params().get('first_fetch') or '3 days'
    max_fetch = arg_to_number(demisto.params().get('max_fetch')) or 1000
    verify_certificate = not demisto.params().get('insecure', False)
    proxy = demisto.params().get('proxy', False)

    # How much time before the first fetch to retrieve events
    first_fetch_time = arg_to_datetime(
        arg=first_fetch,
        arg_name='First fetch time',
        required=True
    )
    first_fetch_time = first_fetch_time.strftime(DATE_FORMAT) if first_fetch_time else ''
    demisto.debug(f'{first_fetch_time=}')
    demisto.info(f'Orca Security. Command being called is {command}')
    try:

        headers: dict = {
            "Authorization": f'Token {api_token}'
        }

        client = Client(
            server_url=server_url,
            verify=verify_certificate,
            headers=headers,
            proxy=proxy)

        last_run = demisto.getLastRun()
        if not last_run:
            demisto.debug(f'first run {last_run=}')
            last_fetch = first_fetch_time
        else:
            last_fetch = last_run.get('lastRun')
            demisto.debug(f"Isn't the first run {last_fetch}")
        next_page_token = last_run.get('next_page_token')

        if command == 'test-module':
            return_results(test_module(client, last_fetch, max_fetch))
        elif command in ('fetch-events', 'orca-security-get-events'):
            alerts, next_page_token = get_alerts(client, max_fetch, last_fetch, next_page_token)

            if command == 'fetch-events':
                should_push_events = True

            else:  # command == 'orca-security-get-events'
                should_push_events = argToBoolean(demisto.args().get('should_push_events', False))
                return_results(CommandResults(
                    readable_output=tableToMarkdown(t=alerts,
                                                    name=f'{VENDOR} - {PRODUCT} events',
                                                    removeNull=True),
                    raw_response=alerts
                ))

            if should_push_events:
                alerts = add_time_key_to_alerts(alerts)
                demisto.debug(f'before send_events_to_xsiam {VENDOR=} {PRODUCT=} {alerts=}')
                send_events_to_xsiam(alerts, VENDOR, PRODUCT)
                demisto.debug(f'after send_events_to_xsiam {VENDOR=} {PRODUCT=} {alerts=}')

            current_last_run = {
                'next_page_token': next_page_token
            }
            if next_page_token:
                current_last_run['lastRun'] = last_fetch
            else:
                last_updated = arg_to_datetime(arg=alerts[-1].get('state', {}).get('created_at')) if alerts else None
                current_last_run['lastRun'] = last_updated.strftime(DATE_FORMAT) if last_updated else last_fetch

            demisto.setLastRun(current_last_run)
            demisto.debug(f'{current_last_run=}')

        else:
            raise NotImplementedError('This command is not implemented yet.')

    # Log exceptions and return errors
    except Exception as e:
        return_error(f'Failed to execute {demisto.command()} command.\nError:\n{str(e)}')


''' ENTRY POINT '''

if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
