
import demistomock as demisto
from CommonServerPython import *  # noqa # pylint: disable=unused-wildcard-import
from CommonServerUserPython import *  # noqa

import urllib3
from typing import Dict

# Disable insecure warnings
urllib3.disable_warnings()

''' CONSTANTS '''

DATE_FORMAT = '%Y-%m-%dT%H:%M:%S'  # ISO8601 format with UTC, default in XSOAR
VENDOR = 'orca'
PRODUCT = 'security'

''' CLIENT CLASS '''


class Client(BaseClient):

    def __init__(self, server_url: str, headers: Dict, proxy: bool = False, verify: bool = False):
        super().__init__(base_url=server_url, verify=verify, proxy=proxy, headers=headers)

    def get_alerts_request(self, max_fetch: int, last_fetch: str, next_page_token: Optional[str]) -> Dict:
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
            'dsl_filter': "{\n\"filter\":\n[\n{\n\"field\": \"state.created_at\",\n\"range\": {\n\"gte\": "
                          "\"" + last_fetch + "\"\n}\n}\n],\n"
                                              "\"sort\":\n[\n{\"field\":\"state.created_at\",\n\"order\":\"asc\"\n}\n]}"
        }
        if next_page_token:
            params['next_page_token'] = next_page_token
        demisto.info(f'In get_alerts request {params=}')
        return self._http_request(method='GET', url_suffix='/query/alerts', params=params)


''' COMMAND FUNCTIONS '''


def test_module(client: Client, last_fetch: str) -> str:
    """ Test the connection to Orca Security.
    Args:
        client: client - An Orca client.
        last_fetch: int - The time and date of the last fetch alert
    Returns:
        'ok' if the connection was successful, else throws exception.
    """
    try:
        client.get_alerts_request(1, last_fetch, None)
        return 'ok'
    except DemistoException as e:
        raise Exception(e.message)


def get_alerts(client: Client, max_fetch: int, last_fetch: str, last_alert_id: str, next_page_token: str = None) -> tuple:
    """ Retrieve information about alerts.
    Args:
        client: client - An Orca client.
        max_fetch: int - The maximum number of events per fetch
        last_fetch: int - The time and date of the last fetch alert
        last_alert_id: str - The alert_id of the last fetched alert
        next_page_token: str - The token to the next page.
    Returns:
        - list of alerts
        - next_page_token if exist
    """
    response = client.get_alerts_request(max_fetch, last_fetch, next_page_token)
    next_page_token = response.get('next_page_token')
    alerts = response.get('data', [])
    demisto.debug(f'Get Alerts Response {next_page_token=} , {len(alerts)=}\n {alerts=}')
    if alerts:
        first_alert_id = alerts[0].get('state', {}).get('alert_id')
        if first_alert_id == last_alert_id:
            demisto.debug(f'Removing alert duplication {first_alert_id=}')
            alerts = alerts[1:]
    return alerts, next_page_token


''' MAIN FUNCTION '''


def main() -> None:

    command = demisto.command()
    api_token = demisto.params().get('credentials', {}).get('password')
    server_url = demisto.params().get('server_url')
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

        headers: Dict = {
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
        last_alert_id = last_run.get('last_alert_id', '-1')

        if command == 'test-module':
            return_results(test_module(client, last_fetch))
        elif command in ('fetch-events', 'orca-security-get-events'):
            alerts, next_page_token = get_alerts(client, max_fetch, last_fetch, last_alert_id, next_page_token)

            if command == 'fetch-events':
                should_push_events = True
                current_last_run = {
                    'next_page_token': next_page_token
                }
                if next_page_token:
                    current_last_run['lastRun'] = last_fetch
                    current_last_run['last_alert_id'] = '-1'
                else:
                    last_updated = arg_to_datetime(arg=alerts[-1].get('state', {}).get('created_at')) if alerts else None
                    current_last_run['lastRun'] = last_updated.strftime(DATE_FORMAT) if last_updated else last_fetch
                    current_last_run['last_alert_id'] = alerts[-1].get('state', {}).get('alert_id') if alerts else last_alert_id
                demisto.setLastRun(current_last_run)
                demisto.debug(f'{current_last_run=}')

            else:  # command == 'orca-security-get-events'
                should_push_events = argToBoolean(demisto.args().get('should_push_events', False))
                return_results(CommandResults(
                    readable_output=tableToMarkdown(t=alerts,
                                                    name=f'{VENDOR} - {PRODUCT} events',
                                                    removeNull=True),
                    raw_response=alerts
                ))

            if should_push_events:
                send_events_to_xsiam(alerts, VENDOR, PRODUCT)

        else:
            raise NotImplementedError('This command is not implemented yet.')

    # Log exceptions and return errors
    except Exception as e:
        return_error(f'Failed to execute {demisto.command()} command.\nError:\n{str(e)}')


''' ENTRY POINT '''

if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
