"""Base Integration for Cortex XSOAR (aka Demisto)

This is an empty Integration with some basic structure according
to the code conventions.

MAKE SURE YOU REVIEW/REPLACE ALL THE COMMENTS MARKED AS "TODO"

Developer Documentation: https://xsoar.pan.dev/docs/welcome
Code Conventions: https://xsoar.pan.dev/docs/integrations/code-conventions
Linting: https://xsoar.pan.dev/docs/integrations/linting

This is an empty structure file. Check an example at;
https://github.com/demisto/content/blob/master/Packs/HelloWorld/Integrations/HelloWorld/HelloWorld.py

"""

import demistomock as demisto
from CommonServerPython import *  # noqa # pylint: disable=unused-wildcard-import
from CommonServerUserPython import *  # noqa

import urllib3
from typing import Dict

# Disable insecure warnings
urllib3.disable_warnings()

''' CONSTANTS '''

DATE_FORMAT = '%Y-%m-%dT%H:%M:%SZ'  # ISO8601 format with UTC, default in XSOAR
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
            'dsl_filter': "{\n\"filter\":\n[\n{\n\"field\": \"state.last_updated\",\n\"range\": {\n\"gt\": "
                          "\"" + last_fetch + "\"\n}\n}\n],\n"
                                              "\"sort\":\n[\n{\"field\":\"state.last_updated\",\n\"order\":\"asc\"\n}\n]}"
        }
        if next_page_token:
            params['next_page_token'] = next_page_token
        demisto.info(f'in get_alerts request {params=}')
        return self._http_request(method='GET', url_suffix='/query/alerts', params=params)


''' COMMAND FUNCTIONS '''


def get_alerts(client: Client, max_fetch: int, last_fetch: str, next_page_token: str = None) -> tuple:
    """ Retrieve information about alerts.
    Args:
        client: client - An Orca client.
        max_fetch: int - The maximum number of events per fetch
        last_fetch: int - the timeand date of the last fetch alert
        next_page_token: str - The token to the next page.
    Returns:
        - list of alerts
        - next_page_token if exist
    """
    response = client.get_alerts_request(max_fetch, last_fetch, next_page_token)
    next_page_token = response.get('next_page_token')
    alerts = response.get('data')
    return alerts, next_page_token


''' MAIN FUNCTION '''


def main() -> None:
    """main function, parses params and runs command functions

    :return:
    :rtype:
    """
    command = demisto.command()
    api_token = demisto.params().get('credentials', {}).get('password')
    server_url = demisto.params().get('server_url', 'https://app.eu.orcasecurity.io/api')
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
    first_fetch_time = first_fetch_time.strftime("%Y-%m-%dT%H:%M:%S") if first_fetch_time else ''
    demisto.info(f'{first_fetch_time=}')
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
        if last_run == {}:
            demisto.info(f'first run {last_run=}')
            last_fetch = first_fetch_time
        else:
            demisto.info('not the first run')
            last_fetch = last_run.get('lastRun')
        next_page_token = last_run.get('next_page_token')
        demisto.info(f'before get alerts {last_fetch=} {next_page_token=}')
        alerts, next_page_token = get_alerts(client, max_fetch, last_fetch, next_page_token)
        num_alerts = len(alerts)
        demisto.info(f'after get alerts {next_page_token=} , {num_alerts=}\n {alerts=}')

        if command == 'test-module':
            return_results('ok')
        elif command in ('fetch-events', 'orca-security-get-events'):
            if command == 'fetch-events':
                should_push_events = True
                demisto.info('in fetch events command')
            else:  # command == 'orca-security-get-events'
                should_push_events = argToBoolean(demisto.args().get('should_push_events', False))
                return_results(CommandResults(
                    readable_output=tableToMarkdown(t=alerts,
                                                    name=f'{VENDOR} - {PRODUCT} events',
                                                    removeNull=True),
                    raw_response=alerts
                ))
            if should_push_events:
                current_last_run = {
                    'next_page_token': next_page_token,
                    'lastRun': alerts[num_alerts - 1].get('state', {}).get('last_updated')[:-6] if num_alerts > 0
                    else last_fetch
                }
                demisto.setLastRun(current_last_run)
                demisto.info(f'{current_last_run=}')
                send_events_to_xsiam(alerts, VENDOR, PRODUCT)

    # Log exceptions and return errors
    except Exception as e:
        return_error(f'Failed to execute {demisto.command()} command.\nError:\n{str(e)}')


''' ENTRY POINT '''

if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
