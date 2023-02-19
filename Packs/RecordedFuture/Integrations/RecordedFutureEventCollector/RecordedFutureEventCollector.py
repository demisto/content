
from CommonServerPython import *
import json
import urllib3
from typing import Any

# Disable insecure warnings
urllib3.disable_warnings()

''' CONSTANTS '''
BASE_URL = 'https://api.recordedfuture.com/v2'
STATUS_TO_RETRY = [500, 501, 502, 503, 504]
DATE_FORMAT = '%Y-%m-%dT%H:%M:%SZ'
VENDOR = 'Recorded Future'
PRODUCT = 'Intelligence Cloud'

''' CLIENT CLASS '''


class Client(BaseClient):
    def whoami(self) -> dict[str, Any]:

        return self._http_request(
            method='get',
            url_suffix='/info/whoami',
            timeout=60,
        )

    def _call(self, url_suffix, **kwargs):

        json_data = {
            'demisto_command': demisto.command(),
            'demisto_args': demisto.args(),
        }

        request_kwargs = {
            'method': 'post',
            'url_suffix': url_suffix,
            'json_data': json_data,
            'timeout': 90,
            'retries': 3,
            'status_list_to_retry': STATUS_TO_RETRY
        }

        request_kwargs.update(kwargs)

        try:
            response = self._http_request(**request_kwargs)

            if isinstance(response, dict) and response.get('return_error'):
                # This will raise the Exception or call "demisto.results()" for the error and sys.exit(0).
                return_error(**response['return_error'])

        except DemistoException as err:
            if '404' in str(err):
                return CommandResults(
                    outputs_prefix='',
                    outputs=dict(),
                    raw_response=dict(),
                    readable_output='No results found.',
                    outputs_key_field='',
                )
            else:
                raise err

        return response

    def fetch_incidents(self, last_run) -> dict[str, Any]:
        """Fetch incidents."""
        return self._call(
            url_suffix=f'/v2/alert/fetch_incidents',
            json_data={
                'demisto_last_run': last_run
            },
            timeout=120
        )

    def get_alerts(self) -> dict[str, Any]:
        """Get alerts."""
        return self._call(url_suffix='/v2/alert/search')


def test_module(client: Client):
    """
    Tests API connectivity and authentication'
    When 'ok' is returned it indicates the integration works like it is supposed to and connection to the service is
    successful.
    Raises exceptions if something goes wrong.

    Args:
        client (Client): HelloWorld client to use.
        params (dict): Integration parameters.
        first_fetch_time (int): The first fetch time as configured in the integration params.

    Returns:
        str: 'ok' if test passed, anything else will raise an exception and will fail the test.
    """

    try:
        client.whoami()
        return_results('ok')
    except Exception as err:
        message = str(err)
        try:
            error = json.loads(str(err).split('\n')[1])
            if 'fail' in error.get('result', dict()).get('status', ''):
                message = error.get('result', dict())['message']
        except Exception:
            message = (
                'Unknown error. Please verify that the API'
                f' URL and Token are correctly configured. RAW Error: {err}'
            )
        raise DemistoException(f'Failed due to - {message}')


def get_events(client) -> tuple[dict[str, any], CommandResults]:
    response = client.get_alerts()
    hr = tableToMarkdown(name='Test Event', t=response)
    return response, CommandResults(readable_output=hr)


def fetch_events(client: Client, last_run: str):
    """
    Args:
        client (Client): HelloWorld client to use.
        last_run (dict): A dict with a key containing the latest event created time we got from last fetch.
        first_fetch_time(int): If last_run is None (first time we are fetching), it contains the timestamp in
            milliseconds on when to start fetching events.
        alert_status (str): status of the alert to search for. Options are: 'ACTIVE' or 'CLOSED'.
    Returns:
        dict: Next run dictionary containing the timestamp that will be used in ``last_run`` on the next fetch.
        list: List of events that will be created in XSIAM.
    """
    response = client.fetch_incidents(last_run)

    if isinstance(response, CommandResults):
        # 404 case.
        return

    if incidents := response.get('incidents'):
        demisto.setLastRun(response['demisto_last_run'])
        return incidents


''' MAIN FUNCTION '''


def main() -> None:
    """
    main function, parses params and runs command functions
    """

    params = demisto.params()
    args = demisto.args()
    command = demisto.command()
    api_key = params.get('credentials', {}).get('password')
    verify_certificate = not params.get('insecure', False)
    proxy = params.get('proxy', False)

    demisto.debug(f'Command being called is {command}')
    try:
        headers = {
            'X-RFToken': api_key
        }
        client = Client(
            base_url=BASE_URL,
            headers=headers,
            verify=verify_certificate,
            proxy=proxy
        )

        if command == 'test-module':
            # This is the call made when pressing the integration Test button.
            result = test_module(client)
            return_results(result)

        elif command in ('recorded-future-get-events', 'fetch-events'):
            if command == 'recorded-future-get-events':
                should_push_events = argToBoolean(args.pop('should_push_events'))
                events, results = get_events(client)
                return_results(results)

            else:  # command == 'fetch-events':
                should_push_events = True
                last_run = demisto.getLastRun().get('last_run') or arg_to_datetime(params.get('first_fetch', '3 days'))
                events = fetch_events(
                    client=client,
                    last_run=last_run
                )

            if should_push_events:
                send_events_to_xsiam(
                    events,
                    vendor=VENDOR,
                    product=PRODUCT
                )

    # Log exceptions and return errors
    except Exception as e:
        return_error(f'Failed to execute {command} command.\nError:\n{str(e)}')


''' ENTRY POINT '''

if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
