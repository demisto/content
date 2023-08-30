import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
import json
import urllib3
import dateparser

# Disable insecure warnings
urllib3.disable_warnings()

''' CONSTANTS '''

PARAMS = demisto.params()
SERVICE_TO_URL_MAP = {
    'takedown': PARAMS['takedown_url'],
    'submission': PARAMS['submission_url'],
}
API_MAX_FETCH = 100_000

''' CLIENT CLASS '''


class Client(BaseClient):
    def _http_request(self, method, service, url_suffix='', headers=None, json_data=None, **kwargs):
        return super()._http_request(
            method, full_url=urljoin(PARAMS[service], url_suffix),
            headers=headers, json_data=json_data, **kwargs)

    def test_module(self):
        return 'ok'

    def fetch_incidents(self, headers: dict):
        return self._http_request(
            'GET', 'takedown', 'attacks/', headers
        )


''' HELPER FUNCTIONS '''


''' COMMAND FUNCTIONS '''


def test_module(client: Client) -> str:
    """
    Tests API connectivity and authentication'
    When 'ok' is returned it indicates the integration works like it is supposed to and connection to the service is
    successful.
    Raises exceptions if something goes wrong.

    Args:
        client (Client): HelloWorld client to use.
        params (Dict): Integration parameters.
        first_fetch_time (int): The first fetch time as configured in the integration params.

    Returns:
        str: 'ok' if test passed, anything else will raise an exception and will fail the test.
    """

    # INTEGRATION DEVELOPER TIP
    # Client class should raise the exceptions, but if the test fails
    # the exception text is printed to the Cortex XSOAR UI.
    # If you have some specific errors you want to capture (i.e. auth failure)
    # you should catch the exception here and return a string with a more
    # readable output (for example return 'Authentication Error, API Key
    # invalid').
    # Cortex XSOAR will print everything you return different than 'ok' as
    # an error
    try:
        if PARAMS.get('isFetch'):  # Tests fetch incident:
            if not dateparser.parse(PARAMS['first_fetch']):
                raise ValueError(f'{PARAMS["first_fetch"]!r} is not a valid time.')
            else:
                return 'ok'

    except DemistoException as e:
        if 'Forbidden' in str(e):
            return 'Authorization Error: make sure API Key is correctly set'
        else:
            raise e

    return 'ok'


def fetch_incidents(client: Client) -> list[dict[str, str]]:  # LIVE TESTS NEEDED
    """
    This function retrieves new alerts every interval (default is 1 minute).
    It has to implement the logic of making sure that incidents are fetched only onces and no incidents are missed.
    By default it's invoked by XSOAR every minute. It will use last_run to save the timestamp of the last incident it
    processed. If last_run is not provided, it should use the integration parameter first_fetch_time to determine when
    to start fetching the first time.

    Args:
        client (Client): HelloWorld client to use.
        max_results (int): Maximum numbers of incidents per fetch.
        last_run (dict): A dict with a key containing the latest incident created time we got from last fetch.
        first_fetch_time(int): If last_run is None (first time we are fetching), it contains the timestamp in
            milliseconds on when to start fetching incidents.
        alert_status (str): status of the alert to search for. Options are: 'ACTIVE' or 'CLOSED'.
        min_severity (str): minimum severity of the alert to search for. Options are: "Low", "Medium", "High" and
            "Critical".
        alert_type (str): type of alerts to search for. There is no list of predefined types.
    Returns:
        dict: Next run dictionary containing the timestamp that will be used in ``last_run`` on the next fetch.
        list: List of incidents that will be created in XSOAR.
    """
    # demisto.getLastRun and demisto.setLastRun hold takedown IDs

    def to_xsoar_incident(incident: dict) -> dict:
        return {
            'name': f'Submission ID: {incident["id"]!r}',
            'occurred': arg_to_datetime(incident['date_submitted']).isoformat(),
            'rawJSON': json.dumps(incident),
        }

    headers = {
        'max_results': min(
            arg_to_number(PARAMS['max_fetch']) or 10,
            API_MAX_FETCH
        ),
        'sort': 'id',
        'region': PARAMS['region']
    }

    if last_id := demisto.getLastRun():
        headers['id_after'] = last_id
    else:
        headers['date_from'] = str(
            arg_to_datetime(
                PARAMS['first_fetch'],
                required=True
            ).replace(tzinfo=None))

    incidents = client.fetch_incidents(headers) or [{'id': last_id}]

    demisto.setLastRun(incidents[-1]['id'])

    # the first incident from the API call should be a duplicate of last_id
    if incidents[0]['id'] == last_id:
        incidents.pop(0)

    return list(map(to_xsoar_incident, incidents))


''' MAIN FUNCTION '''


def main() -> None:

    args = demisto.args()
    command = demisto.command()

    client = Client(
        ...
    )

    demisto.debug(f'Command being called is {command}')
    try:

        match command:
            case 'test-module':
                return_results(test_module(client))
            case 'fetch-incidents':
                demisto.incidents(fetch_incidents(client))
            case _:
                raise NotImplementedError(f'{command!r} is not a Netcraft command.')

    except Exception as e:
        return_error(f'Failed to execute {command} command.\nError:\n{e}')


''' ENTRY POINT '''

if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
