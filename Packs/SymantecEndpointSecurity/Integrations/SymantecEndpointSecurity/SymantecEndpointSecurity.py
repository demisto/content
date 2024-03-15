import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

import json
import urllib3
import dateparser
from datetime import datetime, timezone, timedelta
from typing import Any

# Disable insecure warnings
urllib3.disable_warnings()

''' CONSTANTS '''

DATE_FORMAT = '%Y-%m-%dT%H:%M:%SZ'
MAX_INCIDENTS_TO_FETCH = 100
DEFAULT_INDICATORS_THRESHOLD = 65
DATE_PARSER_SETTINGS = {'RETURN_AS_TIMEZONE_AWARE': True, 'TIMEZONE': 'UTC'}
OUTPUT_PREFIX = 'Symantec'

''' CLIENT CLASS '''


class Client(BaseClient):
    """Client class to interact with the service API

    This Client implements API calls, and does not contain any Demisto logic.
    Should only do requests and return data.
    It inherits from BaseClient defined in CommonServer Python.
    Most calls use _http_request() that handles proxy, SSL verification, etc.
    For this HelloWorld implementation, no special attributes defined
    """

    def __init__(self,
                 oauth_token: str,
                 base_url,
                 verify=True,
                 proxy=False,
                 ok_codes=(),
                 headers=None,
                 auth=None,
                 timeout=BaseClient.REQUESTS_TIMEOUT,
                 ) -> None:
        super().__init__(base_url=base_url, verify=verify, proxy=proxy, ok_codes=ok_codes,
                         headers=headers, auth=auth, timeout=timeout)
        self._session_token = None
        self._oauth_token = oauth_token

    def authenticate(self) -> bool:
        headers = {
            "accept": "application/json",
            "authorization": self._oauth_token,
            "content-type": "application/x-www-form-urlencoded"
        }
        resp = self._http_request('POST', '/v1/oauth2/tokens', headers=headers)
        self._session_token = resp.get('access_token')
        return self._session_token is not None

    def get_edr_incidents(self, start_time: str, max_fetch: int, include_events: bool = False, offset: int = 0):
        now = datetime.utcnow()
        json_data = {
            'next': offset,
            'limit': max_fetch,
            'include_events': include_events,
            'query': 'state_id: [0 TO 3]',
            'start_date': start_time,
            'end_date': now.strftime(DATE_FORMAT)
        }
        headers = {
            "authorization": f'Bearer {self._session_token}',
            "accept": "application/json"
        }
        response = self._http_request('POST', url_suffix='/v1/incidents', json_data=json_data, headers=headers)
        return response


''' HELPER FUNCTIONS '''


def ensure_max_age(value: datetime, age: timedelta = timedelta(days=29, hours=23, minutes=59)) -> datetime:
    """The SES Incident API does only support fetching incidents up to 30 days ago
    Ensures that the given datetime is on older than 30 days
    Args:
        value (datetime): The datetime to ensure the age

    Returns:
        datetime: the given datetime or a datetime that is no older than 30 days
    """
    min_date = (datetime.now(tz=timezone.utc) - age)

    if value.tzinfo is None:
        value.replace(tzinfo=timezone.utc)

    return max(value, min_date)


def icdm_fetch_incidents(client: Client, last_fetch_date: datetime):
    last_fetch_str = last_fetch_date.strftime(DATE_FORMAT)
    response = client.get_edr_incidents(start_time=last_fetch_str, max_fetch=100)
    incidents_raw = response['incidents']
    while 'next' in response:
        response = client.get_edr_incidents(start_time=last_fetch_str, max_fetch=100, offset=response['next'])
        incidents_raw += response['incidents']

    incidents_raw.sort(key=lambda x: dateparser.parse(x.get('created', '1970-01-01T00:00:00.000+00:00')))
    return incidents_raw


''' COMMAND FUNCTIONS '''


def test_module(client: Client) -> str:
    """Tests API connectivity and authentication'

    Returning 'ok' indicates that the integration works like it is supposed to.
    Connection to the service is successful.
    Raises exceptions if something goes wrong.

    Args:
        client (Client): client to use
        oauth (str): oauth access token to use for authentication

    Raises:
        e: _description_

    Returns:
        str: 'ok' if test passed, anything else will fail the test.
    """
    message: str = ''
    try:
        if client.authenticate():
            message = 'ok'
        else:
            message = 'Authentication Error: make sure API Key is correctly set'
    except Exception as e:
        raise e

    return message


def fetch_incidents_command(client: Client, max_results: int, last_run: datetime) -> tuple[dict[str, float], list[dict]]:
    """
    This function retrieves new alerts every interval (default is 1 minute).
    It has to implement the logic of making sure that incidents are fetched only onces and no incidents are missed.
    By default it's invoked by XSOAR every minute. It will use last_run to save the timestamp of the last incident it
    processed. If last_run is not provided, it should use the integration parameter first_fetch_time to determine when
    to start fetching the first time.

    Args:
        client (Client): Symantec Endpoint Security client to use.
        max_results (int): Maximum numbers of incidents per fetch.
        last_run (dict): A dict with a key containing the latest incident created time we got from last fetch.
        first_fetch_time(int): If last_run is None (first time we are fetching), it contains the timestamp in
            milliseconds on when to start fetching incidents.
    Returns:
        dict: Next run dictionary containing the timestamp that will be used in ``last_run`` on the next fetch.
        list: list of incidents that will be created in XSOAR.
    """

    incidents: list[Dict[str, Any]] = []
    latest_created_time = datetime.min.replace(tzinfo=timezone.utc)

    incidents_raw = icdm_fetch_incidents(client, last_run)

    for incident in incidents_raw:
        if len(incidents) >= max_results:
            break

        # we are only interested in "INCIDENT_CREATED" (type_id 8075) events
        if incident.get('type_id', 0) != 8075:
            demisto.debug('skipping because type: {}'.format(incident['type_id']))
            continue

        incident_created_time = dateparser.parse(incident.get('created', ''))
        if not incident_created_time:
            incident_created_time = datetime.now(tz=timezone.utc)

        # to prevent duplicates, we are only adding incidents with creation_time > last fetched incident
        if last_run and incident_created_time <= last_run:
            demisto.debug(f'skipping because {incident_created_time} is less than {last_run}')
            continue

        # If no name is present it will throw an exception
        incident_name = f'ICDM EDR Incident {incident["ref_incident_uid"]}'

        incident_result = {
            'name': incident_name,
            'occurred': incident_created_time.strftime(DATE_FORMAT),
            'rawJSON': json.dumps(incident),
            'dbotMirrorId': incident['incident_uid']
        }

        incidents.append(incident_result)

        if incident_created_time > latest_created_time:
            latest_created_time = incident_created_time

    # Save the next_run as a dict with the last_fetch key to be stored
    next_run = {'last_fetch': max(latest_created_time, last_run).timestamp()}

    return next_run, incidents


def icdm_fetch_incidents_command(client: Client, max_results: int, last_fetch_date: datetime) -> CommandResults:
    incidents_raw = icdm_fetch_incidents(client, last_fetch_date)

    result = CommandResults(outputs_prefix=f'{OUTPUT_PREFIX}.Incidents',
                            outputs_key_field='incident_uid',
                            outputs=incidents_raw,
                            readable_output=tableToMarkdown('Symantec Endpoint Security EDR Incidents', t=incidents_raw,
                                                            headers=['ref_incident_uid', 'type', 'conclusion', 'created', 'modified'],  # noqa: E501
                                                            removeNull=True)
                            )
    return result


''' MAIN FUNCTION '''


def main() -> None:  # pragma: no cover
    """
    main function, parses params and runs command functions
    """

    params = demisto.params()
    command = demisto.command()

    oauth = params.get('credentials', {}).get('password')
    base_url = params.get('url')
    verify_certificate = not params.get('insecure', False)
    proxy = params.get('proxy', False)

    demisto.debug(f'Command being called is {command}')
    try:
        client = Client(
            oauth_token=oauth,
            base_url=base_url,
            verify=verify_certificate,
            proxy=proxy)

        if demisto.command() == 'test-module':
            # This is the call made when pressing the integration Test button.
            result = test_module(client)
            return_results(result)

        elif command == 'fetch-incidents':
            max_results = arg_to_number(arg=params.get('max_fetch', 100))
            if not max_results or max_results > MAX_INCIDENTS_TO_FETCH:
                max_results = MAX_INCIDENTS_TO_FETCH

            last_fetch = arg_to_datetime(arg=demisto.getLastRun().get('last_fetch'), settings=DATE_PARSER_SETTINGS)
            if not last_fetch:
                last_fetch = arg_to_datetime(arg=params.get('first_fetch'), required=True, settings=DATE_PARSER_SETTINGS)

            assert last_fetch is not None  # The line above should ensure, that we have at least a first fetch date

            client.authenticate()

            next_run, incidents = fetch_incidents_command(client=client, max_results=max_results,
                                                          last_run=ensure_max_age(last_fetch))

            demisto.setLastRun(next_run)
            demisto.incidents(incidents)
        else:
            raise NotImplementedError(f'Command {command} is not implemented')

    # Log exceptions and return errors
    except Exception as e:
        return_error(f'Failed to execute {command} command.\nError:\n{str(e)}')


''' ENTRY POINT '''

if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
