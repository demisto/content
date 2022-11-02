import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

''' IMPORTS '''

import json
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional, Tuple, Union, cast

import dateparser
import urllib3

# Disable insecure warnings
urllib3.disable_warnings()

''' CONSTANTS '''

"""Date format supported by XSOAR incidents"""
DATE_FORMAT_ISO = '%Y-%m-%dT%H:%M:%SZ'

"""Date format from the API response"""
DATE_FORMAT_UTC = '%Y-%m-%dT%H:%M:%S.%f+0000'

"""URL to the API, same for everyone (uses a client ID)"""
API_URL = "https://api.qis.io/v1/alerts/"


''' CLIENT CLASS '''


class Client(BaseClient):

    """Client class to interact with the service API

    This Client implements API calls, and does not contain any Demisto logic.
    Should only do requests and return data.
    It inherits from BaseClient defined in CommonServer Python.
    Most calls use _http_request() that handles proxy, SSL verification, etc.
    For this QuadrantSIEM implementation, no special attributes defined
    """

    def get_incidents_timespan(self, category: str, start: str, end: str) -> Dict[str, Any]:
        """
        Gets alerts in the specified time range (start -> end).
        Used by fetch-incidents.

        Args:
            category (str): which category to pull alerts from (reportable, benign, investigated, resolved, escalated, noncritical, critical).
            start (str): the latest date time in ISO format for the time range.
            end (str): the earliest date time in ISO format for the tiem range.

        Returns:
            dict: returned data from API. dict containing keys "total" (int), "category" (str), "timespan" (List[str]), and "alerts"(List[Dict[str,Any]]).
        """

        return self._http_request(
            method='GET',
            url_suffix='/timespan',
            params={
                'start': start,
                'end': end,
                'category': category,
                'stream': 'false'
            }
        )

    def get_incidents_all(self, category: str) -> Dict[str, Any]:
        """
        NOT USED. HERE AS A FUNCTION OF THE API. CAN BE USED FOR FUTURE IMPLEMENTATIONS.

        Gets all alerts.

        Args:
            category (str): which category to pull alerts from (reportable, benign, investigated, resolved, escalated, noncritical, critical).

        Returns:
            dict: returned data from API. dict containing keys "total" (int), "category" (str), "timespan" (List[str]), and "alerts"(List[Dict[str,Any]]).
        """

        return self._http_request(
            method='GET',
            url_suffix='/all',
            params={
                'category': category,
                'stream': 'false'
            }
        )

    def get_incidents_latest(self, category: str) -> Dict[str, Any]:
        """
        Gets incidents within a 5 minute window.
        Used by test_module.

        Args:
            category (str): which category to pull alerts from (reportable, benign, investigated, resolved, escalated, noncritical, critical).

        Returns:
            dict: returned data from API. dict containing keys "total" (int), "category" (str), "timespan" (List[str]), and "alerts"(List[Dict[str,Any]]).
        """

        return self._http_request(
            method='GET',
            url_suffix='/latest',
            params={
                'category': category,
                'stream': 'false'
            }
        )


''' HELPER FUNCTIONS '''

# None currently defined. Left if needed for future implementation.

''' COMMAND FUNCTIONS '''


def test_module(client: Client, params: Dict[str, Any], first_fetch_time: int) -> str:
    """
    Tests API connectivity and authentication'
    When 'ok' is returned it indicates the integration works like it is supposed to and connection to the service is
    successful.
    Raises exceptions if something goes wrong.

    Args:
        client (Client): QuadrantSIEM client to use.
        params (Dict): integration parameters.
        first_fetch_time (int): the first fetch time as configured in the integration params.

    Returns:
        str: 'ok' if test passed, anything else will raise an exception and will fail the test.
    """

    try:
        if params.get('isFetch'):
            # Tests fetch incident:
            fetch_incidents(
                client=client,
                last_run={},
                first_fetch=first_fetch_time,
                category=params.get('category', 'escalated'),
                look_back=params.get('lookBack', 1440)
            )
        else:
            # Call /latest API to get last 5 minutes of alerts
            client.get_incidents_latest(category=params.get('category'))

    except DemistoException as e:
        if 'Forbidden' in str(e):
            return 'Authorization Error: make sure Client ID and API Key is correctly set'
        else:
            raise e

    return 'ok'


def fetch_incidents(client: Client, last_run: Dict[str, any],
                    first_fetch: Optional[int], category: str, look_back: int
                    ) -> Tuple[Dict[str, int], List[dict]]:
    """
    This function retrieves new alerts every interval (default is 1 minute).
    It has to implement the logic of making sure that incidents are fetched only onces and no incidents are missed.
    By default it's invoked by XSOAR every minute. It will use last_run to save the timestamp of the last incident it
    processed. If last_run is not provided, it should use the integration parameter first_fetch_time to determine when
    to start fetching the first time.

    Args:
        client (Client): QuadrantSIEM client to use.
        last_run (dict): A dict with a key containing the latest incident created time we got from last fetch.
        first_fetch (int): If last_run is None (first time we are fetching), it contains the timestamp in
            milliseconds on when to start fetching incidents.
        category (str): which category to pull alerts from (reportable, benign, investigated, resolved, escalated, noncritical, critical).
        look_back (str): how far back in minutes to pull alerts in the pull timeframe (look_back -> current time).
    Returns:
        dict: Next run dictionary containing the alert ids that were pulled in the timeframe (look_back -> current time) and
            that will be used in ``last_run`` on the next fetch to compare with the next fetch alert ids to find new alerts.
        list: List of incidents that will be created in XSOAR.
    """

    # Get the last fetch alert ids, if exists
    # last_run is a dict with a single key, called last_fetch
    last_fetch = last_run.get('last_fetch', [])

    # Initialize an empty list of incidents to return
    # Each incident is a dict with a string as a key
    incidents: List[Dict[str, Any]] = []

    # Initalize an empty list of alert ids to return for next_run
    # Will be populated with this fetch's alert ids
    new_last_fetch: List[str] = []

    # If last_fetch is an empty list (no previous run), use first_fetch
    # instead of look_back
    if not last_fetch:
        start = first_fetch
    else:
        # Calculating x minutes ago, as defined by look_back
        cur_time = datetime.utcnow()
        n_days_ago = timedelta(minutes=look_back)
        start = cur_time - n_days_ago

    # Creating timeframe, ISO format, for API call
    # start (x minutes ago as defined by look_back) -> end (current time)
    start = start.strftime(DATE_FORMAT_ISO)
    end = get_current_time()

    demisto.debug("Pulling alerts in timeframe " + str(start) + " to " + str(end))

    # Call the timespan API
    response = client.get_incidents_timespan(
        category=category,
        start=start,
        end=end
    )

    # Get the alerts from the response
    alerts = response['alerts']

    demisto.debug("Total alerts returned from API: " + str(response['total']))

    demisto.info("Creating incidents")

    # Go through each returned alert, add the alert id to new_last_fetch,
    # then check if the alert id was seen in the last fetch, last_fetch.
    # If it was not in the last fetch, create an incident entry and add
    # to the incidents list to be created.
    for alert in alerts:

        # Add alert id
        new_last_fetch.append(alert['snort_id'])

        # If this alert id was not seen in the last fetch, create an incident
        if alert['snort_id'] not in last_fetch:
            # Name of the incident
            incident_name = alert['alert']['signature']

            # Occurance of incident
            # Translate to ISO format
            incident_created = alert['timestamp']
            incident_created = datetime.strptime(incident_created, DATE_FORMAT_UTC)
            incident_created = str(incident_created.strftime(DATE_FORMAT_ISO))

            # Create incident entry
            incident_entry = {
                'name': incident_name,
                'occurred': incident_created,
                'rawJSON': json.dumps(alert),
            }

            # Add incident entry to incidents to be created
            incidents.append(incident_entry)

    demisto.debug("Alert IDs from last fetch: " + str(last_fetch))
    demisto.debug("Alert IDs from current fetch: " + str(new_last_fetch))
    demisto.info("Finished creating incidents")
    demisto.debug("Total new alerts to be created: " + str(len(incidents)))

    # Save the next_run as a dict with the last_fetch key to be stored
    next_run = {'last_fetch': new_last_fetch}

    demisto.info("Returning from fetch_incidents")

    return next_run, incidents


''' MAIN FUNCTION '''


def main() -> None:
    """
    main function, parses params and runs command functions

    """

    # Get parameters what what command was called
    params = demisto.params()
    command = demisto.command()

    # Commented out as no commands that uses args
    # Left in if needed for future implementation
    # args = demisto.args()

    # Get data from parameters
    api_key = params.get('apikey')
    client_id = params.get('clientID')
    category = params.get('category', 'escalated')
    first_fetch = params.get('first_fetch', '1 day')

    # Get look_back in minutes and make sure what was provided is an int
    look_back = params.get('lookBack', 1440)
    try:
        look_back = int(look_back)
    except ValueError:
        return_error("Look back was not an integer: " + str(ValueError))

    # Combine the base URL with the client ID
    base_url = API_URL + client_id

    # if your Client class inherits from BaseClient, SSL verification is
    # handled out of the box by it, just pass ``verify_certificate`` to
    # the Client constructor
    verify_certificate = not params.get('insecure', False)

    # How much time before the first fetch to retrieve incidents
    first_fetch_time = arg_to_datetime(
        arg=first_fetch,
        required=True
    )

    # if your Client class inherits from BaseClient, system proxy is handled
    # out of the box by it, just pass ``proxy`` to the Client constructor
    proxy = params.get('proxy', False)

    demisto.debug(f'Command being called is {command}')

    try:
        headers = {
            'accept': 'application/json',
            'API-Key': api_key
        }
        client = Client(
            base_url=base_url,
            verify=verify_certificate,
            headers=headers,
            proxy=proxy)

        if command == 'test-module':
            # This is the call made when pressing the integration Test button.
            result = test_module(client, params, first_fetch_time)
            return_results(result)

        elif command == 'fetch-incidents':
            # Set and define the fetch incidents command to run after activated via integration settings.

            next_run, incidents = fetch_incidents(
                client=client,
                last_run=demisto.getLastRun(),  # getLastRun() gets the last run dict
                first_fetch=first_fetch_time,
                category=category,
                look_back=look_back
            )

            # saves next_run for the time fetch-incidents is invoked
            demisto.info("Setting lastRun")
            demisto.setLastRun(next_run)

            # fetch-incidents calls ``demisto.incidents()`` to provide the list
            # of incidents to create
            demisto.info("Creating new incidents.")
            demisto.incidents(incidents)

        else:
            raise NotImplementedError(f'Command {command} is not implemented')

    # Log exceptions and return errors
    except Exception as e:
        return_error(f'Failed to execute {command} command.\nError:\n{str(e)}')


''' ENTRY POINT '''

if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
