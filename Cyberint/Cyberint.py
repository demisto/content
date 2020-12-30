import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *

''' IMPORTS '''

import json
import requests
import dateparser
from typing import Dict, List, Optional, Tuple

# Disable insecure warnings
requests.packages.urllib3.disable_warnings()

''' CONSTANTS '''
DATE_FORMAT = '%Y-%m-%dT%H:%M:%SZ'


class Client(BaseClient):
    """
    API Client to communicate with Cyberint and get alerts.
    """

    def __init__(self, base_url: str, access_token: str, verify_ssl: bool, proxy: bool):
        """
        API Client constructor.

        Args:
            base_url (str): URL to access when getting alerts.
            access_token (str): Access token for authentication.
            verify_ssl (bool): Whether or not to verify SSL.
            proxy (bool): Whether or not to use proxy
        """
        headers = {'Content-Type': 'application/json'}
        self._cookies = {'access_token': access_token}
        super().__init__(base_url=base_url, verify=verify_ssl, proxy=proxy, headers=headers)

    def list_alerts(self, page: Optional[str], page_size: Optional[str],
                    created_date_from: Optional[str], created_date_to: Optional[str],
                    modification_date_from: Optional[str], modification_date_to: Optional[str],
                    environments: Optional[List[str]], statuses: Optional[List[str]],
                    severities: Optional[List[str]], types: Optional[List[str]]) -> Dict:
        """
        List alerts according to parameters.

        Args:
            page (str): N. of page to return.
            page_size (str): Size of the page to return.
            created_date_from (str): ISO-Formatted creation date minimum.
            created_date_to (str): ISO-Formatted creation date maximum.
            modification_date_from (str): ISO-Formatted modification date minimum.:
            modification_date_to (str): ISO-Formatted modification date maximum.:
            environments (list(str)): Environments in which the alerts were created
            statuses (list(str)): Statuses of the alerts
            severities (list(str)): Severities of the alerts.
            types (list(str)): Types of the alerts,

        Returns:
            response (Response): API response from Cyberint.
        """
        body = {'page': page, 'size': page_size, 'filters': {
            'created_date': {'from': created_date_from, 'to': created_date_to},
            'modification_date': {'from': modification_date_from, 'to': modification_date_to},
            'environments': environments, 'status': statuses, 'severity': severities,
            'type': types
        }}
        body = remove_empty_elements(body)
        response = self._http_request(method='POST', json_data=body, cookies=self._cookies,
                                      url_suffix='api/v1/alerts')
        return response


def test_module(client):
    """
    Test the connection to the API by sending a normal request.

    Args:
        client: Cyberint API  client

    Returns:
        'ok' if test passed, anything else will fail the test.
    """

    try:
        result = client.list_alerts(*([None] * 10))
        if result:
            return 'ok'
        return f'Unidentified error in retrieving test response: {str(result)}'
    except DemistoException as exception:
        if 'Invalid token or token expired' in str(exception):
            return 'Error verifying access token and / or environment, make sure the ' \
                   'configuration parameters are correct.'
        return str(exception)


def set_date_pair(start_date_arg: Optional[str], end_date_arg: Optional[str],
                  date_range_arg: Optional[str]) -> Tuple[str, str]:
    """
    Calculate the date range to send to the API based on the arguments from the user.

    Args:
        start_date_arg (str): Optional start_date from the user.
        end_date_arg (str): Optional end_date from the user.
        date_range_arg (str): Optional date range from the user.

    Returns:
        start_date (str): Start date to send to the API.
        end_date (str): End date to send to the API.
    """
    if date_range_arg:
        start_date, end_date = parse_date_range(date_range=date_range_arg,
                                                date_format=DATE_FORMAT)
        return start_date, end_date
    return start_date_arg, end_date_arg


def cyberint_list_alerts_command(client: Client, args: dict) -> CommandResults:
    """
    List alerts on cyberint according to parameters.

    Args:
        client (Client): Cyberint API client.
        args (dict): Command arguments from XSOAR.

    Returns:
        CommandResults: outputs, readable outputs and raw response for XSOAR.
    """
    created_date_from, created_date_to = set_date_pair(args.get('created_date_start'),
                                                       args.get('created_date_end'),
                                                       args.get('created_date_range'))
    modify_date_from, modify_date_to = set_date_pair(args.get('modification_date_start'),
                                                     args.get('modification_date_end'),
                                                     args.get('modification_date_range'))
    result = client.list_alerts(args.get('page'), args.get('page_size'), created_date_from,
                                created_date_to, modify_date_from, modify_date_to,
                                args.get('environments'), args.get('statuses'),
                                args.get('severities'), args.get('types'))
    alerts = result.get('alerts')
    total_alerts = result.get('total')
    table_headers = ['ref_id', 'title', 'status', 'severity', 'publish_date', 'type',
                     'environment']
    readable_output = tableToMarkdown(name='Found alerts:', t=alerts, headers=table_headers,
                                      removeNull=True)
    readable_output += f'Total alerts: {total_alerts}\nCurrent page: {args.get("page", 1)}'
    return CommandResults(outputs_key_field='ref_id', outputs_prefix='Cyberint.Alert',
                          readable_output=readable_output, raw_response=result,
                          outputs=alerts)


def fetch_incidents(client, last_run, first_fetch_time):
    """
    This function will execute each interval (default is 1 minute).

    Args:
        client (Client): HelloWorld client
        last_run (dateparser.time): The greatest incident created_time we fetched from last fetch
        first_fetch_time (dateparser.time): If last_run is None then fetch all incidents since first_fetch_time

    Returns:
        next_run: This will be last_run in the next fetch-incidents
        incidents: Incidents that will be created in Demisto
    """
    # Get the last fetch time, if exists
    last_fetch = last_run.get('last_fetch')

    # Handle first time fetch
    if last_fetch is None:
        last_fetch, _ = dateparser.parse(first_fetch_time)
    else:
        last_fetch = dateparser.parse(last_fetch)

    latest_created_time = last_fetch
    incidents = []
    items = client.list_incidents()
    for item in items:
        incident_created_time = dateparser.parse(item['created_time'])
        incident = {
            'name': item['description'],
            'occurred': incident_created_time.strftime('%Y-%m-%dT%H:%M:%SZ'),
            'rawJSON': json.dumps(item)
        }

        incidents.append(incident)

        # Update last run and add incident if the incident is newer than last fetch
        if incident_created_time > latest_created_time:
            latest_created_time = incident_created_time

    next_run = {'last_fetch': latest_created_time.strftime(DATE_FORMAT)}
    return next_run, incidents


def main():
    """
        PARSE AND VALIDATE INTEGRATION PARAMS
    """
    access_token = demisto.params().get('access_token')
    environment = demisto.params().get('environment')

    # get the service API url
    base_url = f'https://{environment}.cyberint.io/alert/'
    verify_certificate = not demisto.params().get('insecure', False)
    # How much time before the first fetch to retrieve incidents
    first_fetch_time = demisto.params().get('fetch_time', '3 days').strip()

    proxy = demisto.params().get('proxy', False)

    LOG(f'Command being called is {demisto.command()}')
    try:
        client = Client(
            base_url=base_url,
            verify_ssl=verify_certificate,
            access_token=access_token,
            proxy=proxy)
        if demisto.command() == 'test-module':
            # This is the call made when pressing the integration Test button.
            result = test_module(client)
            demisto.results(result)

        elif demisto.command() == 'fetch-incidents':
            # Set and define the fetch incidents command to run after activated via integration settings.
            next_run, incidents = fetch_incidents(
                client=client,
                last_run=demisto.getLastRun(),
                first_fetch_time=first_fetch_time)

            demisto.setLastRun(next_run)
            demisto.incidents(incidents)

        elif demisto.command() == 'cyberint-list-alerts':
            return_results(cyberint_list_alerts_command(client, demisto.args()))


    # Log exceptions
    except Exception as e:
        return_error(f'Failed to execute {demisto.command()} command. Error: {str(e)}')


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
