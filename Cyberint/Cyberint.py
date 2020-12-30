import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *

''' IMPORTS '''

import json
import requests
import dateparser
from typing import Dict, List, Optional, Tuple

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
        print(body)
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
                                                date_format=DATE_FORMAT, utc=False)
        return start_date, end_date
    min_date = datetime.fromisocalendar(2020, 12, 1)
    if start_date_arg and not end_date_arg:
        return start_date_arg, datetime.strftime(datetime.now(), DATE_FORMAT)
    if end_date_arg and not start_date_arg:
        return datetime.strftime(min_date, DATE_FORMAT), end_date_arg
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
    created_date_from, created_date_to = set_date_pair(args.get('created_date_from', None),
                                                       args.get('created_date_to', None),
                                                       args.get('created_date_range', None))
    modify_date_from, modify_date_to = set_date_pair(args.get('modification_date_from', None),
                                                     args.get('modification_date_to', None),
                                                     args.get('modification_date_range', None))
    result = client.list_alerts(args.get('page'), args.get('page_size'), created_date_from,
                                created_date_to, modify_date_from, modify_date_to,
                                argToList(args.get('environments')),
                                argToList(args.get('statuses')),
                                argToList(args.get('severities')), argToList(args.get('types')))
    alerts = result.get('alerts')
    total_alerts = result.get('total')
    table_headers = ['ref_id', 'title', 'status', 'severity', 'created_date', 'type',
                     'environment']
    readable_output = tableToMarkdown(name='Found alerts:', t=alerts, headers=table_headers,
                                      removeNull=True)
    readable_output += f'Total alerts: {total_alerts}\nCurrent page: {args.get("page", 1)}'
    return CommandResults(outputs_key_field='ref_id', outputs_prefix='Cyberint.Alert',
                          readable_output=readable_output, raw_response=result,
                          outputs=alerts)


def fetch_incidents(client: Client, last_run: Dict[str, int],
                    first_fetch_time: str, fetch_severity: Optional[List[str]],
                    fetch_status: Optional[List[str]], fetch_type: Optional[List[str]],
                    fetch_environment: Optional[List[str]],
                    max_fetch: Optional[int]) -> Tuple[Dict[str, int], List[dict]]:
    """
    Fetch incidents (alerts) each minute (by default).
    Args:
        client (Client): Cyberint Client.
        last_run (dict): Dict with last_fetch object,
                                  saving the last fetch time(in millisecond timestamp).
        first_fetch_time (dict): Dict with first fetch time in str (ex: 3 days ago).
        fetch_severity (list(str)): Severities to fetch.
        fetch_status (list(str)): Statuses to fetch.
        fetch_type (list(str)): Types to fetch.
        fetch_environment (list(str)): Environments to fetch.
        max_fetch (int): Max number of alerts to fetch.
    Returns:
        Tuple of next_run (seconds timestamp) and the incidents list
    """
    last_fetch_timestamp = last_run.get('last_fetch', None)
    if last_fetch_timestamp:
        last_fetch_date = datetime.fromtimestamp(last_fetch_timestamp / 1000)
        last_fetch = last_fetch_date
    else:
        first_fetch_date = dateparser.parse(first_fetch_time)
        last_fetch = first_fetch_date
    incidents = []
    next_run = last_fetch
    alerts = client.list_alerts('1', max_fetch, datetime.strftime(last_fetch, DATE_FORMAT),
                                datetime.strftime(datetime.now(), DATE_FORMAT), None, None,
                                fetch_environment, fetch_status, fetch_severity, fetch_type)
    for alert in alerts.get('alerts', []):
        alert_created_time = datetime.strptime(alert.get('created_date'), '%Y-%m-%dT%H:%M:%S')
        alert_id = alert.get('ref_id')
        alert_title = alert.get('title')
        incident = {
            'name': f'Cyberint alert {alert_id}: {alert_title}',
            'occurred': datetime.strftime(alert_created_time, DATE_FORMAT),
            'rawJSON': json.dumps(alert)
        }
        incidents.append(incident)
    if incidents:
        last_incident_time = incidents[0].get('occurred', '')
        next_run = datetime.strptime(last_incident_time, DATE_FORMAT)
    next_run += timedelta(seconds=1)
    next_run_timestamp = int(datetime.timestamp(next_run) * 1000)
    return {'last_fetch': next_run_timestamp}, incidents


def main():
    """
        PARSE AND VALIDATE INTEGRATION PARAMS
    """
    params = demisto.params()
    access_token = params.get('access_token')
    environment = params.get('environment')
    fetch_environment = argToList(params.get('fetch_environment', ''))
    fetch_status = params.get('fetch_status', [])
    fetch_type = params.get('fetch_type', [])
    fetch_severity = params.get('fetch_severity', [])
    max_fetch = int(params.get('max_fetch', '50'))
    verify_certificate = not params.get('insecure', False)
    first_fetch_time = params.get('fetch_time', '3 days').strip()
    proxy = params.get('proxy', False)
    base_url = f'https://{environment}.cyberint.io/alert/'

    demisto.info(f'Command being called is {demisto.command()}')
    try:
        client = Client(
            base_url=base_url,
            verify_ssl=verify_certificate,
            access_token=access_token,
            proxy=proxy)

        if demisto.command() == 'test-module':
            result = test_module(client)
            demisto.results(result)

        elif demisto.command() == 'fetch-incidents':
            next_run, incidents = fetch_incidents(
                client, demisto.getLastRun(), first_fetch_time, fetch_severity, fetch_status,
                fetch_type, fetch_environment, max_fetch)
            demisto.setLastRun(next_run)
            demisto.incidents(incidents)

        elif demisto.command() == 'cyberint-list-alerts':
            return_results(cyberint_list_alerts_command(client, demisto.args()))
    except Exception as e:
        return_error(f'Failed to execute {demisto.command()} command. Error: {str(e)}')


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
