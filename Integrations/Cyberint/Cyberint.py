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
        Client for CyberInt RESTful API.

        Args:
            base_url (str): URL to access when getting alerts.
            access_token (str): Access token for authentication.
            verify_ssl (bool): specifies whether to verify the SSL certificate or not.
            proxy (bool): specifies if to use XSOAR proxy settings.
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
        Retrieve a list of alerts according to parameters.

        Args:
            page (str): Index of page to return.
            page_size (str): Size of the page to return.
            created_date_from (str): Minimal ISO-Formatted creation date.
            created_date_to (str): Maximal ISO-Formatted creation date.
            modification_date_from (str): Minimal ISO-Formatted modification date.
            modification_date_to (str): Maximal ISO-Formatted modification date.
            environments (list(str)): Environments in which the alerts were created.
            statuses (list(str)): Alerts statuses.
            severities (list(str)): Alerts severities.
            types (list(str)): Alerts type.

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

    def update_alerts(self, alerts: List[str], status: str, closure_reason: Optional[str]) -> Dict:
        """
        Update the status of one or more alerts

        Args:
            alerts (list(str)): Reference IDs for the alert(s)
            status (str): Desired status to update for the alert(s)
            closure_reason (str): Reason for updating the alerts status to closed.

        Returns:
            response (Response): API response from Cyberint.
        """
        body = {'alert_ref_ids': alerts,
                'data': {'status': status, 'closure_reason': closure_reason}}
        body = remove_empty_elements(body)
        response = self._http_request(method='PUT', json_data=body, cookies=self._cookies,
                                      url_suffix='api/v1/alerts/status')
        return response


def test_module(client):
    """
    Test the connection to the API by sending a normal request.

    Args:
        client: Cyberint API  client

    Returns:
        'ok' if test passed, anything else will fail the test.
    """
    return_value = None
    try:
        result = client.list_alerts(*([None] * 10))
        if result:
            return_value = 'ok'
    except DemistoException as exception:
        if 'Invalid token or token expired' in str(exception):
            return_value = 'Error verifying access token and / or environment, make sure the ' \
                           'configuration parameters are correct.'
        else:
            return_value = str(exception)
    finally:
        return return_value


def verify_input_date_format(date: str) -> str:
    """
    Make sure a date entered by the user is in the correct string format (with a Z at the end).

    Args:
        date (str): Date string given by the user. Can be None.

    Returns:
        str: Fixed date in the same format as the one needed by the API.
    """
    if date and not date.endswith('Z'):
        date += 'Z'
    return date


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
    min_date = datetime.fromisocalendar(2020, 2, 1)
    start_date_arg = verify_input_date_format(start_date_arg)
    end_date_arg = verify_input_date_format(end_date_arg)
    if start_date_arg and not end_date_arg:
        end_date_arg = datetime.strftime(datetime.now(), DATE_FORMAT)
    elif end_date_arg and not start_date_arg:
        start_date_arg = datetime.strftime(min_date, DATE_FORMAT)
    return start_date_arg, end_date_arg


def cyberint_alerts_fetch_command(client: Client, args: dict) -> CommandResults:
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
    readable_output = f'Total alerts: {total_alerts}\nCurrent page: {args.get("page", 1)}\n'
    readable_output += tableToMarkdown(name='CyberInt alerts:', t=alerts, headers=table_headers,
                                       removeNull=True)
    return CommandResults(outputs_key_field='ref_id', outputs_prefix='Cyberint.Alert',
                          readable_output=readable_output, raw_response=result,
                          outputs=alerts)


def cyberint_alerts_status_update(client: Client, args: dict) -> CommandResults:
    """
        Update the status of one or more alerts

        Args:
        client (Client): Cyberint API client.
        args (dict): Command arguments from XSOAR.

    Returns:
        CommandResults: outputs, readable outputs and raw response for XSOAR.
    """
    alert_ids = argToList(args.get('alert_ref_ids'))
    status = args.get('status')
    closure_reason = args.get('closure_reason')
    response = client.update_alerts(alert_ids, status,
                                    closure_reason)
    table_headers = ['ref_id', 'status', 'closure_reason']
    outputs = []
    for alert_id in alert_ids:
        outputs.append({'ref_id': alert_id, 'status': status, 'closure_reason': closure_reason})

    readable_output = tableToMarkdown(name='CyberInt alerts updated information:', t=outputs,
                                      headers=table_headers, removeNull=True)
    return CommandResults(outputs_key_field='ref_id', outputs_prefix='Cyberint.Alert',
                          readable_output=readable_output, raw_response=response,
                          outputs=outputs)


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
    #  Start by setting the time to fetch from.
    last_fetch_timestamp = last_run.get('last_fetch', None)
    if last_fetch_timestamp:
        last_fetch_date = datetime.fromtimestamp(last_fetch_timestamp / 1000)
        last_fetch = last_fetch_date
    else:
        first_fetch_date = dateparser.parse(first_fetch_time)
        last_fetch = first_fetch_date
    incidents = []
    next_run = last_fetch
    #  Send the API request to fetch the alerts.
    alerts = client.list_alerts('1', max_fetch, datetime.strftime(last_fetch, DATE_FORMAT),
                                datetime.strftime(datetime.now(), DATE_FORMAT), None, None,
                                fetch_environment, fetch_status, fetch_severity, fetch_type)
    for alert in alerts.get('alerts', []):
        #  Create the XS0AR incident.
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
        #  Update the time for the next fetch so that there won't be duplicates.
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
            return_results(result)

        elif demisto.command() == 'fetch-incidents':
            fetch_environment = argToList(params.get('fetch_environment', ''))
            fetch_status = params.get('fetch_status', [])
            fetch_type = params.get('fetch_type', [])
            fetch_severity = params.get('fetch_severity', [])
            max_fetch = int(params.get('max_fetch', '50'))
            next_run, incidents = fetch_incidents(
                client, demisto.getLastRun(), first_fetch_time, fetch_severity, fetch_status,
                fetch_type, fetch_environment, max_fetch)
            demisto.setLastRun(next_run)
            demisto.incidents(incidents)

        elif demisto.command() == 'cyberint-alerts-fetch':
            return_results(cyberint_alerts_fetch_command(client, demisto.args()))

        elif demisto.command() == 'cyberint-alerts-status-update':
            return_results(cyberint_alerts_status_update(client, demisto.args()))
    except Exception as e:
        if 'Invalid token or token expired' in str(e):
            return_error('Error verifying access token and / or environment, make sure the '
                         'configuration parameters are correct.')
        if 'datetime' in str(e).lower():
            return_error('Invalid time specified, make sure the arguments are correctly formatted.')
        return_error(f'Failed to execute {demisto.command()} command. Error: {str(e)}')


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
