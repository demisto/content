import json

import dateparser
import demistomock as demisto
import requests
from CommonServerPython import *  # noqa: E402 lgtm [py/polluting-import]
from CommonServerUserPython import *  # noqa: E402 lgtm [py/polluting-import]

# IMPORTS


# Disable insecure warnings
requests.packages.urllib3.disable_warnings()

# CONSTANTS
DATE_FORMAT = '%Y-%m-%dT%H:%M:%SZ'


class Client(BaseClient):
    """
    Client will implement the service API, and should not contain any Demisto logic.
    Should only do requests and return data.
    """

    def alert_list(self, url_suffix, request_data):

        data = self._http_request(
            method='GET',
            url_suffix=url_suffix,
            json_data=request_data
        )
        return data

    def list_incidents(self):
        """
        returns dummy incident data, just for the example.
        """
        return [
            {
                'incident_id': 1,
                'description': 'Hello incident 1',
                'created_time': datetime.utcnow().strftime(DATE_FORMAT)
            },
            {
                'incident_id': 2,
                'description': 'Hello incident 2',
                'created_time': datetime.utcnow().strftime(DATE_FORMAT)
            }
        ]


def convert_severity(severity):

    severity_options = {
        'Low': 0,  # low severity
        'Medium': 1,  # medium severity
        'High': 2  # high severity
    }
    return severity_options[severity]


def convert_resolution_status(resolution_status):

    resolution_status_options = {
        'Low': 0,  # low severity
        'Medium': 1,  # medium severity
        'High': 2  # high severity
    }
    return resolution_status_options[resolution_status]


def args_to_json_filter(all_params):
    request_data = {}
    filters = {}
    for key, value in all_params.items():
        if key in ['skip', 'limit']:
            request_data[key] = int(value)
        if key in ['service', 'instance']:
            filters[f'entity.{key}'] = {'eq': int(value)}
        if key == 'severity':
            filters[key] = {'eq': convert_severity(value)}
        if key == 'resolution_status':
            filters[key] = {'eq': convert_resolution_status(value)}
    request_data['filters'] = filters
    return request_data


def test_module(client):
    try:
        client.alert_list(alert_id='5f06d71dba4289d0602ba5ac', customer_filters='', skip='', limit='', severity='',
                          service='', instance='', resolution_status='', username='')
    except DemistoException as e:
        if 'Forbidden' in str(e):
            return 'Authorization Error: make sure API Key is correctly set'
        else:
            raise e
    return 'ok'


def alerts_list_command(client, args):
    alert_id = args.get('alert_id')
    customer_filters = args.get('customer_filters')
    all_params = assign_params(skip=args.get('skip'), limit=args.get('limit'), severity=args.get('severity'),
                               service=args.get('service'), instance=args.get('instance'),
                               resolution_status=args.get('resolution_status'))
    request_data = {}
    url_suffix = '/alerts/'
    if alert_id:
        url_suffix += alert_id
    elif customer_filters:
        request_data['filters'] = json.loads(customer_filters)
    else:
        request_data = args_to_json_filter(all_params)

    alerts = client.alert_list(url_suffix, request_data)

    return CommandResults(
        readable_output=alerts,
        outputs_prefix='MicrosoftCloudAppSecurity.Alert',
        outputs_key_field='alert_id',
        outputs=alerts
    )


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
    token = demisto.params().get('token')

    # get the service API url
    base_url = f'{urljoin(demisto.params().get("url"))}api/v1'

    verify_certificate = not demisto.params().get('insecure', False)

    # How much time before the first fetch to retrieve incidents
    first_fetch_time = demisto.params().get('fetch_time', '3 days').strip()

    proxy = demisto.params().get('proxy', False)

    LOG(f'Command being called is {demisto.command()}')
    try:
        client = Client(
            base_url=base_url,
            verify=verify_certificate,
            headers={'Authorization': f'Token {token}'},
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

        elif demisto.command() == 'microsoft-cas-alerts-list':
            return_results(alerts_list_command(client, demisto.args()))

    # Log exceptions
    except Exception as e:
        return_error(f'Failed to execute {demisto.command()} command. Error: {str(e)}')


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
