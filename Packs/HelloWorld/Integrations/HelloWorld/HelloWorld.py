import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *
''' IMPORTS '''

import json
import requests
import dateparser

# Disable insecure warnings
requests.packages.urllib3.disable_warnings()

''' CONSTANTS '''
DATE_FORMAT = '%Y-%m-%dT%H:%M:%SZ'


class Client(BaseClient):
    """
    Client will implement the service API, and should not contain any Demisto logic.
    Should only do requests and return data.
    """

    def get_ip_reputation(ip):
        return self._http_request(
            method='GET',
            url_suffix=f'/ip/{ip}'
        )

    def get_domain_reputation(domain):
        return self._http_request(
            method='GET',
            url_suffix=f'/domain/{domain}'
        )

    def search_alerts(status, severity, alert_type):
        return self._http_request(
            method='GET',
            url_suffix=f'/alerts',
            params={
            }
        )

    def get_alert(alert_id):
        return self._http_request(
            method='GET',
            url_suffix=f'/alerts/{alert_id}'
        )

    def scan_start(hostname):
        return self._http_request(
            method='POST',
            url_suffix='/scan'
        )

    def scan_status(scan_id):
        return self._http_request(
            method='GET',
            url_suffix='/scan/'
        )

    def scan_results(scan_id):
        # do multi-form data request
        data = self._http_request()

        return data

    def say_hello(self, name):
        return f'Hello {name}'

    def say_hello_http_request(self, name):
        """
        initiates a http request to a test url
        """
        data = self._http_request(
            method='GET',
            url_suffix='/hello/' + name
        )
        return data.get('result')

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


def test_module(client):
    """
    Returning 'ok' indicates that the integration works like it is supposed to. Connection to the service is successful.

    Args:
        client: HelloWorld client

    Returns:
        'ok' if test passed, anything else will fail the test.
    """

    result = client.say_hello('DBot')
    if 'Hello DBot' == result:
        return 'ok'
    else:
        return 'Test failed because ......'


def say_hello_command(client, args):
    """
    Returns Hello {somename}

    Args:
        client (Client): HelloWorld client.
        args (dict): all command arguments.

    Returns:
        Hello {someone}

        readable_output (str): This will be presented in the war room - should be in markdown syntax - human readable
        outputs (dict): Dictionary/JSON - saved in the incident context in order to be used as inputs for other tasks in the
                 playbook
        raw_response (dict): Used for debugging/troubleshooting purposes - will be shown only if the command executed with
                      raw-response=true
    """
    name = args.get('name')

    result = client.say_hello(name)

    # readable output will be in markdown format - https://www.markdownguide.org/basic-syntax/
    readable_output = f'## {result}'
    outputs = {
        'hello': result
    }

    return (
        readable_output,
        outputs,
        result  # raw response - the original response
    )


def say_hello_over_http_command(client, args):
    name = args.get('name')

    result = client.say_hello_http_request(name)

    # readable output will be in markdown format - https://www.markdownguide.org/basic-syntax/
    readable_output = f'## {result}'
    outputs = {
        'hello': result
    }

    return (
        readable_output,
        outputs,
        result  # raw response - the original response
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


def ip_reputation_command(client, args, threshold):
    ips = argToList(args.get('ip'))
    threshold = int(args.get('threshold', threshold))

    for ip in ips:
        ip_data = client.get_ip_reputation(ip)

        score = 0
        reputation = ip_data.get('reputation')
        if reputation => threshold:
            score = 3 # bad
        elif reputation >= threshold/2:
            score = 2 # suspicious
        else:
            score = 1 # good

        dbot_score = {
            'Indicator': ip,
            'Vendor': 'HelloWorld',
            'Type': 'ip',
            'Score': score
        }
        ip_standard_context = {
            'Address': ip,
            'ASN': ip_data.get('ip')
        }

        if score == 3:
            # if score is bad
            ip_standard_context['Malicious'] = {
                'Vendor': 'HelloWorld',
                'Desciption': f'Hello World returned repuration {reputation}'
            }

        outputs = {
            'DBotScore(val.Vendor == obj.Vendor && val.Indicator == obj.Indicator)': dbot_score,
            outputPaths['ip']: ip_standard_context,
            'HelloWorld.IP(val.ip == obj.ip)': ip_data
        }

        readable_output = tableToMarkdown('IP List', ip)


def domain_reputation_command(client, args):
    pass


def search_alerts_command(client, args):
    status = args.get('status')
    severity = args.get('severity')

    alerts = client.search_alerts(
        severity=severity,
        status=status
    )

    return (
        tableToMarkdown('HelloWorld Alerts', alerts, ['id', 'name', 'description', 'severity', 'status', 'type']),
        {
            'HelloWorld.Alert(val.id == obj.id)': alerts
        },
        alerts
    )


def get_alert_command(client, args):
    pass


def scan_start_command(client, args):
    pass


def scan_status_command(client, args):
    pass


def scan_results_command(client, args):
    pass


def main():
    """
        PARSE AND VALIDATE INTEGRATION PARAMS
    """
    username = demisto.params().get('credentials').get('identifier')
    password = demisto.params().get('credentials').get('password')

    # get the service API url
    base_url = urljoin(demisto.params()['url'], '/api/v1/suffix')

    verify_certificate = not demisto.params().get('insecure', False)

    # How much time before the first fetch to retrieve incidents
    first_fetch_time = demisto.params().get('fetch_time', '3 days').strip()

    proxy = demisto.params().get('proxy', False)

    LOG(f'Command being called is {demisto.command()}')
    try:
        client = Client(
            base_url=base_url,
            verify=verify_certificate,
            auth=(username, password),
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

        elif demisto.command() == 'ip':
            threshold = int(demisto.params().get('threshold_ip'))
            return_outputs(*ip_reputation_command(client, demisto.args(), threshold))

        elif demisto.command() == 'domain':
            return_outputs(*domain_reputation_command(client, demisto.args()))

        elif demisto.command() == 'helloworld-say-hello':
            return_outputs(*say_hello_command(client, demisto.args()))

        elif demisto.command() == 'helloworld-search-alerts':
            return_outputs(*search_alerts_command(client, demisto.args()))

        elif demisto.command() == 'helloworld-get-alert':
            return_outputs(*get_alert_command(client, demisto.args()))

        elif demisto.command() == 'helloworld-scan-start':
            return_outputs(*scan_start_command(client, demisto.args()))

        elif demisto.command() == 'helloworld-scan-status':
            return_outputs(*scan_status_command(client, demisto.args()))

        elif demisto.command() == 'helloworld-scan-results':
            return_outputs(*scan_results_command(client, demisto.args()))

        

        

        

    # Log exceptions
    except Exception as e:
        return_error(f'Failed to execute {demisto.command()} command. Error: {str(e)}')


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
