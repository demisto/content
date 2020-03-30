import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *
''' IMPORTS '''

import json
import requests
import dateparser
import traceback
from typing import Any, Dict

# Disable insecure warnings
requests.packages.urllib3.disable_warnings()

''' CONSTANTS '''
DATE_FORMAT = '%Y-%m-%dT%H:%M:%SZ'
MAX_INCIDENTS_TO_FETCH = 50


class Client(BaseClient):
    """
    Client will implement the service API, and should not contain any Demisto logic.
    Should only do requests and return data.
    """

    def get_ip_reputation(self, ip: str):
        return self._http_request(
            method='GET',
            url_suffix=f'/ip',
            params={
                'ip': ip
            }
        )

    def get_domain_reputation(self, domain: str):
        return self._http_request(
            method='GET',
            url_suffix=f'/domain',
            params={
                'domain': domain
            }
        )

    def search_alerts(self, alert_status: str, severity: int, alert_type: str, max_results: int, start_time: int):
        request_params: Dict[str, Any] = {}

        if alert_status:
            request_params['alert_status'] = alert_status

        if alert_type:
            request_params['alert_type'] = alert_type

        if severity:
            request_params['severity'] = severity

        if max_results:
            request_params['max_results'] = max_results

        if start_time:
            request_params['start_time'] = start_time

        return self._http_request(
            method='GET',
            url_suffix=f'/get_alerts',
            params=request_params
        )

    def get_alert(self, alert_id: str):
        return self._http_request(
            method='GET',
            url_suffix=f'/get_alert_details',
            params={
                'alert_id': alert_id
            }
        )

    def update_alert_status(self, alert_id: str, alert_status: str):
        self._http_request(
            method='GET',
            url_suffix='/change_alert_status',
            params={
                'alert_id': alert_id,
                'alert_status': alert_status
            }
        )

    def scan_start(self, hostname):
        return self._http_request(
            method='GET',
            url_suffix='/start_scan',
            params={
                'hostname': hostname
            }
        )

    def scan_status(self, scan_id):
        return self._http_request(
            method='GET',
            url_suffix='/check_scan',
            params={
                'scan_id': scan_id
            }
        )

    def scan_results(self, scan_id):
        return self._http_request(
            method='GET',
            url_suffix='/get_scan_results',
            params={
                'scan_id': scan_id
            }
        )

    def say_hello(self, name):
        return f'Hello {name}'


def test_module(client, first_fetch_time):
    """
    Returning 'ok' indicates that the integration works like it is supposed to. Connection to the service is successful.

    Args:
        client: HelloWorld client

    Returns:
        'ok' if test passed, anything else will fail the test.
    """

    client.search_alerts(max_results=1, start_time=first_fetch_time, alert_status=None, alert_type=None, severity=None)
    return 'ok'


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


def convert_to_demisto_severity(severity):
    return {
        '0': 1,  # low severity
        '1': 2,  # medium severity
        '2': 3,  # high severity
        '3': 4   # critical severity
    }[str(severity)]


def fetch_incidents(client, last_run, first_fetch_time, alert_type, alert_status):
    """
    This function will execute each interval (default is 1 minute).

    Args:
        client (Client): HelloWorld client
        last_run (dict): The greatest incident created_time we fetched from last fetch
        first_fetch_time (int): If last_run is None then fetch incidents
            since first_fetch_time (timestamp in milliseconds)

        alert_type (str): Alert type
        alert_status (str): Alert status - ACTIVE, CLOSED

    Returns:
        next_run: This will be last_run in the next fetch-incidents
        incidents: Incidents that will be created in Demisto
    """
    # Get the last fetch time, if exists
    last_fetch = last_run.get('last_fetch')
    # Handle first fetch time
    if last_fetch is None:
        last_fetch = first_fetch_time
    else:
        last_fetch = int(last_fetch)

    latest_created_time = last_fetch
    incidents = []

    alerts = client.search_alerts(
        alert_type=alert_type,
        alert_status=alert_status,
        max_results=MAX_INCIDENTS_TO_FETCH,
        start_time=last_fetch,
        severity=None
    )

    for alert in alerts:
        incident_created_time = int(alert['created'])
        incident_created_time_ms = incident_created_time * 1000

        incident_name = alert['name']
        incident = {
            'name': incident_name,
            'details': alert['name'],
            'occurred': timestamp_to_datestring(incident_created_time_ms),
            'rawJSON': json.dumps(alert),
            'type': 'Hello World Alert',
            'severity': convert_to_demisto_severity(alert.get('severity')),
            'CustomFields': {
                'helloworldid': alert.get('alert_id'),
                'helloworldstatus': alert.get('alert_status'),
                'helloworldtype': alert.get('alert_type')
            }
        }

        incidents.append(incident)

        # Update last run and add incident if the incident is newer than last fetch
        if incident_created_time > latest_created_time:
            latest_created_time = incident_created_time

    next_run = {'last_fetch': latest_created_time}
    return next_run, incidents


def ip_reputation_command(client, args, default_threshold):
    ips = argToList(args.get('ip'))
    threshold = int(args.get('threshold', default_threshold))

    dbot_score_list = []
    ip_standard_list = []
    ip_data_list = []

    for ip in ips:
        ip_data = client.get_ip_reputation(ip)
        ip_data['ip'] = ip

        score = 0
        reputation = ip_data.get('score')
        if reputation >= threshold:
            score = 3  # bad
        elif reputation >= threshold / 2:
            score = 2  # suspicious
        else:
            score = 1  # good

        dbot_score = {
            'Indicator': ip,
            'Vendor': 'HelloWorld',
            'Type': 'ip',
            'Score': score
        }
        ip_standard_context = {
            'Address': ip,
            'ASN': ip_data.get('asn')
        }

        if score == 3:
            # if score is bad
            ip_standard_context['Malicious'] = {
                'Vendor': 'HelloWorld',
                'Desciption': f'Hello World returned reputation {reputation}'
            }

        ip_standard_list.append(ip_standard_context)
        dbot_score_list.append(dbot_score)
        ip_data_list.append(ip_data)

    outputs = {
        'DBotScore(val.Vendor == obj.Vendor && val.Indicator == obj.Indicator)': dbot_score_list,
        outputPaths['ip']: ip_standard_list,
        'HelloWorld.IP(val.ip == obj.ip)': ip_data_list
    }

    readable_output = tableToMarkdown('IP List', ip_standard_list)

    return (
        readable_output,
        outputs,
        ip_data_list
    )


def domain_reputation_command(client, args, default_threshold_domain):
    domains = argToList(args.get('domain'))
    threshold = int(args.get('threshold', default_threshold_domain))

    dbot_score_list = []
    domain_standard_list = []
    domain_data_list = []

    for domain in domains:
        domain_data = client.get_domain_reputation(domain)
        domain_data['domain'] = domain

        score = 0
        reputation = domain_data.get('score')
        if reputation >= threshold:
            score = 3  # bad
        elif reputation >= threshold / 2:
            score = 2  # suspicious
        else:
            score = 1  # good

        dbot_score = {
            'Indicator': domain,
            'Vendor': 'HelloWorld',
            'Type': 'domain',
            'Score': score
        }
        domain_standard_context = {
            'Name': domain,
        }

        if score == 3:
            # if score is bad
            domain_standard_context['Malicious'] = {
                'Vendor': 'HelloWorld',
                'Description': f'Hello World returned reputation {reputation}'
            }

        domain_standard_list.append(domain_standard_context)
        dbot_score_list.append(dbot_score)
        domain_data_list.append(domain_data)

    outputs = {
        'DBotScore(val.Vendor == obj.Vendor && val.Indicator == obj.Indicator)': dbot_score_list,
        outputPaths['domain']: domain_standard_list,
        'HelloWorld.Domain(val.domain == obj.domain)': domain_data_list
    }

    readable_output = tableToMarkdown('Domain List', domain_standard_list)

    return (
        readable_output,
        outputs,
        domain_data_list
    )


def arg_to_int(arg, arg_name: str, required: bool = False):
    if arg is None:
        if required is True:
            raise ValueError(f'Missing "{arg_name}"')
        return None
    if isinstance(arg, str):
        if arg.isdigit():
            return int(arg)
        raise ValueError(f'Invalid number: "{arg_name}"="{arg}"')
    if isinstance(arg, int):
        return arg
    return ValueError(f'Invalid number: "{arg_name}"')


def arg_to_timestamp(arg, arg_name: str, required: bool = False):
    if arg is None:
        if required is True:
            raise ValueError(f'Missing "{arg_name}"')
        return None

    if isinstance(arg, str) and arg.isdigit():
        # timestamp that str - we just convert it to int
        return int(arg)
    if isinstance(arg, str):
        # if the arg is string of date format 2019-10-23T00:00:00 or "3 days", etc
        date = dateparser.parse(arg, settings={'TIMEZONE': 'UTC'})
        if date is None:
            # if d is None it means dateparser failed to parse it
            raise ValueError(f'Invalid date: {arg_name}')

        return int(date.timestamp())
    if isinstance(arg, (int, float)):
        return arg


def search_alerts_command(client, args):
    status = args.get('status')
    severity = args.get('severity')
    alert_type = args.get('alert_type')
    start_time = arg_to_timestamp(
        arg=args.get('start_time'),
        arg_name='start_time',
        required=False
    )

    max_results = arg_to_int(
        arg=args.get('max_results'),
        arg_name='max_results',
        required=False
    )

    alerts = client.search_alerts(
        severity=severity,
        alert_status=status,
        alert_type=alert_type,
        start_time=start_time,
        max_results=max_results
    )

    readable_output = tableToMarkdown('HelloWorld Alerts', alerts)
    outputs = {
        'HelloWorld.Alert(val.alert_id == obj.alert_id)': alerts
    }

    return (
        readable_output,
        outputs,
        alerts
    )


def get_alert_command(client, args):
    alert_id = args.get('alert_id')

    alert = client.get_alert(alert_id=alert_id)

    readable_output = tableToMarkdown(f'HelloWorld Alert {alert_id}', alert)
    outputs = {
        'HelloWorld.Alert(val.alert_id == obj.alert_id)': alert
    }

    return (
        readable_output,
        outputs,
        alert
    )


def scan_start_command(client, args):
    hostname = args.get('hostname')

    scan = client.scan_start(hostname=hostname)
    scan_id = scan.get('scan_id')

    readable_output = f'Started scan {scan_id}'
    outputs = {
        'HelloWorld.Scan(val.scan_id == obj.scan_id)': scan
    }
    return (
        readable_output,
        outputs,
        scan
    )


def scan_status_command(client, args):
    scan_id_list = argToList(args.get('scan_id'))

    scan_list = []
    for scan_id in scan_id_list:
        scan = client.scan_status(scan_id=scan_id)
        scan_list.append(scan)

    readable_output = tableToMarkdown('Scan status', scan_list)
    outputs = {
        'HelloWorld.Scan(val.scan_id == obj.scan_id)': scan_list
    }

    return (
        readable_output,
        outputs,
        scan_list
    )


def scan_results_command(client, args):
    scan_id = args.get('scan_id')
    scan_format = args.get('format')

    results = client.scan_results(scan_id=scan_id)
    if scan_format == 'file':
        demisto.results(
            fileResult(
                filename=f'{scan_id}.json',
                data=json.dumps(results, indent=4),
                file_type=entryTypes['entryInfoFile']
            )
        )
    elif scan_format == 'json':
        markdown = tableToMarkdown(f'Scan {scan_id} results', results.get('data'))
        return_outputs(
            readable_output=markdown,
            outputs={
                'HelloWorld.Scan(val.scan_id == obj.scan_id)': results
            },
            raw_response=results
        )


def main():
    """
        PARSE AND VALIDATE INTEGRATION PARAMS
    """
    api_key = demisto.params().get('apikey')

    # get the service API url
    base_url = urljoin(demisto.params()['url'], '/api/v1')

    verify_certificate = not demisto.params().get('insecure', False)

    # How much time before the first fetch to retrieve incidents
    first_fetch_time = arg_to_timestamp(
        arg=demisto.params().get('first_fetch', '3 days'),
        arg_name='First fetch time',
        required=True
    )

    proxy = demisto.params().get('proxy', False)

    demisto.debug(f'Command being called is {demisto.command()}')
    try:
        headers = {
            'Authorization': f'Bearer {api_key}'
        }
        client = Client(
            base_url=base_url,
            verify=verify_certificate,
            headers=headers,
            proxy=proxy)

        if demisto.command() == 'test-module':
            # This is the call made when pressing the integration Test button.
            result = test_module(client, first_fetch_time)
            demisto.results(result)

        elif demisto.command() == 'fetch-incidents':
            # Set and define the fetch incidents command to run after activated via integration settings.
            alert_status = demisto.params().get('alert_status')
            alert_type = demisto.params().get('alert_type')

            next_run, incidents = fetch_incidents(
                client=client,
                last_run=demisto.getLastRun(),
                first_fetch_time=first_fetch_time,
                alert_status=alert_status,
                alert_type=alert_type
            )

            demisto.setLastRun(next_run)
            demisto.incidents(incidents)

        elif demisto.command() == 'ip':
            default_threshold_ip = int(demisto.params().get('threshold_ip', '65'))
            return_outputs(*ip_reputation_command(client, demisto.args(), default_threshold_ip))

        elif demisto.command() == 'domain':
            default_threshold_domain = int(demisto.params().get('threshold_domain', '65'))
            return_outputs(*domain_reputation_command(client, demisto.args(), default_threshold_domain))

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
            scan_results_command(client, demisto.args())

    # Log exceptions
    except Exception as e:
        demisto.error(traceback.format_exc())
        return_error(f'Failed to execute {demisto.command()} command.\nError:\n{str(e)}')


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
