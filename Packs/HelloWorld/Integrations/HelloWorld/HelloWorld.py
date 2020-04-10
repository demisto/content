import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *

''' IMPORTS '''


import json
import requests
import dateparser
import traceback
from typing import Any, Dict, Tuple, List, Optional, cast

# Disable insecure warnings
requests.packages.urllib3.disable_warnings()


''' CONSTANTS '''


DATE_FORMAT = '%Y-%m-%dT%H:%M:%SZ'
MAX_INCIDENTS_TO_FETCH = 50


''' CLIENT CLASS '''


class Client(BaseClient):
    """Client class to interact with the service API

    This Client implements API calls, and does not contain any Demisto logic.
    Should only do requests and return data.
    It inherits from BaseClient defined in CommonServer Python.
    Most calls use _http_request() that handles proxy, SSL verification, etc.
    For this HelloWorld implementation, no special attributes defined
    """

    def get_ip_reputation(self, ip: str) -> Dict[str, Any]:
        """Gets the IP reputation using the '/ip' API endpoint

        :type ip: ``str``
        :param ip: IP address to get the reputation for

        :return: dict containing the IP reputation as returned from the API
        :rtype: ``Dict[str, Any]``
        """

        return self._http_request(
            method='GET',
            url_suffix=f'/ip',
            params={
                'ip': ip
            }
        )

    def get_domain_reputation(self, domain: str) -> Dict[str, Any]:
        """Gets the Domain reputation using the '/domain' API endpoint

        :type domain: ``str``
        :param domain: domain name to get the reputation for

        :return: dict containing the domain reputation as returned from the API
        :rtype: ``Dict[str, Any]``
        """

        return self._http_request(
            method='GET',
            url_suffix=f'/domain',
            params={
                'domain': domain
            }
        )

    def search_alerts(self, alert_status: Optional[str], severity: Optional[int],
                      alert_type: Optional[str], max_results: Optional[int],
                      start_time: Optional[int]) -> List[Dict[str, Any]]:
        """Searches for HelloWorld alerts using the '/get_alerts' API endpoint

        All the parameters are passed directly to the API as HTTP POST parameters in the request

        :type alert_status: ``Optional[str]``
        :param alert_status: status of the alert to search for. Options are: 'ACTIVE' or 'CLOSED'

        :type severity: ``Optional[int]``
        :param severity: severity of the alert to search for. Values are from 0 to 3

        :type alert_type: ``Optional[str]``
        :param alert_type: type of alerts to search for. There is no list of predefined types

        :type max_results: ``Optional[int]``
        :param max_results: maximum number of results to return

        :type start_time: ``Optional[int]``
        :param start_time: start timestamp (epoch in seconds) for the alert search

        :return: list containing the found HelloWorld alerts as dicts
        :rtype: ``List[Dict[str, Any]]``
        """

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

    def get_alert(self, alert_id: str) -> Dict[str, Any]:
        """Gets a specific HelloWorld alert by id

        :type alert_id: ``str``
        :param alert_id: id of the alert to return

        :return: dict containing the alert as returned from the API
        :rtype: ``Dict[str, Any]``
        """

        return self._http_request(
            method='GET',
            url_suffix=f'/get_alert_details',
            params={
                'alert_id': alert_id
            }
        )

    def update_alert_status(self, alert_id: str, alert_status: str) -> None:
        """Changes the status of a specific HelloWorld alert

        :type alert_id: ``str``
        :param alert_id: id of the alert to return

        :type alert_status: ``str``
        :param alert_status: new alert status. Options are: 'ACTIVE' or 'CLOSED'

        :return:
        :rtype:
        """
        self._http_request(
            method='GET',
            url_suffix='/change_alert_status',
            params={
                'alert_id': alert_id,
                'alert_status': alert_status
            }
        )

    def scan_start(self, hostname: str) -> Dict[str, Any]:
        """Starts a HelloWorld scan on a specific hostname

        :type hostname: ``str``
        :param hostname: hostname of the machine to scan

        :return: dict containing the scan status as returned from the API
        :rtype: ``Dict[str, Any]``
        """

        return self._http_request(
            method='GET',
            url_suffix='/start_scan',
            params={
                'hostname': hostname
            }
        )

    def scan_status(self, scan_id: str) -> Dict[str, Any]:
        """Gets the status of a HelloWorld scan

        :type scan_id: ``str``
        :param scan_id: ID of the scan to retrieve status for

        :return: dict containing the scan status as returned from the API
        :rtype: ``Dict[str, Any]``
        """

        return self._http_request(
            method='GET',
            url_suffix='/check_scan',
            params={
                'scan_id': scan_id
            }
        )

    def scan_results(self, scan_id: str) -> Dict[str, Any]:
        """Gets the results of a HelloWorld scan

        :type scan_id: ``str``
        :param scan_id: ID of the scan to retrieve results for

        :return: dict containing the scan results as returned from the API
        :rtype: ``Dict[str, Any]``
        """

        return self._http_request(
            method='GET',
            url_suffix='/get_scan_results',
            params={
                'scan_id': scan_id
            }
        )

    def say_hello(self, name: str) -> str:
        """Says 'Hello {name}'

        :type name: ``str``
        :param name: name to append to the 'Hello' string

        :return: string containing 'Hello {name}'
        :rtype: ``str``
        """

        return f'Hello {name}'


''' HELPER FUNCTIONS '''


def convert_to_demisto_severity(severity: int) -> int:
    """Maps HelloWorld severity to Cortex XSOAR severity

    :type severity: ``int``
    :param severity: severity as returned from the HelloWorld API (0 to 3)

    :return: Cortex XSOAR Severity (1 to 4)
    :rtype: ``int``
    """

    # In this case the mapping is very straightforward, but more complex
    # mappings might be required in your integration, hence a dedicated function
    # is recommended
    return {
        '0': 1,  # low severity
        '1': 2,  # medium severity
        '2': 3,  # high severity
        '3': 4   # critical severity
    }[str(severity)]


def convert_to_helloworld_severity(severity: Optional[str]) -> Optional[int]:
    """Maps Cortex XSOAR severity to HelloWorld severity

    :type severity: ``Optional[str]``
    :param severity: severity in XSOAR format ('Low,'Medium','High','Critical)

    :return: HelloWorld severity (0 to 3) or None if not specified
    :rtype: ``Optional[int]``
    """

    # In this case the mapping is very straightforward, but more complex
    # mappings might be required in your integration, hence a dedicated function
    # is recommended
    if not severity:
        return None

    return {
        'Low': 0,  # low severity
        'High': 1,  # medium severity
        'Medium': 2,  # high severity
        'Critical': 3   # critical severity
    }[str(severity)]


def arg_to_int(arg: Any, arg_name: str, required: bool = False) -> Optional[int]:
    """Converts an XSOAR argument to a Python int

    :type arg: ``Any``
    :param arg: argument to convert

    :type arg_name: ``str``
    :param arg_name: argument name

    :type required: ``bool``
    :param required:
        throws exception if ``True`` and argument provided is None

    :return:
        returns an ``int`` if arg can be converted
        returns ``None`` if arg is ``None`` and required is set to ``False``
        otherwise throws an Exception
    :rtype: ``Optional[int]``
    """

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
    raise ValueError(f'Invalid number: "{arg_name}"')


def arg_to_timestamp(arg: Any, arg_name: str, required: bool = False) -> Optional[int]:
    """Converts an XSOAR argument to a timestamp (seconds from epoch)

    :type arg: ``Any``
    :param arg: argument to convert

    :type arg_name: ``str``
    :param arg_name: argument name

    :type required: ``bool``
    :param required:
        throws exception if ``True`` and argument provided is None

    :return:
        returns an ``int`` containing a timestamp (seconds from epoch) if conversion works
        returns ``None`` if arg is ``None`` and required is set to ``False``
        otherwise throws an Exception
    :rtype: ``Optional[int]``
    """

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
        # Convert to int if the input is a float
        return int(arg)
    raise ValueError(f'Invalid date: "{arg_name}"')


''' COMMAND FUNCTIONS '''


def test_module(client: Client, first_fetch_time: int) -> str:
    """Tests API connectivity and authentication'

    Returning 'ok' indicates that the integration works like it is supposed to.
    Connection to the service is successful.
    Raises exceptions if something goes wrong.

    :type client: ``Client``
    :param Client: HelloWorld client to use

    :type name: ``str``
    :param name: name to append to the 'Hello' string

    :return: 'ok' if test passed, anything else will fail the test.
    :rtype: ``str``
    """

    """ INTEGRATION DEVELOPER TIP
    Client class should handle the exceptions, but if the test fails
    the exception text is printed to the Cortex XSOAR UI
    If you have some specific errors you want to capture (i.e. auth failure)
    you can catch the exception here and return a string with a more readable
    output (for example return 'Authentication Error, API Key invalid')
    Cortex XSOAR will print everything you return different than 'ok' as an error
    """

    client.search_alerts(max_results=1, start_time=first_fetch_time, alert_status=None, alert_type=None, severity=None)
    return 'ok'


def say_hello_command(client: Client, args: Dict[str, Any]) -> Tuple[str, dict, str]:
    """helloworld-say-hello command: Returns Hello {somename}

    :type client: ``Client``
    :param Client: HelloWorld client to use

    :type args: ``str``
    :param args:
        all command arguments, usually passed from ``demisto.args()``.
        ``args['name']`` is used as input name

    :return:
        A tuple containing three elements that is then passed to ``return_outputs``:
            readable_output (``str``): This will be presented in the war room
                    should be in markdown syntax - human readable
            outputs (``dict``): Dictionary/JSON - saved in the incident context in order
                    to be used as inputs for other tasks in the playbook
            raw_response (``str``): Used for debugging/troubleshooting purposes
                    will be shown only if the command executed with ``raw-response=true``

    :rtype: ``Tuple[str, dict, str]``
    """

    """ INTEGRATION DEVELOPER TIP
    In this case 'name' is an argument set in the HelloWorld.yml file as mandatory,
    so the null check here as XSOAR will always check it before your code is called.
    Although it's not mandatory to check, you are welcome to do so.
    """
    name = args.get('name', None)
    if not name:
        raise ValueError('name not specified')

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


def fetch_incidents(client: Client, last_run: Dict[str, int], first_fetch_time: Optional[int],
                    alert_status: Optional[str], severity: Optional[str],
                    alert_type: Optional[str]) -> Tuple[Dict[str, int], List[dict]]:
    """This function retrieves new alerts every interval (default is 1 minute).

    :type client: ``Client``
    :param Client: HelloWorld client to use

    :type last_run: ``Optional[Dict[str, int]]``
    :param last_run:
        A dict with a key containing the latest incident created time we got from last fetch

    :type first_fetch_time: ``Optional[int]``
    :param first_fetch_time:
        If last_run is None (first time we are fetching), it contains
        the timestamp in milliseconds on when to start fetching incidents

    :type alert_status: ``Optional[str]``
    :param alert_status: status of the alert to search for. Options are: 'ACTIVE' or 'CLOSED'

    :type severity: ``Optional[int]``
    :param severity: severity of the alert to search for. Values are from 0 to 3

    :type alert_type: ``Optional[str]``
    :param alert_type: type of alerts to search for. There is no list of predefined types
    :return:
        A tuple containing two elements:
            next_run (``Dict[str, int]``): Contains the timestamp that will be
                    used in ``last_run`` on the next fetch.
            incidents (``List[dict]``): List of incidents that will be created in XSOAR
    :rtype: ``Tuple[Dict[str, int], List[dict]]``
    """

    # Get the last fetch time, if exists
    last_fetch = last_run.get('last_fetch', None)
    # Handle first fetch time
    if last_fetch is None:
        last_fetch = first_fetch_time
    else:
        last_fetch = int(last_fetch)

    # for type checking, making sure that latest_created_time is int
    latest_created_time = cast(int, last_fetch)

    incidents = []

    alerts = client.search_alerts(
        alert_type=alert_type,
        alert_status=alert_status,
        max_results=MAX_INCIDENTS_TO_FETCH,
        start_time=last_fetch,
        severity=convert_to_helloworld_severity(severity)
    )

    for alert in alerts:
        incident_created_time = int(alert.get('created', 0))
        incident_created_time_ms = incident_created_time * 1000

        incident_name = alert['name']
        incident = {
            'name': incident_name,
            # 'details': alert['name'],
            'occurred': timestamp_to_datestring(incident_created_time_ms),
            'rawJSON': json.dumps(alert),
            # 'type': 'Hello World Alert',
            'severity': convert_to_demisto_severity(alert.get('severity', 0)),
            # 'CustomFields': {
            #     'helloworldid': alert.get('alert_id'),
            #     'helloworldstatus': alert.get('alert_status'),
            #     'helloworldtype': alert.get('alert_type')
            # }
        }

        incidents.append(incident)

        # Update last run and add incident if the incident is newer than last fetch
        if incident_created_time > latest_created_time:
            latest_created_time = incident_created_time

    next_run = {'last_fetch': latest_created_time}
    return next_run, incidents


def ip_reputation_command(client: Client, args: Dict[str, Any], default_threshold: int) -> Tuple[str, dict, Any]:
    """ip command: Returns IP reputation for a list of IPs

    :type client: ``Client``
    :param Client: HelloWorld client to use

    :type args: ``Dict[str, Any]``
    :param args:
        all command arguments, usually passed from ``demisto.args()``.
        ``args['ip']`` is a list of IPs or a single IP
        ``args['threshold']`` threshold to determine whether an IP is malicious

    :type default_threshold: ``int``
    :param default_threshold:
        default threshold to determine whether an IP is malicious
        if threshold is not specified in the XSOAR arguments

    :return:
        A tuple containing three elements that is then passed to ``return_outputs``:
            readable_output (``str``): This will be presented in the war room
                    should be in markdown syntax - human readable
            outputs (``dict``): Dictionary/JSON - saved in the incident context in order
                    to be used as inputs for other tasks in the playbook
            raw_response (``Any``): Used for debugging/troubleshooting purposes
                    will be shown only if the command executed with ``raw-response=true``

    :rtype: ``Tuple[str, dict, Any]``
    """

    ips = argToList(args.get('ip'))
    if len(ips) == 0:
        raise ValueError('IP(s) not specified')

    threshold = int(args.get('threshold', default_threshold))

    dbot_score_list: List[dict] = []
    ip_standard_list: List[dict] = []
    ip_data_list: List[dict] = []

    for ip in ips:
        ip_data = client.get_ip_reputation(ip)
        ip_data['ip'] = ip

        score = 0
        reputation = int(ip_data.get('score', 0))
        if reputation == 0:
            score = 0  # unknown
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
            # if score is bad must add DBotScore Vendor and Description
            ip_standard_context['Malicious'] = {
                'Vendor': 'HelloWorld',
                'Description': f'Hello World returned reputation {reputation}'
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


def domain_reputation_command(client: Client, args: Dict[str, Any], default_threshold: int) -> Tuple[str, dict, Any]:
    """domain command: Returns domain reputation for a list of domains

    :type client: ``Client``
    :param Client: HelloWorld client to use

    :type args: ``Dict[str, Any]``
    :param args:
        all command arguments, usually passed from ``demisto.args()``.
        ``args['domain']`` list of domains or a single domain
        ``args['threshold']`` threshold to determine whether a domain is malicious

    :type default_threshold: ``int``
    :param default_threshold:
        default threshold to determine whether an domain is malicious
        if threshold is not specified in the XSOAR arguments

    :return:
        A tuple containing three elements that is then passed to ``return_outputs``:
            readable_output (``str``): This will be presented in the war room
                    should be in markdown syntax - human readable
            outputs (``dict``): Dictionary/JSON - saved in the incident context in order
                    to be used as inputs for other tasks in the playbook
            raw_response (``Any``): Used for debugging/troubleshooting purposes
                    will be shown only if the command executed with ``raw-response=true``

    :rtype: ``Tuple[str, dict, Any]``
    """

    domains = argToList(args.get('domain'))
    if len(domains) == 0:
        raise ValueError('domain(s) not specified')

    threshold = int(args.get('threshold', default_threshold))

    dbot_score_list: List[dict] = []
    domain_standard_list: List[dict] = []
    domain_data_list: List[dict] = []

    for domain in domains:
        domain_data = client.get_domain_reputation(domain)
        domain_data['domain'] = domain

        score = 0
        reputation = int(domain_data.get('score', 0))
        if reputation == 0:
            score = 0  # unknown
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
            # if score is bad must add DBotScore Vendor and Description
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


def search_alerts_command(client: Client, args: Dict[str, Any]) -> Tuple[str, dict, Any]:
    """helloworld-search-alerts command: Search alerts in HelloWorld

    :type client: ``Client``
    :param Client: HelloWorld client to use

    :type args: ``Dict[str, Any]``
    :param args:
        all command arguments, usually passed from ``demisto.args()``.
        ``args['status']`` alert status. Options are 'ACTIVE' or 'CLOSED'
        ``args['severity']`` alert severity (0 to 3)
        ``args['alert_type']`` alert type
        ``args['start_time']``  start time as ISO8601 date or seconds since epoch
        ``args['max_results']`` maximum number of results to return

    :return:
        A tuple containing three elements that is then passed to ``return_outputs``:
            readable_output (``str``): This will be presented in the war room
                    should be in markdown syntax - human readable
            outputs (``dict``): Dictionary/JSON - saved in the incident context in order
                    to be used as inputs for other tasks in the playbook
            raw_response (``Any``): Used for debugging/troubleshooting purposes
                    will be shown only if the command executed with ``raw-response=true``

    :rtype: ``Tuple[str, dict, Any]``
    """

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


def get_alert_command(client: Client, args: Dict[str, Any]) -> Tuple[str, dict, dict]:
    """helloworld-get-alert command: Returns a HelloWorld alert

    :type client: ``Client``
    :param Client: HelloWorld client to use

    :type args: ``Dict[str, Any]``
    :param args:
        all command arguments, usually passed from ``demisto.args()``.
        ``args['alert_id']`` alert ID to return

    :return:
        A tuple containing three elements that is then passed to ``return_outputs``:
            readable_output (``str``): This will be presented in the war room
                    should be in markdown syntax - human readable
            outputs (``dict``): Dictionary/JSON - saved in the incident context in order
                    to be used as inputs for other tasks in the playbook
            raw_response (``dict``): Used for debugging/troubleshooting purposes
                    will be shown only if the command executed with ``raw-response=true``

    :rtype: ``Tuple[str, dict, dict]``
    """

    alert_id = args.get('alert_id', None)
    if not alert_id:
        raise ValueError('alert_id not specified')

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


def scan_start_command(client: Client, args: Dict[str, Any]) -> Tuple[str, dict, dict]:
    """helloworld-start-scan command: Starts a HelloWorld scan

    :type client: ``Client``
    :param Client: HelloWorld client to use

    :type args: ``Dict[str, Any]``
    :param args:
        all command arguments, usually passed from ``demisto.args()``.
        ``args['hostname']`` hostname to run the scan on

    :return:
        A tuple containing three elements that is then passed to ``return_outputs``:
            readable_output (``str``): This will be presented in the war room
                    should be in markdown syntax - human readable
            outputs (``dict``): Dictionary/JSON - saved in the incident context in order
                    to be used as inputs for other tasks in the playbook
            raw_response (``dict``): Used for debugging/troubleshooting purposes
                    will be shown only if the command executed with ``raw-response=true``

    :rtype: ``Tuple[str, dict, dict]``
    """

    hostname = args.get('hostname', None)
    if not hostname:
        raise ValueError('hostname not specified')

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


def scan_status_command(client: Client, args: Dict[str, Any]) -> Tuple[str, dict, Any]:
    """helloworld-scan-status command: Returns status for HelloWorld scans

    :type client: ``Client``
    :param Client: HelloWorld client to use

    :type args: ``Dict[str, Any]``
    :param args:
        all command arguments, usually passed from ``demisto.args()``.
        ``args['scan_id']`` list of scan IDs or single scan ID

    :return:
        A tuple containing three elements that is then passed to ``return_outputs``:
            readable_output (``str``): This will be presented in the war room
                    should be in markdown syntax - human readable
            outputs (``dict``): Dictionary/JSON - saved in the incident context in order
                    to be used as inputs for other tasks in the playbook
            raw_response (``Any``): Used for debugging/troubleshooting purposes
                    will be shown only if the command executed with ``raw-response=true``

    :rtype: ``Tuple[str, dict, Any]``
    """

    scan_id_list = argToList(args.get('scan_id', []))
    if len(scan_id_list) == 0:
        raise ValueError('scan_id(s) not specified')

    scan_list: List[Dict[str, Any]] = []
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


def scan_results_command(client: Client, args: Dict[str, Any]) -> None:
    """helloworld-scan-results command: Returns results for a HelloWorld scan

    :type client: ``Client``
    :param Client: HelloWorld client to use

    :type args: ``Dict[str, Any]``
    :param args:
        all command arguments, usually passed from ``demisto.args()``.
        ``args['scan_id']`` scan ID to retrieve results
        ``args['format']`` format of the results. Options are 'file' or 'json'

    :return: ``None``, as it calls ``return_outputs()`` or `demisto.results()`` directly
    :rtype:
    """

    scan_id = args.get('scan_id', None)
    if not scan_id:
        raise ValueError('scan_id not specified')

    scan_format = args.get('format', 'file')

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


''' MAIN FUNCTION '''


def main() -> None:
    """main function, parses params and runs command functions

    :return:
    :rtype:
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
    # Using assert as a type guard (since first_fetch_time is always an int when required=True)
    assert isinstance(first_fetch_time, int)

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
            alert_status = demisto.params().get('alert_status', None)
            alert_type = demisto.params().get('alert_type', None)
            severity = demisto.params().get('severity', None)

            next_run, incidents = fetch_incidents(
                client=client,
                last_run=demisto.getLastRun(),
                first_fetch_time=first_fetch_time,
                alert_status=alert_status,
                severity=severity,
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


''' ENTRY POINT '''


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
