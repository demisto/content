import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *

import json
import urllib3
import dateparser
import traceback
from typing import Any, Dict, Tuple, List, Optional, Union, cast

# Disable insecure warnings
urllib3.disable_warnings()


''' CONSTANTS '''


DATE_FORMAT = '%Y-%m-%dT%H:%M:%SZ'
MAX_INCIDENTS_TO_FETCH = 50
HELLOWORLD_SEVERITIES = ['Low', 'Medium', 'High', 'Critical']

''' CLIENT CLASS '''


class Client(BaseClient):

    def list_report(self, url_suffix) -> Dict[str, Any]:
        return self._http_request(
            method='GET',
            url_suffix=url_suffix
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
            url_suffix='/domain',
            params={
                'domain': domain
            }
        )

    def search_alerts(self, alert_status: Optional[str], severity: Optional[str],
                      alert_type: Optional[str], max_results: Optional[int],
                      start_time: Optional[int]) -> List[Dict[str, Any]]:
        """Searches for HelloWorld alerts using the '/get_alerts' API endpoint

        All the parameters are passed directly to the API as HTTP POST parameters in the request

        :type alert_status: ``Optional[str]``
        :param alert_status: status of the alert to search for. Options are: 'ACTIVE' or 'CLOSED'

        :type severity: ``Optional[str]``
        :param severity:
            severity of the alert to search for. Comma-separated values.
            Options are: "Low", "Medium", "High", "Critical"

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
            url_suffix='/get_alerts',
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
            url_suffix='/get_alert_details',
            params={
                'alert_id': alert_id
            }
        )

    def update_alert_status(self, alert_id: str, alert_status: str) -> Dict[str, Any]:
        """Changes the status of a specific HelloWorld alert

        :type alert_id: ``str``
        :param alert_id: id of the alert to return

        :type alert_status: ``str``
        :param alert_status: new alert status. Options are: 'ACTIVE' or 'CLOSED'

        :return: dict containing the alert as returned from the API
        :rtype: ``Dict[str, Any]``
        """

        return self._http_request(
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
        """Returns 'Hello {name}'

        :type name: ``str``
        :param name: name to append to the 'Hello' string

        :return: string containing 'Hello {name}'
        :rtype: ``str``
        """

        return f'Hello {name}'


''' HELPER FUNCTIONS '''


def parse_domain_date(domain_date: Union[List[str], str], date_format: str = '%Y-%m-%dT%H:%M:%S.000Z') -> Optional[str]:
    """Converts whois date format to an ISO8601 string

    Converts the HelloWorld domain WHOIS date (YYYY-mm-dd HH:MM:SS) format
    in a datetime. If a list is returned with multiple elements, takes only
    the first one.

    :type domain_date: ``Union[List[str],str]``
    :param severity:
        a string or list of strings with the format 'YYYY-mm-DD HH:MM:SS'

    :return: Parsed time in ISO8601 format
    :rtype: ``Optional[str]``
    """

    if isinstance(domain_date, str):
        # if str parse the value
        return dateparser.parse(domain_date).strftime(date_format)
    elif isinstance(domain_date, list) and len(domain_date) > 0 and isinstance(domain_date[0], str):
        # if list with at least one element, parse the first element
        return dateparser.parse(domain_date[0]).strftime(date_format)
    # in any other case return nothing
    return None


def convert_to_demisto_severity(severity: str) -> int:
    """Maps HelloWorld severity to Cortex XSOAR severity

    Converts the HelloWorld alert severity level ('Low', 'Medium',
    'High', 'Critical') to Cortex XSOAR incident severity (1 to 4)
    for mapping.

    :type severity: ``str``
    :param severity: severity as returned from the HelloWorld API (str)

    :return: Cortex XSOAR Severity (1 to 4)
    :rtype: ``int``
    """

    # In this case the mapping is straightforward, but more complex mappings
    # might be required in your integration, so a dedicated function is
    # recommended. This mapping should also be documented.
    return {
        'Low': 1,  # low severity
        'Medium': 2,  # medium severity
        'High': 3,  # high severity
        'Critical': 4   # critical severity
    }[severity]


def arg_to_int(arg: Any, arg_name: str, required: bool = False) -> Optional[int]:
    """Converts an XSOAR argument to a Python int

    This function is used to quickly validate an argument provided to XSOAR
    via ``demisto.args()`` into an ``int`` type. It will throw a ValueError
    if the input is invalid. If the input is None, it will throw a ValueError
    if required is ``True``, or ``None`` if required is ``False.

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

    This function is used to quickly validate an argument provided to XSOAR
    via ``demisto.args()`` into an ``int`` containing a timestamp (seconds
    since epoch). It will throw a ValueError if the input is invalid.
    If the input is None, it will throw a ValueError if required is ``True``,
    or ``None`` if required is ``False.

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
        # timestamp is a str containing digits - we just convert it to int
        return int(arg)
    if isinstance(arg, str):
        # we use dateparser to handle strings either in ISO8601 format, or
        # relative time stamps.
        # For example: format 2019-10-23T00:00:00 or "3 days", etc
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
        client.search_alerts(max_results=1, start_time=first_fetch_time, alert_status=None, alert_type=None, severity=None)
    except DemistoException as e:
        if 'Forbidden' in str(e):
            return 'Authorization Error: make sure API Key is correctly set'
        else:
            raise e
    return 'ok'


def say_hello_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    """helloworld-say-hello command: Returns Hello {somename}

    :type client: ``Client``
    :param Client: HelloWorld client to use

    :type args: ``str``
    :param args:
        all command arguments, usually passed from ``demisto.args()``.
        ``args['name']`` is used as input name

    :return:
        A ``CommandResults`` object that is then passed to ``return_results``,
        that contains the hello world message

    :rtype: ``CommandResults``
    """

    # INTEGRATION DEVELOPER TIP
    # In this case 'name' is an argument set in the HelloWorld.yml file as mandatory,
    # so the null check here as XSOAR will always check it before your code is called.
    # Although it's not mandatory to check, you are welcome to do so.

    name = args.get('name', None)
    if not name:
        raise ValueError('name not specified')

    # Call the Client function and get the raw response
    result = client.say_hello(name)

    # Create the human readable output.
    # It will  be in markdown format - https://www.markdownguide.org/basic-syntax/
    # More complex output can be formatted using ``tableToMarkDown()`` defined
    # in ``CommonServerPython.py``
    readable_output = f'## {result}'

    # More information about Context:
    # https://xsoar.pan.dev/docs/integrations/context-and-outputs
    # We return a ``CommandResults`` object, and we want to pass a custom
    # markdown here, so the argument ``readable_output`` is explicit. If not
    # passed, ``CommandResults``` will do a ``tableToMarkdown()`` do the data
    # to generate the readable output.
    return CommandResults(
        readable_output=readable_output,
        outputs_prefix='hello',
        outputs_key_field='',
        outputs=result
    )


def fetch_incidents(client: Client, max_results: int, last_run: Dict[str, int],
                    first_fetch_time: Optional[int], alert_status: Optional[str],
                    min_severity: str, alert_type: Optional[str]
                    ) -> Tuple[Dict[str, int], List[dict]]:
    """This function retrieves new alerts every interval (default is 1 minute).

    This function has to implement the logic of making sure that incidents are
    fetched only onces and no incidents are missed. By default it's invoked by
    XSOAR every minute. It will use last_run to save the timestamp of the last
    incident it processed. If last_run is not provided, it should use the
    integration parameter first_fetch_time to determine when to start fetching
    the first time.

    :type client: ``Client``
    :param Client: HelloWorld client to use

    :type max_results: ``int``
    :param max_results: Maximum numbers of incidents per fetch

    :type last_run: ``Optional[Dict[str, int]]``
    :param last_run:
        A dict with a key containing the latest incident created time we got
        from last fetch

    :type first_fetch_time: ``Optional[int]``
    :param first_fetch_time:
        If last_run is None (first time we are fetching), it contains
        the timestamp in milliseconds on when to start fetching incidents

    :type alert_status: ``Optional[str]``
    :param alert_status:
        status of the alert to search for. Options are: 'ACTIVE'
        or 'CLOSED'

    :type min_severity: ``str``
    :param min_severity:
        minimum severity of the alert to search for.
        Options are: "Low", "Medium", "High", "Critical"

    :type alert_type: ``Optional[str]``
    :param alert_type:
        type of alerts to search for. There is no list of predefined types

    :return:
        A tuple containing two elements:
            next_run (``Dict[str, int]``): Contains the timestamp that will be
                    used in ``last_run`` on the next fetch.
            incidents (``List[dict]``): List of incidents that will be created in XSOAR

    :rtype: ``Tuple[Dict[str, int], List[dict]]``
    """

    # Get the last fetch time, if exists
    # last_run is a dict with a single key, called last_fetch
    last_fetch = last_run.get('last_fetch', None)
    # Handle first fetch time
    if last_fetch is None:
        # if missing, use what provided via first_fetch_time
        last_fetch = first_fetch_time
    else:
        # otherwise use the stored last fetch
        last_fetch = int(last_fetch)

    # for type checking, making sure that latest_created_time is int
    latest_created_time = cast(int, last_fetch)

    # Initialize an empty list of incidents to return
    # Each incident is a dict with a string as a key
    incidents: List[Dict[str, Any]] = []

    # Get the CSV list of severities from min_severity
    severity = ','.join(HELLOWORLD_SEVERITIES[HELLOWORLD_SEVERITIES.index(min_severity):])

    alerts = client.search_alerts(
        alert_type=alert_type,
        alert_status=alert_status,
        max_results=max_results,
        start_time=last_fetch,
        severity=severity
    )

    for alert in alerts:
        # If no created_time set is as epoch (0). We use time in ms so we must
        # convert it from the HelloWorld API response
        incident_created_time = int(alert.get('created', '0'))
        incident_created_time_ms = incident_created_time * 1000

        # to prevent duplicates, we are only adding incidents with creation_time > last fetched incident
        if last_fetch:
            if incident_created_time <= last_fetch:
                continue

        # If no name is present it will throw an exception
        incident_name = alert['name']

        # INTEGRATION DEVELOPER TIP
        # The incident dict is initialized with a few mandatory fields:
        # name: the incident name
        # occurred: the time on when the incident occurred, in ISO8601 format
        # we use timestamp_to_datestring() from CommonServerPython.py to
        # handle the conversion.
        # rawJSON: everything else is packed in a string via json.dumps()
        # and is included in rawJSON. It will be used later for classification
        # and mapping inside XSOAR.
        # severity: it's not mandatory, but is recommended. It must be
        # converted to XSOAR specific severity (int 1 to 4)
        # Note that there are other fields commented out here. You can do some
        # mapping of fields (either out of the box fields, like "details" and
        # "type") or custom fields (like "helloworldid") directly here in the
        # code, or they can be handled in the classification and mapping phase.
        # In either case customers can override them. We leave the values
        # commented out here, but you can use them if you want.
        incident = {
            'name': incident_name,
            # 'details': alert['name'],
            'occurred': timestamp_to_datestring(incident_created_time_ms),
            'rawJSON': json.dumps(alert),
            # 'type': 'Hello World Alert',  # Map to a specific XSOAR incident Type
            'severity': convert_to_demisto_severity(alert.get('severity', 'Low')),
            # 'CustomFields': {  # Map specific XSOAR Custom Fields
            #     'helloworldid': alert.get('alert_id'),
            #     'helloworldstatus': alert.get('alert_status'),
            #     'helloworldtype': alert.get('alert_type')
            # }
        }

        incidents.append(incident)

        # Update last run and add incident if the incident is newer than last fetch
        if incident_created_time > latest_created_time:
            latest_created_time = incident_created_time

    # Save the next_run as a dict with the last_fetch key to be stored
    next_run = {'last_fetch': latest_created_time}
    return next_run, incidents


def ip_reputation_command(client: Client, args: Dict[str, Any], default_threshold: int) -> CommandResults:
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
        A ``CommandResults`` object that is then passed to ``return_results``,
        that contains IPs

    :rtype: ``CommandResults``
    """

    # INTEGRATION DEVELOPER TIP
    # Reputation commands usually support multiple inputs (i.e. arrays), so
    # they can be invoked once in XSOAR. In this case the API supports a single
    # IP at a time, so we will cycle this for all the members of the array.
    # We use argToList(), implemented in CommonServerPython.py to automatically
    # return a list of a single element even if the provided input is a scalar.

    ips = argToList(args.get('ip'))
    if len(ips) == 0:
        raise ValueError('IP(s) not specified')

    # It's a good practice to document the threshold you use to determine
    # if a score is malicious in your integration documentation.
    # Thresholds should also be possible to override, as in this case,
    # where threshold is an actual argument of the command.
    threshold = int(args.get('threshold', default_threshold))

    # Context standard for IP class
    ip_standard_list: List[Common.IP] = []
    ip_data_list: List[Dict[str, Any]] = []

    for ip in ips:
        ip_data = client.get_ip_reputation(ip)
        ip_data['ip'] = ip

        # HelloWorld score to XSOAR reputation mapping
        # See: https://xsoar.pan.dev/docs/integrations/dbot
        # We are using Common.DBotScore as macros to simplify
        # the mapping.

        score = 0
        reputation = int(ip_data.get('score', 0))
        if reputation == 0:
            score = Common.DBotScore.NONE  # unknown
        elif reputation >= threshold:
            score = Common.DBotScore.BAD  # bad
        elif reputation >= threshold / 2:
            score = Common.DBotScore.SUSPICIOUS  # suspicious
        else:
            score = Common.DBotScore.GOOD  # good

        # The context is bigger here than other commands, as it consists in 3
        # parts: the vendor-specific context (HelloWorld), the standard-context
        # (IP) and the DBotScore.
        # More information:
        # https://xsoar.pan.dev/docs/integrations/context-and-outputs
        # https://xsoar.pan.dev/docs/integrations/context-standards
        # https://xsoar.pan.dev/docs/integrations/dbot
        # Also check the HelloWorld Design Document

        # Create the DBotScore structure first using the Common.DBotScore class.
        dbot_score = Common.DBotScore(
            indicator=ip,
            indicator_type=DBotScoreType.IP,
            integration_name='HelloWorld',
            score=score,
            malicious_description=f'Hello World returned reputation {reputation}'
        )

        # Create the IP Standard Context structure using Common.IP and add
        # dbot_score to it.
        ip_standard_context = Common.IP(
            ip=ip,
            asn=ip_data.get('asn'),
            dbot_score=dbot_score
        )

        ip_standard_list.append(ip_standard_context)

        # INTEGRATION DEVELOPER TIP
        # In the integration specific Context output (HelloWorld.IP) in this
        # example you want to provide a lot of information as it can be used
        # programmatically from within Cortex XSOAR in playbooks and commands.
        # On the other hand, this API is way to verbose, so we want to select
        # only certain keys to be returned in order not to clog the context
        # with useless information. What to actually return in the context and
        # to define as a command output is subject to design considerations.

        # INTEGRATION DEVELOPER TIP
        # To generate the Context Outputs on the YML use ``demisto-sdk``'s
        # ``json-to-outputs`` option.

        # Define which fields we want to exclude from the context output as
        # they are too verbose.
        ip_context_excluded_fields = ['objects', 'nir']
        ip_data_list.append({k: ip_data[k] for k in ip_data if k not in ip_context_excluded_fields})

    # In this case we want to use an custom markdown to specify the table title,
    # but otherwise ``CommandResults()`` will call ``tableToMarkdown()``
    #  automatically
    readable_output = tableToMarkdown('IP List', ip_data_list)

    # INTEGRATION DEVELOPER TIP
    # The output key will be ``HelloWorld.IP``, using ``ip`` as the key field.
    # ``indicators`` is used to provide the context standard (IP)
    return CommandResults(
        readable_output=readable_output,
        outputs_prefix='HelloWorld.IP',
        outputs_key_field='ip',
        outputs=ip_data_list,
        indicators=ip_standard_list
    )


def domain_reputation_command(client: Client, args: Dict[str, Any], default_threshold: int) -> CommandResults:
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
        A ``CommandResults`` object that is then passed to ``return_results``,
        that contains Domains

    :rtype: ``CommandResults``
    """

    # INTEGRATION DEVELOPER TIP
    # Reputation commands usually support multiple inputs (i.e. arrays), so
    # they can be invoked once in XSOAR. In this case the API supports a single
    # IP at a time, so we will cycle this for all the members of the array.
    # We use argToList(), implemented in CommonServerPython.py to automatically
    # return a list of a single element even if the provided input is a scalar.

    domains = argToList(args.get('domain'))
    if len(domains) == 0:
        raise ValueError('domain(s) not specified')

    threshold = int(args.get('threshold', default_threshold))

    # Context standard for Domain class
    domain_standard_list: List[Common.Domain] = []

    domain_data_list: List[Dict[str, Any]] = []

    for domain in domains:
        domain_data = client.get_domain_reputation(domain)
        domain_data['domain'] = domain

        # INTEGRATION DEVELOPER TIP
        # We want to convert the dates to ISO8601 as
        # Cortex XSOAR customers and integrations use this format by default
        if 'creation_date' in domain_data:
            domain_data['creation_date'] = parse_domain_date(domain_data['creation_date'])
        if 'expiration_date' in domain_data:
            domain_data['expiration_date'] = parse_domain_date(domain_data['expiration_date'])
        if 'updated_date' in domain_data:
            domain_data['updated_date'] = parse_domain_date(domain_data['updated_date'])

        # HelloWorld score to XSOAR reputation mapping
        # See: https://xsoar.pan.dev/docs/integrations/dbot
        # We are using Common.DBotScore as macros to simplify
        # the mapping.

        score = 0
        reputation = int(domain_data.get('score', 0))
        if reputation == 0:
            score = Common.DBotScore.NONE  # unknown
        elif reputation >= threshold:
            score = Common.DBotScore.BAD  # bad
        elif reputation >= threshold / 2:
            score = Common.DBotScore.SUSPICIOUS  # suspicious
        else:
            score = Common.DBotScore.GOOD  # good

        # INTEGRATION DEVELOPER TIP
        # The context is bigger here than other commands, as it consists in 3
        # parts: the vendor-specific context (HelloWorld), the standard-context
        # (Domain) and the DBotScore.
        # More information:
        # https://xsoar.pan.dev/docs/integrations/context-and-outputs
        # https://xsoar.pan.dev/docs/integrations/context-standards
        # https://xsoar.pan.dev/docs/integrations/dbot
        # Also check the sample Design Document

        dbot_score = Common.DBotScore(
            indicator=domain,
            integration_name='HelloWorld',
            indicator_type=DBotScoreType.DOMAIN,
            score=score,
            malicious_description=f'Hello World returned reputation {reputation}'
        )

        # Create the Domain Standard Context structure using Common.Domain and
        # add dbot_score to it.
        domain_standard_context = Common.Domain(
            domain=domain,
            creation_date=domain_data.get('creation_date', None),
            expiration_date=domain_data.get('expiration_date', None),
            updated_date=domain_data.get('updated_date', None),
            organization=domain_data.get('org', None),
            name_servers=domain_data.get('name_servers', None),
            registrant_name=domain_data.get('name', None),
            registrant_country=domain_data.get('country', None),
            registrar_name=domain_data.get('registrar', None),
            dbot_score=dbot_score
        )

        domain_standard_list.append(domain_standard_context)
        domain_data_list.append(domain_data)

    # In this case we want to use an custom markdown to specify the table title,
    # but otherwise ``CommandResults()`` will call ``tableToMarkdown()``
    #  automatically
    readable_output = tableToMarkdown('Domain List', domain_data_list)

    # INTEGRATION DEVELOPER TIP
    # The output key will be ``HelloWorld.Domain``, using ``domain`` as the key
    # field.
    # ``indicators`` is used to provide the context standard (Domain)
    return CommandResults(
        readable_output=readable_output,
        outputs_prefix='HelloWorld.Domain',
        outputs_key_field='domain',
        outputs=domain_data_list,
        indicators=domain_standard_list
    )


def search_alerts_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    """helloworld-search-alerts command: Search alerts in HelloWorld

    :type client: ``Client``
    :param Client: HelloWorld client to use

    :type args: ``Dict[str, Any]``
    :param args:
        all command arguments, usually passed from ``demisto.args()``.
        ``args['status']`` alert status. Options are 'ACTIVE' or 'CLOSED'
        ``args['severity']`` alert severity CSV
        ``args['alert_type']`` alert type
        ``args['start_time']``  start time as ISO8601 date or seconds since epoch
        ``args['max_results']`` maximum number of results to return

    :return:
        A ``CommandResults`` object that is then passed to ``return_results``,
        that contains alerts

    :rtype: ``CommandResults``
    """

    status = args.get('status')

    # Check if severity contains allowed values, use all if default
    severities: List[str] = HELLOWORLD_SEVERITIES
    severity = args.get('severity', None)
    if severity:
        severities = severity.split(',')
        if not all(s in HELLOWORLD_SEVERITIES for s in severities):
            raise ValueError(
                f'severity must be a comma-separated value '
                f'with the following options: {",".join(HELLOWORLD_SEVERITIES)}')

    alert_type = args.get('alert_type')

    # Convert the argument to a timestamp using helper function
    start_time = arg_to_timestamp(
        arg=args.get('start_time'),
        arg_name='start_time',
        required=False
    )

    # Convert the argument to an int using helper function
    max_results = arg_to_int(
        arg=args.get('max_results'),
        arg_name='max_results',
        required=False
    )

    # Severity is passed to the API as a CSV
    alerts = client.search_alerts(
        severity=','.join(severities),
        alert_status=status,
        alert_type=alert_type,
        start_time=start_time,
        max_results=max_results
    )

    # INTEGRATION DEVELOPER TIP
    # We want to convert the "created" time from timestamp(s) to ISO8601 as
    # Cortex XSOAR customers and integrations use this format by default
    for alert in alerts:
        if 'created' not in alert:
            continue
        created_time_ms = int(alert.get('created', '0')) * 1000
        alert['created'] = timestamp_to_datestring(created_time_ms)

    # in this example we are not providing a custom markdown, we will
    # let ``CommandResults`` generate it by default.
    return CommandResults(
        outputs_prefix='HelloWorld.Alert',
        outputs_key_field='alert_id',
        outputs=alerts
    )


def get_alert_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    """helloworld-get-alert command: Returns a HelloWorld alert

    :type client: ``Client``
    :param Client: HelloWorld client to use

    :type args: ``Dict[str, Any]``
    :param args:
        all command arguments, usually passed from ``demisto.args()``.
        ``args['alert_id']`` alert ID to return

    :return:
        A ``CommandResults`` object that is then passed to ``return_results``,
        that contains an alert

    :rtype: ``CommandResults``
    """

    alert_id = args.get('alert_id', None)
    if not alert_id:
        raise ValueError('alert_id not specified')

    alert = client.get_alert(alert_id=alert_id)

    # INTEGRATION DEVELOPER TIP
    # We want to convert the "created" time from timestamp(s) to ISO8601 as
    # Cortex XSOAR customers and integrations use this format by default
    if 'created' in alert:
        created_time_ms = int(alert.get('created', '0')) * 1000
        alert['created'] = timestamp_to_datestring(created_time_ms)

    # tableToMarkdown() is defined is CommonServerPython.py and is used very
    # often to convert lists and dicts into a human readable format in markdown
    readable_output = tableToMarkdown(f'HelloWorld Alert {alert_id}', alert)

    return CommandResults(
        readable_output=readable_output,
        outputs_prefix='HelloWorld.Alert',
        outputs_key_field='alert_id',
        outputs=alert
    )


def update_alert_status_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    """helloworld-update-alert-status command: Changes the status of an alert

    Changes the status of a HelloWorld alert and returns the updated alert info

    :type client: ``Client``
    :param Client: HelloWorld client to use

    :type args: ``Dict[str, Any]``
    :param args:
        all command arguments, usually passed from ``demisto.args()``.
        ``args['alert_id']`` alert ID to update
        ``args['status']`` new status, either ACTIVE or CLOSED

    :return:
        A ``CommandResults`` object that is then passed to ``return_results``,
        that contains an updated alert

    :rtype: ``CommandResults``
    """

    alert_id = args.get('alert_id', None)
    if not alert_id:
        raise ValueError('alert_id not specified')

    status = args.get('status', None)
    if status not in ('ACTIVE', 'CLOSED'):
        raise ValueError('status must be either ACTIVE or CLOSED')

    alert = client.update_alert_status(alert_id, status)

    # INTEGRATION DEVELOPER TIP
    # We want to convert the "updated" time from timestamp(s) to ISO8601 as
    # Cortex XSOAR customers and integrations use this format by default
    if 'updated' in alert:
        updated_time_ms = int(alert.get('updated', '0')) * 1000
        alert['updated'] = timestamp_to_datestring(updated_time_ms)

    # tableToMarkdown() is defined is CommonServerPython.py and is used very
    # often to convert lists and dicts into a human readable format in markdown
    readable_output = tableToMarkdown(f'HelloWorld Alert {alert_id}', alert)

    return CommandResults(
        readable_output=readable_output,
        outputs_prefix='HelloWorld.Alert',
        outputs_key_field='alert_id',
        outputs=alert
    )


def scan_start_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    """helloworld-start-scan command: Starts a HelloWorld scan

    :type client: ``Client``
    :param Client: HelloWorld client to use

    :type args: ``Dict[str, Any]``
    :param args:
        all command arguments, usually passed from ``demisto.args()``.
        ``args['hostname']`` hostname to run the scan on

    :return:
        A ``CommandResults`` object that is then passed to ``return_results``,
        that contains a scan job

    :rtype: ``CommandResults``
    """

    hostname = args.get('hostname', None)
    if not hostname:
        raise ValueError('hostname not specified')

    scan = client.scan_start(hostname=hostname)

    # INTEGRATION DEVELOPER TIP
    # The API doesn't return the hostname of the scan it was called against,
    # which is the input. It could be useful to have that information in the
    # XSOAR context, so we are adding it manually here, based on the command
    # input argument.
    scan['hostname'] = hostname

    scan_id = scan.get('scan_id')

    readable_output = f'Started scan {scan_id}'

    return CommandResults(
        readable_output=readable_output,
        outputs_prefix='HelloWorld.Scan',
        outputs_key_field='scan_id',
        outputs=scan
    )


def scan_status_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    """helloworld-scan-status command: Returns status for HelloWorld scans

    :type client: ``Client``
    :param Client: HelloWorld client to use

    :type args: ``Dict[str, Any]``
    :param args:
        all command arguments, usually passed from ``demisto.args()``.
        ``args['scan_id']`` list of scan IDs or single scan ID

    :return:
        A ``CommandResults`` object that is then passed to ``return_results``,
        that contains a scan status

    :rtype: ``CommandResults``
    """

    scan_id_list = argToList(args.get('scan_id', []))
    if len(scan_id_list) == 0:
        raise ValueError('scan_id(s) not specified')

    scan_list: List[Dict[str, Any]] = []
    for scan_id in scan_id_list:
        scan = client.scan_status(scan_id=scan_id)
        scan_list.append(scan)

    readable_output = tableToMarkdown('Scan status', scan_list)

    return CommandResults(
        readable_output=readable_output,
        outputs_prefix='HelloWorld.Scan',
        outputs_key_field='scan_id',
        outputs=scan_list
    )


def build_url_params_for_list_report(args):
    start_date = args.get('start_date')
    end_date = args.get('end_date')
    device_type = args.get('device_type')
    url_params = f'?startDate={start_date}&endDate={end_date}&device_type={device_type}'

    arguments = assign_params(**args)

    for key, value in arguments.items():
        if key == 'offset':
            limit = arguments.get('limit')
            url_params += f'&{key}={int(value)}&limit={int(limit)}'

        if key == 'filter_key':
            filter_operator = arguments.get('filter_operator')
            filter_value = arguments.get('filter_value')
            url_params += f'&filterBy={value}&filter_operator={filter_operator}&filter_value{filter_value}'

        if key == 'device_group':
            url_params += f'&{key}={value}'
        if key == 'device_name':
            url_params += f'&{key}={value}'

    return url_params


def list_report_command(client: Client, args: Dict[str, Any]):
    url_suffix = '/api/v2.0/reporting'
    url_params = build_url_params_for_list_report(args)
    url_to_search_with = url_suffix + url_params
    report_response_data = client.list_report(url_to_search_with)
    return CommandResults(
        readable_output='human_readable',
        outputs_prefix='MicrosoftCloudAppSecurity.Alerts',
        outputs_key_field='_id',
        outputs=report_response_data
    )


def build_url_params_for_list_messages(args):
    start_date = args.get('start_date')
    end_date = args.get('end_date')
    url_params = f'?startDate={start_date}&endDate={end_date}'

    arguments = assign_params(**args)

    for key, value in arguments.items():
        if key == 'offset':
            limit = arguments.get('limit')
            url_params += f'&{key}={value}&limit={limit}'

        if key == 'attachment_name_value':
            attachment_name_operator = arguments.get('attachment_name_operator', 'is')
            url_params += f'&attachmentNameOperator={attachment_name_operator}&attachmentNameValue={value}'

        if key == 'recipient_filter_value':
            recipient_operator = arguments.get('recipient_filter_operator', 'is')
            url_params += f'&envelopeRecipientfilterOperator={recipient_operator}&envelopeRecipientfilterValue={value}'

        if key == 'sender_filter_value':
            sender_filter_operator = arguments.get('sender_filter_operator')
            url_params += f'&envelopeSenderfilterOperator={sender_filter_operator}&envelopeSenderfilterValue={value}'

        if key == 'subject_filter_value':
            subject_filter_operator = arguments.get('subject_filter_operator')
            url_params += f'&subjectfilterOperator={subject_filter_operator}&subjectfilterValue={value}'

        if key == 'domain_name_value':
            domain_name_operator = arguments.get('domain_name_operator')
            url_params += f'&domainNameOperator={domain_name_operator}&domainNameValue={value}'

        if key == 'file_hash':
            url_params += f'&fileSha256={value}'
        if key == 'message_id':
            url_params += f'&messageIdHeader={value}'
        if key == 'cisco_message_id':
            url_params += f'&ciscoMid={value}'
        if key == 'sender_ip':
            url_params += f'&senderIp={value}'
        if key == 'message_direction':
            url_params += f'&messageDirection={value}'
        if key == 'spam_positive':
            url_params += f'&spamPositive={value}'
        if key == 'quarantined_as_spam':
            url_params += f'&quarantinedAsSpam={value}'
        if key == 'quarantine_status':
            url_params += f'&quarantineStatus={value}'
        if key == 'url_reputation':
            url_params += f'&urlReputation={value}'
        if key == 'virus_positive':
            url_params += f'&virusPositive={value}'
        if key == 'contained_malicious_urls':
            url_params += f'&containedMaliciousUrls={value}'
        if key == 'contained_neutral_urls':
            url_params += f'&containedNeutralUrls={value}'
        if key == 'macro_file_types_detected':
            url_params += f'&macroFileTypesDetected={value}'

    return url_params


def list_messages_command(client, args):
    url_suffix = '/esa/api/v2.0/message-tracking/messages'
    url_params = build_url_params_for_list_messages(args)
    url_to_search_with = url_suffix + url_params
    report_response_data = client.list_report(url_to_search_with)
    return CommandResults(
        readable_output='human_readable',
        outputs_prefix='MicrosoftCloudAppSecurity.Alerts',
        outputs_key_field='_id',
        outputs=report_response_data
    )


''' MAIN FUNCTION '''


def main() -> None:

    params = demisto.params()
    args = demisto.args()

    api_key = params.get('apikey')

    base_url = urljoin(params.get('url'), '/api/v1')

    verify_certificate = not params.get('insecure', False)

    first_fetch_time = arg_to_timestamp(
        arg=params.get('first_fetch', '3 days'),
        arg_name='First fetch time',
        required=True
    )
    assert isinstance(first_fetch_time, int)

    proxy = params.get('proxy', False)

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
            result = test_module(client, first_fetch_time)
            return_results(result)

        elif demisto.command() == 'fetch-incidents':
            alert_status = params.get('alert_status', None)
            alert_type = params.get('alert_type', None)
            min_severity = params.get('min_severity', None)

            # Convert the argument to an int using helper function or set to MAX_INCIDENTS_TO_FETCH
            max_results = arg_to_int(
                arg=demisto.params().get('max_fetch'),
                arg_name='max_fetch',
                required=False
            )
            if not max_results or max_results > MAX_INCIDENTS_TO_FETCH:
                max_results = MAX_INCIDENTS_TO_FETCH

            next_run, incidents = fetch_incidents(
                client=client,
                max_results=max_results,
                last_run=demisto.getLastRun(),  # getLastRun() gets the last run dict
                first_fetch_time=first_fetch_time,
                alert_status=alert_status,
                min_severity=min_severity,
                alert_type=alert_type
            )

            demisto.setLastRun(next_run)
            demisto.incidents(incidents)

        elif demisto.command() == 'cisco-email-security-report-get':
            return_results(list_report_command(client, args))
        elif demisto.command() == 'cisco-email-security-messages-search':
            return_results(list_messages_command(client, args))

    # Log exceptions and return errors
    except Exception as e:
        demisto.error(traceback.format_exc())  # print the traceback
        return_error(f'Failed to execute {demisto.command()} command.\nError:\n{str(e)}')


''' ENTRY POINT '''


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
