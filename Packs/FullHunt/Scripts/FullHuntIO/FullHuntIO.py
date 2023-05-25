import json
import requests
import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
"""Base Script for Cortex XSOAR (aka Demisto)
This is an empty script with some basic structure according
to the code conventions.
MAKE SURE YOU REVIEW/REPLACE ALL THE COMMENTS MARKED AS "TODO"
Developer Documentation: https://xsoar.pan.dev/docs/welcome
Code Conventions: https://xsoar.pan.dev/docs/integrations/code-conventions
Linting: https://xsoar.pan.dev/docs/integrations/linting
"""

import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *

''' IMPORTS '''


''' CONSTANTS '''

URL = 'https://fullhunt.io/api/v1/'
APIKEY = demisto.params().get("api_key")


EXCEPTION_MESSAGES = {
    "API_RATE_LIMIT": "API Rate limit hit. Try after sometime.",
    "UNAUTHENTICATED": "Unauthenticated. Check the configured API Key.",
    "COMMAND_FAIL": "Failed to execute {} command.\n Error: {}",
    "SERVER_ERROR": "The server encountered an internal error and was unable to complete your request.",
    "CONNECTION_TIMEOUT": "Connection timed out. Check your network connectivity.",
    "PROXY": "Proxy Error - cannot connect to proxy. Either try clearing the "
    "'Use system proxy' check-box or check the host, "
    "authentication details and connection details for the proxy.",
    "INVALID_RESPONSE": "Invalid response from FullHunt. Response: {}",
    "QUERY_STATS_RESPONSE": "FullHunt request failed. Reason: {}",
}


''' CLIENT CLASS '''


class Client(BaseClient):
    """Client class to interact with the service API
    This Client implements API calls, and does not contain any Demisto logic.
    Should only do requests and return data.
    It inherits from BaseClient defined in CommonServer Python.
    Most calls use _http_request() that handles proxy, SSL verification, etc.
    For this HelloWorld implementation, no special attributes defined
    """

    def get_domain_reputation(self, domain: str) -> Dict[str, Any]:
        """
        Gets the Domain reputation using the '/domain' API endpoint.
        Args:
            domain (str): Domain name to get the reputation for.
        Returns:
            dict: dict containing the domain reputation as returned from the API.
        """

        return self._http_request(
            method='GET',
            url_suffix='/domain',
            params={
                'domain': domain
            }
        )


''' STANDALONE FUNCTION '''


''' COMMAND FUNCTION '''


def test_module(client: Client, params: Dict[str, Any], first_fetch_time: int) -> str:
    """
    Tests API connectivity and authentication'
    When 'ok' is returned it indicates the integration works like it is supposed to and connection to the service is
    successful.
    Raises exceptions if something goes wrong.
    Args:
        client (Client): HelloWorld client to use.
        params (Dict): Integration parameters.
        first_fetch_time (int): The first fetch time as configured in the integration params.
    Returns:
        str: 'ok' if test passed, anything else will raise an exception and will fail the test.
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
        if params.get('isFetch'):  # Tests fetch incident:
            alert_status = params.get('alert_status', None)
            alert_type = params.get('alert_type', None)
            min_severity = params.get('min_severity', None)

            fetch_incidents(
                client=client,
                max_results=1,
                last_run={},
                first_fetch_time=first_fetch_time,
                alert_status=alert_status,
                min_severity=min_severity,
                alert_type=alert_type
            )
        else:
            client.search_alerts(max_results=1, start_time=first_fetch_time, alert_status=None, alert_type=None,
                                 severity=None)

    except DemistoException as e:
        if 'Forbidden' in str(e):
            return 'Authorization Error: make sure API Key is correctly set'
        else:
            raise e

    return 'ok'


def domain_reputation_command(client: Client, args: Dict[str, Any], default_threshold: int,
                              reliability: DBotScoreReliability) -> List[CommandResults]:
    """
    domain command: Returns domain reputation for a list of domains.
    Args:
        client (Client): HelloWorld client to use.
        args (dict): all command arguments, usually passed from ``demisto.args()``.
            ``args['domain']`` list of domains or a single domain.
            ``args['threshold']`` threshold to determine whether a domain is malicious.
        default_threshold (int): default threshold to determine whether a domain is malicious if threshold is not
            specified in the XSOAR arguments.
        reliability (DBotScoreReliability): reliability of the source providing the intelligence data.
    Returns:
        CommandResults: A ``CommandResults`` object that is then passed to ``return_results``, that contains Domains.
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

    # Initialize an empty list of CommandResults to return,
    # each CommandResult will contain context standard for Domain
    command_results: List[CommandResults] = []

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
            malicious_description=f'Hello World returned reputation {reputation}',
            reliability=reliability
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

        # In this case we want to use an custom markdown to specify the table title,
        # but otherwise ``CommandResults()`` will call ``tableToMarkdown()``
        #  automatically
        readable_output = tableToMarkdown('Domain', domain_data)

        # INTEGRATION DEVELOPER TIP
        # The output key will be ``HelloWorld.Domain``, using ``domain`` as the key
        # field.
        # ``indicator`` is used to provide the context standard (Domain)
        command_results.append(CommandResults(
            readable_output=readable_output,
            outputs_prefix='HelloWorld.Domain',
            outputs_key_field='domain',
            outputs=domain_data,
            indicator=domain_standard_context
        ))
    return command_results


''' MAIN FUNCTION '''


def main() -> None:
    """
    main function, parses params and runs command functions
    """

    params = demisto.params()
    args = demisto.args()
    command = demisto.command()

    api_key = params.get('credentials', {}).get('password')

    # get the service API url
    base_url = urljoin(params.get('url'), '/api/v1')

    # if your Client class inherits from BaseClient, SSL verification is
    # handled out of the box by it, just pass ``verify_certificate`` to
    # the Client constructor
    verify_certificate = not params.get('insecure', False)

    # How much time before the first fetch to retrieve incidents
    first_fetch_time = arg_to_datetime(
        arg=params.get('first_fetch', '3 days'),
        arg_name='First fetch time',
        required=True
    )
    first_fetch_timestamp = int(first_fetch_time.timestamp()) if first_fetch_time else None
    # Using assert as a type guard (since first_fetch_time is always an int when required=True)
    assert isinstance(first_fetch_timestamp, int)

    # if your Client class inherits from BaseClient, system proxy is handled
    # out of the box by it, just pass ``proxy`` to the Client constructor
    proxy = params.get('proxy', False)

    # Integration that implements reputation commands (e.g. url, ip, domain,..., etc) must have
    # a reliability score of the source providing the intelligence data.
    reliability = params.get('integrationReliability', DBotScoreReliability.C)

    # INTEGRATION DEVELOPER TIP
    # You can use functions such as ``demisto.debug()``, ``demisto.info()``,
    # etc. to print information in the XSOAR server log. You can set the log
    # level on the server configuration
    # See: https://xsoar.pan.dev/docs/integrations/code-conventions#logging

    demisto.debug(f'Command being called is {command}')
    try:
        headers = {
            'Authorization': f'Bearer {api_key}'
        }
        client = Client(
            base_url=base_url,
            verify=verify_certificate,
            headers=headers,
            proxy=proxy)

        if command == 'test-module':
            # This is the call made when pressing the integration Test button.
            result = test_module(client, params, first_fetch_timestamp)
            return_results(result)

        elif command == 'fetch-incidents':
            # Set and define the fetch incidents command to run after activated via integration settings.
            alert_status = params.get('alert_status', None)
            alert_type = params.get('alert_type', None)
            min_severity = params.get('min_severity', None)

            # Convert the argument to an int using helper function or set to MAX_INCIDENTS_TO_FETCH
            max_results = arg_to_number(
                arg=params.get('max_fetch'),
                arg_name='max_fetch',
                required=False
            )
            if not max_results or max_results > MAX_INCIDENTS_TO_FETCH:
                max_results = MAX_INCIDENTS_TO_FETCH

            next_run, incidents = fetch_incidents(
                client=client,
                max_results=max_results,
                last_run=demisto.getLastRun(),  # getLastRun() gets the last run dict
                first_fetch_time=first_fetch_timestamp,
                alert_status=alert_status,
                min_severity=min_severity,
                alert_type=alert_type
            )

            # saves next_run for the time fetch-incidents is invoked
            demisto.setLastRun(next_run)
            # fetch-incidents calls ``demisto.incidents()`` to provide the list
            # of incidents to create
            demisto.incidents(incidents)

        elif command == 'ip':
            default_threshold_ip = arg_to_number(params.get('threshold_ip')) or DEFAULT_INDICATORS_THRESHOLD
            return_results(ip_reputation_command(client, args, default_threshold_ip, reliability))

        elif command == 'domain':
            default_threshold_domain = \
                arg_to_number(params.get('threshold_domain')) or DEFAULT_INDICATORS_THRESHOLD
            return_results(domain_reputation_command(client, args, default_threshold_domain, reliability))

        elif command == 'helloworld-say-hello':
            return_results(say_hello_command(client, args))

        elif command == 'helloworld-search-alerts':
            return_results(search_alerts_command(client, args))

        elif command == 'helloworld-get-alert':
            return_results(get_alert_command(client, args))

        elif command == 'helloworld-update-alert-status':
            return_results(update_alert_status_command(client, args))

        elif command == 'helloworld-scan-start':
            return_results(scan_start_command(client, args))

        elif command == 'helloworld-scan-status':
            return_results(scan_status_command(client, args))

        elif command == 'helloworld-scan-results':
            return_results(scan_results_command(client, args))

        else:
            raise NotImplementedError(f'Command {command} is not implemented')

    # Log exceptions and return errors
    except Exception as e:
        return_error(f'Failed to execute {command} command.\nError:\n{str(e)}')


''' ENTRY POINT '''

if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
