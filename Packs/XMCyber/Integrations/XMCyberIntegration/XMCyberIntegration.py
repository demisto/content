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
BREACHPOINT_LABEL = 'Demisto Breachpoint'
CRITICAL_ASSET_LABEL = 'Demisto Critical Asset'

''' CLIENT CLASS '''


class Client(BaseClient):
    """Client class to interact with XM Cyber API"""

    def get_ip_reputation(self, ip: str) -> Dict[str, Any]:
        """Gets the IP reputation using the '/ip' API endpoint

        :type ip: ``str``
        :param ip: IP address to get the reputation for

        :return: dict containing the IP reputation as returned from the API
        :rtype: ``Dict[str, Any]``
        """

        return self._http_request(
            method='GET',
            url_suffix='/ip',
            params={
                'ip': ip
            }
        )

    def get_inbound_paths(self, entity_id: str, time_id):
        # /api/systemReport/entity/inbound
        return self._http_request(
            method='GET',
            url_suffix='/systemReport/entity/inbound',
            params={
                'entityId': entity_id,
                'timeId': time_id
            }
        )

    def get_outbound_paths(self, entity_id: str, time_id):
        # /api/systemReport/entity/outbound
        return self._http_request(
            method='GET',
            url_suffix='/systemReport/entity/outbound',
            params={
                'entityId': entity_id,
                'timeId': time_id
            }
        )

    def get_critical_assets(self, time_id):
        demisto.info('Matans first debug log!')
        page = 1
        total_pages = 1
        critical_assets = []
        while page <= total_pages:
            demisto.info(f'in while loop {page} {total_pages}')
            res = self._http_request(
                method='GET',
                url_suffix=f'/systemReport/entities?time_id={time_id}&page={page}&pageSize=200&filter=%7B"asset"%3A%20true%7D',
            )
            critical_assets.extend(res['data'])
            total_pages = res['paging']['totalPages']
            page += 1
        return critical_assets

    def get_top_techniques(self, time_id):
        # /api/systemReport/techniques
        return self._http_request(
            method='GET',
            url_suffix='/systemReport/techniques',
            params={
                'timeId': time_id
            }
        )

    def get_entities_by_label(self, label: str):
        #is this the right API?
        #/discoveryRules/matchingSensors/getMatchingSensors
        raise NotImplemented()

    def unlabel_entities(self, entities: List[str], label: str):
        # api does not exist
        raise NotImplemented()

    def label_entities(self, entities: List[str], label: str):
        # api does not exist
        raise NotImplemented()

    def lookup_entities_by_ip(self, ips):
        # need to find API
        raise NotImplemented()


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


def raw_path_to_incident_path(path: Any) -> Any:
    raise NotImplemented()

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


def asset_attack_path_list_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    time_id = args.get('time_id')
    if not time_id:
        time_id = 'timeAgo_days_7'
    critical_assets = client.get_critical_assets(time_id)
    attack_paths = []
    for critical_asset in critical_assets:
        paths = client.get_inbound_paths(critical_asset, time_id)
        for path in paths:
            attack_paths.append(raw_path_to_incident_path(path))
    readable_output = 'loaded list of {0} asset attack paths'.format(len(attack_paths))
    return CommandResults(
        outputs_prefix='XMCyber.AttackPath',
        outputs_key_field='pathId',
        outputs= attack_paths,
        indicators= attack_paths,
        readable_output= readable_output
    )


def techniques_list_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    time_id = args.get('time_id')
    if not time_id:
        time_id = 'timeAgo_days_7'
    techniques = client.get_top_techniques(time_id)
    readable_output = 'loaded list of {0} top techniques'.format(len(techniques))
    return CommandResults(
        outputs_prefix='XMCyber.Technique',
        outputs_key_field='technique',
        outputs=techniques,
        indicators=techniques,
        readable_output=readable_output
    )


def breachpoint_update_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    ips = argToList(args.get('ip'))
    if len(ips) == 0:
        raise ValueError('IP(s) not specified')
    entities = client.lookup_entities_by_ip(ips)
    client.label_entities(entities, BREACHPOINT_LABEL)
    labeled_entities = client.get_entities_by_label(BREACHPOINT_LABEL)
    readable_output = 'The {0} has been updated, there are {1} labeled entities'.format( \
        BREACHPOINT_LABEL, len(labeled_entities))
    return CommandResults(
        outputs_prefix='XMCyber.Entity',
        outputs_key_field='entityId',
        outputs=labeled_entities,
        indicators=labeled_entities,
        readable_output=readable_output
    )


def critical_asset_add_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    ips = argToList(args.get('ip'))
    if len(ips) == 0:
        raise ValueError('IP(s) not specified')
    entities = client.lookup_entities_by_ip(ips)
    client.label_entities(entities, CRITICAL_ASSET_LABEL)
    labeled_entities = client.get_entities_by_label(CRITICAL_ASSET_LABEL)
    readable_output = 'The {0} has been updated, there are {1} labeled entities'.format(\
        CRITICAL_ASSET_LABEL, len(labeled_entities))
    return CommandResults(
        outputs_prefix='XMCyber.Entity',
        outputs_key_field='entityId',
        outputs=labeled_entities,
        indicators=labeled_entities,
        readable_output=readable_output
    )


def attack_paths_to_entity_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    time_id = args.get('time_id')
    if not time_id:
        time_id = 'timeAgo_days_7'
    ips = argToList(args.get('ip'))
    if len(ips) == 0:
        raise ValueError('IP(s) not specified')
    entities = client.lookup_entities_by_ip(ips)
    attack_paths = []
    for entity in entities:
        paths = client.get_inbound_paths(entity, time_id)
        for path in paths:
            attack_paths.append(raw_path_to_incident_path(path))
    readable_output = 'found {0} attack paths to {1} entities'.format(len(attack_paths), len(entities))
    return CommandResults(
        outputs_prefix='XMCyber.AttackPath',
        outputs_key_field='pathId',
        outputs=attack_paths,
        indicators=attack_paths,
        readable_output=readable_output
    )


def attack_paths_from_entity_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    time_id = args.get('time_id')
    if not time_id:
        time_id = 'timeAgo_days_7'
    ips = argToList(args.get('ip'))
    if len(ips) == 0:
        raise ValueError('IP(s) not specified')
    entities = client.lookup_entities_by_ip(ips)
    attack_paths = []
    for entity in entities:
        paths = client.get_outbound_paths(entity, time_id)
        for path in paths:
            attack_paths.append(raw_path_to_incident_path(path))
    readable_output = 'found {0} attack paths from {1} entities'.format(len(attack_paths), len(entities))
    return CommandResults(
        outputs_prefix='XMCyber.AttackPath',
        outputs_key_field='pathId',
        outputs=attack_paths,
        indicators=attack_paths,
        readable_output=readable_output
    )


''' MAIN FUNCTION '''


def main() -> None:
    """main function, parses params and runs command functions

    :return:
    :rtype:
    """

    api_key = demisto.params().get('apikey')

    base_url = urljoin(demisto.params()['url'], '/api')

    verify_certificate = not demisto.params().get('insecure', False)

    proxy = demisto.params().get('proxy', False)

    # INTEGRATION DEVELOPER TIP
    # You can use functions such as ``demisto.debug()``, ``demisto.info()``,
    # etc. to print information in the XSOAR server log. You can set the log
    # level on the server configuration
    # See: https://xsoar.pan.dev/docs/integrations/code-conventions#logging

    demisto.debug('Matans first debug log!')

    demisto.debug(f'Command being called is {demisto.command()}')
    try:
        headers = {
            'X-Api-Key': api_key,
            'Content-Type': 'application/json; charset=utf-8'
        }
        client = Client(
            base_url=base_url,
            verify=verify_certificate,
            headers=headers,
            proxy=proxy)

        if demisto.command() == 'test-module':
            # This is the call made when pressing the integration Test button.
            result = test_module(client)
            return_results(result)

        elif demisto.command() == 'xmcyber-asset-attack-path-list':
            return_results(asset_attack_path_list_command(client, demisto.args()))

        elif demisto.command() == 'xmcyber-techniques-list':
            return_results(techniques_list_command(client, demisto.args()))

        elif demisto.command() == 'xmcyber-breachpoint-update':
            return_results(breachpoint_update_command(client, demisto.args()))

        elif demisto.command() == 'xmcyber-critical-asset-add':
            return_results(critical_asset_add_command(client, demisto.args()))

        elif demisto.command() == 'xmcyber-attack-paths-to-entity':
            return_results(attack_paths_to_entity_command(client, demisto.args()))

        elif demisto.command() == 'xmcyber-attack-paths-from-entity':
            return_results(attack_paths_from_entity_command(client, demisto.args()))

    # Log exceptions and return errors
    except Exception as e:
        demisto.error(traceback.format_exc())  # print the traceback
        return_error(f'Failed to execute {demisto.command()} command.\nError:\n{str(e)}')


''' ENTRY POINT '''


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
