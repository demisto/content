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

    def get_version(self) -> Dict[str, Any]:
        """Get version

        :return: dict containing the version
        :rtype: ``Dict[str, Any]``
        """

        return self._http_request(
            method='GET',
            url_suffix='/version'
        )

    def get_entity_report(self, entity_id: str, time_id: str):
        return self._http_request(
            method='GET',
            url_suffix='/systemReport/entity',
            params={
                'entityId': entity_id,
                'timeId': time_id
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
        page = 1
        total_pages = 1
        techniques = []
        while page <= total_pages:
            demisto.info(f'in while loop {page} {total_pages}')
            res = self._http_request(
                method='GET',
                url_suffix='/systemReport/techniques',
                params={
                    'timeId': time_id
                }
            )
            techniques.extend(res['data'])
            total_pages = res['paging']['totalPages']
            page += 1
        return techniques

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

    def lookup_entities_by_ip(self, ip):
        demisto.info(f'looking up {ip}')
        page = 1
        total_pages = 1
        entities = []
        while page <= total_pages:
            res = self._http_request(
                method='GET',
                url_suffix='/systemReport/entities',
                params={
                    'search': ip
                }
            )
            entities.extend(res['data'])
            total_pages = res['paging']['totalPages']
            page += 1
        return entities


''' HELPER FUNCTIONS '''


def escape_ip(ip):
    try:
        address = ip['Address']
        return '/' + address.replace('.', '\\.') + '/'
    except (AttributeError, TypeError):
        return '/' + ip.replace('.', '\\.') + '/'


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


def test_module(client: Client) -> str:
    """Tests API connectivity and authentication'

    Returning 'ok' indicates that the integration works like it is supposed to.
    Connection to the service is successful.
    Raises exceptions if something goes wrong.

    :type client: ``Client``
    :param Client: HelloWorld client to use

    :return: 'ok' if test passed, anything else will fail the test.
    :rtype: ``str``
    """
    try:
        version = client.get_version()
        system_version = version['system']
        s_version = system_version.split('.')
        major = int(s_version[0])
        minor = int(s_version[1])
        if major < 1 or (major == 1 and minor < 37):
            return f'Instance version not compatible. {system_version} (found) < 1.37 (required).'

    except DemistoException as e:
        if 'Forbidden' in str(e):
            return 'Authorization Error: make sure API Key is correctly set'
        else:
            raise e
    except Exception as e:
        return f'Verification Error: could not load XM Cyber version.\n{e}'
    return 'ok'


def asset_attack_path_list_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    time_id = args.get('time_id')
    if not time_id:
        time_id = 'timeAgo_days_7'
    critical_assets = client.get_critical_assets(time_id)
    attack_paths = []
    for critical_asset in critical_assets:
        paths = client.get_inbound_paths(critical_asset['entityId'], time_id)
        for path in paths:
            attack_paths.append(path)
    readable_output = 'loaded list of {0} asset attack paths'.format(len(attack_paths))
    return CommandResults(
        outputs_prefix='XMCyber.AttackPath',
        outputs_key_field='pathId',
        outputs=attack_paths,
        readable_output=readable_output
    )


def techniques_list_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    time_id = args.get('time_id')
    if not time_id:
        time_id = 'timeAgo_days_7'
    techniques = client.get_top_techniques(time_id)
    readable_output = f'loaded list of {len(techniques)} top techniques'
    return CommandResults(
        outputs_prefix='XMCyber.Technique',
        outputs_key_field='technique',
        outputs=techniques,
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
        readable_output=readable_output
    )


def attack_paths_to_entity_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    time_id = args.get('time_id')
    if not time_id:
        time_id = 'timeAgo_days_7'
    ips = argToList(args.get('ip'))
    if len(ips) == 0:
        raise ValueError('IP(s) not specified')
    entities = client.lookup_entities_by_ip(ips[0])
    attack_paths = []
    for entity in entities:
        paths = client.get_inbound_paths(entity['agentId'], time_id)
        for path in paths:
            attack_paths.append(raw_path_to_incident_path(path))
    readable_output = 'found {0} attack paths to {1} entities'.format(len(attack_paths), len(entities))
    return CommandResults(
        outputs_prefix='XMCyber.AttackPath',
        outputs_key_field='pathId',
        outputs=attack_paths,
        readable_output=readable_output,

    )


def attack_complexity_to_ip_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    time_id = args.get('time_id')
    if not time_id:
        time_id = 'timeAgo_days_7'
    ips = argToList(args.get('ip'))
    if len(ips) == 0:
        raise ValueError('IP(s) not specified')
    try:
        address = ips[0]['Address']
    except (AttributeError, TypeError):
        address = ips[0]
    entities = client.lookup_entities_by_ip(address)
    if len(entities) == 0:
        outputs = {
            'EntityIpAddress': address,
            'AverageAttackComplexity': -1,
            'EntityId': 'N/A'
        }
        readable_output = f'Could not find entity with the IP {address}'
    else:
        entity_id = entities[0]['agentId']
        report = client.get_entity_report(entity_id, time_id)
        attack_complexity = report['attackComplexity']
        average = attack_complexity['avg']['value']
        level = attack_complexity['avg']['level']
        entity_name = entities[0]['name']
        readable_output = f'Entity {entity_name} has average {average} which is {level}'
        outputs = {
            'EntityIpAddress': address,
            'AverageAttackComplexity': average,
            'EntityId': entity_id
        }
    return CommandResults(
        outputs_prefix='XMCyber',
        outputs_key_field='EntityId',
        outputs=outputs,
        readable_output=readable_output,
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
        readable_output=readable_output
    )


def entity_get_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    ips = argToList(args.get('ip'))
    entities = []
    outputs = []

    demisto.info(f'ips {ips}')
    for ip in ips:
        demisto.info(f'ip {ip}')
        try:
            entities.extend(client.lookup_entities_by_ip(ip['Address']))
        except AttributeError:
            entities.extend(client.lookup_entities_by_ip(ip))
    if len(entities) == 0:
        readable_output = 'No entities match the properties'
    else:
        readable_output = '#Found the following entities'
        for entity in entities:
            name = entity['name']
            readable_output += f'\n- {name}'
            outputs.append({
                'EntityId': entity['entityId'],
                'Name': name
            })
    return CommandResults(
        outputs_prefix='XMCyber',
        outputs_key_field='EntityId',
        outputs=outputs,
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
    demisto.info(f'Command running: {demisto.command()}')
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

        elif demisto.command() == 'xmcyber-attack-complexity-to-ip':
            return_results(attack_complexity_to_ip_command(client, demisto.args()))

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

        elif demisto.command() == 'xmcyber-entity-get':
            return_results(entity_get_command(client, demisto.args()))

    # Log exceptions and return errors
    except Exception as e:
        demisto.error(traceback.format_exc())  # print the traceback
        return_error(f'Failed to execute {demisto.command()} command.\nError:\n{str(e)}\n'
                     f'Traceback:\n{traceback.format_exc()}')


''' ENTRY POINT '''


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
