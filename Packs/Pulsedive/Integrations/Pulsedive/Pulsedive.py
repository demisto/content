import traceback
from typing import Dict, List, Optional, Union

import dateparser
import demistomock as demisto  # noqa: F401
import requests
from CommonServerPython import *  # noqa: F401

# Disable insecure warnings
requests.packages.urllib3.disable_warnings()


''' CONSTANTS '''


DATE_FORMAT = '%Y-%m-%dT%H:%M:%SZ'
MAX_INCIDENTS_TO_FETCH = 50
HELLOWORLD_SEVERITIES = ['Low', 'Medium', 'High', 'Critical']

''' CLIENT CLASS '''


class Client(BaseClient):

    def test_connect(self):
        return self._http_request(
            method='GET',
            url_suffix='/info.php?',
            params={
                'value': 'pulsedive.com'
            }
        )

    def get_ip_reputation(self, ip: str, api_key) -> Dict[str, Any]:
        return self._http_request(
            method='GET',
            url_suffix='/info.php?',
            params={
                'indicator': ip,
                'pretty': '1',
                'key': api_key

            }
        )

    def get_domain_reputation(self, domain: str, api_key) -> Dict[str, Any]:
        return self._http_request(
            method='GET',
            url_suffix='/info.php?',
            params={
                'indicator': domain,
                'pretty': '1',
                'key': api_key
            }
        )

    def get_url_reputation(self, url: str, api_key) -> Dict[str, Any]:
        return self._http_request(
            method='GET',
            url_suffix='/info.php?',
            params={
                'indicator': url,
                'pretty': '1',
                'key': api_key
            }
        )


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


def convert_to_xsoar_severity(pulsedive_severity) -> int:
    if (pulsedive_severity == 'unknown' or pulsedive_severity == 'none'):
        xsoar_severity = Common.DBotScore.NONE  # unknown
    elif pulsedive_severity == 'high':
        xsoar_severity = Common.DBotScore.SUSPICIOUS  # suspicious
    elif pulsedive_severity == 'critical':
        xsoar_severity = Common.DBotScore.BAD  # bad
    else:
        xsoar_severity = Common.DBotScore.GOOD  # good
    return xsoar_severity


''' COMMAND FUNCTIONS '''


def test_module(client: Client) -> str:
    """Tests API connectivity and authentication"""

    try:
        client.test_connect()
    except DemistoException:
        return 'Could not connect to Pulsedive'
    return 'ok'


def ip_reputation_command(client: Client, args: Dict[str, Any], api_key) -> List[CommandResults]:
    ips = argToList(args.get('ip'))
    if len(ips) == 0:
        raise ValueError('IP(s) not specified')

    command_results: List[CommandResults] = []
    for ip in ips:
        ip_data = client.get_ip_reputation(ip, api_key)
        # remove the array
        indicator_ip = ip_data['indicator']
        reputation = ip_data['risk']
        score = convert_to_xsoar_severity(reputation)

        # Create the DBotScore structure first using the Common.DBotScore class.
        dbot_score = Common.DBotScore(
            indicator=indicator_ip,
            indicator_type=DBotScoreType.IP,
            integration_name='Pulsedive',
            score=score,
            malicious_description=f'Pulsedive returned reputation {reputation}'
        )

        # Create the IP Standard Context structure using Common.IP and add
        # dbot_score to it.
        ip_standard_context = Common.IP(
            ip=indicator_ip,
            dbot_score=dbot_score
        )

        ip_data.pop('objects', None)
        ip_data.pop('nir', None)
        command_results.append(CommandResults(
            readable_output=tableToMarkdown('IP:', ip_data),
            outputs_prefix='Pulsedive.IP',
            outputs_key_field='indicator',
            outputs=ip_data,
            indicator=ip_standard_context
        ))

    return command_results


def domain_reputation_command(client: Client, args: Dict[str, Any], api_key) -> List[CommandResults]:
    domains = argToList(args.get('domain'))
    if len(domains) == 0:
        raise ValueError('domain(s) not specified')

    command_results: List[CommandResults] = []
    for domain in domains:
        domain_data = client.get_domain_reputation(domain, api_key)
        indicator_domain = domain_data['indicator']
        reputation = domain_data['risk']
        score = convert_to_xsoar_severity(reputation)

        if 'creation_date' in domain_data:
            domain_data['creation_date'] = parse_domain_date(domain_data['creation_date'])
        if 'expiration_date' in domain_data:
            domain_data['expiration_date'] = parse_domain_date(domain_data['expiration_date'])
        if 'updated_date' in domain_data:
            domain_data['updated_date'] = parse_domain_date(domain_data['updated_date'])

        dbot_score = Common.DBotScore(
            indicator=indicator_domain,
            integration_name='Pulsedive',
            indicator_type=DBotScoreType.DOMAIN,
            score=score,
            malicious_description=f'Pulsedive returned reputation {reputation}'
        )

        domain_standard_context = Common.Domain(
            domain=indicator_domain,
            # creation_date=domain_data.get('creation_date', None),
            # expiration_date=domain_data.get('expiration_date', None),
            # updated_date=domain_data.get('updated_date', None),
            # organization=domain_data.get('org', None),
            # name_servers=domain_data.get('name_servers', None),
            # registrant_name=domain_data.get('name', None),
            # registrant_country=domain_data.get('country', None),
            # registrar_name=domain_data.get('registrar', None),
            dbot_score=dbot_score
        )

        command_results.append(CommandResults(
            readable_output=tableToMarkdown('Domain:', domain_data),
            outputs_prefix='Pulsedive.Domain',
            outputs_key_field='indicator',
            outputs=domain_data,
            indicator=domain_standard_context
        ))

    return command_results


def url_reputation_command(client: Client, args: Dict[str, Any], api_key) -> List[CommandResults]:

    urls = argToList(args.get('url'))
    if len(urls) == 0:
        raise ValueError('URL(s) not specified')

    command_results: List[CommandResults] = []
    for url in urls:
        url_data = client.get_url_reputation(url, api_key)
        indicator_url = url_data['indicator']
        reputation = url_data['risk']
        score = convert_to_xsoar_severity(reputation)

        dbot_score = Common.DBotScore(
            indicator=str(indicator_url),
            indicator_type=DBotScoreType.URL,
            integration_name='Pulsedive',
            score=score,
            malicious_description=f'Pulsedive returned reputation {reputation}'
        )

        url_standard_context = Common.URL(
            url=indicator_url,
            dbot_score=dbot_score
        )

        url_data.pop('objects', None)
        url_data.pop('nir', None)
        command_results.append(CommandResults(
            readable_output=tableToMarkdown('URL:', url_data),
            outputs_prefix='Pulsedive.URL',
            outputs_key_field='indicator',
            outputs=url_data,
            indicator=url_standard_context
        ))

    return command_results


''' MAIN FUNCTION '''


def main() -> None:

    api_key = demisto.params().get('apikey')
    base_url = 'https://www.pulsedive.com/api'
    verify_certificate = not demisto.params().get('insecure', False)
    proxy = demisto.params().get('proxy', False)
    headers = {'User-Agent': 'XSOAR - Integration'}

    # INTEGRATION DEVELOPER TIP
    # You can use functions such as ``demisto.debug()``, ``demisto.info()``,
    # etc. to print information in the XSOAR server log. You can set the log
    # level on the server configuration
    # See: https://xsoar.pan.dev/docs/integrations/code-conventions#logging
    # demisto.debug(f'Command being called is {demisto.command()}')

    try:

        client = Client(
            base_url=base_url,
            verify=verify_certificate,
            proxy=proxy,
            headers=headers)

        if demisto.command() == 'test-module':
            # This is the call made when pressing the integration Test button.
            result = test_module(client)
            return_results(result)

        # Done
        elif demisto.command() == 'ip':
            return_results(ip_reputation_command(client, demisto.args(), api_key))

        # Done
        elif demisto.command() == 'domain':
            return_results(domain_reputation_command(client, demisto.args(), api_key))

        # WIP
        elif demisto.command() == 'url':
            return_results(url_reputation_command(client, demisto.args(), api_key))

    # Log exceptions and return errors
    except Exception as e:
        demisto.error(traceback.format_exc())  # print the traceback
        return_error(f'Failed to execute {demisto.command()} command.\nError:\n{str(e)}')


''' ENTRY POINT '''


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
