from typing import List, Optional, Union
import urllib3
from CommonServerPython import *

# Disable insecure warnings
urllib3.disable_warnings()


''' CONSTANTS '''


DATE_FORMAT = '%Y-%m-%dT%H:%M:%SZ'


''' CLIENT CLASS '''


class Client(BaseClient):

    def get_domain_data(self, domain: str) -> Dict[str, Any]:
        return self._http_request(
            method='GET',
            url_suffix=f'full/{domain}',
            params={}
        )

    def get_search_data(self, field: str, value: str, limit: int) -> Dict[str, Any]:
        return self._http_request(
            method='GET',
            url_suffix=f'domains/{field}/{value}',
            params={'limit': limit}
        )

    def test_module(self):
        return self._http_request(
            method='GET',
            url_suffix='domains/ip/8.8.8.8',
            params={}
        )


''' HELPER FUNCTIONS '''


def parse_domain_date(domain_date: Union[List[str], str], date_format: str = '%Y-%m-%dT%H:%M:%S.000Z') -> Optional[str]:
    """Converts whois date format to an ISO8601 string

    Converts the HelloWorld domain WHOIS date (YYYY-mm-dd HH:MM:SS) format
    in a datetime. If a list is returned with multiple elements, takes only
    the first one.

    :type domain_date: ``Union[List[str],str]``
    :param date_format:
        a string or list of strings with the format 'YYYY-mm-DD HH:MM:SS'

    :return: Parsed time in ISO8601 format
    :rtype: ``Optional[str]``
    """

    if isinstance(domain_date, str):
        # if str parse the value
        domain_date_dt = dateparser.parse(domain_date)
        if domain_date_dt:
            return domain_date_dt.strftime(date_format)
    elif isinstance(domain_date, list) and len(domain_date) > 0 and isinstance(domain_date[0], str):
        # if list with at least one element, parse the first element
        domain_date_dt = dateparser.parse(domain_date[0])
        if domain_date_dt:
            return domain_date_dt.strftime(date_format)
    # in any other case return nothing
    return None


''' COMMAND FUNCTIONS '''


def test_module_command(client: Client) -> str:
    """Tests API connectivity and authentication'

    Returning 'ok' indicates that the integration works like it is supposed to.
    Connection to the service is successful.
    Raises exceptions if something goes wrong.

    :type client: ``Client``
    :param client: the base client

    :return: 'ok' if test passed, anything else will fail the test.
    :rtype: ``str``
    """
    try:
        client.test_module()
    except DemistoException as e:
        if 'Forbidden' in str(e):
            return 'Authorization Error: make sure API Key is correctly set'
        else:
            raise e
    return 'ok'


def domain_command(client: Client, args: Dict[str, Any]) -> List[CommandResults]:
    """domain command: Returns domain reputation for a list of domains

    :type client: ``Client``
    :param client: Hostio client to use

    :type args: ``Dict[str, Any]``
    :param args:
        all command arguments, usually passed from ``demisto.args()``.
        ``args['domain']`` list of domains or a single domain

    :return:
        A ``CommandResults`` object that is then passed to ``return_results``,
        that contains Domains

    :rtype: ``CommandResults``
    """

    domains = argToList(args.get('domain'))
    if len(domains) == 0:
        raise ValueError('domain(s) not specified')

    command_results: List[CommandResults] = []
    for domain in domains:
        domain_data = client.get_domain_data(domain)
        domain_data['domain'] = domain

        score = Common.DBotScore.NONE
        readable_output = tableToMarkdown('Domain', domain_data)

        # if not enough, raise error??
        # if not domain_data['web']:
        #     readable_output = f'No information given about {domain}'

        if 'date' in domain_data['web']:
            domain_data['updated_date'] = parse_domain_date(domain_data['web']['date'])

        reputation = int(domain_data['web'].get('rank', 0))
        # if reputation == 0:
        #     score = Common.DBotScore.NONE  # unknown
        # elif reputation >= threshold:
        #     score = Common.DBotScore.BAD  # bad
        # elif reputation >= threshold / 2:
        #     score = Common.DBotScore.SUSPICIOUS  # suspicious
        # else:
        #     score = Common.DBotScore.GOOD  # good
        dbot_score = Common.DBotScore(
            indicator=domain,
            integration_name='HostIo',
            indicator_type=DBotScoreType.DOMAIN,
            score=score,
            malicious_description=f'HostIo returned reputation {reputation}'
        )

        domain_standard_context = Common.Domain(
            domain=domain,
            updated_date=domain_data.get('updated_date', None),
            name_servers=domain_data['web'].get('server', None),
            registrant_name=domain_data['web'].get('title', None),
            registrant_country=domain_data['web'].get('country', None),
            registrant_email=domain_data['web'].get('email', None),
            registrant_phone=domain_data['web'].get('phone', None),
            dns=domain_data.get('dns', None),
            dbot_score=dbot_score
        )

        command_results.append(CommandResults(
            readable_output=readable_output,
            outputs_prefix='HostIo.Domain',
            outputs_key_field='domain',
            outputs=domain_data,
            indicator=domain_standard_context
        ))
    return command_results


def search_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    field = args.get('field', None)
    value = args.get('value', None)
    limit = args.get('limit', 25)

    data = client.get_search_data(field, value, limit)
    read = tableToMarkdown('Search', data)
    context = {
        'Field': field,
        'Value': value,
        'Domains': data.get('domains', []),
        'Total': data.get('total')
    }

    return CommandResults(
        readable_output=read,
        outputs_prefix='HostIo.Search',
        outputs_key_field=['field', 'value'],
        outputs=context,
        raw_response=data)


''' MAIN FUNCTION '''


def main() -> None:
    """main function, parses params and runs command functions

    :return:
    :rtype:
    """
    params = demisto.params()
    api_key = params.get('token')
    base_url = 'https://host.io/api'

    verify_certificate = not params.get('insecure', False)
    proxy = params.get('proxy', False)

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
            result = test_module_command(client)
            return_results(result)

        elif demisto.command() == 'domain':
            return_results(domain_command(client, demisto.args()))

        elif demisto.command() == 'hostio-domain-search':
            return_results(search_command(client, demisto.args()))

    except Exception as e:
        demisto.error(traceback.format_exc())
        return_error(f'Failed to execute {demisto.command()} command.\nError:\n{str(e)}')


''' ENTRY POINT '''

if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
