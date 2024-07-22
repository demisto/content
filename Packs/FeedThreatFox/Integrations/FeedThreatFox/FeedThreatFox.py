import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

from CommonServerUserPython import *  # noqa

import urllib3
from typing import Dict, Any

# Disable insecure warnings
urllib3.disable_warnings()


''' CONSTANTS '''

DATE_FORMAT = '%Y-%m-%dT%H:%M:%SZ'  # ISO8601 format with UTC, default in XSOAR
LOG = "THREAT FOX-"


class Client(BaseClient):
    def get_indicators_request(self, query: dict):
        url_suffix = '/api/v1'
        body = query
        return self._http_request('POST', url_suffix=url_suffix, json_data=body)
    
    def test_module(self) -> str:
        """Tests API connectivity and authentication'

        Returning 'ok' indicates that the integration works like it is supposed to.
        Connection to the service is successful.
        Raises exceptions if something goes wrong.

        :type client: ``Client``
        :param Client: client to use

        :return: 'ok' if test passed, anything else will fail the test.
        :rtype: ``str``
        """
        message: str = ''
        try:
            self.get_indicators_request({'days': 1, 'limit': 5})
            message = 'ok'
        except DemistoException as e:
                raise e
        return message
        
def check_params_for_query(args: dict):
    """Checks that there are no extra params and no missing ones for the query.
    Args:
        args: dict
    Returns:
        Boolean: True if params are good and False otherwise.
        Str: The query type (one of these: 'search_term', 'id', 'hash', 'tag', 'malware', 'days').
            If args are not good than it will be None.
    """
    args_lst = list({ele for ele in args if args[ele]})
    if 'limit' in args_lst:
        args_lst.remove('limit')
    if len(args_lst) != 1:
        return False, None
    else:
        return True, args_lst[0]


def create_query(query_arg, id: str | None = None, search_term: str | None = None, hash: str | None = None, tag: str | None = None,
                 malware: str | None = None, days: str | None = None, limit: str | None = None):
    """Creates a valid query to send to the API.

    Args:
        query_arg (str): the query type (should be one of those: 'search_term', 'id', 'hash', 'tag', 'malware', 'days').

    Returns:
        Str: The query to send to the API.
    """
    
    query_dict = {'search_term': 'search_ioc', 'id': 'ioc', 'hash': 'search_hash',
            'tag': 'taginfo', 'malware': 'malwareinfo', 'days': 'get_iocs'}
    
    q_id = arg_to_number(id)
    q_limit = arg_to_number(limit) or 50
        
    query = assign_params(
        query = query_dict[query_arg],
        id = q_id,
        search_term = search_term,
        hash = hash,
        tag = tag,
        malware = malware,
        days = days,
        limit = q_limit
    )
    
    # Only queries searching by tag or malware can specify a limit.
    if query_arg != 'tag' and query_arg != 'malware':
       del query['limit']
    
    return query


def parse_indicators(indicators):
    
    res = []
    
    indicators = [indicators] if type(indicators) != list else indicators
    
    for indicator in indicators:
                
        res_indicator = assign_params(
            ID=indicator.get('id'),
            value=indicator.get('ioc'),
            Tags1=indicator.get('threat_type'),
            Description = indicator.get('threat_type_desc'),
            malware_family_tags=
                indicator.get('malware_printable') if indicator.get('malware_printable') != 'Unknown malware' else None,
            aliases_tags = indicator.get('malware_alias'),
            first_seen_by_source = indicator.get('first_seen'),
            last_seen_by_source = indicator.get('last_seen'),
            reported_by = indicator.get('reporter'),
            Tags2 = indicator.get('tags'),
            Confidence = indicator.get('confidence_level'),
            Publications = indicator.get('reference')
        )
        res.append(res_indicator)
    return res


def threatfox_get_indicators_command(client: Client, args: dict[str, Any]) -> CommandResults:

    search_term = args.get('search_term')
    id = args.get('id')
    hash = args.get('hash')
    tag = args.get('tag')
    malware = args.get('malware')
    limit = args.get('limit')
    
    is_valid, query_type = check_params_for_query(args)
    
    if not is_valid:
        raise DemistoException("Arguments given are invalid.")
    
    query = create_query(query_type, id, search_term, hash, tag, malware, limit=limit)

    demisto.debug(f'{LOG} calling api with {query=}')
    result = client.get_indicators_request(query)
    demisto.debug(f'{LOG} got {result=}')
    
    query_status = result.get('query_status')
    query_data = result.get('data')
    
    if query_status != 'ok':
        raise DemistoException(f'failed to run command {query_status} {query_data}')
    
    parsed_indicators = parse_indicators(result.get('data') or result)
    
    human_readable = tableToMarkdown(name='Indicators', t=parsed_indicators,
                                     headers=['ID', 'value', 'Tags1', 'Description', 'malware_family_tags',
                                              'aliases_tags', 'first_seen_by_source', 'last_seen_by_source', 'reported_by',
                                              'Tags2', 'Confidence', 'Publications'], removeNull=True)
    
    return CommandResults(readable_output=human_readable)


''' MAIN FUNCTION '''


def main() -> None:
    
    params = demisto.params()
    base_url = urljoin(params['url'], '/api/v1')
    with_ports = params.get('with_ports', False)
    confidence_threshold = params.get('confidence_threshold', 75)
    create_relationship = params.get('create_relationship', True)
    
    demisto.debug(f'Command being called is {demisto.command()}')
    try:

        client = Client(base_url=base_url)
        
        if demisto.command() == 'test-module':
            result = client.test_module()
            return_results(result)

        elif demisto.command() == 'threatfox-get-indicators':
            return_results(threatfox_get_indicators_command(client, demisto.args()))

    except Exception as e:
        return_error(f'Failed to execute {demisto.command()} command.\nError:\n{str(e)}')


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
