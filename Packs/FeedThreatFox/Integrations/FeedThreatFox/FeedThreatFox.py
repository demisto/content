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
    if q_limit>1000:
        q_limit = 1000
        
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


def parse_indicator_for_get_command(indicator):
    
    res_indicator = assign_params(
            ID=indicator.get('id'),
            value=value(indicator),
            Description = indicator.get('threat_type_desc'),
            malware_family_tags=
                indicator.get('malware_printable') if indicator.get('malware_printable') != 'Unknown malware' else None,
            aliases_tags = indicator.get('malware_alias'),
            first_seen_by_source = indicator.get('first_seen'),
            last_seen_by_source = indicator.get('last_seen'),
            reported_by = indicator.get('reporter'),
            Tags = indicator.get('tags'),
            Confidence = indicator.get('confidence_level'),
            Publications = indicator.get('reference')
        )
    return res_indicator


def parse_indicators(indicators):
    res = []
    indicators = [indicators] if type(indicators) != list else indicators
    for indicator in indicators:
        res.append(parse_indicator_for_get_command(indicator))
    return res


def indicator_type(indicator):
    """Returns the ioc type according to 'ioc_type' field in the indicator
    """
    type = indicator.get('ioc_type')
    if type == 'domain':
        return FeedIndicatorType.FQDN
    elif type == 'url':
        return FeedIndicatorType.URL
    elif "ip:port" in type:
        return FeedIndicatorType.ip_to_indicator_type(indicator.get('ioc'))
    elif type == 'envelope_from' or type == 'body_from':
        return FeedIndicatorType.Email
    else:  # 'sha1_hash' 'sha256_hash' 'md5_hash'
        return FeedIndicatorType.File
    
def parse_indicator_for_fetch(indicator):
    res_indicator = assign_params(
        indicatoridentification = indicator.get('id'),
        description = indicator.get('threat_type_desc'),
        malwarefamily = indicator.get('malware_printable') if indicator.get('malware_printable') != 'Unknown malware' else None,
        aliases = indicator.get('malware_alias'),
        firstseenbysource = indicator.get('first_seen'),
        lastseenbysource = indicator.get('last_seen'),
        reportedby = indicator.get('reporter'),
        Tags = tags(indicator)
    )
    return res_indicator


def tags(indicator):
    res = [indicator.get('malware_printable'), indicator.get('malware_alias'), indicator.get('threat_type')]
    if indicator.get('tags'):
        res.extend(indicator.get('tags'))


def value(indicator):
    if indicator.get('ioc_type') == "ip:port":
        return indicator.get('ioc').split(':')[0]
    return indicator.get('ioc')


def create_relationships(value, ioc_type, related_malware, demisto_ioc_type):
    relationships = []
    return []
    if related_malware:
        if type == 'domain' or type == "ip:port" or type == 'url':
            relationships.append(EntityRelationship(entity_a=value, entity_a_type=demisto_ioc_type,
                                                    name=EntityRelationship.Relationships.COMMUNICATED_BY,
                                                    entity_b=related_malware, entity_b_type=FeedIndicatorType.Malware,
                                                    brand='ThreatFox Feed'))
        else: # case File (sha..)
            relationships.append(EntityRelationship(entity_a=value, entity_a_type=demisto_ioc_type,
                                                    name=EntityRelationship.Relationships.RELATED_TO,
                                                    entity_b=related_malware, entity_b_type=FeedIndicatorType.Malware,
                                                    brand='ThreatFox Feed'))
    return relationships



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
                                     headers=['ID', 'value', 'Description', 'malware_family_tags',
                                              'aliases_tags', 'first_seen_by_source', 'last_seen_by_source', 'reported_by',
                                              'Tags', 'Confidence', 'Publications'], removeNull=True)
    
    return CommandResults(readable_output=human_readable)


def fetch_indicators_command(client: Client, with_ports, confidence_threshold, create_relationship, interval, tlp_color):
    
    response = client.get_indicators_request({ "query": "get_iocs", "days": interval })
    
    if response.get('query_status') != 'ok':
        raise DemistoException("couldn't fetch")  # write something better
    
    demisto.debug(f'{LOG} got {response=}')  # erase
    
    results = []
       
    for indicator in response.get('data'):
        ioc_type = indicator.get('ioc_type')
        if ioc_type == 'sha3_384_hash':
            demisto.debug(f'{LOG} got indicator of indicator type "sha3" skipping it')
            continue
        if arg_to_number(indicator.get('confidence_level')) < confidence_threshold:
            demisto.debug(f'{LOG} got indicator with low confidence level, skipping it')
            continue
        
        demisto_ioc_type = indicator_type(indicator)
        ioc_value = value(indicator)
        relationships = create_relationships(ioc_value, demisto_ioc_type, indicator.get("malware_printable"), demisto_ioc_type)
      
        fields = {'trafficlightprotocol': tlp_color} | parse_indicator_for_fetch(indicator)
        #if with_ports and ioc_type == "ip:port":
        #    fields['tags'].append(ioc_value.split(':')[1])
        
        results.append({
            'value': ioc_value,
            'type': demisto_ioc_type,
            'fields': fields,
            'rawJSON': indicator,
            'relationships': relationships
        })

    demisto.debug(f'{LOG} {results=}')  # erase
    return results


''' MAIN FUNCTION '''


def main() -> None:
    
    command = demisto.command()
    
    params = demisto.params()
    base_url = urljoin(params['url'], '/api/v1')
    with_ports = argToBoolean(params.get('with_ports', False))
    confidence_threshold = arg_to_number(params.get('confidence_threshold', 75))   # Need to check that it is a number
    create_relationship = argToBoolean(params.get('create_relationship', False))
    interval = arg_to_number(params.get('fetch_interval'))  # Need to check that it is a number
    tlp_color = params.get('tlp_color')
    
    demisto.debug(f'Command being called is {demisto.command()}')
    try:

        client = Client(base_url=base_url)
        
        if command == 'test-module':
            result = client.test_module()
            return_results(result)

        elif command == 'threatfox-get-indicators':
            return_results(threatfox_get_indicators_command(client, demisto.args()))
            
        elif command == 'fetch-indicators':
            res = fetch_indicators_command(client=client, with_ports=with_ports, confidence_threshold=confidence_threshold,
                                          create_relationship=create_relationship, interval=interval, tlp_color=tlp_color)
            for iter_ in batch(res, batch_size=2000):
                demisto.createIndicators(iter_)

    except Exception as e:
        return_error(f'Failed to execute {demisto.command()} command.\nError:\n{str(e)}')


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
