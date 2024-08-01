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
    def get_indicators_request(self, query: dict)->dict:
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
   
        
def check_params_for_query(args: dict)->tuple[bool, str|None]:
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


def create_query(query_arg, id: str | None = None, search_term: str | None = None,
                 hash: str | None = None, tag: str | None = None, malware: str | None = None,
                 days: str | None = None, limit: str | None = None)-> dict:
    """Creates a valid query to send to the API.

    Args:
        query_arg (str): the query type (should be one of those:
        'search_term', 'id', 'hash', 'tag', 'malware', 'days').

    Returns:
        Str: The query to send to the API.
    """
    
    query_dict = {'search_term': 'search_ioc', 'id': 'ioc', 'hash': 'search_hash',
            'tag': 'taginfo', 'malware': 'malwareinfo', 'days': 'get_iocs'}
    
    q_days = str((arg_to_number(days) or 1)/1440)
    q_id = arg_to_number(id)
    
    query = assign_params(
        query = query_dict[query_arg],
        id = q_id,
        search_term = search_term,
        hash = hash,
        tag = tag,
        malware = malware,
        days = q_days
    )
    
    # Only queries searching by tag or malware can specify a limit.
    if query_arg == 'tag' or query_arg == 'malware':
        q_limit = arg_to_number(limit) or 50
        if q_limit>1000:
            q_limit = 1000
        query['limit'] = q_limit
    
    return query


def parse_indicator_for_get_command(indicator: dict)->dict:
    
    res_indicator = assign_params(
            ID=indicator.get('id'),
            Value=value(indicator),
            Description = indicator.get('threat_type_desc'),
            MalwareFamilyTags=
                indicator.get('malware_printable') if indicator.get('malware_printable') != 'Unknown malware' else None,
            AliasesTags = indicator.get('malware_alias'),
            FirstSeenBySource = indicator.get('first_seen'),
            LastSeenBySource = indicator.get('last_seen'),
            ReportedBy = indicator.get('reporter'),
            Tags = indicator.get('tags'),
            Confidence = indicator.get('confidence_level'),
            Publications = indicator.get('reference')
        )
    return res_indicator


def parse_indicators(indicators: list)->List[dict[str, Any]]:
    res = []
    indicators = [indicators] if type(indicators) != list else indicators
    for indicator in indicators:
        res.append(parse_indicator_for_get_command(indicator))
    return res


def indicator_type(indicator: dict) -> str:
    """Returns the ioc type according to 'ioc_type' field in the indicator
    """
    type = indicator.get('ioc_type')
    if type == 'domain':
        return FeedIndicatorType.FQDN
    elif type == 'url':
        return FeedIndicatorType.URL
    elif type=='ip:port':
        indicator_type = FeedIndicatorType.ip_to_indicator_type(indicator.get('ioc'))
        return indicator_type if indicator_type else FeedIndicatorType.IP
    elif type == 'envelope_from' or type == 'body_from':
        return FeedIndicatorType.Email
    else:  # 'sha1_hash' 'sha256_hash' 'md5_hash'
        return FeedIndicatorType.File
    
    
def parse_indicator_for_fetch(indicator:dict, with_ports:bool, create_relationship:bool, tlp_color:str)->dict[str, Any]:
    
    demisto_ioc_type = indicator_type(indicator)
    ioc_value = value(indicator)
    relationships = create_relationships(ioc_value, indicator['ioc_type'], indicator.get("malware_printable"),
                                             demisto_ioc_type) if create_relationship else None
    
    fields = assign_params(
        indicatoridentification = indicator.get('id'),
        description = indicator.get('threat_type_desc'),
        malwarefamily = indicator.get('malware_printable') if indicator.get('malware_printable') != 'Unknown malware' else None,
        aliases = indicator.get('malware_alias'),
        firstseenbysource = date(indicator.get('first_seen')),
        lastseenbysource = date(indicator.get('last_seen')),
        reportedby = indicator.get('reporter'),
        Tags = tags(indicator, with_ports),
        publications = publications(indicator),
        confidence = indicator.get('confidence_level'),
        trafficlightprotocol= tlp_color
    )
    
    return assign_params(
            value= ioc_value,
            type= demisto_ioc_type,
            fields= fields,
            relationships= relationships,
            rawJSON= indicator
        )
    

def publications(indicator: dict)->Optional[List[dict[str, Any]]]:
    if not indicator.get('reference'):
        return None
    return [{'link': indicator.get('reference'),'title': indicator.get('malware_printable') if indicator.get('malware_printable')!= 'Unknown malware' else 'Malware' , 'source': 'ThreatFox'}]


def date(date):
    if date:
        parsed_date = arg_to_datetime(date, required=False)
        return parsed_date.strftime('%Y-%m-%dT%H:%M:%SZ')
    return None


def validate_interval(interval):
    if interval%1440 != 0:
        raise DemistoException("The fetch interval must be in whole days, between 1-7.")
    elif interval > 10080:
        raise DemistoException("The fetch interval must not be more than 7 days.")
    return interval


def tags(indicator, with_ports):
    
    res = [indicator.get('malware_printable'), indicator.get('malware_alias'), indicator.get('threat_type')]
    if indicator.get('tags'):
        res.extend(indicator.get('tags'))
    if with_ports and indicator.get('ioc_type') == "ip:port":
            res.append('port: ' + indicator.get('ioc').split(':')[1])
            
    res = [tag.lower() for tag in res if tag]
    
    # remove duplicate tags
    seen = set()
    res =  [tag for tag in res if tag not in seen and not seen.add(tag)]
    
    #TODO dedup
    
    return res


def value(indicator)->str:
    if indicator.get('ioc_type') == 'ip:port':
        return indicator.get('ioc').split(':')[0]
    return indicator.get('ioc')


def create_relationships(value: str, type: str, related_malware: Optional[str], demisto_ioc_type: str)->list:
    
    if related_malware:
        name = EntityRelationship.Relationships.COMMUNICATED_BY \
            if type == 'domain' or type == "ip:port" or type == 'url' else EntityRelationship.Relationships.RELATED_TO
        reverse_name = EntityRelationship.Relationships.COMMUNICATED_WITH \
            if type == 'domain' or type == "ip:port" or type == 'url' else EntityRelationship.Relationships.RELATED_TO
        return [EntityRelationship(entity_a=value, entity_a_type=demisto_ioc_type,
                                                    name=name,
                                                    entity_b=related_malware, entity_b_type=FeedIndicatorType.Malware,
                                                    brand='ThreatFox Feed', reverse_name=reverse_name).to_indicator()]
    return []


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
    
    if query_status != 'ok' and query_status:
        raise DemistoException(f'failed to run command {query_status} {query_data}')
    
    parsed_indicators = parse_indicators(result.get('data') or result)
    
    human_readable = tableToMarkdown(name='Indicators', t=parsed_indicators,
                                     headers=['ID', 'Value', 'Description', 'MalwareFamilyTags',
                                              'AliasesTags', 'FirstSeenBySource', 'LastSeenBySource', 'ReportedBy',
                                              'Tags', 'Confidence', 'Publications'], removeNull=True)
    
    return CommandResults(readable_output=human_readable)


def fetch_indicators_command(client: Client, with_ports, confidence_threshold,
                             create_relationship, interval, tlp_color):
    
    response = client.get_indicators_request({ "query": "get_iocs",
                                              "days": int((arg_to_number(interval) or 1)/1440)})
    
    if response.get('query_status') != 'ok':
        raise DemistoException("couldn't fetch")  # write something better
    
    demisto.debug(f'{LOG} got {response=}')  # erase
    
    results = []
       
    for indicator in response['data']:
        
        if indicator.get('ioc_type') == 'sha3_384_hash':
            demisto.debug(f'{LOG} got indicator of indicator type "sha3" skipping it')
            continue
        if arg_to_number(indicator.get('confidence_level')) < confidence_threshold:
            demisto.debug(f'{LOG} got indicator with low confidence level, skipping it')
            continue
        
        results.append(parse_indicator_for_fetch(indicator, with_ports, create_relationship, tlp_color))
        
    return results


''' MAIN FUNCTION '''


def main() -> None:
    
    command = demisto.command()
    
    params = demisto.params()
    base_url = urljoin(params['url'], '/api/v1')
    with_ports = argToBoolean(params.get('with_ports', False))
    confidence_threshold = arg_to_number(params.get('confidence_threshold'))   # Need to check that it is a number
    create_relationship = argToBoolean(params.get('create_relationship'))
    tlp_color = params.get('tlp_color')
    interval = validate_interval(arg_to_number(params.get('feedFetchInterval', 1440)))  # Need to check that it is a number
    
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
                demisto.debug(f"{LOG} {iter_=}")
                demisto.createIndicators(iter_)
    
    except Exception as e:
        raise Exception(e)
   # except Exception as e:
    #    return_error(f'Failed to execute {demisto.command()} command.\nError:\n{str(e)}')


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
    
    
    
