import json
import io

import pytest

import FeedThreatFox as ftf
CLIENT = ftf.Client(base_url= 'https://threatfox-api.abuse.ch/')

def util_load_json(path):
    with io.open(path, mode='r', encoding='utf-8') as f:
        return json.loads(f.read())


def test_get_indicators_request(mocker):
    """
    Given:
        - A query.
    
    When:
        - Running get_indicators_request function.
    
    Then:
        - The http request is called with the right query.
    """
    http_request = mocker.patch.object(CLIENT, '_http_request', return_value={})
    query = { "query": "ioc", "id": 41 }
    CLIENT.get_indicators_request(query)
    assert http_request.call_args.kwargs['json_data'] == query
    
    
test_check_params_good_arguments_data = [
    ({'days': 1},  # case days
     (True, 'days')),  # expected
    ({'id': 41, 'limit': 10},  # case id with limit (even though it is not needed)
     (True, 'id')),  # expected
    ({'search_term': '1.1.1.1'},  # case search_term
     (True, 'search_term')),  # expected
    ({'hash': '2151c4b970eff0071948dbbc19066aa4'},  # case hash
     (True, 'hash')),  # expected
    ({'tag': 'Magecart', 'limit': 10},  # case tag with limit
     (True, 'tag')),  # expected
    ({'malware': "Cobalt Strike", 'limit': 10},  # case malware without limit (limit is needed, there is a default value)
     (True, 'malware')),  # expected
]
@pytest.mark.parametrize('query_args, expected_result', test_check_params_good_arguments_data)
def test_check_params_good_arguments(query_args, expected_result):
    """
    Given:
        - Good arguments for a query.
    
    When:
        - Running check_params function.
    
    Then:
        - The function returns (True, {the argument's name}).
    """
    from FeedThreatFox import check_params_for_query
    is_valid, query_arg = check_params_for_query(query_args)
    assert (is_valid, query_arg) == expected_result
    
    
test_check_params_bad_arguments_data = [
    ( {'days': 1, 'tag': 'bla'},  # case two argument are given
     (False, None)),  # expected
    ({},  # case no arguments are given
     (False, None))  # expected
]
@pytest.mark.parametrize('query_args, expected_result', test_check_params_bad_arguments_data)
def test_check_params_bad_arguments(query_args, expected_result):
    """
    Given:
        - Wrong arguments for a query.
    
    When:
        - Running check_params function.
    
    Then:
        - The function returns (False, None).
    """
    from FeedThreatFox import check_params_for_query
    is_valid, query_arg = check_params_for_query(query_args)
    assert (is_valid, query_arg) == expected_result
    

test_create_query_data = [
    ('days', {'days': 1, 'id': None, 'search_term': None, 'hash': None, 'tag': None, 'malware': None, 'limit': None},  # case days
     {"query": "get_iocs", "days" : 1}),  # expected query
    ('days', {'days': 1, 'limit': 10, 'id': None, 'search_term': None,
      'hash': None, 'tag': None, 'malware': None},  # case days with limit that isn't needed
     {"query": "get_iocs", "days" : 1}),  # expected query, ignores limit
    ('tag', {'tag': 'bla', 'limit': 10, 'id': None, 'search_term': None,
      'hash': None, 'days': None, 'malware': None},  # case tag  with needed limit
     {"query": "taginfo", "tag": "bla", "limit" : 10}),  # expected query with limit
    ('tag', {'tag': 'bla', 'limit': None, 'id': None, 'search_term': None,
      'hash': None, 'days': None, 'malware': None},  # case tag with no needed limit
     {"query": "taginfo", "tag": "bla", "limit" : 50})  # expected query with default limit
]
@pytest.mark.parametrize('query_arg, args, expected_query', test_create_query_data)
def test_create_query(query_arg, args, expected_query):
    """
        Given:
            - Wrong arguments for a query.
        
        When:
            - Running check_params function.
        
        Then:
            - The function returns (False, None).
    """
    from FeedThreatFox import create_query
    query = create_query(query_arg, id = args['id'], search_term=args['search_term'], hash=args['hash'],
                         tag=args['tag'], malware=args['malware'], days=args['days'], limit=args['limit'])
    assert query == expected_query
 

def test_threatfox_get_indicators_command__bad_args():
    """
        Given:
            - Invalid arguments.
        
        When:
            - Running threatfox-get-indicators command.
        
        Then:
            - An exception is thrown.
    """
    from FeedThreatFox import threatfox_get_indicators_command
    from CommonServerPython import DemistoException
    with pytest.raises(DemistoException):
        threatfox_get_indicators_command(CLIENT, {'days': 1, 'tag': 'bla'})
        
        
def test_threatfox_get_indicators_command__bad_response(mocker):
    """
        Given:
            - Arguments with no relevant indicators.
        
        When:
            - Running threatfox-get-indicators command.
        
        Then:
            - An exception is thrown.
    """
    from FeedThreatFox import threatfox_get_indicators_command
    from CommonServerPython import DemistoException
    mocker.patch.object(CLIENT, '_http_request', return_value={'query_status': 'not okay', 'data': 'details about the problem'})
    with pytest.raises(DemistoException):
        threatfox_get_indicators_command(CLIENT, {'tag': 'bla'})


def test_threatfox_get_indicators_command(mocker):
    """
        Given:
            - Arguments.
        
        When:
            - Running threatfox-get-indicators command.
        
        Then:
            - The http request is called with the right argument.
    """
    from FeedThreatFox import threatfox_get_indicators_command
    http = mocker.patch.object(CLIENT, '_http_request', return_value={'query_status': 'ok', 'data': {}})
    threatfox_get_indicators_command(CLIENT, {'id': '41'})
    assert http.call_args.kwargs['json_data'] == { "query": "ioc", "id": 41 }


indicator_data = [
    ({'id': '123', 'ioc': '8.218.152.23:80', 'threat_type_desc': 'bla1',  # case one indicator
      'ioc_type': 'ip:port', 'malware': 'bla2', 'malware_printable': 'bla3', 'malware_alias': 'bla4', 'confidence_level': 100,
      'first_seen': '2024-08-04 07:31:49 UTC', 'last_seen': '2024-07-03T05:11:35Z UTC', 'reference': 'bla5',
      'reporter': 'bla6', 'tags': ['bla7', 'bla8']},
    [{'ID': '123', 'Value': '8.218.152.23', 'Description': 'bla1', 'MalwareFamilyTags': 'bla3',  # expected
      'AliasesTags': 'bla4', 'FirstSeenBySource': '2024-08-04 07:31:49 UTC', 'LastSeenBySource': '2024-07-03T05:11:35Z UTC',
      'ReportedBy': 'bla6', 'Tags': ['bla3', 'bla4', 'bla7', 'bla8', 'port: 80'], 'Confidence': 100,
      'Publications': [{'link': 'bla5','title': 'bla3', 'source': 'ThreatFox'}]}]
     ),
    ([{'id': '456', 'ioc': 'habdvhbkj',  # case two indicators
       'threat_type_desc': 'bla1', 'ioc_type': 'sha1_hash', 'malware': 'bla2', 'malware_printable': 'bla3',
       'malware_alias': 'bla4', 'confidence_level': 100, 'first_seen': '2024-08-04 07:31:49 UTC',
       'last_seen': '2024-07-03T05:11:35Z UTC'},
      {'id': '789', 'ioc': '8.218.152.23:80', 'threat_type_desc': 'bla1', 'ioc_type': 'ip:port', 'malware': 'bla2',
      'malware_printable': 'Unknown malware', 'malware_alias': 'bla4', 'confidence_level': 100,
      'first_seen': '2024-08-04 07:31:49 UTC', 'last_seen': '2024-07-03T05:11:35Z UTC',
      'tags': ['bla7', 'bla8']}],
     [{'ID': '456', 'Value': 'habdvhbkj', 'Description': 'bla1', 'MalwareFamilyTags': 'bla3',  # expected
      'AliasesTags': 'bla4', 'FirstSeenBySource': '2024-08-04 07:31:49 UTC', 'LastSeenBySource': '2024-07-03T05:11:35Z UTC',
      'Tags': ['bla3', 'bla4'], 'Confidence': 100},
      {'ID': '789', 'Value': '8.218.152.23', 'Description': 'bla1',
      'AliasesTags': 'bla4', 'FirstSeenBySource': '2024-08-04 07:31:49 UTC', 'LastSeenBySource': '2024-07-03T05:11:35Z UTC',
      'Tags': ['bla4', 'bla7', 'bla8', 'port: 80'], 'Confidence': 100}]),
]

@pytest.mark.parametrize('indicators, expected', indicator_data)
def test_parse_indicators_for_get_command(indicators, expected):
    """
        Given:
            - The raw response of an indicator.
        
        When:
            - Running parse_indicators_for_get_command func.
        
        Then:
            - The indicator returned is parsed correctly.
    """
    from FeedThreatFox import parse_indicators_for_get_command
    res = parse_indicators_for_get_command(indicators)
    assert res == expected
    

from CommonServerPython import FeedIndicatorType
types_data = [
    ({'ioc_type': 'domain'}, FeedIndicatorType.FQDN),
    ({'ioc_type': 'url'}, FeedIndicatorType.URL),
    ({'ioc_type': 'ip:port'}, FeedIndicatorType.IP),
    ({'ioc_type': 'envelope_from'}, FeedIndicatorType.Email),
    ({'ioc_type': 'body_from'}, FeedIndicatorType.Email),
    ({'ioc_type': 'sha1_hash'}, FeedIndicatorType.File)
]
@pytest.mark.parametrize('indicator, expected_type', types_data)
def test_indicator_type(indicator, expected_type):
    """
        Given:
            - An indicator.
        
        When:
            - Running indicator_type func.
        
        Then:
            - The right indicator type is returned.
    """
    from FeedThreatFox import indicator_type
    type = indicator_type(indicator)
    assert type == expected_type
    

publications_data = [
    ({}, None),  # case no reference field
    ({'reference': 'bla', 'malware_printable': 'Unknown malware'},  # case malware_printable in unknown
     [{'link': 'bla','title': 'Malware' , 'source': 'ThreatFox'}]),
    ({'reference': 'bla', 'malware_printable': 'bla2'},  # case there is malware_printable
     [{'link': 'bla','title': 'bla2' , 'source': 'ThreatFox'}]),
    ({'reference': 'bla'},  # case no malware_printable field
     [{'link': 'bla','title': 'Malware' , 'source': 'ThreatFox'}])
]
@pytest.mark.parametrize('indicator, expected', publications_data)
def test_publications(indicator, expected):
    """
        Given:
            - An indicator.
        
        When:
            - Running publications func.
        
        Then:
            - The right publications list is returned.
    """
    from FeedThreatFox import publications
    publications = publications(indicator)
    assert publications == expected
    
date_data = [
    ('2024-07-03T05:11:35Z UTC', '2024-07-03T05:11:35Z'),
    (None, None)
]
@pytest.mark.parametrize('given_date, expected', date_data)
def test_date(given_date, expected):
    """
        Given:
            - A date from raw response.
        
        When:
            - Running date func.
        
        Then:
            - The date is parsed correctly.
    """
    from FeedThreatFox import date
    res_date = date(given_date)
    assert res_date == expected


tags_data = [
    ({'malware_alias': 'Bla2', 'threat_type': 'bla3', 'ioc_type': 'ip:port', 'ioc': '1.1.1.1:80', 'tags': ['Bla2']}, True,  # case
     ['bla2', 'bla3', 'port: 80']),  # expected
    ({'malware_printable': 'bla1', 'tags': ['bla4', 'bla5']}, False,  # second case
     ['bla1', 'bla4', 'bla5']),  # expected
    ({'malware_printable': 'Unknown malware'}, False,  # third case
     [])  # expected
]
@pytest.mark.parametrize('indicator, with_ports, expected_tags', tags_data)
def test_tags(indicator, with_ports, expected_tags):
    """
        Given:
            - The raw json of an indicator and a with_ports boolean argument.
        
        When:
            - Running tags func.
        
        Then:
            - The right list of tags to add to the indicator is returned.
    """
    from FeedThreatFox import tags
    tags = tags(indicator, with_ports)
    assert tags == expected_tags
    

value_data = [
    ({'ioc_type': 'ip:port', 'ioc': '1.1.1.1:80'}, '1.1.1.1'),
    ({'ioc_type': 'url', 'ioc': 'www...'}, 'www...')
]
@pytest.mark.parametrize('indicator, expected_value', value_data)
def test_value(indicator, expected_value):
    """
        Given:
            - The raw json of an indicator.
        
        When:
            - Running value func.
        
        Then:
            - The value of the indicator is given, when the value is an ip and port then the port is dumped.
    """
    from FeedThreatFox import value
    value = value(indicator)
    assert value == expected_value
    

from CommonServerPython import FeedIndicatorType
relationships_data = [
    ('bla1', 'bla2', None, FeedIndicatorType.Email,  # case no related_malware field
     []),  # case no relationships
    ('bla3', 'domain', 'bla4', FeedIndicatorType.FQDN,  # case indicator type is domain
     [{'name': 'communicated-by', 'reverseName': 'communicated-with',    # expected communicated-by relationship
       'type': 'IndicatorToIndicator', 'entityA': 'bla3', 'entityAFamily': 'Indicator',
       'entityAType': 'Domain', 'entityB': 'bla4', 'entityBFamily': 'Indicator', 'entityBType': 'Malware', 'fields': {}}]),
    ('bla5', 'sha1_hash', 'bla6', FeedIndicatorType.File,  # case indicator type is file
     [{'name': 'related-to', 'reverseName': 'related-to', 'type': 'IndicatorToIndicator',  # expected related-to relationship
       'entityA': 'bla5', 'entityAFamily': 'Indicator', 'entityAType': 'File', 'entityB': 'bla6',
       'entityBFamily': 'Indicator', 'entityBType': 'Malware', 'fields': {}}])
]
@pytest.mark.parametrize('value, type, related_malware, demisto_ioc_type, expected', relationships_data)
def test_create_relationships(value, type, related_malware, demisto_ioc_type, expected):
    """
        Given:
            - A value, type and related_malware fields of an indicator.
        
        When:
            - Running create_relationships func.
        
        Then:
            - The right relationships are returned from the function.
    """
    from FeedThreatFox import create_relationships
    relationships = create_relationships(value, type, related_malware, demisto_ioc_type)
    assert relationships == expected

    