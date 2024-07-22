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
 
 
 
"""
test_threatfox_get_indicators_command__bad_args_data = [
    ( {'days': 1, 'tag': 'bla'},  # case two argument are given
     (False, None)),  # expected
    ({},  # case no arguments are given
     (False, None))  # expected
]
@pytest.mark.parametrize('args', test_create_query_data)
def test_threatfox_get_indicators_command__bad_args(mocker, args):
    
        Given:
            - Invalid arguments.
        
        When:
            - Running threatfox-get-indicators command.
        
        Then:
            - An exception is thrown.
    
    from FeedThreatFox import threatfox_get_indicators_command, check_params_for_query, create_query
    is_valid, query_type = check_params_for_query(args, return_value={'query_status': 'not okay', 'data': 'details about the problem'})
    http_request = mocker.patch.object(CLIENT, '_http_request', return_value={}
"""
    
    