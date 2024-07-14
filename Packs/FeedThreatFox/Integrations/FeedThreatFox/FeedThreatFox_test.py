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
    from FeedThreatFox import check_params
    is_valid, query_arg = check_params(query_args)
    assert (is_valid, query_arg) == expected_result
    
    
test_check_params_bad_arguments_data = [
    ( {'days': 1, 'tag': 'bla'},  # case two argument are given
     (False, None)),  # expected
    ({},  # case no arguments are given
     (False, None))  # expected
]
@pytest.mark.parametrize('query_args, expected_result', test_check_params_bad_arguments_data)
def test_check_params_bad_arguments(query_args, expected_result,test_check_params_bad_arguments_data):
    """
    Given:
        - Wrong arguments for a query.
    
    When:
        - Running check_params function.
    
    Then:
        - The function returns (False, None).
    """
    from FeedThreatFox import check_params
    is_valid, query_arg = check_params(query_args)
    assert (is_valid, query_arg) == expected_result
    