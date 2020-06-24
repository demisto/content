import json
import urllib
from DeHashed import Client, test_module, dehashed_search_command

DEHASHED_URL = 'https://url.com/' # disable-secrets-detection
INTEGRATION_CONTEXT_BRAND = 'DeHashed'

def load_test_data(json_path):
    with open(json_path) as f:
        return json.load(f)


def test_module_command(requests_mock):
    test_data = load_test_data('test_data/search.json')
    url_params = {'query': 'vin:"test" "test1"'}
    encoded = urllib.parse.urlencode(url_params)

    requests_mock.get(f'{DEHASHED_URL}search?{encoded}', json=test_data['api_response'])

    client = Client(
        base_url=f'{DEHASHED_URL}'
    )
    client._headers = {}
    res = test_module(client)

    assert res == 'ok'


def test_search_command_using_is_operator_without_filter(requests_mock):
    test_data = load_test_data('test_data/search.json')
    scan_expected_result = {"DeHashed.Search(val.Id==obj.Id)": test_data['expected_results']['full_results']}
    url_params = {'query': '"testgamil.co"'}
    encoded = urllib.parse.urlencode(url_params)
    requests_mock.get(f'{DEHASHED_URL}search?{encoded}', json=test_data['api_response'])

    client = Client(
        base_url=f'{DEHASHED_URL}'
    )
    client._headers = {}
    markdown, context, raw = dehashed_search_command(client, test_data['is_op_single'])

    assert scan_expected_result == context


def test_search_command_using_contains_operator_without_filter(requests_mock):
    test_data = load_test_data('test_data/search.json')
    scan_expected_result = {"DeHashed.Search(val.Id==obj.Id)": test_data['expected_results']['full_results']}
    url_params = {'query': 'testgamil.co'}
    encoded = urllib.parse.urlencode(url_params)
    requests_mock.get(f'{DEHASHED_URL}search?{encoded}', json=test_data['api_response'])

    client = Client(
        base_url=f'{DEHASHED_URL}'
    )
    client._headers = {}
    markdown, context, raw = dehashed_search_command(client, test_data['contains_op_single'])

    assert scan_expected_result == context


def test_search_command_using_regex_operator_without_filter(requests_mock):
    test_data = load_test_data('test_data/search.json')
    scan_expected_result = {"DeHashed.Search(val.Id==obj.Id)": test_data['expected_results']['full_results']}
    url_params = {'query': '/joh?n(ath[oa]n)/'}
    encoded = urllib.parse.urlencode(url_params)
    requests_mock.get(f'{DEHASHED_URL}search?{encoded}', json=test_data['api_response'])

    client = Client(
        base_url=f'{DEHASHED_URL}'
    )
    client._headers = {}
    markdown, context, raw = dehashed_search_command(client, test_data['regex_op_single'])

    assert scan_expected_result == context


def test_search_command_using_is_operator_with_filter_and_multi_values(requests_mock):
    test_data = load_test_data('test_data/search.json')
    scan_expected_result = {"DeHashed.Search(val.Id==obj.Id)": test_data['expected_results']['full_results']}
    url_params = {'query': 'email:"testgamil.co" "test1gmail.com"'}
    encoded = urllib.parse.urlencode(url_params)
    requests_mock.get(f'{DEHASHED_URL}search?{encoded}', json=test_data['api_response'])

    client = Client(
        base_url=f'{DEHASHED_URL}'
    )
    client._headers = {}
    markdown, context, raw = dehashed_search_command(client, test_data['is_op_multi'])

    assert scan_expected_result == context


def test_search_command_using_contains_operator_with_filter_and_multi_values(requests_mock):
    test_data = load_test_data('test_data/search.json')
    scan_expected_result = {"DeHashed.Search(val.Id==obj.Id)": test_data['expected_results']['full_results']}
    url_params = {'query': 'name:(test1 OR test2)'}
    encoded = urllib.parse.urlencode(url_params)
    requests_mock.get(f'{DEHASHED_URL}search?{encoded}', json=test_data['api_response'])

    client = Client(
        base_url=f'{DEHASHED_URL}'
    )
    client._headers = {}
    markdown, context, raw = dehashed_search_command(client, test_data['contains_op_multi'])

    assert scan_expected_result == context


def test_search_command_using_regex_operator_with_filter_and_multi_values(requests_mock):
    test_data = load_test_data('test_data/search.json')
    scan_expected_result = {"DeHashed.Search(val.Id==obj.Id)": test_data['expected_results']['full_results']}
    url_params = {'query': 'vin:/joh?n(ath[oa]n)/ /joh?n11(ath[oa]n)/'}
    encoded = urllib.parse.urlencode(url_params)
    requests_mock.get(f'{DEHASHED_URL}search?{encoded}', json=test_data['api_response'])

    client = Client(
        base_url=f'{DEHASHED_URL}'
    )
    client._headers = {}
    markdown, context, raw = dehashed_search_command(client, test_data['regex_op_multi'])

    assert scan_expected_result == context


