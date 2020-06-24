import json
from DeHashed import Client, test_module, dehashed_search_command

DEHASHED_URL = 'https://url.com/' # disable-secrets-detection
INTEGRATION_CONTEXT_BRAND = 'DeHashed'

def load_test_data(json_path):
    with open(json_path) as f:
        return json.load(f)


def test_module_command(requests_mock):
    test_data = load_test_data('test_data/search.json')
    requests_mock.post(f'{DEHASHED_URL}/search?query=vin:', json=test_data['api_response'])

    client = Client(
        base_url=f'{DEHASHED_URL}'
    )
    client._headers = {}
    res = test_module(client)

    assert res == 'ok'


def test_search_command_using_is_operator_without_filter(requests_mock):
    test_data = load_test_data('test_data/search.json')
    scan_expected_tesult = {f'{INTEGRATION_CONTEXT_BRAND}.search.actionId(val.Id == obj.Id)': 123}
    requests_mock.post(f'{DEHASHED_URL}/search', json=test_data['api_response'])

    client = Client(
        base_url=f'{DEHASHED_URL}'
    )
    client._headers = {}
    markdown, context, raw = dehashed_search_command(client, test_data['is_op'])

    assert scan_expected_tesult == context


def test_search_command_using_contains_operator_without_filter(requests_mock):
    pass


def test_search_command_using_regex_operator_without_filter(requests_mock):
    pass


def test_search_command_using_is_operator_with_filter(requests_mock):
    pass


def test_search_command_using_contains_operator_with_filter(requests_mock):
    pass


def test_search_command_using_regex_operator_with_filter(requests_mock):
    pass


