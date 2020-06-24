import json

NOZOMIGUARDIAN_URL = 'https://test.com'


def load_test_data(json_path):
    with open(json_path) as f:
        return json.load(f)


def test_search_by_query(requests_mock):
    from NozomiGuardian import Client, search_by_query
    search_by_query_response = load_test_data('./test_data/search_by_query.json')
    requests_mock.get(f'{NOZOMIGUARDIAN_URL}/api/open/query/do?query='
                      f'links | where from match 192.168.10.2 | where protocol match ssh', json=search_by_query_response)

    client = Client(
        f'{NOZOMIGUARDIAN_URL}',
        auth=('test', 'test')
    )
    args = {
        'query': 'links | where from match 192.168.10.2 | where protocol match ssh'
    }
    _, outputs, _ = search_by_query(client, args)
    expected_output = search_by_query_response

    assert expected_output.get('result') == outputs.get('NozomiGuardian').get('Queries')[0][0]


def test_list_all_assets(requests_mock):
    from NozomiGuardian import Client, list_all_assets
    list_all_assets_response = load_test_data('./test_data/list_all_assets.json')
    requests_mock.get(f'{NOZOMIGUARDIAN_URL}/api/open/query/do?query=assets', json=list_all_assets_response)

    client = Client(
        f'{NOZOMIGUARDIAN_URL}',
        auth=('test', 'test')
    )
    _, outputs, _ = list_all_assets(client)
    expected_output = list_all_assets_response

    assert expected_output.get('result')[0].get('capture_device') == \
        outputs.get('NozomiGuardian').get('Assets')[0]['CaptureDevice']


def test_find_ip_by_mac(requests_mock):
    from NozomiGuardian import Client, find_ip_by_mac
    find_ip_by_mac_response = load_test_data('./test_data/find_ip_by_mac.json')
    requests_mock.get(f'{NOZOMIGUARDIAN_URL}/api/open/query/do?query=assets | '
                      f'where mac_address match 00:0c:29:22:50:26', json=find_ip_by_mac_response)

    client = Client(
        f'{NOZOMIGUARDIAN_URL}',
        auth=('test', 'test')
    )
    args = {
        'mac': '00:0c:29:22:50:26'
    }
    _, outputs, _ = find_ip_by_mac(client, args)
    expected_output = find_ip_by_mac_response

    assert expected_output.get('result')[0].get('ip') == outputs.get('NozomiGuardian').get('Mappings')[0]['IP']
