import pytest
from NozomiNetworks import *
import demistomock as demisto
from unittest.mock import patch

# Mock the `callingContext` before invoking your client or code that needs it
demisto.callingContext = {
    'context': {
        'IntegrationBrand': 'NozomiNetworks'
    }
}

NOZOMIGUARDIAN_URL = 'https://test.com'


@pytest.mark.parametrize('obj, expected', [({'last_id': "an_id"}, True), ({}, False), (None, False), ])
def test_has_last_id(obj, expected):
    assert has_last_id(obj) is expected


@pytest.mark.parametrize('obj, expected', [({'last_fetch': "a_timestamp"}, True), ({}, False), (None, False), ])
def test_has_last_run(obj, expected):
    assert has_last_run(obj) is expected


def test_start_time_return_value():
    assert start_time({'last_fetch': 1540390400000}) == "1540390400000"


def test_start_time_return_timestamp():
    time = start_time({})
    assert time is not None
    assert len(time) == 13


def test_start_time_if_last_run_0_return_default():
    time = start_time({'last_fetch': '0'})
    assert time is not None
    assert len(time) == 13


@pytest.mark.parametrize(
    'obj, expected',
    [
        (None, ''),
        ('', ''),
        ("1540390400000", " | where record_created_at > 1540390400000"),
    ]
)
def test_time_filter(obj, expected):
    assert better_than_time_filter(obj) == expected


@pytest.mark.parametrize(
    'obj, expected',
    [
        (None, ''),
        ('', ''),
        ("1540390400000", " | where record_created_at == 1540390400000"),
    ]
)
def test_equal_time_filter_with_ts(obj, expected):
    assert equal_than_time_filter(obj) == expected


def test_parse_incidents():
    i = parse_incident({
        'id': '1af93f46-65c1-4f52-a46a-2a181597fb0c',
        'type_id': 'NET:RST-FROM-SLAVE',
        'name': 'Link RST sent by Slave',
        'description': 'The slave 10.197.23.139 sent a RST of the connection to the master.',
        'severity': 10,
        'mac_src': '00:02:3e:99:c9:5d',
        'mac_dst': '00:c0:c9:30:04:f1',
        'ip_src': '10.197.23.182',
        'ip_dst': '10.197.23.139',
        'risk': '4.5',
        'protocol': 'iec104',
        'src_roles': 'master',
        'dst_roles': 'slave',
        'record_created_at': 1392048082242,
        'ack': False,
        'port_src': 1097,
        'port_dst': 2404,
        'status': 'open',
        'threat_name': '',
        'type_name': 'Link RST sent by Slave',
        'zone_src': 'RemoteRTU',
        'zone_dst': 'RemoteRTU'
    })

    del i['occurred']

    assert i == {
        'name': 'Link RST sent by Slave_1af93f46-65c1-4f52-a46a-2a181597fb0c',
        'severity': 2,
        'rawJSON': '{"id": "1af93f46-65c1-4f52-a46a-2a181597fb0c", '
                   '"type_id": "NET:RST-FROM-SLAVE", "name": "Link RST sent by Slave", '
                   '"description": "The slave 10.197.23.139 sent a RST of the connection to the master.", '
                   '"severity": 10, "mac_src": "00:02:3e:99:c9:5d", "mac_dst": "00:c0:c9:30:04:f1", '
                   '"ip_src": "10.197.23.182", "ip_dst": "10.197.23.139", "risk": "4.5", "protocol": "iec104", '
                   '"src_roles": "master", "dst_roles": "slave", "record_created_at": 1392048082242, "ack": false, '
                   '"port_src": 1097, "port_dst": 2404, "status": "open", "threat_name": "", '
                   '"type_name": "Link RST sent by Slave", "zone_src": "RemoteRTU", "zone_dst": "RemoteRTU"}'
    }


@pytest.mark.parametrize('obj, expected', [(10, 4), (9.0, 4), (8.5, 4), (2.3, 1), (1.6, 1)])
def test_parse_severity(obj, expected):
    assert parse_severity({'risk': obj}) is expected


def test_http_incident_request(requests_mock):
    request_path = '/api/open/query/do?query=alerts'
    r = __get_client(
        [
            {
                'json': __load_test_data('./test_data/query_alerts.json'),
                'path': request_path
            }
        ],
        requests_mock).http_get_request(request_path)
    assert len(r['result']) == 126
    assert r['total'] == 126


def test_incidents_better_than_id():
    filtered = incidents_better_than_id([{'id': 'a'}, {'id': 'b'}, {'id': 'f'}, {'id': '0'}], 'a')
    assert filtered == [{'id': 'b'}, {'id': 'f'}]


def test_incidents_filtered(requests_mock):
    fi, lr, lid = incidents(
        '1392048082000',
        None,
        {},
        '4',
        True,
        __get_client(
            [{'json': __load_test_data('./test_data/incidents_better_than_time.json'),
              'path': '/api/open/query/do?query=alerts | sort record_created_at asc | sort id asc '
              '| where record_created_at > 1392048082000 | where risk >= 4 | head 20'}],
            requests_mock))

    assert lid is not None
    assert lr == 1392048082242
    assert list(map(lambda i: {
        'name': f"{i['name'].partition('_')[0]}",
        'severity': i['severity']
    }, fi)) == [{'name': 'Link RST sent by Slave', 'severity': 2}, {'name': 'New Node', 'severity': 4}]


def test_nozomi_alerts_ids_from_demisto_incidents():
    assert nozomi_alerts_ids_from_demisto_incidents([]) == []


def test_is_alive(requests_mock):
    assert is_alive(
        __get_client(
            [{'json': __load_test_data('./test_data/alive.json'), 'path': '/api/open/query/do?query=alerts | count'}],
            requests_mock)) == 'ok'


def test_ids_from_incidents():
    assert ids_from_incidents([{'id': 1}, {'id': 2}]) == [1, 2]


@pytest.mark.parametrize('obj, expected', [('8', ' | where risk >= 8'), ('', ''), (None, '')])
def test_risk_filter(obj, expected):
    assert risk_filter(obj) == expected


@pytest.mark.parametrize('obj, expected', [(True, ''), (False, ' | where is_incident == false')])
def test_also_n2os_incidents_filter_true(obj, expected):
    assert also_n2os_incidents_filter(True) == ''


def test_find_assets(requests_mock):
    result = find_assets({}, __get_client(
        [
            {
                'json': __load_test_data('./test_data/find_assets.json'),
                'path': '/api/open/query/do?query=assets | sort id | head 50'
            }
        ],
        requests_mock
    ))

    assert ('### Nozomi Networks - Results for Find Assets' in result['readable_output']) is True
    assert len(result['outputs']) == 8
    assert result['outputs_key_field'] == 'id'
    assert result['outputs_prefix'] == 'Nozomi.Asset'


def test_assets_limit_from_args():
    assert assets_limit_from_args({'limit': 40}) == 40


def test_assets_limit_from_args_string():
    assert assets_limit_from_args({'limit': '40'}) == 40


def test_assets_limit_from_args_empty():
    assert assets_limit_from_args({}) == 50


def test_assets_max_limit_reached_return_1000():
    assert assets_limit_from_args({'limit': 1001}) == 100


def test_assets_limit_from_args_none():
    assert assets_limit_from_args(None) == 50


def test_find_assets_empty(requests_mock):
    result = find_assets(
        {'filter': ' | where level == 4'},
        __get_client(
            [
                {
                    'json': __load_test_data('./test_data/empty_find_asset.json'),
                    'path': '/api/open/query/do?query=assets | sort id | where level == 4 | head 50'
                }
            ],
            requests_mock
        ))
    assert result['outputs'] == []
    assert result['readable_output'] == 'Nozomi Networks - No assets found'


def test_better_than_id_filter_empty():
    assert better_than_id_filter(None) == ''
    assert better_than_id_filter('') == ''


def test_better_than_id_filter():
    assert better_than_id_filter('an_id') == ' | where id > an_id'


def test_filter_from_args_empty():
    filter_from_args({})
    assert filter_from_args({}) == ''


def test_filter_from_args_none():
    assert filter_from_args(None) == ''


def test_filter_from_args_valid():
    assert filter_from_args({'filter': ' | where id == 123'}) == ' | where id == 123'


def test_filter_without_where():
    assert filter_from_args({'filter': 'id == 123'}) == ' | where id == 123'


def test_filter_with_where():
    assert filter_from_args({'filter': '| where id == 123'}) == '| where id == 123'


def test_ip_from_mac(requests_mock):
    mac = '00:d0:c9:ca:bd:6a'
    result = find_ip_by_mac(
        {'mac': mac, 'only_nodes_confirmed': False},
        __get_client(
            [
                {
                    'json': __load_test_data('./test_data/find_by_mac.json'),
                    'path': '/api/open/query/do?query=nodes | select ip mac_address '
                            '| where mac_address == 00:d0:c9:ca:bd:6a'
                }
            ],
            requests_mock
        ))
    assert result['readable_output'] == "Nozomi Networks - Results for the Ip from Mac Search is " \
                                        "['10.196.97.231', '172.16.0.4']"
    assert result['outputs'] == {'ips': ['10.196.97.231', '172.16.0.4'], 'mac': mac}
    assert result['outputs_prefix'] == 'Nozomi.IpByMac'
    assert result['outputs_key_field'] is None


def test_ip_from_mac_not_found(requests_mock):
    result = find_ip_by_mac(
        {'mac': '12:33:44:55:bd:6a', 'only_nodes_confirmed': False},
        __get_client(
            [
                {
                    'json': __load_test_data('./test_data/empty_find_by_mac.json'),
                    'path': '/api/open/query/do?query=nodes | select ip mac_address '
                            '| where mac_address == 12:33:44:55:bd:6a'
                }
            ],
            requests_mock
        ))
    assert result['readable_output'] == 'Nozomi Networks - No IP results were found for mac address: 12:33:44:55:bd:6a'
    assert result['outputs'] is None


def test_query_count_alerts(requests_mock):
    result = query(
        {'query': 'alerts | count'},
        __get_client(
            [
                {
                    'json': __load_test_data('./test_data/alive.json'),
                    'path': '/api/open/query/do?query=alerts | count | head 500'
                }
            ],
            requests_mock
        ))
    assert result['outputs'] == [{'count': 126}]
    assert result['outputs_prefix'] == 'Nozomi.Query.Result'
    assert result['outputs_key_field'] == ''


@patch('NozomiNetworks.handle_proxy')
def test_get_proxies_with_proxy_enabled(mock_handle_proxy):
    mock_handle_proxy.return_value = {'http': 'http://proxy.com'}

    client = Client(base_url="https://test.com", proxy=True)
    proxies = client.get_proxies()

    assert proxies == {'http': 'http://proxy.com'}
    mock_handle_proxy.assert_called_once()


def test_get_proxies_without_proxy():
    client = Client(base_url="https://test.com", proxy=False)
    proxies = client.get_proxies()
    assert proxies == {}


def test_get_proxies_with_none_proxy():
    client = Client(base_url="https://test.com", proxy=None)
    proxies = client.get_proxies()
    assert proxies == {}


def __get_client(dummy_responses, requests_mock):
    for dummy_response in dummy_responses:
        requests_mock.get(
            f'{NOZOMIGUARDIAN_URL}{dummy_response["path"]}',
            json=dummy_response["json"]
        )
    return Client(
        f'{NOZOMIGUARDIAN_URL}',
        auth=('test', 'test')
    )


def __load_test_data(json_path):
    with open(json_path) as f:
        return json.load(f)
