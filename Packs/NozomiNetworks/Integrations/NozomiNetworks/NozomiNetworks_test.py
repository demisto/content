import pytest
from NozomiNetworks import *
import demistomock as demisto
from unittest.mock import MagicMock, patch

demisto.callingContext = {
    'context': {
        'IntegrationBrand': 'NozomiNetworks'
    }
}

NOZOMIGUARDIAN_URL = 'https://test.com'


def mock_sign_in(client):
    client.bearer_token = "mock_access_token"
    client.token_expiry = datetime.now() + timedelta(seconds=1800)
    client.use_basic_auth = False


@pytest.fixture
def client_with_mock_sign_in():
    client = Client(base_url=NOZOMIGUARDIAN_URL)
    client.sign_in = MagicMock(side_effect=lambda: mock_sign_in(client))
    return client


@pytest.mark.parametrize('obj, expected', [({'last_fetch': "a_timestamp"}, True), ({}, False), (None, False)])
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


def test_incidents_when_ibtt_is_none(requests_mock):
    st = '1392048082000'
    last_run = {'last_fetch': '1392048082000'}
    risk = '4'
    also_n2os_incidents = True

    client = __get_client([], requests_mock)

    with patch('NozomiNetworks.incidents_better_than_time', return_value=None):
        incidents_result, lft = incidents(st, last_run, risk, also_n2os_incidents, client)

        assert incidents_result == []
        assert lft == last_run.get('last_fetch', st)


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


def test_response_with_error():
    client = MagicMock()

    client.http_post_request.return_value = {'error': "pippo"}

    assert ack_unack_alerts(ids=[1, 2, 3], status=True, client=client) is None


def test_incidents_filtered(requests_mock):
    fi, lr = incidents(
        '1392048082000',
        {},
        '4',
        True,
        __get_client(
            [{'json': __load_test_data('./test_data/incidents_better_than_time.json'),
              'path': '/api/open/query/do?query=alerts | sort record_created_at asc '
              '| where record_created_at > 1392048082000 | where risk >= 4&page=1&count=100'}],
            requests_mock))

    assert lr == 1392048082242
    assert [{
        'name': f"{i['name'].partition('_')[0]}",
        'severity': i['severity']
    } for i in fi] == [{'name': 'Link RST sent by Slave', 'severity': 2}, {'name': 'New Node', 'severity': 4}]


def test_nozomi_alerts_ids_from_demisto_incidents():
    assert nozomi_alerts_ids_from_demisto_incidents([]) == []


def test_is_alive(requests_mock):
    requests_mock.post(f"{NOZOMIGUARDIAN_URL}/api/open/sign_in", json={
        "access_token": "mock_access_token",
        "token_type": "Bearer",
        "expires_in": 1800
    })

    requests_mock.get(f"{NOZOMIGUARDIAN_URL}/api/open/query/do?query=alerts | count", json={
        "result": [{"count": 126}],
        "total": 1
    })

    client = Client(base_url=NOZOMIGUARDIAN_URL)
    assert is_alive(client) == 'ok'


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


def test_find_assets_with_none_result_in_loop(requests_mock):
    response_sequence = [
        {"result": None},
        {"result": [{"id": "1", "name": "Asset 1"}]}
    ]

    client = MagicMock()
    client.http_get_request = MagicMock(side_effect=response_sequence)

    args = {}
    head = 10
    result = find_assets(args, client, head=head)

    client.http_get_request.assert_called()
    assert len(result['outputs']) == 1
    assert result['outputs'][0]['id'] == "1"
    assert "Nozomi.Asset" in result['outputs_prefix']
    assert result['outputs_key_field'] == "id"
    assert "Asset 1" in result['readable_output']


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


def test_incidents_head_limit(requests_mock):
    import urllib.parse

    query = "alerts | sort record_created_at asc | where record_created_at > 1392048082000 | where risk >= 4"
    request_path = f"/api/open/query/do?query={urllib.parse.quote(query)}&page=1&count=100"

    client = __get_client(
        [
            {
                'json': {
                    "result": [
                        {
                            "id": 1,
                            "name": "Mock Incident 1",
                            "record_created_at": 1392048082001,
                            "risk": 4.5  # Example field for severity parsing
                        },
                        {
                            "id": 2,
                            "name": "Mock Incident 2",
                            "record_created_at": 1392048082002,
                            "risk": 3.0
                        }
                    ],
                    "total": 2
                },
                'path': request_path
            }
        ],
        requests_mock
    )

    incidents_result, lft = incidents(
        '1392048082000',
        {},
        '4',
        True,
        client
    )

    assert requests_mock.called
    assert lft == 1392048082002
    assert len(incidents_result) == 2
    assert incidents_result[0]['name'] == "Mock Incident 1_1"
    assert incidents_result[1]['name'] == "Mock Incident 2_2"


def test_last_fetched_time_empty_incidents():
    last_run = {'last_fetch': 1392048082000}
    result = last_fetched_time([], last_run)
    assert result == 1392048082000

    incidents = [{'id': 1}]
    result = last_fetched_time(incidents, last_run)
    assert result == 1392048082000


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


def test_sign_in(client_with_mock_sign_in):
    client = client_with_mock_sign_in
    client.sign_in()
    assert client.bearer_token == "mock_access_token"
    assert not client.use_basic_auth


def test_fallback_to_basic_auth_real_logic(requests_mock, capfd):
    with capfd.disabled():
        client = Client(base_url=NOZOMIGUARDIAN_URL)
        requests_mock.post(f"{NOZOMIGUARDIAN_URL}/api/open/sign_in", status_code=500)
        try:
            client.sign_in()
        except Exception as e:
            assert "Authentication failed" in str(e)

        assert client.use_basic_auth


def test_sign_in_successful(requests_mock):
    requests_mock.post(
        f"{NOZOMIGUARDIAN_URL}/api/open/sign_in",
        json={},
        status_code=200,
        headers={"Authorization": "Bearer mock_token"}
    )

    client = Client(base_url=NOZOMIGUARDIAN_URL, auth_credentials=("mock_key", "mock_token"))
    client.sign_in()

    assert client.bearer_token == "Bearer mock_token"
    assert not client.use_basic_auth


def test_sign_in_failure_with_auth_fallback(requests_mock):
    requests_mock.post(f"{NOZOMIGUARDIAN_URL}/api/open/sign_in", status_code=401, text="Unauthorized")

    client = Client(base_url=NOZOMIGUARDIAN_URL, auth_credentials=("mock_key", "mock_token"))
    client.sign_in()

    assert client.bearer_token is None
    assert client.use_basic_auth


def test_sign_in_exception_handling(requests_mock):
    requests_mock.post(f"{NOZOMIGUARDIAN_URL}/api/open/sign_in", exc=requests.exceptions.ConnectionError)

    client = Client(base_url=NOZOMIGUARDIAN_URL, auth_credentials=("mock_key", "mock_token"))
    client.sign_in()

    assert client.bearer_token is None
    assert client.use_basic_auth


def test_request_auth_failure():
    __run_request_test(401, "Authentication failure or resource forbidden.")


def test_request_forbidden_failure():
    __run_request_test(403, "Authentication failure or resource forbidden.")


@patch('NozomiNetworks.handle_proxy')
def test_build_proxies_with_proxy_enabled(mock_handle_proxy):
    mock_handle_proxy.return_value = {'http': 'pippoebasta'}

    client = Client(base_url="https://test.com", proxy=True)
    proxies = client.build_proxies()

    assert proxies == {'http': 'pippoebasta'}
    mock_handle_proxy.assert_called_once()


def test_build_proxies_without_proxy():
    client = Client(base_url="https://test.com", proxy=False)
    proxies = client.build_proxies()
    assert proxies == {}


def test_build_proxies_with_none_proxy():
    client = Client(base_url="https://test.com", proxy=None)
    proxies = client.build_proxies()
    assert proxies == {}


@pytest.mark.parametrize("use_basic_auth, bearer_token, expected_headers", [
    (True, "dummy_token", {"accept": "application/json"}),
    (False, "Bearer my_token", {"accept": "application/json", "Authorization": "Bearer my_token"}),
    (True, None, {"accept": "application/json"})
])
def test_build_headers(use_basic_auth, bearer_token, expected_headers):
    client = Client(bearer_token=bearer_token, use_basic_auth=use_basic_auth)
    assert client.build_headers() == expected_headers


@pytest.mark.parametrize(
    "demisto_params, expected_result, expect_exception",
    [
        ({'incidentPerRun': '15'}, 15, False),
        ({}, DEFAULT_COUNT_ALERTS, False),
        ({'incidentPerRun': 'abc'}, None, True),
    ]
)
def test_incident_per_run(demisto_params, expected_result, expect_exception):
    with patch('NozomiNetworks.demisto') as mock_demisto:
        mock_demisto.params.return_value = demisto_params
        if expect_exception:
            with pytest.raises(ValueError):
                incident_per_run()
        else:
            result = incident_per_run()
            assert result == expected_result


@pytest.mark.parametrize(
    "current_page, incidents_count, incident_per_run_value, expected_next_page",
    [
        (50, 10, 20, 1),
        (50, 30, 20, 51),
        (100, 10, 20, 1),
        (99, 0, 20, 99),
        (100, 0, 20, 100),
        (50, 20, 20, 51),
        (100, 50, 20, 1),
    ]
)
def test_build_next_page(current_page, incidents_count, incident_per_run_value, expected_next_page):
    with patch('NozomiNetworks.incident_per_run', return_value=incident_per_run_value):
        result = build_next_page(current_page, incidents_count)
        assert result == expected_next_page


@pytest.mark.parametrize(
    "last_fetch, next_page, st, expected_result",
    [
        (1672531200000, 1, 1672617600000, 1672531200000),
        (1672531200000, 2, 1672617600000, 1672617600000),
        (1672531200000, 10, 1672617600000, 1672617600000)
    ]
)
def test_last_fetch_to_set(last_fetch, next_page, st, expected_result):
    result = last_fetch_to_set(last_fetch, next_page, st)
    assert result == expected_result


def __get_client(dummy_responses, requests_mock):
    requests_mock.post(f"{NOZOMIGUARDIAN_URL}/api/open/sign_in", json={
        "access_token": "mock_access_token",
        "token_type": "Bearer",
        "expires_in": 1800
    })

    for dummy_response in dummy_responses:
        requests_mock.get(
            f'{NOZOMIGUARDIAN_URL}{dummy_response["path"]}',
            json=dummy_response["json"]
        )

    client = Client(base_url=NOZOMIGUARDIAN_URL)

    client.sign_in()

    return client


def __run_request_test(status_code, expected_exception_message):
    client = Client(base_url=NOZOMIGUARDIAN_URL)
    client.bearer_token = "mock_token"

    with patch('NozomiNetworks.requests.request') as mock_request:
        mock_response = MagicMock()
        mock_response.status_code = status_code
        mock_request.return_value = mock_response

        with pytest.raises(Exception) as exc_info:
            client._make_request('GET', '/test/path')

        assert str(exc_info.value) == expected_exception_message


def __load_test_data(json_path):
    with open(json_path) as f:
        return json.load(f)
