import pytest
from json import load
from GroupIB_TIA_Feed import fetch_indicators_command, Client


with open('test_data/example.json') as examples:
    RAW_JSON = load(examples)
with open('test_data/results.json') as results:
    RESULTS = load(results)
COLLECTION_NAMES = [
    'compromised/mule', 'compromised/imei', 'attacks/ddos', 'attacks/deface',
    'attacks/phishing', 'attacks/phishing_kit', 'apt/threat',
    'suspicious_ip/tor_node', 'suspicious_ip/open_proxy', 'suspicious_ip/socks_proxy',
    'malware/cnc', 'osi/vulnerability'
]


@pytest.fixture(scope='function', params=COLLECTION_NAMES, ids=COLLECTION_NAMES)
def session_fixture(request):
    return request.param, Client(base_url='https://some.ru')


def test_fetch_indicators_command(mocker, session_fixture):
    collection_name, client = session_fixture
    mocker.patch.object(client, 'create_update_generator', return_value=[[RAW_JSON[collection_name]]])
    next_run, indicators = fetch_indicators_command(client=client, last_run={}, first_fetch_time='3 days',
                                                    indicator_collections=[collection_name], requests_count=1,
                                                    common_fields={})
    expected_next_run, expected_indicators = RESULTS[collection_name]
    assert next_run == expected_next_run
    for i in range(len(expected_indicators)):
        raw_json = indicators[i].get("rawJSON")
        expected_raw_json = expected_indicators[i].get("rawJSON")
        assert sorted(raw_json.items()) == sorted(expected_raw_json.items())
