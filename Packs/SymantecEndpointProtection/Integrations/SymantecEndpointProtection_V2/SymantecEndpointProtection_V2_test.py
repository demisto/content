import demistomock as demisto
import json


def mock_demisto(mocker):
    mocker.patch.object(demisto, 'params', return_value={'proxy': True})


def _get_api_response():
    response = "test-data/SEPM-endpoint-api-response.json"
    with open(response) as f:
        api_response = json.loads(f.read())
    return api_response


def _get_expected_output():
    response = "test-data/SEPM-expected-endpoint-extract.json"
    with open(response) as f:
        api_response = json.loads(f.read())
    return api_response


def test_endpoint_ip_extract(mocker):
    mock_demisto(mocker)
    from SymantecEndpointProtection_V2 import endpoint_ip_extract
    raw_json = _get_api_response()
    assert [{'Address': '192.168.1.12', 'Mac': 'demisto-PC'},
            {'Address': '192.168.1.125', 'Mac': 'DESKTOP-TF35B9B'}] == endpoint_ip_extract(raw_json)


def test_endpoint_endpoint_extract(mocker):
    mock_demisto(mocker)
    from SymantecEndpointProtection_V2 import endpoint_endpoint_extract
    raw_json = _get_api_response()
    assert endpoint_endpoint_extract(raw_json) == _get_expected_output()


def test_filter_only_old_clients(mocker):
    mock_demisto(mocker)
    from SymantecEndpointProtection_V2 import filter_only_old_clients
    raw_json = _get_api_response()
    assert filter_only_old_clients(raw_json, None) == []
    assert (filter_only_old_clients(raw_json, 10)) == raw_json
