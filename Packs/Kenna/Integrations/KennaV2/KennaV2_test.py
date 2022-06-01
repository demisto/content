import pytest

from KennaV2 import parse_response, search_vulnerabilities, get_connectors, Client, \
    search_fixes, search_assets, get_asset_vulnerabilities, get_connector_runs
from Tests_Data.ExpectedResult import VULNERABILITIES_SEARCH_EXPECTED, GET_CONNECTORS_EXPECTED, SEARCH_FIXES_EXPECTED, \
    SEARCH_ASSETS_EXPECTED, GET_ASSETS_VULNERABILITIES_EXPECTED, GET_CONNECTOR_RUNS_EXPECTED
from Tests_Data.RawData import VULNERABILITIES_SEARCH_RESPONSE, GET_CONNECTORS_RESPONSE, SEARCH_FIXES_RESPONSE, \
    SEARCH_ASSETS_RESPONSE, GET_ASSETS_VULNERABILITIES_RESPONSE, GET_CONNECTOR_RUNS_RESPONSE


def test_parse_response():
    raw = [{
        'id': '12',
        'cve-id': 'CVE-AS12',
        'list': [{
            'list-id': '123'
        }]
    }]
    expected = [{
        'ID': '12',
        'CVE-ID': 'CVE-AS12',
        'List': [{
            'List-ID': '123'
        }]
    }]
    wanted = ['ID', 'CVE-ID', ['List', 'List-ID']]
    actual = ['id', 'cve-id', ['list', 'list-id']]
    to_dict = parse_response(raw, wanted, actual)
    assert to_dict == expected


@pytest.mark.parametrize('command, args, response, expected_result', [
    (search_vulnerabilities, {"to_context": "True"}, VULNERABILITIES_SEARCH_RESPONSE, VULNERABILITIES_SEARCH_EXPECTED),
    (get_connectors, {"to_context": "True"}, GET_CONNECTORS_RESPONSE, GET_CONNECTORS_EXPECTED),
    (search_fixes, {"to_context": "True"}, SEARCH_FIXES_RESPONSE, SEARCH_FIXES_EXPECTED),
    (search_assets, {"to_context": "True"}, SEARCH_ASSETS_RESPONSE, SEARCH_ASSETS_EXPECTED),
    (get_asset_vulnerabilities, {'id': '3', "to_context": "True"}, GET_ASSETS_VULNERABILITIES_RESPONSE,
     GET_ASSETS_VULNERABILITIES_EXPECTED),
    (get_connector_runs, {"to_context": "True"}, GET_CONNECTOR_RUNS_RESPONSE, GET_CONNECTOR_RUNS_EXPECTED)
])
def test_commands(command, args, response, expected_result, mocker):
    client = Client('https://api.kennasecurity.com', 'api', True, True)
    mocker.patch.object(client, 'http_request', return_value=response)
    result = command(client, args)
    assert expected_result == result[1]
