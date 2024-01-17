import json
import pytest
from pathlib import Path
from pytest_mock import MockerFixture

from KennaV2 import parse_response, search_vulnerabilities, get_connectors, Client, \
    search_fixes, get_asset_vulnerabilities, get_connector_runs, search_assets_by_external_id_command, \
    update_asset_command, search_assets_command
from test_data.ExpectedResult import VULNERABILITIES_SEARCH_EXPECTED, GET_CONNECTORS_EXPECTED, SEARCH_FIXES_EXPECTED, \
    GET_ASSETS_VULNERABILITIES_EXPECTED, GET_CONNECTOR_RUNS_EXPECTED
from test_data.RawData import VULNERABILITIES_SEARCH_RESPONSE, GET_CONNECTORS_RESPONSE, SEARCH_FIXES_RESPONSE, \
    GET_ASSETS_VULNERABILITIES_RESPONSE, GET_CONNECTOR_RUNS_RESPONSE


class MockClient:
    def http_request(self, message, suffix):
        pass


def util_load_json(path: str) -> dict:
    return json.loads(Path(path).read_text())


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
    (get_asset_vulnerabilities, {'id': '3', "to_context": "True"}, GET_ASSETS_VULNERABILITIES_RESPONSE,
     GET_ASSETS_VULNERABILITIES_EXPECTED),
    (get_connector_runs, {"to_context": "True"}, GET_CONNECTOR_RUNS_RESPONSE, GET_CONNECTOR_RUNS_EXPECTED)
])
def test_commands(command, args, response, expected_result, mocker):
    client = Client('https://api.kennasecurity.com', 'api', True, True)
    mocker.patch.object(client, 'http_request', return_value=response)
    result = command(client, args)
    assert expected_result == result[1]


def test_search_assets_by_external_id_command(mocker: MockerFixture) -> None:
    """
    Given
        a valid external_id,
    When
        the search_assets_by_external_id_command function is called,
    Then
        it should return a table with the assets that match the given external_id.
    """
    mocker.patch.object(MockClient, 'http_request', return_value=util_load_json("test_data/assets_response.json"))
    result = search_assets_by_external_id_command(MockClient(), {"external_id": "external_123"})
    assert result.readable_output == (
        '### Kenna Assets\n'
        '|IP-address|Operating System|Score|id|\n'
        '|---|---|---|---|\n'
        '| 0.0.0 | Windows | 1000 | 1 |\n'
        '| 0.0.0 | Windows | 1000 | 2 |\n'
        '| 0.0.0 | Windows | 1000 | 5 |\n'
        '| 0.0.0 | Windows | 1000 | 6 |\n'
    )


def test_search_assets_command(mocker: MockerFixture) -> None:
    """
    Given
        A MockClient instance and a set of arguments for the search_assets_command function.
    When
        The function is called with the arguments,
    Then
        It should return the expected readable output.
    """
    args = {
        'limit': 2,
        'to_context': True,
        'hostname': 'test-hostname',
        'tags': ['tag1', 'tag2'],
        'id': ['id1', 'id2'],
        'min-score': 5
    }
    mocker.patch.object(MockClient, 'http_request', return_value=util_load_json("test_data/assets_response.json"))
    result = search_assets_command(MockClient(), args)

    assert result.readable_output == (
        '### Kenna Assets\n'
        '|IP-address|Operating System|Score|id|\n'
        '|---|---|---|---|\n'
        '| 0.0.0 | Windows | 1000 | 1 |\n'
        '| 0.0.0 | Windows | 1000 | 2 |\n'
    )


@pytest.mark.parametrize(
    "mock_response, excepted_result",
    [
        pytest.param(
            {'status': 'success'},
            'Asset with ID 123 was successfully updated.',
            id="successfully updated."
        ),
        pytest.param(
            {'status': 'failure'},
            'Could not update asset with ID 123.',
            id="failure."
        )
    ]
)
def test_update_asset_command(mocker: MockerFixture, mock_response: dict[str, str], excepted_result: str) -> None:
    """
    Given
        a valid asset id and notes,
    When
        the update_asset_command function is called with different API responses,
    Then
        it should return the expected result based on the API response.
    """
    mocker.patch.object(MockClient, 'http_request', return_value=mock_response)
    args = {'id': '123', 'notes': 'Test notes'}
    result = update_asset_command(MockClient(), args)
    assert result.readable_output == excepted_result
